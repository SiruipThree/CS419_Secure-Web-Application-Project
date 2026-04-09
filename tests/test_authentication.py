from __future__ import annotations

import json

import bcrypt

import secure_app.auth as auth_module
from secure_app.storage import load_json


def _login_attempt(client, identifier: str, password: str, ip_address: str = "127.0.0.1"):
    return client.post(
        "/login",
        data={"identifier": identifier, "password": password},
        follow_redirects=False,
        environ_overrides={"REMOTE_ADDR": ip_address},
    )


def _read_security_events(log_file):
    events = []
    for line in log_file.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        events.append(json.loads(line.split(" - ", 2)[2]))
    return events


def test_registered_password_uses_bcrypt_with_cost_factor_12(make_user):
    password = "StrongPass!123"

    stored_user = make_user("alice", password=password)
    password_hash = stored_user["password_hash"]

    assert password_hash.startswith("$2")
    assert password_hash.split("$")[2] == "12"
    assert bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))


def test_plaintext_password_is_never_written_to_disk(flask_app, make_user):
    password = "StrongPass!123"

    make_user("alice", password=password)
    users_file_contents = flask_app.config["USERS_FILE"].read_text(encoding="utf-8")

    assert password not in users_file_contents
    assert '"password":' not in users_file_contents


def test_account_locks_after_five_failed_attempts_for_fifteen_minutes(
    client,
    flask_app,
    make_user,
    monkeypatch,
):
    now = 1_700_000_000
    monkeypatch.setattr(auth_module.time, "time", lambda: now)

    make_user("alice")
    flask_app.config["SECURITY_LOG_FILE"].write_text("", encoding="utf-8")

    for _ in range(5):
        response = _login_attempt(
            client,
            "alice",
            "WrongPass!123",
            ip_address="203.0.113.10",
        )
        assert response.status_code == 400

    user_record = load_json(flask_app.config["USERS_FILE"], {})["alice"]

    assert user_record["failed_attempts"] == 5
    assert user_record["locked_until"] == now + (15 * 60)

    response = _login_attempt(
        client,
        "alice",
        "StrongPass!123",
        ip_address="203.0.113.10",
    )

    assert response.status_code == 400
    assert b"Account locked. Try again in 15 minutes." in response.data

    events = _read_security_events(flask_app.config["SECURITY_LOG_FILE"])

    assert any(
        event["event_type"] == "ACCOUNT_LOCKED" and event["user_id"] == "alice"
        for event in events
    )
    assert any(
        event["event_type"] == "LOGIN_FAILED"
        and event["user_id"] == "alice"
        and event["details"]["reason"] == "Account locked"
        for event in events
    )


def test_rate_limit_blocks_the_eleventh_attempt_from_the_same_ip(
    client,
    flask_app,
    monkeypatch,
):
    now = 1_700_000_000
    monkeypatch.setattr(auth_module.time, "time", lambda: now)
    flask_app.config["SECURITY_LOG_FILE"].write_text("", encoding="utf-8")

    for _ in range(10):
        response = _login_attempt(
            client,
            "ghost",
            "WrongPass!123",
            ip_address="198.51.100.24",
        )
        assert response.status_code == 400
        assert b"Rate limit exceeded" not in response.data

    response = _login_attempt(
        client,
        "ghost",
        "WrongPass!123",
        ip_address="198.51.100.24",
    )

    assert response.status_code == 400
    assert b"Rate limit exceeded. Try again in a minute." in response.data

    rate_limits = load_json(flask_app.config["RATE_LIMITS_FILE"], {})
    assert len(rate_limits["198.51.100.24"]) == 10

    events = _read_security_events(flask_app.config["SECURITY_LOG_FILE"])

    assert any(
        event["event_type"] == "LOGIN_FAILED"
        and event["user_id"] == "ghost"
        and event["details"]["reason"] == "Rate limit exceeded. Try again in a minute."
        for event in events
    )
    assert any(event["event_type"] == "SUSPICIOUS_ACTIVITY" for event in events)


def test_successful_login_creates_a_server_side_session(client, flask_app, make_user):
    password = "StrongPass!123"
    make_user("alice", password=password)

    response = _login_attempt(client, "alice", password)

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/dashboard")
    assert f'{flask_app.config["SESSION_COOKIE_NAME"]}=' in response.headers["Set-Cookie"]

    sessions = load_json(flask_app.config["SESSIONS_FILE"], {})

    assert len(sessions) == 1

    session_token, session_data = next(iter(sessions.items()))
    assert session_token
    assert session_data["user_id"] == "alice"
    assert session_data["system_role"] == "user"
    assert session_data["expires_at"] > session_data["created_at"]


def test_authentication_attempts_are_logged_for_success_and_failure(
    client,
    flask_app,
    make_user,
):
    password = "StrongPass!123"
    make_user("alice", password=password)
    flask_app.config["SECURITY_LOG_FILE"].write_text("", encoding="utf-8")

    unknown_user_response = _login_attempt(
        client,
        "ghost",
        "WrongPass!123",
        ip_address="192.0.2.10",
    )
    failed_password_response = _login_attempt(
        client,
        "alice",
        "WrongPass!123",
        ip_address="192.0.2.11",
    )
    success_response = _login_attempt(
        client,
        "alice",
        password,
        ip_address="192.0.2.12",
    )

    assert unknown_user_response.status_code == 400
    assert failed_password_response.status_code == 400
    assert success_response.status_code == 302

    events = _read_security_events(flask_app.config["SECURITY_LOG_FILE"])

    assert any(
        event["event_type"] == "LOGIN_FAILED"
        and event["user_id"] == "ghost"
        and event["details"]["reason"] == "Unknown user or email"
        for event in events
    )
    assert any(
        event["event_type"] == "LOGIN_FAILED"
        and event["user_id"] == "alice"
        and event["details"]["reason"] == "Invalid password match"
        for event in events
    )
    assert any(
        event["event_type"] == "LOGIN_SUCCESS" and event["user_id"] == "alice"
        for event in events
    )
