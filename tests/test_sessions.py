from __future__ import annotations

import json
from http.cookies import SimpleCookie

import secure_app.sessions as sessions_module
from secure_app.storage import load_json


def _login(client, identifier: str, password: str):
    return client.post(
        "/login",
        data={"identifier": identifier, "password": password},
        follow_redirects=False,
    )


def _session_cookie_value(response, cookie_name: str) -> str:
    cookie = SimpleCookie()
    cookie.load(response.headers["Set-Cookie"])
    return cookie[cookie_name].value


def _read_security_events(log_file):
    events = []
    for line in log_file.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        events.append(json.loads(line.split(" - ", 2)[2]))
    return events


def test_session_contains_last_activity_and_csrf_token(client, flask_app, make_user):
    make_user("alice")
    _login(client, "alice", "StrongPass!123")

    sessions = load_json(flask_app.config["SESSIONS_FILE"], {})
    assert len(sessions) == 1

    session_data = next(iter(sessions.values()))
    assert "last_activity" in session_data
    assert "csrf_token" in session_data
    assert len(session_data["csrf_token"]) > 20
    assert session_data["last_activity"] == session_data["created_at"]


def test_session_cookie_uses_hardening_flags(client, flask_app, make_user):
    make_user("alice")

    response = _login(client, "alice", "StrongPass!123")

    assert response.status_code == 302
    set_cookie = response.headers["Set-Cookie"]
    assert f'{flask_app.config["SESSION_COOKIE_NAME"]}=' in set_cookie
    assert "HttpOnly;" in set_cookie
    assert "SameSite=Strict" in set_cookie
    assert f"Max-Age={flask_app.config['SESSION_TIMEOUT_SECONDS']}" in set_cookie


def test_session_last_activity_refreshes_on_access(
    client, flask_app, make_user, monkeypatch
):
    login_time = 1_700_000_000
    monkeypatch.setattr(sessions_module.time, "time", lambda: login_time)

    make_user("alice")
    _login(client, "alice", "StrongPass!123")

    access_time = login_time + 300
    monkeypatch.setattr(sessions_module.time, "time", lambda: access_time)
    client.get("/dashboard")

    sessions = load_json(flask_app.config["SESSIONS_FILE"], {})
    session_data = next(iter(sessions.values()))
    assert session_data["last_activity"] == access_time
    assert session_data["expires_at"] == access_time + flask_app.config["SESSION_TIMEOUT_SECONDS"]


def test_session_expires_after_idle_timeout(
    client, flask_app, make_user, monkeypatch
):
    login_time = 1_700_000_000
    monkeypatch.setattr(sessions_module.time, "time", lambda: login_time)

    make_user("alice")
    _login(client, "alice", "StrongPass!123")

    expired_time = login_time + flask_app.config["SESSION_TIMEOUT_SECONDS"] + 1
    monkeypatch.setattr(sessions_module.time, "time", lambda: expired_time)

    response = client.get("/dashboard")
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/login")


def test_login_invalidates_previous_sessions(flask_app, make_user):
    make_user("alice")

    with flask_app.test_client() as first_client:
        _login(first_client, "alice", "StrongPass!123")
        sessions_before = load_json(flask_app.config["SESSIONS_FILE"], {})
        assert len(sessions_before) == 1
        old_token = next(iter(sessions_before.keys()))

    with flask_app.test_client() as second_client:
        _login(second_client, "alice", "StrongPass!123")
        sessions_after = load_json(flask_app.config["SESSIONS_FILE"], {})
        assert len(sessions_after) == 1
        new_token = next(iter(sessions_after.keys()))
        assert old_token != new_token


def test_concurrent_sessions_not_allowed(client, flask_app, make_user):
    """Logging in from a second client invalidates the first session."""
    make_user("alice")

    _login(client, "alice", "StrongPass!123")

    with flask_app.test_client() as second_client:
        _login(second_client, "alice", "StrongPass!123")

    sessions = load_json(flask_app.config["SESSIONS_FILE"], {})
    assert len(sessions) == 1


def test_logout_destroys_session(client, flask_app, make_user):
    make_user("alice")
    _login(client, "alice", "StrongPass!123")

    sessions = load_json(flask_app.config["SESSIONS_FILE"], {})
    csrf_token = next(iter(sessions.values()))["csrf_token"]

    client.post("/logout", data={"csrf_token": csrf_token})

    sessions_after = load_json(flask_app.config["SESSIONS_FILE"], {})
    assert len(sessions_after) == 0


def test_replayed_session_cookie_is_rejected_after_logout(flask_app, make_user):
    make_user("alice")

    with flask_app.test_client() as victim_client:
        login_response = _login(victim_client, "alice", "StrongPass!123")
        session_token = _session_cookie_value(
            login_response,
            flask_app.config["SESSION_COOKIE_NAME"],
        )
        sessions = load_json(flask_app.config["SESSIONS_FILE"], {})
        csrf_token = next(iter(sessions.values()))["csrf_token"]

        logout_response = victim_client.post("/logout", data={"csrf_token": csrf_token})
        assert logout_response.status_code == 302

    with flask_app.test_client() as hijacker_client:
        hijacker_client.set_cookie(
            flask_app.config["SESSION_COOKIE_NAME"],
            session_token,
        )
        response = hijacker_client.get("/dashboard")

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/login")


def test_replayed_old_session_cookie_is_rejected_after_relogin(flask_app, make_user):
    make_user("alice")

    with flask_app.test_client() as first_client:
        first_login = _login(first_client, "alice", "StrongPass!123")
        old_token = _session_cookie_value(
            first_login,
            flask_app.config["SESSION_COOKIE_NAME"],
        )

    with flask_app.test_client() as second_client:
        second_login = _login(second_client, "alice", "StrongPass!123")
        new_token = _session_cookie_value(
            second_login,
            flask_app.config["SESSION_COOKIE_NAME"],
        )

    assert old_token != new_token

    with flask_app.test_client() as hijacker_client:
        hijacker_client.set_cookie(
            flask_app.config["SESSION_COOKIE_NAME"],
            old_token,
        )
        response = hijacker_client.get("/dashboard")

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/login")


def test_session_creation_and_destruction_are_logged(client, flask_app, make_user):
    make_user("alice")
    flask_app.config["SECURITY_LOG_FILE"].write_text("", encoding="utf-8")

    _login(client, "alice", "StrongPass!123")
    sessions = load_json(flask_app.config["SESSIONS_FILE"], {})
    csrf_token = next(iter(sessions.values()))["csrf_token"]

    client.post("/logout", data={"csrf_token": csrf_token})

    events = _read_security_events(flask_app.config["SECURITY_LOG_FILE"])
    assert any(
        event["event_type"] == "SESSION_CREATED"
        and event["user_id"] == "alice"
        and event["details"]["reason"] == "login"
        for event in events
    )
    assert any(
        event["event_type"] == "SESSION_DESTROYED"
        and event["user_id"] == "alice"
        and event["details"]["reason"] == "logout"
        for event in events
    )


def test_csrf_token_required_for_upload(client, flask_app, login_as):
    login_as("alice")

    response = client.post(
        "/upload",
        data={"title": "Test", "document": (b"hello", "test.txt")},
        content_type="multipart/form-data",
    )
    assert response.status_code == 403


def test_csrf_token_accepted_for_upload(client, flask_app, login_as):
    from io import BytesIO

    login_as("alice")
    sessions = load_json(flask_app.config["SESSIONS_FILE"], {})
    csrf_token = next(iter(sessions.values()))["csrf_token"]

    response = client.post(
        "/upload",
        data={
            "title": "Test Doc",
            "document_type": "txt",
            "document": (BytesIO(b"hello world"), "test.txt"),
            "csrf_token": csrf_token,
        },
        content_type="multipart/form-data",
    )
    assert response.status_code == 200
    assert b"Encrypted upload stored successfully" in response.data


def test_csrf_token_required_for_logout(client, flask_app, login_as):
    login_as("alice")

    response = client.post("/logout", data={})
    assert response.status_code == 403
