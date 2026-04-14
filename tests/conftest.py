from __future__ import annotations

import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app import create_app
from secure_app.auth import UserAuth
from secure_app.logging_utils import configure_app_logging
from secure_app.storage import bootstrap_storage, load_json, save_json


@pytest.fixture()
def flask_app(tmp_path):
    app = create_app()

    data_dir = tmp_path / "data"
    log_dir = tmp_path / "logs"
    app.config.update(
        TESTING=True,
        DATA_DIR=data_dir,
        USERS_FILE=data_dir / "users.json",
        RATE_LIMITS_FILE=data_dir / "rate_limits.json",
        SESSIONS_FILE=data_dir / "sessions.json",
        DOCUMENTS_FILE=data_dir / "documents.json",
        SHARES_FILE=data_dir / "shares.json",
        AUDIT_FILE=data_dir / "audit.json",
        DOCUMENT_STORAGE_DIR=data_dir / "documents",
        UPLOAD_STAGING_DIR=data_dir / "uploads",
        LOG_DIR=log_dir,
        SECURITY_LOG_FILE=log_dir / "security.log",
        ACCESS_LOG_FILE=log_dir / "access.log",
        ENCRYPTION_KEY_FILE=tmp_path / "secret.key",
    )

    bootstrap_storage(app.config)
    configure_app_logging(app)
    return app


@pytest.fixture()
def client(flask_app):
    with flask_app.test_client() as client:
        yield client


@pytest.fixture()
def make_user(flask_app):
    auth_service = UserAuth(
        flask_app.config["USERS_FILE"],
        flask_app.config["RATE_LIMITS_FILE"],
    )

    def _make_user(
        username: str,
        *,
        email: str | None = None,
        password: str = "StrongPass!123",
        role: str = "user",
    ):
        result = auth_service.register(
            username,
            email or f"{username}@example.com",
            password,
            password,
        )
        assert result.get("success"), result

        users = load_json(flask_app.config["USERS_FILE"], {})
        users[username]["role"] = role
        save_json(flask_app.config["USERS_FILE"], users)
        return users[username]

    return _make_user


@pytest.fixture()
def login_as(client, make_user):
    def _login_as(
        username: str,
        *,
        email: str | None = None,
        password: str = "StrongPass!123",
        role: str = "user",
    ):
        make_user(username, email=email, password=password, role=role)
        response = client.post(
            "/login",
            data={"identifier": username, "password": password},
            follow_redirects=False,
        )
        assert response.status_code == 302
        return response

    return _login_as


@pytest.fixture()
def csrf_token(flask_app):
    """Return the CSRF token for the current (most recent) session."""
    def _csrf_token():
        sessions = load_json(flask_app.config["SESSIONS_FILE"], {})
        if not sessions:
            return ""
        return next(iter(sessions.values())).get("csrf_token", "")
    return _csrf_token


@pytest.fixture()
def grant_share(flask_app):
    def _grant_share(document_id: str, principal: str, role: str):
        shares = load_json(flask_app.config["SHARES_FILE"], [])
        shares.append(
            {
                "document_id": document_id,
                "principal": principal,
                "role": role,
            }
        )
        save_json(flask_app.config["SHARES_FILE"], shares)

    return _grant_share
