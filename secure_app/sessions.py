from __future__ import annotations

"""Server-side session management using the file-based session store."""

import secrets
import time

from secure_app.access_control import normalize_system_role
from secure_app.storage import load_json, save_json


def load_sessions(config):
    return load_json(config["SESSIONS_FILE"], {})


def _save_sessions(config, sessions: dict) -> None:
    save_json(config["SESSIONS_FILE"], sessions)


def _expires_at(config, created_at: float) -> float:
    return created_at + float(config["SESSION_TIMEOUT_SECONDS"])


def create_session(config, user_id: str, system_role: str) -> str:
    sessions = load_sessions(config)
    session_token = secrets.token_urlsafe(32)
    created_at = time.time()
    sessions[session_token] = {
        "user_id": user_id,
        "system_role": normalize_system_role(system_role),
        "created_at": created_at,
        "expires_at": _expires_at(config, created_at),
    }
    _save_sessions(config, sessions)
    return session_token


def get_session(config, session_token: str | None) -> dict | None:
    if not session_token:
        return None

    sessions = load_sessions(config)
    session = sessions.get(session_token)
    if not isinstance(session, dict):
        return None

    if time.time() > float(session.get("expires_at", 0)):
        sessions.pop(session_token, None)
        _save_sessions(config, sessions)
        return None

    return session


def invalidate_session(config, session_token: str | None) -> None:
    if not session_token:
        return None

    sessions = load_sessions(config)
    if session_token in sessions:
        sessions.pop(session_token, None)
        _save_sessions(config, sessions)
    return None
