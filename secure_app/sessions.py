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


def _expires_at(config, base_time: float) -> float:
    return base_time + float(config["SESSION_TIMEOUT_SECONDS"])


def invalidate_user_sessions(config, user_id: str) -> int:
    """Remove all existing sessions for a given user (concurrent session
    control and session-fixation prevention on login)."""
    sessions = load_sessions(config)
    tokens_to_remove = [
        token
        for token, data in sessions.items()
        if isinstance(data, dict) and data.get("user_id") == user_id
    ]
    for token in tokens_to_remove:
        sessions.pop(token, None)
    if tokens_to_remove:
        _save_sessions(config, sessions)
    return len(tokens_to_remove)


def create_session(config, user_id: str, system_role: str) -> str:
    invalidate_user_sessions(config, user_id)

    sessions = load_sessions(config)
    session_token = secrets.token_urlsafe(32)
    now = time.time()
    sessions[session_token] = {
        "user_id": user_id,
        "system_role": normalize_system_role(system_role),
        "created_at": now,
        "last_activity": now,
        "expires_at": _expires_at(config, now),
        "csrf_token": secrets.token_urlsafe(32),
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

    now = time.time()
    if now > float(session.get("expires_at", 0)):
        sessions.pop(session_token, None)
        _save_sessions(config, sessions)
        return None

    session["last_activity"] = now
    session["expires_at"] = _expires_at(config, now)
    sessions[session_token] = session
    _save_sessions(config, sessions)
    return session


def invalidate_session(config, session_token: str | None) -> None:
    if not session_token:
        return None

    sessions = load_sessions(config)
    if session_token in sessions:
        sessions.pop(session_token, None)
        _save_sessions(config, sessions)
    return None
