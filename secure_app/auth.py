"""Authentication service skeleton.

Implement password hashing, lockout tracking, duplicate account checks,
and login rate limiting here.
"""

from secure_app.storage import load_json


def load_users(config):
    return load_json(config["USERS_FILE"], [])


def user_exists(config, username: str, email: str) -> bool:
    users = load_users(config)
    normalized_username = username.lower()
    normalized_email = email.lower()
    return any(
        user.get("username", "").lower() == normalized_username
        or user.get("email", "").lower() == normalized_email
        for user in users
    )
