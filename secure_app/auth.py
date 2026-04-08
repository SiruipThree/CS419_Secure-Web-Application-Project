from __future__ import annotations

import time
from pathlib import Path

import bcrypt

from secure_app.access_control import normalize_system_role
from secure_app.logging_utils import security_log
from secure_app.security import (
    validate_email,
    validate_password_strength,
    validate_username,
)
from secure_app.storage import load_json, save_json


class UserAuth:
    def __init__(self, users_file="data/users.json", rate_limits_file="data/rate_limits.json"):
        self.users_file = Path(users_file)
        self.rate_limits_file = Path(rate_limits_file)

    def _load_users(self) -> dict[str, dict]:
        users = load_json(self.users_file, {})

        if isinstance(users, dict):
            return users

        if isinstance(users, list):
            return {
                user["username"]: user
                for user in users
                if isinstance(user, dict) and user.get("username")
            }

        return {}

    def _save_users(self, users: dict[str, dict]) -> None:
        save_json(self.users_file, users)

    def _check_rate_limit(self, ip_address: str | None) -> bool:
        """Allow at most 10 login attempts per IP address per minute."""

        limits = load_json(self.rate_limits_file, {})
        now = time.time()
        key = ip_address or "unknown"

        attempts = [timestamp for timestamp in limits.get(key, []) if now - timestamp < 60]
        if len(attempts) >= 10:
            return False

        attempts.append(now)
        limits[key] = attempts
        save_json(self.rate_limits_file, limits)
        return True

    def get_user(self, username: str | None) -> dict | None:
        if not username:
            return None
        return self._load_users().get(username)

    def find_user(self, identifier: str | None) -> tuple[str | None, dict | None]:
        if not identifier:
            return None, None

        normalized_identifier = identifier.strip()
        users = self._load_users()

        if normalized_identifier in users:
            return normalized_identifier, users[normalized_identifier]

        for username, user in users.items():
            if user.get("email", "").lower() == normalized_identifier.lower():
                return username, user

        return None, None

    def list_users(self) -> list[dict]:
        users = []
        for username, user in sorted(self._load_users().items()):
            users.append(
                {
                    "username": username,
                    "email": user.get("email", ""),
                    "role": normalize_system_role(user.get("role", "user")),
                    "created_at": user.get("created_at"),
                    "locked_until": user.get("locked_until"),
                }
            )
        return users

    def register(self, username, email, password, confirm_password):
        username = (username or "").strip()
        email = (email or "").strip()

        if password != confirm_password:
            security_log.log_event(
                "VALIDATION_FAILED",
                user_id=username or None,
                details={"reason": "Passwords do not match"},
                severity="WARNING",
            )
            return {"error": "Passwords do not match"}

        if not validate_username(username):
            security_log.log_event(
                "VALIDATION_FAILED",
                user_id=username or None,
                details={"reason": "Invalid username format"},
                severity="WARNING",
            )
            return {"error": "Invalid username format"}

        if not validate_email(email):
            security_log.log_event(
                "VALIDATION_FAILED",
                user_id=username,
                details={"reason": "Invalid email format"},
                severity="WARNING",
            )
            return {"error": "Invalid email format"}

        is_valid, validation_message = validate_password_strength(password)
        if not is_valid:
            security_log.log_event(
                "VALIDATION_FAILED",
                user_id=username,
                details={"reason": validation_message},
                severity="WARNING",
            )
            return {"error": validation_message}

        users = self._load_users()

        if username in users:
            security_log.log_event(
                "REGISTRATION_FAILED",
                user_id=username,
                details={"reason": "Username already taken"},
                severity="WARNING",
            )
            return {"error": "Username already taken"}

        if any(existing_user.get("email", "").lower() == email.lower() for existing_user in users.values()):
            security_log.log_event(
                "REGISTRATION_FAILED",
                user_id=username,
                details={"reason": "Email already registered"},
                severity="WARNING",
            )
            return {"error": "Email already registered"}

        salt = bcrypt.gensalt(rounds=12)
        hashed = bcrypt.hashpw(password.encode("utf-8"), salt)

        users[username] = {
            "username": username,
            "email": email,
            "password_hash": hashed.decode("utf-8"),
            "created_at": time.time(),
            "role": "user",
            "failed_attempts": 0,
            "locked_until": None,
        }

        self._save_users(users)
        security_log.log_event(
            "USER_REGISTERED",
            user_id=username,
            details={"action": "New user registration"},
        )
        return {"success": True, "user_id": username, "role": "user"}

    def login(self, identifier, password, ip_address):
        if not self._check_rate_limit(ip_address):
            security_log.log_event(
                "SUSPICIOUS_ACTIVITY",
                user_id=identifier or None,
                details={"reason": "Rate limit exceeded - Possible brute force"},
                severity="WARNING",
            )
            return {"error": "Rate limit exceeded. Try again in a minute."}

        username, user = self.find_user(identifier)

        if not user or not username:
            return {"error": "Invalid credentials"}

        locked_until = user.get("locked_until")
        if locked_until and time.time() < locked_until:
            remaining = int((locked_until - time.time()) / 60)
            return {"error": f"Account locked. Try again in {remaining} minutes."}

        if bcrypt.checkpw(password.encode("utf-8"), user["password_hash"].encode("utf-8")):
            user["failed_attempts"] = 0
            user["locked_until"] = None
            users = self._load_users()
            users[username] = user
            self._save_users(users)
            role = normalize_system_role(user.get("role", "user"))
            security_log.log_event(
                "LOGIN_SUCCESS",
                user_id=username,
                details={"action": "Credentials verified", "role": role},
            )
            return {"success": True, "user_id": username, "role": role}

        user["failed_attempts"] = int(user.get("failed_attempts", 0)) + 1
        if user["failed_attempts"] >= 5:
            user["locked_until"] = time.time() + (15 * 60)
            security_log.log_event(
                "ACCOUNT_LOCKED",
                user_id=username,
                details={"reason": "Exceeded maximum failed attempts (5)"},
                severity="ERROR",
            )

        users = self._load_users()
        users[username] = user
        self._save_users(users)
        security_log.log_event(
            "LOGIN_FAILED",
            user_id=username,
            details={"reason": "Invalid password match"},
            severity="WARNING",
        )
        return {"error": "Invalid credentials"}

    def change_password(self, username, old_password, new_password, confirm_password):
        users = self._load_users()
        user = users.get(username)

        if not user:
            return {"error": "User not found."}

        if not bcrypt.checkpw(old_password.encode("utf-8"), user["password_hash"].encode("utf-8")):
            security_log.log_event(
                "VALIDATION_FAILED",
                user_id=username,
                details={"reason": "Password change failed - Incorrect current password"},
                severity="WARNING",
            )
            return {"error": "Incorrect current password."}

        if new_password != confirm_password:
            return {"error": "New passwords do not match."}

        if bcrypt.checkpw(new_password.encode("utf-8"), user["password_hash"].encode("utf-8")):
            return {"error": "New password cannot be the same as the current password."}

        is_valid, validation_message = validate_password_strength(new_password)
        if not is_valid:
            security_log.log_event(
                "VALIDATION_FAILED",
                user_id=username,
                details={"reason": f"Password change failed - {validation_message}"},
                severity="WARNING",
            )
            return {"error": validation_message}

        salt = bcrypt.gensalt(rounds=12)
        hashed = bcrypt.hashpw(new_password.encode("utf-8"), salt)
        user["password_hash"] = hashed.decode("utf-8")
        users[username] = user
        self._save_users(users)

        security_log.log_event(
            "PASSWORD_CHANGE",
            user_id=username,
            details={"action": "User successfully updated their password"},
        )
        return {"success": "Password updated successfully."}
