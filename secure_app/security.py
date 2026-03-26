import html
import re
from typing import Iterable

from flask import has_request_context, request
from werkzeug.utils import secure_filename


USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_]{3,20}$")
EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
PASSWORD_SPECIALS = set("!@#$%^&*")


def sanitize_text(value: str) -> str:
    return html.escape(value.strip())


def validate_username(username: str) -> bool:
    return bool(USERNAME_PATTERN.fullmatch(username))


def validate_email(email: str) -> bool:
    return bool(EMAIL_PATTERN.fullmatch(email))


def validate_password_strength(password: str) -> tuple[bool, str]:
    if len(password) < 12:
        return False, "Password must be at least 12 characters long."
    if not any(char.isupper() for char in password):
        return False, "Password must include an uppercase letter."
    if not any(char.islower() for char in password):
        return False, "Password must include a lowercase letter."
    if not any(char.isdigit() for char in password):
        return False, "Password must include a number."
    if not any(char in PASSWORD_SPECIALS for char in password):
        return False, "Password must include a special character."
    return True, "Password is strong."


def allowed_file(filename: str, allowed_extensions: Iterable[str]) -> bool:
    if "." not in filename:
        return False
    extension = filename.rsplit(".", 1)[1].lower()
    return extension in set(allowed_extensions)


def safe_upload_name(filename: str) -> str:
    cleaned = secure_filename(filename)
    if not cleaned:
        raise ValueError("Invalid filename.")
    return cleaned


def apply_security_headers(response):
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "frame-ancestors 'none'"
    )
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    if has_request_context() and request.is_secure:
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )
    return response
