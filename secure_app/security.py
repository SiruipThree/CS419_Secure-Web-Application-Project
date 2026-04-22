from __future__ import annotations

import html
import ipaddress
import re
import zipfile
from io import BytesIO
from pathlib import Path
from typing import Any, Iterable, Mapping
from urllib.parse import urlsplit

from flask import has_request_context, request
from werkzeug.utils import secure_filename

#TODO: username, email, pasword, etc, rules.
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_]{3,20}$")
EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
PASSWORD_SPECIALS = set("!@#$%^&*")
EICAR_TEST_SIGNATURE = (
    b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$"
    b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
)

#sanitize text
def sanitize_text(value: str) -> str:
    return html.escape(value.strip())


def sanitize_output(data: Any) -> Any:
    """Escape string output for explicit non-Jinja rendering contexts."""

    if isinstance(data, str):
        return html.escape(data)
    return data


def validate_username(username: str) -> bool:
    return bool(USERNAME_PATTERN.fullmatch(username))


def validate_email(email: str) -> bool:
    return bool(EMAIL_PATTERN.fullmatch(email))

#URL check 
def validate_url(
    value: str,
    *,
    allowed_schemes: Iterable[str] = ("https",),
    max_length: int = 2048,
    allow_private_hosts: bool = False,
) -> tuple[bool, str]:
    normalized_value = (value or "").strip()
    if not normalized_value:
        return False, "URL is required."

    if len(normalized_value) > max_length:
        return False, f"URL must be {max_length} characters or fewer."

    if any(ord(char) < 32 for char in normalized_value):
        return False, "URL contains invalid control characters."

    parsed = urlsplit(normalized_value)
    normalized_schemes = {scheme.lower() for scheme in allowed_schemes}
    scheme = parsed.scheme.lower()

    if scheme not in normalized_schemes:
        allowed_label = ", ".join(sorted(normalized_schemes))
        return False, f"URL scheme must be one of: {allowed_label}."

    if not parsed.netloc or not parsed.hostname:
        return False, "URL must include a hostname."

    if parsed.username or parsed.password:
        return False, "URL must not include embedded credentials."

    host = parsed.hostname
    if not allow_private_hosts:
        if host.lower() == "localhost":
            return False, "URL must not target localhost."

        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            if "." not in host:
                return False, "URL must use a fully qualified public hostname."
        else:
            if (
                address.is_private
                or address.is_loopback
                or address.is_link_local
                or address.is_multicast
                or address.is_reserved
                or address.is_unspecified
            ):
                return False, "URL must target a public host."

    return True, "URL is valid."

#password check 
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


def validate_document_title(title: str, max_length: int = 120) -> tuple[bool, str]:
    normalized_title = title.strip()
    if not normalized_title:
        return False, "Document title is required."
    if len(normalized_title) > max_length:
        return False, f"Document title must be {max_length} characters or fewer."
    if any(ord(char) < 32 for char in normalized_title):
        return False, "Document title contains invalid control characters."
    return True, "Document title is valid."


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


def safe_file_path(filename: str, base_dir: str | Path) -> Path:
    base_path = Path(base_dir).resolve()
    candidate_path = (base_path / safe_upload_name(filename)).resolve()

    try:
        candidate_path.relative_to(base_path)
    except ValueError as exc:
        raise ValueError("Path traversal detected.") from exc

    return candidate_path


def validate_uploaded_file(
    filename: str,
    selected_file_type: str | None,
    content_type: str | None,
    payload: bytes,
    allowed_extensions: Iterable[str],
    allowed_mime_types: Mapping[str, set[str]],
) -> tuple[bool, str, str]:
    if not filename:
        return False, "Select a file to upload.", ""

    normalized_selected_type = (selected_file_type or "").strip().lower()

    if not normalized_selected_type:
        return False, "Select a document type.", ""

    if normalized_selected_type not in allowed_extensions:
        return False, "Selected document type is not allowed.", ""

    if not allowed_file(filename, allowed_extensions):
        return False, "File type is not allowed.", ""

    cleaned_name = safe_upload_name(filename)
    extension = cleaned_name.rsplit(".", 1)[1].lower()
    if extension != normalized_selected_type:
        return False, "Uploaded file extension does not match the selected document type.", ""

    normalized_content_type = (content_type or "").split(";", 1)[0].strip().lower()
    accepted_mime_types = {
        mime_type.lower()
        for mime_type in allowed_mime_types.get(normalized_selected_type, set())
    }

    if (
        accepted_mime_types
        and normalized_content_type
        and normalized_content_type not in accepted_mime_types
        and normalized_content_type != "application/octet-stream"
    ):
        return False, "Uploaded file content type is not allowed.", ""

    if not matches_file_signature(normalized_selected_type, payload):
        return False, "Uploaded file contents do not match the selected file type.", ""

    is_clean, scan_message = scan_for_malware(payload)
    if not is_clean:
        return False, scan_message, ""

    return True, "File is valid.", cleaned_name


def matches_file_signature(extension: str, payload: bytes) -> bool:
    if not payload:
        return False

    if extension == "pdf":
        return payload.startswith(b"%PDF-")

    if extension in {"jpg", "jpeg"}:
        return payload.startswith(b"\xff\xd8\xff")

    if extension == "png":
        return payload.startswith(b"\x89PNG\r\n\x1a\n")

    if extension == "docx":
        if not payload.startswith(b"PK"):
            return False

        try:
            with zipfile.ZipFile(BytesIO(payload)) as archive:
                names = set(archive.namelist())
        except zipfile.BadZipFile:
            return False

        return "[Content_Types].xml" in names and any(
            name.startswith("word/") for name in names
        )

    if extension == "txt":
        try:
            payload.decode("utf-8")
        except UnicodeDecodeError:
            return False
        return True

    return False


def scan_for_malware(payload: bytes) -> tuple[bool, str]:
    if EICAR_TEST_SIGNATURE in payload:
        return False, "Uploaded file matched a malware test signature."

    return True, "File passed malware scanning."


def _is_secure_request() -> bool:
    forwarded_proto = request.headers.get("X-Forwarded-Proto", "")
    if forwarded_proto:
        return forwarded_proto.split(",", 1)[0].strip().lower() == "https"
    return request.is_secure


def apply_security_headers(response):
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "connect-src 'self'; "
        "frame-ancestors 'none'"
    )
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    if has_request_context() and _is_secure_request():
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )
    return response
