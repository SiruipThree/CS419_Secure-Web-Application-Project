import hashlib
import secrets
from datetime import datetime, timezone
from pathlib import Path

from cryptography.fernet import Fernet

from secure_app.logging_utils import access_log, security_log
from secure_app.security import (
    safe_file_path,
    validate_document_title,
    validate_uploaded_file,
)
from secure_app.storage import load_json, save_json


def load_documents(config):
    return load_json(config["DOCUMENTS_FILE"], [])


def _load_cipher(config) -> Fernet:
    key_path = Path(config["ENCRYPTION_KEY_FILE"])
    key_path.parent.mkdir(parents=True, exist_ok=True)

    if key_path.exists():
        key = key_path.read_bytes()
    else:
        key = Fernet.generate_key()
        key_path.write_bytes(key)

    return Fernet(key)


def _next_document_version(documents: list[dict], owner: str, title: str) -> int:
    matching_versions = [
        int(document.get("version", 0))
        for document in documents
        if document.get("owner") == owner and document.get("title") == title
    ]
    return max(matching_versions, default=0) + 1


def _append_audit_event(
    config,
    event_type: str,
    user_id: str,
    details: dict,
) -> None:
    audit_events = load_json(config["AUDIT_FILE"], [])
    audit_events.append(
        {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "user_id": user_id,
            "details": details,
        }
    )
    save_json(config["AUDIT_FILE"], audit_events)


def load_recent_audit_events(config, limit: int = 10) -> list[dict]:
    events = load_json(config["AUDIT_FILE"], [])
    return list(reversed(events[-limit:]))


def list_recent_documents(config, owner: str | None = None, limit: int = 10) -> list[dict]:
    documents = load_documents(config)
    if owner is not None:
        documents = [document for document in documents if document.get("owner") == owner]
    return list(reversed(documents[-limit:]))


def store_encrypted_document(config, title: str, uploaded_file, owner: str = "demo-user"):
    plaintext = uploaded_file.read()

    is_valid_title, title_message = validate_document_title(
        title, config["DOCUMENT_TITLE_MAX_LENGTH"]
    )
    if not is_valid_title:
        raise ValueError(title_message)

    is_valid_file, file_message, cleaned_name = validate_uploaded_file(
        uploaded_file.filename or "",
        getattr(uploaded_file, "mimetype", None),
        plaintext,
        config["ALLOWED_EXTENSIONS"],
        config["ALLOWED_MIME_TYPES"],
    )
    if not is_valid_file:
        raise ValueError(file_message)
    if not plaintext:
        raise ValueError("Uploaded file is empty.")

    cipher = _load_cipher(config)
    encrypted_payload = cipher.encrypt(plaintext)

    documents = load_documents(config)
    normalized_title = title.strip()
    document_id = secrets.token_urlsafe(16)
    version = _next_document_version(documents, owner, normalized_title)
    stored_name = f"{document_id}.bin"
    stored_path = safe_file_path(stored_name, config["DOCUMENT_STORAGE_DIR"])
    stored_path.write_bytes(encrypted_payload)

    timestamp = datetime.now(timezone.utc).isoformat()
    content_type = (
        getattr(uploaded_file, "mimetype", None) or "application/octet-stream"
    ).split(";", 1)[0]

    metadata = {
        "id": document_id,
        "title": normalized_title,
        "owner": owner,
        "version": version,
        "filename": cleaned_name,
        "storage_name": stored_name,
        "content_type": content_type,
        "size_bytes": len(plaintext),
        "sha256": hashlib.sha256(plaintext).hexdigest(),
        "created_at": timestamp,
        "updated_at": timestamp,
    }
    documents.append(metadata)
    save_json(config["DOCUMENTS_FILE"], documents)

    access_log.log_event(
        "DOCUMENT_UPLOAD",
        owner,
        {
            "document_id": document_id,
            "filename": cleaned_name,
            "version": version,
        },
    )
    _append_audit_event(
        config,
        "DOCUMENT_UPLOAD",
        owner,
        {
            "document_id": document_id,
            "title": normalized_title,
            "filename": cleaned_name,
            "version": version,
        },
    )

    return metadata


def get_document_record(config, document_id: str) -> dict:
    for document in load_documents(config):
        if document.get("id") == document_id:
            return document
    raise FileNotFoundError("Document not found.")


def decrypt_document(config, document_id: str, user_id: str = "demo-user"):
    document = get_document_record(config, document_id)
    encrypted_path = safe_file_path(
        document["storage_name"], config["DOCUMENT_STORAGE_DIR"]
    )

    if not encrypted_path.exists():
        security_log.log_event(
            "DOCUMENT_MISSING",
            user_id,
            {"document_id": document_id, "storage_name": document["storage_name"]},
            severity="ERROR",
        )
        raise FileNotFoundError("Encrypted document payload is missing.")

    plaintext = _load_cipher(config).decrypt(encrypted_path.read_bytes())
    access_log.log_event(
        "DOCUMENT_DOWNLOAD",
        user_id,
        {"document_id": document_id, "filename": document["filename"]},
    )
    _append_audit_event(
        config,
        "DOCUMENT_DOWNLOAD",
        user_id,
        {"document_id": document_id, "filename": document["filename"]},
    )
    return document, plaintext
