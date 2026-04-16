from __future__ import annotations

import base64
import hashlib
import secrets
import zipfile
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
from xml.etree import ElementTree

from cryptography.fernet import Fernet

from secure_app.access_control import (
    GUEST_SHARE_PRINCIPALS,
    can_delete_document,
    can_download_document,
    can_edit_document,
    can_edit_own_content,
    can_manage_document_shares,
    can_view_document,
    higher_document_role,
    normalize_document_role,
    normalize_system_role,
)
from secure_app.logging_utils import access_log, security_log
from secure_app.security import (
    safe_file_path,
    validate_document_title,
    validate_uploaded_file,
)
from secure_app.storage import load_json, save_json


def load_documents(config):
    return load_json(config["DOCUMENTS_FILE"], [])


def load_shares(config):
    return load_json(config["SHARES_FILE"], [])


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
    user_id: str | None,
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


def load_recent_audit_events(
    config,
    limit: int = 10,
    user_id: str | None = None,
) -> list[dict]:
    events = load_json(config["AUDIT_FILE"], [])
    if user_id is not None:
        events = [event for event in events if event.get("user_id") == user_id]
    return list(reversed(events[-limit:]))


def list_recent_documents(config, owner: str | None = None, limit: int = 10) -> list[dict]:
    documents = load_documents(config)
    if owner is not None:
        documents = [document for document in documents if document.get("owner") == owner]
    return list(reversed(documents[-limit:]))


def _share_applies_to_user(share: dict, user_id: str | None, system_role: str) -> bool:
    principal = share.get("principal")
    if principal == user_id and user_id:
        return True
    if principal in GUEST_SHARE_PRINCIPALS:
        return True
    if principal == "authenticated":
        return normalize_system_role(system_role) in {"admin", "user"}
    return False


def get_document_role(
    config,
    document: dict,
    user_id: str | None = None,
    system_role: str = "guest",
) -> str | None:
    if user_id and document.get("owner") == user_id:
        return "owner"

    resolved_role = None
    for share in load_shares(config):
        if share.get("document_id") != document.get("id"):
            continue
        if not _share_applies_to_user(share, user_id, system_role):
            continue
        resolved_role = higher_document_role(resolved_role, share.get("role"))
    return normalize_document_role(resolved_role)


def list_document_shares(config, document_id: str) -> list[dict]:
    shares = [
        share
        for share in load_shares(config)
        if share.get("document_id") == document_id
    ]
    return sorted(shares, key=lambda share: (share.get("principal", ""), share.get("role", "")))


def list_shared_documents(
    config,
    user_id: str | None = None,
    system_role: str = "guest",
    limit: int = 10,
) -> list[dict]:
    visible_documents = []
    normalized_system_role = normalize_system_role(system_role)

    for document in load_documents(config):
        document_role = get_document_role(config, document, user_id, normalized_system_role)
        if not can_view_document(normalized_system_role, document_role):
            continue
        if normalized_system_role != "admin" and user_id and document.get("owner") == user_id:
            continue

        visible_documents.append(
            {
                **document,
                "document_role": document_role or "viewer",
            }
        )

    return list(reversed(visible_documents[-limit:]))


def list_owned_documents(
    config,
    owner: str | None = None,
    limit: int = 10,
) -> list[dict]:
    if not owner:
        return []

    visible_documents = []
    for document in load_documents(config):
        if document.get("owner") != owner:
            continue
        visible_documents.append(
            {
                **document,
                "document_role": "owner",
            }
        )
    return list(reversed(visible_documents[-limit:]))


def list_outbound_document_shares(
    config,
    owner: str | None = None,
    limit: int = 50,
) -> list[dict]:
    if not owner:
        return []

    owned_documents = {
        document.get("id"): document
        for document in load_documents(config)
        if document.get("owner") == owner
    }

    outbound_shares = []
    for share in load_shares(config):
        document = owned_documents.get(share.get("document_id"))
        if document is None:
            continue
        outbound_shares.append(
            {
                "document_id": document["id"],
                "title": document["title"],
                "document_type": document.get("document_type", ""),
                "recipient": share.get("principal"),
                "role": share.get("role"),
            }
        )
    return list(reversed(outbound_shares[-limit:]))


def list_visible_documents(
    config,
    user_id: str | None = None,
    system_role: str = "guest",
) -> list[dict]:
    normalized_system_role = normalize_system_role(system_role)
    documents = load_documents(config)
    if normalized_system_role == "admin":
        visible_documents = []
        for document in documents:
            document_role = get_document_role(
                config,
                document,
                user_id=user_id,
                system_role=normalized_system_role,
            )
            visible_documents.append(
                {
                    **document,
                    "document_role": document_role or "viewer",
                }
            )
        return list(reversed(visible_documents))
    return list_shared_documents(
        config,
        user_id=user_id,
        system_role=normalized_system_role,
        limit=len(documents) or 10,
    )


def store_encrypted_document(
    config,
    title: str,
    document_type: str,
    uploaded_file,
    owner: str = "demo-user",
):
    plaintext = uploaded_file.read()

    is_valid_title, title_message = validate_document_title(
        title, config["DOCUMENT_TITLE_MAX_LENGTH"]
    )
    if not is_valid_title:
        raise ValueError(title_message)

    is_valid_file, file_message, cleaned_name = validate_uploaded_file(
        uploaded_file.filename or "",
        document_type,
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
        "document_type": document_type.strip().lower(),
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


def authorize_document_access(
    config,
    document_id: str,
    user_id: str | None = None,
    system_role: str = "guest",
    require_edit: bool = False,
) -> tuple[dict, str | None]:
    document = get_document_record(config, document_id)
    document_role = get_document_role(config, document, user_id, system_role)
    allowed = (
        can_edit_document(system_role, document_role)
        if require_edit
        else can_view_document(system_role, document_role)
    )
    if allowed:
        return document, document_role

    security_log.log_event(
        "DOCUMENT_ACCESS_DENIED",
        user_id,
        {
            "document_id": document_id,
            "system_role": normalize_system_role(system_role),
            "document_role": document_role,
            "require_edit": require_edit,
        },
        severity="WARNING",
    )
    raise PermissionError("You do not have access to this document.")


def authorize_document_download(
    config,
    document_id: str,
    user_id: str | None = None,
    system_role: str = "guest",
):
    document = get_document_record(config, document_id)
    document_role = get_document_role(config, document, user_id, system_role)
    if can_download_document(system_role, document_role):
        return document, document_role

    security_log.log_event(
        "DOCUMENT_DOWNLOAD_DENIED",
        user_id,
        {
            "document_id": document_id,
            "system_role": normalize_system_role(system_role),
            "document_role": document_role,
        },
        severity="WARNING",
    )
    raise PermissionError("You do not have permission to download this document.")


def authorize_document_delete(
    config,
    document_id: str,
    user_id: str | None = None,
    system_role: str = "guest",
):
    document = get_document_record(config, document_id)
    document_role = get_document_role(config, document, user_id, system_role)
    if can_delete_document(system_role, document_role):
        return document

    security_log.log_event(
        "DOCUMENT_DELETE_DENIED",
        user_id,
        {
            "document_id": document_id,
            "system_role": normalize_system_role(system_role),
            "document_role": document_role,
        },
        severity="WARNING",
    )
    raise PermissionError("You do not have permission to delete this document.")


def decrypt_document(
    config,
    document_id: str,
    user_id: str | None = None,
    system_role: str = "guest",
):
    document, document_role = authorize_document_download(
        config,
        document_id,
        user_id=user_id,
        system_role=system_role,
    )
    plaintext = load_document_plaintext(config, document, user_id=user_id)
    access_log.log_event(
        "DOCUMENT_DOWNLOAD",
        user_id,
        {
            "document_id": document_id,
            "filename": document["filename"],
            "document_role": document_role or normalize_system_role(system_role),
        },
    )
    _append_audit_event(
        config,
        "DOCUMENT_DOWNLOAD",
        user_id,
        {"document_id": document_id, "filename": document["filename"]},
    )
    return document, plaintext


def load_document_plaintext(config, document: dict, user_id: str | None = None) -> bytes:
    encrypted_path = safe_file_path(
        document["storage_name"], config["DOCUMENT_STORAGE_DIR"]
    )

    if not encrypted_path.exists():
        security_log.log_event(
            "DOCUMENT_MISSING",
            user_id,
            {
                "document_id": document.get("id"),
                "storage_name": document["storage_name"],
            },
            severity="ERROR",
        )
        raise FileNotFoundError("Encrypted document payload is missing.")

    return _load_cipher(config).decrypt(encrypted_path.read_bytes())


def build_document_preview(document: dict, plaintext: bytes) -> dict:
    document_type = (document.get("document_type") or "").lower()
    preview = {
        "kind": "unsupported",
        "content": "",
        "embed_src": "",
        "message": "Preview is not available for this file type.",
        "truncated": False,
    }

    if document_type == "txt":
        text = plaintext.decode("utf-8", errors="replace")
        preview["kind"] = "text"
        preview["content"] = text
        preview["truncated"] = False
        preview["message"] = "Showing the document content."
        return preview

    if document_type == "docx":
        text = _extract_docx_text(plaintext)
        if text:
            preview["kind"] = "text"
            preview["content"] = text
            preview["truncated"] = False
            preview["message"] = "Showing extracted text from the Word document."
        else:
            preview["message"] = "No previewable text could be extracted from this Word document."
        return preview

    if document_type in {"png", "jpg", "jpeg"}:
        preview["kind"] = "image"
        preview["embed_src"] = _data_uri(document.get("content_type", "application/octet-stream"), plaintext)
        preview["message"] = "Showing an inline image preview."
        return preview

    if document_type == "pdf":
        preview["kind"] = "beta"
        preview["message"] = "Previews are currently unavailable for PDF documents."
        return preview

    return preview


def _data_uri(content_type: str, payload: bytes) -> str:
    encoded = base64.b64encode(payload).decode("ascii")
    return f"data:{content_type};base64,{encoded}"


def _extract_docx_text(payload: bytes) -> str:
    try:
        with zipfile.ZipFile(BytesIO(payload)) as archive:
            document_xml = archive.read("word/document.xml")
    except (KeyError, zipfile.BadZipFile):
        return ""

    try:
        root = ElementTree.fromstring(document_xml)
    except ElementTree.ParseError:
        return ""

    namespace = {"w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main"}
    paragraphs = []
    for paragraph in root.findall(".//w:p", namespace):
        fragments = [
            node.text.strip()
            for node in paragraph.findall(".//w:t", namespace)
            if node.text and node.text.strip()
        ]
        if fragments:
            paragraphs.append("".join(fragments))
    return "\n".join(paragraphs)


def authorize_owned_document_edit(
    config,
    document_id: str,
    user_id: str | None = None,
    system_role: str = "guest",
):
    document, document_role = authorize_document_access(
        config,
        document_id,
        user_id=user_id,
        system_role=system_role,
        require_edit=True,
    )
    normalized_system_role = normalize_system_role(system_role)
    normalized_document_role = normalize_document_role(document_role)
    if (
        normalized_system_role not in {"admin", "user"}
        or not can_edit_own_content(normalized_system_role)
        or normalized_document_role not in {"owner", "editor"}
    ):
        security_log.log_event(
            "DOCUMENT_EDIT_DENIED",
            user_id,
            {
                "document_id": document_id,
                "system_role": normalized_system_role,
                "document_role": document_role,
            },
            severity="WARNING",
        )
        raise PermissionError("You do not have permission to edit this document.")
    return document


def authorize_document_share_management(
    config,
    document_id: str,
    user_id: str | None = None,
    system_role: str = "guest",
):
    document = get_document_record(config, document_id)
    document_role = get_document_role(config, document, user_id, system_role)
    if can_manage_document_shares(system_role, document_role):
        return document

    security_log.log_event(
        "DOCUMENT_SHARE_DENIED",
        user_id,
        {
            "document_id": document_id,
            "system_role": normalize_system_role(system_role),
            "document_role": document_role,
        },
        severity="WARNING",
    )
    raise PermissionError("You do not have permission to share this document.")


def share_document_with_user(
    config,
    document_id: str,
    recipient_username: str,
    access_role: str = "viewer",
    user_id: str | None = None,
    system_role: str = "guest",
):
    normalized_access_role = (access_role or "").strip().lower()
    if normalized_access_role not in {"viewer", "editor"}:
        raise ValueError("Select a valid access level.")
    normalized_recipient = (recipient_username or "").strip()
    if not normalized_recipient:
        raise ValueError("Enter a username to share the document with.")
    document = get_document_record(config, document_id)
    document_role = get_document_role(config, document, user_id, system_role)

    can_return_to_owner = (
        normalize_document_role(document_role) == "editor"
        and normalized_recipient == document.get("owner")
    )
    if not can_return_to_owner:
        document = authorize_document_share_management(
            config,
            document_id,
            user_id=user_id,
            system_role=system_role,
        )
    if user_id and normalized_recipient == user_id:
        raise ValueError("You already have access to this document.")
    if normalized_recipient == document.get("owner"):
        if can_return_to_owner:
            access_log.log_event(
                "DOCUMENT_RETURNED_TO_OWNER",
                user_id,
                {
                    "document_id": document_id,
                    "owner": normalized_recipient,
                },
            )
            _append_audit_event(
                config,
                "DOCUMENT_RETURNED_TO_OWNER",
                user_id,
                {
                    "document_id": document_id,
                    "owner": normalized_recipient,
                },
            )
            return {
                "document_id": document_id,
                "principal": normalized_recipient,
                "role": "owner",
            }
        raise ValueError("The document owner already has access.")

    shares = load_shares(config)
    for share in shares:
        if (
            share.get("document_id") == document_id
            and share.get("principal") == normalized_recipient
        ):
            share["role"] = normalized_access_role
            save_json(config["SHARES_FILE"], shares)
            access_log.log_event(
                "DOCUMENT_SHARED",
                user_id,
                {
                    "document_id": document_id,
                    "recipient": normalized_recipient,
                    "role": normalized_access_role,
                },
            )
            _append_audit_event(
                config,
                "DOCUMENT_SHARED",
                user_id,
                {
                    "document_id": document_id,
                    "recipient": normalized_recipient,
                    "role": normalized_access_role,
                },
            )
            return share

    new_share = {
        "document_id": document_id,
        "principal": normalized_recipient,
        "role": normalized_access_role,
    }
    shares.append(new_share)
    save_json(config["SHARES_FILE"], shares)
    access_log.log_event(
        "DOCUMENT_SHARED",
        user_id,
        {
            "document_id": document_id,
            "recipient": normalized_recipient,
            "role": normalized_access_role,
        },
    )
    _append_audit_event(
        config,
        "DOCUMENT_SHARED",
        user_id,
        {
            "document_id": document_id,
            "recipient": normalized_recipient,
            "role": normalized_access_role,
        },
    )
    return new_share


def update_document_title(
    config,
    document_id: str,
    title: str,
    user_id: str | None = None,
    system_role: str = "guest",
):
    document = authorize_owned_document_edit(
        config,
        document_id,
        user_id=user_id,
        system_role=system_role,
    )
    is_valid_title, title_message = validate_document_title(
        title, config["DOCUMENT_TITLE_MAX_LENGTH"]
    )
    if not is_valid_title:
        raise ValueError(title_message)

    normalized_title = title.strip()
    timestamp = datetime.now(timezone.utc).isoformat()
    documents = load_documents(config)

    for index, candidate in enumerate(documents):
        if candidate.get("id") != document_id:
            continue
        updated_document = {
            **candidate,
            "title": normalized_title,
            "updated_at": timestamp,
        }
        documents[index] = updated_document
        save_json(config["DOCUMENTS_FILE"], documents)
        access_log.log_event(
            "DOCUMENT_EDIT",
            user_id,
            {
                "document_id": document_id,
                "title": normalized_title,
            },
        )
        _append_audit_event(
            config,
            "DOCUMENT_EDIT",
            user_id,
            {
                "document_id": document_id,
                "title": normalized_title,
            },
        )
        return updated_document

    raise FileNotFoundError("Document not found.")


def document_supports_inline_editing(document: dict) -> bool:
    return (document.get("document_type") or "").lower() == "txt"


def load_editable_document_content(document: dict, plaintext: bytes) -> str:
    if not document_supports_inline_editing(document):
        return ""
    return plaintext.decode("utf-8", errors="replace")


def update_document_content(
    config,
    document_id: str,
    title: str,
    content: str,
    user_id: str | None = None,
    system_role: str = "guest",
):
    document = authorize_owned_document_edit(
        config,
        document_id,
        user_id=user_id,
        system_role=system_role,
    )
    is_valid_title, title_message = validate_document_title(
        title, config["DOCUMENT_TITLE_MAX_LENGTH"]
    )
    if not is_valid_title:
        raise ValueError(title_message)

    normalized_title = title.strip()
    timestamp = datetime.now(timezone.utc).isoformat()
    documents = load_documents(config)
    plaintext = None
    if document_supports_inline_editing(document):
        plaintext = (content or "").encode("utf-8")
        encrypted_payload = _load_cipher(config).encrypt(plaintext)
        stored_path = safe_file_path(document["storage_name"], config["DOCUMENT_STORAGE_DIR"])
        stored_path.write_bytes(encrypted_payload)

    for index, candidate in enumerate(documents):
        if candidate.get("id") != document_id:
            continue
        updated_document = {
            **candidate,
            "title": normalized_title,
            "updated_at": timestamp,
        }
        if plaintext is not None:
            updated_document["size_bytes"] = len(plaintext)
            updated_document["sha256"] = hashlib.sha256(plaintext).hexdigest()
        documents[index] = updated_document
        save_json(config["DOCUMENTS_FILE"], documents)
        access_log.log_event(
            "DOCUMENT_EDIT",
            user_id,
            {
                "document_id": document_id,
                "title": normalized_title,
            },
        )
        _append_audit_event(
            config,
            "DOCUMENT_EDIT",
            user_id,
            {
                "document_id": document_id,
                "title": normalized_title,
            },
        )
        return updated_document

    raise FileNotFoundError("Document not found.")


def permanently_delete_document(
    config,
    document_id: str,
    user_id: str | None = None,
    system_role: str = "guest",
):
    document = authorize_document_delete(
        config,
        document_id,
        user_id=user_id,
        system_role=system_role,
    )

    documents = [
        candidate
        for candidate in load_documents(config)
        if candidate.get("id") != document_id
    ]
    save_json(config["DOCUMENTS_FILE"], documents)

    shares = [
        share
        for share in load_shares(config)
        if share.get("document_id") != document_id
    ]
    save_json(config["SHARES_FILE"], shares)

    encrypted_path = safe_file_path(
        document["storage_name"], config["DOCUMENT_STORAGE_DIR"]
    )
    if encrypted_path.exists():
        encrypted_path.unlink()

    access_log.log_event(
        "DOCUMENT_DELETE",
        user_id,
        {
            "document_id": document_id,
            "filename": document["filename"],
        },
    )
    _append_audit_event(
        config,
        "DOCUMENT_DELETE",
        user_id,
        {
            "document_id": document_id,
            "filename": document["filename"],
            "title": document["title"],
        },
    )
    return document
