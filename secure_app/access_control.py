"""Authorization helpers for system roles and document-level permissions."""

SYSTEM_ROLES = {"admin", "user", "guest"}
DOCUMENT_ROLES = {"owner", "editor", "viewer"}


def can_manage_users(system_role: str) -> bool:
    return system_role == "admin"


def can_create_content(system_role: str) -> bool:
    return system_role in {"admin", "user"}


def can_view_shared_content(system_role: str) -> bool:
    return system_role in {"admin", "user", "guest"}


def can_edit_document(document_role: str) -> bool:
    return document_role in {"owner", "editor"}


def can_view_document(document_role: str) -> bool:
    return document_role in DOCUMENT_ROLES
