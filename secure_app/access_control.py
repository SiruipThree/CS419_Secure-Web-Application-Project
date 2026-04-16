from __future__ import annotations

"""Authorization helpers for system roles and document-level permissions."""

SYSTEM_ROLES = {"admin", "user", "guest"}
DOCUMENT_ROLES = {"owner", "editor", "viewer"}
GUEST_SHARE_PRINCIPALS = {"guest", "*"}
SYSTEM_PERMISSION_MATRIX = {
    "admin": {
        "create_content",
        "edit_own_content",
        "delete_own_content",
        "view_all_content",
        "manage_users",
        "view_shared_content",
    },
    "user": {
        "create_content",
        "edit_own_content",
        "delete_own_content",
        "view_shared_content",
    },
    "guest": {
        "view_shared_content",
    },
}

_DOCUMENT_ROLE_PRIORITY = {
    "viewer": 1,
    "editor": 2,
    "owner": 3,
}


def normalize_system_role(system_role: str | None) -> str:
    if system_role in SYSTEM_ROLES:
        return system_role
    return "guest"


def normalize_document_role(document_role: str | None) -> str | None:
    if document_role in DOCUMENT_ROLES:
        return document_role
    return None


def has_system_permission(system_role: str | None, permission: str) -> bool:
    normalized_system_role = normalize_system_role(system_role)
    return permission in SYSTEM_PERMISSION_MATRIX[normalized_system_role]


def higher_document_role(current_role: str | None, candidate_role: str | None) -> str | None:
    current = normalize_document_role(current_role)
    candidate = normalize_document_role(candidate_role)

    if current is None:
        return candidate
    if candidate is None:
        return current
    if _DOCUMENT_ROLE_PRIORITY[candidate] > _DOCUMENT_ROLE_PRIORITY[current]:
        return candidate
    return current


def is_authenticated(system_role: str | None, is_authenticated_user: bool = False) -> bool:
    return is_authenticated_user or normalize_system_role(system_role) in {"admin", "user"}


def can_access_dashboard(system_role: str) -> bool:
    return normalize_system_role(system_role) in {"admin", "user"}


def can_access_admin(system_role: str) -> bool:
    return normalize_system_role(system_role) == "admin"


def can_manage_users(system_role: str) -> bool:
    return has_system_permission(system_role, "manage_users")


def can_create_content(system_role: str) -> bool:
    return has_system_permission(system_role, "create_content")


def can_edit_own_content(system_role: str) -> bool:
    return has_system_permission(system_role, "edit_own_content")


def can_delete_own_content(system_role: str) -> bool:
    return has_system_permission(system_role, "delete_own_content")


def can_view_all_content(system_role: str) -> bool:
    return has_system_permission(system_role, "view_all_content")


def can_view_shared_content(system_role: str) -> bool:
    return has_system_permission(system_role, "view_shared_content")


def can_view_audit_events(system_role: str) -> bool:
    return normalize_system_role(system_role) in {"admin", "user"}


def can_view_document(system_role: str, document_role: str | None) -> bool:
    if can_view_all_content(system_role):
        return True
    return normalize_document_role(document_role) in DOCUMENT_ROLES


def can_edit_document(system_role: str, document_role: str | None) -> bool:
    if can_view_all_content(system_role):
        return True
    if not can_edit_own_content(system_role):
        return False
    return normalize_document_role(document_role) in {"owner", "editor"}


def can_download_document(system_role: str, document_role: str | None) -> bool:
    if not is_authenticated(system_role):
        return False
    return normalize_document_role(document_role) == "owner"


def can_delete_document(system_role: str, document_role: str | None) -> bool:
    if not can_delete_own_content(system_role):
        return False
    return normalize_document_role(document_role) == "owner"


def can_manage_document_shares(system_role: str, document_role: str | None) -> bool:
    if can_view_all_content(system_role):
        return True
    return normalize_document_role(document_role) == "owner"
