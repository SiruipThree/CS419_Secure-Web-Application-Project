import json
from io import BytesIO

from secure_app.access_control import (
    can_create_content,
    can_delete_document,
    can_delete_own_content,
    can_download_document,
    can_edit_document,
    can_edit_own_content,
    can_manage_users,
    can_view_all_content,
    can_view_document,
    can_view_shared_content,
)
from secure_app.storage import load_json


def _get_csrf(flask_app):
    sessions = load_json(flask_app.config["SESSIONS_FILE"], {})
    if not sessions:
        return ""
    return next(iter(sessions.values())).get("csrf_token", "")


def test_permission_matrix_matches_admin_user_guest_roles():
    assert can_create_content("admin") is True
    assert can_edit_own_content("admin") is True
    assert can_delete_own_content("admin") is True
    assert can_view_all_content("admin") is True
    assert can_manage_users("admin") is True
    assert can_view_shared_content("admin") is True

    assert can_create_content("user") is True
    assert can_edit_own_content("user") is True
    assert can_delete_own_content("user") is True
    assert can_view_all_content("user") is False
    assert can_manage_users("user") is False
    assert can_view_shared_content("user") is True

    assert can_create_content("guest") is False
    assert can_edit_own_content("guest") is False
    assert can_delete_own_content("guest") is False
    assert can_view_all_content("guest") is False
    assert can_manage_users("guest") is False
    assert can_view_shared_content("guest") is True


def test_document_permissions_respect_own_content_matrix():
    assert can_view_document("admin", None) is True
    assert can_edit_document("admin", "owner") is True
    assert can_delete_document("admin", "viewer") is False
    assert can_download_document("admin", "viewer") is False

    assert can_view_document("user", "owner") is True
    assert can_edit_document("user", "owner") is True
    assert can_delete_document("user", "owner") is True
    assert can_download_document("user", "owner") is True

    assert can_view_document("user", "viewer") is True
    assert can_edit_document("user", "viewer") is False
    assert can_delete_document("user", "viewer") is False
    assert can_download_document("user", "viewer") is False

    assert can_view_document("user", "editor") is True
    assert can_edit_document("user", "editor") is True
    assert can_delete_document("user", "editor") is False
    assert can_download_document("user", "editor") is False

    assert can_view_document("guest", "viewer") is True
    assert can_edit_document("guest", "owner") is False
    assert can_delete_document("guest", "owner") is False
    assert can_download_document("guest", "viewer") is False


def test_unauthenticated_users_are_redirected_to_login_for_protected_routes(client):
    for path in ("/dashboard", "/upload", "/admin", "/shared"):
        response = client.get(path)
        assert response.status_code == 302
        assert response.headers["Location"].endswith("/login")


def test_user_can_access_dashboard_but_not_admin(client, login_as):
    login_as("alice", role="user")

    dashboard_response = client.get("/dashboard")
    admin_response = client.get("/admin")

    assert dashboard_response.status_code == 200
    assert admin_response.status_code == 403


def test_logged_in_guest_is_limited_to_read_only_routes(client, login_as):
    login_as("visitor", role="guest")

    assert client.get("/documents").status_code == 200
    assert client.get("/shared").status_code == 302
    assert client.get("/dashboard").status_code == 403
    assert client.get("/upload").status_code == 403


def test_admin_can_access_admin_console_and_view_any_document(
    client,
    flask_app,
    login_as,
):
    login_as("owner_user")
    upload_response = client.post(
        "/upload",
        data={
            "title": "Admin Review",
            "document_type": "txt",
            "document": (BytesIO(b"roadmap"), "roadmap.txt"),
            "csrf_token": _get_csrf(flask_app),
        },
        content_type="multipart/form-data",
    )
    assert upload_response.status_code == 200

    document = json.loads(flask_app.config["DOCUMENTS_FILE"].read_text())[0]
    client.post("/logout", data={"csrf_token": _get_csrf(flask_app)})

    login_as("root_admin", role="admin")

    admin_response = client.get("/admin")
    view_response = client.get(f"/documents/{document['id']}/preview")
    download_response = client.get(f"/documents/{document['id']}/download")

    assert admin_response.status_code == 200
    assert b"owner_user" in admin_response.data
    assert view_response.status_code == 200
    assert download_response.status_code == 403


def test_admin_cannot_delete_document_they_do_not_own(client, flask_app, login_as):
    login_as("owner_user")
    upload_response = client.post(
        "/upload",
        data={
            "title": "Protected Doc",
            "document_type": "txt",
            "document": (BytesIO(b"cannot delete"), "protected.txt"),
            "csrf_token": _get_csrf(flask_app),
        },
        content_type="multipart/form-data",
    )
    assert upload_response.status_code == 200

    document = json.loads(flask_app.config["DOCUMENTS_FILE"].read_text())[0]
    client.post("/logout", data={"csrf_token": _get_csrf(flask_app)})

    login_as("root_admin", role="admin")
    response = client.post(
        f"/documents/{document['id']}/delete",
        data={"csrf_token": _get_csrf(flask_app)},
    )

    assert response.status_code == 403


def test_user_cannot_download_another_users_document_without_share(
    client,
    flask_app,
    login_as,
):
    login_as("owner_user")
    upload_response = client.post(
        "/upload",
        data={
            "title": "Private Plan",
            "document_type": "txt",
            "document": (BytesIO(b"classified"), "plan.txt"),
            "csrf_token": _get_csrf(flask_app),
        },
        content_type="multipart/form-data",
    )
    assert upload_response.status_code == 200

    document = json.loads(flask_app.config["DOCUMENTS_FILE"].read_text())[0]
    client.post("/logout", data={"csrf_token": _get_csrf(flask_app)})

    login_as("other_user")
    download_response = client.get(f"/documents/{document['id']}/download")

    assert download_response.status_code == 403


def test_guest_can_download_document_shared_to_guest(
    client,
    flask_app,
    grant_share,
    login_as,
):
    login_as("owner_user")
    upload_response = client.post(
        "/upload",
        data={
            "title": "Public Handout",
            "document_type": "txt",
            "document": (BytesIO(b"share me"), "handout.txt"),
            "csrf_token": _get_csrf(flask_app),
        },
        content_type="multipart/form-data",
    )
    assert upload_response.status_code == 200

    document = json.loads(flask_app.config["DOCUMENTS_FILE"].read_text())[0]
    grant_share(document["id"], "guest", "viewer")
    client.post("/logout", data={"csrf_token": _get_csrf(flask_app)})

    login_as("visitor", role="guest")
    shared_response = client.get("/documents")
    preview_response = client.get(f"/documents/{document['id']}/preview")
    download_response = client.get(f"/documents/{document['id']}/download")

    assert shared_response.status_code == 200
    assert b"Public Handout" in shared_response.data
    assert b"Shared With You" in shared_response.data
    assert preview_response.status_code == 200
    assert b"share me" in preview_response.data
    assert download_response.status_code == 403


def test_admin_documents_page_shows_all_uploaded_content(client, flask_app, login_as):
    login_as("alice")
    first_upload = client.post(
        "/upload",
        data={
            "title": "Alice Plan",
            "document_type": "txt",
            "document": (BytesIO(b"alice"), "alice.txt"),
            "csrf_token": _get_csrf(flask_app),
        },
        content_type="multipart/form-data",
    )
    assert first_upload.status_code == 200
    client.post("/logout", data={"csrf_token": _get_csrf(flask_app)})

    login_as("bob")
    second_upload = client.post(
        "/upload",
        data={
            "title": "Bob Plan",
            "document_type": "txt",
            "document": (BytesIO(b"bob"), "bob.txt"),
            "csrf_token": _get_csrf(flask_app),
        },
        content_type="multipart/form-data",
    )
    assert second_upload.status_code == 200
    client.post("/logout", data={"csrf_token": _get_csrf(flask_app)})

    login_as("root_admin", role="admin")
    response = client.get("/documents")

    assert response.status_code == 200
    assert b"Alice Plan" in response.data
    assert b"Bob Plan" in response.data
    assert b"All Documents" in response.data
    assert b"viewer access" in response.data


def test_documents_page_partitions_shared_sections(client, flask_app, login_as, make_user):
    login_as("owner_user")
    make_user("recipient_user")
    upload_response = client.post(
        "/upload",
        data={
            "title": "Outbound Plan",
            "document_type": "txt",
            "document": (BytesIO(b"outbound"), "outbound.txt"),
            "csrf_token": _get_csrf(flask_app),
        },
        content_type="multipart/form-data",
    )
    assert upload_response.status_code == 200

    document = json.loads(flask_app.config["DOCUMENTS_FILE"].read_text())[0]
    share_response = client.post(
        f"/documents/{document['id']}/share",
        data={
            "recipient_username": "recipient_user",
            "access_role": "viewer",
            "csrf_token": _get_csrf(flask_app),
        },
    )
    assert share_response.status_code == 200

    documents_response = client.get("/documents")
    assert documents_response.status_code == 200
    assert b"Available Documents" in documents_response.data
    assert b"Shared With You" in documents_response.data
    assert b"Shared With Others" in documents_response.data
    assert b"Recipient: recipient_user" in documents_response.data
    assert b"viewer access" in documents_response.data


def test_shared_document_preview_is_available_to_guest(client, flask_app, grant_share, login_as):
    login_as("owner_user")
    upload_response = client.post(
        "/upload",
        data={
            "title": "Shared Notes",
            "document_type": "txt",
            "document": (BytesIO(b"visible preview"), "shared.txt"),
            "csrf_token": _get_csrf(flask_app),
        },
        content_type="multipart/form-data",
    )
    assert upload_response.status_code == 200

    document = json.loads(flask_app.config["DOCUMENTS_FILE"].read_text())[0]
    grant_share(document["id"], "guest", "viewer")
    client.post("/logout", data={"csrf_token": _get_csrf(flask_app)})

    login_as("visitor", role="guest")
    documents_response = client.get("/documents")
    preview_response = client.get(f"/documents/{document['id']}/preview")

    assert documents_response.status_code == 200
    assert b"Documents" in documents_response.data
    assert b"Shared With You" in documents_response.data
    assert b"Shared Notes" in documents_response.data
    assert preview_response.status_code == 200
    assert b"visible preview" in preview_response.data


def test_shared_document_is_visible_to_named_user_after_owner_shares_it(
    client,
    flask_app,
    login_as,
    make_user,
):
    login_as("owner_user")
    make_user("recipient_user")
    upload_response = client.post(
        "/upload",
        data={
            "title": "Team Plan",
            "document_type": "txt",
            "document": (BytesIO(b"shared with recipient"), "team-plan.txt"),
            "csrf_token": _get_csrf(flask_app),
        },
        content_type="multipart/form-data",
    )
    assert upload_response.status_code == 200

    document = json.loads(flask_app.config["DOCUMENTS_FILE"].read_text())[0]
    share_response = client.post(
        f"/documents/{document['id']}/share",
        data={
            "recipient_username": "recipient_user",
            "access_role": "viewer",
            "csrf_token": _get_csrf(flask_app),
        },
    )
    assert share_response.status_code == 200
    client.post("/logout", data={"csrf_token": _get_csrf(flask_app)})

    login_response = client.post(
        "/login",
        data={"identifier": "recipient_user", "password": "StrongPass!123"},
        follow_redirects=False,
    )
    assert login_response.status_code == 302
    shared_response = client.get("/documents")
    preview_response = client.get(f"/documents/{document['id']}/preview")
    download_response = client.get(f"/documents/{document['id']}/download")

    assert shared_response.status_code == 200
    assert b"Team Plan" in shared_response.data
    assert b"Shared With You" in shared_response.data
    assert b"viewer access" in shared_response.data
    assert preview_response.status_code == 200
    assert b"shared with recipient" in preview_response.data
    assert download_response.status_code == 403


def test_editor_can_edit_shared_text_document_but_cannot_download(
    client,
    flask_app,
    grant_share,
    login_as,
):
    login_as("owner_user")
    upload_response = client.post(
        "/upload",
        data={
            "title": "Editable Shared Doc",
            "document_type": "txt",
            "document": (BytesIO(b"original content"), "editable.txt"),
            "csrf_token": _get_csrf(flask_app),
        },
        content_type="multipart/form-data",
    )
    assert upload_response.status_code == 200

    document = json.loads(flask_app.config["DOCUMENTS_FILE"].read_text())[0]
    grant_share(document["id"], "editor_user", "editor")
    client.post("/logout", data={"csrf_token": _get_csrf(flask_app)})

    login_as("editor_user")
    edit_page = client.get(f"/documents/{document['id']}/edit")
    assert edit_page.status_code == 200
    assert b"Document Content" in edit_page.data

    edit_response = client.post(
        f"/documents/{document['id']}/edit",
        data={
            "title": "Editor Revised",
            "content": "revised by editor",
            "csrf_token": _get_csrf(flask_app),
        },
    )
    assert edit_response.status_code == 200
    assert b"Document details updated successfully." in edit_response.data

    preview_response = client.get(f"/documents/{document['id']}/preview")
    download_response = client.get(f"/documents/{document['id']}/download")
    assert preview_response.status_code == 200
    assert b"revised by editor" in preview_response.data
    assert download_response.status_code == 403

    client.post("/logout", data={"csrf_token": _get_csrf(flask_app)})
    owner_login_response = client.post(
        "/login",
        data={"identifier": "owner_user", "password": "StrongPass!123"},
        follow_redirects=False,
    )
    assert owner_login_response.status_code == 302
    owner_preview = client.get(f"/documents/{document['id']}/preview")
    owner_download = client.get(f"/documents/{document['id']}/download")
    assert owner_preview.status_code == 200
    assert b"revised by editor" in owner_preview.data
    assert owner_download.status_code == 200
    assert owner_download.data == b"revised by editor"


def test_unauthenticated_download_redirects_to_login(
    client,
    flask_app,
    login_as,
):
    login_as("owner_user")
    upload_response = client.post(
        "/upload",
        data={
            "title": "Private Handout",
            "document_type": "txt",
            "document": (BytesIO(b"download me"), "handout.txt"),
            "csrf_token": _get_csrf(flask_app),
        },
        content_type="multipart/form-data",
    )
    assert upload_response.status_code == 200

    document = json.loads(flask_app.config["DOCUMENTS_FILE"].read_text())[0]
    client.post("/logout", data={"csrf_token": _get_csrf(flask_app)})

    download_response = client.get(f"/documents/{document['id']}/download")

    assert download_response.status_code == 302
    assert download_response.headers["Location"].endswith("/login")


def test_owner_dashboard_shows_edit_link_for_user_and_admin(client, flask_app, login_as):
    login_as("alice")
    upload_response = client.post(
        "/upload",
        data={
            "title": "Editable Doc",
            "document_type": "txt",
            "document": (BytesIO(b"owned"), "owned.txt"),
            "csrf_token": _get_csrf(flask_app),
        },
        content_type="multipart/form-data",
    )
    assert upload_response.status_code == 200

    user_dashboard = client.get("/dashboard")
    assert b"edit" in user_dashboard.data
    assert b"view" in user_dashboard.data
    assert b"#share-panel" in user_dashboard.data

    client.post("/logout", data={"csrf_token": _get_csrf(flask_app)})
    login_as("root_admin", role="admin")
    admin_dashboard = client.get("/dashboard")
    assert b"edit" not in admin_dashboard.data
    assert b"view" in admin_dashboard.data
    assert b"#share-panel" not in admin_dashboard.data

    admin_upload_response = client.post(
        "/upload",
        data={
            "title": "Admin Owned",
            "document_type": "txt",
            "document": (BytesIO(b"admin owned"), "admin-owned.txt"),
            "csrf_token": _get_csrf(flask_app),
        },
        content_type="multipart/form-data",
    )
    assert admin_upload_response.status_code == 200

    admin_dashboard = client.get("/dashboard")
    assert b"edit" in admin_dashboard.data
    assert b"view" in admin_dashboard.data
    assert b"#share-panel" in admin_dashboard.data


def test_admin_cannot_edit_document_they_do_not_own(client, flask_app, login_as):
    login_as("alice")
    upload_response = client.post(
        "/upload",
        data={
            "title": "Owned By Alice",
            "document_type": "txt",
            "document": (BytesIO(b"alice"), "alice.txt"),
            "csrf_token": _get_csrf(flask_app),
        },
        content_type="multipart/form-data",
    )
    assert upload_response.status_code == 200

    document = json.loads(flask_app.config["DOCUMENTS_FILE"].read_text())[0]
    client.post("/logout", data={"csrf_token": _get_csrf(flask_app)})

    login_as("root_admin", role="admin")
    response = client.get(f"/documents/{document['id']}/edit")

    assert response.status_code == 403
