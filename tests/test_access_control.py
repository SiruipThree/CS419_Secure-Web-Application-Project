import json
from io import BytesIO

from secure_app.access_control import (
    can_create_content,
    can_delete_document,
    can_delete_own_content,
    can_edit_document,
    can_edit_own_content,
    can_manage_users,
    can_view_all_content,
    can_view_document,
    can_view_shared_content,
)


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
    assert can_delete_document("admin", "viewer") is True

    assert can_view_document("user", "owner") is True
    assert can_edit_document("user", "owner") is True
    assert can_delete_document("user", "owner") is True

    assert can_view_document("user", "viewer") is True
    assert can_edit_document("user", "viewer") is False
    assert can_delete_document("user", "viewer") is False

    assert can_view_document("user", "editor") is True
    assert can_edit_document("user", "editor") is False
    assert can_delete_document("user", "editor") is False

    assert can_view_document("guest", "viewer") is True
    assert can_edit_document("guest", "owner") is False
    assert can_delete_document("guest", "owner") is False


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

    assert client.get("/shared").status_code == 200
    assert client.get("/dashboard").status_code == 403
    assert client.get("/upload").status_code == 403


def test_admin_can_access_admin_console_and_download_any_document(
    client,
    flask_app,
    login_as,
):
    login_as("owner_user")
    upload_response = client.post(
        "/upload",
        data={
            "title": "Admin Review",
            "document": (BytesIO(b"roadmap"), "roadmap.txt"),
        },
        content_type="multipart/form-data",
    )
    assert upload_response.status_code == 200

    document = json.loads(flask_app.config["DOCUMENTS_FILE"].read_text())[0]
    client.post("/logout")

    login_as("root_admin", role="admin")

    admin_response = client.get("/admin")
    download_response = client.get(f"/documents/{document['id']}/download")

    assert admin_response.status_code == 200
    assert b"owner_user" in admin_response.data
    assert download_response.status_code == 200
    assert download_response.data == b"roadmap"


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
            "document": (BytesIO(b"classified"), "plan.txt"),
        },
        content_type="multipart/form-data",
    )
    assert upload_response.status_code == 200

    document = json.loads(flask_app.config["DOCUMENTS_FILE"].read_text())[0]
    client.post("/logout")

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
            "document": (BytesIO(b"share me"), "handout.txt"),
        },
        content_type="multipart/form-data",
    )
    assert upload_response.status_code == 200

    document = json.loads(flask_app.config["DOCUMENTS_FILE"].read_text())[0]
    grant_share(document["id"], "guest", "viewer")
    client.post("/logout")

    login_as("visitor", role="guest")
    shared_response = client.get("/shared")
    download_response = client.get(f"/documents/{document['id']}/download")

    assert shared_response.status_code == 200
    assert b"Public Handout" in shared_response.data
    assert download_response.status_code == 200
    assert download_response.data == b"share me"


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
            "document": (BytesIO(b"download me"), "handout.txt"),
        },
        content_type="multipart/form-data",
    )
    assert upload_response.status_code == 200

    document = json.loads(flask_app.config["DOCUMENTS_FILE"].read_text())[0]
    client.post("/logout")

    download_response = client.get(f"/documents/{document['id']}/download")

    assert download_response.status_code == 302
    assert download_response.headers["Location"].endswith("/login")
