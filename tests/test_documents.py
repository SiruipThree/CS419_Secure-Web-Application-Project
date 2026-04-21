import json
from io import BytesIO

from secure_app.storage import load_json


def _get_csrf(flask_app):
    sessions = load_json(flask_app.config["SESSIONS_FILE"], {})
    if not sessions:
        return ""
    return next(iter(sessions.values())).get("csrf_token", "")


def _read_security_events(log_file):
    events = []
    for line in log_file.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        events.append(json.loads(line.split(" - ", 2)[2]))
    return events


def test_upload_rejects_invalid_extension(client, flask_app, login_as):
    login_as("alice")
    flask_app.config["SECURITY_LOG_FILE"].write_text("", encoding="utf-8")

    response = client.post(
        "/upload",
        data={
            "title": "Quarterly Plan",
            "document_type": "pdf",
            "document": (BytesIO(b"malicious payload"), "../../payload.exe"),
            "csrf_token": _get_csrf(flask_app),
        },
        content_type="multipart/form-data",
    )

    assert response.status_code == 400
    assert b"File type is not allowed." in response.data

    events = _read_security_events(flask_app.config["SECURITY_LOG_FILE"])
    assert any(
        event["event_type"] == "UPLOAD_VALIDATION_FAILED"
        and event["user_id"] == "alice"
        and event["details"]["reason"] == "File type is not allowed."
        for event in events
    )


def test_upload_rejects_legacy_doc_extension(client, flask_app, login_as):
    login_as("alice")

    response = client.post(
        "/upload",
        data={
            "title": "Legacy Word File",
            "document_type": "docx",
            "document": (BytesIO(b"legacy payload"), "report.doc"),
            "csrf_token": _get_csrf(flask_app),
        },
        content_type="multipart/form-data",
    )

    assert response.status_code == 400
    assert b"File type is not allowed." in response.data


def test_upload_rejects_content_signature_mismatch(client, flask_app, login_as):
    login_as("alice")

    response = client.post(
        "/upload",
        data={
            "title": "Fake PDF",
            "document_type": "pdf",
            "document": (BytesIO(b"not a pdf"), "report.pdf"),
            "csrf_token": _get_csrf(flask_app),
        },
        content_type="multipart/form-data",
    )

    assert response.status_code == 400
    assert b"Uploaded file contents do not match the selected file type." in response.data


def test_upload_requires_document_type_selection(client, flask_app, login_as):
    login_as("alice")

    response = client.post(
        "/upload",
        data={
            "title": "Untyped Upload",
            "document": (BytesIO(b"hello"), "notes.txt"),
            "csrf_token": _get_csrf(flask_app),
        },
        content_type="multipart/form-data",
    )

    assert response.status_code == 400
    assert b"Select a document type." in response.data


def test_upload_rejects_selected_type_mismatch(client, flask_app, login_as):
    login_as("alice")

    response = client.post(
        "/upload",
        data={
            "title": "Wrong Type",
            "document_type": "pdf",
            "document": (BytesIO(b"hello"), "notes.txt"),
            "csrf_token": _get_csrf(flask_app),
        },
        content_type="multipart/form-data",
    )

    assert response.status_code == 400
    assert b"Uploaded file extension does not match the selected document type." in response.data


def test_upload_rejects_eicar_test_signature(client, flask_app, login_as):
    login_as("alice")

    response = client.post(
        "/upload",
        data={
            "title": "Suspicious File",
            "document_type": "txt",
            "document": (
                BytesIO(
                    b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$"
                    b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
                ),
                "eicar.txt",
            ),
            "csrf_token": _get_csrf(flask_app),
        },
        content_type="multipart/form-data",
    )

    assert response.status_code == 400
    assert b"Uploaded file matched a malware test signature." in response.data


def test_upload_encrypts_file_and_download_restores_plaintext(client, flask_app, login_as):
    login_as("alice")
    plaintext = b"Top secret launch plan"

    response = client.post(
        "/upload",
        data={
            "title": "Launch Plan",
            "document_type": "txt",
            "document": (BytesIO(plaintext), "launch-plan.txt"),
            "csrf_token": _get_csrf(flask_app),
        },
        content_type="multipart/form-data",
    )

    assert response.status_code == 200
    assert b"Encrypted upload stored successfully" in response.data

    documents = json.loads(flask_app.config["DOCUMENTS_FILE"].read_text())
    assert len(documents) == 1

    document = documents[0]
    assert document["document_type"] == "txt"
    assert document["version"] == 1
    assert len(document["version_history"]) == 1
    assert document["version_history"][0]["version"] == 1
    encrypted_payload = (
        flask_app.config["DOCUMENT_STORAGE_DIR"] / document["storage_name"]
    ).read_bytes()

    assert plaintext not in encrypted_payload

    download_response = client.get(f"/documents/{document['id']}/download")
    assert download_response.status_code == 200
    assert download_response.data == plaintext
    assert download_response.headers["Content-Type"].startswith("text/plain")

    audit_events = json.loads(flask_app.config["AUDIT_FILE"].read_text())
    assert [event["event_type"] for event in audit_events] == [
        "DOCUMENT_UPLOAD",
        "DOCUMENT_DOWNLOAD",
    ]


def test_upload_too_large_returns_413(client, flask_app, login_as):
    login_as("alice")
    flask_app.config["MAX_CONTENT_LENGTH"] = 32

    response = client.post(
        "/upload",
        data={
            "title": "Large File",
            "document_type": "txt",
            "document": (BytesIO(b"a" * 512), "large.txt"),
            "csrf_token": _get_csrf(flask_app),
        },
        content_type="multipart/form-data",
    )

    assert response.status_code == 413


def test_owner_can_edit_document_title_from_edit_route(client, flask_app, login_as):
    login_as("alice")

    upload_response = client.post(
        "/upload",
        data={
            "title": "Original Title",
            "document_type": "txt",
            "document": (BytesIO(b"edit me"), "notes.txt"),
            "csrf_token": _get_csrf(flask_app),
        },
        content_type="multipart/form-data",
    )
    assert upload_response.status_code == 200

    document = json.loads(flask_app.config["DOCUMENTS_FILE"].read_text())[0]

    edit_page = client.get(f"/documents/{document['id']}/edit")
    assert edit_page.status_code == 200
    assert b"Original Title" in edit_page.data

    response = client.post(
        f"/documents/{document['id']}/edit",
        data={
            "title": "Updated Title",
            "content": "Updated body",
            "csrf_token": _get_csrf(flask_app),
        },
    )

    assert response.status_code == 200
    assert b"Document details updated successfully." in response.data

    updated_document = json.loads(flask_app.config["DOCUMENTS_FILE"].read_text())[0]
    assert updated_document["title"] == "Updated Title"
    assert updated_document["version"] == 2
    assert len(updated_document["version_history"]) == 2
    assert [entry["version"] for entry in updated_document["version_history"]] == [1, 2]

    download_response = client.get(f"/documents/{document['id']}/download")
    assert download_response.status_code == 200
    assert download_response.data == b"Updated body"

    original_version_download = client.get(
        f"/documents/{document['id']}/versions/1/download"
    )
    assert original_version_download.status_code == 200
    assert original_version_download.data == b"edit me"

    audit_events = json.loads(flask_app.config["AUDIT_FILE"].read_text())
    assert [event["event_type"] for event in audit_events] == [
        "DOCUMENT_UPLOAD",
        "DOCUMENT_EDIT",
        "DOCUMENT_DOWNLOAD",
        "DOCUMENT_DOWNLOAD",
    ]


def test_owner_can_edit_title_for_non_text_document(client, flask_app, login_as):
    login_as("alice")

    upload_response = client.post(
        "/upload",
        data={
            "title": "Original PDF Title",
            "document_type": "pdf",
            "document": (BytesIO(b"%PDF-1.7\nplaceholder"), "report.pdf"),
            "csrf_token": _get_csrf(flask_app),
        },
        content_type="multipart/form-data",
    )
    assert upload_response.status_code == 200

    document = json.loads(flask_app.config["DOCUMENTS_FILE"].read_text())[0]
    encrypted_before = (
        flask_app.config["DOCUMENT_STORAGE_DIR"] / document["storage_name"]
    ).read_bytes()

    response = client.post(
        f"/documents/{document['id']}/edit",
        data={
            "title": "Renamed PDF Title",
            "content": "",
            "csrf_token": _get_csrf(flask_app),
        },
    )

    assert response.status_code == 200
    assert b"Document details updated successfully." in response.data

    updated_document = json.loads(flask_app.config["DOCUMENTS_FILE"].read_text())[0]
    assert updated_document["title"] == "Renamed PDF Title"
    assert updated_document["version"] == 2
    assert len(updated_document["version_history"]) == 2
    assert updated_document["storage_name"] != document["storage_name"]
    encrypted_after = (
        flask_app.config["DOCUMENT_STORAGE_DIR"] / updated_document["storage_name"]
    ).read_bytes()
    assert encrypted_after != encrypted_before
    assert (
        flask_app.config["DOCUMENT_STORAGE_DIR"] / document["storage_name"]
    ).exists()

    latest_download = client.get(f"/documents/{document['id']}/download")
    assert latest_download.status_code == 200
    assert latest_download.data == b"%PDF-1.7\nplaceholder"

    original_version_download = client.get(
        f"/documents/{document['id']}/versions/1/download"
    )
    assert original_version_download.status_code == 200
    assert original_version_download.data == b"%PDF-1.7\nplaceholder"


def test_owner_can_upload_new_binary_version_for_existing_document(
    client,
    flask_app,
    login_as,
):
    login_as("alice")

    upload_response = client.post(
        "/upload",
        data={
            "title": "Quarterly Report",
            "document_type": "pdf",
            "document": (BytesIO(b"%PDF-1.7\nversion one"), "report-v1.pdf"),
            "csrf_token": _get_csrf(flask_app),
        },
        content_type="multipart/form-data",
    )
    assert upload_response.status_code == 200

    document = json.loads(flask_app.config["DOCUMENTS_FILE"].read_text())[0]
    original_storage_name = document["storage_name"]

    version_page = client.get(f"/documents/{document['id']}/versions/upload")
    assert version_page.status_code == 200
    assert b"Upload New Version" in version_page.data

    revision_response = client.post(
        f"/documents/{document['id']}/versions/upload",
        data={
            "title": "Quarterly Report Revised",
            "document": (BytesIO(b"%PDF-1.7\nversion two"), "report-v2.pdf"),
            "csrf_token": _get_csrf(flask_app),
        },
        content_type="multipart/form-data",
    )
    assert revision_response.status_code == 200
    assert b"New document version uploaded successfully as version 2." in revision_response.data

    updated_document = json.loads(flask_app.config["DOCUMENTS_FILE"].read_text())[0]
    assert updated_document["id"] == document["id"]
    assert updated_document["title"] == "Quarterly Report Revised"
    assert updated_document["filename"] == "report-v2.pdf"
    assert updated_document["version"] == 2
    assert len(updated_document["version_history"]) == 2
    assert [entry["version"] for entry in updated_document["version_history"]] == [1, 2]
    assert updated_document["storage_name"] != original_storage_name
    assert (
        flask_app.config["DOCUMENT_STORAGE_DIR"] / original_storage_name
    ).exists()

    latest_download = client.get(f"/documents/{document['id']}/download")
    assert latest_download.status_code == 200
    assert latest_download.data == b"%PDF-1.7\nversion two"

    original_version_download = client.get(
        f"/documents/{document['id']}/versions/1/download"
    )
    assert original_version_download.status_code == 200
    assert original_version_download.data == b"%PDF-1.7\nversion one"

    audit_events = json.loads(flask_app.config["AUDIT_FILE"].read_text())
    assert [event["event_type"] for event in audit_events] == [
        "DOCUMENT_UPLOAD",
        "DOCUMENT_VERSION_UPLOAD",
        "DOCUMENT_DOWNLOAD",
        "DOCUMENT_DOWNLOAD",
    ]


def test_editor_can_upload_new_version_for_shared_document(
    client,
    flask_app,
    login_as,
    make_user,
):
    login_as("alice")
    make_user("carol")

    upload_response = client.post(
        "/upload",
        data={
            "title": "Shared PDF",
            "document_type": "pdf",
            "document": (BytesIO(b"%PDF-1.7\nowner draft"), "shared-v1.pdf"),
            "csrf_token": _get_csrf(flask_app),
        },
        content_type="multipart/form-data",
    )
    assert upload_response.status_code == 200

    document = json.loads(flask_app.config["DOCUMENTS_FILE"].read_text())[0]
    share_response = client.post(
        f"/documents/{document['id']}/share",
        data={
            "recipient_username": "carol",
            "access_role": "editor",
            "csrf_token": _get_csrf(flask_app),
        },
    )
    assert share_response.status_code == 200

    client.post("/logout", data={"csrf_token": _get_csrf(flask_app)})
    login_response = client.post(
        "/login",
        data={"identifier": "carol", "password": "StrongPass!123"},
        follow_redirects=False,
    )
    assert login_response.status_code == 302

    version_page = client.get(f"/documents/{document['id']}/versions/upload")
    assert version_page.status_code == 200

    revision_response = client.post(
        f"/documents/{document['id']}/versions/upload",
        data={
            "title": "Editor Revised PDF",
            "document": (BytesIO(b"%PDF-1.7\neditor revision"), "shared-v2.pdf"),
            "csrf_token": _get_csrf(flask_app),
        },
        content_type="multipart/form-data",
    )
    assert revision_response.status_code == 200

    editor_download = client.get(f"/documents/{document['id']}/download")
    assert editor_download.status_code == 200
    assert editor_download.data == b"%PDF-1.7\neditor revision"

    client.post("/logout", data={"csrf_token": _get_csrf(flask_app)})
    owner_login_response = client.post(
        "/login",
        data={"identifier": "alice", "password": "StrongPass!123"},
        follow_redirects=False,
    )
    assert owner_login_response.status_code == 302

    owner_download = client.get(f"/documents/{document['id']}/download")
    assert owner_download.status_code == 200
    assert owner_download.data == b"%PDF-1.7\neditor revision"

    original_version_download = client.get(
        f"/documents/{document['id']}/versions/1/download"
    )
    assert original_version_download.status_code == 200
    assert original_version_download.data == b"%PDF-1.7\nowner draft"

    updated_document = json.loads(flask_app.config["DOCUMENTS_FILE"].read_text())[0]
    assert updated_document["version"] == 2
    assert updated_document["title"] == "Editor Revised PDF"
    assert updated_document["filename"] == "shared-v2.pdf"


def test_viewer_cannot_upload_new_version(client, flask_app, login_as, make_user):
    login_as("alice")
    make_user("bob")

    upload_response = client.post(
        "/upload",
        data={
            "title": "Viewer Shared PDF",
            "document_type": "pdf",
            "document": (BytesIO(b"%PDF-1.7\nowner only"), "viewer-shared.pdf"),
            "csrf_token": _get_csrf(flask_app),
        },
        content_type="multipart/form-data",
    )
    assert upload_response.status_code == 200

    document = json.loads(flask_app.config["DOCUMENTS_FILE"].read_text())[0]
    share_response = client.post(
        f"/documents/{document['id']}/share",
        data={
            "recipient_username": "bob",
            "access_role": "viewer",
            "csrf_token": _get_csrf(flask_app),
        },
    )
    assert share_response.status_code == 200

    client.post("/logout", data={"csrf_token": _get_csrf(flask_app)})
    login_response = client.post(
        "/login",
        data={"identifier": "bob", "password": "StrongPass!123"},
        follow_redirects=False,
    )
    assert login_response.status_code == 302

    version_page = client.get(f"/documents/{document['id']}/versions/upload")
    assert version_page.status_code == 403


def test_upload_new_version_rejects_document_type_mismatch(
    client,
    flask_app,
    login_as,
):
    login_as("alice")

    upload_response = client.post(
        "/upload",
        data={
            "title": "Type Locked PDF",
            "document_type": "pdf",
            "document": (BytesIO(b"%PDF-1.7\nfirst version"), "locked-v1.pdf"),
            "csrf_token": _get_csrf(flask_app),
        },
        content_type="multipart/form-data",
    )
    assert upload_response.status_code == 200

    document = json.loads(flask_app.config["DOCUMENTS_FILE"].read_text())[0]
    revision_response = client.post(
        f"/documents/{document['id']}/versions/upload",
        data={
            "title": "Type Locked PDF",
            "document": (BytesIO(b"not a pdf"), "locked-v2.txt"),
            "csrf_token": _get_csrf(flask_app),
        },
        content_type="multipart/form-data",
    )

    assert revision_response.status_code == 400
    assert (
        b"Uploaded file extension does not match the selected document type."
        in revision_response.data
    )


def test_non_owner_cannot_edit_document(client, flask_app, login_as):
    login_as("alice")

    upload_response = client.post(
        "/upload",
        data={
            "title": "Owner Title",
            "document_type": "txt",
            "document": (BytesIO(b"private"), "notes.txt"),
            "csrf_token": _get_csrf(flask_app),
        },
        content_type="multipart/form-data",
    )
    assert upload_response.status_code == 200

    document = json.loads(flask_app.config["DOCUMENTS_FILE"].read_text())[0]
    client.post("/logout", data={"csrf_token": _get_csrf(flask_app)})

    login_as("bob")
    edit_page = client.get(f"/documents/{document['id']}/edit")

    assert edit_page.status_code == 403


def test_owner_can_share_document_with_existing_user(client, flask_app, login_as, make_user):
    login_as("alice")
    make_user("bob")

    upload_response = client.post(
        "/upload",
        data={
            "title": "Shared Plan",
            "document_type": "txt",
            "document": (BytesIO(b"share this"), "plan.txt"),
            "csrf_token": _get_csrf(flask_app),
        },
        content_type="multipart/form-data",
    )
    assert upload_response.status_code == 200

    document = json.loads(flask_app.config["DOCUMENTS_FILE"].read_text())[0]
    preview_response = client.post(
        f"/documents/{document['id']}/share",
        data={
            "recipient_username": "bob",
            "access_role": "viewer",
            "csrf_token": _get_csrf(flask_app),
        },
    )

    assert preview_response.status_code == 200
    assert b"Document shared with bob as viewer." in preview_response.data

    shares = json.loads(flask_app.config["SHARES_FILE"].read_text())
    assert shares == [
        {
            "document_id": document["id"],
            "principal": "bob",
            "role": "viewer",
        }
    ]

    audit_events = json.loads(flask_app.config["AUDIT_FILE"].read_text())
    assert [event["event_type"] for event in audit_events] == [
        "DOCUMENT_UPLOAD",
        "DOCUMENT_SHARED",
    ]


def test_share_rejects_unknown_recipient(client, flask_app, login_as):
    login_as("alice")

    upload_response = client.post(
        "/upload",
        data={
            "title": "Private Plan",
            "document_type": "txt",
            "document": (BytesIO(b"owner only"), "plan.txt"),
            "csrf_token": _get_csrf(flask_app),
        },
        content_type="multipart/form-data",
    )
    assert upload_response.status_code == 200

    document = json.loads(flask_app.config["DOCUMENTS_FILE"].read_text())[0]
    response = client.post(
        f"/documents/{document['id']}/share",
        data={
            "recipient_username": "missing_user",
            "access_role": "viewer",
            "csrf_token": _get_csrf(flask_app),
        },
    )

    assert response.status_code == 400
    assert b"Recipient username was not found." in response.data


def test_owner_can_share_document_with_editor_access(client, flask_app, login_as, make_user):
    login_as("alice")
    make_user("carol")

    upload_response = client.post(
        "/upload",
        data={
            "title": "Editor Share",
            "document_type": "txt",
            "document": (BytesIO(b"editable"), "editable.txt"),
            "csrf_token": _get_csrf(flask_app),
        },
        content_type="multipart/form-data",
    )
    assert upload_response.status_code == 200

    document = json.loads(flask_app.config["DOCUMENTS_FILE"].read_text())[0]
    response = client.post(
        f"/documents/{document['id']}/share",
        data={
            "recipient_username": "carol",
            "access_role": "editor",
            "csrf_token": _get_csrf(flask_app),
        },
    )

    assert response.status_code == 200
    assert b"Document shared with carol as editor." in response.data

    shares = json.loads(flask_app.config["SHARES_FILE"].read_text())
    assert shares == [
        {
            "document_id": document["id"],
            "principal": "carol",
            "role": "editor",
        }
    ]


def test_pdf_preview_is_available_inline_for_shared_user(
    client,
    flask_app,
    login_as,
    make_user,
):
    login_as("alice")
    make_user("bob")

    upload_response = client.post(
        "/upload",
        data={
            "title": "Shared PDF",
            "document_type": "pdf",
            "document": (BytesIO(b"%PDF-1.7\nshared pdf"), "shared.pdf"),
            "csrf_token": _get_csrf(flask_app),
        },
        content_type="multipart/form-data",
    )
    assert upload_response.status_code == 200

    document = json.loads(flask_app.config["DOCUMENTS_FILE"].read_text())[0]
    share_response = client.post(
        f"/documents/{document['id']}/share",
        data={
            "recipient_username": "bob",
            "access_role": "viewer",
            "csrf_token": _get_csrf(flask_app),
        },
    )
    assert share_response.status_code == 200
    client.post("/logout", data={"csrf_token": _get_csrf(flask_app)})

    login_response = client.post(
        "/login",
        data={"identifier": "bob", "password": "StrongPass!123"},
        follow_redirects=False,
    )
    assert login_response.status_code == 302
    preview_response = client.get(f"/documents/{document['id']}/preview")
    inline_content_response = client.get(f"/documents/{document['id']}/preview/content")

    assert preview_response.status_code == 200
    assert b"Showing an inline PDF preview." in preview_response.data
    assert f"/documents/{document['id']}/preview/content".encode("utf-8") in preview_response.data
    assert inline_content_response.status_code == 200
    assert inline_content_response.data == b"%PDF-1.7\nshared pdf"
    assert inline_content_response.headers["Content-Type"].startswith("application/pdf")


def test_owner_can_permanently_delete_document(client, flask_app, login_as, make_user):
    login_as("alice")
    make_user("bob")

    upload_response = client.post(
        "/upload",
        data={
            "title": "Delete Me",
            "document_type": "txt",
            "document": (BytesIO(b"remove me"), "delete-me.txt"),
            "csrf_token": _get_csrf(flask_app),
        },
        content_type="multipart/form-data",
    )
    assert upload_response.status_code == 200

    document = json.loads(flask_app.config["DOCUMENTS_FILE"].read_text())[0]
    stored_path = flask_app.config["DOCUMENT_STORAGE_DIR"] / document["storage_name"]
    assert stored_path.exists()

    share_response = client.post(
        f"/documents/{document['id']}/share",
        data={
            "recipient_username": "bob",
            "access_role": "viewer",
            "csrf_token": _get_csrf(flask_app),
        },
    )
    assert share_response.status_code == 200

    delete_response = client.post(
        f"/documents/{document['id']}/delete",
        data={"csrf_token": _get_csrf(flask_app)},
        follow_redirects=False,
    )
    assert delete_response.status_code == 302
    assert delete_response.headers["Location"].endswith("/dashboard")

    assert json.loads(flask_app.config["DOCUMENTS_FILE"].read_text()) == []
    assert json.loads(flask_app.config["SHARES_FILE"].read_text()) == []
    assert stored_path.exists() is False

    preview_response = client.get(f"/documents/{document['id']}/preview")
    assert preview_response.status_code == 404

    audit_events = json.loads(flask_app.config["AUDIT_FILE"].read_text())
    assert [event["event_type"] for event in audit_events] == [
        "DOCUMENT_UPLOAD",
        "DOCUMENT_SHARED",
        "DOCUMENT_DELETE",
    ]


def test_viewer_can_download_shared_document(client, flask_app, login_as, make_user):
    login_as("alice")
    make_user("bob")
    plaintext = b"viewer downloadable content"

    upload_response = client.post(
        "/upload",
        data={
            "title": "Viewer Download Test",
            "document_type": "txt",
            "document": (BytesIO(plaintext), "viewer-dl.txt"),
            "csrf_token": _get_csrf(flask_app),
        },
        content_type="multipart/form-data",
    )
    assert upload_response.status_code == 200

    document = json.loads(flask_app.config["DOCUMENTS_FILE"].read_text())[0]
    client.post(
        f"/documents/{document['id']}/share",
        data={
            "recipient_username": "bob",
            "access_role": "viewer",
            "csrf_token": _get_csrf(flask_app),
        },
    )

    client.post("/logout", data={"csrf_token": _get_csrf(flask_app)})
    client.post(
        "/login",
        data={"identifier": "bob", "password": "StrongPass!123"},
        follow_redirects=False,
    )

    download_response = client.get(f"/documents/{document['id']}/download")
    assert download_response.status_code == 200
    assert download_response.data == plaintext


def test_editor_can_download_shared_document(client, flask_app, login_as, make_user):
    login_as("alice")
    make_user("carol")
    plaintext = b"editor downloadable content"

    upload_response = client.post(
        "/upload",
        data={
            "title": "Editor Download Test",
            "document_type": "txt",
            "document": (BytesIO(plaintext), "editor-dl.txt"),
            "csrf_token": _get_csrf(flask_app),
        },
        content_type="multipart/form-data",
    )
    assert upload_response.status_code == 200

    document = json.loads(flask_app.config["DOCUMENTS_FILE"].read_text())[0]
    client.post(
        f"/documents/{document['id']}/share",
        data={
            "recipient_username": "carol",
            "access_role": "editor",
            "csrf_token": _get_csrf(flask_app),
        },
    )

    client.post("/logout", data={"csrf_token": _get_csrf(flask_app)})
    client.post(
        "/login",
        data={"identifier": "carol", "password": "StrongPass!123"},
        follow_redirects=False,
    )

    download_response = client.get(f"/documents/{document['id']}/download")
    assert download_response.status_code == 200
    assert download_response.data == plaintext


def test_unauthenticated_user_cannot_download(client, flask_app, login_as):
    login_as("alice")

    upload_response = client.post(
        "/upload",
        data={
            "title": "Auth Required",
            "document_type": "txt",
            "document": (BytesIO(b"secret"), "secret.txt"),
            "csrf_token": _get_csrf(flask_app),
        },
        content_type="multipart/form-data",
    )
    assert upload_response.status_code == 200

    document = json.loads(flask_app.config["DOCUMENTS_FILE"].read_text())[0]
    client.post("/logout", data={"csrf_token": _get_csrf(flask_app)})

    download_response = client.get(
        f"/documents/{document['id']}/download",
        follow_redirects=False,
    )
    assert download_response.status_code == 302
    assert "/login" in download_response.headers["Location"]


def test_shared_user_cannot_delete_document(client, flask_app, login_as, make_user):
    login_as("alice")
    make_user("bob")

    upload_response = client.post(
        "/upload",
        data={
            "title": "No Delete For Viewer",
            "document_type": "txt",
            "document": (BytesIO(b"protected"), "protected.txt"),
            "csrf_token": _get_csrf(flask_app),
        },
        content_type="multipart/form-data",
    )
    assert upload_response.status_code == 200

    document = json.loads(flask_app.config["DOCUMENTS_FILE"].read_text())[0]
    client.post(
        f"/documents/{document['id']}/share",
        data={
            "recipient_username": "bob",
            "access_role": "editor",
            "csrf_token": _get_csrf(flask_app),
        },
    )

    client.post("/logout", data={"csrf_token": _get_csrf(flask_app)})
    client.post(
        "/login",
        data={"identifier": "bob", "password": "StrongPass!123"},
        follow_redirects=False,
    )

    delete_response = client.post(
        f"/documents/{document['id']}/delete",
        data={"csrf_token": _get_csrf(flask_app)},
    )
    assert delete_response.status_code == 403

    documents = json.loads(flask_app.config["DOCUMENTS_FILE"].read_text())
    assert len(documents) == 1


def test_return_to_owner_downgrades_editor_to_viewer(
    client,
    flask_app,
    login_as,
    make_user,
):
    login_as("alice")
    make_user("carol")

    upload_response = client.post(
        "/upload",
        data={
            "title": "Return Flow Doc",
            "document_type": "txt",
            "document": (BytesIO(b"draft content"), "return-flow.txt"),
            "csrf_token": _get_csrf(flask_app),
        },
        content_type="multipart/form-data",
    )
    assert upload_response.status_code == 200

    document = json.loads(flask_app.config["DOCUMENTS_FILE"].read_text())[0]
    client.post(
        f"/documents/{document['id']}/share",
        data={
            "recipient_username": "carol",
            "access_role": "editor",
            "csrf_token": _get_csrf(flask_app),
        },
    )

    shares_before = json.loads(flask_app.config["SHARES_FILE"].read_text())
    assert shares_before[0]["principal"] == "carol"
    assert shares_before[0]["role"] == "editor"

    client.post("/logout", data={"csrf_token": _get_csrf(flask_app)})
    client.post(
        "/login",
        data={"identifier": "carol", "password": "StrongPass!123"},
        follow_redirects=False,
    )

    return_response = client.post(
        f"/documents/{document['id']}/share",
        data={
            "recipient_username": "alice",
            "access_role": "viewer",
            "csrf_token": _get_csrf(flask_app),
        },
    )
    assert return_response.status_code == 200
    assert b"Updated document returned to the owner." in return_response.data

    shares_after = json.loads(flask_app.config["SHARES_FILE"].read_text())
    assert shares_after[0]["principal"] == "carol"
    assert shares_after[0]["role"] == "viewer"

    edit_page = client.get(f"/documents/{document['id']}/edit")
    assert edit_page.status_code == 403

    audit_events = json.loads(flask_app.config["AUDIT_FILE"].read_text())
    returned_events = [
        e for e in audit_events if e["event_type"] == "DOCUMENT_RETURNED_TO_OWNER"
    ]
    assert len(returned_events) == 1
    assert returned_events[0]["details"]["editor_downgraded_to"] == "viewer"


def test_preview_creates_audit_event(client, flask_app, login_as):
    login_as("alice")

    upload_response = client.post(
        "/upload",
        data={
            "title": "Preview Audit Test",
            "document_type": "txt",
            "document": (BytesIO(b"audit this"), "audit.txt"),
            "csrf_token": _get_csrf(flask_app),
        },
        content_type="multipart/form-data",
    )
    assert upload_response.status_code == 200

    document = json.loads(flask_app.config["DOCUMENTS_FILE"].read_text())[0]
    preview_response = client.get(f"/documents/{document['id']}/preview")
    assert preview_response.status_code == 200

    audit_events = json.loads(flask_app.config["AUDIT_FILE"].read_text())
    event_types = [e["event_type"] for e in audit_events]
    assert "DOCUMENT_UPLOAD" in event_types
    assert "DOCUMENT_PREVIEW" in event_types

    preview_event = [e for e in audit_events if e["event_type"] == "DOCUMENT_PREVIEW"][0]
    assert preview_event["user_id"] == "alice"
    assert preview_event["details"]["document_id"] == document["id"]


def test_pdf_preview_content_creates_audit_event(client, flask_app, login_as):
    login_as("alice")

    upload_response = client.post(
        "/upload",
        data={
            "title": "PDF Audit Test",
            "document_type": "pdf",
            "document": (BytesIO(b"%PDF-1.7\naudit pdf"), "audit.pdf"),
            "csrf_token": _get_csrf(flask_app),
        },
        content_type="multipart/form-data",
    )
    assert upload_response.status_code == 200

    document = json.loads(flask_app.config["DOCUMENTS_FILE"].read_text())[0]
    content_response = client.get(f"/documents/{document['id']}/preview/content")
    assert content_response.status_code == 200

    audit_events = json.loads(flask_app.config["AUDIT_FILE"].read_text())
    preview_events = [e for e in audit_events if e["event_type"] == "DOCUMENT_PREVIEW"]
    assert len(preview_events) >= 1
    assert preview_events[-1]["user_id"] == "alice"
    assert preview_events[-1]["details"]["document_id"] == document["id"]
