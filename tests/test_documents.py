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

    download_response = client.get(f"/documents/{document['id']}/download")
    assert download_response.status_code == 200
    assert download_response.data == b"Updated body"

    audit_events = json.loads(flask_app.config["AUDIT_FILE"].read_text())
    assert [event["event_type"] for event in audit_events] == [
        "DOCUMENT_UPLOAD",
        "DOCUMENT_EDIT",
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
    encrypted_after = (
        flask_app.config["DOCUMENT_STORAGE_DIR"] / updated_document["storage_name"]
    ).read_bytes()
    assert updated_document["title"] == "Renamed PDF Title"
    assert encrypted_after == encrypted_before


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
