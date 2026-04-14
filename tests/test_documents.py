import json
from io import BytesIO

from secure_app.storage import load_json


def _get_csrf(flask_app):
    sessions = load_json(flask_app.config["SESSIONS_FILE"], {})
    if not sessions:
        return ""
    return next(iter(sessions.values())).get("csrf_token", "")


def test_upload_rejects_invalid_extension(client, flask_app, login_as):
    login_as("alice")

    response = client.post(
        "/upload",
        data={
            "title": "Quarterly Plan",
            "document": (BytesIO(b"malicious payload"), "../../payload.exe"),
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
            "document": (BytesIO(b"not a pdf"), "report.pdf"),
            "csrf_token": _get_csrf(flask_app),
        },
        content_type="multipart/form-data",
    )

    assert response.status_code == 400
    assert b"Uploaded file contents do not match the selected file type." in response.data


def test_upload_rejects_eicar_test_signature(client, flask_app, login_as):
    login_as("alice")

    response = client.post(
        "/upload",
        data={
            "title": "Suspicious File",
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
            "document": (BytesIO(b"a" * 512), "large.txt"),
            "csrf_token": _get_csrf(flask_app),
        },
        content_type="multipart/form-data",
    )

    assert response.status_code == 413
    assert b"Upload Too Large" in response.data
