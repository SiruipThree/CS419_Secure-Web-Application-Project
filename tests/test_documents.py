import json
from io import BytesIO


def test_upload_rejects_invalid_extension(client):
    response = client.post(
        "/upload",
        data={
            "title": "Quarterly Plan",
            "document": (BytesIO(b"malicious payload"), "../../payload.exe"),
        },
        content_type="multipart/form-data",
    )

    assert response.status_code == 400
    assert b"File type is not allowed." in response.data


def test_upload_rejects_content_signature_mismatch(client):
    response = client.post(
        "/upload",
        data={
            "title": "Fake PDF",
            "document": (BytesIO(b"not a pdf"), "report.pdf"),
        },
        content_type="multipart/form-data",
    )

    assert response.status_code == 400
    assert b"Uploaded file contents do not match the selected file type." in response.data


def test_upload_encrypts_file_and_download_restores_plaintext(client, flask_app):
    plaintext = b"Top secret launch plan"

    response = client.post(
        "/upload",
        data={
            "title": "Launch Plan",
            "document": (BytesIO(plaintext), "launch-plan.txt"),
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


def test_upload_too_large_returns_413(client, flask_app):
    flask_app.config["MAX_CONTENT_LENGTH"] = 32

    response = client.post(
        "/upload",
        data={
            "title": "Large File",
            "document": (BytesIO(b"a" * 512), "large.txt"),
        },
        content_type="multipart/form-data",
    )

    assert response.status_code == 413
    assert b"Upload Too Large" in response.data
