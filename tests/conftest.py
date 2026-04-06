import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app import create_app
from secure_app.logging_utils import configure_app_logging
from secure_app.storage import bootstrap_storage


@pytest.fixture()
def flask_app(tmp_path):
    app = create_app()

    data_dir = tmp_path / "data"
    log_dir = tmp_path / "logs"
    app.config.update(
        TESTING=True,
        DATA_DIR=data_dir,
        USERS_FILE=data_dir / "users.json",
        SESSIONS_FILE=data_dir / "sessions.json",
        DOCUMENTS_FILE=data_dir / "documents.json",
        SHARES_FILE=data_dir / "shares.json",
        AUDIT_FILE=data_dir / "audit.json",
        DOCUMENT_STORAGE_DIR=data_dir / "documents",
        UPLOAD_STAGING_DIR=data_dir / "uploads",
        LOG_DIR=log_dir,
        SECURITY_LOG_FILE=log_dir / "security.log",
        ACCESS_LOG_FILE=log_dir / "access.log",
        ENCRYPTION_KEY_FILE=tmp_path / "secret.key",
    )

    bootstrap_storage(app.config)
    configure_app_logging(app)
    return app


@pytest.fixture()
def client(flask_app):
    with flask_app.test_client() as client:
        yield client
