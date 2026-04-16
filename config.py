from pathlib import Path
import os


BASE_DIR = Path(__file__).resolve().parent


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-change-me")
    ENV = os.getenv("FLASK_ENV", "development")
    DEBUG = ENV == "development"
    FORCE_HTTPS = os.getenv(
        "FORCE_HTTPS",
        "0" if ENV == "development" else "1",
    ) == "1"
    TLS_CERT_FILE = os.getenv("TLS_CERT_FILE")
    TLS_KEY_FILE = os.getenv("TLS_KEY_FILE")

    SESSION_COOKIE_NAME = "session_token"
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SECURE = ENV != "development"
    SESSION_COOKIE_SAMESITE = "Strict"
    SESSION_TIMEOUT_SECONDS = int(os.getenv("SESSION_TIMEOUT_SECONDS", "1800"))

    MAX_LOGIN_ATTEMPTS = 5
    ACCOUNT_LOCKOUT_MINUTES = 15
    MAX_LOGIN_ATTEMPTS_PER_IP_PER_MINUTE = 10

    MAX_UPLOAD_MB = int(os.getenv("MAX_UPLOAD_MB", "16"))
    MAX_CONTENT_LENGTH = MAX_UPLOAD_MB * 1024 * 1024
    DOCUMENT_TITLE_MAX_LENGTH = 120
    ALLOWED_EXTENSIONS = {
        "pdf",
        "txt",
        "docx",
        "png",
        "jpg",
        "jpeg",
    }
    ALLOWED_MIME_TYPES = {
        "pdf": {"application/pdf"},
        "txt": {"text/plain"},
        "docx": {
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        },
        "png": {"image/png"},
        "jpg": {"image/jpeg"},
        "jpeg": {"image/jpeg"},
    }
    DOCUMENT_TYPE_LABELS = {
        "pdf": "PDF document (.pdf)",
        "txt": "Text document (.txt)",
        "docx": "Word document (.docx)",
        "png": "PNG image (.png)",
        "jpg": "JPEG image (.jpg)",
        "jpeg": "JPEG image (.jpeg)",
    }

    DATA_DIR = BASE_DIR / "data"
    USERS_FILE = DATA_DIR / "users.json"
    RATE_LIMITS_FILE = DATA_DIR / "rate_limits.json"
    SESSIONS_FILE = DATA_DIR / "sessions.json"
    DOCUMENTS_FILE = DATA_DIR / "documents.json"
    SHARES_FILE = DATA_DIR / "shares.json"
    AUDIT_FILE = DATA_DIR / "audit.json"
    DOCUMENT_STORAGE_DIR = DATA_DIR / "documents"
    UPLOAD_STAGING_DIR = DATA_DIR / "uploads"

    LOG_DIR = BASE_DIR / "logs"
    SECURITY_LOG_FILE = LOG_DIR / "security.log"
    ACCESS_LOG_FILE = LOG_DIR / "access.log"
    ENCRYPTION_KEY_FILE = BASE_DIR / "secret.key"
