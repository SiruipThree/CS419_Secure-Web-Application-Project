import json
import logging
from datetime import datetime, timezone
from pathlib import Path


def _build_file_handler(path: Path) -> logging.FileHandler:
    handler = logging.FileHandler(path)
    handler.setFormatter(
        logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    )
    return handler


def configure_app_logging(app) -> None:
    security_logger = logging.getLogger("security")
    access_logger = logging.getLogger("access")

    security_logger.setLevel(logging.INFO)
    access_logger.setLevel(logging.INFO)

    if not security_logger.handlers:
        security_logger.addHandler(_build_file_handler(app.config["SECURITY_LOG_FILE"]))
    if not access_logger.handlers:
        access_logger.addHandler(_build_file_handler(app.config["ACCESS_LOG_FILE"]))


def log_security_event(app, event_type: str, details: dict, severity: str = "INFO") -> None:
    logger = logging.getLogger("security")
    payload = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": event_type,
        "severity": severity,
        "details": details,
    }
    log_method = getattr(logger, severity.lower(), logger.info)
    log_method(json.dumps(payload))
