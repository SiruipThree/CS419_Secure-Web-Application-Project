from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from flask import has_request_context, request


class _EventLogger:
    def __init__(self, name: str):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.INFO)
        self.logger.propagate = False
        self._configured_path: str | None = None

        if not self.logger.handlers:
            self.logger.addHandler(logging.NullHandler())

    def configure(self, log_file: str | Path) -> None:
        path = Path(log_file)
        path.parent.mkdir(parents=True, exist_ok=True)

        resolved_path = str(path.resolve())
        if self._configured_path == resolved_path:
            return

        self.logger.handlers.clear()
        handler = logging.FileHandler(path)
        handler.setFormatter(
            logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
        )
        self.logger.addHandler(handler)
        self._configured_path = resolved_path

    def _emit(self, severity: str, payload: dict[str, Any]) -> None:
        log_method = getattr(self.logger, severity.lower(), self.logger.info)
        log_method(json.dumps(payload))


class SecurityLogger(_EventLogger):
    def __init__(self):
        super().__init__("security")

    def log_event(
        self,
        event_type: str,
        user_id: str | None,
        details: dict[str, Any],
        severity: str = "INFO",
    ) -> None:
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "user_id": user_id,
            "ip_address": request.remote_addr if has_request_context() else None,
            "user_agent": (
                request.headers.get("User-Agent") if has_request_context() else None
            ),
            "details": details,
            "severity": severity,
        }
        self._emit(severity, payload)


class AccessLogger(_EventLogger):
    def __init__(self):
        super().__init__("access")

    def log_event(
        self,
        event_type: str,
        user_id: str | None,
        details: dict[str, Any],
        severity: str = "INFO",
    ) -> None:
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "user_id": user_id,
            "ip_address": request.remote_addr if has_request_context() else None,
            "details": details,
            "severity": severity,
        }
        self._emit(severity, payload)


security_log = SecurityLogger()
access_log = AccessLogger()


def configure_app_logging(app) -> None:
    security_log.configure(app.config["SECURITY_LOG_FILE"])
    access_log.configure(app.config["ACCESS_LOG_FILE"])
