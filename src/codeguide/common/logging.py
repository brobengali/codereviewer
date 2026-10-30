"""Structured logging facility with automatic secret redaction."""

import json
import logging
from datetime import datetime, timezone
from typing import Any

from codeguide.common.redaction import redact_text

__all__ = ["StructuredRedactingFormatter", "configure_logging"]


class StructuredRedactingFormatter(logging.Formatter):
    """Formats log records as structured JSON while redacting sensitive tokens."""

    def __init__(
        self,
        patterns: list[str] | None = None,
        marker: str = "[REDACTED]",
    ) -> None:
        super().__init__()
        self._patterns = patterns or []
        self._marker = marker

    def format(self, record: logging.LogRecord) -> str:
        raw_message = record.getMessage()
        clean_message = redact_text(raw_message, self._patterns, self._marker)

        log_payload: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": clean_message,
        }

        # Include structured extra attributes if present on record
        standard_attrs = {
            "name",
            "msg",
            "args",
            "levelname",
            "levelno",
            "pathname",
            "filename",
            "module",
            "exc_info",
            "exc_text",
            "stack_info",
            "lineno",
            "funcName",
            "created",
            "msecs",
            "relativeCreated",
            "thread",
            "threadName",
            "processName",
            "process",
            "message",
        }
        for key, val in record.__dict__.items():
            if key not in standard_attrs and not key.startswith("_"):
                if isinstance(val, str):
                    log_payload[key] = redact_text(val, self._patterns, self._marker)
                else:
                    log_payload[key] = val

        if record.exc_info:
            log_payload["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_payload)


def configure_logging(
    level: str,
    patterns: list[str] | None = None,
    marker: str = "[REDACTED]",
) -> logging.Logger:
    """Initialize root logger with redacting structured formatter."""
    logger = logging.getLogger("codeguide")
    logger.setLevel(level.upper())
    logger.handlers.clear()

    handler = logging.StreamHandler()
    handler.setFormatter(StructuredRedactingFormatter(patterns=patterns, marker=marker))
    logger.addHandler(handler)
    logger.propagate = False
    return logger
