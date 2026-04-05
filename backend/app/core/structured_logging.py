"""Structured JSON logging with decision_id correlation (Sprint 26, APEP-209).

Provides JSON-formatted log output with consistent fields for log aggregation
(ELK, Loki, CloudWatch). Every log entry includes service metadata and supports
correlation via decision_id, session_id, and trace_id.
"""

import json
import logging
import sys
from datetime import datetime, timezone
from typing import Any

from opentelemetry import trace

from app.core.config import settings


class StructuredJsonFormatter(logging.Formatter):
    """Formats log records as single-line JSON for log aggregation."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "service": settings.app_name,
            "version": settings.app_version,
        }

        # Inject OpenTelemetry trace context if available
        span = trace.get_current_span()
        span_ctx = span.get_span_context()
        if span_ctx and span_ctx.is_valid:
            log_entry["trace_id"] = format(span_ctx.trace_id, "032x")
            log_entry["span_id"] = format(span_ctx.span_id, "016x")

        # Merge extra structured fields set via StructuredLogger
        if hasattr(record, "_structured_fields"):
            log_entry.update(record._structured_fields)

        # Include exception info if present
        if record.exc_info and record.exc_info[1] is not None:
            log_entry["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_entry, default=str)


class StructuredLogger:
    """Wrapper around stdlib logger that supports structured key-value fields.

    Usage:
        logger = get_logger(__name__)
        logger.info("policy_decision", decision_id="abc", agent_id="agent-1")
    """

    def __init__(self, logger: logging.Logger) -> None:
        self._logger = logger

    def _log(self, level: int, event: str, *args: Any, **fields: Any) -> None:
        if args:
            event = event % args
        record = self._logger.makeRecord(
            name=self._logger.name,
            level=level,
            fn="",
            lno=0,
            msg=event,
            args=(),
            exc_info=None,
        )
        record._structured_fields = fields  # type: ignore[attr-defined]
        self._logger.handle(record)

    def debug(self, event: str, *args: Any, **fields: Any) -> None:
        if self._logger.isEnabledFor(logging.DEBUG):
            self._log(logging.DEBUG, event, *args, **fields)

    def info(self, event: str, *args: Any, **fields: Any) -> None:
        if self._logger.isEnabledFor(logging.INFO):
            self._log(logging.INFO, event, *args, **fields)

    def warning(self, event: str, *args: Any, **fields: Any) -> None:
        if self._logger.isEnabledFor(logging.WARNING):
            self._log(logging.WARNING, event, *args, **fields)

    def error(self, event: str, *args: Any, **fields: Any) -> None:
        if self._logger.isEnabledFor(logging.ERROR):
            self._log(logging.ERROR, event, *args, **fields)

    def critical(self, event: str, *args: Any, **fields: Any) -> None:
        if self._logger.isEnabledFor(logging.CRITICAL):
            self._log(logging.CRITICAL, event, *args, **fields)

    def exception(self, event: str, *args: Any, **fields: Any) -> None:
        """Log at ERROR level with exception info."""
        if args:
            event = event % args
        if self._logger.isEnabledFor(logging.ERROR):
            record = self._logger.makeRecord(
                name=self._logger.name,
                level=logging.ERROR,
                fn="",
                lno=0,
                msg=event,
                args=(),
                exc_info=True,
            )
            record._structured_fields = fields  # type: ignore[attr-defined]
            self._logger.handle(record)


_configured = False


def configure_logging() -> None:
    """Configure root logger with structured JSON output.

    Call once at application startup (idempotent).
    """
    global _configured
    if _configured:
        return
    _configured = True

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(StructuredJsonFormatter())

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(logging.DEBUG if settings.debug else logging.INFO)

    # Quieten noisy third-party loggers
    for noisy in ("uvicorn.access", "uvicorn.error", "motor", "pymongo"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def get_logger(name: str) -> StructuredLogger:
    """Get a structured logger for the given module name.

    Automatically configures JSON logging on first call.
    """
    configure_logging()
    return StructuredLogger(logging.getLogger(name))
