# ============================================================
# GuardianHer AI — config/logging_config.py
#
# Structured logging configuration for the entire application.
#
# Design decisions:
#   1. All logging is configured in ONE place.  No module
#      calls basicConfig() or adds handlers independently.
#
#   2. Development mode: human-readable coloured console output
#      with millisecond timestamps.
#
#   3. Production mode: JSON-structured log records that are
#      machine-parseable by IBM Log Analysis (LogDNA) and any
#      other log aggregation pipeline.
#
#   4. Per-module verbosity control — noisy third-party SDKs
#      (ibm_watson, urllib3, botocore) are throttled to WARNING
#      while our own modules run at INFO/DEBUG.
#
#   5. A separate SOS audit logger writes every SOS state
#      transition and escalation action to a dedicated handler.
#      This audit log is intentionally append-only and
#      unaffected by the root log level.
#
# Usage (call once from app.py before any other import):
#
#     from config.logging_config import setup_logging
#     setup_logging()
#
# In any module:
#     import logging
#     logger = logging.getLogger(__name__)
#     logger.info("message")
# ============================================================

from __future__ import annotations

import json
import logging
import logging.config
import sys
from datetime import datetime, timezone
from typing import Any

from config.settings import settings


# ─────────────────────────────────────────────────────────────
# ANSI Colour Codes (development console output)
# ─────────────────────────────────────────────────────────────

_RESET  = "\033[0m"
_BOLD   = "\033[1m"
_DIM    = "\033[2m"
_RED    = "\033[91m"
_YELLOW = "\033[93m"
_CYAN   = "\033[96m"
_GREEN  = "\033[92m"
_BLUE   = "\033[94m"

_LEVEL_COLOURS: dict[int, str] = {
    logging.DEBUG:    _CYAN,
    logging.INFO:     _GREEN,
    logging.WARNING:  _YELLOW,
    logging.ERROR:    _RED,
    logging.CRITICAL: _BOLD + _RED,
}


# ─────────────────────────────────────────────────────────────
# Formatters
# ─────────────────────────────────────────────────────────────

class ColouredConsoleFormatter(logging.Formatter):
    """
    Human-readable formatter for development console output.

    Output format:
        2025-01-15 14:30:05.123 | INFO     | modules.ai.threat_scorer | message
    """

    def format(self, record: logging.LogRecord) -> str:
        colour = _LEVEL_COLOURS.get(record.levelno, _RESET)
        time_str = datetime.fromtimestamp(record.created, tz=timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S.%f"
        )[:-3]  # Trim microseconds to milliseconds

        level_str = f"{colour}{record.levelname}{_RESET}"
        name_str  = f"{_DIM}{record.name}{_RESET}"
        # Use record.getMessage() directly — avoids conflicts with
        # the parent Formatter's %-style _fmt placeholder handling.
        msg_str   = record.getMessage()

        # Append exception info if present
        if record.exc_info:
            exc_text = self.formatException(record.exc_info)
            msg_str = f"{msg_str}\n{_DIM}{exc_text}{_RESET}"

        time_col  = f"{_DIM}{time_str}{_RESET}"
        return f"{time_col} | {level_str:<8} | {name_str:<40} | {msg_str}"


class JSONFormatter(logging.Formatter):
    """
    Machine-readable JSON formatter for production / IBM Log Analysis.

    Each log record is a single-line JSON object.  IBM LogDNA
    ingests these records and indexes the structured fields,
    enabling log-based alerting on SOS events and AI errors.

    Output format (one line per record):
        {
            "timestamp": "2025-01-15T14:30:05.123Z",
            "level": "INFO",
            "logger": "modules.ai.threat_scorer",
            "message": "...",
            "app": "GuardianHer AI",
            "env": "production",
            "extra": { ... any extra fields passed to logger.info(...) }
        }
    """

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(
                record.created, tz=timezone.utc
            ).isoformat(timespec="milliseconds"),
            "level":   record.levelname,
            "logger":  record.name,
            "message": record.getMessage(),
            "app":     "GuardianHer AI",
            "env":     settings.APP_ENV.value if hasattr(settings.APP_ENV, "value") else str(settings.APP_ENV),
        }

        # Include any extra fields the caller passed via extra={...}
        standard_keys = {
            "name", "msg", "args", "levelname", "levelno", "pathname",
            "filename", "module", "exc_info", "exc_text", "stack_info",
            "lineno", "funcName", "created", "msecs", "relativeCreated",
            "thread", "threadName", "processName", "process", "message",
        }
        extra = {k: v for k, v in record.__dict__.items() if k not in standard_keys}
        if extra:
            payload["extra"] = extra

        # Append exception details if present
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)

        return json.dumps(payload, default=str, ensure_ascii=False)


# ─────────────────────────────────────────────────────────────
# SOS Audit Logger
# Writes a dedicated immutable audit trail of every SOS event,
# state transition, evidence action, and AI inference result.
# ─────────────────────────────────────────────────────────────

class SOSAuditFormatter(logging.Formatter):
    """
    Formatter for the SOS audit logger.
    Always produces JSON so the audit trail is machine-verifiable.
    The 'event_type' field is mandatory for audit records.
    """

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "audit_timestamp": datetime.fromtimestamp(
                record.created, tz=timezone.utc
            ).isoformat(timespec="milliseconds"),
            "audit_level":  record.levelname,
            "event_type":   getattr(record, "event_type", "UNKNOWN"),
            "sos_event_id": getattr(record, "sos_event_id", None),
            "user_id":      getattr(record, "user_id", None),
            "message":      record.getMessage(),
        }
        return json.dumps(payload, default=str, ensure_ascii=False)


# ─────────────────────────────────────────────────────────────
# Third-Party Library Noise Suppression
# ─────────────────────────────────────────────────────────────

#: Noisy libraries throttled to WARNING to reduce log volume
_THROTTLED_LOGGERS: list[str] = [
    "ibm_watson",
    "ibm_watsonx_ai",
    "ibm_boto3",
    "ibm_botocore",
    "botocore",
    "urllib3",
    "requests",
    "httpx",
    "asyncio",
    "watchdog",
    "streamlit",
    "tornado",
    "matplotlib",
    "PIL",
]


# ─────────────────────────────────────────────────────────────
# Main Setup Function
# ─────────────────────────────────────────────────────────────

def setup_logging() -> None:
    """
    Configure the Python logging system for GuardianHer AI.

    Call this ONCE at the very beginning of app.py, before any
    other imports that might trigger logging calls.

    Behaviour:
      - Development: coloured, human-readable console output
      - Production:  JSON-structured output for IBM Log Analysis
      - Always:      SOS audit logger with separate JSON handler

    The root log level is read from settings.LOG_LEVEL which
    maps to the LOG_LEVEL environment variable.
    """

    root_level = getattr(logging, settings.LOG_LEVEL, logging.INFO)

    # ── Choose formatter based on environment ────────────────
    if settings.IS_DEVELOPMENT:
        primary_formatter = ColouredConsoleFormatter()
    else:
        primary_formatter = JSONFormatter()

    # ── Root console handler ─────────────────────────────────
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(root_level)
    console_handler.setFormatter(primary_formatter)

    # ── Configure root logger ────────────────────────────────
    root_logger = logging.getLogger()
    root_logger.setLevel(root_level)
    # Remove any existing handlers (e.g., added by Streamlit)
    root_logger.handlers.clear()
    root_logger.addHandler(console_handler)

    # ── Throttle noisy third-party loggers ───────────────────
    for noisy_logger in _THROTTLED_LOGGERS:
        logging.getLogger(noisy_logger).setLevel(logging.WARNING)

    # ── SOS Audit Logger ─────────────────────────────────────
    _configure_sos_audit_logger()

    # ── Application-level module verbosity ───────────────────
    # Our own modules always log at root_level.
    # In debug mode, key modules get DEBUG for extra verbosity.
    if root_level == logging.DEBUG:
        for module_name in [
            "modules.ai.threat_scorer",
            "modules.emergency.sos_trigger",
            "modules.emergency.escalation_engine",
            "services.sos_service",
        ]:
            logging.getLogger(module_name).setLevel(logging.DEBUG)

    logger = logging.getLogger(__name__)
    logger.info(
        "[GuardianHer AI] Logging initialised. env=%s level=%s",
        settings.APP_ENV,
        settings.LOG_LEVEL,
    )


def _configure_sos_audit_logger() -> None:
    """
    Set up the dedicated SOS audit logger.

    The audit logger is named 'guardianher.sos_audit' and is
    used exclusively by services/sos_service.py and
    modules/emergency/ to record every state transition,
    escalation decision, and evidence action.

    In development: writes to stdout alongside normal logs.
    In production:  writes to a dedicated audit stream that
                    can be routed to IBM Log Analysis with a
                    separate retention policy.

    Usage anywhere in the codebase:
        audit_log = logging.getLogger("guardianher.sos_audit")
        audit_log.info(
            "SOS state transition",
            extra={
                "event_type":   "SOS_STATE_CHANGE",
                "sos_event_id": "abc-123",
                "user_id":      "user-456",
            }
        )
    """
    audit_logger = logging.getLogger("guardianher.sos_audit")
    audit_logger.setLevel(logging.INFO)
    # Do not propagate to root — audit records should not mix
    # with general application logs in production.
    audit_logger.propagate = False

    audit_handler = logging.StreamHandler(sys.stdout)
    audit_handler.setLevel(logging.INFO)
    audit_handler.setFormatter(SOSAuditFormatter())
    audit_logger.handlers.clear()
    audit_logger.addHandler(audit_handler)


# ─────────────────────────────────────────────────────────────
# Convenience: get_audit_logger
# ─────────────────────────────────────────────────────────────

def get_audit_logger() -> logging.Logger:
    """
    Return the SOS audit logger instance.

    Shorthand used by sos_service.py and emergency modules:

        from config.logging_config import get_audit_logger
        audit = get_audit_logger()
        audit.info("Alert dispatched", extra={
            "event_type": "ALERT_DISPATCHED",
            "sos_event_id": sos_id,
            "user_id": user_id,
        })
    """
    return logging.getLogger("guardianher.sos_audit")
