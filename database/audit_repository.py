# ============================================================
# GuardianHer AI — database/audit_repository.py
#
# Repository for the `audit_logs` table.
#
# Critical design constraint:
#   This table is STRICTLY APPEND-ONLY.
#   INSERT is the only permitted DML operation.
#   No UPDATE, DELETE, or TRUNCATE is ever issued.
#
#   This ensures a tamper-evident, chronological record of
#   every security-relevant action in the system — suitable
#   for legal proceedings, regulatory compliance audits,
#   and IBM AI Fairness 360 bias audit trails.
#
# Usage:
#   from database.audit_repository import AuditRepository
#   audit = AuditRepository()
#   audit.log(event_type="SOS_TRIGGERED", user_id="...", description="...")
# ============================================================

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional

from database.connection import get_db

logger = logging.getLogger(__name__)


def _utc_now() -> str:
    return datetime.now(tz=timezone.utc).isoformat(timespec="milliseconds")


# ─────────────────────────────────────────────────────────────
# Canonical event type constants
# Centralised here so callers never type raw strings.
# ─────────────────────────────────────────────────────────────

class AuditEvent:
    """
    Canonical audit event type identifiers.

    Use these constants when calling AuditRepository.log() to
    ensure consistent, queryable event_type values.
    """
    # User lifecycle
    USER_CREATED          = "USER_CREATED"
    USER_UPDATED          = "USER_UPDATED"
    USER_DEACTIVATED      = "USER_DEACTIVATED"
    USER_PII_ERASED       = "USER_PII_ERASED"
    USER_LOGIN            = "USER_LOGIN"
    USER_LOGOUT           = "USER_LOGOUT"

    # Emergency contacts
    CONTACT_ADDED         = "CONTACT_ADDED"
    CONTACT_UPDATED       = "CONTACT_UPDATED"
    CONTACT_REMOVED       = "CONTACT_REMOVED"

    # SOS workflow
    SOS_TRIGGERED         = "SOS_TRIGGERED"
    SOS_CONFIRMING        = "SOS_CONFIRMING"
    SOS_ACTIVATED         = "SOS_ACTIVATED"
    SOS_RESOLVED          = "SOS_RESOLVED"
    SOS_CANCELLED         = "SOS_CANCELLED"
    SOS_FALSE_ALARM       = "SOS_FALSE_ALARM"

    # Escalation and notifications
    ALERT_DISPATCHED      = "ALERT_DISPATCHED"
    ALERT_DELIVERY_FAILED = "ALERT_DELIVERY_FAILED"
    RESPONDER_DISPATCHED  = "RESPONDER_DISPATCHED"

    # Evidence
    EVIDENCE_UPLOADED     = "EVIDENCE_UPLOADED"
    EVIDENCE_VERIFIED     = "EVIDENCE_VERIFIED"
    EVIDENCE_DOWNLOADED   = "EVIDENCE_DOWNLOADED"

    # AI inference
    AI_THREAT_SCORED      = "AI_THREAT_SCORED"
    AI_NLP_PROCESSED      = "AI_NLP_PROCESSED"
    AI_FAIRNESS_AUDIT     = "AI_FAIRNESS_AUDIT"
    AI_FAIRNESS_BREACH    = "AI_FAIRNESS_BREACH"

    # System
    DB_MIGRATION_APPLIED  = "DB_MIGRATION_APPLIED"
    CONFIG_LOADED         = "CONFIG_LOADED"
    IBM_SERVICE_CONNECTED = "IBM_SERVICE_CONNECTED"
    IBM_SERVICE_FAILED    = "IBM_SERVICE_FAILED"


class AuditRepository:
    """
    Append-only repository for the `audit_logs` table.

    Every INSERT is performed inside a separate transaction
    so audit records are committed immediately — independent
    of any outer transaction that may roll back.
    """

    def __init__(self) -> None:
        self._db = get_db()

    # ── Insert (the ONLY write operation) ────────────────────

    def log(
        self,
        event_type: str,
        description: str,
        user_id: Optional[str] = None,
        sos_event_id: Optional[str] = None,
        severity: str = "INFO",
        metadata: Optional[dict] = None,
        ip_address: Optional[str] = None,
    ) -> str:
        """
        Append a new audit log entry.

        This method never raises — if the INSERT fails (e.g., DB
        locked), it logs the error to the Python logger and returns
        an empty string. Audit logging must never cause the primary
        SOS workflow to fail.

        Args:
            event_type:    Canonical event type string (use AuditEvent constants).
            description:   Human-readable description of the event.
            user_id:       UUID of the user who performed the action (None for system).
            sos_event_id:  UUID of the related SOS event (None if not applicable).
            severity:      INFO | WARNING | ERROR | CRITICAL
            metadata:      Dict of additional event-specific details (JSON-serialised).
            ip_address:    Client IP address if available.

        Returns:
            UUID of the new audit log row, or empty string on failure.
        """
        log_id = str(uuid.uuid4())
        metadata_json = json.dumps(metadata, default=str) if metadata else None

        try:
            with self._db.get_cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO audit_logs
                        (id, event_type, user_id, sos_event_id, severity,
                         description, metadata, ip_address, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        log_id,
                        event_type,
                        user_id,
                        sos_event_id,
                        severity.upper(),
                        description,
                        metadata_json,
                        ip_address,
                        _utc_now(),
                    ),
                )
            return log_id
        except Exception as exc:
            # Audit failure must NEVER propagate — only log to Python logger
            logger.error(
                "[AuditRepo] Failed to write audit log event_type=%s: %s",
                event_type, exc,
            )
            return ""

    # ── Read ─────────────────────────────────────────────────

    def get_by_id(self, log_id: str) -> Optional[dict]:
        """Return a single audit log entry by primary key."""
        with self._db.get_read_cursor() as cur:
            cur.execute("SELECT * FROM audit_logs WHERE id = ?;", (log_id,))
            row = cur.fetchone()
            if row and row.get("metadata"):
                try:
                    row["metadata"] = json.loads(row["metadata"])
                except (json.JSONDecodeError, TypeError):
                    pass
            return row

    def get_by_event_type(
        self,
        event_type: str,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict]:
        """
        Return audit logs filtered by event type, newest first.
        Used by the AI fairness dashboard to retrieve inference logs.
        """
        with self._db.get_read_cursor() as cur:
            cur.execute(
                """
                SELECT * FROM audit_logs
                WHERE event_type = ?
                ORDER BY created_at DESC
                LIMIT ? OFFSET ?;
                """,
                (event_type, limit, offset),
            )
            return cur.fetchall()

    def get_by_user(
        self,
        user_id: str,
        limit: int = 50,
        offset: int = 0,
    ) -> list[dict]:
        """Return audit history for a specific user (account activity log)."""
        with self._db.get_read_cursor() as cur:
            cur.execute(
                """
                SELECT * FROM audit_logs
                WHERE user_id = ?
                ORDER BY created_at DESC
                LIMIT ? OFFSET ?;
                """,
                (user_id, limit, offset),
            )
            return cur.fetchall()

    def get_by_sos_event(self, sos_event_id: str) -> list[dict]:
        """
        Return all audit log entries related to a specific SOS event.
        Provides a complete timeline of the incident response.
        """
        with self._db.get_read_cursor() as cur:
            cur.execute(
                """
                SELECT * FROM audit_logs
                WHERE sos_event_id = ?
                ORDER BY created_at ASC;
                """,
                (sos_event_id,),
            )
            rows = cur.fetchall()
            for row in rows:
                if row.get("metadata"):
                    try:
                        row["metadata"] = json.loads(row["metadata"])
                    except (json.JSONDecodeError, TypeError):
                        pass
            return rows

    def get_recent(
        self,
        limit: int = 50,
        severity: Optional[str] = None,
    ) -> list[dict]:
        """
        Return the most recent audit log entries across all users.
        Used by the responder dashboard system activity feed.

        Args:
            limit:    Maximum number of rows.
            severity: Filter by severity level (None = all levels).
        """
        with self._db.get_read_cursor() as cur:
            if severity:
                cur.execute(
                    """
                    SELECT * FROM audit_logs
                    WHERE severity = ?
                    ORDER BY created_at DESC LIMIT ?;
                    """,
                    (severity.upper(), limit),
                )
            else:
                cur.execute(
                    "SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT ?;",
                    (limit,),
                )
            return cur.fetchall()

    def get_ai_inferences_for_fairness(
        self,
        lookback_days: int = 30,
    ) -> list[dict]:
        """
        Return AI_THREAT_SCORED audit events within the lookback window.
        Used by modules/ai/fairness_monitor.py to build the AIF360
        dataset for bias auditing.

        Each row's `metadata` field contains the feature vector
        context tags (time_of_day, zone_type, etc.) used as
        demographic proxy variables in the fairness audit.
        """
        cutoff = (
            datetime.now(tz=timezone.utc) - timedelta(days=lookback_days)
        ).isoformat(timespec="milliseconds")

        with self._db.get_read_cursor() as cur:
            cur.execute(
                """
                SELECT id, sos_event_id, metadata, created_at
                FROM audit_logs
                WHERE event_type = 'AI_THREAT_SCORED'
                  AND created_at >= ?
                ORDER BY created_at ASC;
                """,
                (cutoff,),
            )
            rows = cur.fetchall()
            for row in rows:
                if row.get("metadata"):
                    try:
                        row["metadata"] = json.loads(row["metadata"])
                    except (json.JSONDecodeError, TypeError):
                        pass
            return rows

    # ── Stats ────────────────────────────────────────────────

    def count_by_severity(self, lookback_hours: int = 24) -> dict[str, int]:
        """
        Return event counts grouped by severity over the last N hours.
        Used by the dashboard warning indicators.
        """
        cutoff = (
            datetime.now(tz=timezone.utc) - timedelta(hours=lookback_hours)
        ).isoformat(timespec="milliseconds")

        with self._db.get_read_cursor() as cur:
            cur.execute(
                """
                SELECT severity, COUNT(*) as cnt
                FROM audit_logs
                WHERE created_at >= ?
                GROUP BY severity;
                """,
                (cutoff,),
            )
            return {row["severity"]: row["cnt"] for row in cur.fetchall()}

    def count_errors_today(self) -> int:
        """Return ERROR + CRITICAL audit events for today (UTC)."""
        today = datetime.now(tz=timezone.utc).date().isoformat()
        with self._db.get_read_cursor() as cur:
            cur.execute(
                """
                SELECT COUNT(*) as cnt FROM audit_logs
                WHERE severity IN ('ERROR', 'CRITICAL')
                  AND created_at >= ?;
                """,
                (f"{today}T00:00:00",),
            )
            row = cur.fetchone()
            return row["cnt"] if row else 0
