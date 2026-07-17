# ============================================================
# GuardianHer AI — database/sos_repository.py
#
# Repository for the `sos_events` table.
#
# Critical design constraint:
#   This table is APPEND-ONLY. The only DML operations
#   permitted are INSERT and SELECT — never UPDATE or DELETE.
#
#   The one exception is `update_status()`, which is the
#   formally sanctioned state-transition method. It is
#   restricted to a whitelist of valid (from_state, to_state)
#   transitions matching the SOSState state machine.
#
#   This constraint ensures a tamper-evident audit trail that
#   can be used as legal evidence in court proceedings.
#
# Usage:
#   from database.sos_repository import SOSRepository
#   repo = SOSRepository()
#   event = repo.create(user_id="...", trigger_source=SOSTriggerSource.MANUAL, ...)
# ============================================================

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Optional

from config.constants import SOSState, SOSTriggerSource, ThreatLevel
from database.connection import get_db

logger = logging.getLogger(__name__)


def _utc_now() -> str:
    return datetime.now(tz=timezone.utc).isoformat(timespec="milliseconds")


# Valid state machine transitions (from_state -> allowed_to_states)
_VALID_TRANSITIONS: dict[SOSState, set[SOSState]] = {
    SOSState.TRIGGERED:  {SOSState.CONFIRMING, SOSState.ACTIVE, SOSState.CANCELLED},
    SOSState.CONFIRMING: {SOSState.ACTIVE, SOSState.CANCELLED, SOSState.FALSE_ALARM},
    SOSState.ACTIVE:     {SOSState.RESOLVED, SOSState.FALSE_ALARM},
    SOSState.RESOLVED:   set(),   # Terminal state
    SOSState.CANCELLED:  set(),   # Terminal state
    SOSState.FALSE_ALARM: set(),  # Terminal state
}


class SOSRepository:
    """
    All database operations for the `sos_events` table.

    This repository enforces the append-only and state-machine
    constraints that protect the legal integrity of the SOS record.
    """

    def __init__(self) -> None:
        self._db = get_db()

    # ── Create (the only INSERT this table ever gets) ────────

    def create(
        self,
        user_id: str,
        trigger_source: SOSTriggerSource,
        latitude: Optional[float] = None,
        longitude: Optional[float] = None,
        address: Optional[str] = None,
        threat_score: Optional[float] = None,
        threat_level: Optional[ThreatLevel] = None,
    ) -> dict:
        """
        Insert a new SOS event record with initial status TRIGGERED.

        Args:
            user_id:        UUID of the user in distress.
            trigger_source: What activated the SOS (MANUAL, BIOMETRIC, etc.).
            latitude:       GPS latitude at trigger time.
            longitude:      GPS longitude at trigger time.
            address:        Reverse-geocoded address string (optional).
            threat_score:   Initial watsonx.ai threat probability (0.0–1.0).
            threat_level:   Initial threat level enum value.

        Returns:
            The newly created SOS event dict.
        """
        event_id = str(uuid.uuid4())
        now = _utc_now()

        with self._db.get_cursor() as cur:
            cur.execute(
                """
                INSERT INTO sos_events
                    (id, user_id, trigger_source, status, threat_score,
                     threat_level, latitude, longitude, address, triggered_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    event_id,
                    user_id,
                    trigger_source.value,
                    SOSState.TRIGGERED.value,
                    threat_score,
                    threat_level.value if threat_level else None,
                    latitude,
                    longitude,
                    address,
                    now,
                ),
            )

        logger.info(
            "[SOSRepo] Created SOS event id=%s user=%s source=%s",
            event_id, user_id, trigger_source.value,
        )
        return self.get_by_id(event_id)

    # ── Read ─────────────────────────────────────────────────

    def get_by_id(self, event_id: str) -> Optional[dict]:
        """Return a single SOS event by primary key."""
        with self._db.get_read_cursor() as cur:
            cur.execute("SELECT * FROM sos_events WHERE id = ?;", (event_id,))
            return cur.fetchone()

    def get_active_for_user(self, user_id: str) -> Optional[dict]:
        """
        Return the most recent non-terminal SOS event for a user.
        Used by the SOS page to detect if a session is in-flight.

        Terminal states (RESOLVED, CANCELLED, FALSE_ALARM) are excluded.
        """
        with self._db.get_read_cursor() as cur:
            cur.execute(
                """
                SELECT * FROM sos_events
                WHERE user_id = ?
                  AND status NOT IN ('RESOLVED', 'CANCELLED', 'FALSE_ALARM')
                ORDER BY triggered_at DESC
                LIMIT 1;
                """,
                (user_id,),
            )
            return cur.fetchone()

    def get_all_active(self) -> list[dict]:
        """
        Return all SOS events currently in ACTIVE state.
        Used by the responder dashboard to populate the live alert feed.
        """
        with self._db.get_read_cursor() as cur:
            cur.execute(
                """
                SELECT se.*, u.name AS user_name, u.phone AS user_phone
                FROM sos_events se
                JOIN users u ON se.user_id = u.id
                WHERE se.status = 'ACTIVE'
                ORDER BY se.triggered_at DESC;
                """
            )
            return cur.fetchall()

    def get_history_for_user(
        self,
        user_id: str,
        limit: int = 20,
        offset: int = 0,
    ) -> list[dict]:
        """
        Return paginated SOS event history for a user.
        Used by pages/incident_report.py to show past incidents.

        Args:
            user_id: UUID of the user.
            limit:   Maximum rows to return.
            offset:  Pagination offset.

        Returns:
            List of SOS event dicts, newest first.
        """
        with self._db.get_read_cursor() as cur:
            cur.execute(
                """
                SELECT * FROM sos_events
                WHERE user_id = ?
                ORDER BY triggered_at DESC
                LIMIT ? OFFSET ?;
                """,
                (user_id, limit, offset),
            )
            return cur.fetchall()

    def get_recent(self, limit: int = 5) -> list[dict]:
        """Return the N most recent SOS events across all users (responder view)."""
        with self._db.get_read_cursor() as cur:
            cur.execute(
                """
                SELECT se.*, u.name AS user_name
                FROM sos_events se
                JOIN users u ON se.user_id = u.id
                ORDER BY se.triggered_at DESC
                LIMIT ?;
                """,
                (limit,),
            )
            return cur.fetchall()

    # ── Update (state transitions only) ─────────────────────

    def update_status(
        self,
        event_id: str,
        new_status: SOSState,
        responder_id: Optional[str] = None,
        notes: Optional[str] = None,
    ) -> Optional[dict]:
        """
        Advance the SOS event to a new status.

        Enforces the state machine — invalid transitions are rejected
        with a ValueError rather than silently accepted.

        Args:
            event_id:     UUID of the SOS event.
            new_status:   Target state.
            responder_id: UUID of the responder acknowledging (optional).
            notes:        Free-text notes added by responder or system.

        Returns:
            Updated SOS event dict.

        Raises:
            ValueError: If the transition is not permitted by the state machine.
        """
        event = self.get_by_id(event_id)
        if not event:
            raise ValueError(f"SOS event '{event_id}' not found.")

        current = SOSState(event["status"])
        allowed = _VALID_TRANSITIONS.get(current, set())

        if new_status not in allowed:
            raise ValueError(
                f"Invalid SOS state transition: {current.value} -> {new_status.value}. "
                f"Allowed transitions: {[s.value for s in allowed] or 'none (terminal state)'}."
            )

        updates: dict = {"status": new_status.value}

        # Set resolved_at timestamp on terminal transitions
        if new_status in {SOSState.RESOLVED, SOSState.CANCELLED, SOSState.FALSE_ALARM}:
            updates["resolved_at"] = _utc_now()

        if responder_id:
            updates["responder_id"] = responder_id

        if notes:
            updates["notes"] = notes

        set_clause = ", ".join(f"{col} = ?" for col in updates)
        values = list(updates.values()) + [event_id]

        with self._db.get_cursor() as cur:
            cur.execute(
                f"UPDATE sos_events SET {set_clause} WHERE id = ?;",
                values,
            )

        logger.info(
            "[SOSRepo] State transition id=%s %s -> %s",
            event_id, current.value, new_status.value,
        )
        return self.get_by_id(event_id)

    def update_threat_score(
        self,
        event_id: str,
        threat_score: float,
        threat_level: ThreatLevel,
    ) -> None:
        """
        Update the AI threat score on an active SOS event.
        Called after watsonx.ai returns its inference result.
        """
        with self._db.get_cursor() as cur:
            cur.execute(
                "UPDATE sos_events SET threat_score = ?, threat_level = ? WHERE id = ?;",
                (threat_score, threat_level.value, event_id),
            )
        logger.debug(
            "[SOSRepo] Updated threat score id=%s score=%.3f level=%s",
            event_id, threat_score, threat_level.value,
        )

    # ── Stats ────────────────────────────────────────────────

    def count_by_status(self) -> dict[str, int]:
        """
        Return event counts grouped by status.
        Used by the responder dashboard summary panel.
        """
        with self._db.get_read_cursor() as cur:
            cur.execute(
                "SELECT status, COUNT(*) as cnt FROM sos_events GROUP BY status;"
            )
            return {row["status"]: row["cnt"] for row in cur.fetchall()}

    def count_today(self) -> int:
        """Return count of SOS events triggered today (UTC)."""
        today = datetime.now(tz=timezone.utc).date().isoformat()
        with self._db.get_read_cursor() as cur:
            cur.execute(
                "SELECT COUNT(*) as cnt FROM sos_events "
                "WHERE triggered_at >= ?;",
                (f"{today}T00:00:00",),
            )
            row = cur.fetchone()
            return row["cnt"] if row else 0
