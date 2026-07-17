# ============================================================
# GuardianHer AI — database/emergency_repository.py
#
# Repository for the `emergency_contacts` table.
#
# Responsibilities:
#   - CRUD operations for each user's trusted contact list
#   - Enforce the MAX_TRUSTED_CONTACTS limit per user
#   - Priority-ordered retrieval for SOS dispatch ordering
#   - Alert channel preference management
#
# Usage:
#   from database.emergency_repository import EmergencyContactRepository
#   repo = EmergencyContactRepository()
#   contacts = repo.get_by_user("user-uuid")
# ============================================================

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Optional

from config.constants import MAX_TRUSTED_CONTACTS
from database.connection import get_db

logger = logging.getLogger(__name__)


def _utc_now() -> str:
    return datetime.now(tz=timezone.utc).isoformat(timespec="milliseconds")


class EmergencyContactRepository:
    """
    All database operations for the `emergency_contacts` table.

    Contacts are always returned ordered by priority ASC
    (lowest priority number = first alerted).
    """

    def __init__(self) -> None:
        self._db = get_db()

    # ── Create ───────────────────────────────────────────────

    def create(
        self,
        user_id: str,
        name: str,
        phone: str,
        email: Optional[str] = None,
        relationship: Optional[str] = None,
        priority: int = 1,
        alert_channels: Optional[list[str]] = None,
    ) -> dict:
        """
        Add a new trusted emergency contact for a user.

        Args:
            user_id:        Owner user UUID.
            name:           Contact's display name.
            phone:          Contact's phone number (used for SMS/call dispatch).
            email:          Contact's email (used for email alerts).
            relationship:   family | friend | colleague | other
            priority:       Alert dispatch order. 1 = alerted first.
            alert_channels: List of channels. Default: ["sms", "call"]

        Returns:
            The newly created contact record as a dict.

        Raises:
            ValueError: If the user already has MAX_TRUSTED_CONTACTS contacts.
        """
        existing_count = self.count_by_user(user_id)
        if existing_count >= MAX_TRUSTED_CONTACTS:
            raise ValueError(
                f"User '{user_id}' already has the maximum "
                f"{MAX_TRUSTED_CONTACTS} emergency contacts."
            )

        if alert_channels is None:
            alert_channels = ["sms", "call"]

        contact_id = str(uuid.uuid4())
        now = _utc_now()
        channels_json = json.dumps(alert_channels)

        with self._db.get_cursor() as cur:
            cur.execute(
                """
                INSERT INTO emergency_contacts
                    (id, user_id, name, phone, email, relationship,
                     priority, alert_channels, is_active, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?);
                """,
                (contact_id, user_id, name, phone, email, relationship,
                 priority, channels_json, now, now),
            )

        logger.info(
            "[EmergencyRepo] Added contact id=%s for user=%s priority=%d",
            contact_id, user_id, priority,
        )
        return self.get_by_id(contact_id)

    # ── Read ─────────────────────────────────────────────────

    def get_by_id(self, contact_id: str) -> Optional[dict]:
        """Return a single contact dict by primary key."""
        with self._db.get_read_cursor() as cur:
            cur.execute(
                "SELECT * FROM emergency_contacts WHERE id = ?;",
                (contact_id,),
            )
            row = cur.fetchone()
            if row:
                row["alert_channels"] = json.loads(row.get("alert_channels", "[]"))
            return row

    def get_by_user(self, user_id: str, active_only: bool = True) -> list[dict]:
        """
        Return all contacts for a user, ordered by priority (lowest first).

        This is the primary query used by escalation_engine.py at SOS time.

        Args:
            user_id:     Owner user UUID.
            active_only: If True, exclude soft-deleted contacts.

        Returns:
            List of contact dicts ordered by priority ASC.
        """
        query = """
            SELECT * FROM emergency_contacts
            WHERE user_id = ?
            {}
            ORDER BY priority ASC, created_at ASC;
        """.format("AND is_active = 1" if active_only else "")

        with self._db.get_read_cursor() as cur:
            cur.execute(query, (user_id,))
            rows = cur.fetchall()
            for row in rows:
                row["alert_channels"] = json.loads(row.get("alert_channels", "[]"))
            return rows

    def get_priority_one(self, user_id: str) -> Optional[dict]:
        """
        Return the single highest-priority contact (priority = 1).
        Used by call_dialer.py — only one contact receives the auto-call.
        """
        with self._db.get_read_cursor() as cur:
            cur.execute(
                """
                SELECT * FROM emergency_contacts
                WHERE user_id = ? AND is_active = 1
                ORDER BY priority ASC LIMIT 1;
                """,
                (user_id,),
            )
            row = cur.fetchone()
            if row:
                row["alert_channels"] = json.loads(row.get("alert_channels", "[]"))
            return row

    def count_by_user(self, user_id: str) -> int:
        """Return total active contact count for a user."""
        with self._db.get_read_cursor() as cur:
            cur.execute(
                "SELECT COUNT(*) as cnt FROM emergency_contacts "
                "WHERE user_id = ? AND is_active = 1;",
                (user_id,),
            )
            row = cur.fetchone()
            return row["cnt"] if row else 0

    # ── Update ───────────────────────────────────────────────

    def update(self, contact_id: str, **fields) -> Optional[dict]:
        """
        Update contact fields. Updatable: name, phone, email,
        relationship, priority, alert_channels.

        If alert_channels is passed as a list, it is JSON-serialised
        automatically before storage.
        """
        allowed = {"name", "phone", "email", "relationship", "priority", "alert_channels"}
        updates = {k: v for k, v in fields.items() if k in allowed}
        if not updates:
            return self.get_by_id(contact_id)

        # Serialise alert_channels list → JSON string for storage
        if "alert_channels" in updates and isinstance(updates["alert_channels"], list):
            updates["alert_channels"] = json.dumps(updates["alert_channels"])

        updates["updated_at"] = _utc_now()
        set_clause = ", ".join(f"{col} = ?" for col in updates)
        values = list(updates.values()) + [contact_id]

        with self._db.get_cursor() as cur:
            cur.execute(
                f"UPDATE emergency_contacts SET {set_clause} WHERE id = ?;",
                values,
            )

        logger.info("[EmergencyRepo] Updated contact id=%s", contact_id)
        return self.get_by_id(contact_id)

    def reorder_priorities(self, user_id: str, ordered_contact_ids: list[str]) -> None:
        """
        Re-assign priority values based on the provided order.
        The first element in ordered_contact_ids gets priority=1, etc.

        Called from pages/contacts.py drag-and-drop reorder UI.
        """
        now = _utc_now()
        with self._db.get_cursor() as cur:
            for priority, contact_id in enumerate(ordered_contact_ids, start=1):
                cur.execute(
                    "UPDATE emergency_contacts SET priority = ?, updated_at = ? "
                    "WHERE id = ? AND user_id = ?;",
                    (priority, now, contact_id, user_id),
                )
        logger.info(
            "[EmergencyRepo] Reordered %d contacts for user=%s",
            len(ordered_contact_ids), user_id,
        )

    # ── Soft delete ──────────────────────────────────────────

    def deactivate(self, contact_id: str) -> None:
        """Soft-delete a contact (is_active = 0). Does not physically remove."""
        with self._db.get_cursor() as cur:
            cur.execute(
                "UPDATE emergency_contacts SET is_active = 0, updated_at = ? "
                "WHERE id = ?;",
                (_utc_now(), contact_id),
            )
        logger.info("[EmergencyRepo] Deactivated contact id=%s", contact_id)

    def delete_all_for_user(self, user_id: str) -> int:
        """
        Hard-delete all contacts for a user.
        Called only during GDPR erasure (after user anonymisation).
        Returns the number of rows deleted.
        """
        with self._db.get_cursor() as cur:
            cur.execute(
                "DELETE FROM emergency_contacts WHERE user_id = ?;",
                (user_id,),
            )
            count = cur.rowcount
        logger.info(
            "[EmergencyRepo] Hard-deleted %d contacts for user=%s (GDPR erasure).",
            count, user_id,
        )
        return count
