# ============================================================
# GuardianHer AI — database/user_repository.py
#
# Repository for the `users` table.
#
# Responsibilities:
#   - Create, read, update, deactivate user records
#   - Look up users by ID, email, phone, or IBM App ID subject
#   - Enforce business rules (uniqueness, role validation)
#     before touching the database
#
# SOLID adherence:
#   - Single Responsibility: only this file writes to `users`
#   - Open/Closed: new query methods can be added without
#     changing existing ones
#   - Dependency Inversion: depends on DatabaseManager
#     interface, not the concrete sqlite3 module
#
# Usage:
#   from database.user_repository import UserRepository
#   repo = UserRepository()
#   user = repo.get_by_id("user-uuid")
# ============================================================

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Optional

from config.constants import UserRole, MAX_TRUSTED_CONTACTS
from database.connection import get_db

logger = logging.getLogger(__name__)


def _utc_now() -> str:
    """Return current UTC time as ISO-8601 string."""
    return datetime.now(tz=timezone.utc).isoformat(timespec="milliseconds")


class UserRepository:
    """
    All database operations for the `users` table.

    Instances are lightweight — they hold no state beyond the
    shared DatabaseManager reference. Create one per service
    call or share a single instance per Streamlit session.
    """

    def __init__(self) -> None:
        self._db = get_db()

    # ── Create ───────────────────────────────────────────────

    def create(
        self,
        name: str,
        phone: Optional[str] = None,
        email: Optional[str] = None,
        role: UserRole = UserRole.USER,
        language: str = "en",
        ibm_app_id_sub: Optional[str] = None,
    ) -> dict:
        """
        Insert a new user record.

        Args:
            name:           Display name.
            phone:          Phone number (must be unique if provided).
            email:          Email address (must be unique if provided).
            role:           RBAC role (default: UserRole.USER).
            language:       ISO-639-1 language code for notifications.
            ibm_app_id_sub: IBM App ID JWT 'sub' claim for SSO linking.

        Returns:
            The newly created user record as a dict.

        Raises:
            ValueError:  If a user with the same phone/email already exists.
            sqlite3.Error: On any database-level error.
        """
        # Guard: uniqueness pre-check (friendlier error than DB constraint)
        if phone and self.get_by_phone(phone):
            raise ValueError(f"A user with phone '{phone}' already exists.")
        if email and self.get_by_email(email):
            raise ValueError(f"A user with email '{email}' already exists.")

        user_id = str(uuid.uuid4())
        now = _utc_now()

        with self._db.get_cursor() as cur:
            cur.execute(
                """
                INSERT INTO users
                    (id, name, email, phone, role, language,
                     is_active, ibm_app_id_sub, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?);
                """,
                (user_id, name, email, phone, role.value,
                 language, ibm_app_id_sub, now, now),
            )

        logger.info("[UserRepo] Created user id=%s role=%s", user_id, role.value)
        return self.get_by_id(user_id)  # Return full record with defaults applied

    # ── Read ─────────────────────────────────────────────────

    def get_by_id(self, user_id: str) -> Optional[dict]:
        """Return user dict by primary key, or None if not found."""
        with self._db.get_read_cursor() as cur:
            cur.execute("SELECT * FROM users WHERE id = ?;", (user_id,))
            return cur.fetchone()

    def get_by_email(self, email: str) -> Optional[dict]:
        """Return user dict by email address, or None."""
        with self._db.get_read_cursor() as cur:
            cur.execute(
                "SELECT * FROM users WHERE email = ? AND is_active = 1;",
                (email,),
            )
            return cur.fetchone()

    def get_by_phone(self, phone: str) -> Optional[dict]:
        """Return user dict by phone number, or None."""
        with self._db.get_read_cursor() as cur:
            cur.execute(
                "SELECT * FROM users WHERE phone = ? AND is_active = 1;",
                (phone,),
            )
            return cur.fetchone()

    def get_by_ibm_app_id_sub(self, sub: str) -> Optional[dict]:
        """
        Look up a user by their IBM App ID JWT subject claim.
        Used by modules/auth/session_manager.py after token validation.
        """
        with self._db.get_read_cursor() as cur:
            cur.execute(
                "SELECT * FROM users WHERE ibm_app_id_sub = ?;",
                (sub,),
            )
            return cur.fetchone()

    def get_all_active(self, role: Optional[UserRole] = None) -> list[dict]:
        """
        Return all active users, optionally filtered by role.
        Used by the responder dashboard to list all responders.
        """
        with self._db.get_read_cursor() as cur:
            if role:
                cur.execute(
                    "SELECT * FROM users WHERE is_active = 1 AND role = ? "
                    "ORDER BY name ASC;",
                    (role.value,),
                )
            else:
                cur.execute(
                    "SELECT * FROM users WHERE is_active = 1 ORDER BY name ASC;"
                )
            return cur.fetchall()

    # ── Update ───────────────────────────────────────────────

    def update(self, user_id: str, **fields) -> Optional[dict]:
        """
        Update one or more user fields by ID.

        Only these fields are updatable via this method:
            name, phone, email, language, role

        The `ibm_app_id_sub` and `id` fields are immutable.
        The `updated_at` timestamp is always refreshed.

        Args:
            user_id: UUID of the user to update.
            **fields: Keyword arguments matching column names.

        Returns:
            Updated user dict, or None if not found.
        """
        allowed = {"name", "phone", "email", "language", "role"}
        updates = {k: v for k, v in fields.items() if k in allowed}
        if not updates:
            logger.warning("[UserRepo] update() called with no valid fields.")
            return self.get_by_id(user_id)

        updates["updated_at"] = _utc_now()

        set_clause = ", ".join(f"{col} = ?" for col in updates)
        values = list(updates.values()) + [user_id]

        with self._db.get_cursor() as cur:
            cur.execute(
                f"UPDATE users SET {set_clause} WHERE id = ?;",
                values,
            )

        logger.info("[UserRepo] Updated user id=%s fields=%s", user_id, list(updates.keys()))
        return self.get_by_id(user_id)

    def link_ibm_app_id(self, user_id: str, sub: str) -> None:
        """
        Associate an IBM App ID JWT subject with a user record.
        Called during first SSO login.
        """
        with self._db.get_cursor() as cur:
            cur.execute(
                "UPDATE users SET ibm_app_id_sub = ?, updated_at = ? WHERE id = ?;",
                (sub, _utc_now(), user_id),
            )
        logger.info("[UserRepo] Linked IBM App ID sub to user id=%s", user_id)

    # ── Deactivate (soft delete) ─────────────────────────────

    def deactivate(self, user_id: str) -> None:
        """
        Soft-delete a user by setting is_active = 0.
        Hard deletes are not permitted — they would break the
        SOS event audit trail foreign key chain.

        For GDPR right-to-erasure: anonymise the PII fields
        separately using anonymise_pii() below.
        """
        with self._db.get_cursor() as cur:
            cur.execute(
                "UPDATE users SET is_active = 0, updated_at = ? WHERE id = ?;",
                (_utc_now(), user_id),
            )
        logger.info("[UserRepo] Deactivated user id=%s", user_id)

    def anonymise_pii(self, user_id: str) -> None:
        """
        Overwrite personally identifiable fields with anonymous
        placeholders to fulfil GDPR Art. 17 right-to-erasure requests.

        The user row is retained (is_active=0) to preserve the
        integrity of the sos_events audit trail.
        """
        anon_name  = f"[deleted-{user_id[:8]}]"
        anon_phone = None
        anon_email = None

        with self._db.get_cursor() as cur:
            cur.execute(
                """
                UPDATE users SET
                    name = ?, phone = ?, email = ?,
                    ibm_app_id_sub = NULL,
                    is_active = 0,
                    updated_at = ?
                WHERE id = ?;
                """,
                (anon_name, anon_phone, anon_email, _utc_now(), user_id),
            )
        logger.info("[UserRepo] PII anonymised for user id=%s (GDPR erasure).", user_id)

    # ── Stats ────────────────────────────────────────────────

    def count_active(self) -> int:
        """Return count of active registered users (for dashboard stats)."""
        with self._db.get_read_cursor() as cur:
            cur.execute("SELECT COUNT(*) as cnt FROM users WHERE is_active = 1;")
            row = cur.fetchone()
            return row["cnt"] if row else 0
