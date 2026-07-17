# ============================================================
# GuardianHer AI — database/migrations.py
#
# Schema version management and automatic table creation.
#
# Design decisions:
#   1. run_migrations() is called once from app.py at startup.
#      It is idempotent — safe to call on every startup.
#   2. Each migration version is a tuple: (version, description,
#      list_of_sql_statements).  Versions are applied in order
#      and only if not already recorded in schema_versions.
#   3. The initial migration (version 1) runs ALL_CREATE_STATEMENTS
#      from schema.py — the complete table + index set.
#   4. Future schema changes (version 2, 3, ...) add ALTER TABLE
#      or new CREATE TABLE statements here without touching
#      existing repository or service code.
#
# Usage (called once in app.py):
#   from database.migrations import run_migrations
#   run_migrations()
# ============================================================

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import NamedTuple

from database.connection import get_db
from database.schema import ALL_CREATE_STATEMENTS, SCHEMA_VERSION

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────
# Migration record type
# ─────────────────────────────────────────────────────────────

class Migration(NamedTuple):
    """A single versioned migration step."""
    version: int
    description: str
    statements: list[str]


# ─────────────────────────────────────────────────────────────
# Migration registry
# Add new entries here for every schema change after v1.
# NEVER modify existing migration entries — add a new one.
# ─────────────────────────────────────────────────────────────

MIGRATIONS: list[Migration] = [
    Migration(
        version=1,
        description="Initial schema: users, emergency_contacts, sos_events, "
                    "incident_reports, wearable_data, safe_zones, audit_logs",
        statements=ALL_CREATE_STATEMENTS,
    ),
    # Example future migration:
    # Migration(
    #     version=2,
    #     description="Add user notification_preferences column",
    #     statements=[
    #         "ALTER TABLE users ADD COLUMN notification_prefs TEXT DEFAULT '{}';",
    #     ],
    # ),
]


# ─────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────

def _utc_now() -> str:
    """Return current UTC timestamp as ISO-8601 string."""
    return datetime.now(tz=timezone.utc).isoformat(timespec="milliseconds")


def _get_applied_versions() -> set[int]:
    """
    Return the set of migration version numbers already applied.
    Returns an empty set on the very first run (before any tables exist).
    """
    db = get_db()
    try:
        with db.get_read_cursor() as cur:
            cur.execute("SELECT version FROM schema_versions;")
            rows = cur.fetchall()
            return {row["version"] for row in rows}
    except Exception:
        # schema_versions table doesn't exist yet — this is the first run
        return set()


def _apply_migration(migration: Migration) -> None:
    """
    Execute all SQL statements in a migration within a single transaction.
    Record the migration version in schema_versions on success.
    """
    db = get_db()
    logger.info(
        "[DB Migration] Applying v%d: %s (%d statements)",
        migration.version,
        migration.description,
        len(migration.statements),
    )
    with db.get_cursor() as cur:
        for statement in migration.statements:
            cur.execute(statement)

        # Record this migration as applied
        cur.execute(
            """
            INSERT INTO schema_versions (version, description, applied_at)
            VALUES (?, ?, ?);
            """,
            (migration.version, migration.description, _utc_now()),
        )

    logger.info("[DB Migration] v%d applied successfully.", migration.version)


# ─────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────

def run_migrations() -> None:
    """
    Apply all pending migrations in version order.

    Called once from app.py at startup — before any repository
    code runs. Safe to call multiple times (idempotent).

    Raises:
        Exception: Re-raises any SQL error encountered during
                   a migration so app.py can surface it clearly.
    """
    applied = _get_applied_versions()
    pending = [m for m in MIGRATIONS if m.version not in applied]

    if not pending:
        logger.debug(
            "[DB Migration] Schema is up to date (version %d). No migrations needed.",
            SCHEMA_VERSION,
        )
        return

    logger.info(
        "[DB Migration] %d pending migration(s) found. Current schema target: v%d.",
        len(pending),
        SCHEMA_VERSION,
    )

    for migration in sorted(pending, key=lambda m: m.version):
        _apply_migration(migration)

    logger.info("[DB Migration] All migrations complete. Schema at v%d.", SCHEMA_VERSION)


def get_schema_status() -> dict:
    """
    Return a dict describing the current schema state.
    Used by the responder dashboard health panel.

    Returns:
        {
            "current_version": 1,
            "target_version":  1,
            "is_current":      True,
            "applied_at":      "2025-01-15T14:30:00Z",
        }
    """
    db = get_db()
    try:
        with db.get_read_cursor() as cur:
            cur.execute(
                "SELECT version, applied_at FROM schema_versions "
                "ORDER BY version DESC LIMIT 1;"
            )
            row = cur.fetchone()
            if row:
                return {
                    "current_version": row["version"],
                    "target_version":  SCHEMA_VERSION,
                    "is_current":      row["version"] == SCHEMA_VERSION,
                    "applied_at":      row["applied_at"],
                }
    except Exception:
        pass

    return {
        "current_version": 0,
        "target_version":  SCHEMA_VERSION,
        "is_current":      False,
        "applied_at":      None,
    }
