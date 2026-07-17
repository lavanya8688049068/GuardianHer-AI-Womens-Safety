# ============================================================
# GuardianHer AI — database/incident_repository.py
#
# Repository for the `incident_reports` table.
#
# Responsibilities:
#   - Create incident records linked to SOS events
#   - Attach evidence artifact paths and integrity hashes
#   - Manage incident lifecycle (ACTIVE -> RESOLVED -> CLOSED)
#   - Store Watson NLP summary and AI analysis output
#   - Store generated PDF report and FIR draft paths
#
# Usage:
#   from database.incident_repository import IncidentRepository
#   repo = IncidentRepository()
#   report = repo.create_from_sos(sos_event_id="...", user_id="...")
# ============================================================

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Optional

from config.constants import IncidentStatus
from database.connection import get_db

logger = logging.getLogger(__name__)


def _utc_now() -> str:
    return datetime.now(tz=timezone.utc).isoformat(timespec="milliseconds")


class IncidentRepository:
    """
    All database operations for the `incident_reports` table.

    One incident report is created per SOS event at the point
    the event transitions to ACTIVE status. The report is
    progressively enriched as evidence is collected and AI
    analysis completes.
    """

    def __init__(self) -> None:
        self._db = get_db()

    # ── Create ───────────────────────────────────────────────

    def create_from_sos(self, sos_event_id: str, user_id: str) -> dict:
        """
        Create a new incident report record for an active SOS event.

        Called by services/sos_service.py when the SOS transitions
        from CONFIRMING -> ACTIVE. Evidence fields are NULL at creation
        and populated progressively as the event unfolds.

        Args:
            sos_event_id: UUID of the triggering SOS event.
            user_id:      UUID of the user in distress.

        Returns:
            Newly created incident report dict.

        Raises:
            ValueError: If a report for this SOS event already exists.
        """
        existing = self.get_by_sos_event(sos_event_id)
        if existing:
            raise ValueError(
                f"Incident report for SOS event '{sos_event_id}' already exists "
                f"(id={existing['id']})."
            )

        report_id = str(uuid.uuid4())
        now = _utc_now()

        with self._db.get_cursor() as cur:
            cur.execute(
                """
                INSERT INTO incident_reports
                    (id, sos_event_id, user_id, status, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?);
                """,
                (report_id, sos_event_id, user_id,
                 IncidentStatus.ACTIVE.value, now, now),
            )

        logger.info(
            "[IncidentRepo] Created report id=%s sos=%s user=%s",
            report_id, sos_event_id, user_id,
        )
        return self.get_by_id(report_id)

    # ── Read ─────────────────────────────────────────────────

    def get_by_id(self, report_id: str) -> Optional[dict]:
        """Return a single incident report by primary key."""
        with self._db.get_read_cursor() as cur:
            cur.execute(
                "SELECT * FROM incident_reports WHERE id = ?;",
                (report_id,),
            )
            row = cur.fetchone()
            if row and row.get("ai_analysis"):
                try:
                    row["ai_analysis"] = json.loads(row["ai_analysis"])
                except (json.JSONDecodeError, TypeError):
                    pass  # Leave as raw string if malformed
            return row

    def get_by_sos_event(self, sos_event_id: str) -> Optional[dict]:
        """
        Return the incident report linked to a specific SOS event.
        The sos_event_id column has a UNIQUE constraint — at most
        one report per SOS event.
        """
        with self._db.get_read_cursor() as cur:
            cur.execute(
                "SELECT * FROM incident_reports WHERE sos_event_id = ?;",
                (sos_event_id,),
            )
            return cur.fetchone()

    def get_by_user(
        self,
        user_id: str,
        status: Optional[IncidentStatus] = None,
        limit: int = 20,
        offset: int = 0,
    ) -> list[dict]:
        """
        Return paginated incident history for a user.

        Args:
            user_id: UUID of the user.
            status:  Filter by incident status (None = all statuses).
            limit:   Page size.
            offset:  Pagination offset.

        Returns:
            List of incident report dicts joined with SOS event data.
        """
        if status:
            query = """
                SELECT ir.*, se.trigger_source, se.threat_score,
                       se.threat_level, se.latitude, se.longitude, se.address
                FROM incident_reports ir
                JOIN sos_events se ON ir.sos_event_id = se.id
                WHERE ir.user_id = ? AND ir.status = ?
                ORDER BY ir.created_at DESC
                LIMIT ? OFFSET ?;
            """
            params = (user_id, status.value, limit, offset)
        else:
            query = """
                SELECT ir.*, se.trigger_source, se.threat_score,
                       se.threat_level, se.latitude, se.longitude, se.address
                FROM incident_reports ir
                JOIN sos_events se ON ir.sos_event_id = se.id
                WHERE ir.user_id = ?
                ORDER BY ir.created_at DESC
                LIMIT ? OFFSET ?;
            """
            params = (user_id, limit, offset)

        with self._db.get_read_cursor() as cur:
            cur.execute(query, params)
            return cur.fetchall()

    def get_all_active(self) -> list[dict]:
        """
        Return all active incidents with user and SOS data joined.
        Used by responder dashboard for live monitoring.
        """
        with self._db.get_read_cursor() as cur:
            cur.execute(
                """
                SELECT ir.*, u.name AS user_name, u.phone AS user_phone,
                       se.threat_score, se.threat_level, se.latitude,
                       se.longitude, se.address, se.triggered_at
                FROM incident_reports ir
                JOIN users u ON ir.user_id = u.id
                JOIN sos_events se ON ir.sos_event_id = se.id
                WHERE ir.status = 'ACTIVE'
                ORDER BY ir.created_at DESC;
                """
            )
            return cur.fetchall()

    # ── Update — Evidence attachment ─────────────────────────

    def attach_audio_evidence(
        self, report_id: str, storage_path: str, sha256_hash: str
    ) -> None:
        """
        Record the audio evidence file path and integrity hash.
        Called by services/evidence_service.py after upload completes.
        """
        with self._db.get_cursor() as cur:
            cur.execute(
                "UPDATE incident_reports SET evidence_audio = ?, audio_hash = ?, "
                "updated_at = ? WHERE id = ?;",
                (storage_path, sha256_hash, _utc_now(), report_id),
            )
        logger.debug("[IncidentRepo] Audio evidence attached to report id=%s", report_id)

    def attach_gps_evidence(
        self, report_id: str, storage_path: str, sha256_hash: str
    ) -> None:
        """Record GPS track evidence file path and integrity hash."""
        with self._db.get_cursor() as cur:
            cur.execute(
                "UPDATE incident_reports SET evidence_gps = ?, gps_hash = ?, "
                "updated_at = ? WHERE id = ?;",
                (storage_path, sha256_hash, _utc_now(), report_id),
            )
        logger.debug("[IncidentRepo] GPS evidence attached to report id=%s", report_id)

    def attach_photo_evidence(
        self, report_id: str, storage_path: str, sha256_hash: str
    ) -> None:
        """Record photo evidence file path and integrity hash."""
        with self._db.get_cursor() as cur:
            cur.execute(
                "UPDATE incident_reports SET evidence_photo = ?, photo_hash = ?, "
                "updated_at = ? WHERE id = ?;",
                (storage_path, sha256_hash, _utc_now(), report_id),
            )
        logger.debug("[IncidentRepo] Photo evidence attached to report id=%s", report_id)

    # ── Update — AI enrichment ───────────────────────────────

    def update_ai_analysis(
        self,
        report_id: str,
        summary: str,
        incident_type: str,
        ai_analysis: dict,
    ) -> None:
        """
        Store Watson NLP summary, incident type classification,
        and the full watsonx.ai analysis JSON blob.

        Called by modules/ai/nlp_processor.py after processing
        the audio transcript and incident description.
        """
        with self._db.get_cursor() as cur:
            cur.execute(
                """
                UPDATE incident_reports SET
                    summary = ?, incident_type = ?, ai_analysis = ?,
                    updated_at = ?
                WHERE id = ?;
                """,
                (summary, incident_type, json.dumps(ai_analysis), _utc_now(), report_id),
            )
        logger.debug("[IncidentRepo] AI analysis stored for report id=%s", report_id)

    def set_pdf_report_path(self, report_id: str, pdf_path: str) -> None:
        """Record the path to the generated PDF incident report."""
        with self._db.get_cursor() as cur:
            cur.execute(
                "UPDATE incident_reports SET pdf_report_path = ?, updated_at = ? "
                "WHERE id = ?;",
                (pdf_path, _utc_now(), report_id),
            )

    def set_fir_draft(self, report_id: str, fir_text: str) -> None:
        """Store the generated FIR (First Information Report) draft."""
        with self._db.get_cursor() as cur:
            cur.execute(
                "UPDATE incident_reports SET fir_draft = ?, updated_at = ? "
                "WHERE id = ?;",
                (fir_text, _utc_now(), report_id),
            )

    # ── Update — Status transition ───────────────────────────

    def update_status(
        self, report_id: str, new_status: IncidentStatus
    ) -> Optional[dict]:
        """
        Advance the incident report status.
        Only forward transitions are allowed:
            ACTIVE -> RESOLVED -> CLOSED
        """
        report = self.get_by_id(report_id)
        if not report:
            raise ValueError(f"Incident report '{report_id}' not found.")

        current = IncidentStatus(report["status"])
        _allowed: dict[IncidentStatus, set] = {
            IncidentStatus.ACTIVE:   {IncidentStatus.RESOLVED},
            IncidentStatus.RESOLVED: {IncidentStatus.CLOSED},
            IncidentStatus.CLOSED:   set(),
        }

        if new_status not in _allowed.get(current, set()):
            raise ValueError(
                f"Invalid incident status transition: {current.value} -> {new_status.value}."
            )

        with self._db.get_cursor() as cur:
            cur.execute(
                "UPDATE incident_reports SET status = ?, updated_at = ? WHERE id = ?;",
                (new_status.value, _utc_now(), report_id),
            )

        logger.info(
            "[IncidentRepo] Status %s -> %s for report id=%s",
            current.value, new_status.value, report_id,
        )
        return self.get_by_id(report_id)

    # ── Stats ────────────────────────────────────────────────

    def count_by_status(self) -> dict[str, int]:
        """Return incident counts grouped by status (dashboard summary)."""
        with self._db.get_read_cursor() as cur:
            cur.execute(
                "SELECT status, COUNT(*) as cnt FROM incident_reports GROUP BY status;"
            )
            return {row["status"]: row["cnt"] for row in cur.fetchall()}
