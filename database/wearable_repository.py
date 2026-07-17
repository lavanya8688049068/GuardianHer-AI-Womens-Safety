# ============================================================
# GuardianHer AI — database/wearable_repository.py
#
# Repository for the `wearable_data` table.
#
# Responsibilities:
#   - Insert biometric sensor readings (append-only)
#   - Retrieve rolling time-window data for anomaly analysis
#   - Fetch all readings associated with an SOS event
#     (for biometric evidence packaging)
#   - Compute user biometric baseline statistics
#
# This table is append-only: no UPDATE or DELETE is issued.
#
# Usage:
#   from database.wearable_repository import WearableRepository
#   repo = WearableRepository()
#   repo.insert_reading(user_id="...", heart_rate=88.0, ...)
# ============================================================

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional

from database.connection import get_db

logger = logging.getLogger(__name__)


def _utc_now() -> str:
    return datetime.now(tz=timezone.utc).isoformat(timespec="milliseconds")


class WearableRepository:
    """
    All database operations for the `wearable_data` table.

    Rows are sensor snapshots recorded at the
    SENSOR_POLL_INTERVAL_SECONDS cadence (10s by default).
    """

    def __init__(self) -> None:
        self._db = get_db()

    # ── Insert (append-only) ─────────────────────────────────

    def insert_reading(
        self,
        user_id: str,
        heart_rate: Optional[float] = None,
        gsr: Optional[float] = None,
        spo2: Optional[float] = None,
        temperature: Optional[float] = None,
        accelerometer_x: Optional[float] = None,
        accelerometer_y: Optional[float] = None,
        accelerometer_z: Optional[float] = None,
        threat_score: Optional[float] = None,
        is_distress: bool = False,
        device_id: Optional[str] = None,
        sos_event_id: Optional[str] = None,
        recorded_at: Optional[str] = None,
    ) -> str:
        """
        Insert a single biometric reading snapshot.

        Args:
            user_id:         UUID of the user wearing the device.
            heart_rate:      Beats per minute.
            gsr:             Galvanic Skin Response in µS.
            spo2:            Blood oxygen saturation percentage.
            temperature:     Skin surface temperature in °C.
            accelerometer_*: Motion vector components in m/s².
            threat_score:    On-device ONNX pre-score (0.0–1.0).
            is_distress:     True if anomaly was detected at read time.
            device_id:       Wearable hardware identifier string.
            sos_event_id:    Link to an active SOS event if present.
            recorded_at:     ISO-8601 timestamp (defaults to now).

        Returns:
            The UUID of the newly inserted record.
        """
        reading_id = str(uuid.uuid4())
        ts = recorded_at or _utc_now()

        with self._db.get_cursor() as cur:
            cur.execute(
                """
                INSERT INTO wearable_data (
                    id, user_id, sos_event_id, heart_rate, gsr, spo2,
                    temperature, accelerometer_x, accelerometer_y,
                    accelerometer_z, threat_score, is_distress,
                    device_id, recorded_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    reading_id, user_id, sos_event_id,
                    heart_rate, gsr, spo2, temperature,
                    accelerometer_x, accelerometer_y, accelerometer_z,
                    threat_score, int(is_distress),
                    device_id, ts,
                ),
            )

        return reading_id

    def insert_batch(self, readings: list[dict]) -> int:
        """
        Insert multiple biometric readings in a single transaction.
        Each dict in `readings` should contain the same kwargs as
        insert_reading(). Missing keys default to None / False.

        Returns:
            Number of rows successfully inserted.
        """
        inserted = 0
        with self._db.get_cursor() as cur:
            for r in readings:
                reading_id = str(uuid.uuid4())
                cur.execute(
                    """
                    INSERT INTO wearable_data (
                        id, user_id, sos_event_id, heart_rate, gsr, spo2,
                        temperature, accelerometer_x, accelerometer_y,
                        accelerometer_z, threat_score, is_distress,
                        device_id, recorded_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        reading_id,
                        r.get("user_id"),
                        r.get("sos_event_id"),
                        r.get("heart_rate"),
                        r.get("gsr"),
                        r.get("spo2"),
                        r.get("temperature"),
                        r.get("accelerometer_x"),
                        r.get("accelerometer_y"),
                        r.get("accelerometer_z"),
                        r.get("threat_score"),
                        int(r.get("is_distress", False)),
                        r.get("device_id"),
                        r.get("recorded_at") or _utc_now(),
                    ),
                )
                inserted += 1

        logger.debug("[WearableRepo] Inserted %d readings.", inserted)
        return inserted

    # ── Read — rolling window ────────────────────────────────

    def get_recent_for_user(
        self,
        user_id: str,
        window_seconds: int = 60,
        limit: int = 100,
    ) -> list[dict]:
        """
        Return the most recent biometric readings within a time window.

        Used by modules/ai/biometric_analyzer.py to build the
        rolling anomaly detection input window.

        Args:
            user_id:        UUID of the user.
            window_seconds: How far back to look (default 60s).
            limit:          Hard cap on rows returned.

        Returns:
            List of reading dicts, oldest first (chronological order).
        """
        cutoff = (
            datetime.now(tz=timezone.utc) - timedelta(seconds=window_seconds)
        ).isoformat(timespec="milliseconds")

        with self._db.get_read_cursor() as cur:
            cur.execute(
                """
                SELECT * FROM wearable_data
                WHERE user_id = ? AND recorded_at >= ?
                ORDER BY recorded_at ASC
                LIMIT ?;
                """,
                (user_id, cutoff, limit),
            )
            return cur.fetchall()

    def get_latest_reading(self, user_id: str) -> Optional[dict]:
        """
        Return the single most recent biometric reading for a user.
        Used by pages/biometric_monitor.py for the live display.
        """
        with self._db.get_read_cursor() as cur:
            cur.execute(
                """
                SELECT * FROM wearable_data
                WHERE user_id = ?
                ORDER BY recorded_at DESC
                LIMIT 1;
                """,
                (user_id,),
            )
            return cur.fetchone()

    def get_by_sos_event(self, sos_event_id: str) -> list[dict]:
        """
        Return all biometric readings tagged to a specific SOS event.

        Used by services/evidence_service.py to package biometric
        evidence for the incident report.
        """
        with self._db.get_read_cursor() as cur:
            cur.execute(
                """
                SELECT * FROM wearable_data
                WHERE sos_event_id = ?
                ORDER BY recorded_at ASC;
                """,
                (sos_event_id,),
            )
            return cur.fetchall()

    # ── Read — baseline statistics ───────────────────────────

    def get_baseline_stats(
        self, user_id: str, lookback_days: int = 7
    ) -> Optional[dict]:
        """
        Compute personal biometric baseline statistics for a user.

        Uses the last `lookback_days` of non-distress readings.
        The biometric_analyzer uses this to detect deviations
        from the user's personal normal (not population normal).

        Returns:
            Dict with avg/min/max/stddev per metric, or None if
            insufficient data (<50 readings in the window).
        """
        cutoff = (
            datetime.now(tz=timezone.utc) - timedelta(days=lookback_days)
        ).isoformat(timespec="milliseconds")

        with self._db.get_read_cursor() as cur:
            cur.execute(
                """
                SELECT
                    COUNT(*)            AS reading_count,
                    AVG(heart_rate)     AS hr_avg,
                    MIN(heart_rate)     AS hr_min,
                    MAX(heart_rate)     AS hr_max,
                    AVG(gsr)            AS gsr_avg,
                    MIN(gsr)            AS gsr_min,
                    MAX(gsr)            AS gsr_max,
                    AVG(spo2)           AS spo2_avg,
                    AVG(temperature)    AS temp_avg
                FROM wearable_data
                WHERE user_id = ?
                  AND recorded_at >= ?
                  AND is_distress = 0;
                """,
                (user_id, cutoff),
            )
            row = cur.fetchone()

        if not row or row.get("reading_count", 0) < 50:
            return None  # Not enough data for a meaningful baseline

        return row

    # ── Read — chart data ────────────────────────────────────

    def get_chart_data(
        self,
        user_id: str,
        hours: int = 1,
        metric: str = "heart_rate",
    ) -> list[dict]:
        """
        Return time-series data for charting on the biometric monitor page.

        Args:
            user_id: UUID of the user.
            hours:   Look-back window in hours.
            metric:  Column name to include alongside recorded_at.

        Returns:
            List of {"recorded_at": ..., metric: ...} dicts.
        """
        allowed_metrics = {"heart_rate", "gsr", "spo2", "temperature", "threat_score"}
        if metric not in allowed_metrics:
            raise ValueError(f"Invalid metric '{metric}'. Allowed: {allowed_metrics}")

        cutoff = (
            datetime.now(tz=timezone.utc) - timedelta(hours=hours)
        ).isoformat(timespec="milliseconds")

        with self._db.get_read_cursor() as cur:
            cur.execute(
                f"""
                SELECT recorded_at, {metric}
                FROM wearable_data
                WHERE user_id = ? AND recorded_at >= ? AND {metric} IS NOT NULL
                ORDER BY recorded_at ASC;
                """,
                (user_id, cutoff),
            )
            return cur.fetchall()

    # ── Housekeeping ─────────────────────────────────────────

    def delete_old_passive_readings(self, days_to_keep: int = 30) -> int:
        """
        Delete passive (non-distress, non-SOS) readings older than
        `days_to_keep` days to prevent unbounded database growth.

        Readings tagged to an SOS event are NEVER deleted —
        they are evidence.
        """
        cutoff = (
            datetime.now(tz=timezone.utc) - timedelta(days=days_to_keep)
        ).isoformat(timespec="milliseconds")

        with self._db.get_cursor() as cur:
            cur.execute(
                """
                DELETE FROM wearable_data
                WHERE sos_event_id IS NULL
                  AND is_distress = 0
                  AND recorded_at < ?;
                """,
                (cutoff,),
            )
            deleted = cur.rowcount

        logger.info("[WearableRepo] Cleaned up %d old passive readings.", deleted)
        return deleted
