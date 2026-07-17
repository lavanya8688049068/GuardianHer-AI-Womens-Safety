# ============================================================
# GuardianHer AI — database/schema.py
#
# Single source of truth for all SQLite table definitions.
#
# Design decisions:
#   1. All CREATE TABLE statements use IF NOT EXISTS so this
#      module is safe to run on every application startup.
#   2. Every table uses TEXT UUIDs as primary keys (not
#      INTEGER AUTOINCREMENT) to ensure IDs are portable when
#      migrating from SQLite to IBM Db2 in production.
#   3. Every timestamp column is stored as TEXT in ISO-8601
#      format (YYYY-MM-DDTHH:MM:SS.ffffffZ) for readability
#      and cross-database portability.
#   4. Foreign key constraints are declared on every relation.
#      They are enforced only when PRAGMA foreign_keys = ON is
#      set in connection.py — which it always is.
#   5. The sos_events and audit_logs tables are append-only by
#      convention. No UPDATE or DELETE is permitted on them.
#      The repositories enforce this rule programmatically.
#
# Tables:
#   users               — registered app users
#   emergency_contacts  — each user's trusted contacts
#   sos_events          — append-only SOS event log
#   incident_reports    — incident lifecycle records
#   wearable_data       — biometric sensor readings
#   safe_zones          — curated safe-location registry
#   audit_logs          — immutable application audit trail
# ============================================================

from __future__ import annotations

# ─────────────────────────────────────────────────────────────
# Schema version — increment whenever any DDL changes.
# migrations.py reads this to decide whether to run upgrades.
# ─────────────────────────────────────────────────────────────
SCHEMA_VERSION: int = 1

# ─────────────────────────────────────────────────────────────
# Table: users
# Stores registered GuardianHer AI application users.
# ─────────────────────────────────────────────────────────────
CREATE_USERS_TABLE = """
CREATE TABLE IF NOT EXISTS users (
    id              TEXT PRIMARY KEY,           -- UUID v4
    name            TEXT NOT NULL,
    email           TEXT UNIQUE,
    phone           TEXT UNIQUE,
    role            TEXT NOT NULL DEFAULT 'user',
    -- role: user | guardian | responder | ngo_admin | system_admin
    language        TEXT NOT NULL DEFAULT 'en', -- ISO-639-1 language code
    is_active       INTEGER NOT NULL DEFAULT 1, -- 1=active, 0=deactivated
    ibm_app_id_sub  TEXT UNIQUE,                -- IBM App ID subject claim (JWT sub)
    created_at      TEXT NOT NULL,              -- ISO-8601 UTC timestamp
    updated_at      TEXT NOT NULL               -- ISO-8601 UTC timestamp
);
"""

# Index on phone for fast contact lookup during SOS dispatch
CREATE_USERS_IDX_PHONE = """
CREATE INDEX IF NOT EXISTS idx_users_phone ON users (phone);
"""

CREATE_USERS_IDX_EMAIL = """
CREATE INDEX IF NOT EXISTS idx_users_email ON users (email);
"""

# ─────────────────────────────────────────────────────────────
# Table: emergency_contacts
# Each row is one trusted contact for one user.
# A user may have up to MAX_TRUSTED_CONTACTS (10) contacts.
# ─────────────────────────────────────────────────────────────
CREATE_EMERGENCY_CONTACTS_TABLE = """
CREATE TABLE IF NOT EXISTS emergency_contacts (
    id              TEXT PRIMARY KEY,           -- UUID v4
    user_id         TEXT NOT NULL,              -- owner of this contact list
    name            TEXT NOT NULL,
    phone           TEXT NOT NULL,
    email           TEXT,
    relationship    TEXT,                       -- family | friend | colleague | other
    priority        INTEGER NOT NULL DEFAULT 1, -- 1 = alerted first; lower = higher priority
    alert_channels  TEXT NOT NULL DEFAULT '["sms","call"]',
    -- JSON array: ["push","sms","call","email"]
    is_active       INTEGER NOT NULL DEFAULT 1,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);
"""

CREATE_EMERGENCY_CONTACTS_IDX_USER = """
CREATE INDEX IF NOT EXISTS idx_emergency_contacts_user_id
    ON emergency_contacts (user_id, priority);
"""

# ─────────────────────────────────────────────────────────────
# Table: sos_events
# APPEND-ONLY log of every SOS trigger and state transition.
# No UPDATE or DELETE is ever issued against this table —
# this ensures a tamper-evident chain of custody.
# ─────────────────────────────────────────────────────────────
CREATE_SOS_EVENTS_TABLE = """
CREATE TABLE IF NOT EXISTS sos_events (
    id              TEXT PRIMARY KEY,           -- UUID v4
    user_id         TEXT NOT NULL,
    trigger_source  TEXT NOT NULL,
    -- trigger_source: MANUAL | BIOMETRIC | VOICE | WEARABLE | CHECKIN_EXPIRY
    status          TEXT NOT NULL DEFAULT 'TRIGGERED',
    -- status: TRIGGERED | CONFIRMING | ACTIVE | RESOLVED | CANCELLED | FALSE_ALARM
    threat_score    REAL,                       -- 0.0–1.0 from watsonx.ai (NULL if scoring failed)
    threat_level    TEXT,                       -- SAFE | CAUTION | ELEVATED | HIGH | CRITICAL
    latitude        REAL,                       -- GPS coordinates at trigger time
    longitude       REAL,
    address         TEXT,                       -- Reverse-geocoded address (optional)
    notes           TEXT,                       -- Free-text notes added during/after event
    responder_id    TEXT,                       -- NULL until a responder acknowledges
    triggered_at    TEXT NOT NULL,              -- ISO-8601 UTC
    resolved_at     TEXT,                       -- NULL until resolved/cancelled
    FOREIGN KEY (user_id)      REFERENCES users (id),
    FOREIGN KEY (responder_id) REFERENCES users (id)
);
"""

CREATE_SOS_EVENTS_IDX_USER = """
CREATE INDEX IF NOT EXISTS idx_sos_events_user_id
    ON sos_events (user_id, triggered_at DESC);
"""

CREATE_SOS_EVENTS_IDX_STATUS = """
CREATE INDEX IF NOT EXISTS idx_sos_events_status
    ON sos_events (status, triggered_at DESC);
"""

# ─────────────────────────────────────────────────────────────
# Table: incident_reports
# One incident report per SOS event (created after activation).
# Stores the assembled evidence manifest and generated reports.
# ─────────────────────────────────────────────────────────────
CREATE_INCIDENT_REPORTS_TABLE = """
CREATE TABLE IF NOT EXISTS incident_reports (
    id              TEXT PRIMARY KEY,           -- UUID v4
    sos_event_id    TEXT NOT NULL UNIQUE,       -- 1-to-1 with sos_events
    user_id         TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'ACTIVE',
    -- status: ACTIVE | RESOLVED | CLOSED
    summary         TEXT,                       -- Watson NLP–generated description
    incident_type   TEXT,                       -- harassment | assault | stalking | domestic | other
    evidence_audio  TEXT,                       -- Storage path / IBM COS key for audio file
    evidence_gps    TEXT,                       -- Storage path / IBM COS key for GPS GeoJSON
    evidence_photo  TEXT,                       -- Storage path / IBM COS key for photo
    audio_hash      TEXT,                       -- SHA-256 integrity hash for audio
    gps_hash        TEXT,                       -- SHA-256 integrity hash for GPS track
    photo_hash      TEXT,                       -- SHA-256 integrity hash for photo
    ai_analysis     TEXT,                       -- JSON blob: watsonx.ai threat analysis output
    pdf_report_path TEXT,                       -- Path to generated PDF report
    fir_draft       TEXT,                       -- Generated FIR / police report text
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    FOREIGN KEY (sos_event_id) REFERENCES sos_events (id),
    FOREIGN KEY (user_id)      REFERENCES users (id)
);
"""

CREATE_INCIDENT_REPORTS_IDX_USER = """
CREATE INDEX IF NOT EXISTS idx_incident_reports_user_id
    ON incident_reports (user_id, created_at DESC);
"""

# ─────────────────────────────────────────────────────────────
# Table: wearable_data
# Time-series biometric readings from the wearable device.
# Rows are append-only; no UPDATE is needed.
# ─────────────────────────────────────────────────────────────
CREATE_WEARABLE_DATA_TABLE = """
CREATE TABLE IF NOT EXISTS wearable_data (
    id              TEXT PRIMARY KEY,           -- UUID v4
    user_id         TEXT NOT NULL,
    sos_event_id    TEXT,                       -- NULL during passive monitoring
    heart_rate      REAL,                       -- bpm
    gsr             REAL,                       -- Galvanic Skin Response (µS)
    spo2            REAL,                       -- Blood oxygen %
    temperature     REAL,                       -- Skin temperature (°C)
    accelerometer_x REAL,                       -- m/s² — motion vectors
    accelerometer_y REAL,
    accelerometer_z REAL,
    threat_score    REAL,                       -- On-device ONNX pre-score (0.0–1.0)
    is_distress     INTEGER NOT NULL DEFAULT 0, -- 1 if anomaly detected
    device_id       TEXT,                       -- Wearable hardware identifier
    recorded_at     TEXT NOT NULL,              -- ISO-8601 UTC — sensor sample timestamp
    FOREIGN KEY (user_id)      REFERENCES users (id),
    FOREIGN KEY (sos_event_id) REFERENCES sos_events (id)
);
"""

CREATE_WEARABLE_DATA_IDX_USER = """
CREATE INDEX IF NOT EXISTS idx_wearable_data_user_time
    ON wearable_data (user_id, recorded_at DESC);
"""

CREATE_WEARABLE_DATA_IDX_SOS = """
CREATE INDEX IF NOT EXISTS idx_wearable_data_sos
    ON wearable_data (sos_event_id) WHERE sos_event_id IS NOT NULL;
"""

# ─────────────────────────────────────────────────────────────
# Table: safe_zones
# Curated registry of safe locations shown on the map.
# Populated from safe_zones.json on startup and
# updated by crowd-sourced and government data feeds.
# ─────────────────────────────────────────────────────────────
CREATE_SAFE_ZONES_TABLE = """
CREATE TABLE IF NOT EXISTS safe_zones (
    id              TEXT PRIMARY KEY,           -- UUID v4
    name            TEXT NOT NULL,
    zone_type       TEXT NOT NULL,
    -- zone_type: hospital | police_station | pharmacy | fire_station | shelter | safe_haven
    latitude        REAL NOT NULL,
    longitude       REAL NOT NULL,
    address         TEXT,
    phone           TEXT,
    is_24h          INTEGER NOT NULL DEFAULT 0, -- 1 if open 24 hours
    is_verified     INTEGER NOT NULL DEFAULT 0, -- 1 if government-verified
    city            TEXT,
    country         TEXT NOT NULL DEFAULT 'IN', -- ISO-3166-1 alpha-2
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);
"""

CREATE_SAFE_ZONES_IDX_GEO = """
CREATE INDEX IF NOT EXISTS idx_safe_zones_geo
    ON safe_zones (latitude, longitude);
"""

CREATE_SAFE_ZONES_IDX_TYPE = """
CREATE INDEX IF NOT EXISTS idx_safe_zones_type
    ON safe_zones (zone_type, is_24h);
"""

# ─────────────────────────────────────────────────────────────
# Table: audit_logs
# APPEND-ONLY immutable audit trail.
# Records every security-relevant event in the system.
# Matches the SOSAuditFormatter JSON output structure.
# ─────────────────────────────────────────────────────────────
CREATE_AUDIT_LOGS_TABLE = """
CREATE TABLE IF NOT EXISTS audit_logs (
    id              TEXT PRIMARY KEY,           -- UUID v4
    event_type      TEXT NOT NULL,
    -- e.g. USER_CREATED | SOS_TRIGGERED | SOS_RESOLVED | CONTACT_ADDED
    --      EVIDENCE_UPLOADED | AI_INFERENCE | RESPONDER_DISPATCHED
    user_id         TEXT,                       -- actor (NULL for system events)
    sos_event_id    TEXT,                       -- related SOS (NULL if not SOS-related)
    severity        TEXT NOT NULL DEFAULT 'INFO',
    -- severity: DEBUG | INFO | WARNING | ERROR | CRITICAL
    description     TEXT NOT NULL,              -- human-readable description
    metadata        TEXT,                       -- JSON blob with event-specific details
    ip_address      TEXT,                       -- client IP if available
    created_at      TEXT NOT NULL               -- ISO-8601 UTC — immutable once set
    -- No FOREIGN KEYs intentionally: audit log must survive even if
    -- referenced rows are deleted (GDPR erasure of user data).
);
"""

CREATE_AUDIT_LOGS_IDX_EVENT = """
CREATE INDEX IF NOT EXISTS idx_audit_logs_event_type
    ON audit_logs (event_type, created_at DESC);
"""

CREATE_AUDIT_LOGS_IDX_USER = """
CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id
    ON audit_logs (user_id, created_at DESC) WHERE user_id IS NOT NULL;
"""

CREATE_AUDIT_LOGS_IDX_SOS = """
CREATE INDEX IF NOT EXISTS idx_audit_logs_sos
    ON audit_logs (sos_event_id) WHERE sos_event_id IS NOT NULL;
"""

# ─────────────────────────────────────────────────────────────
# Schema version tracking table
# migrations.py reads/writes this to track applied versions.
# ─────────────────────────────────────────────────────────────
CREATE_SCHEMA_VERSIONS_TABLE = """
CREATE TABLE IF NOT EXISTS schema_versions (
    version         INTEGER PRIMARY KEY,
    description     TEXT NOT NULL,
    applied_at      TEXT NOT NULL
);
"""

# ─────────────────────────────────────────────────────────────
# Ordered DDL execution list
# migrations.py iterates this list in order on every startup.
# ─────────────────────────────────────────────────────────────
ALL_CREATE_STATEMENTS: list[str] = [
    CREATE_SCHEMA_VERSIONS_TABLE,
    CREATE_USERS_TABLE,
    CREATE_USERS_IDX_PHONE,
    CREATE_USERS_IDX_EMAIL,
    CREATE_EMERGENCY_CONTACTS_TABLE,
    CREATE_EMERGENCY_CONTACTS_IDX_USER,
    CREATE_SOS_EVENTS_TABLE,
    CREATE_SOS_EVENTS_IDX_USER,
    CREATE_SOS_EVENTS_IDX_STATUS,
    CREATE_INCIDENT_REPORTS_TABLE,
    CREATE_INCIDENT_REPORTS_IDX_USER,
    CREATE_WEARABLE_DATA_TABLE,
    CREATE_WEARABLE_DATA_IDX_USER,
    CREATE_WEARABLE_DATA_IDX_SOS,
    CREATE_SAFE_ZONES_TABLE,
    CREATE_SAFE_ZONES_IDX_GEO,
    CREATE_SAFE_ZONES_IDX_TYPE,
    CREATE_AUDIT_LOGS_TABLE,
    CREATE_AUDIT_LOGS_IDX_EVENT,
    CREATE_AUDIT_LOGS_IDX_USER,
    CREATE_AUDIT_LOGS_IDX_SOS,
]
