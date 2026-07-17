# ============================================================
# GuardianHer AI — config/constants.py
#
# Single source of truth for every magic number, threshold,
# limit, and enumeration used across the application.
#
# Rules:
#   - No value in this file is read from the environment.
#     Environment-dependent values belong in settings.py.
#   - If a numeric literal appears in more than one module,
#     it MUST live here instead.
#   - All enums use str mixins so they serialise to plain
#     strings in JSON payloads and database records.
#
# Import pattern (anywhere in the project):
#   from config.constants import BiometricThresholds, SOSState
# ============================================================

from enum import Enum


# ─────────────────────────────────────────────────────────────
# Application Meta
# ─────────────────────────────────────────────────────────────

APP_NAME: str = "GuardianHer AI"
APP_VERSION: str = "1.0.0"
APP_TAGLINE: str = "AI-Powered Women's Safety Platform"
HACKATHON_NAME: str = "IBM Hackathon 2025"


# ─────────────────────────────────────────────────────────────
# Environment Names
# ─────────────────────────────────────────────────────────────

class Environment(str, Enum):
    """Valid values for the APP_ENV environment variable."""
    DEVELOPMENT = "development"
    PRODUCTION  = "production"
    TEST        = "test"


# ─────────────────────────────────────────────────────────────
# User & Role Constants
# ─────────────────────────────────────────────────────────────

class UserRole(str, Enum):
    """
    RBAC roles enforced by modules/auth/role_checker.py.
    Stored in the users table and embedded in IBM App ID JWT claims.
    """
    USER        = "user"         # Regular app user (default)
    GUARDIAN    = "guardian"     # Emergency contact / family member portal
    RESPONDER   = "responder"    # Police / NGO first responder dashboard
    NGO_ADMIN   = "ngo_admin"    # NGO analytics and case management
    SYSTEM_ADMIN = "system_admin" # Platform administration


MAX_TRUSTED_CONTACTS: int = 10          # Per user limit (FR-M04)
MAX_CONTACT_NAME_LENGTH: int = 100
MAX_CONTACT_PHONE_LENGTH: int = 20


# ─────────────────────────────────────────────────────────────
# Biometric Thresholds
# Used by: modules/ai/biometric_analyzer.py
#          modules/wearable/sensor_processor.py
# ─────────────────────────────────────────────────────────────

class BiometricThresholds:
    """
    Physiological distress thresholds.
    Values derived from published stress-detection research
    (WESAD dataset, 2018; Koldijk et al., 2018).
    """

    # Heart Rate (bpm)
    HR_RESTING_MIN: int    = 40     # Below this → sensor error / unconscious
    HR_RESTING_MAX: int    = 100    # Normal resting upper bound
    HR_ELEVATED: int       = 120    # Mild stress / light exercise
    HR_DISTRESS: int       = 140    # Strong stress signal (FR-W01)
    HR_CRITICAL: int       = 170    # Extreme distress / physical confrontation
    HR_SENSOR_MAX: int     = 220    # Physiological maximum — above is noise

    # Galvanic Skin Response (µS) — multiplier above personal baseline
    GSR_NORMAL_FACTOR: float   = 1.0    # Baseline (personal)
    GSR_ELEVATED_FACTOR: float = 1.5    # Mild stress
    GSR_SPIKE_FACTOR: float    = 2.5    # Distress signal (FR-W01)
    GSR_EXTREME_FACTOR: float  = 4.0    # Panic / extreme fear

    # Sensor sampling
    SENSOR_POLL_INTERVAL_SECONDS: int  = 10     # How often wearable is read
    BIOMETRIC_WINDOW_SECONDS: int      = 60     # Rolling anomaly-detection window
    BASELINE_UPDATE_ALPHA: float       = 0.05   # EMA alpha for baseline update
    BASELINE_WARMUP_READINGS: int      = 50     # Min readings before baseline valid


# ─────────────────────────────────────────────────────────────
# AI Threat Scoring Thresholds
# Used by: modules/ai/threat_scorer.py
#          modules/emergency/escalation_engine.py
# ─────────────────────────────────────────────────────────────

class ThreatLevel(str, Enum):
    """
    Human-readable threat level mapped from a raw score (0.0–1.0).
    Displayed in the UI and logged in sos_events.
    """
    SAFE     = "SAFE"       # score < 0.30
    CAUTION  = "CAUTION"    # 0.30 ≤ score < 0.50
    ELEVATED = "ELEVATED"   # 0.50 ≤ score < 0.75
    HIGH     = "HIGH"       # score ≥ 0.75
    CRITICAL = "CRITICAL"   # score ≥ 0.90  (reserved for combined triggers)


class ThreatScoreThresholds:
    """Numeric boundaries that map raw watsonx.ai scores to ThreatLevel."""
    SAFE_MAX: float     = 0.30
    CAUTION_MAX: float  = 0.50
    ELEVATED_MAX: float = 0.75
    HIGH_MAX: float     = 0.90
    # Above HIGH_MAX → CRITICAL

    # On-device ONNX pre-screen — skip cloud call below this
    ONDEVICE_PASSTHROUGH: float = 0.30

    # Minimum score to trigger any outgoing notification
    NOTIFICATION_TRIGGER: float = 0.50

    # Score required to trigger auto-call to primary contact
    AUTOCALL_TRIGGER: float = 0.75

    # Minimum watsonx.ai inference confidence to trust the score
    MIN_MODEL_CONFIDENCE: float = 0.60


# ─────────────────────────────────────────────────────────────
# SOS Workflow Constants
# Used by: services/sos_service.py
#          modules/emergency/sos_trigger.py
#          modules/emergency/escalation_engine.py
# ─────────────────────────────────────────────────────────────

class SOSState(str, Enum):
    """
    SOS event state machine states.
    Transitions: IDLE → TRIGGERED → CONFIRMING → ACTIVE
                                               → CANCELLED
                                               → FALSE_ALARM
                 ACTIVE → RESOLVED
    Invalid transitions are silently rejected (no exception raised).
    """
    IDLE        = "IDLE"
    TRIGGERED   = "TRIGGERED"
    CONFIRMING  = "CONFIRMING"   # 15-second window for user to cancel
    ACTIVE      = "ACTIVE"       # Escalation dispatched
    RESOLVED    = "RESOLVED"     # Responder or user marked safe
    CANCELLED   = "CANCELLED"    # User cancelled within window
    FALSE_ALARM = "FALSE_ALARM"  # AI-flagged or user-confirmed false positive


class SOSTriggerSource(str, Enum):
    """What caused the SOS event — logged for analytics and fairness auditing."""
    MANUAL        = "MANUAL"        # User pressed SOS button
    BIOMETRIC     = "BIOMETRIC"     # Biometric anomaly score exceeded threshold
    VOICE         = "VOICE"         # Wake-word / distress phrase detected
    WEARABLE      = "WEARABLE"      # Wearable gesture (squeeze/hold)
    CHECKIN_EXPIRY = "CHECKIN_EXPIRY" # Safe-arrival timer expired without confirmation


class SOSWorkflowTiming:
    """All time constants governing the SOS workflow (in seconds)."""
    CONFIRMATION_WINDOW: int  = 15   # Seconds user has to cancel before auto-escalate
    NOTIFICATION_RETRY_DELAY: int = 5    # Seconds between notification retry attempts
    NOTIFICATION_RETRY_COUNT: int = 2    # Number of retry attempts per channel
    GPS_TRACK_INTERVAL: int   = 15   # Seconds between GPS evidence track points
    AUDIO_CAPTURE_MAX: int    = 300  # Maximum audio evidence duration (5 minutes)
    THREAT_SCORE_CACHE_TTL: int = 30 # Seconds to reuse last score (avoid hammering AI)


# ─────────────────────────────────────────────────────────────
# Escalation Channel Priority
# Used by: modules/emergency/escalation_engine.py
#          modules/notifications/notification_router.py
# ─────────────────────────────────────────────────────────────

class AlertChannel(str, Enum):
    """
    Notification delivery channels, in priority order.
    Router attempts channels from highest to lowest priority
    until at least one succeeds.
    """
    PUSH  = "PUSH"    # FCM push notification (fastest, requires internet)
    SMS   = "SMS"     # Twilio SMS (works on 2G, no internet needed)
    CALL  = "CALL"    # Twilio auto-call (no app needed on recipient)
    EMAIL = "EMAIL"   # SMTP email (low-priority fallback)


class EscalationPolicy:
    """
    Defines which channels are activated per ThreatLevel.
    Keys are ThreatLevel enum values.
    """
    CHANNEL_MAP: dict = {
        ThreatLevel.CAUTION:  [AlertChannel.PUSH],
        ThreatLevel.ELEVATED: [AlertChannel.PUSH, AlertChannel.SMS],
        ThreatLevel.HIGH:     [AlertChannel.PUSH, AlertChannel.SMS, AlertChannel.CALL],
        ThreatLevel.CRITICAL: [AlertChannel.PUSH, AlertChannel.SMS, AlertChannel.CALL],
    }

    # Include police alert API at or above this threat level
    POLICE_ALERT_THRESHOLD: ThreatLevel = ThreatLevel.HIGH


# ─────────────────────────────────────────────────────────────
# Check-In Timer Constants
# Used by: services/checkin_service.py
# ─────────────────────────────────────────────────────────────

class CheckInTiming:
    MIN_DURATION_MINUTES: int  = 5     # Shortest allowed check-in window
    MAX_DURATION_HOURS: int    = 24    # Longest allowed check-in window
    WARNING_LEAD_MINUTES: int  = 5     # Send "are you okay?" this many mins before expiry
    GRACE_PERIOD_SECONDS: int  = 60    # Extra window after expiry before SOS triggers


# ─────────────────────────────────────────────────────────────
# Evidence & Storage Constants
# Used by: services/evidence_service.py
#          modules/emergency/evidence_recorder.py
# ─────────────────────────────────────────────────────────────

class EvidenceType(str, Enum):
    """Types of evidence artifacts stored per incident."""
    AUDIO      = "AUDIO"       # MP3/WAV background recording
    GPS_TRACK  = "GPS_TRACK"   # GeoJSON LineString of coordinates
    BIOMETRIC  = "BIOMETRIC"   # JSON export of sensor readings during event
    PHOTO      = "PHOTO"       # Auto-captured front-camera photo
    TRANSCRIPT = "TRANSCRIPT"  # Watson STT transcript of audio evidence
    AI_REPORT  = "AI_REPORT"   # watsonx.ai threat analysis JSON


class EvidenceStorage:
    DOWNLOAD_LINK_TTL_HOURS: int  = 72    # Pre-signed URL expiry
    MAX_AUDIO_SIZE_MB: int        = 50    # Maximum single audio file
    MAX_PHOTO_SIZE_MB: int        = 10    # Maximum single photo
    HASH_ALGORITHM: str           = "sha256"  # Integrity hash algorithm
    ENCRYPTION_ALGORITHM: str     = "AES-256-CBC"


# ─────────────────────────────────────────────────────────────
# AI Fairness Constants
# Used by: modules/ai/fairness_monitor.py
# ─────────────────────────────────────────────────────────────

class FairnessThresholds:
    """
    IBM AI Fairness 360 metric thresholds.
    If any metric breaches its threshold, the NGO dashboard
    displays a bias alert and the team is notified.
    """
    DISPARATE_IMPACT_RATIO_MIN: float    = 0.80   # Must be ≥ 0.80 (80% rule)
    STATISTICAL_PARITY_DIFF_MAX: float   = 0.10   # Must be ≤ ±0.10
    EQUAL_OPPORTUNITY_DIFF_MAX: float    = 0.10   # Must be ≤ ±0.10
    AUDIT_WINDOW_DAYS: int               = 30     # Rolling window for audit
    AUDIT_SCHEDULE_HOURS: int            = 24     # Run audit every 24 hours
    MIN_SAMPLE_SIZE_FOR_AUDIT: int       = 100    # Skip audit if fewer records


# ─────────────────────────────────────────────────────────────
# Database Constants
# Used by: database/connection.py, database/schema.py
# ─────────────────────────────────────────────────────────────

class DatabaseConfig:
    SCHEMA_VERSION: int   = 1        # Increment when schema changes
    WAL_MODE: bool        = True     # Write-Ahead Logging for concurrent reads
    FOREIGN_KEYS: bool    = True     # Enforce FK constraints
    BUSY_TIMEOUT_MS: int  = 5000    # How long to wait on locked DB before error


# ─────────────────────────────────────────────────────────────
# Maps & Geospatial Constants
# Used by: modules/maps/route_planner.py
#          modules/maps/crime_heatmap.py
#          modules/maps/safe_zone_checker.py
# ─────────────────────────────────────────────────────────────

class MapConfig:
    DEFAULT_ZOOM: int            = 15    # Streamlit folium default zoom level
    SAFE_ZONE_RADIUS_METERS: int = 500   # Proximity radius for safe zone lookup
    ROUTE_MAX_OPTIONS: int       = 3     # Number of ranked route options shown
    HEATMAP_CACHE_TTL_MINUTES: int = 15  # Crime tile cache duration
    CRIME_RADIUS_METERS: int     = 300   # Crime density lookup radius per route point

    # Folium map tile provider
    TILE_PROVIDER: str = "CartoDB positron"

    # Route safety score weights (must sum to 1.0)
    WEIGHT_CRIME_DENSITY: float   = 0.50
    WEIGHT_LIGHTING: float        = 0.25
    WEIGHT_FOOT_TRAFFIC: float    = 0.15
    WEIGHT_TIME_OF_DAY: float     = 0.10


# ─────────────────────────────────────────────────────────────
# Incident Report Constants
# Used by: modules/emergency/incident_builder.py
# ─────────────────────────────────────────────────────────────

class IncidentStatus(str, Enum):
    """Lifecycle states for an incident record."""
    ACTIVE   = "ACTIVE"    # SOS is live
    RESOLVED = "RESOLVED"  # Situation resolved, evidence collected
    CLOSED   = "CLOSED"    # Legal process complete / archived


class ReportFormat(str, Enum):
    """Output formats for generated incident reports."""
    PDF      = "PDF"
    JSON     = "JSON"
    FIR      = "FIR"       # First Information Report (India)
    POLICE   = "POLICE"    # Generic police report template


# ─────────────────────────────────────────────────────────────
# UI / Display Constants
# Used by: pages/*, ui/*
# ─────────────────────────────────────────────────────────────

class UIColors:
    """IBM-aligned palette — matches assets/css/style.css."""
    PRIMARY_BLUE: str   = "#3b82d4"
    DEEP_PURPLE: str    = "#7c5cd8"
    SUCCESS_GREEN: str  = "#27ae60"
    ALERT_ORANGE: str   = "#e67e22"
    DANGER_RED: str     = "#c0392b"
    BACKGROUND: str     = "#ffffff"
    SURFACE: str        = "#f7f8fa"
    BORDER: str         = "#e5e7eb"
    TEXT_PRIMARY: str   = "#1f2328"
    TEXT_MUTED: str     = "#57606a"


class ThreatLevelColors:
    """Map ThreatLevel enum values to display colours."""
    COLOR_MAP: dict = {
        ThreatLevel.SAFE:     UIColors.SUCCESS_GREEN,
        ThreatLevel.CAUTION:  UIColors.ALERT_ORANGE,
        ThreatLevel.ELEVATED: UIColors.ALERT_ORANGE,
        ThreatLevel.HIGH:     UIColors.DANGER_RED,
        ThreatLevel.CRITICAL: UIColors.DANGER_RED,
    }

    EMOJI_MAP: dict = {
        ThreatLevel.SAFE:     "🟢",
        ThreatLevel.CAUTION:  "🟡",
        ThreatLevel.ELEVATED: "🟠",
        ThreatLevel.HIGH:     "🔴",
        ThreatLevel.CRITICAL: "🆘",
    }


# ─────────────────────────────────────────────────────────────
# Streamlit Session State Keys
# Used by: app.py, pages/*, modules/auth/session_manager.py
# Centralised here to prevent typo-driven KeyError bugs.
# ─────────────────────────────────────────────────────────────

class SessionKeys:
    """Keys used with st.session_state throughout the app."""
    CURRENT_PAGE: str        = "current_page"
    AUTHENTICATED: str       = "authenticated"
    USER_ID: str             = "user_id"
    USER_ROLE: str           = "user_role"
    USER_NAME: str           = "user_name"
    JWT_TOKEN: str           = "jwt_token"
    ACTIVE_SOS_ID: str       = "active_sos_id"
    ACTIVE_SOS_STATE: str    = "active_sos_state"
    CURRENT_LAT: str         = "current_lat"
    CURRENT_LNG: str         = "current_lng"
    BIOMETRIC_BUFFER: str    = "biometric_buffer"
    THREAT_SCORE: str        = "threat_score"
    WATSON_SESSION_ID: str   = "watson_session_id"
    CHECKIN_TIMER_ID: str    = "checkin_timer_id"


# ─────────────────────────────────────────────────────────────
# Page Navigation Names
# Used by: app.py sidebar router
# ─────────────────────────────────────────────────────────────

class Pages:
    """Page identifiers for the sidebar navigation router in app.py."""
    HOME               = "home"
    SOS                = "sos"
    SAFE_ROUTE         = "safe_route"
    CHECK_IN           = "check_in"
    CONTACTS           = "contacts"
    AI_COMPANION       = "ai_companion"
    INCIDENT_REPORT    = "incident_report"
    BIOMETRIC_MONITOR  = "biometric_monitor"
    SETTINGS           = "settings"
    RESPONDER_DASHBOARD = "responder_dashboard"
