# ============================================================
# GuardianHer AI — config/settings.py
#
# Centralised application settings loaded from environment
# variables via python-dotenv.
#
# Design decisions:
#   1. A single `Settings` dataclass is constructed once at
#      module import time and re-exported as the `settings`
#      singleton. Every module that needs a config value does:
#
#          from config.settings import settings
#          key = settings.WATSONX_API_KEY
#
#   2. All types are explicit — no raw os.getenv() calls
#      scattered through the codebase.
#
#   3. `_required()` raises a clear ConfigurationError at
#      startup if a mandatory variable is absent, preventing
#      cryptic AttributeErrors deep in IBM SDK calls.
#
#   4. Sensitive fields use SecretStr so they are masked in
#      logs and repr() output ("[REDACTED]").
#
#   5. Feature flags are parsed as booleans — truthy strings
#      are: "true", "1", "yes" (case-insensitive).
# ============================================================

from __future__ import annotations

import os
import logging
from dataclasses import dataclass, field
from typing import Optional

from dotenv import load_dotenv

from config.constants import Environment

# Load .env file from the project root (silent if absent in prod)
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), "..", ".env"))

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────

class ConfigurationError(RuntimeError):
    """
    Raised at startup when a required environment variable is
    missing or invalid.  Surfaces as a clear error message
    before the Streamlit UI renders.
    """
    pass


class SecretStr(str):
    """
    Thin str subclass that masks its value in repr() and str()
    so API keys never appear in logs or Streamlit tracebacks.

    The raw value is always accessible via `.get_secret()`.
    """

    def __repr__(self) -> str:
        return "[REDACTED]"

    def __str__(self) -> str:
        return "[REDACTED]"

    def get_secret(self) -> str:
        """Return the actual secret value."""
        return super().__str__()


def _required(key: str) -> str:
    """
    Read a mandatory environment variable.
    Raises ConfigurationError with a helpful message if absent.
    """
    value = os.getenv(key)
    if not value:
        raise ConfigurationError(
            f"[GuardianHer AI] Required environment variable '{key}' is not set. "
            f"Copy .env.example to .env and fill in your credentials."
        )
    return value


def _optional(key: str, default: str = "") -> str:
    """Read an optional environment variable, returning `default` if absent."""
    return os.getenv(key, default)


def _secret(key: str, required: bool = True) -> SecretStr:
    """
    Read a secret environment variable and wrap it in SecretStr
    so it is masked in logs.
    """
    value = _required(key) if required else _optional(key)
    return SecretStr(value)


def _bool_flag(key: str, default: bool = False) -> bool:
    """
    Parse a boolean feature flag from an environment variable.
    Truthy: "true", "1", "yes"  (case-insensitive)
    Falsy:  anything else, or absent
    """
    raw = os.getenv(key, str(default)).strip().lower()
    return raw in {"true", "1", "yes"}


# ─────────────────────────────────────────────────────────────
# Settings Dataclass
# ─────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Settings:
    """
    Immutable settings object.  Frozen to prevent accidental
    mutation of config values at runtime.

    Instantiated once as the module-level `settings` singleton.
    """

    # ── Application ──────────────────────────────────────────
    APP_ENV: Environment
    APP_SECRET_KEY: SecretStr
    LOG_LEVEL: str

    # ── IBM watsonx.ai ───────────────────────────────────────
    WATSONX_API_KEY: SecretStr
    WATSONX_PROJECT_ID: str
    WATSONX_URL: str
    WATSONX_MODEL_ID: str

    # ── IBM Watson NLP ───────────────────────────────────────
    WATSON_NLP_API_KEY: SecretStr
    WATSON_NLP_URL: str

    # ── IBM Watson Speech-to-Text ────────────────────────────
    WATSON_STT_API_KEY: SecretStr
    WATSON_STT_URL: str

    # ── IBM Watson Text-to-Speech ────────────────────────────
    WATSON_TTS_API_KEY: SecretStr
    WATSON_TTS_URL: str

    # ── IBM Watson Assistant ─────────────────────────────────
    WATSON_ASSISTANT_API_KEY: SecretStr
    WATSON_ASSISTANT_URL: str
    WATSON_ASSISTANT_ID: str
    WATSON_ASSISTANT_VERSION: str

    # ── IBM Cloud Object Storage ─────────────────────────────
    IBM_COS_API_KEY: SecretStr
    IBM_COS_SERVICE_CRN: str
    IBM_COS_AUTH_ENDPOINT: str
    IBM_COS_ENDPOINT: str
    IBM_COS_BUCKET_NAME: str

    # ── IBM IoT Platform ─────────────────────────────────────
    IBM_IOT_ORG_ID: str
    IBM_IOT_API_KEY: SecretStr
    IBM_IOT_AUTH_TOKEN: SecretStr

    # ── IBM App ID ───────────────────────────────────────────
    IBM_APP_ID_TENANT_ID: str
    IBM_APP_ID_CLIENT_ID: str
    IBM_APP_ID_SECRET: SecretStr
    IBM_APP_ID_OAUTH_URL: str

    # ── Twilio ───────────────────────────────────────────────
    TWILIO_ACCOUNT_SID: str
    TWILIO_AUTH_TOKEN: SecretStr
    TWILIO_FROM_NUMBER: str

    # ── Firebase ─────────────────────────────────────────────
    FIREBASE_CREDENTIALS_PATH: str

    # ── HERE Maps ────────────────────────────────────────────
    HERE_API_KEY: SecretStr
    HERE_ROUTING_URL: str

    # ── Database ─────────────────────────────────────────────
    DATABASE_PATH: str
    DATABASE_ENCRYPTION_KEY: SecretStr

    # ── Feature Flags ────────────────────────────────────────
    ENABLE_MOCK_SENSORS: bool
    ENABLE_MOCK_BLE: bool
    ENABLE_SMS_ALERTS: bool
    ENABLE_VOICE_CALLS: bool
    ENABLE_AI_FAIRNESS_AUDIT: bool
    ENABLE_WATSON_ASSISTANT: bool

    # ── Derived helpers (not from env) ───────────────────────
    IS_DEVELOPMENT: bool = field(init=False)
    IS_PRODUCTION: bool  = field(init=False)

    def __post_init__(self) -> None:
        # Bypass frozen restriction for derived fields using object.__setattr__
        object.__setattr__(self, "IS_DEVELOPMENT", self.APP_ENV == Environment.DEVELOPMENT)
        object.__setattr__(self, "IS_PRODUCTION",  self.APP_ENV == Environment.PRODUCTION)

    def assert_ibm_services_configured(self) -> None:
        """
        Call this at startup in production to validate that
        all IBM service credentials are non-empty.
        Logs a warning in development if values look like placeholders.
        """
        ibm_fields = [
            ("WATSONX_API_KEY",          self.WATSONX_API_KEY),
            ("WATSON_NLP_API_KEY",        self.WATSON_NLP_API_KEY),
            ("WATSON_STT_API_KEY",        self.WATSON_STT_API_KEY),
            ("WATSON_TTS_API_KEY",        self.WATSON_TTS_API_KEY),
            ("WATSON_ASSISTANT_API_KEY",  self.WATSON_ASSISTANT_API_KEY),
            ("IBM_COS_API_KEY",           self.IBM_COS_API_KEY),
            ("IBM_IOT_API_KEY",           self.IBM_IOT_API_KEY),
        ]
        placeholder_hints = {"your-", "replace-", "xxx", "todo"}

        for name, secret in ibm_fields:
            raw = secret.get_secret()
            if any(hint in raw.lower() for hint in placeholder_hints):
                msg = f"[GuardianHer AI] '{name}' looks like a placeholder. Update .env."
                if self.IS_PRODUCTION:
                    raise ConfigurationError(msg)
                logger.warning(msg)


# ─────────────────────────────────────────────────────────────
# Factory Function
# ─────────────────────────────────────────────────────────────

def _build_settings() -> Settings:
    """
    Construct the Settings singleton from environment variables.
    Called once at module import time.

    In development with ENABLE_MOCK_SENSORS=true, IBM credentials
    are treated as optional so the app can run without real keys.
    """
    mock_mode = _bool_flag("ENABLE_MOCK_SENSORS", default=True)
    is_dev    = _optional("APP_ENV", "development") == Environment.DEVELOPMENT

    # In dev+mock mode, IBM API keys fall back to empty strings so
    # the UI loads and mock modules handle all AI calls locally.
    def _ibm_secret(key: str) -> SecretStr:
        return _secret(key, required=not (is_dev and mock_mode))

    try:
        return Settings(
            # ── Application ──────────────────────────────────
            APP_ENV        = Environment(_optional("APP_ENV", "development")),
            APP_SECRET_KEY = _secret("APP_SECRET_KEY", required=False)
                             or SecretStr("dev-secret-change-in-production"),
            LOG_LEVEL      = _optional("LOG_LEVEL", "INFO").upper(),

            # ── IBM watsonx.ai ────────────────────────────────
            WATSONX_API_KEY   = _ibm_secret("WATSONX_API_KEY"),
            WATSONX_PROJECT_ID = _optional("WATSONX_PROJECT_ID", ""),
            WATSONX_URL       = _optional(
                "WATSONX_URL", "https://us-south.ml.cloud.ibm.com"
            ),
            WATSONX_MODEL_ID  = _optional(
                "WATSONX_MODEL_ID", "guardianher-threat-scorer-v1"
            ),

            # ── IBM Watson NLP ────────────────────────────────
            WATSON_NLP_API_KEY = _ibm_secret("WATSON_NLP_API_KEY"),
            WATSON_NLP_URL     = _optional(
                "WATSON_NLP_URL",
                "https://api.us-south.natural-language-understanding.watson.cloud.ibm.com",
            ),

            # ── IBM Watson STT ────────────────────────────────
            WATSON_STT_API_KEY = _ibm_secret("WATSON_STT_API_KEY"),
            WATSON_STT_URL     = _optional(
                "WATSON_STT_URL",
                "https://api.us-south.speech-to-text.watson.cloud.ibm.com",
            ),

            # ── IBM Watson TTS ────────────────────────────────
            WATSON_TTS_API_KEY = _ibm_secret("WATSON_TTS_API_KEY"),
            WATSON_TTS_URL     = _optional(
                "WATSON_TTS_URL",
                "https://api.us-south.text-to-speech.watson.cloud.ibm.com",
            ),

            # ── IBM Watson Assistant ──────────────────────────
            WATSON_ASSISTANT_API_KEY = _ibm_secret("WATSON_ASSISTANT_API_KEY"),
            WATSON_ASSISTANT_URL     = _optional(
                "WATSON_ASSISTANT_URL",
                "https://api.us-south.assistant.watson.cloud.ibm.com",
            ),
            WATSON_ASSISTANT_ID      = _optional("WATSON_ASSISTANT_ID", ""),
            WATSON_ASSISTANT_VERSION = _optional("WATSON_ASSISTANT_VERSION", "2024-08-25"),

            # ── IBM COS ───────────────────────────────────────
            IBM_COS_API_KEY      = _ibm_secret("IBM_COS_API_KEY"),
            IBM_COS_SERVICE_CRN  = _optional("IBM_COS_SERVICE_CRN", ""),
            IBM_COS_AUTH_ENDPOINT = _optional(
                "IBM_COS_AUTH_ENDPOINT",
                "https://iam.cloud.ibm.com/identity/token",
            ),
            IBM_COS_ENDPOINT     = _optional(
                "IBM_COS_ENDPOINT",
                "https://s3.us-south.cloud-object-storage.appdomain.cloud",
            ),
            IBM_COS_BUCKET_NAME  = _optional("IBM_COS_BUCKET_NAME", "guardianher-evidence"),

            # ── IBM IoT ───────────────────────────────────────
            IBM_IOT_ORG_ID     = _optional("IBM_IOT_ORG_ID", ""),
            IBM_IOT_API_KEY    = _ibm_secret("IBM_IOT_API_KEY"),
            IBM_IOT_AUTH_TOKEN = _ibm_secret("IBM_IOT_AUTH_TOKEN"),

            # ── IBM App ID ────────────────────────────────────
            IBM_APP_ID_TENANT_ID = _optional("IBM_APP_ID_TENANT_ID", ""),
            IBM_APP_ID_CLIENT_ID = _optional("IBM_APP_ID_CLIENT_ID", ""),
            IBM_APP_ID_SECRET    = _ibm_secret("IBM_APP_ID_SECRET"),
            IBM_APP_ID_OAUTH_URL = _optional(
                "IBM_APP_ID_OAUTH_URL",
                "https://us-south.appid.cloud.ibm.com/oauth/v4",
            ),

            # ── Twilio ────────────────────────────────────────
            TWILIO_ACCOUNT_SID  = _optional("TWILIO_ACCOUNT_SID", ""),
            TWILIO_AUTH_TOKEN   = _secret("TWILIO_AUTH_TOKEN", required=False),
            TWILIO_FROM_NUMBER  = _optional("TWILIO_FROM_NUMBER", ""),

            # ── Firebase ─────────────────────────────────────
            FIREBASE_CREDENTIALS_PATH = _optional(
                "FIREBASE_CREDENTIALS_PATH",
                "./config/firebase_credentials.json",
            ),

            # ── HERE Maps ────────────────────────────────────
            HERE_API_KEY    = _secret("HERE_API_KEY", required=False),
            HERE_ROUTING_URL = _optional(
                "HERE_ROUTING_URL",
                "https://router.hereapi.com/v8/routes",
            ),

            # ── Database ─────────────────────────────────────
            DATABASE_PATH           = _optional("DATABASE_PATH", "./data/guardianher.db"),
            DATABASE_ENCRYPTION_KEY = _secret("DATABASE_ENCRYPTION_KEY", required=False),

            # ── Feature Flags ─────────────────────────────────
            ENABLE_MOCK_SENSORS      = _bool_flag("ENABLE_MOCK_SENSORS",      default=True),
            ENABLE_MOCK_BLE          = _bool_flag("ENABLE_MOCK_BLE",          default=True),
            ENABLE_SMS_ALERTS        = _bool_flag("ENABLE_SMS_ALERTS",        default=False),
            ENABLE_VOICE_CALLS       = _bool_flag("ENABLE_VOICE_CALLS",       default=False),
            ENABLE_AI_FAIRNESS_AUDIT = _bool_flag("ENABLE_AI_FAIRNESS_AUDIT", default=True),
            ENABLE_WATSON_ASSISTANT  = _bool_flag("ENABLE_WATSON_ASSISTANT",  default=True),
        )
    except (ValueError, KeyError) as exc:
        raise ConfigurationError(
            f"[GuardianHer AI] Settings construction failed: {exc}"
        ) from exc


# ─────────────────────────────────────────────────────────────
# Module-level singleton — the only instance ever created
# ─────────────────────────────────────────────────────────────

settings: Settings = _build_settings()
