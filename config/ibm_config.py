# ============================================================
# GuardianHer AI — config/ibm_config.py
#
# Single source of truth for all IBM service client
# instantiation and configuration objects.
#
# Design decisions:
#   1. Each IBM service has a dedicated factory function that
#      returns a fully-configured SDK client.  Callers never
#      construct clients themselves — they call the factory:
#
#          from config.ibm_config import get_watsonx_client
#          client = get_watsonx_client()
#
#   2. Clients are cached after first construction using a
#      module-level dict (_client_cache).  IBM SDK clients
#      are stateful and expensive to construct — we create
#      each one exactly once per process.
#
#   3. In mock/dev mode (ENABLE_MOCK_SENSORS=true), factory
#      functions return None without raising exceptions.
#      Callers check for None and use mock implementations.
#
#   4. All credential reads go through `settings` — no direct
#      os.getenv() calls in this file.
#
# IBM services configured here:
#   - IBM watsonx.ai            (threat scoring inference)
#   - IBM Watson NLP            (distress keyword / sentiment)
#   - IBM Watson STT            (ambient audio transcription)
#   - IBM Watson TTS            (spoken alerts / voice UI)
#   - IBM Watson Assistant      (post-incident companion)
#   - IBM Cloud Object Storage  (encrypted evidence vault)
#   - IBM IoT Platform          (wearable sensor MQTT broker)
#   - IBM App ID                (OAuth 2.0 identity)
# ============================================================

from __future__ import annotations

import logging
from typing import Any, Optional

from config.settings import settings, ConfigurationError

logger = logging.getLogger(__name__)

# Module-level client cache — each service client is instantiated once
_client_cache: dict[str, Any] = {}


# ─────────────────────────────────────────────────────────────
# Internal Helpers
# ─────────────────────────────────────────────────────────────

def _is_mock_mode() -> bool:
    """
    Returns True if the app is running in development mock mode.
    In mock mode, IBM clients return None and mock modules take over.
    """
    return settings.ENABLE_MOCK_SENSORS and settings.IS_DEVELOPMENT


def _get_cached(key: str) -> Optional[Any]:
    """Return a previously constructed client from the cache, or None."""
    return _client_cache.get(key)


def _set_cached(key: str, client: Any) -> Any:
    """Store a constructed client in the cache and return it."""
    _client_cache[key] = client
    return client


def _warn_mock(service_name: str) -> None:
    """Log a consistent mock-mode warning for a service."""
    logger.warning(
        "[GuardianHer AI] %s is running in MOCK MODE. "
        "Set ENABLE_MOCK_SENSORS=false and provide real credentials for production.",
        service_name,
    )


# ─────────────────────────────────────────────────────────────
# 1. IBM watsonx.ai
#    Used by: modules/ai/threat_scorer.py
#             modules/ai/route_scorer.py
# ─────────────────────────────────────────────────────────────

def get_watsonx_client() -> Optional[Any]:
    """
    Return a configured IBM watsonx.ai APIClient.

    The client is used to:
      - Call the threat scoring LSTM model endpoint
      - Call the route safety ranking model endpoint
      - Retrieve model deployment metadata

    Returns:
        ibm_watsonx_ai.APIClient instance, or None in mock mode.

    Raises:
        ConfigurationError: If required credentials are missing in production.
    """
    cache_key = "watsonx"
    if cached := _get_cached(cache_key):
        return cached

    if _is_mock_mode():
        _warn_mock("watsonx.ai")
        return None

    try:
        from ibm_watsonx_ai import APIClient, Credentials  # type: ignore

        credentials = Credentials(
            url=settings.WATSONX_URL,
            api_key=settings.WATSONX_API_KEY.get_secret(),
        )
        client = APIClient(credentials=credentials, project_id=settings.WATSONX_PROJECT_ID)
        logger.info("[GuardianHer AI] watsonx.ai client initialised (project: %s)", settings.WATSONX_PROJECT_ID)
        return _set_cached(cache_key, client)

    except ImportError:
        raise ConfigurationError(
            "ibm-watsonx-ai package is not installed. Run: pip install ibm-watsonx-ai"
        )
    except Exception as exc:
        raise ConfigurationError(
            f"[GuardianHer AI] Failed to initialise watsonx.ai client: {exc}"
        ) from exc


# ─────────────────────────────────────────────────────────────
# 2. IBM Watson NLP (Natural Language Understanding)
#    Used by: modules/ai/nlp_processor.py
# ─────────────────────────────────────────────────────────────

def get_watson_nlu_client() -> Optional[Any]:
    """
    Return a configured IBM Watson NaturalLanguageUnderstanding client.

    Used to:
      - Extract distress keywords from audio transcripts
      - Analyse sentiment and emotion (fear/anger) scores
      - Classify incident type from free-text descriptions
      - Extract location entities from incident narratives

    Returns:
        ibm_watson.NaturalLanguageUnderstandingV1 instance, or None in mock mode.
    """
    cache_key = "watson_nlu"
    if cached := _get_cached(cache_key):
        return cached

    if _is_mock_mode():
        _warn_mock("Watson NLP (NLU)")
        return None

    try:
        from ibm_watson import NaturalLanguageUnderstandingV1  # type: ignore
        from ibm_cloud_sdk_core.authenticators import IAMAuthenticator  # type: ignore

        authenticator = IAMAuthenticator(settings.WATSON_NLP_API_KEY.get_secret())
        client = NaturalLanguageUnderstandingV1(
            version="2022-04-07",
            authenticator=authenticator,
        )
        client.set_service_url(settings.WATSON_NLP_URL)
        logger.info("[GuardianHer AI] Watson NLU client initialised.")
        return _set_cached(cache_key, client)

    except ImportError:
        raise ConfigurationError(
            "ibm-watson package is not installed. Run: pip install ibm-watson"
        )
    except Exception as exc:
        raise ConfigurationError(
            f"[GuardianHer AI] Failed to initialise Watson NLU client: {exc}"
        ) from exc


# ─────────────────────────────────────────────────────────────
# 3. IBM Watson Speech-to-Text
#    Used by: modules/ai/speech_handler.py
# ─────────────────────────────────────────────────────────────

def get_watson_stt_client() -> Optional[Any]:
    """
    Return a configured IBM Watson SpeechToText client.

    Used to:
      - Transcribe ambient audio evidence during an SOS event
      - Detect voice distress wake-phrase in opt-in audio monitoring
      - Generate evidence transcript for incident reports

    Returns:
        ibm_watson.SpeechToTextV1 instance, or None in mock mode.
    """
    cache_key = "watson_stt"
    if cached := _get_cached(cache_key):
        return cached

    if _is_mock_mode():
        _warn_mock("Watson Speech-to-Text")
        return None

    try:
        from ibm_watson import SpeechToTextV1  # type: ignore
        from ibm_cloud_sdk_core.authenticators import IAMAuthenticator  # type: ignore

        authenticator = IAMAuthenticator(settings.WATSON_STT_API_KEY.get_secret())
        client = SpeechToTextV1(authenticator=authenticator)
        client.set_service_url(settings.WATSON_STT_URL)
        logger.info("[GuardianHer AI] Watson STT client initialised.")
        return _set_cached(cache_key, client)

    except ImportError:
        raise ConfigurationError(
            "ibm-watson package is not installed. Run: pip install ibm-watson"
        )
    except Exception as exc:
        raise ConfigurationError(
            f"[GuardianHer AI] Failed to initialise Watson STT client: {exc}"
        ) from exc


# ─────────────────────────────────────────────────────────────
# 4. IBM Watson Text-to-Speech
#    Used by: modules/ai/speech_handler.py
# ─────────────────────────────────────────────────────────────

def get_watson_tts_client() -> Optional[Any]:
    """
    Return a configured IBM Watson TextToSpeech client.

    Used to:
      - Generate spoken safety alerts in regional languages
      - Enable voice-first navigation for low-literacy users
      - Read out post-incident companion responses aloud

    Returns:
        ibm_watson.TextToSpeechV1 instance, or None in mock mode.
    """
    cache_key = "watson_tts"
    if cached := _get_cached(cache_key):
        return cached

    if _is_mock_mode():
        _warn_mock("Watson Text-to-Speech")
        return None

    try:
        from ibm_watson import TextToSpeechV1  # type: ignore
        from ibm_cloud_sdk_core.authenticators import IAMAuthenticator  # type: ignore

        authenticator = IAMAuthenticator(settings.WATSON_TTS_API_KEY.get_secret())
        client = TextToSpeechV1(authenticator=authenticator)
        client.set_service_url(settings.WATSON_TTS_URL)
        logger.info("[GuardianHer AI] Watson TTS client initialised.")
        return _set_cached(cache_key, client)

    except ImportError:
        raise ConfigurationError(
            "ibm-watson package is not installed. Run: pip install ibm-watson"
        )
    except Exception as exc:
        raise ConfigurationError(
            f"[GuardianHer AI] Failed to initialise Watson TTS client: {exc}"
        ) from exc


# ─────────────────────────────────────────────────────────────
# 5. IBM Watson Assistant
#    Used by: modules/ai/assistant_client.py
# ─────────────────────────────────────────────────────────────

def get_watson_assistant_client() -> Optional[Any]:
    """
    Return a configured IBM Watson AssistantV2 client.

    Used to:
      - Create and maintain Watson Assistant sessions per user
      - Send/receive post-incident companion conversation turns
      - Inject incident context variables into session state
      - Drive the FIR report wizard dialogue flow

    Returns:
        ibm_watson.AssistantV2 instance, or None if disabled / mock mode.
    """
    cache_key = "watson_assistant"
    if cached := _get_cached(cache_key):
        return cached

    if not settings.ENABLE_WATSON_ASSISTANT:
        logger.info("[GuardianHer AI] Watson Assistant is disabled via feature flag.")
        return None

    if _is_mock_mode():
        _warn_mock("Watson Assistant")
        return None

    try:
        from ibm_watson import AssistantV2  # type: ignore
        from ibm_cloud_sdk_core.authenticators import IAMAuthenticator  # type: ignore

        authenticator = IAMAuthenticator(settings.WATSON_ASSISTANT_API_KEY.get_secret())
        client = AssistantV2(
            version=settings.WATSON_ASSISTANT_VERSION,
            authenticator=authenticator,
        )
        client.set_service_url(settings.WATSON_ASSISTANT_URL)
        logger.info(
            "[GuardianHer AI] Watson Assistant client initialised (assistant_id: %s).",
            settings.WATSON_ASSISTANT_ID,
        )
        return _set_cached(cache_key, client)

    except ImportError:
        raise ConfigurationError(
            "ibm-watson package is not installed. Run: pip install ibm-watson"
        )
    except Exception as exc:
        raise ConfigurationError(
            f"[GuardianHer AI] Failed to initialise Watson Assistant client: {exc}"
        ) from exc


# ─────────────────────────────────────────────────────────────
# 6. IBM Cloud Object Storage
#    Used by: services/evidence_service.py
# ─────────────────────────────────────────────────────────────

def get_cos_client() -> Optional[Any]:
    """
    Return a configured IBM Cloud Object Storage (boto3-compatible) client.

    Used to:
      - Upload AES-256 encrypted evidence files (audio, GPS, biometric)
      - Generate pre-signed download URLs (72-hour TTL)
      - Verify file integrity via ETag / SHA-256 checks
      - Delete evidence on user right-to-erasure requests (GDPR)

    Returns:
        ibm_boto3.client instance, or None in mock mode (uses local filesystem).
    """
    cache_key = "cos"
    if cached := _get_cached(cache_key):
        return cached

    if _is_mock_mode():
        _warn_mock("IBM Cloud Object Storage")
        logger.info(
            "[GuardianHer AI] Evidence will be stored locally at ./data/evidence/ in mock mode."
        )
        return None

    try:
        import ibm_boto3  # type: ignore
        from ibm_botocore.client import Config  # type: ignore

        client = ibm_boto3.client(
            "s3",
            ibm_api_key_id=settings.IBM_COS_API_KEY.get_secret(),
            ibm_service_instance_id=settings.IBM_COS_SERVICE_CRN,
            ibm_auth_endpoint=settings.IBM_COS_AUTH_ENDPOINT,
            config=Config(signature_version="oauth"),
            endpoint_url=settings.IBM_COS_ENDPOINT,
        )
        logger.info(
            "[GuardianHer AI] IBM COS client initialised (bucket: %s).",
            settings.IBM_COS_BUCKET_NAME,
        )
        return _set_cached(cache_key, client)

    except ImportError:
        raise ConfigurationError(
            "ibm-cos-sdk package is not installed. Run: pip install ibm-cos-sdk"
        )
    except Exception as exc:
        raise ConfigurationError(
            f"[GuardianHer AI] Failed to initialise IBM COS client: {exc}"
        ) from exc


# ─────────────────────────────────────────────────────────────
# 7. IBM IoT Platform (MQTT configuration dict)
#    Used by: modules/wearable/ble_manager.py
#
#    Note: The IoT Platform connection itself is managed by the
#    paho-mqtt client inside ble_manager.py.  This function
#    returns a typed configuration dict (not a live connection)
#    to avoid holding an MQTT socket open at import time.
# ─────────────────────────────────────────────────────────────

def get_iot_config() -> Optional[dict]:
    """
    Return a configuration dict for the IBM Watson IoT Platform MQTT broker.

    The dict is consumed by modules/wearable/ble_manager.py to
    construct the MQTT client connection:

        config = get_iot_config()
        if config:
            mqtt_client.connect(config["host"], config["port"])

    Returns:
        Dict with MQTT broker parameters, or None in mock mode.
    """
    if _is_mock_mode():
        _warn_mock("IBM IoT Platform")
        return None

    org_id = settings.IBM_IOT_ORG_ID
    if not org_id:
        logger.warning(
            "[GuardianHer AI] IBM_IOT_ORG_ID is not set — IoT Platform disabled."
        )
        return None

    return {
        "host":        f"{org_id}.messaging.internetofthings.ibmcloud.com",
        "port":        8883,                              # MQTT over TLS
        "client_id":   f"g:{org_id}:GuardianHerApp:mobile-gateway",
        "username":    settings.IBM_IOT_API_KEY.get_secret(),
        "password":    settings.IBM_IOT_AUTH_TOKEN.get_secret(),
        "tls_enabled": True,
        "org_id":      org_id,
        # Topic pattern for wearable biometric events
        "topic_biometric": f"iot-2/type/wearable/id/+/evt/biometric/fmt/json",
        "topic_sos":       f"iot-2/type/wearable/id/+/evt/sos/fmt/json",
    }


# ─────────────────────────────────────────────────────────────
# 8. IBM App ID (OAuth 2.0 configuration dict)
#    Used by: modules/auth/app_id_client.py
# ─────────────────────────────────────────────────────────────

def get_app_id_config() -> Optional[dict]:
    """
    Return a configuration dict for IBM App ID OAuth 2.0 flows.

    Used by modules/auth/app_id_client.py to:
      - Construct the authorisation URL for the login redirect
      - Exchange authorisation codes for access tokens
      - Validate JWT tokens issued by App ID
      - Fetch user profile attributes (role, name)

    Returns:
        Dict with App ID OAuth parameters, or None in mock mode.
    """
    if _is_mock_mode():
        _warn_mock("IBM App ID")
        logger.info(
            "[GuardianHer AI] Authentication is bypassed in mock mode. "
            "A demo user session will be auto-created."
        )
        return None

    tenant_id = settings.IBM_APP_ID_TENANT_ID
    if not tenant_id:
        logger.warning(
            "[GuardianHer AI] IBM_APP_ID_TENANT_ID is not set — App ID disabled."
        )
        return None

    return {
        "tenant_id":       tenant_id,
        "client_id":       settings.IBM_APP_ID_CLIENT_ID,
        "client_secret":   settings.IBM_APP_ID_SECRET.get_secret(),
        "oauth_base_url":  settings.IBM_APP_ID_OAUTH_URL,
        # Standard OIDC endpoints derived from base URL
        "token_endpoint":  f"{settings.IBM_APP_ID_OAUTH_URL}/{tenant_id}/token",
        "jwks_endpoint":   f"{settings.IBM_APP_ID_OAUTH_URL}/{tenant_id}/publickeys",
        "userinfo_endpoint": f"{settings.IBM_APP_ID_OAUTH_URL}/{tenant_id}/userinfo",
        "scopes":          ["openid", "profile", "email"],
    }


# ─────────────────────────────────────────────────────────────
# Startup Validation
# ─────────────────────────────────────────────────────────────

def validate_ibm_connectivity() -> dict[str, bool]:
    """
    Attempt a lightweight connectivity check for each IBM service.
    Called from app.py on startup in production mode.

    Returns a status dict:
        {
            "watsonx":          True,
            "watson_nlu":       True,
            "watson_stt":       False,  ← connection failed
            ...
        }

    This is intentionally non-fatal — a failed service logs a
    warning rather than crashing the app, allowing degraded-mode
    operation (e.g., rule-based fallbacks for AI modules).
    """
    if _is_mock_mode():
        logger.info("[GuardianHer AI] Skipping IBM connectivity check in mock mode.")
        return {
            "watsonx": False,
            "watson_nlu": False,
            "watson_stt": False,
            "watson_tts": False,
            "watson_assistant": False,
            "cos": False,
            "iot": False,
            "app_id": False,
        }

    status: dict[str, bool] = {}

    # watsonx.ai — check by listing projects
    try:
        client = get_watsonx_client()
        status["watsonx"] = client is not None
    except ConfigurationError:
        status["watsonx"] = False
        logger.warning("[GuardianHer AI] watsonx.ai connectivity check failed.")

    # Watson NLU — check by calling with empty text (400 is expected, 401/403 is not)
    try:
        client = get_watson_nlu_client()
        status["watson_nlu"] = client is not None
    except ConfigurationError:
        status["watson_nlu"] = False
        logger.warning("[GuardianHer AI] Watson NLU connectivity check failed.")

    # Watson STT
    try:
        client = get_watson_stt_client()
        status["watson_stt"] = client is not None
    except ConfigurationError:
        status["watson_stt"] = False
        logger.warning("[GuardianHer AI] Watson STT connectivity check failed.")

    # Watson TTS
    try:
        client = get_watson_tts_client()
        status["watson_tts"] = client is not None
    except ConfigurationError:
        status["watson_tts"] = False
        logger.warning("[GuardianHer AI] Watson TTS connectivity check failed.")

    # Watson Assistant
    try:
        client = get_watson_assistant_client()
        status["watson_assistant"] = client is not None
    except ConfigurationError:
        status["watson_assistant"] = False
        logger.warning("[GuardianHer AI] Watson Assistant connectivity check failed.")

    # COS
    try:
        client = get_cos_client()
        status["cos"] = client is not None
    except ConfigurationError:
        status["cos"] = False
        logger.warning("[GuardianHer AI] IBM COS connectivity check failed.")

    # IoT (config-only, no live connection)
    status["iot"] = get_iot_config() is not None

    # App ID (config-only, no live connection)
    status["app_id"] = get_app_id_config() is not None

    # Log summary
    failed = [k for k, v in status.items() if not v]
    if failed:
        logger.warning(
            "[GuardianHer AI] IBM services with degraded/unavailable status: %s",
            ", ".join(failed),
        )
    else:
        logger.info("[GuardianHer AI] All IBM services connected successfully.")

    return status
