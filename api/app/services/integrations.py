from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from api.app.models import Finding, FindingIntegrationLink, IntegrationConfiguration
from api.app.services.secrets import is_explicit_reference

SUPPORTED_NAMED_HANDOFF_PROVIDERS = ("slack", "teams", "servicenow")

NAMED_HANDOFF_PROVIDER_DEFINITIONS: dict[str, dict[str, Any]] = {
    "slack": {
        "label": "Slack",
        "required_settings": ("channel",),
        "routing_label": "channel",
        "default_event_type": "aegispt.finding.handoff.slack",
    },
    "teams": {
        "label": "Microsoft Teams",
        "required_settings": ("conversation",),
        "routing_label": "conversation",
        "default_event_type": "aegispt.finding.handoff.teams",
    },
    "servicenow": {
        "label": "ServiceNow",
        "required_settings": ("table",),
        "routing_label": "table",
        "default_event_type": "aegispt.finding.handoff.servicenow",
    },
}

_PROVIDER_ALIASES = {
    "service-now": "servicenow",
    "service_now": "servicenow",
    "ms-teams": "teams",
    "microsoft-teams": "teams",
}


class IntegrationHandoffError(RuntimeError):
    def __init__(self, message: str, *, status_code: int = 409) -> None:
        super().__init__(message)
        self.status_code = status_code


def normalize_integration_provider(provider: str) -> str:
    normalized = provider.strip().lower().replace("_", "-")
    return _PROVIDER_ALIASES.get(normalized, normalized)


def is_named_handoff_provider(provider: str) -> bool:
    return normalize_integration_provider(provider) in SUPPORTED_NAMED_HANDOFF_PROVIDERS


def named_handoff_provider_label(provider: str) -> str:
    normalized = normalize_integration_provider(provider)
    definition = NAMED_HANDOFF_PROVIDER_DEFINITIONS.get(normalized)
    if definition is None:
        return normalized
    return str(definition["label"])


def _settings(configuration: IntegrationConfiguration) -> dict[str, Any]:
    return configuration.settings_json if isinstance(configuration.settings_json, dict) else {}


def _auth_ref_kind(auth_ref: str | None) -> str | None:
    value = (auth_ref or "").strip()
    if "://" not in value:
        return None
    return value.split("://", 1)[0]


def _mark_blocked(
    *,
    link: FindingIntegrationLink,
    provider: str,
    reason: str,
    error: str,
) -> None:
    now = datetime.now(tz=UTC)
    link.issue_status = reason[:100]
    link.last_sync_state = "blocked"
    link.last_sync_error = error[:1000]
    link.last_synced_at = now
    link.last_sync_payload_json = {
        "provider": provider,
        "handoff_mode": "operator_triggered_non_background",
        "external_delivery_attempted": False,
        "blocked_reason": reason,
        "error": link.last_sync_error,
    }


def _mark_failed(
    *,
    link: FindingIntegrationLink,
    provider: str,
    error: str,
) -> None:
    now = datetime.now(tz=UTC)
    link.issue_status = "failed"
    link.last_sync_state = "failed"
    link.last_sync_error = error[:1000]
    link.last_synced_at = now
    link.last_sync_payload_json = {
        "provider": provider,
        "handoff_mode": "operator_triggered_non_background",
        "external_delivery_attempted": False,
        "error": link.last_sync_error,
    }


def _non_empty_setting(settings: dict[str, Any], key: str) -> str | None:
    value = settings.get(key)
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def prepare_named_provider_handoff(
    *,
    configuration: IntegrationConfiguration,
    finding: Finding,
    link: FindingIntegrationLink,
    actor: str,
    operator_note: str | None = None,
) -> FindingIntegrationLink:
    provider = normalize_integration_provider(configuration.integration_type)
    definition = NAMED_HANDOFF_PROVIDER_DEFINITIONS[provider]
    label = str(definition["label"])
    settings = _settings(configuration)
    auth_ref = (configuration.auth_ref or "").strip()

    if not auth_ref:
        error = f"{label} handoff requires protected auth_ref before handoff"
        _mark_blocked(link=link, provider=provider, reason="missing_credentials", error=error)
        raise IntegrationHandoffError(error, status_code=409)

    if not is_explicit_reference(auth_ref):
        error = f"{label} handoff auth_ref must be a protected reference, not raw secret material"
        _mark_blocked(link=link, provider=provider, reason="invalid_credentials_reference", error=error)
        raise IntegrationHandoffError(error, status_code=409)

    required_settings = tuple(str(item) for item in definition.get("required_settings", ()))
    missing_settings = [key for key in required_settings if _non_empty_setting(settings, key) is None]
    if missing_settings:
        error = f"{label} handoff requires settings_json fields: {', '.join(missing_settings)}"
        _mark_blocked(link=link, provider=provider, reason="missing_configuration", error=error)
        raise IntegrationHandoffError(error, status_code=409)

    configured_failure = _non_empty_setting(settings, "handoff_failure_reason")
    if configured_failure is not None:
        error = f"{label} handoff failed: {configured_failure}"
        _mark_failed(link=link, provider=provider, error=error)
        raise IntegrationHandoffError(error, status_code=502)

    now = datetime.now(tz=UTC)
    routing_label = str(definition["routing_label"])
    routing_target = _non_empty_setting(settings, routing_label)
    event_type = _non_empty_setting(settings, "event_type") or str(definition["default_event_type"])
    link.issue_status = "prepared"
    link.last_sync_state = "prepared"
    link.last_sync_error = None
    link.last_synced_at = now
    link.last_sync_payload_json = {
        "provider": provider,
        "provider_label": label,
        "event_type": event_type,
        "handoff_mode": "operator_triggered_non_background",
        "external_delivery_attempted": False,
        "requires_manual_delivery": True,
        "routing": {
            "label": routing_label,
            "target": routing_target,
        },
        "auth_ref_kind": _auth_ref_kind(auth_ref),
        "operator": actor,
        "operator_note_recorded": bool(operator_note),
        "finding": {
            "id": str(finding.id),
            "title": finding.title,
            "severity": finding.severity,
            "status": finding.status,
            "target_id": finding.target_id,
            "evidence_ref": finding.evidence_ref,
        },
    }
    return link
