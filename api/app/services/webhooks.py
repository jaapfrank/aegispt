from __future__ import annotations

import os
from datetime import UTC, datetime
from typing import Any

import httpx

from api.app.models import Finding, FindingIntegrationLink, IntegrationConfiguration


class WebhookHandoffError(RuntimeError):
    pass


def _settings(configuration: IntegrationConfiguration) -> dict[str, Any]:
    return configuration.settings_json if isinstance(configuration.settings_json, dict) else {}


def _auth_headers(configuration: IntegrationConfiguration) -> dict[str, str]:
    auth_ref = (configuration.auth_ref or "").strip()
    if not auth_ref.startswith("env://"):
        return {}

    env_name = auth_ref.removeprefix("env://").strip()
    token = os.environ.get(env_name)
    if not token:
        return {}

    settings = _settings(configuration)
    auth_scheme = str(settings.get("auth_scheme") or "Bearer").strip() or "Bearer"
    return {"Authorization": f"{auth_scheme} {token}"}


def _first_string(payload: dict[str, Any], keys: tuple[str, ...]) -> str | None:
    for key in keys:
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _mark_failed(
    *,
    link: FindingIntegrationLink,
    endpoint: str,
    error: str,
    status_code: int | None = None,
) -> None:
    link.issue_status = "failed"
    link.last_sync_state = "failed"
    link.last_sync_error = error[:1000]
    link.last_synced_at = datetime.now(tz=UTC)
    link.last_sync_payload_json = {
        "endpoint": endpoint,
        "http_status": status_code,
        "error": link.last_sync_error,
    }


def send_finding_webhook_handoff(
    *,
    configuration: IntegrationConfiguration,
    finding: Finding,
    link: FindingIntegrationLink,
    actor: str,
    operator_note: str | None = None,
) -> FindingIntegrationLink:
    settings = _settings(configuration)
    endpoint = configuration.base_url.strip()
    timeout_seconds = float(settings.get("handoff_timeout_seconds") or 10.0)
    event_type = str(settings.get("event_type") or "aegispt.finding.handoff.requested").strip()
    if not event_type:
        event_type = "aegispt.finding.handoff.requested"

    body = {
        "event_type": event_type,
        "sent_at": datetime.now(tz=UTC).isoformat(),
        "operator": actor,
        "engagement_id": str(configuration.engagement_id),
        "integration_configuration_id": str(configuration.id),
        "finding": {
            "id": str(finding.id),
            "title": finding.title,
            "severity": finding.severity,
            "status": finding.status,
            "target_id": finding.target_id,
            "summary": finding.summary,
            "evidence_ref": finding.evidence_ref,
        },
        "handoff": {
            "id": str(link.id),
            "key": link.issue_key,
            "url": link.issue_url,
            "operator_note": operator_note,
        },
    }

    try:
        response = httpx.post(
            endpoint,
            json=body,
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                "X-AegisPT-Event": event_type,
                **_auth_headers(configuration),
            },
            timeout=timeout_seconds,
            follow_redirects=False,
        )
    except httpx.HTTPError as exc:
        error = f"webhook handoff request failed: {exc}"
        _mark_failed(link=link, endpoint=endpoint, error=error)
        raise WebhookHandoffError(error) from exc

    if response.status_code >= 400:
        error = f"webhook handoff failed with HTTP {response.status_code}"
        _mark_failed(link=link, endpoint=endpoint, error=error, status_code=response.status_code)
        raise WebhookHandoffError(error)

    remote_payload: dict[str, Any] = {}
    content_type = response.headers.get("content-type") or ""
    if response.content and "json" in content_type.lower():
        try:
            decoded = response.json()
        except ValueError:
            decoded = None
        if isinstance(decoded, dict):
            remote_payload = decoded

    remote_key = _first_string(remote_payload, ("reference_key", "handoff_key", "id", "key"))
    remote_url = _first_string(remote_payload, ("reference_url", "handoff_url", "url"))
    remote_status = _first_string(remote_payload, ("status", "state", "result")) or "delivered"

    if remote_key:
        link.issue_key = remote_key[:100]
    if remote_url and remote_url.startswith(("https://", "http://")):
        link.issue_url = remote_url[:2048]

    link.issue_status = remote_status[:100]
    link.last_sync_state = "delivered"
    link.last_synced_at = datetime.now(tz=UTC)
    link.last_sync_error = None
    link.last_sync_payload_json = {
        "endpoint": endpoint,
        "http_status": response.status_code,
        "remote_reference_key": remote_key,
        "remote_reference_url": remote_url if remote_url and remote_url.startswith(("https://", "http://")) else None,
        "remote_status": remote_status,
    }
    return link
