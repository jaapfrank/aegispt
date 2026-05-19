from __future__ import annotations

import os
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote

import httpx

from api.app.models import FindingIntegrationLink, IntegrationConfiguration


class JiraSyncError(RuntimeError):
    pass


def _settings(configuration: IntegrationConfiguration) -> dict[str, Any]:
    return configuration.settings_json if isinstance(configuration.settings_json, dict) else {}


def _jira_issue_api_url(configuration: IntegrationConfiguration, issue_key: str) -> str:
    settings = _settings(configuration)
    path_template = str(settings.get("issue_api_path_template") or "/rest/api/2/issue/{issue_key}")
    path = path_template.format(issue_key=quote(issue_key, safe=""))
    if not path.startswith("/"):
        path = f"/{path}"
    return f"{configuration.base_url.rstrip('/')}{path}"


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


def _extract_issue_status(payload: dict[str, Any]) -> str:
    fields = payload.get("fields")
    if isinstance(fields, dict):
        status = fields.get("status")
        if isinstance(status, dict) and status.get("name"):
            return str(status["name"]).strip()
        if isinstance(status, str) and status.strip():
            return status.strip()

    for key in ("status", "issue_status"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()

    raise JiraSyncError("jira response did not include an issue status")


def _mark_failed(link: FindingIntegrationLink, error: str) -> None:
    link.last_sync_state = "failed"
    link.last_sync_error = error[:1000]
    link.last_synced_at = datetime.now(tz=UTC)
    link.last_sync_payload_json = {"error": link.last_sync_error}


def sync_jira_issue(
    *,
    configuration: IntegrationConfiguration,
    link: FindingIntegrationLink,
) -> FindingIntegrationLink:
    api_url = _jira_issue_api_url(configuration, link.issue_key)
    settings = _settings(configuration)
    timeout_seconds = float(settings.get("sync_timeout_seconds") or 10.0)

    try:
        response = httpx.get(
            api_url,
            headers={"Accept": "application/json", **_auth_headers(configuration)},
            timeout=timeout_seconds,
            follow_redirects=True,
        )
    except httpx.HTTPError as exc:
        error = f"jira sync request failed: {exc}"
        _mark_failed(link, error)
        raise JiraSyncError(error) from exc

    if response.status_code >= 400:
        error = f"jira sync failed with HTTP {response.status_code}"
        _mark_failed(link, error)
        raise JiraSyncError(error)

    try:
        payload = response.json()
    except ValueError as exc:
        error = "jira sync response was not valid JSON"
        _mark_failed(link, error)
        raise JiraSyncError(error) from exc

    if not isinstance(payload, dict):
        error = "jira sync response was not a JSON object"
        _mark_failed(link, error)
        raise JiraSyncError(error)

    try:
        issue_status = _extract_issue_status(payload)
    except JiraSyncError as exc:
        _mark_failed(link, str(exc))
        raise

    fields = payload.get("fields") if isinstance(payload.get("fields"), dict) else {}
    remote_updated = fields.get("updated") if isinstance(fields, dict) else None
    link.issue_status = issue_status
    link.last_sync_state = "synced"
    link.last_synced_at = datetime.now(tz=UTC)
    link.last_sync_error = None
    link.last_sync_payload_json = {
        "source_url": api_url,
        "remote_key": str(payload.get("key") or link.issue_key),
        "remote_status": issue_status,
        "remote_updated": str(remote_updated) if remote_updated is not None else None,
    }
    return link
