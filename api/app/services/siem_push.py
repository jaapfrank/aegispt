from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from api.app.config import Settings
from api.app.models import (
    Finding,
    FindingIntegrationLink,
    IntegrationConfiguration,
    Run,
    SecretRef,
    Task,
)
from api.app.services.ai_enrichment import build_detection_engineering_for_finding
from api.app.services.audit import write_audit_event
from api.app.services.secrets import (
    ENCRYPTED_SECRET_BACKENDS,
    direct_secret_storage_backend,
    encrypt_secret_value,
    load_secret_value,
    secret_display_label,
)

SUPPORTED_SIEM_PROVIDERS = ("splunk", "elastic", "sentinel")
SIEM_EVENT_SOURCE = "aegispt-pentest-finding"
SIEM_EVENT_RUN_COMPLETION = "run_completion"
SIEM_EVENT_CRITICAL_FINDING = "critical_finding"

_SIEM_PROVIDER_ALIASES = {
    "azure-sentinel": "sentinel",
    "azure_sentinel": "sentinel",
    "microsoft-sentinel": "sentinel",
    "microsoft_sentinel": "sentinel",
}

SIEM_PROVIDER_DEFINITIONS: dict[str, dict[str, str]] = {
    "splunk": {
        "label": "Splunk HEC",
        "credential_kind": "hec_token",
        "default_auth_scheme": "Splunk",
    },
    "elastic": {
        "label": "Elastic",
        "credential_kind": "api_key",
        "default_auth_scheme": "ApiKey",
    },
    "sentinel": {
        "label": "Azure Sentinel",
        "credential_kind": "bearer_token",
        "default_auth_scheme": "Bearer",
    },
}


@dataclass(frozen=True, slots=True)
class SiemDeliveryReceipt:
    provider: str
    delivered: bool
    event_kind: str
    finding_id: uuid.UUID | None = None
    run_id: uuid.UUID | None = None
    blocked: bool = False
    error: str | None = None
    http_status: int | None = None


def normalize_siem_provider(provider: str) -> str:
    normalized = provider.strip().lower().replace("_", "-")
    return _SIEM_PROVIDER_ALIASES.get(normalized, normalized)


def is_siem_provider(provider: str) -> bool:
    return normalize_siem_provider(provider) in SUPPORTED_SIEM_PROVIDERS


def siem_provider_label(provider: str) -> str:
    normalized = normalize_siem_provider(provider)
    return str(SIEM_PROVIDER_DEFINITIONS.get(normalized, {}).get("label") or normalized)


def list_siem_configurations(*, session: Session, engagement_id: uuid.UUID) -> list[IntegrationConfiguration]:
    return list(
        session.scalars(
            select(IntegrationConfiguration)
            .where(
                IntegrationConfiguration.engagement_id == engagement_id,
                IntegrationConfiguration.integration_type.in_(SUPPORTED_SIEM_PROVIDERS),
            )
            .order_by(IntegrationConfiguration.created_at.desc(), IntegrationConfiguration.id.desc())
        )
    )


def store_or_update_siem_credential(
    *,
    session: Session,
    engagement_id: uuid.UUID,
    configuration: IntegrationConfiguration,
    provider: str,
    credential: str,
    settings: Settings,
) -> SecretRef:
    existing = _configured_secret_ref(session=session, configuration=configuration)
    if existing is not None and existing.storage_backend in ENCRYPTED_SECRET_BACKENDS:
        secret_ref = existing
        storage_backend = existing.storage_backend
        fallback_to_local = bool((existing.metadata_json or {}).get("fallback_to_local_secret_key"))
    else:
        storage_backend, fallback_to_local = direct_secret_storage_backend(settings)
        secret_ref = SecretRef(
            id=uuid.uuid4(),
            engagement_id=engagement_id,
            vault_pointer="",
            purpose=f"integration.siem.{provider}.credential",
            secret_kind=str(SIEM_PROVIDER_DEFINITIONS[provider]["credential_kind"]),
            storage_backend=storage_backend,
            display_label=None,
            encrypted_value=None,
            metadata_json={},
        )
        secret_ref.vault_pointer = f"aegispt://secret-ref/{secret_ref.id}"
        session.add(secret_ref)

    secret_ref.purpose = f"integration.siem.{provider}.credential"
    secret_ref.secret_kind = str(SIEM_PROVIDER_DEFINITIONS[provider]["credential_kind"])
    secret_ref.display_label = secret_display_label(
        credential,
        secret_kind=secret_ref.secret_kind,
        storage_backend=secret_ref.storage_backend,
    )
    secret_ref.encrypted_value = encrypt_secret_value(
        credential,
        settings,
        storage_backend=secret_ref.storage_backend,
    )
    secret_ref.metadata_json = {
        "provider": provider,
        "raw_secret_material_exposed": False,
        "fallback_to_local_secret_key": fallback_to_local if secret_ref.storage_backend == "encrypted_local" else False,
    }
    configuration.auth_ref = secret_ref.vault_pointer
    session.flush()
    return secret_ref


def credential_display_label_for_configuration(
    *,
    session: Session,
    configuration: IntegrationConfiguration,
) -> str | None:
    secret_ref = _configured_secret_ref(session=session, configuration=configuration)
    if secret_ref is not None and secret_ref.display_label:
        return secret_ref.display_label
    return None


def credential_configured_for_configuration(
    *,
    session: Session,
    configuration: IntegrationConfiguration,
) -> bool:
    return _configured_secret_ref(session=session, configuration=configuration) is not None


def deliver_critical_findings_to_configured_siems(
    *,
    session: Session,
    finding_ids: list[uuid.UUID],
    actor: str,
    settings: Settings,
) -> list[SiemDeliveryReceipt]:
    if not finding_ids:
        return []

    findings = list(
        session.scalars(
            select(Finding)
            .options(
                selectinload(Finding.run).selectinload(Run.tasks),
                selectinload(Finding.integration_links).selectinload(FindingIntegrationLink.integration_configuration),
            )
            .where(Finding.id.in_(finding_ids))
        )
    )
    receipts: list[SiemDeliveryReceipt] = []
    for finding in findings:
        if str(finding.severity or "").lower() != "critical":
            continue
        run = finding.run
        if run is None:
            continue
        configurations = _enabled_siem_configurations(
            session=session,
            engagement_id=run.engagement_id,
            trigger_kind=SIEM_EVENT_CRITICAL_FINDING,
        )
        for configuration in configurations:
            receipts.append(
                _deliver_finding_event(
                    session=session,
                    configuration=configuration,
                    finding=finding,
                    actor=actor,
                    settings=settings,
                    event_kind=SIEM_EVENT_CRITICAL_FINDING,
                )
            )
    return receipts


def deliver_run_completion_to_configured_siems(
    *,
    session: Session,
    run_id: uuid.UUID,
    actor: str,
    settings: Settings,
) -> list[SiemDeliveryReceipt]:
    run = session.scalar(
        select(Run)
        .options(selectinload(Run.profile), selectinload(Run.findings), selectinload(Run.tasks))
        .where(Run.id == run_id, Run.deleted_at.is_(None))
    )
    if run is None or run.status not in {"completed", "completed_with_errors"}:
        return []

    configurations = _enabled_siem_configurations(
        session=session,
        engagement_id=run.engagement_id,
        trigger_kind=SIEM_EVENT_RUN_COMPLETION,
    )
    receipts: list[SiemDeliveryReceipt] = []
    for configuration in configurations:
        receipts.append(
            _deliver_run_summary_event(
                session=session,
                configuration=configuration,
                run=run,
                actor=actor,
                settings=settings,
            )
        )
        for finding in list(run.findings or []):
            receipts.append(
                _deliver_finding_event(
                    session=session,
                    configuration=configuration,
                    finding=finding,
                    actor=actor,
                    settings=settings,
                    event_kind=SIEM_EVENT_RUN_COMPLETION,
                )
            )
    return receipts


def _enabled_siem_configurations(
    *,
    session: Session,
    engagement_id: uuid.UUID,
    trigger_kind: str,
) -> list[IntegrationConfiguration]:
    configurations = list_siem_configurations(session=session, engagement_id=engagement_id)
    enabled: list[IntegrationConfiguration] = []
    for configuration in configurations:
        settings = _settings_json(configuration)
        if settings.get("enabled", True) is False:
            continue
        if trigger_kind == SIEM_EVENT_RUN_COMPLETION and settings.get("push_on_run_completion", True) is False:
            continue
        if trigger_kind == SIEM_EVENT_CRITICAL_FINDING and settings.get("push_on_critical_finding", True) is False:
            continue
        enabled.append(configuration)
    return enabled


def _deliver_run_summary_event(
    *,
    session: Session,
    configuration: IntegrationConfiguration,
    run: Run,
    actor: str,
    settings: Settings,
) -> SiemDeliveryReceipt:
    provider = normalize_siem_provider(configuration.integration_type)
    resolved_credential = _resolve_delivery_credential(
        session=session,
        configuration=configuration,
        settings=settings,
    )
    if resolved_credential is None:
        error = f"{siem_provider_label(provider)} delivery requires an encrypted credential before push"
        _write_run_delivery_audit(
            session=session,
            actor=actor,
            run=run,
            provider=provider,
            action="run.integration.siem_blocked",
            metadata={
                "error": error,
                "event_kind": SIEM_EVENT_RUN_COMPLETION,
                "external_delivery_attempted": False,
            },
        )
        return SiemDeliveryReceipt(
            provider=provider,
            delivered=False,
            blocked=True,
            error=error,
            run_id=run.id,
            event_kind=SIEM_EVENT_RUN_COMPLETION,
        )

    try:
        payload = _build_run_event_payload(configuration=configuration, run=run, actor=actor)
        delivery = _send_provider_payload(
            provider=provider,
            configuration=configuration,
            credential=resolved_credential,
            payload=payload,
        )
    except Exception as exc:  # pragma: no cover - defensive safety boundary
        delivery = {
            "delivered": False,
            "http_status": None,
            "error": f"{siem_provider_label(provider)} push failed: {exc}",
        }
    _write_run_delivery_audit(
        session=session,
        actor=actor,
        run=run,
        provider=provider,
        action="run.integration.siem_delivered" if delivery["delivered"] else "run.integration.siem_failed",
        metadata={
            "event_kind": SIEM_EVENT_RUN_COMPLETION,
            "http_status": delivery.get("http_status"),
            "error": delivery.get("error"),
            "external_delivery_attempted": True,
        },
    )
    return SiemDeliveryReceipt(
        provider=provider,
        delivered=bool(delivery["delivered"]),
        http_status=delivery.get("http_status"),
        error=delivery.get("error"),
        run_id=run.id,
        event_kind=SIEM_EVENT_RUN_COMPLETION,
    )


def _deliver_finding_event(
    *,
    session: Session,
    configuration: IntegrationConfiguration,
    finding: Finding,
    actor: str,
    settings: Settings,
    event_kind: str,
) -> SiemDeliveryReceipt:
    provider = normalize_siem_provider(configuration.integration_type)
    link = _load_or_create_link(
        session=session,
        finding=finding,
        configuration=configuration,
        actor=actor,
        provider=provider,
    )
    resolved_credential = _resolve_delivery_credential(
        session=session,
        configuration=configuration,
        settings=settings,
    )
    if resolved_credential is None:
        error = f"{siem_provider_label(provider)} delivery requires an encrypted credential before push"
        _mark_link_blocked(
            link=link,
            provider=provider,
            event_kind=event_kind,
            error=error,
        )
        _write_finding_delivery_audit(
            session=session,
            actor=actor,
            finding=finding,
            link=link,
            provider=provider,
            action="finding.integration_link.siem_blocked",
        )
        return SiemDeliveryReceipt(
            provider=provider,
            delivered=False,
            blocked=True,
            error=error,
            finding_id=finding.id,
            event_kind=event_kind,
        )

    try:
        payload = _build_finding_event_payload(
            session=session,
            configuration=configuration,
            finding=finding,
            actor=actor,
            event_kind=event_kind,
        )
        delivery = _send_provider_payload(
            provider=provider,
            configuration=configuration,
            credential=resolved_credential,
            payload=payload,
        )
    except Exception as exc:  # pragma: no cover - defensive safety boundary
        delivery = {
            "delivered": False,
            "http_status": None,
            "error": f"{siem_provider_label(provider)} push failed: {exc}",
        }
        payload = {"sigma_exports": []}

    if delivery["delivered"]:
        _mark_link_delivered(
            link=link,
            provider=provider,
            event_kind=event_kind,
            finding=finding,
            configuration=configuration,
            payload=payload,
            http_status=delivery.get("http_status"),
        )
        _write_finding_delivery_audit(
            session=session,
            actor=actor,
            finding=finding,
            link=link,
            provider=provider,
            action="finding.integration_link.siem_delivered",
        )
    else:
        _mark_link_failed(
            link=link,
            provider=provider,
            event_kind=event_kind,
            error=str(delivery.get("error") or "unknown SIEM delivery error"),
            http_status=delivery.get("http_status"),
        )
        _write_finding_delivery_audit(
            session=session,
            actor=actor,
            finding=finding,
            link=link,
            provider=provider,
            action="finding.integration_link.siem_failed",
        )

    return SiemDeliveryReceipt(
        provider=provider,
        delivered=bool(delivery["delivered"]),
        http_status=delivery.get("http_status"),
        error=delivery.get("error"),
        finding_id=finding.id,
        event_kind=event_kind,
    )


def _load_or_create_link(
    *,
    session: Session,
    finding: Finding,
    configuration: IntegrationConfiguration,
    actor: str,
    provider: str,
) -> FindingIntegrationLink:
    existing = session.scalar(
        select(FindingIntegrationLink).where(
            FindingIntegrationLink.finding_id == finding.id,
            FindingIntegrationLink.integration_configuration_id == configuration.id,
        )
    )
    if existing is not None:
        existing.updated_by = actor
        return existing

    link = FindingIntegrationLink(
        finding_id=finding.id,
        integration_configuration_id=configuration.id,
        issue_key=f"{provider.upper()}-{finding.id.hex[:12]}",
        issue_url=configuration.base_url,
        issue_status="pending",
        last_sync_state="pending",
        last_sync_payload_json={},
        created_by=actor,
        updated_by=actor,
    )
    session.add(link)
    session.flush()
    return link


def _mark_link_blocked(
    *,
    link: FindingIntegrationLink,
    provider: str,
    event_kind: str,
    error: str,
) -> None:
    now = datetime.now(tz=UTC)
    link.issue_status = "missing_credentials"
    link.last_sync_state = "blocked"
    link.last_sync_error = error[:1000]
    link.last_synced_at = now
    link.last_sync_payload_json = _merge_delivery_history(
        link.last_sync_payload_json,
        provider=provider,
        event_kind=event_kind,
        delivered=False,
        blocked=True,
        http_status=None,
        error=link.last_sync_error,
        external_delivery_attempted=False,
    )


def _mark_link_failed(
    *,
    link: FindingIntegrationLink,
    provider: str,
    event_kind: str,
    error: str,
    http_status: int | None,
) -> None:
    now = datetime.now(tz=UTC)
    link.issue_status = "failed"
    link.last_sync_state = "failed"
    link.last_sync_error = error[:1000]
    link.last_synced_at = now
    link.last_sync_payload_json = _merge_delivery_history(
        link.last_sync_payload_json,
        provider=provider,
        event_kind=event_kind,
        delivered=False,
        blocked=False,
        http_status=http_status,
        error=link.last_sync_error,
        external_delivery_attempted=True,
    )


def _mark_link_delivered(
    *,
    link: FindingIntegrationLink,
    provider: str,
    event_kind: str,
    finding: Finding,
    configuration: IntegrationConfiguration,
    payload: dict[str, Any],
    http_status: int | None,
) -> None:
    now = datetime.now(tz=UTC)
    link.issue_status = "delivered"
    link.last_sync_state = "delivered"
    link.last_sync_error = None
    link.last_synced_at = now
    link.issue_url = configuration.base_url
    link.issue_key = f"{provider.upper()}-{finding.id.hex[:12]}"
    link.last_sync_payload_json = _merge_delivery_history(
        link.last_sync_payload_json,
        provider=provider,
        event_kind=event_kind,
        delivered=True,
        blocked=False,
        http_status=http_status,
        error=None,
        external_delivery_attempted=True,
        sigma_exported=bool(payload.get("sigma_exports")),
        target_label=str(payload.get("finding", {}).get("target_id") or finding.target_id),
    )


def _merge_delivery_history(
    existing_payload: dict[str, Any] | None,
    *,
    provider: str,
    event_kind: str,
    delivered: bool,
    blocked: bool,
    http_status: int | None,
    error: str | None,
    external_delivery_attempted: bool,
    sigma_exported: bool = False,
    target_label: str | None = None,
) -> dict[str, Any]:
    payload = dict(existing_payload or {})
    history = payload.get("deliveries")
    if not isinstance(history, list):
        history = []
    history.append(
        {
            "provider": provider,
            "provider_label": siem_provider_label(provider),
            "event_kind": event_kind,
            "delivered": delivered,
            "blocked": blocked,
            "http_status": http_status,
            "error": error,
            "source": SIEM_EVENT_SOURCE,
            "target": target_label,
            "sigma_exported": sigma_exported,
            "external_delivery_attempted": external_delivery_attempted,
            "delivered_at": datetime.now(tz=UTC).isoformat(),
        }
    )
    payload.update(
        {
            "provider": provider,
            "provider_label": siem_provider_label(provider),
            "event_kind": event_kind,
            "source": SIEM_EVENT_SOURCE,
            "last_http_status": http_status,
            "last_error": error,
            "external_delivery_attempted": external_delivery_attempted,
            "sigma_exported": sigma_exported,
            "deliveries": history[-5:],
        }
    )
    return payload


def _build_run_event_payload(
    *,
    configuration: IntegrationConfiguration,
    run: Run,
    actor: str,
) -> dict[str, Any]:
    findings = list(run.findings or [])
    task_counts = _task_counts(run.tasks or [])
    severities: dict[str, int] = {}
    for finding in findings:
        key = str(finding.severity or "unknown").lower()
        severities[key] = severities.get(key, 0) + 1

    return {
        "source": SIEM_EVENT_SOURCE,
        "event_kind": SIEM_EVENT_RUN_COMPLETION,
        "sent_at": datetime.now(tz=UTC).isoformat(),
        "operator": actor,
        "engagement_id": str(run.engagement_id),
        "integration_configuration_id": str(configuration.id),
        "run": {
            "id": str(run.id),
            "status": run.status,
            "requested_by": run.requested_by,
            "profile_name": run.profile.name if run.profile is not None else None,
            "task_counts": task_counts,
            "finding_count": len(findings),
            "findings_by_severity": severities,
        },
    }


def _build_finding_event_payload(
    *,
    session: Session,
    configuration: IntegrationConfiguration,
    finding: Finding,
    actor: str,
    event_kind: str,
) -> dict[str, Any]:
    detection = build_detection_engineering_for_finding(finding)
    include_sigma = bool(_settings_json(configuration).get("include_sigma", False))
    sigma_exports = _sigma_exports_for_finding(finding=finding, detection=detection) if include_sigma else []
    run = finding.run
    return {
        "source": SIEM_EVENT_SOURCE,
        "event_kind": event_kind,
        "sent_at": datetime.now(tz=UTC).isoformat(),
        "operator": actor,
        "engagement_id": str(run.engagement_id) if run is not None else None,
        "integration_configuration_id": str(configuration.id),
        "run_id": str(run.id) if run is not None else None,
        "finding": {
            "id": str(finding.id),
            "title": finding.title,
            "severity": finding.severity,
            "status": finding.status,
            "target_id": finding.target_id,
            "summary": finding.summary,
            "evidence_ref": finding.evidence_ref,
            "methodology_tags": list(finding.methodology_tags or []),
            "wstg_id": finding.wstg_id,
            "asvs_reference": finding.asvs_reference,
            "control_family": finding.control_family,
        },
        "detection_engineering": {
            "available": bool(detection.get("available")),
            "status": detection.get("status"),
            "summary": detection.get("summary"),
            "suggestion_ids": [
                str(item.get("id") or "")
                for item in list(detection.get("suggestions") or [])
                if isinstance(item, dict)
            ],
        },
        "sigma_exports": sigma_exports,
        "inventory_context": _inventory_context_for_finding(session=session, finding=finding),
    }


def _inventory_context_for_finding(*, session: Session, finding: Finding) -> dict[str, Any]:
    snapshot = finding.source_inventory_snapshot
    if snapshot is None:
        return {"available": False}
    summary = snapshot.summary_json if isinstance(snapshot.summary_json, dict) else {}
    return {
        "available": True,
        "snapshot_id": str(snapshot.id),
        "summary": {
            "host_count": summary.get("host_count"),
            "service_count": summary.get("service_count"),
            "endpoint_count": summary.get("endpoint_count"),
        },
    }


def _sigma_exports_for_finding(*, finding: Finding, detection: dict[str, Any]) -> list[dict[str, Any]]:
    suggestions = [
        item
        for item in list(detection.get("suggestions") or [])
        if isinstance(item, dict) and str(item.get("id") or "").strip()
    ]
    exports: list[dict[str, Any]] = []
    for index, suggestion in enumerate(suggestions[:2], start=1):
        level = _sigma_level_for_severity(str(finding.severity or "medium"))
        rule_id = f"aegispt-{finding.id.hex[:8]}-{index}"
        product = _sigma_product_for_target(finding.target_id)
        title = f"AegisPT advisory detection: {finding.title}"
        description = str(suggestion.get("description") or detection.get("summary") or finding.summary or "").strip()
        sigma_yaml = "\n".join(
            [
                f'title: "{_yaml_escape(title)}"',
                f'id: "{rule_id}"',
                "status: test",
                f'description: "{_yaml_escape(description or "Operator review required before production use.")}"',
                "logsource:",
                f"  product: {product}",
                "detection:",
                "  selection:",
                f'    aegispt_finding_id: "{finding.id}"',
                f'    aegispt_suggestion_id: "{_yaml_escape(str(suggestion.get("id") or ""))}"',
                "  condition: selection",
                "falsepositives:",
                '  - "Requires customer telemetry tuning and analyst review."',
                f"level: {level}",
            ]
        )
        exports.append(
            {
                "format": "sigma-yaml",
                "title": title,
                "rule_id": rule_id,
                "level": level,
                "content": sigma_yaml,
            }
        )
    return exports


def _yaml_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _sigma_level_for_severity(severity: str) -> str:
    normalized = severity.strip().lower()
    mapping = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
        "info": "low",
    }
    return mapping.get(normalized, "medium")


def _sigma_product_for_target(target_id: str) -> str:
    parsed = urlparse(str(target_id or "").strip())
    if parsed.scheme in {"http", "https"}:
        return "web"
    return "network"


def _task_counts(tasks: list[Task]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for task in tasks:
        key = str(task.status or "unknown")
        counts[key] = counts.get(key, 0) + 1
    return counts


def _send_provider_payload(
    *,
    provider: str,
    configuration: IntegrationConfiguration,
    credential: str,
    payload: dict[str, Any],
) -> dict[str, Any]:
    try:
        if provider == "splunk":
            response = _post_splunk_event(configuration=configuration, credential=credential, payload=payload)
        elif provider == "elastic":
            response = _post_elastic_document(configuration=configuration, credential=credential, payload=payload)
        elif provider == "sentinel":
            response = _post_sentinel_log_entry(configuration=configuration, credential=credential, payload=payload)
        else:
            return {"delivered": False, "error": f"unsupported SIEM provider: {provider}", "http_status": None}
    except httpx.HTTPError as exc:
        return {"delivered": False, "error": str(exc), "http_status": None}

    if response.status_code >= 400:
        return {
            "delivered": False,
            "error": f"{siem_provider_label(provider)} push failed with HTTP {response.status_code}",
            "http_status": response.status_code,
        }
    return {"delivered": True, "error": None, "http_status": response.status_code}


def _post_splunk_event(
    *,
    configuration: IntegrationConfiguration,
    credential: str,
    payload: dict[str, Any],
) -> httpx.Response:
    settings = _settings_json(configuration)
    timeout_seconds = float(settings.get("timeout_seconds") or 10.0)
    event_body = {
        "time": datetime.now(tz=UTC).timestamp(),
        "source": SIEM_EVENT_SOURCE,
        "sourcetype": str(settings.get("sourcetype") or "aegispt:pentest:finding"),
        "index": str(settings.get("index_name") or "aegispt_pentest"),
        "event": {
            **payload,
            "alert_level": _splunk_alert_level(_payload_severity(payload)),
        },
    }
    return httpx.post(
        configuration.base_url,
        json=event_body,
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"{_auth_scheme(configuration, provider='splunk')} {credential}",
        },
        timeout=timeout_seconds,
        follow_redirects=False,
    )


def _post_elastic_document(
    *,
    configuration: IntegrationConfiguration,
    credential: str,
    payload: dict[str, Any],
) -> httpx.Response:
    settings = _settings_json(configuration)
    timeout_seconds = float(settings.get("timeout_seconds") or 10.0)
    index_name = str(settings.get("index_name") or "aegispt-findings").strip() or "aegispt-findings"
    endpoint = f"{configuration.base_url.rstrip('/')}/{index_name}/_doc"
    document = _elastic_ecs_document(payload)
    return httpx.post(
        endpoint,
        json=document,
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"{_auth_scheme(configuration, provider='elastic')} {credential}",
        },
        timeout=timeout_seconds,
        follow_redirects=False,
    )


def _post_sentinel_log_entry(
    *,
    configuration: IntegrationConfiguration,
    credential: str,
    payload: dict[str, Any],
) -> httpx.Response:
    settings = _settings_json(configuration)
    timeout_seconds = float(settings.get("timeout_seconds") or 10.0)
    endpoint = configuration.base_url
    entries = _sentinel_log_entries(payload, table_name=str(settings.get("custom_log_table") or "AegisPTFindings_CL"))
    return httpx.post(
        endpoint,
        json=entries,
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"{_auth_scheme(configuration, provider='sentinel')} {credential}",
            "X-AegisPT-Stream": str(settings.get("stream_name") or "Custom-AegisPTFindings"),
        },
        timeout=timeout_seconds,
        follow_redirects=False,
    )


def _elastic_ecs_document(payload: dict[str, Any]) -> dict[str, Any]:
    finding = payload.get("finding") if isinstance(payload.get("finding"), dict) else {}
    target_id = str(finding.get("target_id") or "")
    parsed_target = urlparse(target_id)
    severity = str(finding.get("severity") or "unknown").lower()
    document = {
        "@timestamp": payload.get("sent_at"),
        "event": {
            "kind": "alert",
            "category": ["vulnerability"],
            "type": [str(payload.get("event_kind") or "finding")],
            "action": f"aegispt.{payload.get('event_kind')}",
            "provider": "AegisPT",
            "module": SIEM_EVENT_SOURCE,
            "severity": _elastic_severity_number(severity),
        },
        "rule": {
            "id": str(finding.get("id") or payload.get("run", {}).get("id") or "run-summary"),
            "name": str(finding.get("title") or "AegisPT pentest summary"),
        },
        "vulnerability": {
            "enumeration": "AegisPT",
            "id": str(finding.get("id") or ""),
            "severity": severity,
        },
        "tags": list(finding.get("methodology_tags") or []),
        "aegispt": payload,
    }
    if parsed_target.scheme in {"http", "https"}:
        document["url"] = {"full": target_id}
        if parsed_target.hostname:
            document["destination"] = {"domain": parsed_target.hostname}
    elif target_id:
        document["destination"] = {"address": target_id}
    return document


def _sentinel_log_entries(payload: dict[str, Any], *, table_name: str) -> list[dict[str, Any]]:
    finding = payload.get("finding") if isinstance(payload.get("finding"), dict) else {}
    return [
        {
            "TimeGenerated": payload.get("sent_at"),
            "AegisPTTable": table_name,
            "AegisPTSource": SIEM_EVENT_SOURCE,
            "AegisPTEventKind": payload.get("event_kind"),
            "EngagementId": payload.get("engagement_id"),
            "RunId": payload.get("run_id") or payload.get("run", {}).get("id"),
            "FindingId": finding.get("id"),
            "FindingTitle": finding.get("title"),
            "Severity": finding.get("severity"),
            "Status": finding.get("status"),
            "Target": finding.get("target_id"),
            "EvidenceRef": finding.get("evidence_ref"),
            "SigmaExportCount": len(payload.get("sigma_exports") or []),
        }
    ]


def _resolve_delivery_credential(
    *,
    session: Session,
    configuration: IntegrationConfiguration,
    settings: Settings,
) -> str | None:
    secret_ref = _configured_secret_ref(session=session, configuration=configuration)
    if secret_ref is None:
        return None
    return load_secret_value(secret_ref, settings)


def _configured_secret_ref(
    *,
    session: Session,
    configuration: IntegrationConfiguration,
) -> SecretRef | None:
    auth_ref = str(configuration.auth_ref or "").strip()
    if not auth_ref.startswith("aegispt://secret-ref/"):
        return None
    raw_uuid = auth_ref.removeprefix("aegispt://secret-ref/").strip()
    try:
        secret_id = uuid.UUID(raw_uuid)
    except ValueError:
        return None
    secret_ref = session.get(SecretRef, secret_id)
    if secret_ref is None:
        return None
    if secret_ref.storage_backend not in ENCRYPTED_SECRET_BACKENDS or not secret_ref.encrypted_value:
        return None
    return secret_ref


def _settings_json(configuration: IntegrationConfiguration) -> dict[str, Any]:
    return configuration.settings_json if isinstance(configuration.settings_json, dict) else {}


def _auth_scheme(configuration: IntegrationConfiguration, *, provider: str) -> str:
    settings = _settings_json(configuration)
    configured = str(settings.get("auth_scheme") or "").strip()
    if configured:
        return configured
    return str(SIEM_PROVIDER_DEFINITIONS[provider]["default_auth_scheme"])


def _splunk_alert_level(severity: str) -> str:
    mapping = {
        "critical": "sev1",
        "high": "sev2",
        "medium": "sev3",
        "low": "sev4",
        "info": "sev5",
    }
    return mapping.get(severity, "sev5")


def _elastic_severity_number(severity: str) -> int:
    mapping = {
        "critical": 90,
        "high": 75,
        "medium": 50,
        "low": 25,
        "info": 10,
    }
    return mapping.get(severity, 0)


def _payload_severity(payload: dict[str, Any]) -> str:
    finding = payload.get("finding")
    if isinstance(finding, dict):
        return str(finding.get("severity") or "info").lower()
    run = payload.get("run")
    if isinstance(run, dict):
        severities = run.get("findings_by_severity")
        if isinstance(severities, dict):
            for candidate in ("critical", "high", "medium", "low", "info"):
                if severities.get(candidate):
                    return candidate
    return "info"


def _write_finding_delivery_audit(
    *,
    session: Session,
    actor: str,
    finding: Finding,
    link: FindingIntegrationLink,
    provider: str,
    action: str,
) -> None:
    write_audit_event(
        session=session,
        actor=actor,
        action=action,
        object_type="finding_integration_link",
        object_id=str(link.id),
        metadata={
            "finding_id": str(finding.id),
            "run_id": str(finding.run_id) if finding.run_id else None,
            "integration_type": provider,
            "integration_configuration_id": str(link.integration_configuration_id),
            "handoff_status": link.issue_status,
            "last_sync_state": link.last_sync_state,
            "error": link.last_sync_error,
        },
    )


def _write_run_delivery_audit(
    *,
    session: Session,
    actor: str,
    run: Run,
    provider: str,
    action: str,
    metadata: dict[str, Any],
) -> None:
    write_audit_event(
        session=session,
        actor=actor,
        action=action,
        object_type="run",
        object_id=str(run.id),
        metadata={
            "engagement_id": str(run.engagement_id),
            "integration_type": provider,
            **metadata,
        },
    )
