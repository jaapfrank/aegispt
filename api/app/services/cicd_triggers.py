from __future__ import annotations

import copy
import fnmatch
import hashlib
import hmac
import uuid
from datetime import UTC, datetime
from typing import Mapping
from urllib.parse import urlparse

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from api.app.config import Settings
from api.app.models import CicdTrigger, CicdTriggerEvent, Engagement, Run, RunProfile, Scope, SecretRef
from api.app.schemas.triggers import (
    CicdTriggerEventRead,
    CicdTriggerRead,
    CicdTriggerSettingsRead,
    CicdTriggerUpsert,
    CicdWebhookPayload,
    CicdWebhookReceiptRead,
    TriggerSource,
)
from api.app.services.audit import write_audit_event
from api.app.services.packs import bind_pack_to_run, latest_pack_deployment
from api.app.services.run_profiles import ensure_default_run_profiles
from api.app.services.runs import (
    align_run_configuration_with_engagement,
    dispatch_queued_run_tasks,
    latest_scope_query,
    queue_run_tasks,
    required_approvals,
)
from api.app.services.secrets import (
    ENCRYPTED_SECRET_BACKENDS,
    direct_secret_storage_backend,
    encrypt_secret_value,
    load_secret_value,
)

CICD_SOURCES: tuple[TriggerSource, ...] = ("github", "gitlab", "generic")
SIGNATURE_HEADERS: dict[TriggerSource, str] = {
    "github": "x-hub-signature-256",
    "gitlab": "x-gitlab-signature-256",
    "generic": "x-aegispt-signature-256",
}


class CicdTriggerError(Exception):
    def __init__(self, detail: str, *, status_code: int = 400) -> None:
        super().__init__(detail)
        self.detail = detail
        self.status_code = status_code


def upsert_cicd_trigger(
    session: Session,
    *,
    engagement: Engagement,
    trigger_source: str,
    payload: CicdTriggerUpsert,
    settings: Settings,
    actor: str,
) -> CicdTriggerRead:
    source = _normalized_source(trigger_source)
    ensure_default_run_profiles(session)
    enabled_profiles = _normalized_profile_names(payload.enabled_profiles)
    if not enabled_profiles:
        raise CicdTriggerError("enabled_profiles must contain at least one run profile")

    known_profiles = {
        name
        for name in session.scalars(select(RunProfile.name).where(RunProfile.name.in_(enabled_profiles))).all()
    }
    missing_profiles = [name for name in enabled_profiles if name not in known_profiles]
    if missing_profiles:
        raise CicdTriggerError(f"unknown run profiles: {', '.join(missing_profiles)}", status_code=404)

    trigger = session.scalar(
        select(CicdTrigger)
        .options(selectinload(CicdTrigger.webhook_secret_ref), selectinload(CicdTrigger.last_run))
        .where(
            CicdTrigger.engagement_id == engagement.id,
            CicdTrigger.trigger_source == source,
        )
    )
    is_new = trigger is None
    if trigger is None:
        trigger = CicdTrigger(
            engagement_id=engagement.id,
            trigger_source=source,
            status="enabled",
            enabled_profiles_json=[],
            branch_filters_json=[],
            scope_override_allowed=False,
            metadata_json={},
        )

    secret_value = str(payload.webhook_secret or "").strip()
    if secret_value:
        trigger.webhook_secret_ref = _store_or_update_webhook_secret(
            session=session,
            engagement_id=engagement.id,
            trigger=trigger,
            trigger_source=source,
            secret_value=secret_value,
            settings=settings,
        )
    elif trigger.webhook_secret_ref is None:
        raise CicdTriggerError("webhook_secret is required when configuring a new trigger")

    if is_new:
        session.add(trigger)

    trigger.status = "enabled" if payload.enabled else "disabled"
    trigger.enabled_profiles_json = enabled_profiles
    trigger.branch_filters_json = _normalized_branch_filters(payload.branch_filters)
    trigger.scope_override_allowed = bool(payload.scope_override_allowed)
    trigger.metadata_json = {
        "raw_secret_material_exposed": False,
        "source": source,
        "configured_by": actor,
    }
    session.flush()

    return serialize_cicd_trigger(trigger)


def cicd_trigger_settings_view(
    session: Session,
    *,
    engagement: Engagement,
    history_limit: int = 10,
) -> CicdTriggerSettingsRead:
    triggers = session.scalars(
        select(CicdTrigger)
        .options(selectinload(CicdTrigger.webhook_secret_ref), selectinload(CicdTrigger.last_run))
        .where(CicdTrigger.engagement_id == engagement.id)
        .order_by(CicdTrigger.trigger_source.asc())
    ).all()
    trigger_by_source = {trigger.trigger_source: trigger for trigger in triggers}

    history = session.scalars(
        select(CicdTriggerEvent)
        .join(CicdTrigger, CicdTriggerEvent.cicd_trigger_id == CicdTrigger.id)
        .options(selectinload(CicdTriggerEvent.run))
        .where(CicdTrigger.engagement_id == engagement.id)
        .order_by(CicdTriggerEvent.created_at.desc(), CicdTriggerEvent.id.desc())
        .limit(history_limit)
    ).all()

    return CicdTriggerSettingsRead(
        engagement_id=engagement.id,
        triggers=[
            serialize_cicd_trigger(trigger_by_source.get(source), engagement_id=engagement.id, source=source)
            for source in CICD_SOURCES
        ],
        history=[serialize_cicd_trigger_event(event) for event in history],
    )


def process_cicd_webhook(
    session: Session,
    *,
    payload: CicdWebhookPayload,
    raw_body: bytes,
    headers: Mapping[str, str],
    settings: Settings,
    actor: str,
) -> CicdWebhookReceiptRead:
    source = _normalized_source(payload.trigger_source)
    engagement = session.scalar(
        select(Engagement).where(
            Engagement.id == payload.engagement_id,
            Engagement.deleted_at.is_(None),
        )
    )
    if engagement is None:
        raise CicdTriggerError("engagement not found", status_code=404)

    trigger = session.scalar(
        select(CicdTrigger)
        .options(selectinload(CicdTrigger.webhook_secret_ref), selectinload(CicdTrigger.last_run))
        .where(
            CicdTrigger.engagement_id == engagement.id,
            CicdTrigger.trigger_source == source,
        )
    )
    if trigger is None or trigger.webhook_secret_ref is None:
        raise CicdTriggerError("cicd trigger not configured for engagement/source", status_code=404)
    if trigger.status != "enabled":
        raise CicdTriggerError("cicd trigger is disabled", status_code=409)

    signature_valid, signature_error = _verify_signature(
        trigger_source=source,
        headers=headers,
        raw_body=raw_body,
        secret_ref=trigger.webhook_secret_ref,
        settings=settings,
    )
    if not signature_valid:
        event = _record_trigger_event(
            session=session,
            trigger=trigger,
            actor=actor,
            status="invalid_signature",
            status_detail=signature_error,
            ref=payload.ref,
            commit_sha=payload.commit_sha,
            signature_valid=False,
            metadata_json={"raw_secret_material_exposed": False},
        )
        session.flush()
        raise CicdTriggerError(event.status_detail or "invalid signature", status_code=401)

    scope = session.scalar(latest_scope_query(engagement.id))
    if scope is None:
        raise CicdTriggerError("engagement scope required before processing CI/CD triggers", status_code=409)

    branch = _normalize_branch(payload.ref)
    if not _matches_branch_filter(branch=branch, ref=payload.ref, filters=trigger.branch_filters_json):
        event = _record_trigger_event(
            session=session,
            trigger=trigger,
            actor=actor,
            status="ignored_branch",
            status_detail="trigger branch did not match the configured branch filters",
            ref=payload.ref,
            commit_sha=payload.commit_sha,
            signature_valid=True,
            metadata_json={"branch": branch, "raw_secret_material_exposed": False},
        )
        trigger.last_triggered_at = datetime.now(tz=UTC)
        session.flush()
        return CicdWebhookReceiptRead(
            accepted=True,
            engagement_id=engagement.id,
            trigger_source=source,
            ref=payload.ref,
            branch=branch,
            commit_sha=payload.commit_sha,
            event_count=1,
            events=[serialize_cicd_trigger_event(event)],
        )

    override_target_url = str(payload.target_url_override or "").strip() or None
    if override_target_url:
        override_allowed, override_reason = _scope_override_allowed(
            scope=scope,
            override_target_url=override_target_url,
            trigger=trigger,
        )
        if not override_allowed:
            event = _record_trigger_event(
                session=session,
                trigger=trigger,
                actor=actor,
                status="scope_override_rejected",
                status_detail=override_reason,
                ref=payload.ref,
                commit_sha=payload.commit_sha,
                signature_valid=True,
                override_target_url=override_target_url,
                metadata_json={"branch": branch, "raw_secret_material_exposed": False},
            )
            trigger.last_triggered_at = datetime.now(tz=UTC)
            session.flush()
            return CicdWebhookReceiptRead(
                accepted=True,
                engagement_id=engagement.id,
                trigger_source=source,
                ref=payload.ref,
                branch=branch,
                commit_sha=payload.commit_sha,
                event_count=1,
                events=[serialize_cicd_trigger_event(event)],
            )

    events: list[CicdTriggerEvent] = []
    for profile_name in trigger.enabled_profiles_json:
        event = _launch_triggered_profile(
            session=session,
            trigger=trigger,
            engagement=engagement,
            scope=scope,
            profile_name=profile_name,
            branch=branch,
            payload=payload,
            actor=actor,
            settings=settings,
            override_target_url=override_target_url,
        )
        events.append(event)

    trigger.last_triggered_at = datetime.now(tz=UTC)
    linked_runs = [event.run for event in events if event.run is not None]
    if linked_runs:
        latest_run = max(linked_runs, key=lambda item: (item.created_at, item.id.hex))
        trigger.last_run_id = latest_run.id
    session.flush()

    return CicdWebhookReceiptRead(
        accepted=True,
        engagement_id=engagement.id,
        trigger_source=source,
        ref=payload.ref,
        branch=branch,
        commit_sha=payload.commit_sha,
        event_count=len(events),
        events=[serialize_cicd_trigger_event(event) for event in events],
    )


def serialize_cicd_trigger(
    trigger: CicdTrigger | None,
    *,
    engagement_id: uuid.UUID | None = None,
    source: str | None = None,
) -> CicdTriggerRead:
    if trigger is None:
        if engagement_id is None or source is None:
            raise ValueError("engagement_id and source are required for placeholder trigger rendering")
        return CicdTriggerRead(
            engagement_id=engagement_id,
            trigger_source=_normalized_source(source),
            status="unconfigured",
            configured=False,
        )

    return CicdTriggerRead(
        id=trigger.id,
        engagement_id=trigger.engagement_id,
        trigger_source=_normalized_source(trigger.trigger_source),
        status=trigger.status,
        configured=True,
        enabled_profiles=_normalized_profile_names(trigger.enabled_profiles_json),
        branch_filters=_normalized_branch_filters(trigger.branch_filters_json),
        scope_override_allowed=bool(trigger.scope_override_allowed),
        webhook_secret_configured=trigger.webhook_secret_ref is not None,
        webhook_display_label=(
            trigger.webhook_secret_ref.display_label if trigger.webhook_secret_ref is not None else None
        ),
        last_triggered_at=trigger.last_triggered_at,
        last_run_id=trigger.last_run_id,
        last_run_status=trigger.last_run.status if trigger.last_run is not None else None,
    )


def serialize_cicd_trigger_event(event: CicdTriggerEvent) -> CicdTriggerEventRead:
    return CicdTriggerEventRead(
        id=event.id,
        cicd_trigger_id=event.cicd_trigger_id,
        trigger_source=_normalized_source(event.trigger_source),
        profile_name=event.profile_name,
        ref=event.ref,
        branch=_normalize_branch(event.ref),
        commit_sha=event.commit_sha,
        status=event.status,
        status_detail=event.status_detail,
        signature_valid=bool(event.signature_valid),
        scope_override_applied=bool(event.scope_override_applied),
        override_target_url=event.override_target_url,
        run_id=event.run_id,
        run_status=event.run.status if event.run is not None else None,
        created_at=event.created_at,
    )


def _launch_triggered_profile(
    session: Session,
    *,
    trigger: CicdTrigger,
    engagement: Engagement,
    scope: Scope,
    profile_name: str,
    branch: str,
    payload: CicdWebhookPayload,
    actor: str,
    settings: Settings,
    override_target_url: str | None,
) -> CicdTriggerEvent:
    profile = session.scalar(select(RunProfile).where(RunProfile.name == profile_name))
    if profile is None:
        return _record_trigger_event(
            session=session,
            trigger=trigger,
            actor=actor,
            status="profile_missing",
            status_detail=f"run profile '{profile_name}' was not found at trigger time",
            profile_name=profile_name,
            ref=payload.ref,
            commit_sha=payload.commit_sha,
            signature_valid=True,
            override_target_url=override_target_url,
            metadata_json={"branch": branch, "raw_secret_material_exposed": False},
        )

    configuration, _created_secret_refs = _materialize_trigger_configuration(
        session=session,
        engagement=engagement,
        trigger=trigger,
        profile=profile,
        payload=payload,
        override_target_url=override_target_url,
        settings=settings,
    )
    timestamp = datetime.now(tz=UTC)
    run = Run(
        engagement_id=engagement.id,
        profile_id=profile.id,
        profile=profile,
        requested_by=actor,
        status="requested",
        configuration_json=configuration,
        created_at=timestamp,
        updated_at=timestamp,
    )
    session.add(run)
    session.flush()

    deployment = latest_pack_deployment(session, engagement_id=engagement.id, run_profile_name=profile.name)
    if deployment is not None and deployment.pack is not None:
        bind_pack_to_run(session, run=run, pack=deployment.pack)

    write_audit_event(
        session=session,
        actor=actor,
        action="run.requested",
        object_type="run",
        object_id=str(run.id),
        metadata={
            "engagement_id": str(engagement.id),
            "profile_name": profile.name,
            "requested_from": "cicd_trigger",
            "trigger_source": trigger.trigger_source,
            "ref": payload.ref,
            "commit_sha": payload.commit_sha,
            "scope_override_applied": bool(override_target_url),
        },
    )

    if required_approvals(profile) > 0:
        run.status = "pending_approval"
        return _record_trigger_event(
            session=session,
            trigger=trigger,
            actor=actor,
            status="pending_approval",
            status_detail="triggered run preserved the existing approval gate",
            profile_name=profile.name,
            ref=payload.ref,
            commit_sha=payload.commit_sha,
            signature_valid=True,
            override_target_url=override_target_url,
            run=run,
            scope_override_applied=bool(override_target_url),
            metadata_json={"branch": branch, "raw_secret_material_exposed": False},
        )

    queue_run_tasks(session, run, scope, profile)
    session.flush()
    write_audit_event(
        session=session,
        actor=actor,
        action="run.queued",
        object_type="run",
        object_id=str(run.id),
        metadata={
            "engagement_id": str(engagement.id),
            "profile_name": profile.name,
            "requested_from": "cicd_trigger",
            "trigger_source": trigger.trigger_source,
        },
    )

    try:
        dispatch_mode, dispatched_task_ids = dispatch_queued_run_tasks(
            session,
            run=run,
            actor=actor,
            settings=settings,
        )
    except ValueError as exc:
        return _record_trigger_event(
            session=session,
            trigger=trigger,
            actor=actor,
            status="dispatch_blocked",
            status_detail=str(exc),
            profile_name=profile.name,
            ref=payload.ref,
            commit_sha=payload.commit_sha,
            signature_valid=True,
            override_target_url=override_target_url,
            run=run,
            scope_override_applied=bool(override_target_url),
            metadata_json={"branch": branch, "raw_secret_material_exposed": False},
        )

    return _record_trigger_event(
        session=session,
        trigger=trigger,
        actor=actor,
        status="dispatched",
        status_detail=f"triggered run dispatched through {dispatch_mode}",
        profile_name=profile.name,
        ref=payload.ref,
        commit_sha=payload.commit_sha,
        signature_valid=True,
        override_target_url=override_target_url,
        run=run,
        scope_override_applied=bool(override_target_url),
        metadata_json={
            "branch": branch,
            "dispatch_mode": dispatch_mode,
            "dispatched_task_ids": [str(task_id) for task_id in dispatched_task_ids],
            "raw_secret_material_exposed": False,
        },
    )


def _materialize_trigger_configuration(
    session: Session,
    *,
    engagement: Engagement,
    trigger: CicdTrigger,
    profile: RunProfile,
    payload: CicdWebhookPayload,
    override_target_url: str | None,
    settings: Settings,
) -> tuple[dict[str, object], list[SecretRef]]:
    configuration: dict[str, object] = {
        "assessment_type": "CI/CD Triggered Validation",
        "test_profile": profile.name,
        "cicd": {
            "trigger_source": trigger.trigger_source,
            "ref": payload.ref,
            "branch": _normalize_branch(payload.ref),
            "commit_sha": payload.commit_sha,
            "repository_url": payload.repository_url,
            "environment": payload.environment,
            "target_url_override": override_target_url,
            "metadata_json": copy.deepcopy(payload.metadata_json or {}),
        },
    }
    if override_target_url:
        configuration["targets"] = {"urls": [override_target_url]}
    aligned = align_run_configuration_with_engagement(configuration, engagement=engagement)
    return aligned, []


def _record_trigger_event(
    session: Session,
    *,
    trigger: CicdTrigger,
    actor: str,
    status: str,
    status_detail: str | None,
    profile_name: str | None = None,
    ref: str | None = None,
    commit_sha: str | None = None,
    signature_valid: bool,
    override_target_url: str | None = None,
    run: Run | None = None,
    scope_override_applied: bool = False,
    metadata_json: dict[str, object] | None = None,
) -> CicdTriggerEvent:
    event = CicdTriggerEvent(
        cicd_trigger_id=trigger.id,
        run_id=run.id if run is not None else None,
        run=run,
        trigger_source=trigger.trigger_source,
        profile_name=profile_name,
        ref=ref,
        commit_sha=commit_sha,
        status=status,
        status_detail=status_detail,
        signature_valid=signature_valid,
        scope_override_applied=scope_override_applied,
        override_target_url=override_target_url,
        metadata_json=dict(metadata_json or {}),
    )
    session.add(event)
    session.flush()
    write_audit_event(
        session=session,
        actor=actor,
        action=f"cicd_trigger.{status}",
        object_type="cicd_trigger_event",
        object_id=str(event.id),
        metadata={
            "cicd_trigger_id": str(trigger.id),
            "engagement_id": str(trigger.engagement_id),
            "run_id": str(run.id) if run is not None else None,
            "profile_name": profile_name,
            "ref": ref,
            "commit_sha": commit_sha,
            "signature_valid": signature_valid,
            "scope_override_applied": scope_override_applied,
        },
    )
    return event


def _store_or_update_webhook_secret(
    session: Session,
    *,
    engagement_id: uuid.UUID,
    trigger: CicdTrigger,
    trigger_source: TriggerSource,
    secret_value: str,
    settings: Settings,
) -> SecretRef:
    existing = trigger.webhook_secret_ref
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
            purpose=f"cicd_trigger.webhook_secret.{trigger_source}",
            secret_kind="webhook_secret",
            storage_backend=storage_backend,
            display_label=f"{trigger_source} CI/CD webhook secret",
            encrypted_value=None,
            metadata_json={},
        )
        secret_ref.vault_pointer = f"aegispt://secret-ref/{secret_ref.id}"
        session.add(secret_ref)

    secret_ref.purpose = f"cicd_trigger.webhook_secret.{trigger_source}"
    secret_ref.secret_kind = "webhook_secret"
    secret_ref.display_label = f"{trigger_source} CI/CD webhook secret"
    secret_ref.encrypted_value = encrypt_secret_value(
        secret_value,
        settings,
        storage_backend=storage_backend,
    )
    secret_ref.metadata_json = {
        "trigger_source": trigger_source,
        "raw_secret_material_exposed": False,
        "fallback_to_local_secret_key": fallback_to_local if storage_backend == "encrypted_local" else False,
    }
    session.flush()
    return secret_ref


def _verify_signature(
    *,
    trigger_source: TriggerSource,
    headers: Mapping[str, str],
    raw_body: bytes,
    secret_ref: SecretRef,
    settings: Settings,
) -> tuple[bool, str | None]:
    secret = load_secret_value(secret_ref, settings)
    if not secret:
        return False, "configured webhook secret could not be loaded"
    header_name = SIGNATURE_HEADERS[trigger_source]
    provided = str(headers.get(header_name) or "").strip()
    if not provided:
        return False, f"missing signature header: {header_name}"
    digest = hmac.new(secret.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()
    expected = f"sha256={digest}"
    if hmac.compare_digest(provided, expected) or hmac.compare_digest(provided, digest):
        return True, None
    return False, "signature did not match configured webhook secret"


def _scope_override_allowed(
    *,
    scope: Scope,
    override_target_url: str,
    trigger: CicdTrigger,
) -> tuple[bool, str | None]:
    if not trigger.scope_override_allowed:
        return False, "target URL override is not allowed for this trigger"

    parsed = urlparse(override_target_url)
    hostname = str(parsed.hostname or "").strip().lower()
    if not hostname or parsed.scheme not in {"http", "https"}:
        return False, "target URL override must be an http(s) URL within the approved scope"

    allowlist = scope.allowlist_json if isinstance(scope.allowlist_json, dict) else {}
    exact_urls = [
        str(item).strip()
        for key in ("urls", "api_base_urls")
        for item in allowlist.get(key, [])
        if str(item).strip()
    ]
    for allowed_url in exact_urls:
        if override_target_url == allowed_url or override_target_url.startswith(allowed_url.rstrip("/") + "/"):
            return True, None

    domain_candidates = [
        str(item).strip().lower()
        for key in ("domains", "subdomains", "directory_domains", "ad_domains")
        for item in allowlist.get(key, [])
        if str(item).strip()
    ]
    host_candidates = [
        str(item).strip().lower()
        for key in ("hosts", "ip_addresses")
        for item in allowlist.get(key, [])
        if str(item).strip()
    ]
    for candidate in domain_candidates + host_candidates:
        if "*" in candidate and fnmatch.fnmatch(hostname, candidate):
            return True, None
        if hostname == candidate or hostname.endswith(f".{candidate}"):
            return True, None

    return False, "target URL override fell outside the approved scope"


def _matches_branch_filter(*, branch: str | None, ref: str | None, filters: list[str] | None) -> bool:
    normalized_filters = _normalized_branch_filters(filters or [])
    if not normalized_filters:
        return True
    branch_value = str(branch or "").strip()
    ref_value = str(ref or "").strip()
    return any(
        fnmatch.fnmatch(branch_value, pattern) or fnmatch.fnmatch(ref_value, pattern)
        for pattern in normalized_filters
    )


def _normalized_profile_names(values: list[str] | tuple[str, ...] | None) -> list[str]:
    seen: set[str] = set()
    normalized: list[str] = []
    for value in values or []:
        candidate = str(value or "").strip()
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)
        normalized.append(candidate)
    return normalized


def _normalized_branch_filters(values: list[str] | tuple[str, ...] | None) -> list[str]:
    seen: set[str] = set()
    normalized: list[str] = []
    for value in values or []:
        candidate = str(value or "").strip()
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)
        normalized.append(candidate)
    return normalized


def _normalized_source(value: str) -> TriggerSource:
    candidate = str(value or "").strip().lower()
    if candidate not in CICD_SOURCES:
        raise CicdTriggerError("unsupported trigger_source", status_code=400)
    return candidate  # type: ignore[return-value]


def _normalize_branch(ref: str | None) -> str | None:
    candidate = str(ref or "").strip()
    if not candidate:
        return None
    prefixes = ("refs/heads/", "origin/", "heads/")
    for prefix in prefixes:
        if candidate.startswith(prefix):
            return candidate[len(prefix) :]
    return candidate
