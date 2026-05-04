from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.app.auth import get_current_actor, require_roles
from api.app.config import Settings, get_settings
from api.app.db import get_session
from api.app.models import Engagement, InventorySnapshot, RunProfile, ScheduledRun, Scope
from api.app.schemas.deletion import DeleteImpactRead, EngagementDeleteCreate
from api.app.schemas.engagements import (
    EngagementAuthorizationConfirmRead,
    EngagementCreate,
    EngagementDataCleanupRead,
    EngagementDataRetentionRead,
    EngagementDataRetentionUpdate,
    EngagementPurgeCreate,
    EngagementPurgeRead,
    EngagementRead,
    ExposureScorePointRead,
    ExposureScoreRead,
    ScheduledRunCreate,
    ScheduledRunLaunchBatchRead,
    ScheduledRunLaunchDueCreate,
    ScheduledRunLaunchRead,
    ScheduledRunRead,
    ScopeCreate,
    ScopeRead,
)
from api.app.services.audit import write_audit_event
from api.app.services.exposure_score import ensure_exposure_score, list_exposure_score_history
from api.app.services.gdpr_data import (
    apply_engagement_retention_policy,
    build_engagement_data_export,
    engagement_retention_status,
    hard_purge_engagement_assessment_data,
)
from api.app.services.run_profiles import ensure_default_run_profiles
from api.app.services.runs import (
    align_run_configuration_with_engagement,
    latest_scope_query,
    validate_configured_targets_within_scope,
)
from api.app.services.scheduled_runs import (
    launch_due_scheduled_runs_for_engagement,
    normalize_due_at,
)
from api.app.services.secrets import materialize_run_configuration_secrets
from api.app.services.soft_delete import (
    SoftDeleteBlockedError,
    delete_impact_payload,
    engagement_delete_impact,
    soft_delete_engagement,
)
from api.app.services.tenancy import (
    engagement_query_for_tenant,
    get_current_tenant_id,
    load_engagement_for_tenant,
    resolve_created_tenant_id,
)

router = APIRouter(prefix="/api/v1/engagements", tags=["engagements"])

SCHEDULED_CADENCE_CRON = {
    "daily": "0 0 * * *",
    "weekly": "0 0 * * 1",
}


def _schedule_start_time(starts_at: datetime | None) -> datetime:
    if starts_at is None:
        return datetime.now(tz=UTC)
    if starts_at.tzinfo is None:
        return starts_at.replace(tzinfo=UTC)
    return starts_at


def _load_engagement(session: Session, engagement_id: UUID, tenant_id: str | None = None) -> Engagement:
    return load_engagement_for_tenant(session, engagement_id, tenant_id)


def _load_scheduled_run(
    session: Session,
    engagement_id: UUID,
    schedule_id: UUID,
    tenant_id: str | None = None,
) -> ScheduledRun:
    _load_engagement(session, engagement_id, tenant_id)
    scheduled_run = session.scalar(
        select(ScheduledRun).where(
            ScheduledRun.id == schedule_id,
            ScheduledRun.engagement_id == engagement_id,
        )
    )
    if scheduled_run is None:
        raise HTTPException(status_code=404, detail="scheduled run not found")
    return scheduled_run


@router.get("", response_model=list[EngagementRead])
def list_engagements(
    session: Session = Depends(get_session),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> list[EngagementRead]:
    engagements = session.scalars(engagement_query_for_tenant(session, tenant_id)).all()
    return [EngagementRead.model_validate(engagement) for engagement in engagements]


@router.get("/{engagement_id}", response_model=EngagementRead)
def get_engagement(
    engagement_id: UUID,
    session: Session = Depends(get_session),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> EngagementRead:
    engagement = _load_engagement(session, engagement_id, tenant_id)
    return EngagementRead.model_validate(engagement)


@router.get("/{engagement_id}/exposure-score", response_model=ExposureScoreRead)
def get_engagement_exposure_score(
    engagement_id: UUID,
    session: Session = Depends(get_session),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> ExposureScoreRead:
    _load_engagement(session, engagement_id, tenant_id)
    current = ensure_exposure_score(session, engagement_id)
    session.commit()
    history = list(reversed(list_exposure_score_history(session, engagement_id, limit=10)))
    return ExposureScoreRead(
        engagement_id=engagement_id,
        current=ExposureScorePointRead.model_validate(current),
        history=[ExposureScorePointRead.model_validate(item) for item in history],
        advisory_note=(
            "Exposure score is advisory only. It summarizes stored finding posture and remediation progress, "
            "but it never gates runs or guarantees security improvement."
        ),
    )


@router.patch("/{engagement_id}/confirm-authorization", response_model=EngagementAuthorizationConfirmRead)
def confirm_engagement_authorization(
    engagement_id: UUID,
    session: Session = Depends(get_session),
    actor: str = Depends(require_roles("operator", "admin")),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> EngagementAuthorizationConfirmRead:
    engagement = _load_engagement(session, engagement_id, tenant_id)
    engagement.authorization_confirmed_by = actor
    engagement.authorization_confirmed_at = datetime.now(tz=UTC)
    write_audit_event(
        session=session,
        actor=actor,
        action="engagement.authorization_confirmed",
        object_type="engagement",
        object_id=str(engagement.id),
        metadata={
            "roe_ref": engagement.roe_ref,
            "authorization_confirmed_by": actor,
        },
    )
    session.commit()
    session.refresh(engagement)
    return EngagementAuthorizationConfirmRead.model_validate(engagement)


@router.post("", response_model=EngagementRead, status_code=status.HTTP_201_CREATED)
def create_engagement(
    payload: EngagementCreate,
    session: Session = Depends(get_session),
    actor: str = Depends(require_roles("operator", "admin")),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> EngagementRead:
    resolved_tenant_id = resolve_created_tenant_id(payload.tenant_id, tenant_id)
    engagement = Engagement(
        name=payload.name,
        client=payload.client,
        tenant_id=resolved_tenant_id,
        roe_ref=payload.roe_ref,
        retention_days=payload.retention_days,
        starts_at=payload.starts_at,
        ends_at=payload.ends_at,
    )
    session.add(engagement)
    session.flush()

    write_audit_event(
        session=session,
        actor=actor,
        action="engagement.created",
        object_type="engagement",
        object_id=str(engagement.id),
        metadata={"name": payload.name, "tenant_id": resolved_tenant_id},
    )

    session.commit()
    session.refresh(engagement)
    return EngagementRead.model_validate(engagement)


@router.delete("/{engagement_id}", response_model=DeleteImpactRead)
def delete_engagement(
    engagement_id: UUID,
    payload: EngagementDeleteCreate | None = None,
    dry_run: bool = False,
    session: Session = Depends(get_session),
    actor: str = Depends(require_roles("admin")),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> DeleteImpactRead:
    engagement = _load_engagement(session, engagement_id, tenant_id)
    _run_ids, counts, warnings = engagement_delete_impact(session, engagement.id)
    if dry_run:
        return DeleteImpactRead.model_validate(
            delete_impact_payload(
                object_type="engagement",
                object_id=engagement.id,
                counts=counts,
                dry_run=True,
                warnings=warnings,
            )
        )

    confirmation = "" if payload is None or payload.confirmation is None else payload.confirmation
    if confirmation != engagement.name:
        raise HTTPException(
            status_code=409,
            detail="confirmation string must match the engagement name",
        )
    try:
        result = soft_delete_engagement(session=session, engagement=engagement, actor=actor)
    except SoftDeleteBlockedError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    session.commit()
    return DeleteImpactRead.model_validate(result)


@router.get("/{engagement_id}/data-retention", response_model=EngagementDataRetentionRead)
def get_engagement_data_retention(
    engagement_id: UUID,
    session: Session = Depends(get_session),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> EngagementDataRetentionRead:
    engagement = _load_engagement(session, engagement_id, tenant_id)
    return EngagementDataRetentionRead.model_validate(
        engagement_retention_status(session=session, engagement=engagement)
    )


@router.patch("/{engagement_id}/data-retention", response_model=EngagementDataRetentionRead)
def update_engagement_data_retention(
    engagement_id: UUID,
    payload: EngagementDataRetentionUpdate,
    session: Session = Depends(get_session),
    actor: str = Depends(require_roles("admin")),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> EngagementDataRetentionRead:
    engagement = _load_engagement(session, engagement_id, tenant_id)
    previous = engagement.retention_days
    engagement.retention_days = payload.retention_days
    write_audit_event(
        session=session,
        actor=actor,
        action="engagement.retention_policy.updated",
        object_type="engagement",
        object_id=str(engagement.id),
        metadata={
            "previous_retention_days": previous,
            "retention_days": payload.retention_days,
        },
    )
    session.commit()
    session.refresh(engagement)
    return EngagementDataRetentionRead.model_validate(
        engagement_retention_status(session=session, engagement=engagement)
    )


@router.post("/{engagement_id}/data-retention/cleanup", response_model=EngagementDataCleanupRead)
def cleanup_engagement_retained_data(
    engagement_id: UUID,
    session: Session = Depends(get_session),
    actor: str = Depends(require_roles("admin")),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> EngagementDataCleanupRead:
    engagement = _load_engagement(session, engagement_id, tenant_id)
    result = apply_engagement_retention_policy(session=session, engagement=engagement, actor=actor)
    session.commit()
    return EngagementDataCleanupRead.model_validate(result)


@router.get("/{engagement_id}/data-export")
def export_engagement_data(
    engagement_id: UUID,
    session: Session = Depends(get_session),
    actor: str = Depends(get_current_actor),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> dict:
    engagement = _load_engagement(session, engagement_id, tenant_id)
    payload = build_engagement_data_export(session=session, engagement=engagement, actor=actor)
    session.commit()
    return payload


@router.delete("/{engagement_id}/purge", response_model=EngagementPurgeRead)
def purge_engagement_assessment_data(
    engagement_id: UUID,
    payload: EngagementPurgeCreate,
    session: Session = Depends(get_session),
    actor: str = Depends(require_roles("admin")),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> EngagementPurgeRead:
    engagement = _load_engagement(session, engagement_id, tenant_id)
    if payload.confirmation != f"PURGE {engagement.name}":
        raise HTTPException(
            status_code=409,
            detail="confirmation string must match PURGE <engagement name>",
        )
    try:
        result = hard_purge_engagement_assessment_data(
            session=session,
            engagement=engagement,
            actor=actor,
        )
    except SoftDeleteBlockedError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    session.commit()
    return EngagementPurgeRead.model_validate(result)


@router.post(
    "/{engagement_id}/scope",
    response_model=ScopeRead,
    status_code=status.HTTP_201_CREATED,
)
def create_scope(
    engagement_id: UUID,
    payload: ScopeCreate,
    session: Session = Depends(get_session),
    actor: str = Depends(require_roles("operator", "admin")),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> ScopeRead:
    engagement = _load_engagement(session, engagement_id, tenant_id)

    scope = Scope(
        engagement_id=engagement.id,
        allowlist_json=payload.allowlist_json,
        denylist_json=payload.denylist_json,
    )
    session.add(scope)
    session.flush()

    write_audit_event(
        session=session,
        actor=actor,
        action="scope.created",
        object_type="scope",
        object_id=str(scope.id),
        metadata={"engagement_id": str(engagement.id)},
    )

    session.commit()
    session.refresh(scope)
    return ScopeRead.model_validate(scope)


@router.get("/{engagement_id}/scope", response_model=ScopeRead)
def get_latest_scope(
    engagement_id: UUID,
    optional: bool = False,
    session: Session = Depends(get_session),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> ScopeRead | Response:
    engagement = _load_engagement(session, engagement_id, tenant_id)

    scope = session.scalar(
        select(Scope)
        .where(Scope.engagement_id == engagement.id)
        .order_by(Scope.created_at.desc(), Scope.id.desc())
    )
    if scope is None:
        if optional:
            return Response(status_code=status.HTTP_204_NO_CONTENT)
        raise HTTPException(status_code=404, detail="scope not found")
    return ScopeRead.model_validate(scope)


@router.post(
    "/{engagement_id}/schedules",
    response_model=ScheduledRunRead,
    status_code=status.HTTP_201_CREATED,
)
def create_scheduled_run(
    engagement_id: UUID,
    payload: ScheduledRunCreate,
    session: Session = Depends(get_session),
    actor: str = Depends(require_roles("operator", "admin")),
    settings: Settings = Depends(get_settings),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> ScheduledRunRead:
    ensure_default_run_profiles(session)

    engagement = _load_engagement(session, engagement_id, tenant_id)
    scope = session.scalar(latest_scope_query(engagement.id))
    if scope is None:
        raise HTTPException(status_code=400, detail="engagement scope required before scheduling runs")

    profile = session.scalar(select(RunProfile).where(RunProfile.name == payload.profile_name))
    if profile is None:
        raise HTTPException(status_code=404, detail="run profile not found")
    if profile.run_class != "passive":
        raise HTTPException(status_code=409, detail="scheduled scans only support passive run profiles")

    if payload.source_inventory_snapshot_id is not None:
        inventory_snapshot = session.scalar(
            select(InventorySnapshot).where(
                InventorySnapshot.id == payload.source_inventory_snapshot_id,
                InventorySnapshot.engagement_id == engagement.id,
            )
        )
        if inventory_snapshot is None:
            raise HTTPException(status_code=404, detail="inventory snapshot not found for engagement")

    aligned_configuration = align_run_configuration_with_engagement(
        payload.configuration_json,
        engagement=engagement,
    )
    try:
        sanitized_configuration, created_secret_refs = materialize_run_configuration_secrets(
            session,
            engagement_id=engagement.id,
            configuration=aligned_configuration,
            settings=settings,
        )
        validate_configured_targets_within_scope(scope, sanitized_configuration)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    scheduled_run = ScheduledRun(
        engagement_id=engagement.id,
        profile_name=profile.name,
        source_inventory_snapshot_id=payload.source_inventory_snapshot_id,
        cadence=payload.cadence,
        cron_expression=SCHEDULED_CADENCE_CRON[payload.cadence],
        timezone=payload.timezone.strip() or "UTC",
        status="enabled",
        next_run_at=_schedule_start_time(payload.starts_at),
        configuration_json=sanitized_configuration,
        created_by=actor,
        updated_by=actor,
    )
    session.add(scheduled_run)
    session.flush()

    write_audit_event(
        session=session,
        actor=actor,
        action="scheduled_run.created",
        object_type="scheduled_run",
        object_id=str(scheduled_run.id),
        metadata={
            "engagement_id": str(engagement.id),
            "profile_name": profile.name,
            "cadence": payload.cadence,
            "secret_binding_count": len(created_secret_refs),
        },
    )

    session.commit()
    session.refresh(scheduled_run)
    return ScheduledRunRead.model_validate(scheduled_run)


@router.get("/{engagement_id}/schedules", response_model=list[ScheduledRunRead])
def list_scheduled_runs(
    engagement_id: UUID,
    session: Session = Depends(get_session),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> list[ScheduledRunRead]:
    _load_engagement(session, engagement_id, tenant_id)
    scheduled_runs = session.scalars(
        select(ScheduledRun)
        .where(ScheduledRun.engagement_id == engagement_id)
        .order_by(ScheduledRun.created_at.desc(), ScheduledRun.id.desc())
    ).all()
    return [ScheduledRunRead.model_validate(scheduled_run) for scheduled_run in scheduled_runs]


@router.post("/{engagement_id}/schedules/launch-due", response_model=ScheduledRunLaunchBatchRead)
def launch_due_scheduled_runs(
    engagement_id: UUID,
    payload: ScheduledRunLaunchDueCreate | None = None,
    session: Session = Depends(get_session),
    actor: str = Depends(require_roles("operator", "admin")),
    settings: Settings = Depends(get_settings),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> ScheduledRunLaunchBatchRead:
    _load_engagement(session, engagement_id, tenant_id)
    due_at = normalize_due_at(payload.due_at if payload is not None else None)
    dispatch_results = launch_due_scheduled_runs_for_engagement(
        session,
        engagement_id=engagement_id,
        actor=actor,
        settings=settings,
        due_at=due_at,
    )
    launch_reads = [ScheduledRunLaunchRead(**result.__dict__) for result in dispatch_results]

    return ScheduledRunLaunchBatchRead(
        due_at=due_at,
        launched_count=len(launch_reads),
        launches=launch_reads,
    )


@router.get("/{engagement_id}/schedules/{schedule_id}", response_model=ScheduledRunRead)
def get_scheduled_run(
    engagement_id: UUID,
    schedule_id: UUID,
    session: Session = Depends(get_session),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> ScheduledRunRead:
    return ScheduledRunRead.model_validate(_load_scheduled_run(session, engagement_id, schedule_id, tenant_id))


@router.post("/{engagement_id}/schedules/{schedule_id}/pause", response_model=ScheduledRunRead)
def pause_scheduled_run(
    engagement_id: UUID,
    schedule_id: UUID,
    session: Session = Depends(get_session),
    actor: str = Depends(require_roles("operator", "admin")),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> ScheduledRunRead:
    scheduled_run = _load_scheduled_run(session, engagement_id, schedule_id, tenant_id)
    timestamp = datetime.now(tz=UTC)
    scheduled_run.status = "paused"
    scheduled_run.updated_by = actor
    scheduled_run.paused_at = timestamp
    scheduled_run.paused_by = actor

    write_audit_event(
        session=session,
        actor=actor,
        action="scheduled_run.paused",
        object_type="scheduled_run",
        object_id=str(scheduled_run.id),
        metadata={"engagement_id": str(engagement_id)},
    )

    session.commit()
    session.refresh(scheduled_run)
    return ScheduledRunRead.model_validate(scheduled_run)


@router.post("/{engagement_id}/schedules/{schedule_id}/resume", response_model=ScheduledRunRead)
def resume_scheduled_run(
    engagement_id: UUID,
    schedule_id: UUID,
    session: Session = Depends(get_session),
    actor: str = Depends(require_roles("operator", "admin")),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> ScheduledRunRead:
    scheduled_run = _load_scheduled_run(session, engagement_id, schedule_id, tenant_id)
    scheduled_run.status = "enabled"
    scheduled_run.updated_by = actor
    scheduled_run.paused_at = None
    scheduled_run.paused_by = None

    write_audit_event(
        session=session,
        actor=actor,
        action="scheduled_run.resumed",
        object_type="scheduled_run",
        object_id=str(scheduled_run.id),
        metadata={"engagement_id": str(engagement_id)},
    )

    session.commit()
    session.refresh(scheduled_run)
    return ScheduledRunRead.model_validate(scheduled_run)
