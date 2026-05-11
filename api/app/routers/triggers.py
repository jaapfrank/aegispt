from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from api.app.auth import get_current_actor
from api.app.config import Settings, get_settings
from api.app.db import get_session
from api.app.models import Finding, Run
from api.app.schemas.triggers import (
    CicdEphemeralScanCreate,
    CicdEphemeralScanRead,
    CicdTriggerRead,
    CicdTriggerSettingsRead,
    CicdTriggerUpsert,
    CicdWebhookPayload,
    CicdWebhookReceiptRead,
)
from api.app.services.audit import write_audit_event
from api.app.services.cicd_triggers import (
    CicdTriggerError,
    cicd_ephemeral_scan_status,
    cicd_trigger_settings_view,
    launch_ephemeral_cicd_scan,
    process_cicd_webhook,
    upsert_cicd_trigger,
)
from api.app.services.tenancy import get_current_tenant_id, load_engagement_for_tenant

router = APIRouter(prefix="/api/v1", tags=["triggers"])


@router.get("/engagements/{engagement_id}/triggers/cicd", response_model=CicdTriggerSettingsRead)
def get_cicd_trigger_settings(
    engagement_id: UUID,
    session: Session = Depends(get_session),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> CicdTriggerSettingsRead:
    engagement = load_engagement_for_tenant(session, engagement_id, tenant_id)
    return cicd_trigger_settings_view(session, engagement=engagement)


@router.put(
    "/engagements/{engagement_id}/triggers/cicd/{trigger_source}",
    response_model=CicdTriggerRead,
)
def put_cicd_trigger(
    engagement_id: UUID,
    trigger_source: str,
    payload: CicdTriggerUpsert,
    session: Session = Depends(get_session),
    settings: Settings = Depends(get_settings),
    tenant_id: str | None = Depends(get_current_tenant_id),
    actor: str = Depends(get_current_actor),
) -> CicdTriggerRead:
    engagement = load_engagement_for_tenant(session, engagement_id, tenant_id)
    try:
        trigger = upsert_cicd_trigger(
            session,
            engagement=engagement,
            trigger_source=trigger_source,
            payload=payload,
            settings=settings,
            actor=actor,
        )
    except CicdTriggerError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc

    write_audit_event(
        session=session,
        actor=actor,
        action="cicd_trigger.configured",
        object_type="cicd_trigger",
        object_id=str(trigger.id) if trigger.id is not None else f"{engagement.id}:{trigger.trigger_source}",
        metadata={
            "engagement_id": str(engagement.id),
            "trigger_source": trigger.trigger_source,
            "status": trigger.status,
            "enabled_profiles": trigger.enabled_profiles,
            "branch_filters": trigger.branch_filters,
            "scope_override_allowed": trigger.scope_override_allowed,
            "webhook_secret_configured": trigger.webhook_secret_configured,
        },
    )
    session.commit()
    return trigger


@router.post(
    "/engagements/{engagement_id}/cicd/ephemeral-scans",
    response_model=CicdEphemeralScanRead,
    status_code=status.HTTP_202_ACCEPTED,
)
def create_cicd_ephemeral_scan(
    engagement_id: UUID,
    payload: CicdEphemeralScanCreate,
    session: Session = Depends(get_session),
    settings: Settings = Depends(get_settings),
    tenant_id: str | None = Depends(get_current_tenant_id),
    actor: str = Depends(get_current_actor),
) -> CicdEphemeralScanRead:
    engagement = load_engagement_for_tenant(session, engagement_id, tenant_id)
    try:
        receipt = launch_ephemeral_cicd_scan(
            session,
            engagement=engagement,
            payload=payload,
            settings=settings,
            actor=actor,
        )
    except CicdTriggerError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc
    session.commit()
    return receipt


@router.get("/cicd/ephemeral-scans/{run_id}", response_model=CicdEphemeralScanRead)
def get_cicd_ephemeral_scan_status(
    run_id: UUID,
    session: Session = Depends(get_session),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> CicdEphemeralScanRead:
    query = (
        select(Run)
        .options(selectinload(Run.profile), selectinload(Run.findings).selectinload(Finding.remediation))
        .where(Run.id == run_id, Run.deleted_at.is_(None))
    )
    run = session.scalar(query)
    if run is None:
        raise HTTPException(status_code=404, detail="ephemeral scan run not found")
    load_engagement_for_tenant(session, run.engagement_id, tenant_id)
    configuration = run.configuration_json if isinstance(run.configuration_json, dict) else {}
    if not isinstance(configuration.get("cicd_ephemeral"), dict):
        raise HTTPException(status_code=404, detail="run is not a CI/CD ephemeral scan")
    return cicd_ephemeral_scan_status(run)


@router.post(
    "/triggers/cicd",
    response_model=CicdWebhookReceiptRead,
    status_code=status.HTTP_202_ACCEPTED,
)
async def receive_cicd_trigger(
    request: Request,
    session: Session = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> CicdWebhookReceiptRead:
    raw_body = await request.body()
    try:
        payload = CicdWebhookPayload.model_validate_json(raw_body)
    except Exception as exc:
        raise HTTPException(status_code=400, detail="invalid CI/CD trigger payload") from exc

    headers = {key.lower(): value for key, value in request.headers.items()}
    try:
        receipt = process_cicd_webhook(
            session,
            payload=payload,
            raw_body=raw_body,
            headers=headers,
            settings=settings,
            actor=f"cicd-webhook:{payload.trigger_source}",
        )
    except CicdTriggerError as exc:
        session.commit()
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc

    session.commit()
    return receipt
