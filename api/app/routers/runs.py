from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.app.auth import get_current_actor
from api.app.config import Settings, get_settings
from api.app.db import get_session
from api.app.models import Approval, Engagement, InventorySnapshot, Run, RunProfile
from api.app.policy.engine import execution_kill_switch_enabled
from api.app.schemas.packs import RunPackBindCreate, RunPackBindingRead
from api.app.schemas.report_center import RunReportCatalogItemRead
from api.app.schemas.runs import (
    ApprovalCreate,
    ApprovalRead,
    FindingSummaryRead,
    RunCreate,
    RunDispatchRead,
    RunProfileRead,
    RunRead,
    TaskRead,
)
from api.app.services.audit import write_audit_event
from api.app.services.packs import bind_pack_to_run, latest_pack_deployment, load_pack
from api.app.services.report_pdf import render_pdf_report
from api.app.services.run_profiles import ensure_default_run_profiles
from api.app.services.task_dispatch import dispatch_task_batch, supported_execution_tools
from api.app.services.runs import (
    align_run_configuration_with_engagement,
    cancel_run_tasks,
    granted_approvals,
    latest_scope_query,
    load_run,
    pending_approvals,
    queue_run_tasks,
    required_approvals,
    sorted_approvals,
    sorted_findings,
    sorted_tasks,
)
from api.app.services.secrets import materialize_run_configuration_secrets, sanitize_run_configuration
from api.app.services.reports import (
    build_report_catalog,
    load_run_report,
    render_html_report,
    render_markdown_report,
)

router = APIRouter(prefix="/api/v1", tags=["runs"])


def serialize_run_pack_binding(run: Run) -> RunPackBindingRead | None:
    if run.bound_pack is None:
        return None

    deployment = run.bound_pack_deployment
    return RunPackBindingRead(
        pack_id=run.bound_pack.id,
        pack_version=run.bound_pack_version,
        deployment_id=deployment.id if deployment is not None else None,
        deployment_status=deployment.status if deployment is not None else None,
        deployment_target=deployment.deployment_target if deployment is not None else None,
        run_profile_name=deployment.run_profile_name if deployment is not None else None,
        methodology_tags=list(run.bound_pack.methodology_tags or []),
        source_inventory_snapshot_id=run.bound_pack.source_inventory_snapshot_id,
        relevance_decision_id=run.bound_pack.relevance_decision_id,
        manifest_json=dict(run.bound_pack.manifest_json or {}),
    )


def serialize_run(run: Run) -> RunRead:
    profile = run.profile
    if profile is None:
        raise HTTPException(status_code=500, detail="run profile relationship not loaded")

    required = required_approvals(profile)
    granted = granted_approvals(run)
    pending = pending_approvals(run, profile)
    findings = sorted_findings(run)
    findings_by_severity: dict[str, int] = {}
    findings_by_status: dict[str, int] = {}

    for finding in findings:
        findings_by_severity[finding.severity] = findings_by_severity.get(finding.severity, 0) + 1
        findings_by_status[finding.status] = findings_by_status.get(finding.status, 0) + 1

    return RunRead(
        id=run.id,
        engagement_id=run.engagement_id,
        requested_by=run.requested_by,
        status=run.status,
        source_inventory_snapshot_id=run.source_inventory_snapshot_id,
        started_at=run.started_at,
        created_at=run.created_at,
        updated_at=run.updated_at,
        profile=RunProfileRead.model_validate(profile),
        required_approvals=required,
        granted_approvals=granted,
        pending_approvals=pending,
        approvals=[ApprovalRead.model_validate(approval) for approval in sorted_approvals(run)],
        tasks=[TaskRead.model_validate(task) for task in sorted_tasks(run)],
        findings=FindingSummaryRead(
            finding_count=len(findings),
            findings_by_severity=findings_by_severity,
            findings_by_status=findings_by_status,
        ),
        configuration_json=sanitize_run_configuration(dict(run.configuration_json or {})),
        pack_binding=serialize_run_pack_binding(run),
    )


@router.get("/run-profiles", response_model=list[RunProfileRead])
def list_run_profiles(session: Session = Depends(get_session)) -> list[RunProfileRead]:
    changed = ensure_default_run_profiles(session)
    if changed:
        session.commit()
    profiles = session.scalars(select(RunProfile).order_by(RunProfile.name)).all()
    return [RunProfileRead.model_validate(profile) for profile in profiles]


@router.get("/engagements/{engagement_id}/runs", response_model=list[RunRead])
def list_engagement_runs(
    engagement_id: UUID,
    session: Session = Depends(get_session),
) -> list[RunRead]:
    runs = session.scalars(
        select(Run)
        .where(Run.engagement_id == engagement_id)
        .order_by(Run.created_at.desc(), Run.id.desc())
    ).all()
    hydrated_runs = [load_run(session, run.id) for run in runs]
    return [serialize_run(run) for run in hydrated_runs if run is not None]


@router.post(
    "/engagements/{engagement_id}/runs",
    response_model=RunRead,
    status_code=status.HTTP_201_CREATED,
)
def create_run(
    engagement_id: UUID,
    payload: RunCreate,
    session: Session = Depends(get_session),
    actor: str = Depends(get_current_actor),
    settings: Settings = Depends(get_settings),
) -> RunRead:
    ensure_default_run_profiles(session)

    engagement = session.scalar(select(Engagement).where(Engagement.id == engagement_id))
    if engagement is None:
        raise HTTPException(status_code=404, detail="engagement not found")

    scope = session.scalar(latest_scope_query(engagement.id))
    if scope is None:
        raise HTTPException(status_code=400, detail="engagement scope required before requesting runs")

    profile = session.scalar(select(RunProfile).where(RunProfile.name == payload.profile_name))
    if profile is None:
        raise HTTPException(status_code=404, detail="run profile not found")

    source_inventory_snapshot_id = payload.source_inventory_snapshot_id
    if source_inventory_snapshot_id is not None:
        inventory_snapshot = session.scalar(
            select(InventorySnapshot).where(
                InventorySnapshot.id == source_inventory_snapshot_id,
                InventorySnapshot.engagement_id == engagement.id,
            )
        )
        if inventory_snapshot is None:
            raise HTTPException(status_code=404, detail="inventory snapshot not found for engagement")

    aligned_configuration = align_run_configuration_with_engagement(
        payload.configuration_json,
        engagement=engagement,
    )
    sanitized_configuration, created_secret_refs = materialize_run_configuration_secrets(
        session,
        engagement_id=engagement.id,
        configuration=aligned_configuration,
        settings=settings,
    )
    timestamp = datetime.now(tz=UTC)

    run = Run(
        engagement_id=engagement.id,
        profile_id=profile.id,
        profile=profile,
        source_inventory_snapshot_id=source_inventory_snapshot_id,
        requested_by=actor,
        status="requested",
        configuration_json=sanitized_configuration,
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
            "bound_pack_id": str(run.bound_pack_id) if run.bound_pack_id else None,
            "bound_pack_version": run.bound_pack_version,
            "secret_binding_count": len(created_secret_refs),
        },
    )

    if required_approvals(profile) == 0:
        queue_run_tasks(session, run, scope, profile)
        write_audit_event(
            session=session,
            actor=actor,
            action="run.queued",
            object_type="run",
            object_id=str(run.id),
            metadata={"engagement_id": str(engagement.id), "profile_name": profile.name},
        )
    else:
        run.status = "pending_approval"

    session.commit()

    hydrated_run = load_run(session, run.id)
    if hydrated_run is None:
        raise HTTPException(status_code=500, detail="run could not be reloaded after creation")
    return serialize_run(hydrated_run)


@router.get("/runs/{run_id}", response_model=RunRead)
def get_run(run_id: UUID, session: Session = Depends(get_session)) -> RunRead:
    run = load_run(session, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="run not found")
    return serialize_run(run)


@router.get("/runs/{run_id}/pack", response_model=RunPackBindingRead)
def get_run_pack_binding(
    run_id: UUID,
    session: Session = Depends(get_session),
) -> RunPackBindingRead:
    run = load_run(session, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="run not found")
    binding = serialize_run_pack_binding(run)
    if binding is None:
        raise HTTPException(status_code=404, detail="no pack bound to run")
    return binding


@router.post("/runs/{run_id}/bind-pack", response_model=RunPackBindingRead)
def bind_pack_for_run(
    run_id: UUID,
    payload: RunPackBindCreate,
    session: Session = Depends(get_session),
    actor: str = Depends(get_current_actor),
) -> RunPackBindingRead:
    run = load_run(session, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="run not found")
    if run.status in {"running", "completed", "completed_with_errors", "failed", "cancelled", "cancelling"}:
        raise HTTPException(status_code=409, detail="run pack binding is locked after execution starts")

    pack = load_pack(session, payload.pack_id)
    if pack is None:
        raise HTTPException(status_code=404, detail="capability pack not found")
    try:
        bind_pack_to_run(session, run=run, pack=pack)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    write_audit_event(
        session=session,
        actor=actor,
        action="run.pack_bound",
        object_type="run",
        object_id=str(run.id),
        metadata={"pack_id": str(pack.id), "pack_version": pack.version},
    )
    session.commit()
    hydrated_run = load_run(session, run.id)
    if hydrated_run is None:
        raise HTTPException(status_code=500, detail="run could not be reloaded after pack binding")
    binding = serialize_run_pack_binding(hydrated_run)
    if binding is None:
        raise HTTPException(status_code=500, detail="pack binding missing after update")
    return binding


@router.get("/runs/{run_id}/report")
def export_run_report(
    run_id: UUID,
    format: str = Query(default="markdown", pattern="^(markdown|html|pdf)$"),
    variant: str = Query(default="technical", pattern="^(executive|technical|evidence|retest)$"),
    session: Session = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> Response:
    run = load_run_report(session, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="run not found")

    if format == "html":
        content = render_html_report(run, variant=variant)
        media_type = "text/html; charset=utf-8"
        extension = "html"
    elif format == "pdf":
        try:
            content = render_pdf_report(run, variant=variant, settings=settings)
        except RuntimeError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        media_type = "application/pdf"
        extension = "pdf"
    else:
        content = render_markdown_report(run, variant=variant)
        media_type = "text/markdown; charset=utf-8"
        extension = "md"

    headers = {"Content-Disposition": f'attachment; filename="aegispt-run-{run_id}-{variant}.{extension}"'}
    return Response(content=content, media_type=media_type, headers=headers)


@router.get("/runs/{run_id}/reports", response_model=list[RunReportCatalogItemRead])
def list_run_reports(
    run_id: UUID,
    session: Session = Depends(get_session),
) -> list[RunReportCatalogItemRead]:
    run = load_run_report(session, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="run not found")
    return build_report_catalog(run)


@router.post("/runs/{run_id}/approvals", response_model=RunRead)
def record_run_approval(
    run_id: UUID,
    payload: ApprovalCreate,
    session: Session = Depends(get_session),
    actor: str = Depends(get_current_actor),
) -> RunRead:
    run = load_run(session, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="run not found")
    if run.profile is None:
        raise HTTPException(status_code=500, detail="run profile relationship not loaded")
    if required_approvals(run.profile) == 0:
        raise HTTPException(status_code=409, detail="run profile does not require approvals")
    if run.status == "rejected":
        raise HTTPException(status_code=409, detail="run already rejected")
    if run.status in {"cancelled", "cancelling"}:
        raise HTTPException(status_code=409, detail="run has been cancelled")

    existing_approval = session.scalar(
        select(Approval).where(
            Approval.run_id == run.id,
            Approval.step_id == payload.step_id,
            Approval.approver_id == actor,
        )
    )
    if existing_approval is not None:
        raise HTTPException(status_code=409, detail="actor already decided this approval step")

    approval = Approval(
        run_id=run.id,
        step_id=payload.step_id,
        approver_id=actor,
        decision=payload.decision,
    )
    session.add(approval)
    session.flush()

    write_audit_event(
        session=session,
        actor=actor,
        action="run.approval.recorded",
        object_type="approval",
        object_id=str(approval.id),
        metadata={"run_id": str(run.id), "decision": payload.decision, "step_id": payload.step_id},
    )

    if payload.decision == "rejected":
        run.status = "rejected"
        write_audit_event(
            session=session,
            actor=actor,
            action="run.rejected",
            object_type="run",
            object_id=str(run.id),
            metadata={"step_id": payload.step_id},
        )
    elif payload.step_id == "run.launch":
        session.refresh(run, attribute_names=["approvals"])
        if pending_approvals(run, run.profile, step_id=payload.step_id) == 0:
            scope = session.scalar(latest_scope_query(run.engagement_id))
            if scope is None:
                raise HTTPException(status_code=409, detail="engagement scope missing during activation")
            queue_run_tasks(session, run, scope, run.profile)
            write_audit_event(
                session=session,
                actor=actor,
                action="run.queued",
                object_type="run",
                object_id=str(run.id),
                metadata={"activated_by": actor, "step_id": payload.step_id},
            )
        else:
            run.status = "pending_approval"

    session.commit()

    hydrated_run = load_run(session, run.id)
    if hydrated_run is None:
        raise HTTPException(status_code=500, detail="run could not be reloaded after approval")
    return serialize_run(hydrated_run)


@router.post("/runs/{run_id}/dispatch", response_model=RunDispatchRead)
def dispatch_run(
    run_id: UUID,
    session: Session = Depends(get_session),
    actor: str = Depends(get_current_actor),
    settings: Settings = Depends(get_settings),
) -> RunDispatchRead:
    run = load_run(session, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="run not found")
    if execution_kill_switch_enabled(settings):
        raise HTTPException(status_code=409, detail="execution kill switch is enabled")
    if run.status in {"cancelled", "cancelling", "rejected"}:
        raise HTTPException(status_code=409, detail="run is not dispatchable")

    queued_tasks = [task for task in sorted_tasks(run) if task.status == "queued"]
    if not queued_tasks:
        raise HTTPException(status_code=409, detail="run has no queued tasks to dispatch")

    unsupported_tools = sorted({task.tool for task in queued_tasks if task.tool not in supported_execution_tools()})
    if unsupported_tools:
        raise HTTPException(
            status_code=409,
            detail=f"queued tasks require unsupported execution tools: {', '.join(unsupported_tools)}",
        )

    dispatch_mode = dispatch_task_batch([task.id for task in queued_tasks], settings)

    write_audit_event(
        session=session,
        actor=actor,
        action="run.dispatched",
        object_type="run",
        object_id=str(run.id),
        metadata={"dispatch_mode": dispatch_mode, "task_count": len(queued_tasks)},
    )
    session.commit()
    session.expire_all()

    hydrated_run = load_run(session, run.id)
    if hydrated_run is None:
        raise HTTPException(status_code=500, detail="run could not be reloaded after dispatch")

    return RunDispatchRead(
        run=serialize_run(hydrated_run),
        dispatch_mode=dispatch_mode,
        dispatched_task_ids=[task.id for task in queued_tasks],
    )


@router.post("/runs/{run_id}/cancel", response_model=RunRead)
def cancel_run(
    run_id: UUID,
    session: Session = Depends(get_session),
    actor: str = Depends(get_current_actor),
) -> RunRead:
    run = load_run(session, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="run not found")

    changed = cancel_run_tasks(run)
    if not changed:
        raise HTTPException(status_code=409, detail="run can no longer be cancelled")

    write_audit_event(
        session=session,
        actor=actor,
        action="run.cancelled",
        object_type="run",
        object_id=str(run.id),
        metadata={"status": run.status},
    )
    session.commit()

    hydrated_run = load_run(session, run.id)
    if hydrated_run is None:
        raise HTTPException(status_code=500, detail="run could not be reloaded after cancellation")
    return serialize_run(hydrated_run)
