from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    HTTPException,
    Query,
    Request,
    Response,
    status,
)
from sqlalchemy import select
from sqlalchemy.orm import Session
from starlette.responses import StreamingResponse

from api.app.auth import require_roles
from api.app.config import Settings, get_settings
from api.app.db import get_session
from api.app.models import (
    Approval,
    AssessmentChain,
    Finding,
    FindingAiEnrichment,
    InventorySnapshot,
    Run,
    RunProfile,
    Task,
)
from api.app.schemas.deletion import DeleteImpactRead, RunBulkDeleteCreate
from api.app.schemas.packs import RunPackBindCreate, RunPackBindingRead
from api.app.schemas.report_center import (
    RunReportCatalogItemRead,
    RunReportDraftCreate,
    RunReportDraftRead,
)
from api.app.schemas.runs import (
    AgentProposalRead,
    AgentProposalReviewCreate,
    AiRepairActionCreate,
    AiRepairActionRead,
    AiRepairProposalCreate,
    AiRepairProposalRead,
    ApprovalCreate,
    ApprovalRead,
    AssessmentLoopAdvanceCreate,
    AssessmentLoopGoalCreate,
    AssessmentLoopRead,
    AssessmentPlanQueueCreate,
    AssessmentPlanQueueRead,
    AssessmentPlanWaveCompleteCreate,
    AssessmentPlanWaveCompleteRead,
    AssessmentChainPhaseDecisionCreate,
    AssessmentChainRead,
    FindingSummaryRead,
    RunAiInsightsRead,
    RunCreate,
    RunCveIntelQueueTestRead,
    RunCveIntelRead,
    RunCveIntelRefreshCreate,
    RunCredentialVaultCreate,
    RunDispatchRead,
    RunDriftRead,
    RunIntakeInterpretationCreate,
    RunIntakeInterpretationRead,
    RunProfileRead,
    RunRead,
    RunStaleRecoveryCreate,
    TaskRead,
    ToolLibraryProposalCreate,
)
from api.app.services.ai_agent import (
    AgentProposalReviewError,
    TOOL_LIBRARY_MANUAL_PROPOSAL_TOOLS,
    build_ai_insights_for_run,
    review_agent_proposal,
)
from api.app.services.ai_enrichment import (
    build_mission_guidance_for_run,
    list_agent_proposals_for_run,
    store_agent_proposal_record,
    store_agent_reasoning_record,
)
from api.app.services.ai_repair_lane import (
    AiRepairLaneError,
    apply_ai_repair_action,
    create_ai_repair_proposal,
)
from api.app.services.ai_signal_stream import stream_run_ai_signal
from api.app.services.assessment_chain import (
    approve_assessment_chain_phase,
    build_assessment_chain_summary,
    continue_assessment_chain_after_blocked_step,
    create_assessment_chain_launch,
    dispatch_assessment_chain_current_run,
    halt_assessment_chain_at_boundary,
    load_assessment_chain,
    normalize_assessment_mode,
)
from api.app.services.assessment_loop import (
    advance_assessment_loop,
    build_assessment_loop_state,
    record_assessment_loop_goal,
)
from api.app.services.assessment_planner import (
    build_assessment_plan_for_run,
    complete_adaptive_execution_wave,
    queue_assessment_plan_tasks,
)
from api.app.services.attack_paths import build_attack_path_summary
from api.app.services.audit import write_audit_event
from api.app.services.intake_intelligence import (
    attach_intake_interpretation_to_configuration,
    build_intake_interpretation,
)
from api.app.services.kill_chain_progress import build_engagement_kill_chain_progress
from api.app.services.multi_agent_orchestration import build_multi_agent_orchestration_readiness
from api.app.services.on_demand_cve_intel import (
    build_run_cve_intelligence,
    queue_targeted_nuclei_task,
    refresh_run_cve_intelligence,
)
from api.app.services.packs import bind_pack_to_run, latest_pack_deployment, load_pack
from api.app.services.report_pdf import render_pdf_report
from api.app.services.reports import (
    build_report_catalog,
    build_report_draft,
    load_run_report,
    report_context_for_run,
    render_html_report,
    render_markdown_report,
)
from api.app.services.remediation_advisor import build_choke_point_remediation_advisor
from api.app.services.run_credential_vault import (
    clear_run_credential_vault_if_terminal,
    run_credential_vault_payload,
    store_run_credential_vault_secret,
)
from api.app.services.run_drift import build_continuous_exposure_drift_report
from api.app.services.run_profiles import ensure_default_run_profiles
from api.app.services.runner_registry import runner_capability_registry
from api.app.services.runs import (
    align_run_configuration_with_engagement,
    approval_step_id,
    cancel_run_tasks,
    dispatch_queued_run_tasks,
    granted_approvals,
    latest_scope_query,
    load_run,
    pending_approvals,
    planned_tools,
    queue_run_tasks,
    recover_stale_run_tasks,
    required_approvals,
    sorted_approvals,
    sorted_findings,
    sorted_tasks,
    stale_run_recovery_state,
    stale_task_recovery_state,
    validate_bloodhound_run_configuration,
    validate_business_logic_run_configuration,
    validate_configured_targets_within_scope,
    validate_crypto_audit_run_configuration,
    validate_credential_attack_run_configuration,
    validate_easm_run_configuration,
    validate_impacket_lateral_run_configuration,
    validate_metasploit_run_configuration,
    validate_netexec_run_configuration,
    validate_playwright_web_run_configuration,
    validate_priv_esc_linux_run_configuration,
    validate_responder_run_configuration,
    validate_ssh_brute_run_configuration,
    validate_wifi_run_configuration,
)
from api.app.services.secrets import (
    materialize_run_configuration_secrets,
    sanitize_run_configuration,
)
from api.app.services.settings import effective_runtime_settings_for_run
from api.app.services.soft_delete import (
    SoftDeleteBlockedError,
    delete_impact_payload,
    run_delete_blocker,
    run_delete_impact,
    soft_delete_runs,
)
from api.app.services.tenancy import (
    assert_run_tenant,
    get_current_tenant_id,
    load_engagement_for_tenant,
)

router = APIRouter(prefix="/api/v1", tags=["runs"])

TERMINAL_RUN_STATUSES = {"completed", "completed_with_errors", "failed", "cancelled", "rejected"}
AUTO_DISPATCH_BLOCKED_TOOLS = {
    "credential-attacks",
    "impacket-lateral",
    "metasploit",
    "netexec",
    "priv-esc-linux",
    "responder",
    "ssh-brute",
}


@router.get("/runners/capabilities")
def list_runner_capabilities(
    _actor: str = Depends(require_roles("operator", "admin")),
) -> dict[str, Any]:
    return runner_capability_registry()
LAUNCH_AUTO_DISPATCH_WEB_TOOLS = {
    "biz-logic-probe",
    "burp",
    "crypto-audit",
    "headers-security",
    "httpx",
    "logging-probe",
    "nuclei",
    "oauth-probe",
    "playwright-web",
    "zap",
}


def _eligible_for_launch_auto_dispatch(run: Run) -> bool:
    profile = run.profile
    if profile is None:
        return False
    configuration = run.configuration_json if isinstance(run.configuration_json, dict) else {}
    runtime_launch = configuration.get("runtime_launch")
    if (
        not isinstance(runtime_launch, dict)
        or runtime_launch.get("dispatch_after_approval") is not True
    ):
        return False
    if str(profile.run_class or "").lower() not in {"passive", "active"}:
        return False
    task_tools = {str(task.tool or "").strip() for task in run.tasks or []}
    if not task_tools:
        return False
    if not task_tools.issubset(LAUNCH_AUTO_DISPATCH_WEB_TOOLS):
        return False
    return not bool(task_tools & AUTO_DISPATCH_BLOCKED_TOOLS)


def _run_target_values(run: Run) -> list[str]:
    values: list[str] = []
    seen: set[str] = set()

    def add(value: object) -> None:
        normalized = str(value or "").strip()
        if not normalized or normalized in seen:
            return
        seen.add(normalized)
        values.append(normalized)

    for task in list(run.tasks or []):
        add(task.target_id)
        params = task.params_json if isinstance(task.params_json, dict) else {}
        targets = params.get("targets")
        if isinstance(targets, list):
            for target in targets:
                add(target)

    configuration = run.configuration_json if isinstance(run.configuration_json, dict) else {}
    target_map = configuration.get("targets")
    if isinstance(target_map, dict):
        for target_value in target_map.values():
            if isinstance(target_value, list):
                for item in target_value:
                    add(item)
            else:
                add(target_value)
    return values


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


def serialize_task(task, *, run: Run | None = None) -> TaskRead:
    return TaskRead(
        id=task.id,
        source_finding_id=task.source_finding_id,
        tool=task.tool,
        target_id=task.target_id,
        status=task.status,
        params_json=dict(task.params_json or {}),
        stale_recovery=stale_task_recovery_state(task, run=run),
        created_at=task.created_at,
        updated_at=task.updated_at,
    )


def serialize_run(run: Run, *, session: Session, include_kill_chain_progress: bool = True) -> RunRead:
    profile = run.profile
    if profile is None:
        raise HTTPException(status_code=500, detail="run profile relationship not loaded")

    chain_summary = build_assessment_chain_summary(run.assessment_chain)
    phase_key = (
        str(
            dict(run.configuration_json or {}).get("assessment_mode", {}).get("phase_key") or ""
        ).strip()
        if isinstance(run.configuration_json, dict)
        else ""
    )
    if run.assessment_chain_id is not None and run.status != "pending_approval":
        required = 0
        approval_gate_step_id = f"assessment-chain:{phase_key or 'phase'}"
        granted = 0
        pending = 0
    else:
        required = required_approvals(profile)
        approval_gate_step_id = approval_step_id(profile)
        granted = granted_approvals(run, profile=profile)
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
        autonomous_mode=bool(run.autonomous_mode),
        autonomous_intrusive_allowed=bool(run.autonomous_intrusive_allowed),
        source_inventory_snapshot_id=run.source_inventory_snapshot_id,
        started_at=run.started_at,
        created_at=run.created_at,
        updated_at=run.updated_at,
        profile=RunProfileRead.model_validate(profile),
        approval_step_id=approval_gate_step_id,
        required_approvals=required,
        granted_approvals=granted,
        pending_approvals=pending,
        approvals=[ApprovalRead.model_validate(approval) for approval in sorted_approvals(run)],
        tasks=[serialize_task(task, run=run) for task in sorted_tasks(run)],
        findings=FindingSummaryRead(
            finding_count=len(findings),
            findings_by_severity=findings_by_severity,
            findings_by_status=findings_by_status,
        ),
        configuration_json=sanitize_run_configuration(dict(run.configuration_json or {})),
        pack_binding=serialize_run_pack_binding(run),
        ai_mission_guidance=build_mission_guidance_for_run(session=session, run=run),
        multi_agent_orchestration=build_multi_agent_orchestration_readiness(run),
        assessment_chain=chain_summary,
        assessment_plan=build_assessment_plan_for_run(session, run),
        kill_chain_progress=(
            build_engagement_kill_chain_progress(session, run.engagement_id)
            if include_kill_chain_progress
            else None
        ),
        drift_summary=(
            RunDriftRead.model_validate(run.drift_summary)
            if run.drift_summary is not None
            else None
        ),
        stale_recovery=stale_run_recovery_state(run),
    )


def _isoformat(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def _run_stream_snapshot(run: Run) -> dict[str, Any]:
    tasks = sorted_tasks(run)
    task_counts: dict[str, int] = {}
    task_payloads: list[dict[str, Any]] = []

    for task in tasks:
        task_counts[task.status] = task_counts.get(task.status, 0) + 1
        task_payloads.append(
            {
                "id": str(task.id),
                "tool": task.tool,
                "target_id": task.target_id,
                "status": task.status,
                "params_json": sanitize_run_configuration(dict(task.params_json or {})),
                "created_at": _isoformat(task.created_at),
                "updated_at": _isoformat(task.updated_at),
            }
        )

    return {
        "run_id": str(run.id),
        "engagement_id": str(run.engagement_id),
        "status": run.status,
        "created_at": _isoformat(run.created_at),
        "updated_at": _isoformat(run.updated_at),
        "started_at": _isoformat(run.started_at),
        "completed_at": _isoformat(getattr(run, "completed_at", None)),
        "task_counts": task_counts,
        "tasks": task_payloads,
        "assessment_chain": build_assessment_chain_summary(run.assessment_chain),
    }


def _run_stream_fingerprint(snapshot: dict[str, Any]) -> str:
    return json.dumps(
        {
            "status": snapshot.get("status"),
            "updated_at": snapshot.get("updated_at"),
            "tasks": [
                {
                    "id": task.get("id"),
                    "status": task.get("status"),
                    "updated_at": task.get("updated_at"),
                }
                for task in snapshot.get("tasks", [])
                if isinstance(task, dict)
            ],
        },
        sort_keys=True,
    )


def _load_finding_enrichment_stream_events(session: Session, run_id: UUID) -> list[dict[str, Any]]:
    rows = session.execute(
        select(FindingAiEnrichment, Finding)
        .join(Finding, FindingAiEnrichment.finding_id == Finding.id)
        .where(Finding.run_id == run_id)
        .order_by(FindingAiEnrichment.updated_at.asc(), FindingAiEnrichment.id.asc())
    ).all()
    events: list[dict[str, Any]] = []
    for enrichment, finding in rows:
        events.append(
            {
                "run_id": str(run_id),
                "finding_id": str(finding.id),
                "finding_title": finding.title,
                "severity": finding.severity,
                "target_id": finding.target_id,
                "status": enrichment.status,
                "provider": enrichment.provider,
                "updated_at": _isoformat(enrichment.updated_at),
                "available": enrichment.status == "succeeded",
            }
        )
    return events


def _finding_enrichment_event_key(event_payload: dict[str, Any]) -> str:
    return "::".join(
        [
            str(event_payload.get("finding_id") or ""),
            str(event_payload.get("status") or ""),
            str(event_payload.get("updated_at") or ""),
        ]
    )


def _format_sse_event(event: str, payload: dict[str, Any]) -> str:
    data = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return f"event: {event}\ndata: {data}\n\n"


def _load_run_stream_snapshot(session: Session, run_id: UUID) -> dict[str, Any] | None:
    run = load_run(session, run_id)
    if run is None:
        return None
    return _run_stream_snapshot(run)


def _load_run_for_tenant(session: Session, run_id: UUID, tenant_id: str | None) -> Run:
    run = load_run(session, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="run not found")
    assert_run_tenant(run, tenant_id)
    return run


def _load_run_report_for_tenant(session: Session, run_id: UUID, tenant_id: str | None) -> Run:
    run = load_run_report(session, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="run not found")
    assert_run_tenant(run, tenant_id)
    return run


def _load_assessment_chain_for_tenant(
    session: Session,
    chain_id: UUID,
    tenant_id: str | None,
) -> AssessmentChain:
    chain = load_assessment_chain(session, chain_id)
    if chain is None:
        raise HTTPException(status_code=404, detail="assessment chain not found")
    if chain.engagement is None:
        raise HTTPException(status_code=500, detail="assessment chain engagement not loaded")
    if tenant_id is not None and chain.engagement.tenant_id != tenant_id:
        raise HTTPException(status_code=404, detail="assessment chain not found")
    return chain


@router.get("/run-profiles", response_model=list[RunProfileRead])
def list_run_profiles(session: Session = Depends(get_session)) -> list[RunProfileRead]:
    changed = ensure_default_run_profiles(session)
    if changed:
        session.commit()
    profiles = session.scalars(select(RunProfile).order_by(RunProfile.name)).all()
    return [RunProfileRead.model_validate(profile) for profile in profiles]


@router.post("/intake/interpretation", response_model=RunIntakeInterpretationRead)
def interpret_intake_answer(
    payload: RunIntakeInterpretationCreate,
    session: Session = Depends(get_session),
    settings: Settings = Depends(get_settings),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> RunIntakeInterpretationRead:
    if payload.engagement_id is not None:
        load_engagement_for_tenant(session, payload.engagement_id, tenant_id)
    interpretation = build_intake_interpretation(
        question_id=payload.question_id,
        answer=payload.answer,
        configuration_json=payload.configuration_json,
        settings=settings,
        tenant_id=tenant_id,
        session=session,
        engagement_id=payload.engagement_id,
    )
    return RunIntakeInterpretationRead.model_validate(interpretation)


@router.get("/engagements/{engagement_id}/runs", response_model=list[RunRead])
def list_engagement_runs(
    engagement_id: UUID,
    session: Session = Depends(get_session),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> list[RunRead]:
    load_engagement_for_tenant(session, engagement_id, tenant_id)
    runs = session.scalars(
        select(Run)
        .where(Run.engagement_id == engagement_id, Run.deleted_at.is_(None))
        .order_by(Run.created_at.desc(), Run.id.desc())
    ).all()
    hydrated_runs = [load_run(session, run.id) for run in runs]
    return [
        serialize_run(run, session=session, include_kill_chain_progress=False)
        for run in hydrated_runs
        if run is not None
    ]


@router.post(
    "/engagements/{engagement_id}/runs",
    response_model=RunRead,
    status_code=status.HTTP_201_CREATED,
)
def create_run(
    engagement_id: UUID,
    payload: RunCreate,
    background_tasks: BackgroundTasks,
    session: Session = Depends(get_session),
    actor: str = Depends(require_roles("operator", "admin")),
    settings: Settings = Depends(get_settings),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> RunRead:
    ensure_default_run_profiles(session)

    engagement = load_engagement_for_tenant(session, engagement_id, tenant_id)
    if not str(engagement.roe_ref or "").strip() and engagement.authorization_confirmed_at is None:
        raise HTTPException(
            status_code=400,
            detail=(
                "Written authorization is required before starting a scan. "
                f"Set roe_ref or confirm authorization via PATCH "
                f"/api/v1/engagements/{engagement.id}/confirm-authorization"
            ),
        )

    scope = session.scalar(latest_scope_query(engagement.id))
    if scope is None:
        raise HTTPException(
            status_code=400, detail="engagement scope required before requesting runs"
        )

    source_inventory_snapshot_id = payload.source_inventory_snapshot_id
    if source_inventory_snapshot_id is not None:
        inventory_snapshot = session.scalar(
            select(InventorySnapshot).where(
                InventorySnapshot.id == source_inventory_snapshot_id,
                InventorySnapshot.engagement_id == engagement.id,
            )
        )
        if inventory_snapshot is None:
            raise HTTPException(
                status_code=404, detail="inventory snapshot not found for engagement"
            )

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
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    sanitized_configuration = attach_intake_interpretation_to_configuration(
        sanitized_configuration,
        settings=settings,
        tenant_id=engagement.tenant_id,
        session=session,
        engagement_id=engagement.id,
    )
    try:
        validate_configured_targets_within_scope(scope, sanitized_configuration)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if payload.assessment_mode is not None:
        try:
            normalize_assessment_mode(payload.assessment_mode)
            run = create_assessment_chain_launch(
                session,
                engagement=engagement,
                actor=actor,
                settings=settings,
                assessment_mode=payload.assessment_mode,
                auto_advance_on_phase_complete=(
                    True
                    if payload.assessment_auto_advance_on_phase_complete is None
                    else bool(payload.assessment_auto_advance_on_phase_complete)
                ),
                configuration_json=sanitized_configuration,
            )
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        session.commit()
        if payload.dispatch_after_create:
            dispatch_assessment_chain_current_run(
                session,
                chain_id=run.assessment_chain_id,
                actor=actor,
                settings=settings,
                background_tasks=background_tasks,
            )
            session.commit()
        hydrated_run = None
        if run.assessment_chain_id is not None:
            hydrated_chain = load_assessment_chain(session, run.assessment_chain_id)
            if hydrated_chain is not None and hydrated_chain.current_run_id is not None:
                hydrated_run = load_run(session, hydrated_chain.current_run_id)
            elif hydrated_chain is not None and hydrated_chain.last_completed_run_id is not None:
                hydrated_run = load_run(session, hydrated_chain.last_completed_run_id)
        if hydrated_run is None:
            hydrated_run = load_run(session, run.id)
        if hydrated_run is None:
            raise HTTPException(
                status_code=500, detail="assessment chain run could not be reloaded"
            )
        return serialize_run(hydrated_run, session=session)

    profile = session.scalar(select(RunProfile).where(RunProfile.name == payload.profile_name))
    if profile is None:
        raise HTTPException(status_code=404, detail="run profile not found")
    profile_limits = dict(profile.limits_json or {})
    autonomous_mode = (
        payload.autonomous_mode
        if payload.autonomous_mode is not None
        else bool(profile_limits.get("autonomous_mode_default"))
    )
    autonomous_intrusive_allowed = bool(payload.autonomous_intrusive_allowed or False)
    try:
        if "biz-logic-probe" in planned_tools(profile):
            validate_business_logic_run_configuration(
                scope=scope,
                configuration=sanitized_configuration,
            )
        if "crypto-audit" in planned_tools(profile):
            validate_crypto_audit_run_configuration(
                scope=scope,
                configuration=sanitized_configuration,
            )
        if "bloodhound-collect" in planned_tools(profile):
            validate_bloodhound_run_configuration(
                scope=scope,
                configuration=sanitized_configuration,
            )
        if "impacket-lateral" in planned_tools(profile):
            validate_impacket_lateral_run_configuration(
                scope=scope,
                configuration=sanitized_configuration,
                mode=str(profile_limits.get("impacket_mode") or ""),
            )
        if "metasploit" in planned_tools(profile):
            validate_metasploit_run_configuration(
                session,
                engagement_id=engagement.id,
                scope=scope,
                configuration=sanitized_configuration,
            )
        if "credential-attacks" in planned_tools(profile):
            validate_credential_attack_run_configuration(
                session,
                engagement_id=engagement.id,
                scope=scope,
                configuration=sanitized_configuration,
                source_inventory_snapshot_id=source_inventory_snapshot_id,
                mode=str(profile_limits.get("credential_attack_mode") or ""),
            )
        if "netexec" in planned_tools(profile):
            validate_netexec_run_configuration(
                scope=scope,
                configuration=sanitized_configuration,
                intrusive=profile.run_class == "intrusive",
            )
        if "priv-esc-linux" in planned_tools(profile):
            validate_priv_esc_linux_run_configuration(
                scope=scope,
                configuration=sanitized_configuration,
            )
        if "responder" in planned_tools(profile):
            validate_responder_run_configuration(
                scope=scope,
                configuration=sanitized_configuration,
            )
        if "ssh-brute" in planned_tools(profile):
            validate_ssh_brute_run_configuration(
                scope=scope,
                configuration=sanitized_configuration,
            )
        if "wifi-survey" in planned_tools(profile):
            validate_wifi_run_configuration(
                scope=scope,
                configuration=sanitized_configuration,
            )
        if "easm-discover" in planned_tools(profile):
            validate_easm_run_configuration(
                scope=scope,
                configuration=sanitized_configuration,
            )
        if "playwright-web" in planned_tools(profile):
            validate_playwright_web_run_configuration(
                scope=scope,
                configuration=sanitized_configuration,
                profile_limits=profile_limits,
            )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    timestamp = datetime.now(tz=UTC)
    if payload.dispatch_after_create and required_approvals(profile) > 0:
        sanitized_configuration = {
            **dict(sanitized_configuration or {}),
            "runtime_launch": {
                **dict(sanitized_configuration.get("runtime_launch") or {}),
                "dispatch_after_approval": True,
            },
        }

    run = Run(
        engagement_id=engagement.id,
        profile_id=profile.id,
        profile=profile,
        source_inventory_snapshot_id=source_inventory_snapshot_id,
        requested_by=actor,
        status="requested",
        configuration_json=sanitized_configuration,
        autonomous_mode=autonomous_mode,
        autonomous_intrusive_allowed=autonomous_intrusive_allowed,
        created_at=timestamp,
        updated_at=timestamp,
    )
    session.add(run)
    session.flush()

    deployment = latest_pack_deployment(
        session, engagement_id=engagement.id, run_profile_name=profile.name
    )
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
            "autonomous_mode": autonomous_mode,
            "autonomous_intrusive_allowed": autonomous_intrusive_allowed,
        },
    )

    if required_approvals(profile) == 0:
        try:
            queue_run_tasks(session, run, scope, profile)
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
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

    if payload.dispatch_after_create:
        hydrated_for_dispatch = load_run(session, run.id)
        if hydrated_for_dispatch is not None and hydrated_for_dispatch.status == "queued":
            effective_settings = effective_runtime_settings_for_run(
                session,
                run=hydrated_for_dispatch,
                settings=settings,
            )
            inline_background_tasks = (
                background_tasks if effective_settings.inline_dispatch_background else None
            )
            try:
                dispatch_queued_run_tasks(
                    session,
                    run=hydrated_for_dispatch,
                    actor=actor,
                    settings=effective_settings,
                    background_tasks=inline_background_tasks,
                )
            except ValueError as exc:
                raise HTTPException(status_code=409, detail=str(exc)) from exc
            session.commit()

    hydrated_run = load_run(session, run.id)
    if hydrated_run is None:
        raise HTTPException(status_code=500, detail="run could not be reloaded after creation")
    return serialize_run(hydrated_run, session=session)


@router.delete("/runs", response_model=DeleteImpactRead)
def delete_runs_bulk(
    payload: RunBulkDeleteCreate,
    dry_run: bool = Query(default=False),
    session: Session = Depends(get_session),
    actor: str = Depends(require_roles("admin")),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> DeleteImpactRead:
    unique_run_ids = list(dict.fromkeys(payload.run_ids))
    runs = [_load_run_for_tenant(session, run_id, tenant_id) for run_id in unique_run_ids]
    blocked_reason = next(
        (run_delete_blocker(run) for run in runs if run_delete_blocker(run)), None
    )
    counts = run_delete_impact(session, unique_run_ids)
    if dry_run:
        return DeleteImpactRead.model_validate(
            delete_impact_payload(
                object_type="runs",
                object_ids=unique_run_ids,
                counts=counts,
                dry_run=True,
                blocked_reason=blocked_reason,
            )
        )
    if blocked_reason:
        raise HTTPException(status_code=409, detail=blocked_reason)
    try:
        result = soft_delete_runs(session=session, runs=runs, actor=actor)
    except SoftDeleteBlockedError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    session.commit()
    return DeleteImpactRead.model_validate(result)


@router.delete("/runs/{run_id}", response_model=DeleteImpactRead)
def delete_run(
    run_id: UUID,
    dry_run: bool = Query(default=False),
    session: Session = Depends(get_session),
    actor: str = Depends(require_roles("admin")),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> DeleteImpactRead:
    run = _load_run_for_tenant(session, run_id, tenant_id)
    blocked_reason = run_delete_blocker(run)
    counts = run_delete_impact(session, [run.id])
    if dry_run:
        return DeleteImpactRead.model_validate(
            delete_impact_payload(
                object_type="run",
                object_id=run.id,
                counts=counts,
                dry_run=True,
                blocked_reason=blocked_reason,
            )
        )
    if blocked_reason:
        raise HTTPException(status_code=409, detail=blocked_reason)
    try:
        result = soft_delete_runs(session=session, runs=[run], actor=actor)
    except SoftDeleteBlockedError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    session.commit()
    return DeleteImpactRead.model_validate(result)


@router.get("/assessment-chains/{chain_id}", response_model=AssessmentChainRead)
def get_assessment_chain(
    chain_id: UUID,
    session: Session = Depends(get_session),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> AssessmentChainRead:
    chain = _load_assessment_chain_for_tenant(session, chain_id, tenant_id)
    return AssessmentChainRead.model_validate(build_assessment_chain_summary(chain))


@router.get("/assessment-chains/{chain_id}/tasks", response_model=list[TaskRead])
def list_assessment_chain_tasks(
    chain_id: UUID,
    session: Session = Depends(get_session),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> list[TaskRead]:
    chain = _load_assessment_chain_for_tenant(session, chain_id, tenant_id)
    runs = session.scalars(
        select(Run)
        .where(Run.assessment_chain_id == chain.id, Run.deleted_at.is_(None))
        .order_by(Run.created_at.asc(), Run.id.asc())
    ).all()
    tasks = session.scalars(
        select(Task)
        .join(Run, Task.run_id == Run.id)
        .where(Run.assessment_chain_id == chain.id, Run.deleted_at.is_(None))
        .order_by(Task.created_at.asc(), Task.id.asc())
    ).all()
    runs_by_id = {run.id: run for run in runs}
    return [serialize_task(task, run=runs_by_id.get(task.run_id)) for task in tasks]


@router.post(
    "/assessment-chains/{chain_id}/phases/{phase_key}/decision", response_model=AssessmentChainRead
)
def decide_assessment_chain_phase(
    chain_id: UUID,
    phase_key: str,
    payload: AssessmentChainPhaseDecisionCreate,
    session: Session = Depends(get_session),
    actor: str = Depends(require_roles("operator", "admin")),
    settings: Settings = Depends(get_settings),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> AssessmentChainRead:
    chain = _load_assessment_chain_for_tenant(session, chain_id, tenant_id)
    try:
        _ = approve_assessment_chain_phase(
            session,
            chain=chain,
            phase_key=phase_key,
            actor=actor,
            settings=settings,
            decision=payload.decision,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    session.commit()
    if payload.decision == "approved":
        dispatch_assessment_chain_current_run(
            session,
            chain_id=chain.id,
            actor=actor,
            settings=settings,
        )
        session.commit()
    hydrated_chain = load_assessment_chain(session, chain.id)
    if hydrated_chain is None:
        raise HTTPException(status_code=500, detail="assessment chain missing after update")
    return AssessmentChainRead.model_validate(build_assessment_chain_summary(hydrated_chain))


@router.post("/assessment-chains/{chain_id}/halt", response_model=AssessmentChainRead)
def halt_assessment_chain(
    chain_id: UUID,
    session: Session = Depends(get_session),
    actor: str = Depends(require_roles("operator", "admin")),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> AssessmentChainRead:
    chain = _load_assessment_chain_for_tenant(session, chain_id, tenant_id)
    try:
        updated_chain = halt_assessment_chain_at_boundary(
            session,
            chain=chain,
            actor=actor,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    session.commit()
    hydrated_chain = load_assessment_chain(session, chain.id)
    if hydrated_chain is None:
        raise HTTPException(status_code=500, detail="assessment chain missing after halt")
    return AssessmentChainRead.model_validate(
        build_assessment_chain_summary(updated_chain or hydrated_chain)
    )


@router.post("/assessment-chains/{chain_id}/continue", response_model=AssessmentChainRead)
def continue_blocked_assessment_chain(
    chain_id: UUID,
    session: Session = Depends(get_session),
    actor: str = Depends(require_roles("operator", "admin")),
    settings: Settings = Depends(get_settings),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> AssessmentChainRead:
    chain = _load_assessment_chain_for_tenant(session, chain_id, tenant_id)
    try:
        updated_chain = continue_assessment_chain_after_blocked_step(
            session,
            chain=chain,
            actor=actor,
            settings=settings,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    session.commit()
    if updated_chain.current_run_id is not None:
        dispatch_assessment_chain_current_run(
            session,
            chain_id=chain.id,
            actor=actor,
            settings=settings,
        )
        session.commit()
    hydrated_chain = load_assessment_chain(session, chain.id)
    if hydrated_chain is None:
        raise HTTPException(status_code=500, detail="assessment chain missing after continue")
    return AssessmentChainRead.model_validate(
        build_assessment_chain_summary(updated_chain or hydrated_chain)
    )


@router.get("/runs/{run_id}", response_model=RunRead)
def get_run(
    run_id: UUID,
    session: Session = Depends(get_session),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> RunRead:
    run = _load_run_for_tenant(session, run_id, tenant_id)
    return serialize_run(run, session=session)


@router.get("/runs/{run_id}/continuous-exposure-drift")
def get_run_continuous_exposure_drift(
    run_id: UUID,
    session: Session = Depends(get_session),
    _actor: str = Depends(require_roles("operator", "admin")),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> dict[str, Any]:
    _load_run_for_tenant(session, run_id, tenant_id)
    return build_continuous_exposure_drift_report(session, run_id=run_id)


@router.get("/runs/{run_id}/assessment-plan")
def get_run_assessment_plan(
    run_id: UUID,
    session: Session = Depends(get_session),
    _actor: str = Depends(require_roles("operator", "admin")),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> dict[str, Any]:
    run = _load_run_for_tenant(session, run_id, tenant_id)
    return build_assessment_plan_for_run(session, run)


@router.post("/runs/{run_id}/assessment-plan/queue", response_model=AssessmentPlanQueueRead)
def queue_run_assessment_plan(
    run_id: UUID,
    payload: AssessmentPlanQueueCreate,
    session: Session = Depends(get_session),
    actor: str = Depends(require_roles("operator", "admin")),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> AssessmentPlanQueueRead:
    run = _load_run_for_tenant(session, run_id, tenant_id)
    scope = session.scalar(latest_scope_query(run.engagement_id))
    if scope is None:
        raise HTTPException(status_code=409, detail="engagement scope missing during plan launch")
    try:
        outcome = queue_assessment_plan_tasks(
            session,
            run=run,
            scope=scope,
            approved_runners=payload.approved_runners,
            actor=actor,
            allow_wait_overrides=payload.allow_wait_overrides,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if payload.operator_note:
        write_audit_event(
            session=session,
            actor=actor,
            action="assessment_plan.operator_note",
            object_type="run",
            object_id=str(run.id),
            metadata={"note": payload.operator_note},
        )
    session.commit()
    hydrated_run = load_run(session, run.id)
    if hydrated_run is None:
        raise HTTPException(status_code=500, detail="run could not be reloaded after plan queue")
    queued_tasks = outcome.get("queued_tasks") or []
    return AssessmentPlanQueueRead(
        run=serialize_run(hydrated_run, session=session),
        assessment_plan=build_assessment_plan_for_run(session, hydrated_run),
        queued_task_ids=[task.id for task in queued_tasks],
        blocked=list(outcome.get("blocked") or []),
    )


@router.post("/runs/{run_id}/assessment-plan/waves/complete", response_model=AssessmentPlanWaveCompleteRead)
def complete_run_assessment_plan_wave(
    run_id: UUID,
    payload: AssessmentPlanWaveCompleteCreate,
    session: Session = Depends(get_session),
    actor: str = Depends(require_roles("operator", "admin")),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> AssessmentPlanWaveCompleteRead:
    run = _load_run_for_tenant(session, run_id, tenant_id)
    try:
        outcome = complete_adaptive_execution_wave(
            session,
            run=run,
            actor=actor,
            operator_note=payload.operator_note,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    session.commit()
    hydrated_run = load_run(session, run.id)
    if hydrated_run is None:
        raise HTTPException(status_code=500, detail="run could not be reloaded after adaptive wave completion")
    return AssessmentPlanWaveCompleteRead(
        run=serialize_run(hydrated_run, session=session),
        assessment_plan=build_assessment_plan_for_run(session, hydrated_run),
        adaptive_execution_waves=dict(outcome.get("adaptive_execution_waves") or {}),
        proposal_ids=[UUID(str(item)) for item in list(outcome.get("proposal_ids") or [])],
        reasoning_id=UUID(str(outcome["reasoning_id"])) if outcome.get("reasoning_id") else None,
    )


@router.get("/runs/{run_id}/assessment-loop", response_model=AssessmentLoopRead)
def get_run_assessment_loop(
    run_id: UUID,
    session: Session = Depends(get_session),
    _actor: str = Depends(require_roles("operator", "admin")),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> AssessmentLoopRead:
    run = _load_run_for_tenant(session, run_id, tenant_id)
    scope = session.scalar(latest_scope_query(run.engagement_id))
    if scope is None:
        raise HTTPException(status_code=409, detail="engagement scope missing during assessment loop")
    return AssessmentLoopRead.model_validate(
        build_assessment_loop_state(session=session, run=run, scope=scope)
    )


@router.post("/runs/{run_id}/assessment-loop/goal", response_model=AssessmentLoopRead)
def record_run_assessment_loop_goal(
    run_id: UUID,
    payload: AssessmentLoopGoalCreate,
    session: Session = Depends(get_session),
    actor: str = Depends(require_roles("operator", "admin")),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> AssessmentLoopRead:
    run = _load_run_for_tenant(session, run_id, tenant_id)
    scope = session.scalar(latest_scope_query(run.engagement_id))
    if scope is None:
        raise HTTPException(status_code=409, detail="engagement scope missing during assessment loop")
    try:
        outcome = record_assessment_loop_goal(
            session=session,
            run=run,
            scope=scope,
            actor=actor,
            objective=payload.objective,
            operator_note=payload.operator_note,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    session.commit()
    hydrated_run = load_run(session, run.id)
    if hydrated_run is None:
        raise HTTPException(status_code=500, detail="run could not be reloaded after assessment loop goal update")
    hydrated_scope = session.scalar(latest_scope_query(hydrated_run.engagement_id))
    if hydrated_scope is None:
        raise HTTPException(status_code=409, detail="engagement scope missing during assessment loop")
    return AssessmentLoopRead.model_validate(
        {
            **build_assessment_loop_state(session=session, run=hydrated_run, scope=hydrated_scope),
            "goal_oriented_reasoning": outcome.get("goal_oriented_reasoning", {}),
        }
    )


@router.get("/runs/{run_id}/credential-vault")
def get_run_credential_vault(
    run_id: UUID,
    session: Session = Depends(get_session),
    _actor: str = Depends(require_roles("operator", "admin")),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> dict[str, Any]:
    run = _load_run_for_tenant(session, run_id, tenant_id)
    return run_credential_vault_payload(session, run=run)


@router.post("/runs/{run_id}/credential-vault", status_code=status.HTTP_201_CREATED)
def create_run_credential_vault_entry(
    run_id: UUID,
    payload: RunCredentialVaultCreate,
    session: Session = Depends(get_session),
    actor: str = Depends(require_roles("operator", "admin")),
    settings: Settings = Depends(get_settings),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> dict[str, Any]:
    run = _load_run_for_tenant(session, run_id, tenant_id)
    try:
        store_run_credential_vault_secret(
            session,
            run=run,
            settings=settings,
            secret_kind=payload.secret_kind,
            value=payload.value,
            label=payload.label,
            source_task_id=str(payload.source_task_id) if payload.source_task_id else None,
            source_finding_id=str(payload.source_finding_id) if payload.source_finding_id else None,
            target=payload.target,
            username=payload.username,
            actor=actor,
            discovery_source=payload.discovery_source,
            source_tool="ai_loop",
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    session.commit()
    hydrated_run = load_run(session, run.id)
    if hydrated_run is None:
        raise HTTPException(status_code=500, detail="run could not be reloaded after vault update")
    return run_credential_vault_payload(session, run=hydrated_run)


@router.post("/runs/{run_id}/assessment-loop/iterate", response_model=AssessmentLoopRead)
def advance_run_assessment_loop(
    run_id: UUID,
    payload: AssessmentLoopAdvanceCreate,
    session: Session = Depends(get_session),
    actor: str = Depends(require_roles("operator", "admin")),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> AssessmentLoopRead:
    run = _load_run_for_tenant(session, run_id, tenant_id)
    scope = session.scalar(latest_scope_query(run.engagement_id))
    if scope is None:
        raise HTTPException(status_code=409, detail="engagement scope missing during assessment loop")
    try:
        outcome = advance_assessment_loop(
            session=session,
            run=run,
            scope=scope,
            actor=actor,
            operator_note=payload.operator_note,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    session.commit()
    hydrated_run = load_run(session, run.id)
    if hydrated_run is None:
        raise HTTPException(status_code=500, detail="run could not be reloaded after assessment loop iteration")
    hydrated_scope = session.scalar(latest_scope_query(hydrated_run.engagement_id))
    if hydrated_scope is None:
        raise HTTPException(status_code=409, detail="engagement scope missing during assessment loop")
    response = {
        **build_assessment_loop_state(session=session, run=hydrated_run, scope=hydrated_scope),
        "next_action": outcome.get("next_action"),
        "queued_task_id": outcome.get("queued_task_id"),
        "proposal_id": outcome.get("proposal_id"),
        "reasoning_id": outcome.get("reasoning_id"),
        "context_document_id": outcome.get("context_document_id"),
        "rationale_ledger_entry_id": outcome.get("rationale_ledger_entry_id"),
    }
    return AssessmentLoopRead.model_validate(response)


@router.get("/runs/{run_id}/cve-intelligence", response_model=RunCveIntelRead)
def get_run_cve_intelligence(
    run_id: UUID,
    refresh: bool = Query(default=False),
    live_nvd_lookup: bool = Query(default=False),
    session: Session = Depends(get_session),
    settings: Settings = Depends(get_settings),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> RunCveIntelRead:
    run = _load_run_for_tenant(session, run_id, tenant_id)
    cached = (
        dict(run.configuration_json or {}).get("on_demand_cve_intelligence")
        if isinstance(run.configuration_json, dict)
        else None
    )
    if isinstance(cached, dict) and not refresh and not live_nvd_lookup:
        return RunCveIntelRead.model_validate(cached)
    payload = build_run_cve_intelligence(
        session,
        run=run,
        settings=settings,
        allow_live_nvd=live_nvd_lookup,
    )
    return RunCveIntelRead.model_validate(payload)


@router.post("/runs/{run_id}/cve-intelligence/refresh", response_model=RunCveIntelRead)
def refresh_cve_intelligence_for_run(
    run_id: UUID,
    payload: RunCveIntelRefreshCreate,
    session: Session = Depends(get_session),
    actor: str = Depends(require_roles("operator", "admin")),
    settings: Settings = Depends(get_settings),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> RunCveIntelRead:
    run = _load_run_for_tenant(session, run_id, tenant_id)
    result = refresh_run_cve_intelligence(
        session,
        run=run,
        actor=actor,
        settings=settings,
        allow_live_nvd=payload.live_nvd_lookup,
    )
    session.commit()
    return RunCveIntelRead.model_validate(result)


@router.post(
    "/runs/{run_id}/cve-intelligence/{cve_id}/queue-test", response_model=RunCveIntelQueueTestRead
)
def queue_cve_intelligence_test(
    run_id: UUID,
    cve_id: str,
    session: Session = Depends(get_session),
    actor: str = Depends(require_roles("operator", "admin")),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> RunCveIntelQueueTestRead:
    run = _load_run_for_tenant(session, run_id, tenant_id)
    try:
        task = queue_targeted_nuclei_task(session, run=run, cve_id=cve_id, actor=actor)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    result = refresh_run_cve_intelligence(
        session,
        run=run,
        actor=actor,
        allow_live_nvd=False,
    )
    session.commit()
    hydrated_run = load_run(session, run.id)
    if hydrated_run is None:
        raise HTTPException(
            status_code=500, detail="run could not be reloaded after CVE test queueing"
        )
    hydrated_task = next(
        (candidate for candidate in hydrated_run.tasks if str(candidate.id) == str(task.id)),
        task,
    )
    return RunCveIntelQueueTestRead(
        run=serialize_run(hydrated_run, session=session),
        task=serialize_task(hydrated_task, run=hydrated_run),
        cve_intelligence=RunCveIntelRead.model_validate(result),
    )


@router.get("/runs/{run_id}/ai-insights", response_model=RunAiInsightsRead)
def get_run_ai_insights(
    run_id: UUID,
    session: Session = Depends(get_session),
    settings: Settings = Depends(get_settings),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> RunAiInsightsRead:
    run = _load_run_for_tenant(session, run_id, tenant_id)
    return RunAiInsightsRead.model_validate(
        build_ai_insights_for_run(session=session, run=run, settings=settings)
    )


@router.get(
    "/engagements/{engagement_id}/runs/{run_id}/ai-proposals",
    response_model=list[AgentProposalRead],
)
def list_run_ai_proposals_for_engagement(
    engagement_id: UUID,
    run_id: UUID,
    session: Session = Depends(get_session),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> list[AgentProposalRead]:
    load_engagement_for_tenant(session, engagement_id, tenant_id)
    run = _load_run_for_tenant(session, run_id, tenant_id)
    if run.engagement_id != engagement_id:
        raise HTTPException(status_code=404, detail="run not found for engagement")
    proposals = list_agent_proposals_for_run(session=session, run_id=run.id)
    return [AgentProposalRead.model_validate(proposal) for proposal in proposals]


@router.get("/runs/{run_id}/ai-signal/stream")
def stream_run_ai_signal_endpoint(
    run_id: UUID,
    task_id: UUID | None = Query(default=None),
    session: Session = Depends(get_session),
    settings: Settings = Depends(get_settings),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> StreamingResponse:
    run = _load_run_for_tenant(session, run_id, tenant_id)

    def event_stream():
        for message in stream_run_ai_signal(
            session=session, run=run, settings=settings, task_id=task_id
        ):
            yield _format_sse_event(str(message["event"]), dict(message["data"]))

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.post("/runs/{run_id}/tasks/{task_id}/ai-repair", response_model=AiRepairProposalRead)
def create_run_task_ai_repair(
    run_id: UUID,
    task_id: UUID,
    payload: AiRepairProposalCreate,
    session: Session = Depends(get_session),
    actor: str = Depends(require_roles("operator", "admin")),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> AiRepairProposalRead:
    run = _load_run_for_tenant(session, run_id, tenant_id)
    try:
        outcome = create_ai_repair_proposal(
            session=session,
            run=run,
            task_id=task_id,
            actor=actor,
            note=payload.note,
        )
    except AiRepairLaneError as exc:
        if exc.reason == "not_found":
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    session.commit()
    session.refresh(outcome.reasoning)
    session.refresh(outcome.proposal)
    return AiRepairProposalRead(
        run_id=run.id,
        task_id=task_id,
        reasoning=outcome.reasoning,
        proposal=outcome.proposal,
        boundary=outcome.boundary,
    )


@router.post("/runs/{run_id}/tool-proposals", response_model=AgentProposalRead)
def create_run_tool_library_proposal(
    run_id: UUID,
    payload: ToolLibraryProposalCreate,
    session: Session = Depends(get_session),
    actor: str = Depends(require_roles("operator", "admin")),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> AgentProposalRead:
    run = _load_run_for_tenant(session, run_id, tenant_id)
    proposed_tool = str(payload.proposed_tool or "").strip()
    tool_id = str(payload.tool_id or "").strip()
    if proposed_tool not in TOOL_LIBRARY_MANUAL_PROPOSAL_TOOLS:
        raise HTTPException(
            status_code=422, detail=f"Unsupported Tool Library proposal tool: {proposed_tool}"
        )

    allowed_targets = _run_target_values(run)
    target = str(payload.proposed_target or "").strip() or (
        allowed_targets[0] if allowed_targets else ""
    )
    if not target:
        raise HTTPException(
            status_code=409, detail="Current run has no recorded target for a manual tool proposal"
        )
    if target not in allowed_targets:
        raise HTTPException(
            status_code=409,
            detail="Manual tool proposal target must already belong to the current run",
        )

    matched_task = next(
        (task for task in list(run.tasks or []) if str(task.target_id or "").strip() == target),
        None,
    )
    proposed_params = dict(payload.proposed_params or {})
    proposed_params.setdefault("proposal_source", "tool_library")
    proposed_params.setdefault("selected_catalog_tool_id", tool_id or proposed_tool)

    reasoning = store_agent_reasoning_record(
        session=session,
        run=run,
        task=matched_task,
        reasoning_type="tool_library_manual_task",
        status="recorded",
        context_snapshot={
            "run_id": str(run.id),
            "selected_catalog_tool_id": tool_id or proposed_tool,
            "proposed_tool": proposed_tool,
            "proposed_target": target,
            "source": "operator_tool_library",
            "dispatches_work": False,
            "creates_tasks": False,
        },
        observations=[
            {
                "summary": "Operator selected an existing Tool Library capability for manual review.",
                "tool_id": tool_id or proposed_tool,
                "proposed_tool": proposed_tool,
            }
        ],
        hypotheses=[],
        proposals=[
            {
                "proposed_tool": proposed_tool,
                "proposed_target": target,
                "risk_tier": payload.risk_tier,
                "source": "tool_library",
            }
        ],
        provider="tool-library",
        model=None,
        llm_tokens_used=0,
        confidence_score=1.0,
        metadata={
            "proposal_kind": "tool_library_manual_task",
            "actor": actor,
            "dispatches_work": False,
            "creates_tasks": False,
            "grants_approval": False,
            "active_runtime_mutated": False,
            "operator_controlled_flow_only": True,
        },
    )
    proposal = store_agent_proposal_record(
        session=session,
        reasoning=reasoning,
        proposed_tool=proposed_tool,
        proposed_target=target,
        proposed_params=proposed_params,
        reasoning_text=(
            payload.reasoning_text
            or "Manual Tool Library proposal created for operator review; it does not queue or dispatch work."
        ),
        risk_tier=payload.risk_tier,
        priority=75,
        confidence_score=1.0,
        status="pending_review",
        metadata={
            "proposal_kind": "tool_library_manual_task",
            "catalog_tool_id": tool_id or proposed_tool,
            "created_by": actor,
            "requires_operator_review": True,
            "dispatches_work": False,
            "creates_tasks": False,
            "grants_approval": False,
            "active_runtime_mutated": False,
            "operator_controlled_flow_only": True,
            "review_boundary": "review_status_only",
        },
    )
    write_audit_event(
        session=session,
        actor=actor,
        action="tool_library.proposal_created",
        object_type="agent_proposal",
        object_id=str(proposal.id),
        metadata={
            "run_id": str(run.id),
            "agent_reasoning_id": str(reasoning.id),
            "catalog_tool_id": tool_id or proposed_tool,
            "proposed_tool": proposed_tool,
            "proposed_target": target,
            "dispatches_work": False,
            "creates_tasks": False,
        },
    )
    session.commit()
    session.refresh(proposal)
    return AgentProposalRead.model_validate(proposal)


@router.post("/runs/{run_id}/ai-proposals/{proposal_id}/review", response_model=AgentProposalRead)
def review_run_ai_proposal(
    run_id: UUID,
    proposal_id: UUID,
    payload: AgentProposalReviewCreate,
    session: Session = Depends(get_session),
    actor: str = Depends(require_roles("operator", "admin")),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> AgentProposalRead:
    run = _load_run_for_tenant(session, run_id, tenant_id)
    try:
        proposal = review_agent_proposal(
            session=session,
            run=run,
            proposal_id=proposal_id,
            actor=actor,
            decision=payload.decision,
            note=payload.note,
        )
    except AgentProposalReviewError as exc:
        if exc.reason == "not_found":
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    session.commit()
    session.refresh(proposal)
    return AgentProposalRead.model_validate(proposal)


@router.post(
    "/runs/{run_id}/ai-proposals/{proposal_id}/repair-action", response_model=AiRepairActionRead
)
def record_run_ai_repair_action(
    run_id: UUID,
    proposal_id: UUID,
    payload: AiRepairActionCreate,
    session: Session = Depends(get_session),
    actor: str = Depends(require_roles("operator", "admin")),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> AiRepairActionRead:
    run = _load_run_for_tenant(session, run_id, tenant_id)
    try:
        outcome = apply_ai_repair_action(
            session=session,
            run=run,
            proposal_id=proposal_id,
            actor=actor,
            action=payload.action,
            note=payload.note,
        )
    except AiRepairLaneError as exc:
        if exc.reason == "not_found":
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    session.commit()
    session.refresh(outcome.proposal)
    return AiRepairActionRead(
        run_id=run.id,
        action=outcome.action,
        status=outcome.status,
        message=outcome.message,
        proposal=outcome.proposal,
        available_actions=outcome.available_actions,
    )


@router.get("/runs/{run_id}/attack-paths")
def get_run_attack_paths(
    run_id: UUID,
    session: Session = Depends(get_session),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> dict[str, Any]:
    _load_run_for_tenant(session, run_id, tenant_id)
    summary = build_attack_path_summary(session, run_id)
    if summary is None:
        raise HTTPException(status_code=404, detail="run not found")
    return summary


@router.get("/runs/{run_id}/remediation-advisor")
def get_run_remediation_advisor(
    run_id: UUID,
    session: Session = Depends(get_session),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> dict[str, Any]:
    _load_run_for_tenant(session, run_id, tenant_id)
    advisor = build_choke_point_remediation_advisor(session, run_id=run_id)
    if advisor is None:
        raise HTTPException(status_code=404, detail="run not found")
    return advisor


@router.get("/runs/{run_id}/events")
async def stream_run_events(
    run_id: UUID,
    request: Request,
    poll_interval_seconds: float = Query(default=0.5, ge=0.1, le=5.0),
    max_events: int | None = Query(default=None, ge=1, le=1000),
    session: Session = Depends(get_session),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> StreamingResponse:
    _load_run_for_tenant(session, run_id, tenant_id)

    session_factory = request.app.state.session_factory

    async def event_generator():
        last_fingerprint: str | None = None
        emitted_enrichment_keys: set[str] = set()
        emitted_events = 0
        first_event = True

        while True:
            if await request.is_disconnected():
                break

            with session_factory() as stream_session:
                try:
                    _load_run_for_tenant(stream_session, run_id, tenant_id)
                except HTTPException:
                    snapshot = None
                    enrichment_events: list[dict[str, Any]] = []
                else:
                    snapshot = _load_run_stream_snapshot(stream_session, run_id)
                    enrichment_events = _load_finding_enrichment_stream_events(
                        stream_session,
                        run_id,
                    )

            if snapshot is None:
                yield _format_sse_event(
                    "run.missing",
                    {"run_id": str(run_id), "status": "missing"},
                )
                break

            should_stop_after_loop = False
            fingerprint = _run_stream_fingerprint(snapshot)
            if fingerprint != last_fingerprint:
                event_name = "run.snapshot" if first_event else "run.update"
                yield _format_sse_event(event_name, snapshot)
                last_fingerprint = fingerprint
                emitted_events += 1

                if max_events is not None and emitted_events >= max_events:
                    break
                if snapshot["status"] in TERMINAL_RUN_STATUSES:
                    should_stop_after_loop = True

            enrichment_keys = {_finding_enrichment_event_key(event) for event in enrichment_events}
            if first_event:
                emitted_enrichment_keys.update(enrichment_keys)
            else:
                for event_payload in enrichment_events:
                    event_key = _finding_enrichment_event_key(event_payload)
                    if event_key in emitted_enrichment_keys:
                        continue
                    emitted_enrichment_keys.add(event_key)
                    if event_payload.get("status") not in {"succeeded", "failed", "unavailable"}:
                        continue
                    yield _format_sse_event("finding.enriched", event_payload)
                    emitted_events += 1
                    if max_events is not None and emitted_events >= max_events:
                        break

            first_event = False
            if max_events is not None and emitted_events >= max_events:
                break
            if should_stop_after_loop:
                break

            await asyncio.sleep(poll_interval_seconds)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@router.get("/runs/{run_id}/pack", response_model=RunPackBindingRead)
def get_run_pack_binding(
    run_id: UUID,
    session: Session = Depends(get_session),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> RunPackBindingRead:
    run = _load_run_for_tenant(session, run_id, tenant_id)
    binding = serialize_run_pack_binding(run)
    if binding is None:
        raise HTTPException(status_code=404, detail="no pack bound to run")
    return binding


@router.post("/runs/{run_id}/bind-pack", response_model=RunPackBindingRead)
def bind_pack_for_run(
    run_id: UUID,
    payload: RunPackBindCreate,
    session: Session = Depends(get_session),
    actor: str = Depends(require_roles("operator", "admin")),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> RunPackBindingRead:
    run = _load_run_for_tenant(session, run_id, tenant_id)
    if run.status in {
        "running",
        "completed",
        "completed_with_errors",
        "failed",
        "cancelled",
        "cancelling",
    }:
        raise HTTPException(
            status_code=409, detail="run pack binding is locked after execution starts"
        )

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
    variant: str = Query(
        default="technical",
        pattern="^(summary|technical|compliance|evidence|retest|executive|soc2|iso27001|pci_dss|nis2|dora|nfir|assurance|attack_narrative)$",
    ),
    framework: str = Query(default="nis2", pattern="^(nis2|dora|soc2|iso27001|pci_dss|nfir)$"),
    session: Session = Depends(get_session),
    settings: Settings = Depends(get_settings),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> Response:
    run = _load_run_report_for_tenant(session, run_id, tenant_id)
    report_context = report_context_for_run(run, session=session)

    if format == "html":
        content = render_html_report(run, variant=variant, framework=framework, context=report_context)
        media_type = "text/html; charset=utf-8"
        extension = "html"
    elif format == "pdf":
        try:
            content = render_pdf_report(
                run,
                variant=variant,
                framework=framework,
                settings=settings,
                context=report_context,
            )
        except RuntimeError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        media_type = "application/pdf"
        extension = "pdf"
    else:
        content = render_markdown_report(run, variant=variant, framework=framework, context=report_context)
        media_type = "text/markdown; charset=utf-8"
        extension = "md"

    filename_variant = f"{variant}-{framework}" if variant == "compliance" else variant
    headers = {
        "Content-Disposition": f'attachment; filename="aegispt-run-{run_id}-{filename_variant}.{extension}"'
    }
    return Response(content=content, media_type=media_type, headers=headers)


@router.get("/runs/{run_id}/reports", response_model=list[RunReportCatalogItemRead])
def list_run_reports(
    run_id: UUID,
    session: Session = Depends(get_session),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> list[RunReportCatalogItemRead]:
    run = _load_run_report_for_tenant(session, run_id, tenant_id)
    report_context = report_context_for_run(run, session=session)
    return build_report_catalog(run, context=report_context)


@router.post("/runs/{run_id}/report-draft", response_model=RunReportDraftRead)
def draft_run_report(
    run_id: UUID,
    payload: RunReportDraftCreate,
    session: Session = Depends(get_session),
    settings: Settings = Depends(get_settings),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> RunReportDraftRead:
    run = _load_run_report_for_tenant(session, run_id, tenant_id)
    effective_settings = effective_runtime_settings_for_run(session, run=run, settings=settings)
    return build_report_draft(
        run,
        variant=payload.variant,
        sections=payload.sections,
        settings=effective_settings,
        session=session,
    )


@router.post("/runs/{run_id}/approvals", response_model=RunRead)
def record_run_approval(
    run_id: UUID,
    payload: ApprovalCreate,
    background_tasks: BackgroundTasks,
    session: Session = Depends(get_session),
    actor: str = Depends(require_roles("operator", "admin")),
    settings: Settings = Depends(get_settings),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> RunRead:
    run = _load_run_for_tenant(session, run_id, tenant_id)
    if run.profile is None:
        raise HTTPException(status_code=500, detail="run profile relationship not loaded")
    if required_approvals(run.profile) == 0:
        raise HTTPException(status_code=409, detail="run profile does not require approvals")
    if run.status == "rejected":
        raise HTTPException(status_code=409, detail="run already rejected")
    if run.status in {"cancelled", "cancelling"}:
        raise HTTPException(status_code=409, detail="run has been cancelled")

    expected_step_id = approval_step_id(run.profile)
    if payload.step_id != expected_step_id:
        raise HTTPException(
            status_code=409,
            detail=f"run requires approval step {expected_step_id}",
        )

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
        clear_run_credential_vault_if_terminal(
            session,
            run=run,
            actor=actor,
            reason="run_approval_rejected",
        )
        write_audit_event(
            session=session,
            actor=actor,
            action="run.rejected",
            object_type="run",
            object_id=str(run.id),
            metadata={"step_id": payload.step_id},
        )
    elif payload.step_id == expected_step_id:
        session.refresh(run, attribute_names=["approvals"])
        if pending_approvals(run, run.profile, step_id=payload.step_id) == 0:
            scope = session.scalar(latest_scope_query(run.engagement_id))
            if scope is None:
                raise HTTPException(
                    status_code=409, detail="engagement scope missing during activation"
                )
            try:
                queue_run_tasks(session, run, scope, run.profile)
            except ValueError as exc:
                raise HTTPException(status_code=409, detail=str(exc)) from exc
            write_audit_event(
                session=session,
                actor=actor,
                action="run.queued",
                object_type="run",
                object_id=str(run.id),
                metadata={"activated_by": actor, "step_id": payload.step_id},
            )
            if _eligible_for_launch_auto_dispatch(run):
                effective_settings = effective_runtime_settings_for_run(
                    session,
                    run=run,
                    settings=settings,
                )
                inline_background_tasks = (
                    background_tasks if effective_settings.inline_dispatch_background else None
                )
                try:
                    dispatch_queued_run_tasks(
                        session,
                        run=run,
                        actor=actor,
                        settings=effective_settings,
                        background_tasks=inline_background_tasks,
                    )
                except ValueError as exc:
                    if str(exc) != "run has no queued tasks to dispatch":
                        raise HTTPException(status_code=409, detail=str(exc)) from exc
        else:
            run.status = "pending_approval"

    session.commit()

    hydrated_run = load_run(session, run.id)
    if hydrated_run is None:
        raise HTTPException(status_code=500, detail="run could not be reloaded after approval")
    return serialize_run(hydrated_run, session=session)


@router.post("/runs/{run_id}/dispatch", response_model=RunDispatchRead)
def dispatch_run(
    run_id: UUID,
    background_tasks: BackgroundTasks,
    session: Session = Depends(get_session),
    actor: str = Depends(require_roles("operator", "admin")),
    settings: Settings = Depends(get_settings),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> RunDispatchRead:
    run = _load_run_for_tenant(session, run_id, tenant_id)
    effective_settings = effective_runtime_settings_for_run(session, run=run, settings=settings)
    inline_background_tasks = (
        background_tasks if effective_settings.inline_dispatch_background else None
    )
    try:
        dispatch_mode, dispatched_task_ids = dispatch_queued_run_tasks(
            session,
            run=run,
            actor=actor,
            settings=effective_settings,
            background_tasks=inline_background_tasks,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    session.commit()
    session.expire_all()

    hydrated_run = load_run(session, run.id)
    if hydrated_run is None:
        raise HTTPException(status_code=500, detail="run could not be reloaded after dispatch")

    return RunDispatchRead(
        run=serialize_run(hydrated_run, session=session),
        dispatch_mode=dispatch_mode,
        dispatched_task_ids=dispatched_task_ids,
    )


@router.post("/runs/{run_id}/cancel", response_model=RunRead)
def cancel_run(
    run_id: UUID,
    session: Session = Depends(get_session),
    actor: str = Depends(require_roles("operator", "admin")),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> RunRead:
    run = _load_run_for_tenant(session, run_id, tenant_id)

    changed = cancel_run_tasks(run)
    if not changed:
        raise HTTPException(status_code=409, detail="run can no longer be cancelled")
    clear_run_credential_vault_if_terminal(
        session,
        run=run,
        actor=actor,
        reason="run_cancelled",
    )

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
    return serialize_run(hydrated_run, session=session)


@router.post("/runs/{run_id}/stale-recovery", response_model=RunRead)
def recover_stale_run(
    run_id: UUID,
    payload: RunStaleRecoveryCreate,
    session: Session = Depends(get_session),
    actor: str = Depends(require_roles("operator", "admin")),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> RunRead:
    run = _load_run_for_tenant(session, run_id, tenant_id)
    try:
        recovered_task_ids = recover_stale_run_tasks(
            session,
            run=run,
            actor=actor,
            reason=payload.reason,
            task_outcome=payload.task_outcome,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    session.commit()
    hydrated_run = load_run(session, run.id)
    if hydrated_run is None:
        raise HTTPException(
            status_code=500, detail="run could not be reloaded after stale recovery"
        )
    if not recovered_task_ids:
        raise HTTPException(status_code=409, detail="no stale tasks were recovered")
    return serialize_run(hydrated_run, session=session)
