from __future__ import annotations

import copy
import ipaddress
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.app.auth import get_current_actor, require_roles
from api.app.config import Settings, get_settings
from api.app.db import get_session
from api.app.models import (
    Finding,
    FindingIntegrationLink,
    FindingRemediation,
    IntegrationConfiguration,
    Run,
)
from api.app.schemas.evidence_integrity import (
    EvidenceIntegrityResultRead,
    RunEvidenceIntegrityResultRead,
)
from api.app.schemas.finding_views import (
    FindingEvidenceReplayRead,
    FindingTheaterRead,
    RemediationPortfolioRead,
    RemediationRetestPlanCreate,
    RemediationRetestPlanRead,
)
from api.app.schemas.findings import FindingRead, FindingUpdate
from api.app.schemas.integrations import JiraFindingLinkRead, RepositoryFixPullRequestRead
from api.app.schemas.remediation import (
    FindingMicroScanCreate,
    FindingMicroScanRead,
    FindingRemediationRead,
    FindingRemediationUpdate,
    FindingRetestCreate,
    FindingRetestRead,
)
from api.app.services.ai_enrichment import enrich_finding_async, finding_ai_enrichment_view
from api.app.services.audit import write_audit_event
from api.app.services.autofix import ensure_autofix_for_finding
from api.app.services.evidence_integrity import verify_finding_evidence, verify_run_evidence
from api.app.services.exposure_score import record_exposure_score
from api.app.services.finding_retests import (
    FindingRetestRequestError,
    request_single_finding_retest,
)
from api.app.services.proof_of_resolution import (
    ProofOfResolutionRequestError,
    request_proof_of_resolution_micro_scan,
)
from api.app.services.finding_quality import apply_finding_quality_defaults
from api.app.services.finding_sla import apply_finding_sla, apply_findings_sla
from api.app.services.finding_views import build_finding_evidence_replay, build_finding_theater
from api.app.services.remediation import build_remediation_portfolio, build_remediation_retest_plan
from api.app.services.repository_integration import (
    RepositoryIntegrationError,
    create_fix_pr_for_finding,
    ensure_repository_link_for_finding,
)
from api.app.services.runs import (
    load_run,
)
from api.app.services.settings import (
    effective_runtime_settings_for_finding,
    effective_runtime_settings_for_run,
)
from api.app.services.tenancy import (
    assert_finding_tenant,
    assert_run_tenant,
    get_current_tenant_id,
    load_engagement_for_tenant,
)

router = APIRouter(prefix="/api/v1", tags=["findings"])

SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
    "unknown": 5,
}


def _sort_key(finding: Finding) -> tuple[int, str, str]:
    severity_rank = SEVERITY_ORDER.get(finding.severity, SEVERITY_ORDER["unknown"])
    return (severity_rank, finding.title.lower(), finding.target_id.lower())


def _record_exposure_for_finding(session: Session, finding: Finding) -> None:
    if finding.run_id is None:
        return
    engagement_id = session.scalar(select(Run.engagement_id).where(Run.id == finding.run_id))
    if engagement_id is None:
        return
    record_exposure_score(
        session=session,
        engagement_id=engagement_id,
        run_id=finding.run_id,
    )


def _jira_issue_key(configuration: IntegrationConfiguration, finding: Finding) -> str:
    project_key = (configuration.project_key or "AEGIS").strip().upper() or "AEGIS"
    return f"{project_key}-{finding.id.hex[:8].upper()}"


def _jira_issue_url(configuration: IntegrationConfiguration, issue_key: str) -> str:
    return f"{configuration.base_url.rstrip('/')}/browse/{issue_key}"


def _target_map_for_finding_retest(target_id: str) -> dict[str, list[str]]:
    normalized = target_id.strip()
    if normalized.startswith(("http://", "https://")):
        return {"urls": [normalized]}

    try:
        ipaddress.ip_network(normalized, strict=False)
    except ValueError:
        pass
    else:
        if "/" in normalized:
            return {"cidr_ranges": [normalized]}
        return {"ip_addresses": [normalized]}

    if "." in normalized and "/" not in normalized:
        return {"hosts": [normalized]}
    return {"targets": [normalized]}


def _retest_metadata(
    *,
    finding: Finding,
    source_run: Run,
    remediation: FindingRemediation | None,
    notes: str | None,
) -> dict[str, object]:
    return {
        "mode": "single_finding",
        "source_finding_id": str(finding.id),
        "source_run_id": str(source_run.id),
        "source_finding_title": finding.title,
        "source_finding_severity": finding.severity,
        "source_finding_status": finding.status,
        "source_finding_target": finding.target_id,
        "source_evidence_ref": finding.evidence_ref,
        "source_finding_summary": finding.summary,
        "source_summary": finding.summary,
        "remediation_id": str(remediation.id) if remediation is not None else None,
        "remediation_state": remediation.state if remediation is not None else None,
        "remediation_notes": remediation.notes if remediation is not None else None,
        "operator_notes": notes,
        "verification_state": "requested",
    }


def _build_retest_configuration(
    *,
    finding: Finding,
    source_run: Run,
    remediation: FindingRemediation | None,
    notes: str | None,
) -> dict[str, object]:
    configuration = copy.deepcopy(source_run.configuration_json or {})
    if not isinstance(configuration, dict):
        configuration = {}

    configuration["assessment_type"] = configuration.get("assessment_type") or "Single-Finding Retest"
    configuration["test_profile"] = "Single-Finding Retest"
    configuration["execution_profile"] = source_run.profile.name if source_run.profile is not None else None
    configuration["targets"] = _target_map_for_finding_retest(finding.target_id)

    modules = configuration.get("modules")
    if not isinstance(modules, dict):
        modules = {}
    modules = dict(modules)
    modules["single_finding_retest"] = True
    configuration["modules"] = modules

    configuration.pop("follow_up", None)
    configuration["retest"] = _retest_metadata(
        finding=finding,
        source_run=source_run,
        remediation=remediation,
        notes=notes,
    )
    return configuration


@router.get(
    "/engagements/{engagement_id}/remediation/portfolio",
    response_model=RemediationPortfolioRead,
)
def get_engagement_remediation_portfolio(
    engagement_id: UUID,
    session: Session = Depends(get_session),
    tenant_id: str | None = Depends(get_current_tenant_id),
    owner: str | None = Query(default=None, max_length=255),
    remediation_state: str | None = Query(default=None, max_length=50),
    sla_status: str | None = Query(default=None, max_length=50),
    eligible_for_retest: bool | None = Query(default=None),
    sla_days: int = Query(default=30, ge=1, le=3650),
    due_soon_days: int = Query(default=7, ge=0, le=365),
) -> RemediationPortfolioRead:
    load_engagement_for_tenant(session, engagement_id, tenant_id)
    return build_remediation_portfolio(
        session=session,
        engagement_id=engagement_id,
        owner=owner,
        remediation_state=remediation_state,
        sla_status=sla_status,
        eligible_for_retest=eligible_for_retest,
        sla_days=sla_days,
        due_soon_days=due_soon_days,
    )


@router.post(
    "/engagements/{engagement_id}/remediation/retest-plan",
    response_model=RemediationRetestPlanRead,
)
def plan_engagement_remediation_retests(
    engagement_id: UUID,
    payload: RemediationRetestPlanCreate,
    session: Session = Depends(get_session),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> RemediationRetestPlanRead:
    load_engagement_for_tenant(session, engagement_id, tenant_id)
    portfolio = build_remediation_portfolio(
        session=session,
        engagement_id=engagement_id,
        owner=payload.owner,
        remediation_state=payload.remediation_state,
        sla_status=payload.sla_status,
        eligible_for_retest=payload.eligible_for_retest,
        sla_days=payload.sla_days,
        due_soon_days=payload.due_soon_days,
        finding_ids=set(payload.finding_ids) if payload.finding_ids else None,
    )
    return build_remediation_retest_plan(
        engagement_id=engagement_id,
        items=portfolio.items,
        generated_at=portfolio.generated_at,
    )


@router.get("/runs/{run_id}/findings", response_model=list[FindingRead])
def list_run_findings(
    run_id: UUID,
    session: Session = Depends(get_session),
    tenant_id: str | None = Depends(get_current_tenant_id),
    settings: Settings = Depends(get_settings),
) -> list[FindingRead]:
    run = load_run(session, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="run not found")
    assert_run_tenant(run, tenant_id)
    findings = session.scalars(select(Finding).where(Finding.run_id == run_id)).all()
    quality_changed = any(
        apply_finding_quality_defaults(finding, session=session) for finding in findings
    )
    if apply_findings_sla(session, list(findings), settings=settings, tenant_id=tenant_id) or quality_changed:
        session.commit()
    return [FindingRead.model_validate(finding) for finding in sorted(findings, key=_sort_key)]


@router.get("/findings/{finding_id}", response_model=FindingRead)
def get_finding(
    finding_id: UUID,
    session: Session = Depends(get_session),
    tenant_id: str | None = Depends(get_current_tenant_id),
    settings: Settings = Depends(get_settings),
) -> FindingRead:
    finding = session.scalar(select(Finding).where(Finding.id == finding_id))
    if finding is None:
        raise HTTPException(status_code=404, detail="finding not found")
    assert_finding_tenant(finding, tenant_id)
    quality_changed = apply_finding_quality_defaults(finding, session=session)
    if apply_finding_sla(session, finding, settings=settings, tenant_id=tenant_id) or quality_changed:
        session.commit()

    return FindingRead.model_validate(finding)


@router.post("/findings/{finding_id}/ai-enrich")
def enrich_finding_now(
    finding_id: UUID,
    session: Session = Depends(get_session),
    actor: str = Depends(require_roles("operator", "admin")),
    tenant_id: str | None = Depends(get_current_tenant_id),
    settings: Settings = Depends(get_settings),
) -> dict[str, Any]:
    finding = session.scalar(select(Finding).where(Finding.id == finding_id))
    if finding is None:
        raise HTTPException(status_code=404, detail="finding not found")
    assert_finding_tenant(finding, tenant_id)

    effective_settings = effective_runtime_settings_for_finding(
        session,
        finding=finding,
        settings=settings,
    )
    if not effective_settings.ai_finding_enrichment_enabled:
        raise HTTPException(status_code=409, detail="AI finding enrichment is disabled")

    enrichment = enrich_finding_async(finding.id, session, settings=effective_settings)
    if enrichment is None:
        raise HTTPException(status_code=409, detail="AI finding enrichment provider is not available")

    write_audit_event(
        session=session,
        actor=actor,
        action="finding.ai_enrichment.requested",
        object_type="finding",
        object_id=str(finding.id),
        metadata={
            "finding_id": str(finding.id),
            "run_id": str(finding.run_id) if finding.run_id else None,
            "provider": enrichment.provider,
            "status": enrichment.status,
        },
    )
    session.commit()
    session.refresh(enrichment)
    return finding_ai_enrichment_view(enrichment)


@router.post("/findings/{finding_id}/handoff-jira", response_model=JiraFindingLinkRead)
def handoff_finding_to_jira(
    finding_id: UUID,
    session: Session = Depends(get_session),
    actor: str = Depends(get_current_actor),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> JiraFindingLinkRead:
    finding = session.scalar(select(Finding).where(Finding.id == finding_id))
    if finding is None:
        raise HTTPException(status_code=404, detail="finding not found")
    assert_finding_tenant(finding, tenant_id)
    if finding.run_id is None:
        raise HTTPException(status_code=409, detail="finding has no source run engagement for Jira handoff")

    run = session.scalar(select(Run).where(Run.id == finding.run_id, Run.deleted_at.is_(None)))
    if run is None:
        raise HTTPException(status_code=409, detail="source run not found for finding")
    assert_run_tenant(run, tenant_id)

    configuration = session.scalar(
        select(IntegrationConfiguration).where(
            IntegrationConfiguration.engagement_id == run.engagement_id,
            IntegrationConfiguration.integration_type == "jira",
        )
    )
    if configuration is None:
        raise HTTPException(status_code=409, detail="jira integration configuration required before handoff")

    link = session.scalar(
        select(FindingIntegrationLink).where(
            FindingIntegrationLink.finding_id == finding.id,
            FindingIntegrationLink.integration_configuration_id == configuration.id,
        )
    )
    issue_key = link.issue_key if link is not None else _jira_issue_key(configuration, finding)
    issue_url = link.issue_url if link is not None else _jira_issue_url(configuration, issue_key)

    if link is None:
        link = FindingIntegrationLink(
            finding_id=finding.id,
            integration_configuration_id=configuration.id,
            issue_key=issue_key,
            issue_url=issue_url,
            issue_status="Ready for Jira triage",
            last_sync_state="not_synced",
            last_sync_payload_json={
                "handoff_mode": "ui_prepared",
                "remote_issue_created": False,
            },
            created_by=actor,
            updated_by=actor,
        )
        session.add(link)
        action = "finding.integration_link.jira_prepared"
    else:
        link.issue_key = issue_key
        link.issue_url = issue_url
        link.issue_status = link.issue_status or "Ready for Jira triage"
        link.last_sync_error = None
        link.last_sync_payload_json = {
            **(link.last_sync_payload_json or {}),
            "handoff_mode": "ui_prepared",
            "remote_issue_created": False,
        }
        link.updated_by = actor
        action = "finding.integration_link.jira_reprepared"

    session.flush()
    write_audit_event(
        session=session,
        actor=actor,
        action=action,
        object_type="finding_integration_link",
        object_id=str(link.id),
        metadata={
            "engagement_id": str(run.engagement_id),
            "finding_id": str(finding.id),
            "integration_type": "jira",
            "integration_configuration_id": str(configuration.id),
            "issue_key": link.issue_key,
            "last_sync_state": link.last_sync_state,
        },
    )
    session.commit()
    session.refresh(link)
    return JiraFindingLinkRead.model_validate(link)


@router.get("/findings/{finding_id}/theater", response_model=FindingTheaterRead)
def get_finding_theater(
    finding_id: UUID,
    session: Session = Depends(get_session),
    tenant_id: str | None = Depends(get_current_tenant_id),
    settings: Settings = Depends(get_settings),
) -> FindingTheaterRead:
    finding = session.scalar(select(Finding).where(Finding.id == finding_id))
    if finding is None:
        raise HTTPException(status_code=404, detail="finding not found")
    assert_finding_tenant(finding, tenant_id)
    quality_changed = apply_finding_quality_defaults(finding, session=session)
    if apply_finding_sla(session, finding, settings=settings, tenant_id=tenant_id) or quality_changed:
        session.commit()
    effective_settings = effective_runtime_settings_for_finding(
        session,
        finding=finding,
        settings=settings,
    )
    generated_autofix = ensure_autofix_for_finding(session=session, finding=finding, settings=effective_settings)
    generated_repository_link = ensure_repository_link_for_finding(session=session, finding=finding, settings=settings)
    if (generated_autofix is not None and finding.autofix_json is not None) or generated_repository_link is not None:
        session.commit()
    finding_view = build_finding_theater(
        session,
        finding_id,
        autofix_enabled=effective_settings.ai_autofix_enabled,
    )
    if finding_view is None:
        raise HTTPException(status_code=404, detail="finding not found")
    return finding_view


@router.get("/findings/{finding_id}/evidence", response_model=FindingEvidenceReplayRead)
def get_finding_evidence(
    finding_id: UUID,
    session: Session = Depends(get_session),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> FindingEvidenceReplayRead:
    finding = session.scalar(select(Finding).where(Finding.id == finding_id))
    if finding is None:
        raise HTTPException(status_code=404, detail="finding not found")
    assert_finding_tenant(finding, tenant_id)
    if apply_finding_quality_defaults(finding, session=session):
        session.commit()
    evidence_view = build_finding_evidence_replay(session, finding_id)
    if evidence_view is None:
        raise HTTPException(status_code=404, detail="finding not found")
    return evidence_view


@router.post("/findings/{finding_id}/evidence/verify", response_model=EvidenceIntegrityResultRead)
def verify_single_finding_evidence(
    finding_id: UUID,
    session: Session = Depends(get_session),
    actor: str = Depends(get_current_actor),
    settings: Settings = Depends(get_settings),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> EvidenceIntegrityResultRead:
    finding = session.scalar(select(Finding).where(Finding.id == finding_id))
    if finding is None:
        raise HTTPException(status_code=404, detail="finding not found")
    assert_finding_tenant(finding, tenant_id)
    effective_settings = effective_runtime_settings_for_finding(
        session,
        finding=finding,
        settings=settings,
    )
    result = verify_finding_evidence(
        session=session,
        finding=finding,
        settings=effective_settings,
        actor=actor,
    )
    session.commit()
    return result


@router.post("/runs/{run_id}/evidence/verify", response_model=RunEvidenceIntegrityResultRead)
def verify_all_run_evidence(
    run_id: UUID,
    session: Session = Depends(get_session),
    actor: str = Depends(get_current_actor),
    settings: Settings = Depends(get_settings),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> RunEvidenceIntegrityResultRead:
    run = load_run(session, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="run not found")
    assert_run_tenant(run, tenant_id)
    effective_settings = effective_runtime_settings_for_run(
        session,
        run=run,
        settings=settings,
    )
    result = verify_run_evidence(
        session=session,
        run=run,
        settings=effective_settings,
        actor=actor,
    )
    session.commit()
    return result


@router.get("/findings/{finding_id}/remediation", response_model=FindingRemediationRead)
def get_finding_remediation(
    finding_id: UUID,
    session: Session = Depends(get_session),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> FindingRemediationRead:
    finding = session.scalar(select(Finding).where(Finding.id == finding_id))
    if finding is None:
        raise HTTPException(status_code=404, detail="finding not found")
    assert_finding_tenant(finding, tenant_id)

    remediation = session.scalar(select(FindingRemediation).where(FindingRemediation.finding_id == finding_id))
    if remediation is None:
        raise HTTPException(status_code=404, detail="remediation not found")

    return FindingRemediationRead.model_validate(remediation)


@router.post(
    "/findings/{finding_id}/retest",
    response_model=FindingRetestRead,
    status_code=status.HTTP_201_CREATED,
)
def request_finding_retest(
    finding_id: UUID,
    payload: FindingRetestCreate,
    session: Session = Depends(get_session),
    actor: str = Depends(require_roles("operator", "admin")),
    settings: Settings = Depends(get_settings),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> FindingRetestRead:
    finding = session.scalar(select(Finding).where(Finding.id == finding_id))
    if finding is None:
        raise HTTPException(status_code=404, detail="finding not found")
    assert_finding_tenant(finding, tenant_id)
    try:
        retest = request_single_finding_retest(
            session=session,
            finding=finding,
            notes=payload.notes,
            actor=actor,
            settings=settings,
        )
    except FindingRetestRequestError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    session.commit()
    return retest


@router.post(
    "/findings/{finding_id}/proof-of-resolution/micro-scan",
    response_model=FindingMicroScanRead,
    status_code=status.HTTP_201_CREATED,
)
def request_finding_proof_of_resolution_micro_scan(
    finding_id: UUID,
    payload: FindingMicroScanCreate,
    session: Session = Depends(get_session),
    actor: str = Depends(require_roles("operator", "admin")),
    settings: Settings = Depends(get_settings),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> FindingMicroScanRead:
    finding = session.scalar(select(Finding).where(Finding.id == finding_id))
    if finding is None:
        raise HTTPException(status_code=404, detail="finding not found")
    assert_finding_tenant(finding, tenant_id)
    try:
        micro_scan = request_proof_of_resolution_micro_scan(
            session=session,
            finding=finding,
            actor=actor,
            settings=settings,
            notes=payload.notes,
        )
    except ProofOfResolutionRequestError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    session.commit()
    return micro_scan


@router.put("/findings/{finding_id}/remediation", response_model=FindingRemediationRead)
def upsert_finding_remediation(
    finding_id: UUID,
    payload: FindingRemediationUpdate,
    session: Session = Depends(get_session),
    actor: str = Depends(require_roles("operator", "admin")),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> FindingRemediationRead:
    finding = session.scalar(select(Finding).where(Finding.id == finding_id))
    if finding is None:
        raise HTTPException(status_code=404, detail="finding not found")
    assert_finding_tenant(finding, tenant_id)

    remediation = session.scalar(select(FindingRemediation).where(FindingRemediation.finding_id == finding_id))
    previous_state = remediation.state if remediation is not None else None
    if remediation is None:
        remediation = FindingRemediation(
            finding_id=finding.id,
            state=payload.state,
            notes=payload.notes,
            owner=payload.owner,
            created_by=actor,
            updated_by=actor,
        )
        session.add(remediation)
    else:
        remediation.state = payload.state
        remediation.notes = payload.notes
        remediation.owner = payload.owner
        remediation.updated_by = actor

    write_audit_event(
        session=session,
        actor=actor,
        action="finding.remediation.updated",
        object_type="finding",
        object_id=str(finding.id),
        metadata={
            "previous_state": previous_state,
            "state": remediation.state,
            "remediation_owner": remediation.owner,
        },
    )
    _record_exposure_for_finding(session, finding)
    session.commit()
    session.refresh(remediation)

    return FindingRemediationRead.model_validate(remediation)


@router.patch("/findings/{finding_id}", response_model=FindingRead)
def update_finding(
    finding_id: UUID,
    payload: FindingUpdate,
    session: Session = Depends(get_session),
    actor: str = Depends(require_roles("operator", "admin")),
    tenant_id: str | None = Depends(get_current_tenant_id),
    settings: Settings = Depends(get_settings),
) -> FindingRead:
    finding = session.scalar(select(Finding).where(Finding.id == finding_id))
    if finding is None:
        raise HTTPException(status_code=404, detail="finding not found")
    assert_finding_tenant(finding, tenant_id)

    previous_status = finding.status
    reason = (payload.false_positive_reason or payload.reason or "").strip()
    if payload.status == "false_positive" and not reason:
        raise HTTPException(
            status_code=422,
            detail="false_positive_reason is required when marking a finding false_positive",
        )

    finding.status = payload.status
    if finding.status == "false_positive":
        finding.false_positive_reason = reason
        finding.false_positive_confirmed_by = actor

    if previous_status != finding.status:
        write_audit_event(
            session=session,
            actor=actor,
            action="finding.status_changed",
            object_type="finding",
            object_id=str(finding.id),
            metadata={"old_status": previous_status, "new_status": finding.status},
        )
        if finding.status == "false_positive":
            write_audit_event(
                session=session,
                actor=actor,
                action="finding.false_positive_marked",
                object_type="finding",
                object_id=str(finding.id),
                metadata={"old_status": previous_status, "new_status": finding.status, "reason": reason},
            )

    write_audit_event(
        session=session,
        actor=actor,
        action="finding.updated",
        object_type="finding",
        object_id=str(finding.id),
        metadata={"previous_status": previous_status, "status": finding.status},
    )
    apply_finding_sla(session, finding, settings=settings, tenant_id=tenant_id)
    _record_exposure_for_finding(session, finding)
    session.commit()
    session.refresh(finding)

    return FindingRead.model_validate(finding)


@router.post("/findings/{finding_id}/repository/fix-pr", response_model=RepositoryFixPullRequestRead)
def create_finding_fix_pull_request(
    finding_id: UUID,
    session: Session = Depends(get_session),
    actor: str = Depends(require_roles("operator", "admin")),
    settings: Settings = Depends(get_settings),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> RepositoryFixPullRequestRead:
    finding = session.scalar(select(Finding).where(Finding.id == finding_id))
    if finding is None:
        raise HTTPException(status_code=404, detail="finding not found")
    assert_finding_tenant(finding, tenant_id)

    try:
        pull_request = create_fix_pr_for_finding(
            session=session,
            finding=finding,
            actor=actor,
            settings=settings,
        )
    except RepositoryIntegrationError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    write_audit_event(
        session=session,
        actor=actor,
        action="finding.repository_fix_pr.created",
        object_type="finding",
        object_id=str(finding.id),
        metadata={
            "provider": pull_request.provider,
            "repository_url": pull_request.repository_url,
            "branch_name": pull_request.branch_name,
            "pull_request_id": pull_request.pull_request_id,
            "auto_merge_enabled": False,
        },
    )
    session.commit()
    return RepositoryFixPullRequestRead(
        provider=pull_request.provider,
        repository_url=pull_request.repository_url,
        branch_name=pull_request.branch_name,
        pull_request_url=pull_request.pull_request_url,
        pull_request_id=pull_request.pull_request_id,
        auto_merge_enabled=pull_request.auto_merge_enabled,
    )
