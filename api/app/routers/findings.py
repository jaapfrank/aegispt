from __future__ import annotations

import copy
import ipaddress
from datetime import UTC, datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.app.auth import get_current_actor
from api.app.config import Settings, get_settings
from api.app.db import get_session
from api.app.models import Engagement, Finding, FindingRemediation, Run
from api.app.schemas.finding_views import FindingEvidenceReplayRead, FindingTheaterRead
from api.app.schemas.findings import FindingRead, FindingUpdate
from api.app.schemas.remediation import (
    FindingRemediationRead,
    FindingRemediationUpdate,
    FindingRetestCreate,
    FindingRetestRead,
)
from api.app.services.audit import write_audit_event
from api.app.services.finding_views import build_finding_evidence_replay, build_finding_theater
from api.app.services.packs import bind_pack_to_run, latest_pack_deployment
from api.app.services.run_profiles import ensure_default_run_profiles
from api.app.services.runs import (
    align_run_configuration_with_engagement,
    latest_scope_query,
    load_run,
    queue_run_tasks,
    required_approvals,
)
from api.app.services.secrets import materialize_run_configuration_secrets

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


@router.get("/runs/{run_id}/findings", response_model=list[FindingRead])
def list_run_findings(
    run_id: UUID,
    session: Session = Depends(get_session),
) -> list[FindingRead]:
    findings = session.scalars(select(Finding).where(Finding.run_id == run_id)).all()
    return [FindingRead.model_validate(finding) for finding in sorted(findings, key=_sort_key)]


@router.get("/findings/{finding_id}", response_model=FindingRead)
def get_finding(
    finding_id: UUID,
    session: Session = Depends(get_session),
) -> FindingRead:
    finding = session.scalar(select(Finding).where(Finding.id == finding_id))
    if finding is None:
        raise HTTPException(status_code=404, detail="finding not found")

    return FindingRead.model_validate(finding)


@router.get("/findings/{finding_id}/theater", response_model=FindingTheaterRead)
def get_finding_theater(
    finding_id: UUID,
    session: Session = Depends(get_session),
) -> FindingTheaterRead:
    finding_view = build_finding_theater(session, finding_id)
    if finding_view is None:
        raise HTTPException(status_code=404, detail="finding not found")
    return finding_view


@router.get("/findings/{finding_id}/evidence", response_model=FindingEvidenceReplayRead)
def get_finding_evidence(
    finding_id: UUID,
    session: Session = Depends(get_session),
) -> FindingEvidenceReplayRead:
    evidence_view = build_finding_evidence_replay(session, finding_id)
    if evidence_view is None:
        raise HTTPException(status_code=404, detail="finding not found")
    return evidence_view


@router.get("/findings/{finding_id}/remediation", response_model=FindingRemediationRead)
def get_finding_remediation(
    finding_id: UUID,
    session: Session = Depends(get_session),
) -> FindingRemediationRead:
    finding = session.scalar(select(Finding).where(Finding.id == finding_id))
    if finding is None:
        raise HTTPException(status_code=404, detail="finding not found")

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
    actor: str = Depends(get_current_actor),
    settings: Settings = Depends(get_settings),
) -> FindingRetestRead:
    ensure_default_run_profiles(session)

    finding = session.scalar(select(Finding).where(Finding.id == finding_id))
    if finding is None:
        raise HTTPException(status_code=404, detail="finding not found")
    if finding.run_id is None:
        raise HTTPException(status_code=409, detail="finding has no source run to retest")

    source_run = load_run(session, finding.run_id)
    if source_run is None:
        raise HTTPException(status_code=409, detail="source run not found for finding")
    if source_run.profile is None:
        raise HTTPException(status_code=409, detail="source run profile not found")

    engagement = session.scalar(select(Engagement).where(Engagement.id == source_run.engagement_id))
    if engagement is None:
        raise HTTPException(status_code=409, detail="source engagement not found")

    scope = session.scalar(latest_scope_query(engagement.id))
    if scope is None:
        raise HTTPException(status_code=400, detail="engagement scope required before requesting retests")

    remediation = session.scalar(select(FindingRemediation).where(FindingRemediation.finding_id == finding.id))
    retest_configuration = _build_retest_configuration(
        finding=finding,
        source_run=source_run,
        remediation=remediation,
        notes=payload.notes,
    )
    aligned_configuration = align_run_configuration_with_engagement(retest_configuration, engagement=engagement)
    stored_configuration, created_secret_refs = materialize_run_configuration_secrets(
        session,
        engagement_id=engagement.id,
        configuration=aligned_configuration,
        settings=settings,
    )
    timestamp = datetime.now(tz=UTC)

    retest_run = Run(
        engagement_id=engagement.id,
        profile_id=source_run.profile.id,
        profile=source_run.profile,
        source_inventory_snapshot_id=source_run.source_inventory_snapshot_id or finding.source_inventory_snapshot_id,
        requested_by=actor,
        status="requested",
        configuration_json=stored_configuration,
        created_at=timestamp,
        updated_at=timestamp,
    )
    session.add(retest_run)
    session.flush()

    deployment = latest_pack_deployment(session, engagement_id=engagement.id, run_profile_name=source_run.profile.name)
    if deployment is not None and deployment.pack is not None:
        bind_pack_to_run(session, run=retest_run, pack=deployment.pack)

    retest_metadata = dict(stored_configuration.get("retest", {}))
    write_audit_event(
        session=session,
        actor=actor,
        action="run.requested",
        object_type="run",
        object_id=str(retest_run.id),
        metadata={
            "engagement_id": str(engagement.id),
            "profile_name": source_run.profile.name,
            "single_finding_retest": True,
            "source_finding_id": str(finding.id),
            "source_run_id": str(source_run.id),
            "bound_pack_id": str(retest_run.bound_pack_id) if retest_run.bound_pack_id else None,
            "bound_pack_version": retest_run.bound_pack_version,
            "secret_binding_count": len(created_secret_refs),
        },
    )

    queued_tasks = []
    if required_approvals(source_run.profile) == 0:
        queued_tasks = queue_run_tasks(session, retest_run, scope, source_run.profile)
        for task in queued_tasks:
            task_params = dict(task.params_json or {})
            task_params["retest"] = retest_metadata
            task.params_json = task_params
        write_audit_event(
            session=session,
            actor=actor,
            action="run.queued",
            object_type="run",
            object_id=str(retest_run.id),
            metadata={
                "engagement_id": str(engagement.id),
                "profile_name": source_run.profile.name,
                "single_finding_retest": True,
                "source_finding_id": str(finding.id),
            },
        )
    else:
        retest_run.status = "pending_approval"

    write_audit_event(
        session=session,
        actor=actor,
        action="finding.retest_requested",
        object_type="finding",
        object_id=str(finding.id),
        metadata={
            "source_run_id": str(source_run.id),
            "retest_run_id": str(retest_run.id),
            "profile_name": source_run.profile.name,
            "retest_status": retest_run.status,
        },
    )
    session.commit()
    session.refresh(retest_run)

    return FindingRetestRead(
        retest_run_id=retest_run.id,
        source_finding_id=finding.id,
        source_run_id=source_run.id,
        status=retest_run.status,
        profile_name=source_run.profile.name,
        queued_task_ids=[task.id for task in queued_tasks],
        configuration_json=dict(retest_run.configuration_json or {}),
    )


@router.put("/findings/{finding_id}/remediation", response_model=FindingRemediationRead)
def upsert_finding_remediation(
    finding_id: UUID,
    payload: FindingRemediationUpdate,
    session: Session = Depends(get_session),
    actor: str = Depends(get_current_actor),
) -> FindingRemediationRead:
    finding = session.scalar(select(Finding).where(Finding.id == finding_id))
    if finding is None:
        raise HTTPException(status_code=404, detail="finding not found")

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
    session.commit()
    session.refresh(remediation)

    return FindingRemediationRead.model_validate(remediation)


@router.patch("/findings/{finding_id}", response_model=FindingRead)
def update_finding(
    finding_id: UUID,
    payload: FindingUpdate,
    session: Session = Depends(get_session),
    actor: str = Depends(get_current_actor),
) -> FindingRead:
    finding = session.scalar(select(Finding).where(Finding.id == finding_id))
    if finding is None:
        raise HTTPException(status_code=404, detail="finding not found")

    previous_status = finding.status
    finding.status = payload.status

    write_audit_event(
        session=session,
        actor=actor,
        action="finding.updated",
        object_type="finding",
        object_id=str(finding.id),
        metadata={"previous_status": previous_status, "status": finding.status},
    )
    session.commit()
    session.refresh(finding)

    return FindingRead.model_validate(finding)
