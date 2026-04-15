from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.app.auth import get_current_actor
from api.app.db import get_session
from api.app.models import Finding
from api.app.schemas.finding_views import FindingEvidenceReplayRead, FindingTheaterRead
from api.app.schemas.findings import FindingRead, FindingUpdate
from api.app.services.audit import write_audit_event
from api.app.services.finding_views import build_finding_evidence_replay, build_finding_theater

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
