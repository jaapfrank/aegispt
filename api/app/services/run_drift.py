from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from api.app.models import Finding, Run, RunDrift
from api.app.services.audit import write_audit_event
from api.app.services.exposure_score import CLOSED_FINDING_STATUSES, SEVERITY_WEIGHTS

DRIFT_ELIGIBLE_RUN_STATUSES = {"completed", "completed_with_errors"}


def _utc_now() -> datetime:
    return datetime.now(tz=UTC)


def _finding_fingerprint(finding: Finding) -> tuple[str, str]:
    return (
        str(finding.title or "").strip().lower(),
        str(finding.target_id or "").strip().lower(),
    )


def _open_finding_fingerprints(findings: list[Finding]) -> set[tuple[str, str]]:
    return {
        _finding_fingerprint(finding)
        for finding in findings
        if str(finding.status or "").strip().lower() not in CLOSED_FINDING_STATUSES
    }


def _exposure_for_findings(findings: list[Finding]) -> float:
    weight = 0.0
    for finding in findings:
        if str(finding.status or "").strip().lower() in CLOSED_FINDING_STATUSES:
            continue
        severity = str(finding.severity or "unknown").strip().lower()
        weight += float(SEVERITY_WEIGHTS.get(severity, 0.0))
    return min(100.0, round((weight / 40.0) * 100.0, 1))


def _load_run_for_drift(session: Session, run_id: UUID) -> Run | None:
    return session.scalar(
        select(Run)
        .options(selectinload(Run.findings), selectinload(Run.profile), selectinload(Run.drift_summary))
        .where(Run.id == run_id, Run.deleted_at.is_(None))
    )


def _previous_completed_run(session: Session, run: Run) -> Run | None:
    if run.profile_id is None:
        return None
    return session.scalar(
        select(Run)
        .options(selectinload(Run.findings), selectinload(Run.profile))
        .where(
            Run.id != run.id,
            Run.engagement_id == run.engagement_id,
            Run.profile_id == run.profile_id,
            Run.deleted_at.is_(None),
            Run.status.in_(DRIFT_ELIGIBLE_RUN_STATUSES),
        )
        .order_by(Run.created_at.desc(), Run.updated_at.desc(), Run.id.desc())
        .limit(1)
    )


def compute_run_drift(
    session: Session,
    *,
    run_id: UUID,
    actor: str = "system:drift",
    computed_at: datetime | None = None,
) -> RunDrift | None:
    session.flush()
    run = _load_run_for_drift(session, run_id)
    if run is None or str(run.status or "").lower() not in DRIFT_ELIGIBLE_RUN_STATUSES:
        return None

    previous = _previous_completed_run(session, run)
    if previous is None:
        return None

    current_open = _open_finding_fingerprints(list(run.findings or []))
    previous_open = _open_finding_fingerprints(list(previous.findings or []))
    current_exposure = _exposure_for_findings(list(run.findings or []))
    previous_exposure = _exposure_for_findings(list(previous.findings or []))

    drift = run.drift_summary
    if drift is None:
        drift = RunDrift(run_id=run.id, previous_run_id=previous.id, computed_at=computed_at or _utc_now())
        session.add(drift)

    drift.previous_run_id = previous.id
    drift.new_finding_count = len(current_open - previous_open)
    drift.resolved_finding_count = len(previous_open - current_open)
    drift.exposure_delta = round(current_exposure - previous_exposure, 1)
    drift.computed_at = computed_at or _utc_now()
    session.flush()

    write_audit_event(
        session=session,
        actor=actor,
        action="run.drift_computed",
        object_type="run",
        object_id=str(run.id),
        metadata={
            "previous_run_id": str(previous.id),
            "new_finding_count": drift.new_finding_count,
            "resolved_finding_count": drift.resolved_finding_count,
            "exposure_delta": drift.exposure_delta,
        },
    )
    return drift
