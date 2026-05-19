from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from api.app.models import ExposureScore, Finding, Run

SEVERITY_WEIGHTS = {
    "critical": 10.0,
    "high": 5.0,
    "medium": 2.0,
    "low": 0.5,
    "info": 0.0,
    "unknown": 0.0,
}
CLOSED_FINDING_STATUSES = {"resolved", "accepted_risk", "false_positive"}
REMEDIATED_REMEDIATION_STATES = {"ready_for_retest", "verified"}
VERIFIED_REMEDIATION_STATES = {"verified"}
SCORE_NORMALIZATION_WEIGHT = 40.0
REMEDIATED_PROGRESS_CREDIT = 0.5
VERIFIED_PROGRESS_CREDIT = 1.5


def _utc(value: datetime | None) -> datetime:
    if value is None:
        return datetime.now(tz=UTC)
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _normalized_severity(value: str | None) -> str:
    normalized = str(value or "unknown").strip().lower()
    return normalized if normalized in SEVERITY_WEIGHTS else "unknown"


def _finding_key(finding: Finding) -> tuple[str, str]:
    return (
        str(finding.title or "").strip().lower(),
        str(finding.target_id or "").strip().lower(),
    )


def _latest_findings(findings: list[Finding]) -> list[Finding]:
    latest_by_key: dict[tuple[str, str], Finding] = {}
    for finding in findings:
        key = _finding_key(finding)
        existing = latest_by_key.get(key)
        if existing is None:
            latest_by_key[key] = finding
            continue
        existing_sort = (_utc(existing.updated_at), _utc(existing.created_at), str(existing.id))
        candidate_sort = (_utc(finding.updated_at), _utc(finding.created_at), str(finding.id))
        if candidate_sort > existing_sort:
            latest_by_key[key] = finding
    return list(latest_by_key.values())


def _remediation_state(finding: Finding) -> str:
    remediation = finding.remediation
    if remediation is None or not remediation.state:
        return ""
    return str(remediation.state).strip().lower()


def _is_verified(finding: Finding) -> bool:
    return _remediation_state(finding) in VERIFIED_REMEDIATION_STATES


def _is_remediated(finding: Finding) -> bool:
    if _remediation_state(finding) in REMEDIATED_REMEDIATION_STATES:
        return True
    return str(finding.status or "").strip().lower() == "resolved"


def _is_closed(finding: Finding) -> bool:
    if _is_verified(finding):
        return True
    return str(finding.status or "").strip().lower() in CLOSED_FINDING_STATUSES


def _load_findings(session: Session, engagement_id: UUID) -> list[Finding]:
    return session.scalars(
        select(Finding)
        .join(Run, Finding.run_id == Run.id)
        .options(selectinload(Finding.remediation))
        .where(Run.engagement_id == engagement_id, Run.deleted_at.is_(None))
    ).all()


def _history_query(engagement_id: UUID):
    return (
        select(ExposureScore)
        .where(ExposureScore.engagement_id == engagement_id)
        .order_by(ExposureScore.computed_at.desc(), ExposureScore.id.desc())
    )


def latest_exposure_score(session: Session, engagement_id: UUID) -> ExposureScore | None:
    return session.scalar(_history_query(engagement_id).limit(1))


def list_exposure_score_history(session: Session, engagement_id: UUID, *, limit: int = 10) -> list[ExposureScore]:
    return session.scalars(_history_query(engagement_id).limit(limit)).all()


def _latest_run_id_for_engagement(session: Session, engagement_id: UUID) -> UUID | None:
    latest_run = session.scalar(
        select(Run)
        .where(Run.engagement_id == engagement_id, Run.deleted_at.is_(None))
        .order_by(Run.updated_at.desc(), Run.created_at.desc(), Run.id.desc())
        .limit(1)
    )
    return latest_run.id if latest_run is not None else None


def _compute_snapshot(findings: list[Finding]) -> dict[str, object]:
    latest = _latest_findings(findings)
    severity_breakdown = {severity: 0 for severity in SEVERITY_WEIGHTS}
    open_weight = 0.0
    remediated_count = 0
    verified_count = 0
    for finding in latest:
        severity = _normalized_severity(finding.severity)
        if _is_verified(finding):
            verified_count += 1
        if _is_remediated(finding):
            remediated_count += 1
        if _is_closed(finding):
            continue
        severity_breakdown[severity] += 1
        open_weight += SEVERITY_WEIGHTS[severity]

    progress_credit = (
        verified_count * VERIFIED_PROGRESS_CREDIT
        + max(remediated_count - verified_count, 0) * REMEDIATED_PROGRESS_CREDIT
    )
    net_weight = max(0.0, open_weight - progress_credit)
    score = min(100.0, round((net_weight / SCORE_NORMALIZATION_WEIGHT) * 100.0, 1))
    return {
        "score": score,
        "severity_breakdown": severity_breakdown,
        "open_critical_count": int(severity_breakdown["critical"]),
        "open_high_count": int(severity_breakdown["high"]),
        "remediated_count": int(remediated_count),
        "verified_count": int(verified_count),
    }


def _trend(previous_score: float | None, current_score: float) -> str:
    if previous_score is None:
        return "stable"
    if current_score < previous_score - 0.1:
        return "improving"
    if current_score > previous_score + 0.1:
        return "worsening"
    return "stable"


def record_exposure_score(
    session: Session,
    *,
    engagement_id: UUID,
    run_id: UUID | None = None,
    computed_at: datetime | None = None,
) -> ExposureScore:
    session.flush()
    previous = latest_exposure_score(session, engagement_id)
    snapshot = _compute_snapshot(_load_findings(session, engagement_id))
    timestamp = _utc(computed_at)
    exposure = ExposureScore(
        engagement_id=engagement_id,
        run_id=run_id if run_id is not None else _latest_run_id_for_engagement(session, engagement_id),
        score=float(snapshot["score"]),
        severity_breakdown_json=dict(snapshot["severity_breakdown"]),
        open_critical_count=int(snapshot["open_critical_count"]),
        open_high_count=int(snapshot["open_high_count"]),
        remediated_count=int(snapshot["remediated_count"]),
        verified_count=int(snapshot["verified_count"]),
        trend=_trend(previous.score if previous is not None else None, float(snapshot["score"])),
        computed_at=timestamp,
        created_at=timestamp,
        updated_at=timestamp,
    )
    session.add(exposure)
    session.flush()
    return exposure


def ensure_exposure_score(session: Session, engagement_id: UUID) -> ExposureScore:
    current = latest_exposure_score(session, engagement_id)
    if current is not None:
        return current
    return record_exposure_score(session, engagement_id=engagement_id)
