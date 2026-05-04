from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from api.app.config import Settings
from api.app.models import Engagement, Finding, FindingRemediation, Run
from api.app.schemas.problems import (
    ProblemBulkSkippedRead,
    ProblemBulkUpdateCreate,
    ProblemBulkUpdateRead,
    ProblemEngagementOptionRead,
    ProblemFilterOptionsRead,
    ProblemLifecycleStepRead,
    ProblemRead,
    ProblemsRead,
    ProblemsStatsRead,
)
from api.app.services.audit import write_audit_event
from api.app.services.exposure_score import record_exposure_score
from api.app.services.finding_retests import (
    FindingRetestRequestError,
    request_single_finding_retest,
)

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info", "unknown")
PROBLEM_STATUSES = ("open", "in_progress", "resolved", "verified", "reoccurred")
AGE_BUCKETS = ("overdue", "due_soon", "recent")
DEFAULT_SEVERITIES = {"critical", "high"}
DEFAULT_STATUSES = {"open"}


class ProblemBulkDeleteUnsupportedError(ValueError):
    pass


@dataclass(frozen=True)
class ProblemFilters:
    severities: set[str] | None
    statuses: set[str] | None
    engagement_id: UUID | None
    assignee: str | None
    age: str | None
    methodology: str | None
    cursor: str | None
    limit: int


def _utc(value: datetime | None = None) -> datetime:
    if value is None:
        return datetime.now(tz=UTC)
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _normalized_severity(value: str | None) -> str:
    normalized = str(value or "unknown").strip().lower()
    return normalized if normalized in SEVERITY_ORDER else "unknown"


def _normalize_status(value: str | None) -> str:
    normalized = str(value or "open").strip().lower().replace("-", "_")
    return normalized if normalized in PROBLEM_STATUSES else "open"


def _age_bucket(days_open: int) -> str:
    if days_open >= 30:
        return "overdue"
    if days_open >= 23:
        return "due_soon"
    return "recent"


def _days_between(start: datetime | None, end: datetime | None) -> int:
    started = _utc(start)
    ended = _utc(end)
    return max(0, int((ended - started).total_seconds() // 86400))


def _problem_status(finding: Finding) -> str:
    finding_status = str(finding.status or "open").strip().lower()
    remediation_state = str(finding.remediation.state or "").strip().lower() if finding.remediation else ""
    if finding_status in {"open", "reopened"} and remediation_state == "verified":
        return "reoccurred"
    if remediation_state == "verified":
        return "verified"
    if finding_status == "resolved":
        return "resolved"
    if finding_status in {"in_progress", "triaged"} or remediation_state in {
        "planned",
        "in_progress",
        "ready_for_retest",
        "blocked",
    }:
        return "in_progress"
    return "open"


def _verification_label(problem_status: str, remediation_state: str, latest_retest: Run | None) -> str:
    if problem_status == "verified":
        return "Verified"
    if problem_status == "reoccurred":
        return "Reoccurred after verification"
    if latest_retest is not None:
        return f"Latest retest {latest_retest.status}"
    if remediation_state == "ready_for_retest":
        return "Ready for retest"
    if problem_status == "resolved":
        return "Resolved, verification pending"
    return "Unverified"


def _lifecycle(problem_status: str) -> list[ProblemLifecycleStepRead]:
    steps = [
        ("open", "Open"),
        ("in_progress", "In Progress"),
        ("resolved", "Resolved"),
        ("verified", "Verified"),
    ]
    rank = {key: index for index, (key, _label) in enumerate(steps)}
    if problem_status == "reoccurred":
        return [
            *(ProblemLifecycleStepRead(key=key, label=label, state="done") for key, label in steps),
            ProblemLifecycleStepRead(key="reoccurred", label="Reoccurred", state="warning"),
        ]
    current_rank = rank.get(problem_status, 0)
    return [
        ProblemLifecycleStepRead(
            key=key,
            label=label,
            state="current" if key == problem_status else "done" if index < current_rank else "pending",
        )
        for index, (key, label) in enumerate(steps)
    ]


def _encode_cursor(offset: int) -> str | None:
    if offset <= 0:
        return None
    return base64.urlsafe_b64encode(str(offset).encode("ascii")).decode("ascii").rstrip("=")


def _decode_cursor(cursor: str | None) -> int:
    if not cursor:
        return 0
    padded = cursor + "=" * (-len(cursor) % 4)
    try:
        return max(0, int(base64.urlsafe_b64decode(padded.encode("ascii")).decode("ascii")))
    except (ValueError, UnicodeDecodeError):
        return 0


def _load_problem_findings(session: Session, tenant_id: str | None) -> list[Finding]:
    statement = (
        select(Finding)
        .join(Run, Finding.run_id == Run.id)
        .join(Engagement, Run.engagement_id == Engagement.id)
        .options(
            selectinload(Finding.run).selectinload(Run.engagement),
            selectinload(Finding.run).selectinload(Run.profile),
            selectinload(Finding.remediation),
        )
        .where(Run.deleted_at.is_(None), Engagement.deleted_at.is_(None))
        .order_by(Finding.updated_at.desc(), Finding.created_at.desc(), Finding.id.desc())
    )
    if tenant_id is not None:
        statement = statement.where(Engagement.tenant_id == tenant_id)
    return list(session.scalars(statement).all())


def _load_retests_by_finding(session: Session, tenant_id: str | None) -> dict[str, list[Run]]:
    statement = (
        select(Run)
        .join(Engagement, Run.engagement_id == Engagement.id)
        .options(selectinload(Run.profile))
        .where(Run.deleted_at.is_(None), Engagement.deleted_at.is_(None))
        .order_by(Run.created_at.desc(), Run.id.desc())
    )
    if tenant_id is not None:
        statement = statement.where(Engagement.tenant_id == tenant_id)

    linked: dict[str, list[Run]] = {}
    for run in session.scalars(statement).all():
        configuration = run.configuration_json if isinstance(run.configuration_json, dict) else {}
        retest = configuration.get("retest") if isinstance(configuration.get("retest"), dict) else None
        if not retest:
            continue
        source_finding_id = retest.get("source_finding_id")
        if isinstance(source_finding_id, str) and source_finding_id:
            linked.setdefault(source_finding_id, []).append(run)
    return linked


def _problem_from_finding(
    *,
    finding: Finding,
    generated_at: datetime,
    latest_retest: Run | None,
) -> ProblemRead:
    run = finding.run
    if run is None or run.engagement is None:
        raise ValueError("problem finding is missing run engagement context")
    problem_status = _problem_status(finding)
    remediation = finding.remediation
    remediation_state = remediation.state if remediation is not None else "not_started"
    closed_at = finding.updated_at if problem_status in {"resolved", "verified"} else generated_at
    days_open = _days_between(finding.created_at, closed_at)
    return ProblemRead(
        id=finding.id,
        finding_id=finding.id,
        run_id=run.id,
        engagement_id=run.engagement_id,
        engagement_name=run.engagement.name,
        title=finding.title,
        severity=_normalized_severity(finding.severity),
        target_id=finding.target_id,
        status=finding.status,
        problem_status=problem_status,  # type: ignore[arg-type]
        assignee=remediation.owner if remediation is not None else None,
        days_open=days_open,
        age_bucket=_age_bucket(days_open),
        remediation_state=remediation_state,
        verification_status=_verification_label(problem_status, remediation_state, latest_retest),
        methodology_tags=list(finding.methodology_tags or []),
        latest_retest_run_id=latest_retest.id if latest_retest is not None else None,
        latest_retest_status=latest_retest.status if latest_retest is not None else None,
        lifecycle=_lifecycle(problem_status),
        created_at=_utc(finding.created_at),
        updated_at=_utc(finding.updated_at),
    )


def _sort_key(problem: ProblemRead) -> tuple[int, int, str, str]:
    severity_rank = SEVERITY_ORDER.index(problem.severity) if problem.severity in SEVERITY_ORDER else 99
    return (severity_rank, -problem.days_open, problem.title.lower(), str(problem.finding_id))


def _matches(problem: ProblemRead, filters: ProblemFilters) -> bool:
    if filters.engagement_id is not None and problem.engagement_id != filters.engagement_id:
        return False
    if filters.severities is not None and problem.severity not in filters.severities:
        return False
    if filters.statuses is not None and problem.problem_status not in filters.statuses:
        return False
    if filters.assignee is not None:
        wanted = filters.assignee.strip().lower()
        actual = (problem.assignee or "unassigned").strip().lower()
        if actual != wanted:
            return False
    if filters.age is not None and problem.age_bucket != filters.age:
        return False
    if filters.methodology is not None and filters.methodology not in set(problem.methodology_tags or []):
        return False
    return True


def _stats(problems: list[ProblemRead], generated_at: datetime) -> ProblemsStatsRead:
    week_start = generated_at - timedelta(days=7)
    month_start = generated_at - timedelta(days=30)
    open_items = [item for item in problems if item.problem_status in {"open", "in_progress", "reoccurred"}]
    severity_counts = {severity: 0 for severity in SEVERITY_ORDER}
    problem_status_counts = {status: 0 for status in PROBLEM_STATUSES}
    finding_status_counts: dict[str, int] = {}
    for item in problems:
        severity_counts[item.severity] = severity_counts.get(item.severity, 0) + 1
        problem_status_counts[item.problem_status] = problem_status_counts.get(item.problem_status, 0) + 1
        finding_status_counts[item.status] = finding_status_counts.get(item.status, 0) + 1
    recent_resolved = [
        item
        for item in problems
        if item.problem_status in {"resolved", "verified"} and item.updated_at >= month_start
    ]
    resolved_this_week = [
        item
        for item in problems
        if item.problem_status in {"resolved", "verified"} and item.updated_at >= week_start
    ]
    avg_days = (
        round(sum(item.days_open for item in recent_resolved) / len(recent_resolved), 1)
        if recent_resolved
        else 0.0
    )
    return ProblemsStatsRead(
        open_critical=sum(1 for item in open_items if item.severity == "critical"),
        open_high=sum(1 for item in open_items if item.severity == "high"),
        open_medium=sum(1 for item in open_items if item.severity == "medium"),
        avg_days_to_resolve_30d=avg_days,
        resolved_this_week=len(resolved_this_week),
        total_findings=len(problems),
        total_filtered=len(problems),
        total_open=sum(1 for item in problems if item.problem_status == "open"),
        total_in_progress=sum(1 for item in problems if item.problem_status == "in_progress"),
        total_resolved=sum(1 for item in problems if item.problem_status == "resolved"),
        total_verified=sum(1 for item in problems if item.problem_status == "verified"),
        total_false_positive=sum(1 for item in problems if item.status == "false_positive"),
        by_severity=severity_counts,
        by_problem_status=problem_status_counts,
        by_finding_status=finding_status_counts,
        total_recently_resolved=len(recent_resolved),
    )


def _filter_options(problems: list[ProblemRead]) -> ProblemFilterOptionsRead:
    engagement_options: dict[UUID, str] = {}
    assignees: set[str] = set()
    methodologies: set[str] = set()
    for problem in problems:
        engagement_options[problem.engagement_id] = problem.engagement_name
        if problem.assignee:
            assignees.add(problem.assignee)
        methodologies.update(problem.methodology_tags or [])
    return ProblemFilterOptionsRead(
        engagements=[
            ProblemEngagementOptionRead(id=engagement_id, name=name)
            for engagement_id, name in sorted(engagement_options.items(), key=lambda item: item[1].lower())
        ],
        assignees=sorted(assignees, key=str.lower),
        methodologies=sorted(methodologies),
        severities=list(SEVERITY_ORDER),
        statuses=list(PROBLEM_STATUSES),
        age_buckets=list(AGE_BUCKETS),
    )


def build_problems_center(
    *,
    session: Session,
    tenant_id: str | None,
    filters: ProblemFilters,
) -> ProblemsRead:
    generated_at = _utc()
    retests_by_finding = _load_retests_by_finding(session, tenant_id)
    problems = [
        _problem_from_finding(
            finding=finding,
            generated_at=generated_at,
            latest_retest=(retests_by_finding.get(str(finding.id)) or [None])[0],
        )
        for finding in _load_problem_findings(session, tenant_id)
    ]
    problems = sorted(problems, key=_sort_key)
    filtered = [problem for problem in problems if _matches(problem, filters)]
    stats = _stats(problems, generated_at)
    stats.total_filtered = len(filtered)
    offset = _decode_cursor(filters.cursor)
    page = filtered[offset : offset + filters.limit]
    next_offset = offset + filters.limit
    recently_resolved = [
        problem
        for problem in problems
        if problem.problem_status in {"resolved", "verified"} and problem.updated_at >= generated_at - timedelta(days=30)
    ][:20]
    return ProblemsRead(
        generated_at=generated_at,
        items=page,
        recently_resolved=recently_resolved,
        stats=stats,
        filters=_filter_options(problems),
        lifecycle_summary={
            "total_findings": len(problems),
            "visible_findings": len(filtered),
            "default_scope": "open critical/high problems"
            if filters.severities == set(DEFAULT_SEVERITIES) and filters.statuses == set(DEFAULT_STATUSES)
            else "filtered problems",
            "count_truth": (
                "Problems is a finding lifecycle view. Its default list is intentionally filtered, "
                "while stats.total_findings records all tenant-visible findings in the same scope."
            ),
        },
        next_cursor=_encode_cursor(next_offset) if next_offset < len(filtered) else None,
    )


def _ensure_remediation(
    *,
    session: Session,
    finding: Finding,
    actor: str,
) -> FindingRemediation:
    if finding.remediation is not None:
        return finding.remediation
    remediation = session.scalar(select(FindingRemediation).where(FindingRemediation.finding_id == finding.id))
    if remediation is not None:
        finding.remediation = remediation
        return remediation
    remediation = FindingRemediation(
        finding_id=finding.id,
        state="not_started",
        created_by=actor,
        updated_by=actor,
    )
    session.add(remediation)
    session.flush()
    finding.remediation = remediation
    return remediation


def _record_exposure_for_finding(session: Session, finding: Finding) -> None:
    if finding.run_id is None:
        return
    engagement_id = session.scalar(select(Run.engagement_id).where(Run.id == finding.run_id))
    if engagement_id is None:
        return
    record_exposure_score(session=session, engagement_id=engagement_id, run_id=finding.run_id)


def _apply_problem_status(
    *,
    finding: Finding,
    remediation: FindingRemediation,
    problem_status: str,
) -> tuple[str, str]:
    previous_status = finding.status
    previous_state = remediation.state
    if problem_status == "open":
        finding.status = "open"
        remediation.state = "not_started"
    elif problem_status == "in_progress":
        finding.status = "in_progress"
        remediation.state = "in_progress"
    elif problem_status == "resolved":
        finding.status = "resolved"
        remediation.state = "ready_for_retest"
    elif problem_status == "verified":
        finding.status = "resolved"
        remediation.state = "verified"
    elif problem_status == "reoccurred":
        finding.status = "open"
        remediation.state = "in_progress"
    return previous_status, previous_state


def _load_bulk_findings(
    *,
    session: Session,
    finding_ids: list[UUID],
    tenant_id: str | None,
) -> dict[UUID, Finding]:
    statement = (
        select(Finding)
        .join(Run, Finding.run_id == Run.id)
        .join(Engagement, Run.engagement_id == Engagement.id)
        .options(
            selectinload(Finding.run).selectinload(Run.engagement),
            selectinload(Finding.run).selectinload(Run.profile),
            selectinload(Finding.remediation),
        )
        .where(
            Finding.id.in_(finding_ids),
            Run.deleted_at.is_(None),
            Engagement.deleted_at.is_(None),
        )
    )
    if tenant_id is not None:
        statement = statement.where(Engagement.tenant_id == tenant_id)
    return {finding.id: finding for finding in session.scalars(statement).all()}


def bulk_update_problems(
    *,
    session: Session,
    payload: ProblemBulkUpdateCreate,
    actor: str,
    settings: Settings,
    tenant_id: str | None,
) -> ProblemBulkUpdateRead:
    if payload.action == "delete":
        raise ProblemBulkDeleteUnsupportedError(
            "Finding delete is blocked because this task forbids adding finding schema fields and no finding soft-delete marker exists yet."
        )

    unique_ids = list(dict.fromkeys(payload.finding_ids))
    findings_by_id = _load_bulk_findings(session=session, finding_ids=unique_ids, tenant_id=tenant_id)
    skipped = [
        ProblemBulkSkippedRead(finding_id=finding_id, reason="finding not found")
        for finding_id in unique_ids
        if finding_id not in findings_by_id
    ]
    updated_count = 0
    retest_run_ids: list[UUID] = []
    status_target = payload.status or ("resolved" if payload.action == "resolve" else None)

    for finding_id in unique_ids:
        finding = findings_by_id.get(finding_id)
        if finding is None:
            continue

        if payload.action == "schedule_retest":
            try:
                retest = request_single_finding_retest(
                    session=session,
                    finding=finding,
                    notes=payload.retest_notes,
                    actor=actor,
                    settings=settings,
                )
            except FindingRetestRequestError as exc:
                skipped.append(ProblemBulkSkippedRead(finding_id=finding.id, reason=str(exc)))
                continue
            retest_run_ids.append(retest.retest_run_id)
            updated_count += 1
            continue

        remediation = _ensure_remediation(session=session, finding=finding, actor=actor)
        previous_status = finding.status
        previous_state = remediation.state
        if payload.action == "assign":
            remediation.owner = payload.assignee
        elif payload.action in {"status", "resolve"} and status_target is not None:
            previous_status, previous_state = _apply_problem_status(
                finding=finding,
                remediation=remediation,
                problem_status=_normalize_status(status_target),
            )
            if payload.assignee is not None:
                remediation.owner = payload.assignee
        remediation.updated_by = actor
        remediation.updated_at = _utc()
        finding.updated_at = _utc()
        write_audit_event(
            session=session,
            actor=actor,
            action="problems.bulk_updated",
            object_type="finding",
            object_id=str(finding.id),
            metadata={
                "bulk_action": payload.action,
                "previous_status": previous_status,
                "status": finding.status,
                "previous_remediation_state": previous_state,
                "remediation_state": remediation.state,
                "assignee": remediation.owner,
            },
        )
        _record_exposure_for_finding(session, finding)
        updated_count += 1

    message = f"{updated_count} problem{'' if updated_count == 1 else 's'} updated."
    if payload.action == "schedule_retest":
        message = f"{len(retest_run_ids)} retest run{'' if len(retest_run_ids) == 1 else 's'} requested."
    return ProblemBulkUpdateRead(
        action=payload.action,
        requested_count=len(unique_ids),
        updated_count=updated_count,
        retest_run_ids=retest_run_ids,
        skipped=skipped,
        message=message,
    )
