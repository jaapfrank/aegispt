from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from api.app.models import Finding, FindingRemediation, Run
from api.app.schemas.finding_views import (
    RemediationPortfolioItemRead,
    RemediationPortfolioPolicyRead,
    RemediationPortfolioRead,
    RemediationPortfolioSummaryRead,
    RemediationRetestPlanGroupRead,
    RemediationRetestPlanRead,
    RemediationRetestReferenceRead,
)
from api.app.schemas.findings import FindingRead
from api.app.services.runs import required_approvals

ACTIVE_RETEST_STATUSES = {"requested", "pending_approval", "queued", "running", "dispatching"}
RETRYABLE_RETEST_STATUSES = {"failed", "cancelled", "completed_with_errors"}
VERIFIED_FINDING_STATUSES = {"resolved", "accepted_risk", "false_positive"}


def _utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _iso_sort_key(value: RemediationPortfolioItemRead) -> tuple[int, datetime, str]:
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
    rank = severity_order.get(value.finding.severity, severity_order["unknown"])
    due_at = _utc(value.sla_due_at) or datetime.max.replace(tzinfo=UTC)
    return (rank, due_at, value.finding.title.lower())


def _format_owner(owner: str | None) -> str:
    value = (owner or "").strip()
    return value if value else "unassigned"


def _load_findings(session: Session, engagement_id: UUID) -> list[Finding]:
    return session.scalars(
        select(Finding)
        .join(Run, Finding.run_id == Run.id)
        .options(
            selectinload(Finding.run).selectinload(Run.profile),
            selectinload(Finding.remediation),
        )
        .where(Run.engagement_id == engagement_id, Run.deleted_at.is_(None))
        .order_by(Finding.created_at.desc(), Finding.id.desc())
    ).all()


def _load_retests_by_finding(session: Session, engagement_id: UUID) -> dict[str, list[Run]]:
    runs = session.scalars(
        select(Run)
        .options(selectinload(Run.profile), selectinload(Run.tasks))
        .where(Run.engagement_id == engagement_id, Run.deleted_at.is_(None))
        .order_by(Run.created_at.desc(), Run.id.desc())
    ).all()
    linked: dict[str, list[Run]] = {}
    for run in runs:
        configuration = run.configuration_json if isinstance(run.configuration_json, dict) else {}
        retest = configuration.get("retest")
        if not isinstance(retest, dict):
            continue
        source_finding_id = retest.get("source_finding_id")
        if not isinstance(source_finding_id, str) or not source_finding_id:
            continue
        linked.setdefault(source_finding_id, []).append(run)
    return linked


def _retest_reference(run: Run) -> RemediationRetestReferenceRead:
    configuration = run.configuration_json if isinstance(run.configuration_json, dict) else {}
    retest = configuration.get("retest") if isinstance(configuration.get("retest"), dict) else {}
    tasks = list(run.tasks or [])
    return RemediationRetestReferenceRead(
        run_id=run.id,
        status=run.status,
        profile_name=run.profile.name if run.profile is not None else configuration.get("execution_profile"),
        verification_state=str(retest.get("verification_state") or "requested"),
        requested_at=_utc(run.created_at),
        updated_at=_utc(run.updated_at),
        task_counts={
            "queued": sum(1 for task in tasks if task.status == "queued"),
            "running": sum(1 for task in tasks if task.status == "running"),
            "completed": sum(1 for task in tasks if task.status == "completed"),
            "failed": sum(1 for task in tasks if task.status == "failed"),
        },
    )


def _sla_status(
    *,
    finding: Finding,
    remediation: FindingRemediation | None,
    sla_days: int,
    due_soon_days: int,
    generated_at: datetime,
) -> tuple[str, datetime | None, datetime | None, str]:
    state = remediation.state if remediation is not None else "not_started"
    if state == "verified" or finding.status in VERIFIED_FINDING_STATUSES:
        return ("verified", _utc(remediation.created_at if remediation else finding.created_at), None, "Verified or closed items are excluded from SLA pressure.")
    if state == "blocked":
        return ("blocked", _utc(remediation.created_at if remediation else finding.created_at), None, "Remediation is explicitly blocked and needs owner action.")

    started_at = _utc(remediation.created_at if remediation is not None else finding.created_at)
    if started_at is None:
        return ("unknown", None, None, "SLA status is unavailable because no start timestamp is recorded.")

    due_at = started_at + timedelta(days=sla_days)
    due_soon_at = due_at - timedelta(days=due_soon_days)
    if generated_at > due_at:
        return ("overdue", started_at, due_at, f"Past the configured {sla_days}-day portfolio SLA window.")
    if generated_at >= due_soon_at:
        return ("due_soon", started_at, due_at, f"Within {due_soon_days} days of the configured SLA target.")
    return ("on_track", started_at, due_at, "Within the configured portfolio SLA target.")


def _verification_state(
    *,
    finding: Finding,
    remediation: FindingRemediation | None,
    latest_retest: Run | None,
) -> str:
    state = remediation.state if remediation is not None else "not_started"
    if state == "verified" or finding.status == "resolved":
        return "verified"
    if state == "blocked":
        return "blocked"
    if latest_retest is not None and latest_retest.status == "completed":
        return "proof_ready"
    if latest_retest is not None and latest_retest.status in ACTIVE_RETEST_STATUSES:
        return "retest_pending"
    if state == "ready_for_retest":
        return "awaiting_retest"
    return "remediation_pending"


def _eligible_for_retest(
    *,
    finding: Finding,
    remediation: FindingRemediation | None,
    latest_retest: Run | None,
) -> tuple[bool, str]:
    state = remediation.state if remediation is not None else "not_started"
    if finding.status in VERIFIED_FINDING_STATUSES:
        return (False, "Finding status is already closed or accepted; portfolio planning will not create another retest.")
    if state != "ready_for_retest":
        return (False, "Remediation state must be ready_for_retest before batch planning can include it.")
    if latest_retest is None:
        return (True, "Ready for an explicit operator-requested retest plan; no linked retest exists yet.")
    if latest_retest.status in ACTIVE_RETEST_STATUSES:
        return (False, f"A linked retest is already {latest_retest.status}; wait for approval or completion.")
    if latest_retest.status == "completed":
        return (False, "A completed retest already exists; review proof-of-resolution before planning another retest.")
    if latest_retest.status in RETRYABLE_RETEST_STATUSES:
        return (True, f"The latest linked retest ended as {latest_retest.status}; explicit replanning is allowed.")
    return (False, f"Latest retest status {latest_retest.status} is not eligible for automatic inclusion.")


def _portfolio_item(
    *,
    finding: Finding,
    retests: list[Run],
    sla_days: int,
    due_soon_days: int,
    generated_at: datetime,
) -> RemediationPortfolioItemRead:
    remediation = finding.remediation
    latest_retest = retests[0] if retests else None
    eligible, retest_reason = _eligible_for_retest(
        finding=finding,
        remediation=remediation,
        latest_retest=latest_retest,
    )
    sla_status, started_at, due_at, sla_detail = _sla_status(
        finding=finding,
        remediation=remediation,
        sla_days=sla_days,
        due_soon_days=due_soon_days,
        generated_at=generated_at,
    )
    run = finding.run
    return RemediationPortfolioItemRead(
        finding=FindingRead.model_validate(finding),
        run_id=run.id,
        run_status=run.status,
        profile_name=run.profile.name if run.profile is not None else None,
        remediation_state=remediation.state if remediation is not None else "not_started",
        remediation_owner=remediation.owner if remediation is not None else None,
        remediation_notes=remediation.notes if remediation is not None else None,
        remediation_updated_at=_utc(remediation.updated_at if remediation is not None else None),
        sla_started_at=started_at,
        sla_due_at=due_at,
        sla_status=sla_status,
        sla_detail=sla_detail,
        verification_state=_verification_state(
            finding=finding,
            remediation=remediation,
            latest_retest=latest_retest,
        ),
        linked_retest_count=len(retests),
        latest_retest=_retest_reference(latest_retest) if latest_retest is not None else None,
        eligible_for_retest=eligible,
        retest_planning_reason=retest_reason,
        approval_required_count=required_approvals(run.profile) if run.profile is not None else 0,
    )


def _matches_filters(
    item: RemediationPortfolioItemRead,
    *,
    owner: str | None,
    remediation_state: str | None,
    sla_status: str | None,
    eligible_for_retest: bool | None,
    finding_ids: set[UUID] | None,
) -> bool:
    if finding_ids is not None and item.finding.id not in finding_ids:
        return False
    if owner is not None:
        wanted = owner.strip().lower()
        actual = _format_owner(item.remediation_owner).lower()
        if actual != wanted:
            return False
    if remediation_state is not None and item.remediation_state != remediation_state.strip().lower().replace("-", "_"):
        return False
    if sla_status is not None and item.sla_status != sla_status.strip().lower().replace("-", "_"):
        return False
    if eligible_for_retest is not None and item.eligible_for_retest is not eligible_for_retest:
        return False
    return True


def _summary(items: list[RemediationPortfolioItemRead]) -> RemediationPortfolioSummaryRead:
    by_state = Counter(item.remediation_state for item in items)
    by_sla = Counter(item.sla_status for item in items)
    by_owner = Counter(_format_owner(item.remediation_owner) for item in items)
    return RemediationPortfolioSummaryRead(
        total_items=len(items),
        by_remediation_state=dict(sorted(by_state.items())),
        by_sla_status=dict(sorted(by_sla.items())),
        by_owner=dict(sorted(by_owner.items())),
        eligible_for_retest=sum(1 for item in items if item.eligible_for_retest),
        blocked=sum(1 for item in items if item.sla_status == "blocked" or item.remediation_state == "blocked"),
        verified=sum(1 for item in items if item.verification_state == "verified"),
        overdue=sum(1 for item in items if item.sla_status == "overdue"),
        due_soon=sum(1 for item in items if item.sla_status == "due_soon"),
    )


def build_remediation_retest_plan(
    *,
    engagement_id: UUID,
    items: list[RemediationPortfolioItemRead],
    generated_at: datetime | None = None,
) -> RemediationRetestPlanRead:
    generated = generated_at or datetime.now(tz=UTC)
    eligible_items = [item for item in items if item.eligible_for_retest]
    excluded = [
        {
            "finding_id": str(item.finding.id),
            "title": item.finding.title,
            "reason": item.retest_planning_reason,
        }
        for item in items
        if not item.eligible_for_retest
    ]
    grouped: dict[tuple[UUID, str | None, int], list[RemediationPortfolioItemRead]] = {}
    for item in eligible_items:
        approvals = item.approval_required_count
        grouped.setdefault((item.run_id, item.profile_name, approvals), []).append(item)

    groups = [
        RemediationRetestPlanGroupRead(
            source_run_id=source_run_id,
            profile_name=profile_name,
            approval_required_count=approval_required_count,
            finding_ids=[item.finding.id for item in group_items],
            targets=sorted({item.finding.target_id for item in group_items}),
            next_operator_action=(
                f"Plan only: request {len(group_items)} single-finding retest(s) explicitly. "
                f"This profile requires {approval_required_count} approval(s) before dispatch."
            ),
        )
        for (source_run_id, profile_name, approval_required_count), group_items in sorted(
            grouped.items(),
            key=lambda entry: (str(entry[0][1] or ""), str(entry[0][0])),
        )
    ]
    return RemediationRetestPlanRead(
        engagement_id=engagement_id,
        generated_at=generated,
        approval_boundary=(
            "This is a planning-only portfolio grouping. It does not create runs, queue tasks, "
            "grant approvals, deploy packs, or bind runtime packs."
        ),
        groups=groups,
        excluded_items=excluded,
    )


def build_remediation_portfolio(
    *,
    session: Session,
    engagement_id: UUID,
    sla_days: int = 30,
    due_soon_days: int = 7,
    owner: str | None = None,
    remediation_state: str | None = None,
    sla_status: str | None = None,
    eligible_for_retest: bool | None = None,
    finding_ids: set[UUID] | None = None,
) -> RemediationPortfolioRead:
    generated_at = datetime.now(tz=UTC)
    retests_by_finding = _load_retests_by_finding(session, engagement_id)
    all_items = [
        _portfolio_item(
            finding=finding,
            retests=retests_by_finding.get(str(finding.id), []),
            sla_days=sla_days,
            due_soon_days=due_soon_days,
            generated_at=generated_at,
        )
        for finding in _load_findings(session, engagement_id)
    ]
    items = [
        item
        for item in all_items
        if _matches_filters(
            item,
            owner=owner,
            remediation_state=remediation_state,
            sla_status=sla_status,
            eligible_for_retest=eligible_for_retest,
            finding_ids=finding_ids,
        )
    ]
    items = sorted(items, key=_iso_sort_key)
    plan = build_remediation_retest_plan(
        engagement_id=engagement_id,
        items=items,
        generated_at=generated_at,
    )
    return RemediationPortfolioRead(
        engagement_id=engagement_id,
        generated_at=generated_at,
        policy=RemediationPortfolioPolicyRead(
            sla_days=sla_days,
            due_soon_days=due_soon_days,
            basis="remediation.created_at when present, otherwise finding.created_at",
            note="SLA labels are portfolio planning signals only; they are not contractual enforcement.",
        ),
        summary=_summary(items),
        items=items,
        retest_plan=plan,
    )
