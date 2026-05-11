from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from api.app.config import Settings
from api.app.models import (
    AuditEvent,
    Engagement,
    ExposureScore,
    Finding,
    Run,
    ScheduledRun,
)
from api.app.schemas.dashboard import (
    DashboardActiveRunRead,
    DashboardActivityFeedItemRead,
    DashboardBlastRadiusRead,
    DashboardEngagementSummaryRead,
    DashboardFirstRunOnboardingCardRead,
    DashboardFirstRunOnboardingRead,
    DashboardOpenProblemsRead,
    DashboardQuickActionRead,
    DashboardRead,
    DashboardRecentActivityRead,
    DashboardRiskHistoryPointRead,
    DashboardRiskScoreRead,
    DashboardSetupChecklistItemRead,
    DashboardUpcomingScanRead,
)
from api.app.services.attack_paths import build_attack_path_summary_for_loaded_run
from api.app.services.business_impact import BUSINESS_IMPACT_MODEL_VERSION, summarize_blast_radius
from api.app.services.exposure_score import (
    CLOSED_FINDING_STATUSES,
    SCORE_NORMALIZATION_WEIGHT,
    SEVERITY_WEIGHTS,
)
from api.app.services.finding_sla import apply_findings_sla
from api.app.services.settings import read_instance_settings
from api.app.services.tenancy import engagement_query_for_tenant, load_engagement_for_tenant
from api.app.services.zero_day_response import build_zero_day_rapid_response

ACTIVE_RUN_STATUSES = {"pending_approval", "queued", "running", "cancelling"}
TERMINAL_RUN_STATUSES = {"completed", "completed_with_errors", "failed", "cancelled", "rejected"}
OPEN_PROBLEM_SEVERITIES = {"critical", "high", "medium"}
SEVERITY_ORDER = ("critical", "high", "medium", "low", "info", "unknown")

AUDIT_ACTIVITY_LABELS = {
    "assessment_chain.phase_approved": ("Phase approved", "check"),
    "assessment_chain.phase_continued": ("Assessment continued", "play"),
    "assessment_chain.run_launched": ("Phase run launched", "play"),
    "engagement.authorization_confirmed": ("Authorization confirmed", "shield"),
    "engagement.created": ("Engagement created", "plus"),
    "finding.created": ("Finding created", "alert"),
    "finding.false_positive_marked": ("False positive recorded", "check"),
    "finding.remediation.updated": ("Remediation updated", "wrench"),
    "finding.status_changed": ("Finding status changed", "alert"),
    "finding.updated": ("Finding updated", "alert"),
    "finding.validation.queued": ("Validation queued", "check"),
    "finding.validation.reviewed": ("Validation reviewed", "check"),
    "report.generated": ("Report generated", "report"),
    "run.cancelled": ("Run cancelled", "stop"),
    "run.dispatched": ("Run started", "play"),
    "run.pack_bound": ("Pack bound", "pack"),
    "run.queued": ("Run queued", "clock"),
    "run.requested": ("Run requested", "play"),
}


def _utc(value: datetime | None = None) -> datetime:
    if value is None:
        return datetime.now(tz=UTC)
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _normalized_severity(value: str | None) -> str:
    normalized = str(value or "unknown").strip().lower()
    return normalized if normalized in SEVERITY_WEIGHTS else "unknown"


def _is_closed_finding(finding: Finding) -> bool:
    status = str(finding.status or "").strip().lower()
    remediation = finding.remediation
    remediation_state = str(remediation.state or "").strip().lower() if remediation else ""
    return status in CLOSED_FINDING_STATUSES or remediation_state == "verified"


def _activity_time(*values: datetime | None) -> datetime:
    for value in values:
        if value is not None:
            return _utc(value)
    return _utc()


def _sort_time(value: datetime | None) -> tuple[datetime, str]:
    normalized = _utc(value)
    return (normalized, normalized.isoformat())


def _phase_label(run: Run) -> str:
    chain = run.assessment_chain
    if chain is None:
        return run.profile.name if run.profile is not None else "Assessment"
    phases = list(chain.phases_json or [])
    if not phases:
        return str(chain.assessment_mode or "Assessment")
    index = max(0, min(chain.current_phase_index, len(phases) - 1))
    phase = phases[index]
    return str(phase.get("label") or phase.get("title") or phase.get("key") or "Assessment")


def _phase_progress_label(run: Run) -> str:
    chain = run.assessment_chain
    if chain is None:
        tasks = list(run.tasks or [])
        completed = sum(1 for task in tasks if str(task.status).lower() == "completed")
        return f"{completed}/{len(tasks)} tasks complete" if tasks else "No tasks queued"
    phases = list(chain.phases_json or [])
    if not phases:
        return f"Step {chain.current_step_index + 1}"
    return f"Phase {chain.current_phase_index + 1}/{len(phases)}"


def _engagements(
    session: Session,
    tenant_id: str | None,
    engagement_id: UUID | None = None,
) -> list[Engagement]:
    if engagement_id is not None:
        return [load_engagement_for_tenant(session, engagement_id, tenant_id)]
    return list(session.scalars(engagement_query_for_tenant(session, tenant_id)).all())


def _active_runs(session: Session, engagement_ids: list[UUID]) -> list[Run]:
    if not engagement_ids:
        return []
    return list(
        session.scalars(
            select(Run)
            .options(
                selectinload(Run.engagement),
                selectinload(Run.profile),
                selectinload(Run.tasks),
                selectinload(Run.findings).selectinload(Finding.remediation),
                selectinload(Run.assessment_chain),
            )
            .where(
                Run.engagement_id.in_(engagement_ids),
                Run.deleted_at.is_(None),
            )
            .order_by(Run.updated_at.desc(), Run.created_at.desc(), Run.id.desc())
        ).all()
    )


def _open_findings(session: Session, engagement_ids: list[UUID]) -> list[Finding]:
    if not engagement_ids:
        return []
    findings = list(
        session.scalars(
            select(Finding)
            .join(Run, Finding.run_id == Run.id)
            .options(
                selectinload(Finding.remediation),
                selectinload(Finding.run).selectinload(Run.engagement),
            )
            .where(
                Run.engagement_id.in_(engagement_ids),
                Run.deleted_at.is_(None),
            )
            .order_by(Finding.updated_at.desc(), Finding.created_at.desc(), Finding.id.desc())
        ).all()
    )
    return [finding for finding in findings if not _is_closed_finding(finding)]


def _active_run_tile(runs: list[Run]) -> DashboardActiveRunRead | None:
    active_run = next((run for run in runs if str(run.status).lower() in ACTIVE_RUN_STATUSES), None)
    if active_run is None:
        return None
    tasks = list(active_run.tasks or [])
    findings = list(active_run.findings or [])
    findings_by_severity = {severity: 0 for severity in SEVERITY_ORDER}
    for finding in findings:
        severity = _normalized_severity(finding.severity)
        findings_by_severity[severity] += 1
    return DashboardActiveRunRead(
        id=active_run.id,
        engagement_id=active_run.engagement_id,
        engagement_name=active_run.engagement.name if active_run.engagement is not None else "Engagement",
        profile_name=active_run.profile.name if active_run.profile is not None else "Unknown profile",
        status=active_run.status,
        phase_label=_phase_label(active_run),
        phase_progress_label=_phase_progress_label(active_run),
        tasks_total=len(tasks),
        tasks_running=sum(1 for task in tasks if str(task.status).lower() in {"queued", "running"}),
        tasks_completed=sum(1 for task in tasks if str(task.status).lower() == "completed"),
        finding_count=len(findings),
        findings_by_severity=findings_by_severity,
        updated_at=_activity_time(active_run.updated_at, active_run.created_at),
    )


def _open_problem_tile(open_findings: list[Finding]) -> DashboardOpenProblemsRead:
    counts = {"critical": 0, "high": 0, "medium": 0}
    overdue_counts = {"critical": 0, "high": 0}
    for finding in open_findings:
        severity = _normalized_severity(finding.severity)
        if severity in counts:
            counts[severity] += 1
        if severity in overdue_counts and bool(finding.sla_breached):
            overdue_counts[severity] += 1
    return DashboardOpenProblemsRead(
        critical=counts["critical"],
        high=counts["high"],
        medium=counts["medium"],
        total=sum(1 for finding in open_findings if _normalized_severity(finding.severity) in OPEN_PROBLEM_SEVERITIES),
        overdue_critical_count=overdue_counts["critical"],
        overdue_high_count=overdue_counts["high"],
    )


def _computed_risk_score(open_findings: list[Finding]) -> tuple[float, dict[str, int]]:
    severity_breakdown = {severity: 0 for severity in SEVERITY_ORDER}
    open_weight = 0.0
    for finding in open_findings:
        severity = _normalized_severity(finding.severity)
        severity_breakdown[severity] += 1
        open_weight += SEVERITY_WEIGHTS[severity]
    score = min(100.0, round((open_weight / SCORE_NORMALIZATION_WEIGHT) * 100.0, 1))
    return score, severity_breakdown


def _trend(previous_score: float | None, current_score: float) -> str:
    if previous_score is None:
        return "stable"
    if current_score < previous_score - 0.1:
        return "improving"
    if current_score > previous_score + 0.1:
        return "worsening"
    return "stable"


def _risk_tile(
    session: Session,
    engagement_ids: list[UUID],
    open_findings: list[Finding],
    generated_at: datetime,
) -> DashboardRiskScoreRead:
    score, severity_breakdown = _computed_risk_score(open_findings)
    history_rows: list[ExposureScore] = []
    if engagement_ids:
        history_rows = list(
            session.scalars(
                select(ExposureScore)
                .where(ExposureScore.engagement_id.in_(engagement_ids))
                .order_by(ExposureScore.computed_at.desc(), ExposureScore.id.desc())
                .limit(7)
            ).all()
        )
    history = [
        DashboardRiskHistoryPointRead(
            run_id=row.run_id,
            score=float(row.score),
            trend=row.trend,
            computed_at=_utc(row.computed_at),
        )
        for row in reversed(history_rows)
    ]
    if not history:
        history = [
            DashboardRiskHistoryPointRead(
                run_id=None,
                score=score,
                trend="stable",
                computed_at=generated_at,
            )
        ]
    previous = history[-2].score if len(history) > 1 else None
    trend = _trend(previous, score)
    if history[-1].computed_at < generated_at:
        history.append(
            DashboardRiskHistoryPointRead(
                run_id=history[-1].run_id,
                score=score,
                trend=trend,
                computed_at=generated_at,
            )
        )
    return DashboardRiskScoreRead(
        score=score,
        trend=trend,
        severity_breakdown=severity_breakdown,
        history=history[-8:],
        advisory_note=(
            "Risk score is advisory only. It summarizes stored finding posture and does not gate "
            "approval, deployment, or runtime binding decisions."
        ),
    )


def _blast_radius_tile(session: Session, engagement_ids: list[UUID]) -> DashboardBlastRadiusRead:
    if not engagement_ids:
        return DashboardBlastRadiusRead(
            model=BUSINESS_IMPACT_MODEL_VERSION,
            advisory_note="Blast radius is advisory only and requires stored inventory, findings, and attack-path evidence.",
        )

    runs = list(
        session.scalars(
            select(Run)
            .options(
                selectinload(Run.engagement).selectinload(Engagement.inventory_snapshots),
                selectinload(Run.findings),
            )
            .where(Run.engagement_id.in_(engagement_ids), Run.deleted_at.is_(None))
            .order_by(Run.updated_at.desc(), Run.created_at.desc(), Run.id.desc())
            .limit(12)
        ).all()
    )
    paths: list[dict[str, object]] = []
    for run in runs:
        summary = build_attack_path_summary_for_loaded_run(run)
        paths.extend(
            path
            for path in summary.get("candidate_paths", [])
            if isinstance(path, dict) and isinstance(path.get("business_impact"), dict)
        )

    summary = summarize_blast_radius(paths)  # type: ignore[arg-type]
    return DashboardBlastRadiusRead(
        model=str(summary["model"]),
        score=float(summary["score"]),
        tier=str(summary["tier"]),
        critical_path_count=int(summary["critical_path_count"]),
        affected_business_processes=list(summary["affected_business_processes"]),
        highest_impact_path_id=(
            str(summary["highest_impact_path_id"]) if summary.get("highest_impact_path_id") else None
        ),
        financial_exposure=str(summary.get("financial_exposure") or "") or None,
        operational_impact=str(summary.get("operational_impact") or "") or None,
        review_only=True,
        advisory_note=(
            "Blast radius is advisory only. It summarizes stored business tags, inventory, findings, "
            "and attack paths without changing approval, scope, or runtime behavior."
        ),
    )


def _eta_label(now: datetime, next_run_at: datetime) -> str:
    target = _utc(next_run_at)
    delta = target - now
    seconds = int(delta.total_seconds())
    if seconds <= 0:
        return "Due now"
    minutes = seconds // 60
    if minutes < 60:
        return f"In {max(minutes, 1)}m"
    hours = minutes // 60
    if hours < 48:
        return f"In {hours}h"
    return f"In {hours // 24}d"


def _upcoming_scans(
    session: Session,
    engagement_ids: list[UUID],
    engagement_names: dict[UUID, str],
    generated_at: datetime,
) -> list[DashboardUpcomingScanRead]:
    if not engagement_ids:
        return []
    rows = list(
        session.scalars(
            select(ScheduledRun)
            .where(
                ScheduledRun.engagement_id.in_(engagement_ids),
                ScheduledRun.status == "enabled",
                ScheduledRun.paused_at.is_(None),
            )
            .order_by(ScheduledRun.next_run_at.asc(), ScheduledRun.id.asc())
            .limit(5)
        ).all()
    )
    return [
        DashboardUpcomingScanRead(
            id=row.id,
            engagement_id=row.engagement_id,
            engagement_name=engagement_names.get(row.engagement_id, "Engagement"),
            profile_name=row.profile_name,
            cadence=row.cadence,
            status=row.status,
            next_run_at=_utc(row.next_run_at),
            eta_label=_eta_label(generated_at, row.next_run_at),
        )
        for row in rows
    ]


def _recent_activity(runs: list[Run], open_findings: list[Finding]) -> list[DashboardRecentActivityRead]:
    activities: list[DashboardRecentActivityRead] = []
    for run in runs[:12]:
        engagement = run.engagement
        profile = run.profile.name if run.profile is not None else "Unknown profile"
        label = "Run updated"
        if str(run.status).lower() in TERMINAL_RUN_STATUSES:
            label = "Run completed" if run.status == "completed" else "Run stopped"
        elif str(run.status).lower() in ACTIVE_RUN_STATUSES:
            label = "Run active"
        activities.append(
            DashboardRecentActivityRead(
                id=f"run:{run.id}",
                activity_type="run",
                label=label,
                detail=f"{profile} - {run.status}",
                happened_at=_activity_time(run.updated_at, run.created_at),
                engagement_id=run.engagement_id,
                engagement_name=engagement.name if engagement is not None else None,
                run_id=run.id,
                status=run.status,
            )
        )
    for finding in open_findings[:12]:
        run = finding.run
        engagement = run.engagement if run is not None else None
        severity = _normalized_severity(finding.severity)
        activities.append(
            DashboardRecentActivityRead(
                id=f"finding:{finding.id}",
                activity_type="finding",
                label=f"Open {severity} finding",
                detail=f"{finding.title} - {finding.target_id}",
                happened_at=_activity_time(finding.updated_at, finding.created_at),
                engagement_id=run.engagement_id if run is not None else None,
                engagement_name=engagement.name if engagement is not None else None,
                run_id=run.id if run is not None else None,
                finding_id=finding.id,
                severity=severity,
                status=finding.status,
            )
        )
    activities.sort(key=lambda item: (_sort_time(item.happened_at), item.id), reverse=True)
    return activities[:10]


def _humanized_audit_label(action: str) -> tuple[str, str]:
    if action in AUDIT_ACTIVITY_LABELS:
        return AUDIT_ACTIVITY_LABELS[action]
    cleaned = action.replace("_", " ").replace(".", " ").strip()
    label = " ".join(part.capitalize() for part in cleaned.split()) or "Activity recorded"
    return label, "activity"


def _audit_detail(event: AuditEvent) -> str:
    metadata = dict(event.metadata_json or {})
    candidates = [
        metadata.get("profile_name"),
        metadata.get("status"),
        metadata.get("state"),
        metadata.get("new_status"),
        metadata.get("decision"),
        metadata.get("provider"),
        metadata.get("name"),
    ]
    detail_parts = [str(value) for value in candidates if value is not None and value != ""]
    if detail_parts:
        return " · ".join(detail_parts[:2])
    return f"{event.object_type} {event.object_id}"


def _activity_feed(
    session: Session,
    engagement_ids: list[UUID],
    engagement_names: dict[UUID, str],
    runs: list[Run],
) -> list[DashboardActivityFeedItemRead]:
    if not engagement_ids:
        return []

    run_ids = [run.id for run in runs]
    object_ids = {str(engagement_id) for engagement_id in engagement_ids}
    object_ids.update(str(run_id) for run_id in run_ids)
    if run_ids:
        finding_ids = session.scalars(select(Finding.id).where(Finding.run_id.in_(run_ids))).all()
        object_ids.update(str(finding_id) for finding_id in finding_ids)

    if not object_ids:
        return []

    events = list(
        session.scalars(
            select(AuditEvent)
            .where(AuditEvent.object_id.in_(sorted(object_ids)))
            .order_by(AuditEvent.created_at.desc(), AuditEvent.id.desc())
            .limit(10)
        ).all()
    )
    run_engagement_by_id = {run.id: run.engagement_id for run in runs}
    finding_engagement_by_id: dict[str, UUID] = {}
    if run_ids:
        rows = session.execute(
            select(Finding.id, Finding.run_id).where(Finding.run_id.in_(run_ids))
        ).all()
        finding_engagement_by_id = {
            str(finding_id): run_engagement_by_id[run_id]
            for finding_id, run_id in rows
            if run_id in run_engagement_by_id
        }

    feed: list[DashboardActivityFeedItemRead] = []
    for event in events:
        label, icon = _humanized_audit_label(event.action)
        engagement_id: UUID | None = None
        if event.object_type == "engagement":
            try:
                engagement_id = UUID(str(event.object_id))
            except ValueError:
                engagement_id = None
        elif event.object_type == "run":
            try:
                engagement_id = run_engagement_by_id.get(UUID(str(event.object_id)))
            except ValueError:
                engagement_id = None
        elif event.object_type == "finding":
            engagement_id = finding_engagement_by_id.get(str(event.object_id))
        metadata_engagement_id = (event.metadata_json or {}).get("engagement_id")
        if engagement_id is None and metadata_engagement_id:
            try:
                engagement_id = UUID(str(metadata_engagement_id))
            except ValueError:
                engagement_id = None

        feed.append(
            DashboardActivityFeedItemRead(
                id=str(event.id),
                timestamp=_utc(event.created_at),
                label=label,
                icon=icon,
                engagement_name=engagement_names.get(engagement_id) if engagement_id else None,
                detail=_audit_detail(event),
            )
        )
    return feed


def _quick_actions(open_problem_total: int, has_engagements: bool) -> list[DashboardQuickActionRead]:
    return [
        DashboardQuickActionRead(
            id="new-mission",
            label="New Mission",
            target_screen="wizard",
            enabled=True,
            description="Start a scoped engagement through the guided intake.",
        ),
        DashboardQuickActionRead(
            id="open-problems",
            label="Open Problems",
            target_screen="problems-center",
            enabled=open_problem_total > 0,
            description="Review critical, high, and medium open findings.",
        ),
        DashboardQuickActionRead(
            id="reports",
            label="Reports",
            target_screen="report-center",
            enabled=has_engagements,
            description="Open report drafts and export-ready run material.",
        ),
        DashboardQuickActionRead(
            id="mission-control",
            label="Mission Control",
            target_screen="mission-control",
            enabled=has_engagements,
            description="Inspect the selected run, tasks, evidence, and AI signal.",
        ),
    ]


def _settings_map(session: Session, tenant_id: str | None, settings: Settings) -> dict[str, object]:
    settings_read = read_instance_settings(session, tenant_id=tenant_id, settings=settings)
    values: dict[str, object] = {}
    for section in settings_read.sections:
        for setting in section.settings:
            values[setting.key] = setting.value
    return values


def _setting_bool(values: dict[str, object], key: str) -> bool:
    value = values.get(key)
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _completed_scan_exists(runs: list[Run]) -> bool:
    return any(str(run.status or "").strip().lower() == "completed" for run in runs)


def _finding_review_count(session: Session, engagement_ids: list[UUID]) -> int:
    if not engagement_ids:
        return 0
    return int(
        session.scalar(
            select(Finding.id)
            .join(Run, Finding.run_id == Run.id)
            .where(
                Run.engagement_id.in_(engagement_ids),
                Run.deleted_at.is_(None),
                Run.status == "completed",
            )
            .limit(1)
        )
        is not None
    )


def _setup_checklist(
    *,
    session: Session,
    tenant_id: str | None,
    settings: Settings,
    has_engagements: bool,
    engagement_ids: list[UUID],
    runs: list[Run],
) -> list[DashboardSetupChecklistItemRead]:
    values = _settings_map(session, tenant_id, settings)
    if _setting_bool(values, "instance.setup_checklist_dismissed") or not has_engagements:
        return []

    ai_provider = str(values.get("ai.provider") or "disabled").strip().lower()
    reviewed_finding_count = _finding_review_count(session, engagement_ids)
    return [
        DashboardSetupChecklistItemRead(
            id="ai-provider",
            label="AI provider",
            done=ai_provider not in {"", "disabled"},
            detail="Configured" if ai_provider not in {"", "disabled"} else "Disabled until configured",
        ),
        DashboardSetupChecklistItemRead(
            id="first-mission",
            label="First mission",
            done=has_engagements,
            detail="Engagement inventory exists" if has_engagements else "Create a scoped engagement",
        ),
        DashboardSetupChecklistItemRead(
            id="first-run",
            label="First completed scan",
            done=_completed_scan_exists(runs),
            detail="At least one scan completed" if _completed_scan_exists(runs) else "Launch and finish a safe run",
        ),
        DashboardSetupChecklistItemRead(
            id="problem-review",
            label="Review first finding",
            done=reviewed_finding_count > 0,
            detail="A completed run has findings ready for review" if reviewed_finding_count else "Open Findings after the first completed scan stores evidence",
        ),
    ]


def _first_run_onboarding(
    *,
    values: dict[str, object],
    has_engagements: bool,
    runs: list[Run],
) -> DashboardFirstRunOnboardingRead | None:
    if has_engagements or _completed_scan_exists(runs):
        return None

    ai_provider = str(values.get("ai.provider") or "disabled").strip().lower()
    ai_selected = ai_provider == "chatgpt_oauth"
    return DashboardFirstRunOnboardingRead(
        show=True,
        title="Start AegisPT in three steps",
        detail="Connect optional AI, create a scoped engagement, then run the first safe scan.",
        cards=[
            DashboardFirstRunOnboardingCardRead(
                id="chatgpt-oauth",
                label="Connect ChatGPT OAuth",
                done=False,
                detail=(
                    "ChatGPT OAuth is selected. Connect it per engagement after mission creation."
                    if ai_selected
                    else "Optional AI features stay disabled until you choose ChatGPT OAuth in Settings."
                ),
                target_screen="settings",
            ),
            DashboardFirstRunOnboardingCardRead(
                id="create-engagement",
                label="Create your first engagement",
                done=False,
                detail="Use Intake to define scope, authorization, and the initial target.",
                target_screen="wizard",
            ),
            DashboardFirstRunOnboardingCardRead(
                id="run-first-scan",
                label="Run your first scan",
                done=False,
                detail="After mission creation, launch a safe scan and review the live run from Mission Control.",
                target_screen="wizard",
            ),
        ],
    )


def _engagement_summaries(
    engagements: list[Engagement],
    runs: list[Run],
    open_findings: list[Finding],
) -> list[DashboardEngagementSummaryRead]:
    runs_by_engagement: dict[UUID, list[Run]] = {}
    for run in runs:
        runs_by_engagement.setdefault(run.engagement_id, []).append(run)

    findings_by_engagement: dict[UUID, list[Finding]] = {}
    for finding in open_findings:
        if finding.run is not None:
            findings_by_engagement.setdefault(finding.run.engagement_id, []).append(finding)

    summaries: list[DashboardEngagementSummaryRead] = []
    for engagement in engagements:
        engagement_runs = sorted(
            runs_by_engagement.get(engagement.id, []),
            key=lambda run: (_sort_time(run.updated_at), str(run.id)),
            reverse=True,
        )
        engagement_findings = findings_by_engagement.get(engagement.id, [])
        risk_score, severity_breakdown = _computed_risk_score(engagement_findings)
        latest_run = engagement_runs[0] if engagement_runs else None
        summaries.append(
            DashboardEngagementSummaryRead(
                id=engagement.id,
                name=engagement.name,
                client=engagement.client,
                last_run_at=_activity_time(latest_run.updated_at, latest_run.created_at) if latest_run else None,
                last_run_status=latest_run.status if latest_run else None,
                risk_score=risk_score,
                open_critical_count=severity_breakdown["critical"],
                open_high_count=severity_breakdown["high"],
                run_count=len(engagement_runs),
            )
        )
    summaries.sort(
        key=lambda item: (
            item.last_run_at or _activity_time(datetime.min),
            item.open_critical_count,
            item.open_high_count,
            item.name,
        ),
        reverse=True,
    )
    return summaries[:6]


def build_dashboard(
    session: Session,
    *,
    tenant_id: str | None,
    settings: Settings,
    engagement_id: UUID | None = None,
) -> DashboardRead:
    generated_at = _utc()
    engagements = _engagements(session, tenant_id, engagement_id=engagement_id)
    engagement_ids = [engagement.id for engagement in engagements]
    engagement_names = {engagement.id: engagement.name for engagement in engagements}
    runs = _active_runs(session, engagement_ids)
    open_findings = _open_findings(session, engagement_ids)
    setting_values = _settings_map(session, tenant_id, settings)
    if apply_findings_sla(session, open_findings, settings=settings, generated_at=generated_at, tenant_id=tenant_id):
        session.commit()
    open_problems = _open_problem_tile(open_findings)

    return DashboardRead(
        generated_at=generated_at,
        has_engagements=bool(engagements),
        active_run=_active_run_tile(runs),
        risk_score=_risk_tile(session, engagement_ids, open_findings, generated_at),
        blast_radius=_blast_radius_tile(session, engagement_ids),
        zero_day_rapid_response=build_zero_day_rapid_response(session, engagements=engagements),
        open_problems=open_problems,
        upcoming_scans=_upcoming_scans(session, engagement_ids, engagement_names, generated_at),
        recent_activity=_recent_activity(runs, open_findings),
        activity_feed=_activity_feed(session, engagement_ids, engagement_names, runs),
        quick_actions=_quick_actions(open_problems.total, bool(engagements)),
        setup_checklist_dismissed=_setting_bool(setting_values, "instance.setup_checklist_dismissed"),
        setup_checklist=_setup_checklist(
            session=session,
            tenant_id=tenant_id,
            settings=settings,
            has_engagements=bool(engagements),
            engagement_ids=engagement_ids,
            runs=runs,
        ),
        first_run_onboarding=_first_run_onboarding(
            values=setting_values,
            has_engagements=bool(engagements),
            runs=runs,
        ),
        engagements=_engagement_summaries(engagements, runs, open_findings),
    )
