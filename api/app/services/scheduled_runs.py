from __future__ import annotations

import copy
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from api.app.config import Settings
from api.app.models import Engagement, Run, RunProfile, ScheduledRun
from api.app.services.audit import write_audit_event
from api.app.services.packs import bind_pack_to_run, latest_pack_deployment
from api.app.services.run_profiles import ensure_default_run_profiles
from api.app.services.runs import (
    dispatch_queued_run_tasks,
    latest_scope_query,
    load_run,
    queue_run_tasks,
    required_approvals,
)
from api.app.services.secrets import materialize_run_configuration_secrets


@dataclass(frozen=True)
class PreparedScheduledRunLaunch:
    scheduled_run_id: UUID
    run_id: UUID
    run_status: str
    scheduled_due_at: datetime
    next_run_at: datetime


@dataclass(frozen=True)
class ScheduledRunDispatchResult:
    scheduled_run_id: UUID
    run_id: UUID
    run_status: str
    scheduled_due_at: datetime
    next_run_at: datetime
    dispatch_state: str
    dispatch_mode: str | None
    dispatched_task_ids: list[UUID]
    dispatch_error: str | None = None


def normalize_due_at(value: datetime | None) -> datetime:
    if value is None:
        return datetime.now(tz=UTC)
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value


def next_scheduled_run_at(current_next_run_at: datetime, cadence: str, due_at: datetime) -> datetime:
    interval = {
        "daily": timedelta(days=1),
        "weekly": timedelta(weeks=1),
    }.get(cadence)
    if interval is None:
        raise ValueError(f"unsupported schedule cadence: {cadence}")

    next_run_at = current_next_run_at
    if next_run_at.tzinfo is None:
        next_run_at = next_run_at.replace(tzinfo=UTC)
    while next_run_at <= due_at:
        next_run_at += interval
    return next_run_at


def _scheduled_run_configuration(
    scheduled_run: ScheduledRun,
    *,
    scheduled_due_at: datetime,
) -> dict[str, object]:
    configuration = copy.deepcopy(scheduled_run.configuration_json or {})
    schedule_context = configuration.get("schedule")
    if not isinstance(schedule_context, dict):
        schedule_context = {}
    schedule_context.update(
        {
            "scheduled_run_id": str(scheduled_run.id),
            "cadence": scheduled_run.cadence,
            "cron_expression": scheduled_run.cron_expression,
            "scheduled_due_at": scheduled_due_at.isoformat(),
            "source": "scheduled-validation",
        }
    )
    configuration["schedule"] = schedule_context
    return configuration


def prepare_due_scheduled_run_launches(
    session: Session,
    *,
    engagement_id: UUID,
    actor: str,
    settings: Settings,
    due_at: datetime | None = None,
) -> list[PreparedScheduledRunLaunch]:
    ensure_default_run_profiles(session)
    normalized_due_at = normalize_due_at(due_at)

    engagement = session.scalar(
        select(Engagement).where(
            Engagement.id == engagement_id,
            Engagement.deleted_at.is_(None),
        )
    )
    if engagement is None:
        return []

    scope = session.scalar(latest_scope_query(engagement.id))
    if scope is None:
        return []

    scheduled_runs = session.scalars(
        select(ScheduledRun)
        .where(
            ScheduledRun.engagement_id == engagement.id,
            ScheduledRun.status == "enabled",
            ScheduledRun.paused_at.is_(None),
            ScheduledRun.next_run_at <= normalized_due_at,
        )
        .order_by(ScheduledRun.next_run_at.asc(), ScheduledRun.id.asc())
    ).all()

    launches: list[PreparedScheduledRunLaunch] = []
    for scheduled_run in scheduled_runs:
        profile = session.scalar(select(RunProfile).where(RunProfile.name == scheduled_run.profile_name))
        if profile is None:
            continue
        if profile.run_class != "passive":
            write_audit_event(
                session=session,
                actor=actor,
                action="scheduled_run.skipped_non_passive_profile",
                object_type="scheduled_run",
                object_id=str(scheduled_run.id),
                metadata={
                    "engagement_id": str(engagement.id),
                    "profile_name": profile.name,
                    "run_class": profile.run_class,
                },
            )
            continue

        scheduled_due_at = normalize_due_at(scheduled_run.next_run_at)
        configuration, created_secret_refs = materialize_run_configuration_secrets(
            session,
            engagement_id=engagement.id,
            configuration=_scheduled_run_configuration(scheduled_run, scheduled_due_at=scheduled_due_at),
            settings=settings,
        )
        timestamp = datetime.now(tz=UTC)
        run = Run(
            engagement_id=engagement.id,
            profile_id=profile.id,
            profile=profile,
            source_inventory_snapshot_id=scheduled_run.source_inventory_snapshot_id,
            requested_by=actor,
            status="requested",
            configuration_json=configuration,
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
                "scheduled_run_id": str(scheduled_run.id),
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
                metadata={
                    "engagement_id": str(engagement.id),
                    "profile_name": profile.name,
                    "scheduled_run_id": str(scheduled_run.id),
                },
            )
        else:
            run.status = "pending_approval"

        scheduled_run.last_run_at = scheduled_due_at
        scheduled_run.last_launched_run_id = run.id
        scheduled_run.next_run_at = next_scheduled_run_at(scheduled_due_at, scheduled_run.cadence, normalized_due_at)
        scheduled_run.updated_by = actor

        write_audit_event(
            session=session,
            actor=actor,
            action="scheduled_run.launched",
            object_type="scheduled_run",
            object_id=str(scheduled_run.id),
            metadata={
                "engagement_id": str(engagement.id),
                "run_id": str(run.id),
                "scheduled_due_at": scheduled_due_at.isoformat(),
                "next_run_at": scheduled_run.next_run_at.isoformat(),
            },
        )

        launches.append(
            PreparedScheduledRunLaunch(
                scheduled_run_id=scheduled_run.id,
                run_id=run.id,
                run_status=run.status,
                scheduled_due_at=scheduled_due_at,
                next_run_at=scheduled_run.next_run_at,
            )
        )

    session.flush()
    return launches


def launch_due_scheduled_runs_for_engagement(
    session: Session,
    *,
    engagement_id: UUID,
    actor: str,
    settings: Settings,
    due_at: datetime | None = None,
) -> list[ScheduledRunDispatchResult]:
    prepared_launches = prepare_due_scheduled_run_launches(
        session,
        engagement_id=engagement_id,
        actor=actor,
        settings=settings,
        due_at=due_at,
    )
    session.commit()

    results: list[ScheduledRunDispatchResult] = []
    for prepared in prepared_launches:
        dispatch_state = "not_dispatchable"
        dispatch_mode = None
        dispatched_task_ids: list[UUID] = []
        dispatch_error = None

        run = load_scheduled_launch_run(session, prepared.run_id)
        if run is not None and run.status == "queued":
            try:
                dispatch_mode, dispatched_task_ids = dispatch_queued_run_tasks(
                    session,
                    run=run,
                    actor=actor,
                    settings=settings,
                )
                dispatch_state = "dispatched"
            except ValueError as exc:
                dispatch_state = "blocked"
                dispatch_error = str(exc)
            session.commit()
            session.expire_all()
            run = load_scheduled_launch_run(session, prepared.run_id)

        results.append(
            ScheduledRunDispatchResult(
                scheduled_run_id=prepared.scheduled_run_id,
                run_id=prepared.run_id,
                run_status=run.status if run is not None else prepared.run_status,
                scheduled_due_at=prepared.scheduled_due_at,
                next_run_at=prepared.next_run_at,
                dispatch_state=dispatch_state,
                dispatch_mode=dispatch_mode,
                dispatched_task_ids=dispatched_task_ids,
                dispatch_error=dispatch_error,
            )
        )
    return results


def launch_due_scheduled_runs_for_all_engagements(
    session: Session,
    *,
    actor: str,
    settings: Settings,
    due_at: datetime | None = None,
) -> list[ScheduledRunDispatchResult]:
    normalized_due_at = normalize_due_at(due_at)
    engagement_ids = list(
        session.scalars(
            select(ScheduledRun.engagement_id)
            .join(Engagement, ScheduledRun.engagement_id == Engagement.id)
            .where(
                Engagement.deleted_at.is_(None),
                ScheduledRun.status == "enabled",
                ScheduledRun.paused_at.is_(None),
                ScheduledRun.next_run_at <= normalized_due_at,
            )
            .distinct()
            .order_by(ScheduledRun.engagement_id)
        ).all()
    )
    results: list[ScheduledRunDispatchResult] = []
    for engagement_id in engagement_ids:
        results.extend(
            launch_due_scheduled_runs_for_engagement(
                session,
                engagement_id=engagement_id,
                actor=actor,
                settings=settings,
                due_at=normalized_due_at,
            )
        )
    return results


def run_scheduled_scan_tick(app: Any, settings: Settings) -> list[ScheduledRunDispatchResult]:
    session_factory: sessionmaker[Session] | None = getattr(app.state, "session_factory", None)
    if session_factory is None:
        return []
    with session_factory() as session:
        return launch_due_scheduled_runs_for_all_engagements(
            session,
            actor="system:scheduler",
            settings=settings,
        )


def start_scheduled_run_scheduler(app: Any, settings: Settings) -> dict[str, Any]:
    try:
        from apscheduler.schedulers.background import BackgroundScheduler
        from apscheduler.triggers.interval import IntervalTrigger
    except Exception as exc:  # pragma: no cover - dependency failure path is environment-specific.
        status = {"enabled": False, "reason": f"APScheduler unavailable: {exc}"}
        app.state.scheduled_run_scheduler_status = status
        return status

    scheduler = BackgroundScheduler()
    scheduler.add_job(
        run_scheduled_scan_tick,
        trigger=IntervalTrigger(minutes=1),
        args=[app, settings],
        id="aegispt-scheduled-runs",
        replace_existing=True,
        max_instances=1,
        coalesce=True,
    )
    scheduler.start()
    app.state.scheduled_run_scheduler = scheduler
    status = {"enabled": True, "interval": "1 minute"}
    app.state.scheduled_run_scheduler_status = status
    return status


def stop_scheduled_run_scheduler(app: Any) -> None:
    scheduler = getattr(app.state, "scheduled_run_scheduler", None)
    if scheduler is not None:
        scheduler.shutdown(wait=False)
        app.state.scheduled_run_scheduler = None


def load_scheduled_launch_run(session: Session, run_id: UUID) -> Run | None:
    return load_run(session, run_id)
