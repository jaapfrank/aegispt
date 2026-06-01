from __future__ import annotations

import copy
import logging
import threading
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from api.app.config import Settings
from api.app.models import Engagement, Run, RunProfile, ScheduledRun
from api.app.models.control import Task
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

logger = logging.getLogger(__name__)

_TERMINAL_RUN_STATUSES = {"completed", "failed", "cancelled", "errored"}
# Aggressive sweep: dispatch tasks that have been queued for more than 3 seconds.
# This catches AI loop iterations where the worker's inline dispatch path didn't fire,
# closing the gap that otherwise forces operators to manually click "Start queue".
_QUEUED_TASK_STALE_SECONDS = 3
# At startup, any task still in 'running'/'dispatching' belongs to a dead worker
# (the previous API process died/restarted). Reset them so the sweeper redispatches.
_ORPHANED_TASK_STATUSES = ("running", "dispatching")


def reset_orphaned_tasks_at_startup(app: Any) -> int:
    """Reset tasks that were stuck running when the previous API process died.

    Called once at API startup. Resets status='running'/'dispatching' to 'queued'
    so the queue sweeper picks them up and redispatches them via a fresh worker.
    Without this, restarting the API leaves UI showing "scanning..." for tasks
    that no process is actually executing.
    """
    session_factory: sessionmaker[Session] | None = getattr(app.state, "session_factory", None)
    if session_factory is None:
        return 0
    try:
        with session_factory() as session:
            orphaned = list(
                session.scalars(
                    select(Task).where(Task.status.in_(list(_ORPHANED_TASK_STATUSES)))
                ).all()
            )
            if not orphaned:
                return 0
            now = datetime.now(tz=UTC)
            for t in orphaned:
                t.status = "queued"
                t.updated_at = now
            session.commit()
            logger.info("startup: reset %d orphaned running/dispatching task(s) to queued", len(orphaned))
            return len(orphaned)
    except Exception as exc:
        logger.warning("startup: orphan reset failed: %s", exc)
        return 0


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


_SWEEP_DISPATCH_LOCK = threading.Lock()
_SWEEP_DISPATCH_INFLIGHT: set[str] = set()


def _sweep_dispatch_worker(task_ids: list[UUID], settings: Settings) -> None:
    """Run task dispatch off the scheduler thread, marking tasks as in-flight
    so the next sweep does not pick them up again. Dispatches one task at a
    time with retry on SQLite lock contention so a single locked task does
    not block the rest."""
    from time import sleep

    from api.app.services.task_dispatch import dispatch_task_batch

    task_id_strs = [str(tid) for tid in task_ids]
    try:
        for tid in task_ids:
            for attempt in range(5):
                try:
                    dispatch_task_batch([tid], settings)
                    break
                except Exception as exc:
                    msg = str(exc).lower()
                    if "database is locked" in msg or "locked" in msg:
                        logger.info(
                            "sweep: db locked on task %s (attempt %d/5), retrying", tid, attempt + 1
                        )
                        sleep(1.0 + attempt * 0.5)
                        continue
                    logger.warning("sweep: dispatch task %s failed: %s", tid, exc)
                    break
    finally:
        with _SWEEP_DISPATCH_LOCK:
            for tid in task_id_strs:
                _SWEEP_DISPATCH_INFLIGHT.discard(tid)


def sweep_stuck_queued_tasks(app: Any, settings: Settings) -> int:
    """Dispatch tasks stuck in 'queued' status for active runs.

    Runs every 5 seconds via APScheduler. Covers tasks that were created by
    next_step_hints, pivot engine, or AI loop iteration but not immediately
    dispatched. Dispatch runs in a background thread so the sweeper returns
    quickly and the next scheduled run is not skipped by APScheduler's
    max_instances=1 guard.
    """
    session_factory: sessionmaker[Session] | None = getattr(app.state, "session_factory", None)
    if session_factory is None:
        return 0

    stale_cutoff = datetime.now(tz=UTC) - timedelta(seconds=_QUEUED_TASK_STALE_SECONDS)

    with session_factory() as session:
        # Find runs that are active (not terminal)
        active_run_ids = list(
            session.scalars(
                select(Run.id).where(Run.status.not_in(list(_TERMINAL_RUN_STATUSES)))
            ).all()
        )
        if not active_run_ids:
            return 0

        # Find queued tasks for those runs that have been waiting too long
        stale_tasks = session.scalars(
            select(Task).where(
                Task.status == "queued",
                Task.run_id.in_(active_run_ids),
                Task.created_at <= stale_cutoff,
            ).order_by(Task.created_at.asc()).limit(20)
        ).all()

        if not stale_tasks:
            return 0

        # Filter out tasks already being dispatched by an earlier sweep
        with _SWEEP_DISPATCH_LOCK:
            pending = [t for t in stale_tasks if str(t.id) not in _SWEEP_DISPATCH_INFLIGHT]
            for t in pending:
                _SWEEP_DISPATCH_INFLIGHT.add(str(t.id))

        if not pending:
            return 0

        task_ids = [t.id for t in pending]
        logger.info("sweep: dispatching %d stuck queued tasks in background", len(task_ids))

        thread = threading.Thread(
            target=_sweep_dispatch_worker,
            args=(task_ids, settings),
            name=f"aegispt-sweep-dispatch-{len(task_ids)}",
            daemon=True,
        )
        thread.start()

        return len(task_ids)


def finalize_zombie_runs_tick(app: Any, settings: Settings) -> int:
    """Sweep genuinely-stale running/queued runs — NO activity for >10 min.

    Equivalent to running ``scripts/finalize_zombie_runs.py`` on a cron, but
    in-process so it always fires when the API is up. Without this the
    operator has to manually run the script (we accumulated 16 zombies over
    ~5 days before noticing on 2026-05-24).

    2026-05-28 FIX: the staleness predicate was ``started_at < NOW() - 5min``,
    which finalized EVERY run older than 5 minutes regardless of whether it
    was actively making progress. XBOW challenge runs have a 900s (15-min)
    wall-clock budget, so the sweeper was killing healthy runs mid-recon —
    empirically observed killing run 75b955ec (smoke 64) at 10:48 right
    before its SSTI exploit could land against XBEN-009, producing a false
    "no-flag". A run is a zombie only when it has had NO row activity for a
    long time; ``updated_at`` is bumped (onupdate=func.now()) on every loop
    advance + task transition, so it is the correct last-activity signal.
    Switched to ``updated_at < NOW() - 10min`` — comfortably longer than the
    longest single task (Joern CPG / content-discovery ~4min) AND the 900s
    wall-clock budget, so a healthy run self-terminates via the budget guard
    long before this backstop fires; only a truly-hung run trips it.
    """
    session_factory: sessionmaker[Session] | None = getattr(app.state, "session_factory", None)
    if session_factory is None:
        return 0
    from sqlalchemy import text as _text_zombie  # noqa: E402
    with session_factory() as session:
        try:
            res = session.execute(
                _text_zombie(
                    "UPDATE runs SET status='completed_with_errors', updated_at=NOW() "
                    "WHERE status IN ('running','queued') "
                    "AND updated_at < NOW() - INTERVAL '10 minutes' "
                    "RETURNING id"
                )
            )
            rows = res.fetchall()
            # A terminal run must not leave non-terminal tasks behind (operator-
            # flagged 2026-06-01: queued tasks on a completed_with_errors run are
            # inconsistent DB state). Cascade any non-terminal task of ANY terminal
            # run to 'cancelled'. Self-healing: reconciles orphans from THIS sweep
            # AND from any other finalize path (force-kill, crash) within one tick.
            # 'cancelled' is the established terminal task status for "terminated
            # without completing" (matches cancel_run_tasks()).
            cascade = session.execute(
                _text_zombie(
                    "UPDATE tasks SET status='cancelled', updated_at=NOW() "
                    "WHERE status IN ('queued','running','dispatching','prepared') "
                    "AND run_id IN (SELECT id FROM runs WHERE status IN "
                    "('completed','completed_with_errors','failed','cancelled','rejected','stopped'))"
                )
            )
            orphans = cascade.rowcount or 0
            session.commit()
            n = len(rows)
            if n or orphans:
                logger.info(
                    "PROOF_EXEC_ZOMBIE_SWEEP_2026052815 zombie-sweeper: finalized %d "
                    "stale run(s) (no activity >10min) status=completed_with_errors + "
                    "cascaded %d orphaned task(s) to cancelled ids=%s",
                    n, orphans,
                    [str(r[0])[:8] for r in rows],
                )
            return n
        except Exception as exc:  # noqa: BLE001
            session.rollback()
            logger.warning("zombie-sweeper: tick failed: %s", exc)
            return 0


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
    scheduler.add_job(
        sweep_stuck_queued_tasks,
        trigger=IntervalTrigger(seconds=5),
        args=[app, settings],
        id="aegispt-queue-sweeper",
        replace_existing=True,
        max_instances=1,
        coalesce=True,
    )
    scheduler.add_job(
        finalize_zombie_runs_tick,
        trigger=IntervalTrigger(minutes=5),
        args=[app, settings],
        id="aegispt-zombie-sweeper",
        replace_existing=True,
        max_instances=1,
        coalesce=True,
    )
    scheduler.start()
    app.state.scheduled_run_scheduler = scheduler
    status = {
        "enabled": True,
        "interval": "1 minute",
        "sweeper_interval": "5 seconds",
        "zombie_sweeper_interval": "5 minutes",
    }
    app.state.scheduled_run_scheduler_status = status
    return status


def stop_scheduled_run_scheduler(app: Any) -> None:
    scheduler = getattr(app.state, "scheduled_run_scheduler", None)
    if scheduler is not None:
        scheduler.shutdown(wait=False)
        app.state.scheduled_run_scheduler = None


def load_scheduled_launch_run(session: Session, run_id: UUID) -> Run | None:
    return load_run(session, run_id)
