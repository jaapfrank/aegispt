"""Startup orphan-reset must NOT resurrect cancelled runs (2026-06-12).

`reset_orphaned_tasks_at_startup` re-queues running/dispatching tasks from a dead worker.
It used to re-queue EVERY such task, so a run an operator explicitly cancelled came back to
life on the next API restart (its tasks were re-queued + re-dispatched) — the recurring
"resurrection" contention. It must skip tasks whose run is in a terminal status.
"""
from __future__ import annotations

from sqlalchemy import select

from api.app.models import Engagement, Run, RunProfile, Scope, Task
from api.app.services.scheduled_runs import reset_orphaned_tasks_at_startup


def _ensure_profiles(client) -> None:
    assert client.get("/api/v1/run-profiles").status_code == 200


def _make_run_with_task(session, *, run_status: str, task_status: str) -> Task:
    profile = session.scalar(select(RunProfile).where(RunProfile.name == "autonomous-web"))
    assert profile is not None
    engagement = Engagement(name="Orphan Test", client="Acme", roe_ref="ROE-ORPHAN", status="active")
    Scope(engagement=engagement, allowlist_json={"urls": ["https://o.example.test"]}, denylist_json={})
    run = Run(
        engagement=engagement, profile=profile, status=run_status,
        configuration_json={}, requested_by="orphan-test",
        autonomous_mode=True, autonomous_intrusive_allowed=False,
    )
    task = Task(run=run, tool="httpx", target_id="https://o.example.test",
                status=task_status, params_json={})
    session.add(engagement)
    session.add(run)
    session.add(task)
    session.flush()
    return task


def test_orphan_reset_skips_cancelled_run_tasks(client) -> None:
    _ensure_profiles(client)
    with client.app.state.session_factory() as session:
        live_id = _make_run_with_task(session, run_status="running", task_status="running").id
        cancelled_id = _make_run_with_task(session, run_status="cancelled", task_status="running").id
        session.commit()

    reset_orphaned_tasks_at_startup(client.app)

    with client.app.state.session_factory() as session:
        # live run's orphaned task -> re-queued (legit crash recovery)
        assert session.get(Task, live_id).status == "queued"
        # cancelled run's task -> LEFT ALONE (no resurrection)
        assert session.get(Task, cancelled_id).status == "running"
