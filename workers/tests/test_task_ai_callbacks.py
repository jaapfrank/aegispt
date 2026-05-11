from __future__ import annotations

from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from api.app.config import get_settings
from api.app.models import (
    AgentProposal,
    AgentReasoning,
    Base,
    Engagement,
    InventorySnapshot,
    Run,
    RunProfile,
    Scope,
    Task,
)
from workers.orchestration.runtime import get_session_factory
from workers.orchestration.tasks import (
    _maybe_advance_assessment_loop_after_task,
    _maybe_run_post_task_ai_analysis,
)


def _session_factory(tmp_path):
    database_path = tmp_path / "aegispt-worker-ai-callback.db"
    engine = create_engine(
        f"sqlite+pysqlite:///{database_path}",
        future=True,
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(bind=engine)
    return sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)


def _seed_completed_task(session) -> Task:
    engagement = Engagement(
        name="Worker AI Callback",
        client="Acme Corp",
        roe_ref="ROE-WORKER-AI",
        status="active",
    )
    scope = Scope(
        engagement=engagement,
        allowlist_json={"hosts": ["10.0.0.5"]},
        denylist_json={},
    )
    profile = RunProfile(
        name="worker-ai-callback-profile",
        run_class="active",
        limits_json={"tools": ["nmap"], "approval_required": True},
    )
    run = Run(
        engagement=engagement,
        profile=profile,
        requested_by="worker-test",
        status="completed",
        configuration_json={"targets": {"hosts": ["10.0.0.5"]}},
    )
    task = Task(
        run=run,
        tool="nmap",
        target_id="10.0.0.5",
        params_json={"profile": "safe-service-detection"},
        status="completed",
    )
    session.add_all([engagement, scope, profile, run, task])
    session.flush()
    return task


def _seed_completed_ai_loop_task(session) -> Task:
    engagement = Engagement(
        name="Worker AI Loop Callback",
        client="Acme Corp",
        roe_ref="ROE-WORKER-AI-LOOP",
        status="active",
    )
    scope = Scope(
        engagement=engagement,
        allowlist_json={"urls": ["https://loop.example.test"]},
        denylist_json={},
    )
    profile = RunProfile(
        name="worker-ai-loop-profile",
        run_class="passive",
        limits_json={
            "tools": ["httpx"],
            "required_approvals": 0,
            "autonomous_mode_default": True,
        },
    )
    snapshot = InventorySnapshot(
        engagement=engagement,
        requested_by="worker-test",
        status="completed",
        source_tools_json=["httpx"],
        raw_inputs_json={},
        normalized_inventory_json={
            "targets": ["https://loop.example.test"],
            "signal_profile": {
                "signals": [
                    {"key": "login_form_found", "value": True, "confidence": 0.9},
                    {"key": "auth_flow_present", "value": True, "confidence": 0.9},
                    {"key": "session_cookie_present", "value": True, "confidence": 0.9},
                ]
            },
            "tech_stack_profile": {},
        },
        summary_json={"url_count": 1, "service_count": 1},
        confidence_score=0.86,
    )
    session.add_all([engagement, scope, profile, snapshot])
    session.flush()
    run = Run(
        engagement=engagement,
        profile=profile,
        source_inventory_snapshot_id=snapshot.id,
        requested_by="worker-test",
        status="completed",
        autonomous_mode=True,
        autonomous_intrusive_allowed=False,
        configuration_json={
            "targets": {"urls": ["https://loop.example.test"]},
            "run_mode": "ai_loop",
            "ai_assessment_loop": {
                "enabled": True,
                "run_mode": "ai_loop",
                "iteration_count": 1,
                "iterations": [
                    {
                        "iteration": 1,
                        "status": "completed",
                        "next_action": {
                            "tool": "httpx",
                            "target": "https://loop.example.test",
                            "tier": "passive",
                        },
                    }
                ],
            },
        },
    )
    task = Task(
        run=run,
        tool="httpx",
        target_id="https://loop.example.test",
        params_json={"assessment_loop": {"iteration": 1, "run_mode": "ai_loop"}},
        status="completed",
    )
    session.add_all([run, task])
    session.flush()
    return task


def test_worker_post_task_ai_callback_is_opt_in_and_stores_pending_review(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("AI_AGENT_POST_TASK_ANALYSIS_ENABLED", "true")
    monkeypatch.setenv("AI_AGENT_POST_TASK_ANALYSIS_PROVIDER", "deterministic")
    get_settings.cache_clear()
    get_session_factory.cache_clear()

    session_factory = _session_factory(tmp_path)
    with session_factory() as session:
        task = _seed_completed_task(session)
        session.commit()

        _maybe_run_post_task_ai_analysis(session, task)
        session.commit()

        proposals = list(session.scalars(select(AgentProposal)))
        reasoning_records = list(session.scalars(select(AgentReasoning)))
        assert len(reasoning_records) == 1
        assert len(proposals) == 1
        assert proposals[0].status == "pending_review"
        assert proposals[0].proposed_tool == "httpx"
        assert proposals[0].proposed_target == "10.0.0.5"
        assert proposals[0].metadata_json["dispatches_work"] is False

    get_settings.cache_clear()
    get_session_factory.cache_clear()


def test_worker_ai_loop_advances_after_completed_task_and_auto_queues_active_work(
    tmp_path,
) -> None:
    get_settings.cache_clear()
    get_session_factory.cache_clear()

    session_factory = _session_factory(tmp_path)
    with session_factory() as session:
        task = _seed_completed_ai_loop_task(session)
        session.commit()

        outcome = _maybe_advance_assessment_loop_after_task(session, task)
        session.commit()

        assert outcome is not None
        assert outcome["run_mode"] == "ai_loop"
        assert outcome["status"] == "waiting_for_execution"
        assert outcome["queued_task_id"]
        assert outcome["proposal_id"]
        next_action = outcome["next_action"]
        assert next_action["tool"] == "auth-flow"
        assert next_action["tier"] == "active"

        proposals = list(session.scalars(select(AgentProposal)))
        tasks = list(session.scalars(select(Task).order_by(Task.created_at, Task.id)))
        assert len(proposals) == 1
        assert proposals[0].status == "approved"
        assert proposals[0].metadata_json["proposal_kind"] == "assessment_loop_next_action"
        assert proposals[0].metadata_json["dispatches_work"] is True
        assert {item.tool for item in tasks} == {"httpx", "auth-flow"}

    get_settings.cache_clear()
    get_session_factory.cache_clear()


def test_worker_post_task_ai_callback_skips_failed_tasks(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("AI_AGENT_POST_TASK_ANALYSIS_ENABLED", "true")
    monkeypatch.setenv("AI_AGENT_POST_TASK_ANALYSIS_PROVIDER", "deterministic")
    get_settings.cache_clear()
    get_session_factory.cache_clear()

    session_factory = _session_factory(tmp_path)
    with session_factory() as session:
        task = _seed_completed_task(session)
        task.status = "failed"
        session.commit()

        _maybe_run_post_task_ai_analysis(session, task)
        session.commit()

        assert list(session.scalars(select(AgentReasoning))) == []
        assert list(session.scalars(select(AgentProposal))) == []

    get_settings.cache_clear()
    get_session_factory.cache_clear()


def test_worker_post_task_ai_callback_queues_autonomous_follow_up_when_run_opted_in(
    monkeypatch, tmp_path
) -> None:
    monkeypatch.setenv("AI_AGENT_POST_TASK_ANALYSIS_ENABLED", "true")
    monkeypatch.setenv("AI_AGENT_POST_TASK_ANALYSIS_PROVIDER", "deterministic")
    get_settings.cache_clear()
    get_session_factory.cache_clear()

    session_factory = _session_factory(tmp_path)
    with session_factory() as session:
        task = _seed_completed_task(session)
        task.run.autonomous_mode = True
        session.commit()

        outcome = _maybe_run_post_task_ai_analysis(session, task)
        session.commit()

        proposals = list(session.scalars(select(AgentProposal)))
        tasks = list(session.scalars(select(Task).order_by(Task.created_at, Task.id)))
        assert outcome is not None
        assert outcome.autonomous_dispatch_count == 1
        assert len(proposals) == 1
        assert proposals[0].status == "approved"
        assert proposals[0].metadata_json["dispatches_work"] is True
        assert len(tasks) == 2
        autonomous_task = next(item for item in tasks if item.tool == "httpx")
        assert autonomous_task.status == "queued"
        assert autonomous_task.params_json["autonomous_agent"]["enabled"] is True

    get_settings.cache_clear()
    get_session_factory.cache_clear()
