from __future__ import annotations

from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from api.app.config import get_settings
from api.app.models import AgentProposal, AgentReasoning, Base, Engagement, Run, RunProfile, Scope, Task
from workers.orchestration.runtime import get_session_factory
from workers.orchestration.tasks import _maybe_run_post_task_ai_analysis


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
