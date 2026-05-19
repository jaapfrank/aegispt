from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi.testclient import TestClient
from sqlalchemy import select

from api.app.models import AgentReasoning, Engagement, Finding, Run, RunProfile, Task, ToolExecution


@contextmanager
def _client_with_env(tmp_path, monkeypatch, **env: str) -> Iterator[TestClient]:
    database_path = tmp_path / "aegispt-live-ai-signal.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite+pysqlite:///{database_path}")
    monkeypatch.setenv("AUTO_CREATE_TABLES", "true")
    monkeypatch.setenv("TASK_DISPATCH_MODE", "manual")
    for key, value in env.items():
        monkeypatch.setenv(key, value)

    from api.app.config import get_settings
    from api.app.main import create_app

    get_settings.cache_clear()
    with TestClient(create_app()) as test_client:
        yield test_client
    get_settings.cache_clear()


def _seed_completed_task(session, *, name: str = "Live AI Signal") -> tuple[Run, Task]:
    engagement = Engagement(
        name=name,
        client="Acme Corp",
        roe_ref=f"ROE-{name.replace(' ', '-').upper()}",
        status="active",
    )
    profile = RunProfile(
        name=f"profile-{name.replace(' ', '-').lower()}",
        run_class="passive",
        limits_json={"tools": ["nmap"], "approval_required": False},
    )
    run = Run(
        engagement=engagement,
        profile=profile,
        requested_by="operator",
        status="running",
        configuration_json={"targets": {"cidr_ranges": ["10.0.20.0/24"]}},
    )
    task = Task(
        run=run,
        tool="nmap",
        target_id="10.0.20.0/24",
        params_json={"target_kind": "cidr"},
        status="completed",
    )
    execution = ToolExecution(
        task=task,
        runner_digest="sha256:live-ai-signal",
        tool_version="nmap 7.94",
        exit_code=0,
        stdout_text="Host is up\n80/tcp open http\n443/tcp open https",
        stderr_text="",
    )
    finding = Finding(
        run=run,
        title="Exposed HTTP service",
        severity="medium",
        target_id="10.0.20.10",
        evidence_ref="tool_execution.stdout_text",
        status="open",
        summary="HTTP and HTTPS services were detected.",
    )
    session.add_all([engagement, profile, run, task, execution, finding])
    session.flush()
    return run, task


def test_live_ai_signal_sse_falls_back_to_deterministic_and_stores_reasoning(client) -> None:
    with client.app.state.session_factory() as session:
        run, task = _seed_completed_task(session)
        run_id = str(run.id)
        task_id = str(task.id)
        session.commit()

    response = client.get(f"/api/v1/runs/{run_id}/ai-signal/stream?task_id={task_id}")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/event-stream")
    assert "event: status" in response.text
    assert "Deterministic mode" in response.text
    assert "event: token" in response.text
    assert "event: complete" in response.text

    with client.app.state.session_factory() as session:
        records = session.scalars(select(AgentReasoning)).all()
        assert len(records) == 1
        assert records[0].reasoning_type == "live_ai_signal"
        assert records[0].metadata_json["signal_kind"] == "live_ai_signal"
        assert records[0].metadata_json["dispatches_work"] is False
        assert records[0].metadata_json["executes_tools"] is False


def test_live_ai_signal_sse_streams_chatgpt_when_oauth_is_connected(tmp_path, monkeypatch) -> None:
    class StreamResponse:
        def __enter__(self):
            return self

        def __exit__(self, *_exc) -> None:
            return None

        def raise_for_status(self) -> None:
            return None

        def iter_lines(self):
            yield 'data: {"type":"response.output_text.delta","delta":"Nmap found HTTP exposure. "}'
            yield 'data: {"type":"response.output_text.delta","delta":"Prioritize web validation next. "}'
            yield 'data: {"type":"response.output_text.delta","delta":"No approval or task was changed."}'
            yield "data: [DONE]"

    calls: list[dict[str, Any]] = []

    def fake_stream(method: str, url: str, **kwargs):
        calls.append({"method": method, "url": url, **kwargs})
        assert method == "POST"
        assert kwargs["headers"]["Accept"] == "text/event-stream"
        assert kwargs["json"]["store"] is False
        assert kwargs["json"]["stream"] is True
        assert "three concise sentences" in kwargs["json"]["instructions"]
        return StreamResponse()

    with _client_with_env(
        tmp_path,
        monkeypatch,
        AI_AGENT_POST_TASK_ANALYSIS_ENABLED="true",
        AI_AGENT_POST_TASK_ANALYSIS_PROVIDER="chatgpt_oauth",
        CHATGPT_OAUTH_CLIENT_ID="test-chatgpt-client",
    ) as client:
        monkeypatch.setattr("api.app.services.chatgpt_oauth.httpx.stream", fake_stream)
        from api.app.config import get_settings
        from api.app.services.chatgpt_oauth import store_chatgpt_oauth_token_set

        with client.app.state.session_factory() as session:
            run, task = _seed_completed_task(session, name="Connected AI Signal")
            store_chatgpt_oauth_token_set(
                session=session,
                engagement_id=run.engagement_id,
                settings=get_settings(),
                token_set={
                    "access_token": "connected-access-token",
                    "refresh_token": "connected-refresh-token",
                    "expires_at": (datetime.now(tz=UTC) + timedelta(minutes=30)).isoformat(),
                    "account_id": "acct_live_signal",
                },
                source="test",
            )
            run_id = str(run.id)
            task_id = str(task.id)
            session.commit()

        response = client.get(f"/api/v1/runs/{run_id}/ai-signal/stream?task_id={task_id}")

        assert response.status_code == 200
        assert len(calls) == 1
        assert "ChatGPT connected" in response.text
        assert "Nmap found HTTP exposure." in response.text
        with client.app.state.session_factory() as session:
            record = session.scalar(select(AgentReasoning))
            assert record is not None
            assert record.provider == "chatgpt_oauth"
            assert record.metadata_json["analysis_text"].startswith("Nmap found HTTP exposure.")
