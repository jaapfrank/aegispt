from __future__ import annotations

import json
from uuid import UUID, uuid4

from api.app.config import Settings
from api.app.services.task_dispatch import _inline_task_worker_count, dispatch_task_batch
from workers.runners.base.stdout_stream import (
    append_task_stdout,
    mark_task_stdout_completed,
    reset_task_stdout_stream,
    snapshot_task_stdout,
)


def _parse_sse_events(stream_text: str) -> list[tuple[str | None, dict]]:
    events: list[tuple[str | None, dict]] = []
    for chunk in stream_text.strip().split("\n\n"):
        if not chunk.strip():
            continue
        event_name: str | None = None
        data_lines: list[str] = []
        for line in chunk.splitlines():
            if line.startswith("event:"):
                event_name = line.removeprefix("event:").strip()
            elif line.startswith("data:"):
                data_lines.append(line.removeprefix("data:").strip())
        events.append((event_name, json.loads("".join(data_lines))))
    return events


def _create_passive_web_run(client, target_url: str = "https://app.example.test") -> dict:
    engagement_response = client.post(
        "/api/v1/engagements",
        headers={"X-Actor": "tester"},
        json={
            "name": "Run Stream Validation",
            "client": "Acme Corp",
            "roe_ref": "ROE-2026-014",
        },
    )
    engagement_id = engagement_response.json()["id"]

    client.post(
        f"/api/v1/engagements/{engagement_id}/scope",
        headers={"X-Actor": "tester"},
        json={
            "allowlist_json": {
                "urls": [target_url],
            },
            "denylist_json": {},
        },
    )

    run_response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "tester"},
        json={"profile_name": "passive-web-baseline"},
    )
    return run_response.json()


def test_inline_batch_dispatch_uses_parallel_worker_pool(monkeypatch) -> None:
    dispatched: list[str] = []

    def fake_process_task_by_id(task_id: str) -> dict[str, object]:
        dispatched.append(task_id)
        return {"task_id": task_id, "status": "completed"}

    import workers.orchestration.tasks as orchestration_tasks

    monkeypatch.setattr(orchestration_tasks, "process_task_by_id", fake_process_task_by_id)
    task_ids = [str(uuid4()), str(uuid4()), str(uuid4())]

    dispatch_mode = dispatch_task_batch(task_ids, Settings(task_dispatch_mode="inline"))

    assert dispatch_mode == "inline"
    assert sorted(dispatched) == sorted(task_ids)


def test_inline_batch_dispatch_worker_count_uses_runtime_settings() -> None:
    assert _inline_task_worker_count(8, Settings(task_dispatch_mode="inline", inline_task_workers=2)) == 2
    assert _inline_task_worker_count(8, Settings(task_dispatch_mode="inline", inline_task_workers=64)) == 8
    assert _inline_task_worker_count(1, Settings(task_dispatch_mode="inline", inline_task_workers=8)) == 1


def test_inline_batch_dispatch_defers_parallel_work_to_background_tasks() -> None:
    class BackgroundRecorder:
        def __init__(self) -> None:
            self.calls: list[tuple[object, tuple[object, ...]]] = []

        def add_task(self, func, *args) -> None:
            self.calls.append((func, args))

    task_ids = [str(uuid4()), str(uuid4())]
    background_tasks = BackgroundRecorder()

    dispatch_mode = dispatch_task_batch(
        task_ids,
        Settings(task_dispatch_mode="inline"),
        background_tasks=background_tasks,
    )

    assert dispatch_mode == "inline-background-parallel"
    assert len(background_tasks.calls) == 1
    assert background_tasks.calls[0][1][0] == task_ids
    assert isinstance(background_tasks.calls[0][1][1], Settings)


def test_run_event_stream_emits_real_queued_snapshot(client) -> None:
    run_payload = _create_passive_web_run(client)

    stream_response = client.get(f"/api/v1/runs/{run_payload['id']}/events?max_events=1")

    assert stream_response.status_code == 200
    assert stream_response.headers["content-type"].startswith("text/event-stream")

    events = _parse_sse_events(stream_response.text)
    assert len(events) == 1
    event_name, snapshot = events[0]

    assert event_name == "run.snapshot"
    assert snapshot["run_id"] == run_payload["id"]
    assert snapshot["status"] == "queued"
    assert snapshot["task_counts"] == {"queued": 1}
    assert snapshot["tasks"][0]["id"] == run_payload["tasks"][0]["id"]
    assert snapshot["tasks"][0]["status"] == "queued"
    assert snapshot["tasks"][0]["tool"] == "httpx"


def test_run_event_stream_emits_real_completed_snapshot(inline_client, probe_server: str) -> None:
    run_payload = _create_passive_web_run(inline_client, target_url=probe_server)

    dispatch_response = inline_client.post(
        f"/api/v1/runs/{run_payload['id']}/dispatch",
        headers={"X-Actor": "dispatcher"},
    )
    assert dispatch_response.status_code == 200

    stream_response = inline_client.get(f"/api/v1/runs/{run_payload['id']}/events")

    assert stream_response.status_code == 200
    events = _parse_sse_events(stream_response.text)
    assert len(events) == 1
    event_name, snapshot = events[0]

    assert event_name == "run.snapshot"
    assert snapshot["run_id"] == run_payload["id"]
    assert snapshot["status"] == "completed"
    assert snapshot["task_counts"] == {"completed": 1}
    assert snapshot["tasks"][0]["status"] == "completed"


def test_process_task_by_id_accepts_dispatching_task(client, probe_server: str) -> None:
    from api.app.models import Task
    from workers.orchestration.tasks import process_task_by_id

    run_payload = _create_passive_web_run(client, target_url=probe_server)
    task_id = run_payload["tasks"][0]["id"]

    session_factory = client.app.state.session_factory
    with session_factory() as session:
        task = session.get(Task, UUID(task_id))
        assert task is not None
        assert task.run is not None
        task.status = "dispatching"
        task.run.status = "running"
        session.commit()

    result = process_task_by_id(task_id)

    assert result["status"] == "completed"
    detail_response = client.get(f"/api/v1/tasks/{task_id}")
    assert detail_response.status_code == 200
    assert detail_response.json()["status"] == "completed"


def test_run_event_stream_returns_404_for_unknown_run(client) -> None:
    response = client.get(f"/api/v1/runs/{uuid4()}/events?max_events=1")

    assert response.status_code == 404
    assert response.json()["detail"] == "run not found"


def test_task_stdout_stream_emits_completed_runner_stdout(
    inline_client,
    probe_server: str,
) -> None:
    run_payload = _create_passive_web_run(inline_client, target_url=probe_server)
    task_id = run_payload["tasks"][0]["id"]

    dispatch_response = inline_client.post(
        f"/api/v1/runs/{run_payload['id']}/dispatch",
        headers={"X-Actor": "dispatcher"},
    )
    assert dispatch_response.status_code == 200

    stream_response = inline_client.get(f"/api/v1/tasks/{task_id}/stdout/events?max_events=1")

    assert stream_response.status_code == 200
    assert stream_response.headers["content-type"].startswith("text/event-stream")

    events = _parse_sse_events(stream_response.text)
    assert len(events) == 1
    event_name, snapshot = events[0]

    assert event_name == "task.stdout.snapshot"
    assert snapshot["task_id"] == task_id
    assert snapshot["status"] == "completed"
    assert snapshot["source"] == "runner-buffer"
    assert snapshot["stream_terminal"] is True
    assert snapshot["available"] is True
    assert snapshot["line_count"] >= 1
    assert any('"results"' in line["text"] for line in snapshot["lines"])


def test_task_detail_includes_stdout_snapshot_for_polling(
    inline_client,
    probe_server: str,
) -> None:
    run_payload = _create_passive_web_run(inline_client, target_url=probe_server)
    task_id = run_payload["tasks"][0]["id"]

    dispatch_response = inline_client.post(
        f"/api/v1/runs/{run_payload['id']}/dispatch",
        headers={"X-Actor": "dispatcher"},
    )
    assert dispatch_response.status_code == 200

    response = inline_client.get(f"/api/v1/tasks/{task_id}")

    assert response.status_code == 200
    snapshot = response.json()["stdout_snapshot"]
    assert snapshot["task_id"] == task_id
    assert snapshot["available"] is True
    assert snapshot["line_count"] >= 1
    assert any('"results"' in line["text"] for line in snapshot["lines"])


def test_task_stdout_stream_reports_unavailable_for_unstarted_task(client) -> None:
    run_payload = _create_passive_web_run(client)
    task_id = run_payload["tasks"][0]["id"]

    stream_response = client.get(f"/api/v1/tasks/{task_id}/stdout/events?max_events=1")

    assert stream_response.status_code == 200
    events = _parse_sse_events(stream_response.text)
    assert len(events) == 1
    event_name, snapshot = events[0]

    assert event_name == "task.stdout.snapshot"
    assert snapshot["task_id"] == task_id
    assert snapshot["status"] == "unavailable"
    assert snapshot["source"] == "no-stream"
    assert snapshot["stream_terminal"] is False
    assert snapshot["line_count"] == 0


def test_task_stdout_stream_returns_404_for_unknown_task(client) -> None:
    response = client.get(f"/api/v1/tasks/{uuid4()}/stdout/events?max_events=1")

    assert response.status_code == 404
    assert response.json()["detail"] == "task not found"


def test_task_stdout_buffer_is_bounded_and_redacted() -> None:
    task_id = uuid4()

    reset_task_stdout_stream(task_id)
    for index in range(130):
        append_task_stdout(task_id, f"line {index} token=super-secret-token")
    mark_task_stdout_completed(task_id)

    snapshot = snapshot_task_stdout(task_id)

    assert snapshot is not None
    assert snapshot["status"] == "completed"
    assert snapshot["line_count"] == 120
    assert snapshot["truncated"] is True
    assert "super-secret-token" not in json.dumps(snapshot)
    assert "[REDACTED]" in json.dumps(snapshot)


def test_inline_dispatch_executes_httpx_task(inline_client, probe_server: str) -> None:
    engagement_response = inline_client.post(
        "/api/v1/engagements",
        headers={"X-Actor": "tester"},
        json={
            "name": "Inline Dispatch Validation",
            "client": "Acme Corp",
            "roe_ref": "ROE-2026-003",
        },
    )
    engagement_id = engagement_response.json()["id"]

    inline_client.post(
        f"/api/v1/engagements/{engagement_id}/scope",
        headers={"X-Actor": "tester"},
        json={
            "allowlist_json": {
                "urls": [probe_server],
            },
            "denylist_json": {},
        },
    )

    run_response = inline_client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "tester"},
        json={"profile_name": "passive-web-baseline"},
    )
    run_payload = run_response.json()
    task_id = run_payload["tasks"][0]["id"]

    dispatch_response = inline_client.post(
        f"/api/v1/runs/{run_payload['id']}/dispatch",
        headers={"X-Actor": "dispatcher"},
    )

    assert dispatch_response.status_code == 200
    dispatch_payload = dispatch_response.json()
    assert dispatch_payload["dispatch_mode"] == "inline"
    assert dispatch_payload["run"]["status"] == "completed"
    assert dispatch_payload["run"]["tasks"][0]["status"] == "completed"

    task_response = inline_client.get(f"/api/v1/tasks/{task_id}")

    assert task_response.status_code == 200
    task_payload = task_response.json()
    assert task_payload["status"] == "completed"
    assert len(task_payload["executions"]) == 1
    assert task_payload["executions"][0]["exit_code"] == 0
    assert task_payload["executions"][0]["tool_version"].startswith("python-httpx/")
    assert len(task_payload["executions"][0]["artifacts"]) == 1
    assert len(task_payload["executions"][0]["artifacts"][0]["sha256"]) == 64


def test_inline_dispatch_marks_run_completed_with_errors_when_all_tasks_fail(inline_client) -> None:
    engagement_response = inline_client.post(
        "/api/v1/engagements",
        headers={"X-Actor": "tester"},
        json={
            "name": "Inline Dispatch Failure Validation",
            "client": "Acme Corp",
            "roe_ref": "ROE-2026-011",
        },
    )
    engagement_id = engagement_response.json()["id"]

    inline_client.post(
        f"/api/v1/engagements/{engagement_id}/scope",
        headers={"X-Actor": "tester"},
        json={
            "allowlist_json": {
                "urls": [
                    "http://127.0.0.1:1",
                    "http://127.0.0.1:2",
                ],
            },
            "denylist_json": {},
        },
    )

    run_response = inline_client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "tester"},
        json={"profile_name": "passive-web-baseline"},
    )
    run_payload = run_response.json()

    dispatch_response = inline_client.post(
        f"/api/v1/runs/{run_payload['id']}/dispatch",
        headers={"X-Actor": "dispatcher"},
    )

    assert dispatch_response.status_code == 200
    dispatch_payload = dispatch_response.json()
    assert dispatch_payload["run"]["status"] == "completed_with_errors"
    assert {task["status"] for task in dispatch_payload["run"]["tasks"]} == {"failed"}
