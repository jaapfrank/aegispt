from __future__ import annotations


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
