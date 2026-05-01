from __future__ import annotations

import json

from workers.runners.llm_probe import LLM_PROBE_ARTIFACT_NAME, execute_llm_probe


def _create_llm_engagement(client, *, endpoint: str = "https://llm.example.test/v1/chat") -> str:
    engagement_response = client.post(
        "/api/v1/engagements",
        headers={"X-Actor": "llm-operator"},
        json={
            "name": "LLM App Review",
            "client": "Acme Corp",
            "roe_ref": "ROE-LLM-1",
        },
    )
    assert engagement_response.status_code == 201
    engagement_id = engagement_response.json()["id"]

    scope_response = client.post(
        f"/api/v1/engagements/{engagement_id}/scope",
        headers={"X-Actor": "llm-operator"},
        json={
            "allowlist_json": {
                "llm_endpoints": [endpoint],
                "urls": ["https://app.example.test"],
            },
            "denylist_json": {},
        },
    )
    assert scope_response.status_code == 201
    return engagement_id


def test_llm_probe_profile_requires_approval_and_queues_only_authorized_llm_endpoint(
    client,
) -> None:
    engagement_id = _create_llm_engagement(client)

    run_response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "llm-operator"},
        json={
            "profile_name": "active-llm-application-probe",
            "configuration_json": {
                "targets": {"llm_endpoints": ["https://llm.example.test/v1/chat"]},
                "llm": {
                    "provider_mode": "deterministic",
                    "api_key_env": "AEGISPT_TEST_LLM_API_KEY",
                    "model": "test-llm-app",
                    "max_probes": 4,
                },
            },
        },
    )

    assert run_response.status_code == 201
    created = run_response.json()
    assert created["status"] == "pending_approval"
    assert created["required_approvals"] == 1
    assert created["tasks"] == []

    approval_response = client.post(
        f"/api/v1/runs/{created['id']}/approvals",
        headers={"X-Actor": "approver-1"},
        json={"decision": "approved"},
    )

    assert approval_response.status_code == 200
    approved = approval_response.json()
    assert approved["status"] == "queued"
    assert {task["tool"] for task in approved["tasks"]} == {"llm-probe"}
    assert {task["target_id"] for task in approved["tasks"]} == {
        "https://llm.example.test/v1/chat"
    }
    assert "https://app.example.test" not in {task["target_id"] for task in approved["tasks"]}
    params = approved["tasks"][0]["params_json"]
    assert params["provider_mode"] == "deterministic"
    assert params["api_key_env"] == "AEGISPT_TEST_LLM_API_KEY"
    assert params["max_probes"] == 4
    assert "api_key" not in params
    assert "bearer_token" not in params


def test_inline_llm_probe_dispatch_stores_bounded_evidence_and_findings(
    inline_client,
) -> None:
    engagement_id = _create_llm_engagement(inline_client)
    run_response = inline_client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "llm-operator"},
        json={
            "profile_name": "active-llm-application-probe",
            "configuration_json": {
                "targets": {"llm_endpoints": ["https://llm.example.test/v1/chat"]},
                "llm": {
                    "provider_mode": "deterministic",
                    "deterministic_profile": "unsafe",
                    "model": "test-llm-app",
                    "max_probes": 4,
                },
            },
        },
    )
    created = run_response.json()
    approval_response = inline_client.post(
        f"/api/v1/runs/{created['id']}/approvals",
        headers={"X-Actor": "approver-1"},
        json={"decision": "approved"},
    )
    task_id = approval_response.json()["tasks"][0]["id"]

    dispatch_response = inline_client.post(
        f"/api/v1/runs/{created['id']}/dispatch",
        headers={"X-Actor": "dispatcher"},
    )

    assert dispatch_response.status_code == 200
    dispatch_payload = dispatch_response.json()
    assert dispatch_payload["dispatch_mode"] == "inline"
    assert dispatch_payload["run"]["status"] == "completed"
    assert dispatch_payload["run"]["findings"]["finding_count"] == 4
    assert dispatch_payload["run"]["findings"]["findings_by_severity"] == {
        "high": 2,
        "low": 1,
        "medium": 1,
    }

    findings_response = inline_client.get(f"/api/v1/runs/{created['id']}/findings")
    assert findings_response.status_code == 200
    finding_titles = {finding["title"] for finding in findings_response.json()}
    assert "LLM endpoint appears susceptible to prompt-injection override" in finding_titles
    assert "LLM endpoint disclosed secret-like content during a leakage probe" in finding_titles
    assert "LLM endpoint indicated unsafe autonomous tool use" in finding_titles
    assert "LLM endpoint refused a benign safety request" in finding_titles

    task_response = inline_client.get(f"/api/v1/tasks/{task_id}")
    assert task_response.status_code == 200
    task_payload = task_response.json()
    artifact = task_payload["executions"][0]["artifacts"][0]
    assert artifact["metadata_json"]["name"] == LLM_PROBE_ARTIFACT_NAME
    assert task_payload["params_json"]["provider_mode"] == "deterministic"


def test_llm_probe_deterministic_safe_and_missing_or_unsafe_target_fallbacks() -> None:
    safe_execution = execute_llm_probe(
        ["https://llm.example.test/v1/chat"],
        provider_mode="deterministic",
        deterministic_profile="safe",
    )
    safe_payload = json.loads(safe_execution.artifacts[0].data.decode("utf-8"))
    assert safe_execution.exit_code == 0
    assert safe_payload["status"] == "ok"
    assert safe_payload["summary"]["finding_count"] == 0
    assert safe_payload["read_only"] is True
    assert safe_payload["mutation_performed"] is False

    missing_execution = execute_llm_probe([], provider_mode="deterministic")
    missing_payload = json.loads(missing_execution.artifacts[0].data.decode("utf-8"))
    assert missing_execution.exit_code == 2
    assert missing_payload["status"] == "target_required"
    assert missing_payload["summary"]["finding_count"] == 0

    unsafe_execution = execute_llm_probe(
        ["file:///etc/passwd"],
        provider_mode="deterministic",
    )
    unsafe_payload = json.loads(unsafe_execution.artifacts[0].data.decode("utf-8"))
    assert unsafe_execution.exit_code == 2
    assert unsafe_payload["status"] == "completed_with_errors"
    assert unsafe_payload["targets"][0]["status"] == "unsafe_target"
    assert unsafe_payload["targets"][0]["findings"] == []
