from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from fastapi.testclient import TestClient


def create_engagement_with_scope(client) -> str:
    engagement_response = client.post(
        "/api/v1/engagements",
        headers={"X-Actor": "tester"},
        json={
            "name": "Acme Validation",
            "client": "Acme Corp",
            "roe_ref": "ROE-2026-002",
        },
    )
    engagement_id = engagement_response.json()["id"]

    client.post(
        f"/api/v1/engagements/{engagement_id}/scope",
        headers={"X-Actor": "tester"},
        json={
            "allowlist_json": {
                "domains": ["example.com"],
                "urls": ["https://example.com"],
            },
            "denylist_json": {"domains": ["admin.example.com"]},
        },
    )

    return engagement_id


@contextmanager
def build_client_with_env(tmp_path, monkeypatch, **env_overrides: str) -> Iterator[TestClient]:
    database_path = tmp_path / "aegispt-policy.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite+pysqlite:///{database_path}")
    monkeypatch.setenv("AUTO_CREATE_TABLES", "true")
    monkeypatch.setenv("TASK_DISPATCH_MODE", "inline")
    for key, value in env_overrides.items():
        monkeypatch.setenv(key, value)

    from api.app.config import get_settings
    from api.app.main import create_app

    get_settings.cache_clear()

    with TestClient(create_app()) as test_client:
        yield test_client

    get_settings.cache_clear()


def test_list_run_profiles(client) -> None:
    response = client.get("/api/v1/run-profiles")

    assert response.status_code == 200
    payload = response.json()
    profile_names = [profile["name"] for profile in payload]
    assert profile_names == [
        "active-web-safe",
        "active-web-zap-active",
        "intrusive-validation",
        "passive-code-semgrep-audit",
        "passive-web-baseline",
        "passive-web-nuclei-audit",
    ]


def test_passive_run_is_queued_with_tasks(client) -> None:
    engagement_id = create_engagement_with_scope(client)

    response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={"profile_name": "passive-web-baseline"},
    )

    assert response.status_code == 201
    payload = response.json()
    assert payload["status"] == "queued"
    assert payload["required_approvals"] == 0
    assert payload["pending_approvals"] == 0
    assert len(payload["tasks"]) == 2
    assert {task["tool"] for task in payload["tasks"]} == {"httpx"}
    assert payload["findings"]["finding_count"] == 0
    assert payload["findings"]["findings_by_severity"] == {}
    assert payload["findings"]["findings_by_status"] == {}
    assert payload["configuration_json"] == {}


def test_run_configuration_and_inventory_binding_round_trip(client) -> None:
    engagement_id = create_engagement_with_scope(client)

    inventory_response = client.post(
        "/api/v1/inventory/runs",
        headers={"X-Actor": "planner"},
        json={
            "engagement_id": engagement_id,
            "source_tools": ["wizard-input"],
            "observations": [
                {
                    "tool": "wizard-input",
                    "kind": "inventory-seed",
                    "data": {
                        "hosts": ["example.com"],
                        "urls": ["https://example.com"],
                        "confidence": 0.8,
                    },
                }
            ],
            "environment_notes": ["Wizard-seeded inventory"],
            "assumptions": ["Assessment starts from reviewed wizard input"],
        },
    )
    inventory_id = inventory_response.json()["id"]

    configuration_json = {
        "assessment_type": "Mixed Assessment",
        "test_profile": "Adaptive Customer-Specific Mode",
        "execution_profile": "active-web-safe",
        "targets": {"domains": ["example.com"], "urls": ["https://example.com"]},
        "modules": {"discovery": True, "adaptive_ai_generated_tests": True},
        "safety": {"rate_limit_rps": 2, "concurrency": 2, "time_budget_minutes": 120},
        "eta": {"estimated_total_minutes": 120, "estimated_impact": "medium", "confidence": "medium"},
    }

    run_response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "active-web-safe",
            "source_inventory_snapshot_id": inventory_id,
            "configuration_json": configuration_json,
        },
    )

    assert run_response.status_code == 201
    payload = run_response.json()
    assert payload["source_inventory_snapshot_id"] == inventory_id
    assert payload["configuration_json"]["assessment_type"] == "Mixed Assessment"
    assert payload["configuration_json"]["test_profile"] == "Adaptive Customer-Specific Mode"


def test_active_run_requires_approval_before_queueing(client) -> None:
    engagement_id = create_engagement_with_scope(client)

    create_response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={"profile_name": "active-web-safe"},
    )

    assert create_response.status_code == 201
    created_payload = create_response.json()
    assert created_payload["status"] == "pending_approval"
    assert created_payload["required_approvals"] == 1
    assert created_payload["granted_approvals"] == 0
    assert created_payload["tasks"] == []
    assert created_payload["findings"]["finding_count"] == 0

    approval_response = client.post(
        f"/api/v1/runs/{created_payload['id']}/approvals",
        headers={"X-Actor": "approver-1"},
        json={"decision": "approved"},
    )

    assert approval_response.status_code == 200
    approval_payload = approval_response.json()
    assert approval_payload["status"] == "queued"
    assert approval_payload["granted_approvals"] == 1
    assert approval_payload["pending_approvals"] == 0
    assert len(approval_payload["tasks"]) == 1
    assert {task["tool"] for task in approval_payload["tasks"]} == {"zap"}
    assert approval_payload["tasks"][0]["params_json"]["targets"] == ["https://example.com"]
    assert approval_payload["findings"]["finding_count"] == 0


def test_rejected_run_stays_blocked(client) -> None:
    engagement_id = create_engagement_with_scope(client)

    create_response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={"profile_name": "active-web-safe"},
    )
    run_id = create_response.json()["id"]

    rejection_response = client.post(
        f"/api/v1/runs/{run_id}/approvals",
        headers={"X-Actor": "approver-1"},
        json={"decision": "rejected"},
    )

    assert rejection_response.status_code == 200
    rejection_payload = rejection_response.json()
    assert rejection_payload["status"] == "rejected"
    assert rejection_payload["pending_approvals"] == 0
    assert rejection_payload["tasks"] == []


def test_dispatch_is_blocked_when_kill_switch_enabled(tmp_path, monkeypatch) -> None:
    with build_client_with_env(tmp_path, monkeypatch, EXECUTION_KILL_SWITCH="true") as client:
        engagement_id = create_engagement_with_scope(client)

        run_response = client.post(
            f"/api/v1/engagements/{engagement_id}/runs",
            headers={"X-Actor": "operator"},
            json={"profile_name": "passive-web-baseline"},
        )
        run_id = run_response.json()["id"]

        dispatch_response = client.post(
            f"/api/v1/runs/{run_id}/dispatch",
            headers={"X-Actor": "dispatcher"},
        )

        assert dispatch_response.status_code == 409
        assert dispatch_response.json()["detail"] == "execution kill switch is enabled"


def test_cancel_run_marks_queued_tasks_cancelled(client) -> None:
    engagement_id = create_engagement_with_scope(client)

    create_response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={"profile_name": "passive-web-baseline"},
    )
    run_id = create_response.json()["id"]

    cancel_response = client.post(
        f"/api/v1/runs/{run_id}/cancel",
        headers={"X-Actor": "operator"},
    )

    assert cancel_response.status_code == 200
    cancel_payload = cancel_response.json()
    assert cancel_payload["status"] == "cancelled"
    assert {task["status"] for task in cancel_payload["tasks"]} == {"cancelled"}
    assert cancel_payload["pending_approvals"] == 0

    dispatch_response = client.post(
        f"/api/v1/runs/{run_id}/dispatch",
        headers={"X-Actor": "dispatcher"},
    )

    assert dispatch_response.status_code == 409
