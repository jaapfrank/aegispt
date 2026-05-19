from __future__ import annotations

from sqlalchemy import select

from api.app.models import Approval, Run, Task


def test_operator_can_create_local_deception_trap_without_runtime_dispatch(client) -> None:
    before_counts = _runtime_counts(client)

    response = client.post(
        "/api/v1/deception/traps",
        headers={"X-Actor": "deception-operator", "X-Tenant-ID": "lab"},
        json={
            "name": "Local recursive API fixture",
            "trap_kind": "hallucination_api",
            "max_depth": 3,
            "operator_note": "Controlled lab trap only.",
        },
    )

    assert response.status_code == 201
    payload = response.json()
    assert payload["tenant_id"] == "lab"
    assert payload["endpoint_path"].startswith("/api/v1/deception/traps/")
    assert payload["response_preview"]["bounded"] is True
    assert payload["response_preview"]["next"].endswith("?depth=1")
    assert payload["boundary"] == {
        "local_controlled_fixture": True,
        "network_tarpitting": False,
        "automatic_live_deployment": False,
        "legitimate_traffic_interference_expected": False,
        "credential_materialized": False,
        "dispatches_runtime_work": False,
    }
    assert _runtime_counts(client) == before_counts


def test_deception_trap_rejects_live_deployment_shape(client) -> None:
    response = client.post(
        "/api/v1/deception/traps",
        headers={"X-Actor": "deception-operator"},
        json={
            "name": "Unsafe remote trap",
            "trap_kind": "fake_admin_api",
            "local_only": False,
        },
    )

    assert response.status_code == 422
    assert "local_only" in response.text

    extra_response = client.post(
        "/api/v1/deception/traps",
        headers={"X-Actor": "deception-operator"},
        json={
            "name": "Remote bind attempt",
            "trap_kind": "fake_admin_api",
            "deployment_target": "https://customer.example",
        },
    )

    assert extra_response.status_code == 422
    assert "deployment_target" in extra_response.text


def test_deception_probe_records_alert_with_evidence_ref(client) -> None:
    created = client.post(
        "/api/v1/deception/traps",
        headers={"X-Actor": "deception-operator", "X-Tenant-ID": "lab"},
        json={"name": "Shadow admin fixture", "trap_kind": "fake_admin_api", "max_depth": 2},
    )
    trap = created.json()

    probe = client.get(
        f"{trap['endpoint_path']}?depth=1",
        headers={"X-Actor": "review-probe", "X-Tenant-ID": "lab", "User-Agent": "unit-test-probe"},
    )

    assert probe.status_code == 200
    probe_payload = probe.json()
    assert probe_payload["trap_id"] == trap["id"]
    assert probe_payload["payload"]["fixture"] == "aegispt-local-deception"
    assert probe_payload["payload"]["resource"] == "admin-console-shadow-index"
    assert probe_payload["next_path"].endswith("?depth=2")
    assert probe_payload["boundary"]["network_tarpitting"] is False

    alerts = client.get("/api/v1/deception/alerts", headers={"X-Tenant-ID": "lab"}).json()
    assert len(alerts["alerts"]) == 1
    alert = alerts["alerts"][0]
    assert alert["trap_id"] == trap["id"]
    assert alert["actor"] == "review-probe"
    assert alert["user_agent"] == "unit-test-probe"
    assert alert["evidence_ref"].startswith("deception-alert:")
    assert alert["boundary"]["automatic_live_deployment"] is False
    assert alert["boundary"]["credential_materialized"] is False


def test_deception_probe_does_not_create_runs_tasks_or_approvals(client) -> None:
    created = client.post(
        "/api/v1/deception/traps",
        headers={"X-Actor": "deception-operator"},
        json={"name": "Canary document fixture", "trap_kind": "canary_document"},
    )
    trap = created.json()
    before_counts = _runtime_counts(client)

    response = client.get(trap["endpoint_path"], headers={"X-Actor": "review-probe"})

    assert response.status_code == 200
    assert response.json()["payload"]["document"]["classification"] == "decoy"
    assert _runtime_counts(client) == before_counts


def _runtime_counts(client) -> tuple[int, int, int]:
    with client.app.state.session_factory() as session:
        return (
            len(session.scalars(select(Run)).all()),
            len(session.scalars(select(Task)).all()),
            len(session.scalars(select(Approval)).all()),
        )
