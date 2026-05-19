from __future__ import annotations

from uuid import UUID

from sqlalchemy import select

from api.app.models import InventorySnapshot, Run

LAB_URL = "http://127.0.0.1:7001"
LAB_HASH = "a" * 64


def test_wargaming_profile_is_hidden_by_default_but_available_when_requested(client) -> None:
    default_response = client.get("/api/v1/run-profiles")
    assert default_response.status_code == 200
    assert "wargaming-lab-simulation" not in {
        profile["name"] for profile in default_response.json()
    }

    experimental_response = client.get("/api/v1/run-profiles?include_experimental=true")
    assert experimental_response.status_code == 200
    profile = next(
        item
        for item in experimental_response.json()
        if item["name"] == "wargaming-lab-simulation"
    )
    assert profile["run_class"] == "intrusive"
    assert profile["limits_json"]["wargaming_sandbox"] is True
    assert profile["limits_json"]["approval_gates_bypassed"] is False
    assert profile["limits_json"]["automatic_live_execution"] is False


def test_wargaming_run_rejects_non_lab_or_unverified_targets(client) -> None:
    engagement_id = _create_engagement_with_lab_scope(client)

    response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "wargaming-lab-simulation",
            "configuration_json": {
                "targets": {"urls": [LAB_URL]},
                "wargaming_sandbox": {"operator_acknowledged_lab_only": True},
            },
        },
    )

    assert response.status_code == 409
    assert "verified isolated-lab inventory snapshot" in response.json()["detail"]


def test_wargaming_run_requires_lab_acknowledgement_and_blocks_gate_bypass(client) -> None:
    engagement_id = _create_engagement_with_lab_scope(client)
    snapshot_id = _create_lab_inventory_snapshot(client, engagement_id)

    missing_ack = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "wargaming-lab-simulation",
            "source_inventory_snapshot_id": snapshot_id,
            "configuration_json": {
                "targets": {"urls": [LAB_URL]},
                "wargaming_sandbox": {"operator_acknowledged_lab_only": False},
            },
        },
    )
    assert missing_ack.status_code == 409
    assert "lab-only" in missing_ack.json()["detail"]

    bypass = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "wargaming-lab-simulation",
            "source_inventory_snapshot_id": snapshot_id,
            "configuration_json": {
                "targets": {"urls": [LAB_URL]},
                "wargaming_sandbox": {
                    "operator_acknowledged_lab_only": True,
                    "disable_approval_gates": True,
                },
            },
        },
    )
    assert bypass.status_code == 409
    assert "cannot disable approval gates" in bypass.json()["detail"]


def test_wargaming_run_is_pending_approval_simulation_only_and_has_no_tasks(client) -> None:
    engagement_id = _create_engagement_with_lab_scope(client)
    snapshot_id = _create_lab_inventory_snapshot(client, engagement_id)

    response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "wargaming-lab-simulation",
            "source_inventory_snapshot_id": snapshot_id,
            "configuration_json": {
                "targets": {"urls": [LAB_URL]},
                "wargaming_sandbox": {"operator_acknowledged_lab_only": True},
            },
        },
    )

    assert response.status_code == 201
    payload = response.json()
    assert payload["status"] == "pending_approval"
    assert payload["tasks"] == []
    sandbox = payload["configuration_json"]["wargaming_sandbox"]
    assert sandbox["mode"] == "lab_only_simulation"
    assert sandbox["simulation_only"] is True
    assert sandbox["verified_isolated_lab"] is True
    assert sandbox["approval_gates_bypassed"] is False
    assert sandbox["choke_points_disabled"] is False
    assert sandbox["automatic_live_execution"] is False
    assert sandbox["kill_switch_bypassed"] is False


def test_wargaming_run_rejects_dispatch_after_create(client) -> None:
    engagement_id = _create_engagement_with_lab_scope(client)
    snapshot_id = _create_lab_inventory_snapshot(client, engagement_id)
    before_count = _run_count(client)

    response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "wargaming-lab-simulation",
            "source_inventory_snapshot_id": snapshot_id,
            "dispatch_after_create": True,
            "configuration_json": {
                "targets": {"urls": [LAB_URL]},
                "wargaming_sandbox": {"operator_acknowledged_lab_only": True},
            },
        },
    )

    assert response.status_code == 409
    assert "cannot be auto-dispatched" in response.json()["detail"]
    assert _run_count(client) == before_count


def _create_engagement_with_lab_scope(client) -> str:
    engagement_response = client.post(
        "/api/v1/engagements",
        headers={"X-Actor": "tester"},
        json={
            "name": "Digital Twin Lab",
            "client": "Acme Corp",
            "roe_ref": "ROE-LAB-2026",
        },
    )
    engagement_id = engagement_response.json()["id"]
    scope_response = client.post(
        f"/api/v1/engagements/{engagement_id}/scope",
        headers={"X-Actor": "tester"},
        json={"allowlist_json": {"urls": [LAB_URL]}, "denylist_json": {}},
    )
    assert scope_response.status_code == 201
    return engagement_id


def _create_lab_inventory_snapshot(client, engagement_id: str) -> str:
    with client.app.state.session_factory() as session:
        snapshot = InventorySnapshot(
            engagement_id=UUID(engagement_id),
            requested_by="operator",
            status="completed",
            source_tools_json=["imported-digital-twin-fixture"],
            raw_inputs_json={},
            normalized_inventory_json={"assets": [{"type": "url", "value": LAB_URL}]},
            summary_json={
                "wargaming_sandbox": {
                    "verified_isolated_lab": True,
                    "target_classification": "isolated_digital_twin",
                    "verification_evidence_ref": "evidence://lab/digital-twin-attestation",
                    "sandbox_verification_sha256": LAB_HASH,
                    "verified_targets": [LAB_URL],
                }
            },
            environment_notes_json=["isolated local digital twin fixture"],
            assumptions_json=[],
            confidence_score=1.0,
        )
        session.add(snapshot)
        session.commit()
        return str(snapshot.id)


def _run_count(client) -> int:
    with client.app.state.session_factory() as session:
        return len(session.scalars(select(Run)).all())
