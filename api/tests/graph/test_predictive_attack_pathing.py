from __future__ import annotations

from uuid import UUID

from sqlalchemy import select

from api.app.models import Approval, Finding, Run, Task


def _seed_predictive_run(client) -> tuple[str, str]:
    engagement = client.post(
        "/api/v1/engagements",
        headers={"X-Actor": "predictive-operator"},
        json={"name": "Predictive Pathing", "client": "Acme", "roe_ref": "ROE-PREDICT"},
    ).json()
    client.post(
        f"/api/v1/engagements/{engagement['id']}/scope",
        headers={"X-Actor": "predictive-operator"},
        json={
            "allowlist_json": {
                "hosts": ["app.example.test", "api.example.test"],
                "urls": ["https://app.example.test/login", "https://api.example.test/v1"],
            },
            "denylist_json": {},
        },
    )
    inventory = client.post(
        "/api/v1/inventory/runs",
        headers={"X-Actor": "predictive-operator"},
        json={
            "engagement_id": engagement["id"],
            "source_tools": ["predictive-fixture"],
            "observations": [
                {
                    "tool": "predictive-fixture",
                    "kind": "inventory",
                    "data": {
                        "hosts": ["app.example.test", "api.example.test"],
                        "services": [
                            {"host": "app.example.test", "port": 443, "service": "https", "confidence": 0.9},
                            {"host": "api.example.test", "port": 443, "service": "https", "confidence": 0.88},
                        ],
                        "endpoints": [
                            {"url": "https://app.example.test/login", "confidence": 0.91},
                            {"url": "https://api.example.test/v1", "confidence": 0.87},
                        ],
                    },
                }
            ],
        },
    ).json()
    run = client.post(
        f"/api/v1/engagements/{engagement['id']}/runs",
        headers={"X-Actor": "predictive-operator"},
        json={
            "profile_name": "passive-web-baseline",
            "source_inventory_snapshot_id": inventory["id"],
            "configuration_json": {
                "assessment_type": "Website / Web App",
                "targets": {"urls": ["https://app.example.test/login", "https://api.example.test/v1"]},
            },
        },
    ).json()
    with client.app.state.session_factory() as session:
        session.add(
            Finding(
                run_id=UUID(run["id"]),
                source_inventory_snapshot_id=UUID(inventory["id"]),
                title="Critical API auth bypass",
                severity="critical",
                target_id="https://api.example.test/v1",
                evidence_ref="artifact://predictive/auth-bypass",
                status="open",
                summary="Stored evidence shows critical API auth bypass.",
            )
        )
        session.commit()
    return engagement["id"], run["id"]


def test_predictive_attack_path_simulation_is_read_only_and_hypothetical(client) -> None:
    _, run_id = _seed_predictive_run(client)
    with client.app.state.session_factory() as session:
        before = {
            "runs": len(session.scalars(select(Run)).all()),
            "tasks": len(session.scalars(select(Task)).all()),
            "findings": len(session.scalars(select(Finding)).all()),
            "approvals": len(session.scalars(select(Approval)).all()),
        }

    response = client.post(
        f"/api/v1/runs/{run_id}/attack-paths/simulate",
        headers={"X-Actor": "predictive-operator"},
        json={"starting_point_label": "Assume CEO laptop is compromised", "max_paths": 3},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["simulation_mode"] is True
    assert payload["boundary"]["runtime_dispatch_performed"] is False
    assert payload["boundary"]["factual_evidence_persisted"] is False
    assert payload["boundary"]["hypothetical_edges_persisted"] is False
    assert payload["starting_point"]["hypothetical"] is True
    assert payload["hypothetical_edges"]
    assert payload["hypothetical_edges"][0]["classification"] == "hypothetical"
    assert payload["simulated_paths"]
    path = payload["simulated_paths"][0]
    assert path["hypothetical"] is True
    assert "hypothetical" in path["edge_classifications"]
    assert path["target_label"] == "Critical API auth bypass"
    assert path["runtime_dispatch_performed"] is False
    assert path["factual_evidence_persisted"] is False

    with client.app.state.session_factory() as session:
        after = {
            "runs": len(session.scalars(select(Run)).all()),
            "tasks": len(session.scalars(select(Task)).all()),
            "findings": len(session.scalars(select(Finding)).all()),
            "approvals": len(session.scalars(select(Approval)).all()),
        }
    assert after == before
