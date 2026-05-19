from __future__ import annotations

from fastapi.testclient import TestClient


def _create_engagement_with_scope(client: TestClient) -> str:
    engagement = client.post(
        "/api/v1/engagements",
        headers={"X-Actor": "tester"},
        json={"name": "UI Support Validation", "client": "Acme Corp", "roe_ref": "ROE-2026-012"},
    ).json()
    client.post(
        f"/api/v1/engagements/{engagement['id']}/scope",
        headers={"X-Actor": "tester"},
        json={
            "allowlist_json": {"domains": ["app.example.com"], "urls": ["https://app.example.com"]},
            "denylist_json": {"domains": ["admin.example.com"]},
        },
    )
    return engagement["id"]


def _seed_adaptive_pack(client: TestClient, engagement_id: str) -> tuple[str, str, str]:
    inventory = client.post(
        "/api/v1/inventory/runs",
        headers={"X-Actor": "inventory-operator"},
        json={
            "engagement_id": engagement_id,
            "source_tools": ["httpx"],
            "observations": [
                {
                    "tool": "httpx",
                    "kind": "inventory",
                    "data": {
                        "hosts": ["app.example.com"],
                        "endpoints": [{"url": "https://app.example.com", "methods": ["GET"], "status_code": 200}],
                        "technologies": [{"name": "Grafana", "vendor": "Grafana Labs", "confidence": 0.9}],
                        "auth_mechanisms": [{"type": "session-cookie", "confidence": 0.8}],
                        "fingerprints": [{"vendor": "Grafana Labs", "product": "Grafana", "version": "10.4.0"}],
                        "confidence": 0.9,
                    },
                }
            ],
        },
    ).json()

    intel = client.post(
        "/api/v1/threat-intel/ingest",
        headers={"X-Actor": "intel-operator"},
        json={
            "records": [
                {
                    "source": "vendor-advisory",
                    "advisory_id": "CVE-2026-1002",
                    "title": "Grafana UI support advisory",
                    "summary": "Authorization issue for Grafana sessions.",
                    "affected_products": ["grafana"],
                    "product_match_hints": ["grafana labs"],
                    "attack_surface_type": "auth",
                    "suggested_test_patterns": ["playwright", "zap"],
                    "confidence": 0.9,
                    "severity": "high",
                }
            ]
        },
    ).json()[0]

    relevance = client.post(
        "/api/v1/relevance/analyze",
        headers={"X-Actor": "planner"},
        json={
            "engagement_id": engagement_id,
            "inventory_snapshot_id": inventory["id"],
            "threat_intel_ids": [intel["id"]],
            "include_prior_findings": False,
        },
    ).json()

    pack = client.post(
        "/api/v1/packs/generate",
        headers={"X-Actor": "planner"},
        json={"engagement_id": engagement_id, "relevance_decision_id": relevance["id"], "name": "ui-pack"},
    ).json()
    return inventory["id"], relevance["id"], pack["id"]


def test_static_operator_console_is_served(client) -> None:
    response = client.get("/app/")

    assert response.status_code == 200
    assert "AegisPT Operator Console" in response.text
    assert "What do you want to test?" in response.text
    assert "Problems Center" in response.text
    assert "Mission Control" in response.text


def test_ui_support_list_endpoints_reuse_existing_contracts(client, tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("AEGISPT_CODEX_REPO_ROOT", str(tmp_path))
    engagement_id = _create_engagement_with_scope(client)
    inventory_id, relevance_id, pack_id = _seed_adaptive_pack(client, engagement_id)

    task = client.post(
        "/api/v1/codex/tasks",
        headers={"X-Actor": "codex-ui"},
        json={
            "task_type": "pack_refinement",
            "scope": "Prepare a review task for the UI support slice.",
            "inputs": {},
            "constraints": {"runtime_mutation": False},
            "expected_output": {"review_bundle": True},
            "generation_reason": "Expose Codex governance in the operator console.",
            "source_context": {"pack_id": pack_id},
        },
    ).json()

    engagements = client.get("/api/v1/engagements").json()
    scope = client.get(f"/api/v1/engagements/{engagement_id}/scope").json()
    inventory = client.get(f"/api/v1/engagements/{engagement_id}/inventory").json()
    relevance = client.get(f"/api/v1/engagements/{engagement_id}/relevance").json()
    packs = client.get(f"/api/v1/engagements/{engagement_id}/packs").json()
    codex_tasks = client.get("/api/v1/codex/tasks").json()

    assert any(item["id"] == engagement_id for item in engagements)
    assert scope["engagement_id"] == engagement_id
    assert inventory[0]["id"] == inventory_id
    assert relevance[0]["id"] == relevance_id
    assert packs[0]["id"] == pack_id
    assert any(item["id"] == task["id"] for item in codex_tasks)
