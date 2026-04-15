from __future__ import annotations

from fastapi.testclient import TestClient


def _create_engagement_with_scope(client: TestClient) -> str:
    response = client.post(
        "/api/v1/engagements",
        headers={"X-Actor": "tester"},
        json={
            "name": "Codex Task Validation",
            "client": "Acme Corp",
            "roe_ref": "ROE-2026-011",
        },
    )
    engagement_id = response.json()["id"]

    client.post(
        f"/api/v1/engagements/{engagement_id}/scope",
        headers={"X-Actor": "tester"},
        json={
            "allowlist_json": {"domains": ["app.example.com"], "urls": ["https://app.example.com"]},
            "denylist_json": {},
        },
    )
    return engagement_id


def _create_pack(client: TestClient, engagement_id: str) -> str:
    inventory_response = client.post(
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
                        "technologies": [{"name": "Grafana", "vendor": "Grafana Labs", "confidence": 0.9}],
                        "auth_mechanisms": [{"type": "session-cookie", "confidence": 0.8}],
                        "fingerprints": [{"vendor": "Grafana Labs", "product": "Grafana", "version": "10.4.0"}],
                        "confidence": 0.9,
                    },
                }
            ],
        },
    )
    inventory_id = inventory_response.json()["id"]

    intel_response = client.post(
        "/api/v1/threat-intel/ingest",
        headers={"X-Actor": "intel-operator"},
        json={
            "records": [
                {
                    "source": "vendor-advisory",
                    "advisory_id": "CVE-2026-1001",
                    "title": "Grafana pack refinement candidate",
                    "summary": "Grafana authorization control regression.",
                    "affected_products": ["grafana"],
                    "product_match_hints": ["grafana labs"],
                    "attack_surface_type": "auth",
                    "suggested_test_patterns": ["playwright", "zap"],
                    "confidence": 0.9,
                    "severity": "high",
                }
            ]
        },
    )
    intel_id = intel_response.json()[0]["id"]

    relevance_response = client.post(
        "/api/v1/relevance/analyze",
        headers={"X-Actor": "planner"},
        json={
            "engagement_id": engagement_id,
            "inventory_snapshot_id": inventory_id,
            "threat_intel_ids": [intel_id],
            "include_prior_findings": False,
        },
    )
    decision_id = relevance_response.json()["id"]

    pack_response = client.post(
        "/api/v1/packs/generate",
        headers={"X-Actor": "planner"},
        json={
            "engagement_id": engagement_id,
            "relevance_decision_id": decision_id,
            "name": "codex-task-pack",
        },
    )
    return pack_response.json()["id"]


def test_codex_task_api_creates_and_reads_repo_backed_task(client: TestClient, tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("AEGISPT_CODEX_REPO_ROOT", str(tmp_path))
    engagement_id = _create_engagement_with_scope(client)
    pack_id = _create_pack(client, engagement_id)

    response = client.post(
        "/api/v1/codex/tasks",
        headers={"X-Actor": "codex-planner"},
        json={
            "task_type": "pack_refinement",
            "scope": "Refine adaptive pack artifacts inside the controlled build lane.",
            "inputs": {"base_url": "http://127.0.0.1:8000"},
            "constraints": {"touch_runtime": False},
            "expected_output": {"artifacts": ["playwright_flow", "zap_job"]},
            "generation_reason": "Prepare customer-specific refinement without changing runtime behavior.",
            "source_context": {"pack_id": pack_id},
        },
    )

    assert response.status_code == 201
    payload = response.json()
    assert payload["generated_by"] == "codex"
    assert payload["source_context"]["pack_id"] == pack_id
    assert payload["task_file"].startswith("codex/tasks/")

    read_response = client.get(f"/api/v1/codex/tasks/{payload['id']}")
    assert read_response.status_code == 200
    assert read_response.json()["id"] == payload["id"]


def test_codex_task_run_returns_safe_commands_and_result(client: TestClient, tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("AEGISPT_CODEX_REPO_ROOT", str(tmp_path))
    engagement_id = _create_engagement_with_scope(client)
    pack_id = _create_pack(client, engagement_id)

    create_response = client.post(
        "/api/v1/codex/tasks",
        headers={"X-Actor": "codex-planner"},
        json={
            "task_type": "pack_refinement",
            "scope": "Prepare a Codex workspace and validation handoff for an existing pack.",
            "inputs": {},
            "constraints": {"runtime_mutation": "forbidden"},
            "expected_output": {"workspace_export": True},
            "generation_reason": "Create a controlled Codex build-lane task.",
            "source_context": {"pack_id": pack_id},
        },
    )
    task_id = create_response.json()["id"]

    run_response = client.post(
        f"/api/v1/codex/tasks/{task_id}/run",
        headers={"X-Actor": "codex-runner"},
        json={"base_url": "http://127.0.0.1:8000", "workspace_root": "./codex-workspaces/test-pack"},
    )

    assert run_response.status_code == 200
    result = run_response.json()
    assert result["status"] == "prepared"
    assert result["dry_run"] is True
    assert any("export_codex_pack_workspace.sh" in command for command in result["prepared_commands"])
    assert any("validate_codex_pack.sh" in command for command in result["prepared_commands"])
    assert any(hook["path"].endswith(f"/packs/{pack_id}/validate") for hook in result["validation_hooks"])
    assert result["result_file"].startswith("codex/results/")

    stored_result = client.get(f"/api/v1/codex/tasks/{task_id}/result")
    assert stored_result.status_code == 200
    assert stored_result.json()["task_id"] == task_id
