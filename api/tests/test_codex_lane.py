from __future__ import annotations

from fastapi.testclient import TestClient


def _create_engagement_with_scope(client: TestClient) -> str:
    response = client.post(
        "/api/v1/engagements",
        headers={"X-Actor": "tester"},
        json={
            "name": "Codex Build Lane Validation",
            "client": "Acme Corp",
            "roe_ref": "ROE-2026-010",
        },
    )
    engagement_id = response.json()["id"]

    client.post(
        f"/api/v1/engagements/{engagement_id}/scope",
        headers={"X-Actor": "tester"},
        json={
            "allowlist_json": {
                "domains": ["app.example.com"],
                "urls": ["https://app.example.com"],
            },
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
            "source_tools": ["httpx", "nmap"],
            "observations": [
                {
                    "tool": "httpx",
                    "kind": "inventory",
                    "data": {
                        "hosts": ["app.example.com"],
                        "endpoints": [{"url": "https://app.example.com", "methods": ["GET"], "status_code": 200}],
                        "technologies": [{"name": "Grafana", "vendor": "Grafana Labs", "confidence": 0.92}],
                        "auth_mechanisms": [{"type": "session-cookie", "confidence": 0.8}],
                        "api_types": [{"type": "rest", "base_url": "https://app.example.com/api", "confidence": 0.8}],
                        "tls": {"protocols": ["tls1.2"], "issues": ["legacy-cipher"], "confidence": 0.7},
                        "fingerprints": [{"vendor": "Grafana Labs", "product": "Grafana", "version": "10.4.0"}],
                        "confidence": 0.9,
                    },
                }
            ],
            "environment_notes": ["internet-facing dashboard"],
            "assumptions": ["login flow is session-based"],
        },
    )
    inventory_id = inventory_response.json()["id"]

    intel_response = client.post(
        "/api/v1/threat-intel/ingest",
        headers={"X-Actor": "threat-intel-operator"},
        json={
            "records": [
                {
                    "source": "vendor-advisory",
                    "advisory_id": "CVE-2026-1000",
                    "title": "Grafana authorization regression validation",
                    "summary": "Authorization flaw affecting Grafana deployments with session-backed dashboards.",
                    "affected_products": ["grafana"],
                    "product_match_hints": ["grafana labs"],
                    "attack_surface_type": "auth",
                    "suggested_test_patterns": ["playwright", "zap"],
                    "confidence": 0.9,
                    "severity": "high",
                    "references": ["https://example.com/advisories/CVE-2026-1000"],
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
            "name": "grafana-adaptive-pack",
        },
    )
    return pack_response.json()["id"]


def test_codex_context_exposes_guardrails_and_hooks(client: TestClient) -> None:
    engagement_id = _create_engagement_with_scope(client)
    pack_id = _create_pack(client, engagement_id)

    response = client.get(f"/api/v1/packs/{pack_id}/codex-context")

    assert response.status_code == 200
    payload = response.json()
    assert payload["pack_id"] == pack_id
    assert payload["generation_mode"] == "codex-supervised"
    assert payload["active_runtime_mutation_allowed"] is False
    assert payload["repo_conventions"]["suggested_branch_name"].startswith("codex/pack-")
    assert payload["repo_conventions"]["validation_command"].endswith(pack_id)
    assert any(hook["path"].endswith(f"/packs/{pack_id}/validate") for hook in payload["validation_hooks"])
    playwright_hook = next(hook for hook in payload["validation_hooks"] if hook["name"] == "artifact.playwright_flow.validate")
    assert playwright_hook["artifact_types"] == ["playwright_flow"]
    assert playwright_hook["expected_checks"] == ["has steps array"]
    assert any(path.endswith("validation-result.json") for path in playwright_hook["workspace_files"])
    zap_hook = next(hook for hook in payload["validation_hooks"] if hook["name"] == "artifact.zap_job.validate")
    assert zap_hook["artifact_types"] == ["zap_job"]
    assert zap_hook["expected_checks"] == ["has tool", "has targets or note"]
    assert any("/artifacts/" in path for path in zap_hook["workspace_files"])
    assert "Runtime mutation blocked" in payload["operator_visibility"]["required_badges"]
    assert payload["artifacts"]
    playwright_artifact = next(artifact for artifact in payload["artifacts"] if artifact["artifact_type"] == "playwright_flow")
    assert playwright_artifact["validation_checks"] == ["has steps array"]


def test_codex_review_bundle_reuses_existing_pack_records(client: TestClient) -> None:
    engagement_id = _create_engagement_with_scope(client)
    pack_id = _create_pack(client, engagement_id)

    response = client.get(f"/api/v1/packs/{pack_id}/codex-review-bundle")

    assert response.status_code == 200
    payload = response.json()
    assert payload["pack"]["id"] == pack_id
    assert payload["context"]["pack_id"] == pack_id
    assert payload["pack"]["generation_mode"] == "codex-supervised"
    assert payload["artifacts"]
    assert any(artifact["artifact_type"] == "workflow" for artifact in payload["artifacts"])
    assert any(hook["name"] == "artifact.playwright_flow.validate" for hook in payload["context"]["validation_hooks"])
    assert any(hook["name"] == "artifact.zap_job.validate" for hook in payload["context"]["validation_hooks"])
    assert any(
        field == "source_pack_version"
        for field in payload["context"]["operator_visibility"]["finding_provenance_fields"]
    )
