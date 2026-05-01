from __future__ import annotations

from uuid import UUID

from fastapi.testclient import TestClient
from sqlalchemy import select

from api.app.models import CapabilityPack, CapabilityPackApproval, CapabilityPackDeployment


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


def test_codex_reimport_stages_validated_workspace_output_as_child_pack(client: TestClient) -> None:
    engagement_id = _create_engagement_with_scope(client)
    pack_id = _create_pack(client, engagement_id)

    validation_response = client.post(
        f"/api/v1/packs/{pack_id}/validate",
        headers={"X-Actor": "codex-validator"},
    )
    assert validation_response.status_code == 200
    validation_result = validation_response.json()
    assert validation_result["status"] == "passed"

    pack = client.get(f"/api/v1/packs/{pack_id}").json()
    artifacts = client.get(f"/api/v1/packs/{pack_id}/artifacts").json()
    playwright_artifact = next(artifact for artifact in artifacts if artifact["artifact_type"] == "playwright_flow")
    refined_flow = {
        **playwright_artifact["content_json"],
        "steps": [
            *playwright_artifact["content_json"]["steps"],
            {"action": "capture", "label": "codex-reimport-review"},
        ],
    }

    response = client.post(
        f"/api/v1/packs/{pack_id}/codex-reimport",
        headers={"X-Actor": "codex-reimporter"},
        json={
            "codex_task_id": "task-20260422-pack-refinement",
            "pack_version": pack["version"],
            "validation_result": validation_result,
            "change_summary": "Added an explicit post-login review capture.",
            "operator_notes": "Reviewed in the supervised Codex workspace.",
            "artifacts": [
                {
                    "artifact_type": playwright_artifact["artifact_type"],
                    "logical_name": playwright_artifact["logical_name"],
                    "content_json": refined_flow,
                    "methodology_tags": playwright_artifact["methodology_tags"],
                    "provenance_json": {"reviewed_by": "codex"},
                }
            ],
        },
    )

    assert response.status_code == 201
    payload = response.json()
    staged_pack = payload["staged_pack"]
    assert payload["source_pack_id"] == pack_id
    assert payload["imported_artifact_count"] == 1
    assert staged_pack["parent_pack_id"] == pack_id
    assert staged_pack["status"] == "generated"
    assert staged_pack["generation_mode"] == "codex-reimport"
    assert staged_pack["version"] != pack["version"]
    assert staged_pack["manifest_json"]["codex_reimport"]["codex_task_id"] == "task-20260422-pack-refinement"
    assert "existing lifecycle" in payload["lifecycle_note"]

    staged_artifacts = client.get(f"/api/v1/packs/{staged_pack['id']}/artifacts").json()
    staged_flow = next(artifact for artifact in staged_artifacts if artifact["artifact_type"] == "playwright_flow")
    assert staged_flow["content_json"]["steps"][-1]["label"] == "codex-reimport-review"
    assert staged_flow["provenance_json"]["codex_reimport"]["source_pack_id"] == pack_id

    original_artifacts = client.get(f"/api/v1/packs/{pack_id}/artifacts").json()
    original_flow = next(artifact for artifact in original_artifacts if artifact["artifact_type"] == "playwright_flow")
    assert original_flow["content_json"]["steps"][-1].get("label") != "codex-reimport-review"

    approval_before_validation = client.post(
        f"/api/v1/packs/{staged_pack['id']}/approve",
        headers={"X-Actor": "approver"},
    )
    assert approval_before_validation.status_code == 409
    assert "successful validation" in approval_before_validation.json()["detail"]

    staged_validation = client.post(
        f"/api/v1/packs/{staged_pack['id']}/validate",
        headers={"X-Actor": "validator"},
    )
    assert staged_validation.status_code == 200
    assert staged_validation.json()["status"] == "passed"


def test_codex_reimport_rejects_missing_failed_or_mismatched_validation_result(client: TestClient) -> None:
    engagement_id = _create_engagement_with_scope(client)
    pack_id = _create_pack(client, engagement_id)
    artifacts = client.get(f"/api/v1/packs/{pack_id}/artifacts").json()
    metadata_artifact = next(artifact for artifact in artifacts if artifact["artifact_type"] == "metadata")
    artifact_payload = {
        "artifact_type": metadata_artifact["artifact_type"],
        "logical_name": metadata_artifact["logical_name"],
        "content_json": metadata_artifact["content_json"],
    }

    missing_response = client.post(
        f"/api/v1/packs/{pack_id}/codex-reimport",
        headers={"X-Actor": "codex-reimporter"},
        json={"artifacts": [artifact_payload]},
    )
    assert missing_response.status_code == 409
    assert "validation-result payload is required" in missing_response.json()["detail"]

    failed_response = client.post(
        f"/api/v1/packs/{pack_id}/codex-reimport",
        headers={"X-Actor": "codex-reimporter"},
        json={
            "validation_result": {"pack_id": pack_id, "status": "failed"},
            "artifacts": [artifact_payload],
        },
    )
    assert failed_response.status_code == 409
    assert "status must be passed" in failed_response.json()["detail"]

    mismatched_response = client.post(
        f"/api/v1/packs/{pack_id}/codex-reimport",
        headers={"X-Actor": "codex-reimporter"},
        json={
            "validation_result": {
                "pack_id": "00000000-0000-0000-0000-000000000000",
                "status": "passed",
                "blocking_issues_json": [],
            },
            "artifacts": [artifact_payload],
        },
    )
    assert mismatched_response.status_code == 409
    assert "does not match the source pack" in mismatched_response.json()["detail"]


def test_assessment_pattern_pack_effectiveness_is_sparse_advisory_and_non_promoting(
    client: TestClient,
) -> None:
    engagement_id = _create_engagement_with_scope(client)
    pack_id = _create_pack(client, engagement_id)

    with client.app.state.session_factory() as session:
        pack = session.get(CapabilityPack, UUID(pack_id))
        assert pack is not None
        status_before = pack.status
        approvals_before = session.scalars(
            select(CapabilityPackApproval).where(CapabilityPackApproval.pack_id == UUID(pack_id))
        ).all()
        deployments_before = session.scalars(
            select(CapabilityPackDeployment).where(CapabilityPackDeployment.pack_id == UUID(pack_id))
        ).all()

    response = client.get(f"/api/v1/engagements/{engagement_id}/assessment-patterns")

    assert response.status_code == 200
    payload = response.json()
    assert payload["summary"]["sparse_data"] is True
    assert payload["summary"]["run_count"] == 0
    assert payload["summary"]["finding_count"] == 0
    assert payload["boundary"]["advisory_only"] is True
    assert payload["boundary"]["external_model_training_performed"] is False
    assert payload["boundary"]["customer_data_exported"] is False
    assert payload["pack_effectiveness"]["mode"] == "advisory_only"
    assert payload["pack_effectiveness"]["automatic_pack_promotion_performed"] is False
    assert payload["pack_effectiveness"]["automatic_pack_approval_performed"] is False
    assert payload["pack_effectiveness"]["automatic_pack_deployment_performed"] is False
    assert payload["pack_effectiveness"]["automatic_pack_mutation_performed"] is False
    assert payload["pack_effectiveness"]["runtime_binding_changed"] is False
    pack_summary = next(item for item in payload["pack_effectiveness"]["packs"] if item["pack_id"] == pack_id)
    assert "needs_validation_before_promotion" in pack_summary["quality_signals"]
    assert "existing validation, approval, deployment, and runtime binding gates" in pack_summary["next_operator_boundary"]

    with client.app.state.session_factory() as session:
        pack = session.get(CapabilityPack, UUID(pack_id))
        assert pack is not None
        assert pack.status == status_before
        approvals_after = session.scalars(
            select(CapabilityPackApproval).where(CapabilityPackApproval.pack_id == UUID(pack_id))
        ).all()
        deployments_after = session.scalars(
            select(CapabilityPackDeployment).where(CapabilityPackDeployment.pack_id == UUID(pack_id))
        ).all()
        assert len(approvals_after) == len(approvals_before)
        assert len(deployments_after) == len(deployments_before)
