from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

from fastapi.testclient import TestClient
from sqlalchemy import select

from api.app.config import get_settings
from api.app.models import (
    AuditEvent,
    CapabilityPack,
    CapabilityPackArtifact,
    CapabilityPackDeployment,
    CapabilityPackValidationResult,
)
from api.app.services.chatgpt_oauth import store_chatgpt_oauth_token_set


def _create_engagement(client: TestClient, *, tenant_id: str | None = None) -> str:
    headers = {"X-Actor": "custom-vuln-tester"}
    if tenant_id:
        headers["X-Tenant-ID"] = tenant_id
    response = client.post(
        "/api/v1/engagements",
        headers=headers,
        json={
            "name": "Custom CVE Library",
            "client": "Acme Corp",
            "roe_ref": "ROE-CUSTOM-CVE",
        },
    )
    assert response.status_code == 201
    return response.json()["id"]


def _create_deployed_nuclei_artifact(client: TestClient, engagement_id: str) -> str:
    with client.app.state.session_factory() as session:
        pack = CapabilityPack(
            engagement_id=UUID(engagement_id),
            name="custom-cve-nuclei-pack",
            version="2026.04.26",
            status="deployed",
            generated_by="codex",
            generation_mode="codex-supervised",
            description="Generated custom check that passed existing pack lifecycle.",
            source_threat_intel_refs_json=[],
            methodology_tags=["WSTG-VULN"],
            manifest_json={"tools": ["nuclei"], "pack_gate_bypassed": False},
            provenance_json={"source": "unit-test"},
        )
        session.add(pack)
        session.flush()
        artifact = CapabilityPackArtifact(
            pack_id=pack.id,
            artifact_type="nuclei_template",
            logical_name="custom-cve-check.yaml",
            status="generated",
            checksum_sha256="c" * 64,
            methodology_tags=["WSTG-VULN"],
            content_text="id: custom-cve-check\ninfo:\n  name: Custom check\n  severity: high\n",
            content_json=None,
            provenance_json={"source": "custom-cve-library-test"},
        )
        session.add(artifact)
        session.add(
            CapabilityPackValidationResult(
                pack_id=pack.id,
                validator="unit-test",
                executed_by="custom-vuln-tester",
                status="passed",
                summary="Template validated by existing pack lifecycle.",
                artifact_results_json=[],
                validation_artifacts_json=[],
                blocking_issues_json=[],
            )
        )
        session.flush()
        session.add(
            CapabilityPackDeployment(
                pack_id=pack.id,
                engagement_id=UUID(engagement_id),
                deployed_by="custom-vuln-tester",
                deployment_target="engagement-runtime",
                run_profile_name="passive-web-nuclei-audit",
                status="deployed",
                runtime_binding_json={"runner_digest": "sha256:custom"},
            )
        )
        session.commit()
        return str(artifact.id)


def test_custom_vulnerability_crud_search_soft_delete_and_audit(client: TestClient) -> None:
    response = client.post(
        "/api/v1/custom-vulnerabilities",
        headers={"X-Actor": "alice", "X-Tenant-ID": "tenant-a"},
        json={
            "custom_id": "ORG-2026-001",
            "title": "Partner portal auth bypass",
            "description": "Internal advisory for proprietary portal authorization weakness.",
            "severity": "high",
            "cvss_score": 8.4,
            "affected_products": ["Partner Portal", "Acme SSO"],
            "cwe_ids": ["CWE-287"],
            "reporter": "red-team",
            "status": "draft",
        },
    )
    assert response.status_code == 201
    created = response.json()
    assert created["tenant_id"] == "tenant-a"
    assert created["custom_id"] == "ORG-2026-001"
    assert created["test_coverage"]["status"] == "missing_template"

    list_response = client.get(
        "/api/v1/custom-vulnerabilities?q=portal&product=sso&severity=high",
        headers={"X-Tenant-ID": "tenant-a"},
    )
    assert list_response.status_code == 200
    assert list_response.json()["total"] == 1

    patch_response = client.patch(
        f"/api/v1/custom-vulnerabilities/{created['id']}",
        headers={"X-Actor": "alice", "X-Tenant-ID": "tenant-a"},
        json={"status": "active", "severity": "critical", "linked_nuclei_template_ref": "nuclei://pending/custom"},
    )
    assert patch_response.status_code == 200
    updated = patch_response.json()
    assert updated["status"] == "active"
    assert updated["severity"] == "critical"
    assert updated["linked_nuclei_template_ref"] == "nuclei://pending/custom"

    delete_response = client.delete(
        f"/api/v1/custom-vulnerabilities/{created['id']}",
        headers={"X-Actor": "alice", "X-Tenant-ID": "tenant-a"},
    )
    assert delete_response.status_code == 200
    assert delete_response.json()["deleted_at"] is not None

    hidden_response = client.get("/api/v1/custom-vulnerabilities", headers={"X-Tenant-ID": "tenant-a"})
    assert hidden_response.json()["total"] == 0
    visible_response = client.get(
        "/api/v1/custom-vulnerabilities?include_deleted=true",
        headers={"X-Tenant-ID": "tenant-a"},
    )
    assert visible_response.json()["total"] == 1

    with client.app.state.session_factory() as session:
        actions = session.scalars(
            select(AuditEvent.action).where(AuditEvent.object_type == "custom_vulnerability")
        ).all()
        assert "custom_vulnerability.created" in actions
        assert "custom_vulnerability.updated" in actions
        assert "custom_vulnerability.deleted" in actions


def test_custom_vulnerability_import_export_and_ai_structuring(client: TestClient, monkeypatch) -> None:
    engagement_id = _create_engagement(client, tenant_id="tenant-ai")
    with client.app.state.session_factory() as session:
        store_chatgpt_oauth_token_set(
            session=session,
            engagement_id=UUID(engagement_id),
            settings=get_settings(),
            token_set={
                "access_token": "test-access-token",
                "refresh_token": "test-refresh-token",
                "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
                "account_id": "ai-operator",
            },
            source="unit_test",
        )
        session.commit()

    def fake_structure(**kwargs):
        assert kwargs["engagement_id"] == UUID(engagement_id)
        return {
            "records": [
                {
                    "custom_id": "ORG-2026-900",
                    "title": "AI structured appliance flaw",
                    "description": "Plain text advisory structured into safe metadata only.",
                    "severity": "medium",
                    "cvss_score": 5.9,
                    "affected_products": ["Edge Appliance"],
                    "cwe_ids": ["CWE-79"],
                    "status": "draft",
                }
            ]
        }

    monkeypatch.setattr(
        "api.app.services.custom_vulnerabilities.send_chatgpt_backend_streaming_json_request",
        fake_structure,
    )

    nvd_response = client.post(
        "/api/v1/custom-vulnerabilities/import",
        headers={"X-Actor": "importer", "X-Tenant-ID": "tenant-ai"},
        json={
            "format": "nvd_json",
            "default_status": "active",
            "payload": {
                "vulnerabilities": [
                    {
                        "cve": {
                            "id": "CVE-2026-12345",
                            "descriptions": [{"lang": "en", "value": "NVD style imported weakness."}],
                            "metrics": {
                                "cvssMetricV31": [
                                    {"cvssData": {"baseScore": 9.1}, "baseSeverity": "CRITICAL"}
                                ]
                            },
                            "weaknesses": [{"description": [{"lang": "en", "value": "CWE-89"}]}],
                            "configurations": [
                                {
                                    "nodes": [
                                        {
                                            "cpeMatch": [
                                                {"criteria": "cpe:2.3:a:acme:edge_gateway:1.0:*:*:*:*:*:*:*"}
                                            ]
                                        }
                                    ]
                                }
                            ],
                        }
                    }
                ]
            },
        },
    )
    assert nvd_response.status_code == 201
    assert nvd_response.json()["imported_count"] == 1
    assert nvd_response.json()["items"][0]["custom_id"] == "CVE-2026-12345"
    assert nvd_response.json()["items"][0]["severity"] == "critical"

    csaf_response = client.post(
        "/api/v1/custom-vulnerabilities/import",
        headers={"X-Actor": "importer", "X-Tenant-ID": "tenant-ai"},
        json={
            "format": "csaf",
            "payload": {
                "document": {"title": "Vendor advisory"},
                "vulnerabilities": [
                    {
                        "cve": "CVE-2026-23456",
                        "title": "Vendor gateway issue",
                        "notes": [{"category": "description", "text": "CSAF imported proprietary context."}],
                        "product_status": {"known_affected": ["edge-gateway"]},
                        "scores": [{"cvss_v3": {"baseScore": 7.2, "baseSeverity": "HIGH"}}],
                    }
                ],
            },
        },
    )
    assert csaf_response.status_code == 201
    assert csaf_response.json()["imported_count"] == 1

    ai_response = client.post(
        "/api/v1/custom-vulnerabilities/import",
        headers={"X-Actor": "importer", "X-Tenant-ID": "tenant-ai"},
        json={
            "format": "plain_text",
            "payload": "Medium appliance issue. Product: Edge Appliance. CWE-79. Score 5.9.",
            "use_ai": True,
            "engagement_id": engagement_id,
        },
    )
    assert ai_response.status_code == 201
    assert ai_response.json()["ai_assistance"]["status"] == "structured"
    assert ai_response.json()["items"][0]["custom_id"] == "ORG-2026-900"

    export_response = client.get(
        "/api/v1/custom-vulnerabilities/export",
        headers={"X-Actor": "exporter", "X-Tenant-ID": "tenant-ai"},
    )
    assert export_response.status_code == 200
    exported = export_response.json()
    assert exported["format"] == "aegispt_custom_vulnerabilities.v1"
    assert len(exported["items"]) == 3

    reimport_response = client.post(
        "/api/v1/custom-vulnerabilities/import",
        headers={"X-Actor": "importer", "X-Tenant-ID": "tenant-ai"},
        json={"format": "aegispt_export", "payload": exported},
    )
    assert reimport_response.status_code == 201
    assert reimport_response.json()["updated_count"] == 3


def test_custom_vulnerability_scan_options_use_pack_lifecycle_and_engagement_toggle(client: TestClient) -> None:
    engagement_id = _create_engagement(client, tenant_id="tenant-pack")
    artifact_id = _create_deployed_nuclei_artifact(client, engagement_id)

    create_response = client.post(
        "/api/v1/custom-vulnerabilities",
        headers={"X-Actor": "operator", "X-Tenant-ID": "tenant-pack"},
        json={
            "custom_id": "ORG-2026-777",
            "title": "Internal regression signature",
            "description": "Custom check backed by a deployed Nuclei pack artifact.",
            "severity": "high",
            "affected_products": ["Edge Gateway"],
            "status": "active",
            "linked_nuclei_template_ref": f"pack-artifact://{artifact_id}",
        },
    )
    assert create_response.status_code == 201
    vulnerability_id = create_response.json()["id"]

    options_response = client.get(
        f"/api/v1/engagements/{engagement_id}/custom-vulnerabilities/scan-options",
        headers={"X-Tenant-ID": "tenant-pack"},
    )
    assert options_response.status_code == 200
    options = options_response.json()
    assert len(options) == 1
    assert options[0]["enabled"] is False
    assert options[0]["test_coverage"]["status"] == "deployed"
    assert options[0]["profile_option"]["ready_to_run"] is False

    toggle_response = client.post(
        f"/api/v1/engagements/{engagement_id}/custom-vulnerabilities/{vulnerability_id}/toggle",
        headers={"X-Actor": "operator", "X-Tenant-ID": "tenant-pack"},
        json={"enabled": True},
    )
    assert toggle_response.status_code == 200
    assert toggle_response.json()["engagement_state"]["enabled"] is True

    enabled_response = client.get(
        f"/api/v1/engagements/{engagement_id}/custom-vulnerabilities/scan-options",
        headers={"X-Tenant-ID": "tenant-pack"},
    )
    enabled_options = enabled_response.json()
    assert enabled_options[0]["enabled"] is True
    assert enabled_options[0]["profile_option"]["ready_to_run"] is True
    assert enabled_options[0]["profile_option"]["pack_lifecycle_required"] is True
