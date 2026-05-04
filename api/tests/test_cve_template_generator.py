from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import UUID

from sqlalchemy import select

from api.app.config import get_settings
from api.app.models import CapabilityPack, ThreatIntelRecord
from api.app.services.chatgpt_oauth import store_chatgpt_oauth_token_set
from api.app.services.threat_intel import build_finding_threat_intel_badges

SAFE_TEMPLATE = """id: cve-2026-7777-examplecms-detection
info:
  name: CVE-2026-7777 ExampleCMS detection
  author: aegispt-ai
  severity: high
  description: Detection-only check for ExampleCMS exposure requiring operator review.
  tags: cve,cve2026,examplecms,detection
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: word
        words:
          - "ExampleCMS"
"""


def test_generate_cve_template_stages_review_gated_pack_and_deployment_badge(client, monkeypatch) -> None:
    engagement_id = _create_engagement(client)
    record_id = _create_cve_record(client)
    _store_connected_chatgpt_token(client, engagement_id)

    calls: list[dict[str, object]] = []

    def fake_generate(**kwargs):
        calls.append(kwargs)
        assert "detection-only" in kwargs["instructions"]
        assert "CVE-2026-7777" in str(kwargs["input_items"])
        return {
            "template_yaml": SAFE_TEMPLATE,
            "detection_strategy": "GET landing page and match ExampleCMS marker.",
            "rationale": "Presence detection only.",
            "safety_notes": ["No exploit payloads", "No static targets"],
        }

    monkeypatch.setattr(
        "api.app.services.cve_template_generator.send_chatgpt_backend_streaming_json_request",
        fake_generate,
    )

    response = client.post(
        f"/api/v1/threat-intel/{record_id}/generate-template",
        headers={"X-Actor": "template-operator"},
        json={"engagement_id": engagement_id},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "generated"
    assert payload["pack_id"]
    assert payload["artifact_id"]
    assert payload["pack_status"] == "generated"
    assert payload["validation"]["detection_only"] is True
    assert payload["validation"]["auto_deploy"] is False
    assert "approval" in payload["lifecycle_note"]
    assert "ExampleCMS" in payload["template_yaml"]
    assert "generated-detection-template.yaml" in payload["yaml_diff"]
    assert len(calls) == 1

    with client.app.state.session_factory() as session:
        pack = session.get(CapabilityPack, UUID(payload["pack_id"]))
        record = session.get(ThreatIntelRecord, UUID(record_id))
        assert pack is not None
        assert pack.status == "generated"
        assert pack.generation_mode == "ai-cve-nuclei-template"
        assert pack.manifest_json["cve_template_generation"]["auto_deploy"] is False
        assert len(pack.validation_results) == 0
        assert record is not None
        link = record.metadata_json["generated_nuclei_template"]
        assert link["status"] == "pending_review"
        assert link["pack_id"] == payload["pack_id"]

    validate_response = client.post(
        f"/api/v1/packs/{payload['pack_id']}/validate",
        headers={"X-Actor": "validator"},
    )
    assert validate_response.status_code == 200
    assert validate_response.json()["status"] == "passed"

    approve_response = client.post(
        f"/api/v1/packs/{payload['pack_id']}/approve",
        headers={"X-Actor": "reviewer"},
    )
    assert approve_response.status_code == 200
    assert approve_response.json()["status"] == "approved"

    deploy_response = client.post(
        f"/api/v1/packs/{payload['pack_id']}/deploy",
        headers={"X-Actor": "deployer"},
        json={"engagement_id": engagement_id, "deployment_target": "engagement-runtime"},
    )
    assert deploy_response.status_code == 200
    assert deploy_response.json()["status"] == "deployed"

    with client.app.state.session_factory() as session:
        record = session.get(ThreatIntelRecord, UUID(record_id))
        assert record is not None
        link = record.metadata_json["generated_nuclei_template"]
        assert link["status"] == "deployed"
        assert link["deployment_id"] == deploy_response.json()["id"]

        badges = build_finding_threat_intel_badges(
            session,
            SimpleNamespace(
                title="CVE-2026-7777 ExampleCMS vulnerable marker",
                summary="ExampleCMS page detected.",
                target_id="app.example.test",
                evidence_ref="artifact://nuclei/examplecms",
                control_family="web",
                wstg_id=None,
                asvs_reference=None,
                methodology_tags=[],
            ),
        )
        assert badges["available"] is True
        generated_template = badges["badges"][0]["generated_template"]
        assert generated_template["tested_via_generated_template"] is True
        assert generated_template["status"] == "deployed"


def test_generate_cve_template_returns_unavailable_without_chatgpt_oauth(client) -> None:
    engagement_id = _create_engagement(client)
    record_id = _create_cve_record(client)

    response = client.post(
        f"/api/v1/threat-intel/{record_id}/generate-template",
        headers={"X-Actor": "template-operator"},
        json={"engagement_id": engagement_id},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "unavailable"
    assert payload["pack_id"] is None
    assert payload["validation"]["token_exposed"] is False
    assert "ChatGPT OAuth" in payload["message"]


def test_dangerous_generated_template_is_rejected_before_pack_storage(client, monkeypatch) -> None:
    engagement_id = _create_engagement(client)
    record_id = _create_cve_record(client)
    _store_connected_chatgpt_token(client, engagement_id)

    def fake_generate(**_kwargs):
        return {
            "template_yaml": """id: cve-2026-7777-unsafe
info:
  name: Unsafe generated exploit
  severity: critical
http:
  - method: POST
    path:
      - "{{BaseURL}}/exploit"
    raw:
      - "POST /exploit HTTP/1.1"
    matchers:
      - type: word
        words:
          - "root"
""",
        }

    monkeypatch.setattr(
        "api.app.services.cve_template_generator.send_chatgpt_backend_streaming_json_request",
        fake_generate,
    )
    response = client.post(
        f"/api/v1/threat-intel/{record_id}/generate-template",
        headers={"X-Actor": "template-operator"},
        json={"engagement_id": engagement_id},
    )
    assert response.status_code == 422
    assert "rejected" in response.json()["detail"]

    with client.app.state.session_factory() as session:
        packs = session.scalars(
            select(CapabilityPack).where(CapabilityPack.generation_mode == "ai-cve-nuclei-template")
        ).all()
        assert packs == []


def _create_engagement(client) -> str:
    response = client.post(
        "/api/v1/engagements",
        headers={"X-Actor": "tester"},
        json={"name": "CVE Template Generation", "client": "Acme", "roe_ref": "ROE-CVE-TEMPLATE"},
    )
    assert response.status_code == 201
    return response.json()["id"]


def _create_cve_record(client) -> str:
    response = client.post(
        "/api/v1/threat-intel/ingest",
        headers={"X-Actor": "intel"},
        json={
            "records": [
                {
                    "source": "cve-cvss",
                    "advisory_id": "CVE-2026-7777",
                    "title": "ExampleCMS unsafe redirect disclosure",
                    "summary": "ExampleCMS exposes a vulnerable marker on affected frontends.",
                    "affected_products": ["ExampleCMS"],
                    "affected_versions": ["1.2.x"],
                    "product_match_hints": ["CVE-2026-7777", "ExampleCMS"],
                    "suggested_test_patterns": ["cve:CVE-2026-7777", "CWE-79"],
                    "confidence": 0.86,
                    "severity": "high",
                    "references": ["https://example.invalid/cve-2026-7777"],
                    "metadata": {
                        "cve_id": "CVE-2026-7777",
                        "cvss_score": 8.1,
                        "cvss_severity": "HIGH",
                        "cwe_ids": ["CWE-79"],
                    },
                }
            ]
        },
    )
    assert response.status_code == 201
    return response.json()[0]["id"]


def _store_connected_chatgpt_token(client, engagement_id: str) -> None:
    settings = get_settings()
    with client.app.state.session_factory() as session:
        store_chatgpt_oauth_token_set(
            session=session,
            engagement_id=UUID(engagement_id),
            settings=settings,
            source="test",
            token_set={
                "access_token": "test-access-token",
                "refresh_token": "test-refresh-token",
                "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
                "account_id": "acct_test_cve_template",
            },
        )
        session.commit()
