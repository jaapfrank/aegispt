from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import select

from api.app.config import get_settings
from api.app.models import CapabilityPack, ThreatIntelRecord
from api.app.services.chatgpt_oauth import store_chatgpt_oauth_token_set

SAFE_RESEARCH_TEMPLATE = """id: mqtt-anonymous-subscribe-detection
info:
  name: MQTT anonymous subscribe detection
  author: aegispt-ai
  severity: medium
  description: Detection-only HTTP metadata check requiring operator review.
  tags: mqtt,detection,ai-research
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: word
        words:
          - "MQTT"
"""


def test_ai_research_custom_idea_stages_review_gated_nuclei_pack(client, monkeypatch) -> None:
    engagement_id = _create_engagement(client)
    cve_record_id = _create_cve_record(client)
    _store_connected_chatgpt_token(client, engagement_id)
    calls: list[dict[str, object]] = []

    def fake_generate(**kwargs):
        calls.append(kwargs)
        assert "detection-only" in kwargs["instructions"]
        assert "anonymous subscribe" in str(kwargs["input_items"])
        return {
            "template_yaml": SAFE_RESEARCH_TEMPLATE,
            "detection_strategy": "Check landing metadata for MQTT markers without connecting to the broker.",
            "rationale": "Operator asked for MQTT anonymous subscribe research, staged as detection-only review output.",
            "safety_notes": ["No broker login", "No subscribe action"],
        }

    monkeypatch.setattr(
        "api.app.services.ai_research.send_chatgpt_backend_streaming_json_request",
        fake_generate,
    )

    response = client.post(
        "/api/v1/ai/research/generate-script",
        headers={"X-Actor": "research-operator"},
        json={
            "engagement_id": engagement_id,
            "description": "Check if MQTT broker allows anonymous subscribe on port 1883",
            "output_kind": "nuclei_yaml",
        },
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "generated"
    assert payload["pack_id"]
    assert payload["artifact_id"]
    assert payload["pack_status"] == "generated"
    assert payload["validation"]["detection_only"] is True
    assert payload["validation"]["auto_deploy"] is False
    assert "MQTT" in payload["template_yaml"]
    assert "generated-detection-template.yaml" in payload["yaml_diff"]
    assert len(calls) == 1

    with client.app.state.session_factory() as session:
        pack = session.get(CapabilityPack, UUID(payload["pack_id"]))
        record = session.get(ThreatIntelRecord, UUID(payload["record_id"]))
        assert pack is not None
        assert pack.generation_mode == "ai-research-nuclei-template"
        assert pack.status == "generated"
        assert pack.manifest_json["ai_research_generation"]["auto_deploy"] is False
        assert pack.manifest_json["ai_research_generation"]["operator_review_required"] is True
        assert len(pack.validation_results) == 0
        assert record is not None
        assert record.source == "ai-research"
        assert record.metadata_json["ai_research"] is True
        assert record.metadata_json["generated_nuclei_template"]["pack_id"] == payload["pack_id"]

    lab_response = client.get(f"/api/v1/ai/research?engagement_id={engagement_id}")
    assert lab_response.status_code == 200
    lab = lab_response.json()
    assert lab["engagement_id"] == engagement_id
    assert any(record["id"] == cve_record_id for record in lab["cve_records"])
    proposals = lab["research_proposals"]
    assert len(proposals) == 1
    assert proposals[0]["pack_id"] == payload["pack_id"]
    assert proposals[0]["source"] == "custom_idea"
    assert proposals[0]["status"] == "staged"
    assert proposals[0]["validation"]["detection_only"] is True
    assert proposals[0]["yaml_diff"]

    validate_response = client.post(
        f"/api/v1/packs/{payload['pack_id']}/validate",
        headers={"X-Actor": "validator"},
    )
    assert validate_response.status_code == 200
    assert validate_response.json()["status"] == "passed"


def test_ai_research_python_detection_returns_safe_blocked_state(client) -> None:
    engagement_id = _create_engagement(client)
    response = client.post(
        "/api/v1/ai/research/generate-script",
        headers={"X-Actor": "research-operator"},
        json={
            "engagement_id": engagement_id,
            "description": "Write a Python detector for MQTT anonymous subscribe",
            "output_kind": "python_detection",
        },
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "blocked"
    assert payload["pack_id"] is None
    assert payload["validation"]["blocked"] is True
    assert payload["validation"]["auto_deploy"] is False
    assert "Python detection script generation is blocked" in payload["message"]

    with client.app.state.session_factory() as session:
        packs = session.scalars(
            select(CapabilityPack).where(CapabilityPack.generation_mode == "ai-research-nuclei-template")
        ).all()
        assert packs == []


def test_ai_research_unsafe_template_is_rejected_before_pack_storage(client, monkeypatch) -> None:
    engagement_id = _create_engagement(client)
    _store_connected_chatgpt_token(client, engagement_id)

    def fake_generate(**_kwargs):
        return {
            "template_yaml": """id: unsafe-ai-research
info:
  name: Unsafe AI research
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
        "api.app.services.ai_research.send_chatgpt_backend_streaming_json_request",
        fake_generate,
    )
    response = client.post(
        "/api/v1/ai/research/generate-script",
        headers={"X-Actor": "research-operator"},
        json={
            "engagement_id": engagement_id,
            "description": "Generate an aggressive exploit proof",
            "output_kind": "nuclei_yaml",
        },
    )
    assert response.status_code == 422
    assert "rejected" in response.json()["detail"]

    with client.app.state.session_factory() as session:
        packs = session.scalars(
            select(CapabilityPack).where(CapabilityPack.generation_mode == "ai-research-nuclei-template")
        ).all()
        assert packs == []


def _create_engagement(client) -> str:
    response = client.post(
        "/api/v1/engagements",
        headers={"X-Actor": "tester"},
        json={"name": "AI Research Lab", "client": "Acme", "roe_ref": "ROE-RESEARCH"},
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
                    "advisory_id": "CVE-2026-8888",
                    "title": "ExampleMQTT anonymous subscribe marker",
                    "summary": "ExampleMQTT exposes a marker for affected broker frontends.",
                    "affected_products": ["ExampleMQTT"],
                    "affected_versions": ["2.x"],
                    "product_match_hints": ["CVE-2026-8888", "ExampleMQTT"],
                    "suggested_test_patterns": ["cve:CVE-2026-8888", "MQTT"],
                    "confidence": 0.82,
                    "severity": "medium",
                    "references": ["https://example.invalid/cve-2026-8888"],
                    "metadata": {
                        "cve_id": "CVE-2026-8888",
                        "cvss_score": 6.5,
                        "cvss_severity": "MEDIUM",
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
                "account_id": "acct_test_ai_research",
            },
        )
        session.commit()
