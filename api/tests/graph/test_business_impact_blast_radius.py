from __future__ import annotations

from uuid import UUID

from sqlalchemy import select

from api.app.models import Engagement, Finding, InventorySnapshot, Run
from api.app.services.attack_paths import build_attack_path_summary
from api.app.services.business_impact import normalize_business_tags


def _seed_blast_radius_run(client) -> tuple[str, str, str]:
    normalized_inventory = {
        "business_processes": [
            {
                "id": "checkout",
                "label": "Checkout and billing",
                "category": "revenue",
                "criticality": "critical",
                "asset_refs": ["shop.example.test", "https://shop.example.test/checkout"],
            }
        ],
        "hosts": [
            {
                "host": "shop.example.test",
                "business_process": "Checkout and billing",
                "business_category": "revenue",
                "business_criticality": "critical",
                "confidence": 0.91,
            }
        ],
        "services": [
            {
                "host": "shop.example.test",
                "port": 443,
                "protocol": "https",
                "service": "https",
                "confidence": 0.88,
            }
        ],
        "http_endpoints": [
            {
                "url": "https://shop.example.test/checkout",
                "business_process": "Checkout and billing",
                "business_category": "revenue",
                "business_criticality": "critical",
                "confidence": 0.9,
            }
        ],
    }

    with client.app.state.session_factory() as session:
        engagement = Engagement(
            name="Blast Radius Engagement",
            client="Acme",
            roe_ref="ROE-BLAST",
            tenant_id="blast-tenant",
            status="authorized",
        )
        session.add(engagement)
        session.flush()
        run = Run(
            engagement_id=engagement.id,
            requested_by="blast-radius-test",
            status="completed",
            configuration_json={
                "assessment_type": "Website / Web App",
                "targets": {"urls": ["https://shop.example.test"]},
            },
        )
        session.add(run)
        session.flush()
        inventory = InventorySnapshot(
            engagement_id=engagement.id,
            requested_by="blast-radius-test",
            status="completed",
            source_tools_json=["fixture"],
            raw_inputs_json={"source": "business-impact-fixture"},
            normalized_inventory_json=normalized_inventory,
            summary_json={"host_count": 1, "business_process_count": 1},
            confidence_score=0.9,
        )
        session.add(inventory)
        session.flush()
        run.source_inventory_snapshot_id = inventory.id
        finding = Finding(
            run_id=run.id,
            source_inventory_snapshot_id=inventory.id,
            title="Checkout SQL injection",
            severity="critical",
            target_id="https://shop.example.test/checkout",
            evidence_ref="artifact://blast-radius/sql-injection",
            status="open",
            summary="Stored evidence links the vulnerability to checkout.",
        )
        session.add(finding)
        session.commit()
        return str(engagement.id), str(run.id), str(inventory.id)


def test_business_process_tags_are_normalized_from_inventory() -> None:
    tags = normalize_business_tags(
        {
            "business_processes": [
                {
                    "id": "checkout",
                    "label": "Checkout and billing",
                    "category": "revenue",
                    "criticality": "critical",
                    "asset_refs": ["https://shop.example.test/checkout"],
                }
            ]
        }
    )

    assert tags["shop.example.test"]["category"] == "revenue"
    assert tags["https://shop.example.test/checkout"]["criticality"] == "critical"
    assert tags["host:shop.example.test"]["predefined"] is True


def test_attack_graph_bubbles_business_impact_to_candidate_path_and_dashboard(client) -> None:
    engagement_id, run_id, _ = _seed_blast_radius_run(client)

    with client.app.state.session_factory() as session:
        summary = build_attack_path_summary(session, UUID(run_id))

    assert summary is not None
    assert summary["summary"]["blast_radius_tier"] == "critical"
    assert summary["blast_radius"]["score"] >= 90
    assert summary["blast_radius"]["critical_path_count"] == 1
    path = summary["candidate_paths"][0]
    assert path["business_impact"]["primary_process"]["label"] == "Checkout and billing"
    assert path["business_impact"]["financial_exposure"] == "direct revenue exposure"
    assert path["business_impact"]["runtime_actions_performed"] is False

    dashboard_response = client.get(
        "/api/v1/dashboard",
        headers={"X-Tenant-ID": "blast-tenant", "X-Actor": "blast-radius-test"},
    )

    assert dashboard_response.status_code == 200
    dashboard = dashboard_response.json()
    assert dashboard["blast_radius"]["tier"] == "critical"
    assert dashboard["blast_radius"]["critical_path_count"] == 1
    assert dashboard["blast_radius"]["review_only"] is True
    assert dashboard["blast_radius"]["affected_business_processes"][0]["label"] == "Checkout and billing"

    with client.app.state.session_factory() as session:
        stored_run = session.scalar(select(Run).where(Run.id == UUID(run_id)))
        stored_engagement = session.scalar(select(Engagement).where(Engagement.id == UUID(engagement_id)))
    assert stored_run is not None and stored_run.status == "completed"
    assert stored_engagement is not None and stored_engagement.status == "authorized"
