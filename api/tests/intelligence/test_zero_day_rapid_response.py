from __future__ import annotations

from uuid import UUID

from sqlalchemy import select

from api.app.models import Approval, Run


def _create_engagement_with_scope(client, *, url: str = "https://portal.example.test") -> str:
    engagement_response = client.post(
        "/api/v1/engagements",
        headers={"X-Actor": "zero-day-operator"},
        json={"name": "Zero-Day Response", "client": "Acme", "roe_ref": "ROE-ZD"},
    )
    assert engagement_response.status_code == 201
    engagement_id = engagement_response.json()["id"]
    scope_response = client.post(
        f"/api/v1/engagements/{engagement_id}/scope",
        headers={"X-Actor": "zero-day-operator"},
        json={"allowlist_json": {"urls": [url]}, "denylist_json": {}},
    )
    assert scope_response.status_code == 201
    return engagement_id


def _create_inventory_snapshot(
    client,
    *,
    engagement_id: str,
    version: str,
    url: str = "https://portal.example.test",
) -> str:
    response = client.post(
        "/api/v1/inventory/runs",
        headers={"X-Actor": "zero-day-operator"},
        json={
            "engagement_id": engagement_id,
            "source_tools": ["httpx"],
            "observations": [
                {
                    "tool": "httpx",
                    "kind": "inventory",
                    "data": {
                        "endpoints": [{"url": url, "methods": ["GET"], "confidence": 0.9}],
                        "fingerprints": [
                            {
                                "vendor": "Apache",
                                "product": "Struts",
                                "version": version,
                                "confidence": 0.92,
                            }
                        ],
                        "signal_profile": {
                            "signals": [
                                {
                                    "key": "server_header",
                                    "value": f"Apache Struts/{version}",
                                    "confidence": 0.91,
                                    "source": "fixture",
                                }
                            ]
                        },
                    },
                }
            ],
        },
    )
    assert response.status_code == 201
    payload = response.json()
    assert payload["normalized_inventory_json"]["tech_stack_profile"]["server"]
    return payload["id"]


def _ingest_zero_day_record(client) -> str:
    response = client.post(
        "/api/v1/threat-intel/ingest",
        headers={"X-Actor": "zero-day-operator"},
        json={
            "records": [
                {
                    "source": "local-zero-day-feed",
                    "advisory_id": "CVE-2026-32401",
                    "title": "Apache Struts rapid response RCE",
                    "summary": "Breaking advisory for Apache Struts before 2.15.0.",
                    "affected_products": ["Apache Struts"],
                    "affected_versions": ["< 2.15.0"],
                    "product_match_hints": ["Struts"],
                    "severity": "critical",
                    "confidence": 0.94,
                    "references": ["https://example.test/advisories/CVE-2026-32401"],
                }
            ]
        },
    )
    assert response.status_code == 201
    return response.json()[0]["id"]


def test_zero_day_response_matches_stale_tech_stack_versions_and_dashboard_alerts(client) -> None:
    engagement_id = _create_engagement_with_scope(client)
    snapshot_id = _create_inventory_snapshot(client, engagement_id=engagement_id, version="2.14.1")
    record_id = _ingest_zero_day_record(client)

    response = client.get(f"/api/v1/engagements/{engagement_id}/threat-intel/zero-day-response")
    assert response.status_code == 200
    payload = response.json()
    assert payload["boundary"]["external_lookup_performed"] is False
    assert payload["boundary"]["automatic_tests_started"] is False
    assert payload["alert_count"] == 1
    alert = payload["alerts"][0]
    assert alert["record_id"] == record_id
    assert alert["source_inventory_snapshot_id"] == snapshot_id
    assert alert["advisory_id"] == "CVE-2026-32401"
    assert alert["version_status"] == "affected"
    assert "2.14.1" in alert["version_detail"]
    assert alert["matched_product"]["product"] == "Struts"
    assert alert["scan_now"]["requires_operator_approval"] is True

    dashboard_response = client.get(f"/api/v1/dashboard?engagement_id={engagement_id}")
    assert dashboard_response.status_code == 200
    dashboard_alerts = dashboard_response.json()["zero_day_rapid_response"]["alerts"]
    assert dashboard_alerts[0]["advisory_id"] == "CVE-2026-32401"


def test_zero_day_response_does_not_flag_versions_outside_affected_range(client) -> None:
    engagement_id = _create_engagement_with_scope(client)
    _create_inventory_snapshot(client, engagement_id=engagement_id, version="2.15.0")
    _ingest_zero_day_record(client)

    response = client.get(f"/api/v1/engagements/{engagement_id}/threat-intel/zero-day-response")
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "clear"
    assert payload["alert_count"] == 0


def test_scan_now_stages_approval_gated_nuclei_run_without_auto_approval_or_dispatch(client) -> None:
    engagement_id = _create_engagement_with_scope(client)
    snapshot_id = _create_inventory_snapshot(client, engagement_id=engagement_id, version="2.14.1")
    record_id = _ingest_zero_day_record(client)

    response = client.post(
        f"/api/v1/engagements/{engagement_id}/threat-intel/zero-day-response/{record_id}/scan-now",
        headers={"X-Actor": "zero-day-operator"},
        json={"target": "https://portal.example.test"},
    )
    assert response.status_code == 202
    payload = response.json()
    assert payload["accepted"] is True
    assert payload["profile_name"] == "active-web-rce-nuclei-audit"
    assert payload["run_status"] == "pending_approval"
    assert payload["required_approvals"] == 1
    assert payload["automatic_approval_created"] is False
    assert payload["automatic_tests_started"] is False
    assert payload["scope_enforced"] is True

    with client.app.state.session_factory() as session:
        run = session.get(Run, UUID(payload["run_id"]))
        assert run is not None
        assert run.source_inventory_snapshot_id == UUID(snapshot_id)
        assert run.configuration_json["zero_day_rapid_response"]["advisory_id"] == "CVE-2026-32401"
        assert run.configuration_json["zero_day_rapid_response"]["automatic_approval_created"] is False
        assert run.configuration_json["nuclei"]["requested_template_ids"] == ["cve-2026-32401"]
        approvals = session.scalars(select(Approval).where(Approval.run_id == run.id)).all()
        assert approvals == []
        assert list(run.tasks) == []
