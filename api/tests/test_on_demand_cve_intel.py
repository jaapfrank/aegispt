from __future__ import annotations

from pathlib import Path
from uuid import UUID

from sqlalchemy import select

from api.app.config import get_settings
from api.app.models import Run, Task
from api.app.services.cve_sync import FeedFetchResult
from api.app.services.inventory import create_inventory_snapshot_record
from api.app.services.on_demand_cve_intel import build_run_cve_intelligence
from api.app.services.threat_intel import upsert_threat_intel_record


def _create_service_run(client) -> tuple[str, str]:
    engagement_response = client.post(
        "/api/v1/engagements",
        headers={"X-Actor": "operator"},
        json={"name": "On-demand CVE LAN", "client": "Acme", "roe_ref": "ROE-CVE-INTEL"},
    )
    engagement_id = engagement_response.json()["id"]
    client.post(
        f"/api/v1/engagements/{engagement_id}/scope",
        headers={"X-Actor": "operator"},
        json={"allowlist_json": {"ip_addresses": ["10.0.20.14"]}, "denylist_json": {}},
    )
    run_response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "passive-network-service-enumeration",
            "configuration_json": {
                "targets": {"ip_addresses": ["10.0.20.14"]},
                "assessment_type": "Internal Range / LAN",
            },
        },
    )
    assert run_response.status_code == 201
    return engagement_id, run_response.json()["id"]


def _seed_nginx_inventory_and_intel(session, *, engagement_id: str, run_id: str) -> None:
    snapshot = create_inventory_snapshot_record(
        engagement_id=UUID(engagement_id),
        requested_by="operator",
        source_tools=["nmap"],
        observations=[
            {
                "tool": "nmap",
                "kind": "inventory",
                "data": {
                    "hosts": ["10.0.20.14"],
                    "services": [
                        {
                            "host": "10.0.20.14",
                            "port": 80,
                            "protocol": "tcp",
                            "service": "http",
                            "product": "nginx",
                            "version": "1.25",
                            "confidence": 0.9,
                        }
                    ],
                    "fingerprints": [
                        {
                            "vendor": "F5",
                            "product": "nginx",
                            "version": "1.25",
                            "confidence": 0.86,
                        }
                    ],
                },
            }
        ],
        environment_notes=["Service inventory from bounded nmap service detection."],
        assumptions=["No exploit tests were run."],
        raw_inputs_json={"run_id": run_id},
    )
    session.add(snapshot)
    upsert_threat_intel_record(
        session,
        {
            "source": "cve-cvss",
            "advisory_id": "CVE-2026-9999",
            "title": "Critical nginx request smuggling",
            "summary": "nginx 1.25 request handling flaw.",
            "affected_products": ["nginx", "F5 nginx"],
            "affected_versions": ["1.25"],
            "product_match_hints": ["nginx", "nginx 1.25"],
            "confidence": 0.92,
            "severity": "critical",
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-9999"],
            "metadata": {
                "feed_type": "cve_cvss",
                "cvss_score": 9.1,
                "cvss_severity": "CRITICAL",
                "external_lookup_performed": False,
            },
        },
    )


def test_on_demand_cve_intelligence_matches_discovery_products_without_running_tests(
    client,
    tmp_path: Path,
    monkeypatch,
) -> None:
    template_dir = tmp_path / "nuclei-templates"
    template_dir.mkdir()
    (template_dir / "CVE-2026-9999.yaml").write_text(
        "id: CVE-2026-9999\ninfo:\n  name: nginx detection\n  severity: critical\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("NUCLEI_TEMPLATES_DIR", str(template_dir))

    engagement_id, run_id = _create_service_run(client)
    with client.app.state.session_factory() as session:
        _seed_nginx_inventory_and_intel(session, engagement_id=engagement_id, run_id=run_id)
        initial_task_count = len(session.scalars(select(Task).where(Task.run_id == UUID(run_id))).all())
        session.commit()

    response = client.get(f"/api/v1/runs/{run_id}/cve-intelligence")

    assert response.status_code == 200
    payload = response.json()
    assert payload["product_count"] >= 1
    assert payload["cve_count"] == 1
    assert payload["rows"][0]["cve_id"] == "CVE-2026-9999"
    assert payload["rows"][0]["test_status"] == "ready"
    assert payload["rows"][0]["affected_product"]["host"] == "10.0.20.14"
    assert payload["boundary"]["automatic_tests_started"] is False

    with client.app.state.session_factory() as session:
        task_count = len(session.scalars(select(Task).where(Task.run_id == UUID(run_id))).all())
        assert task_count == initial_task_count


def test_operator_action_queues_targeted_nuclei_task_but_does_not_dispatch(
    client,
    tmp_path: Path,
    monkeypatch,
) -> None:
    template_dir = tmp_path / "nuclei-templates"
    template_dir.mkdir()
    (template_dir / "CVE-2026-9999.yaml").write_text(
        "id: CVE-2026-9999\ninfo:\n  name: nginx detection\n  severity: critical\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("NUCLEI_TEMPLATES_DIR", str(template_dir))
    engagement_id, run_id = _create_service_run(client)
    with client.app.state.session_factory() as session:
        _seed_nginx_inventory_and_intel(session, engagement_id=engagement_id, run_id=run_id)
        session.commit()

    response = client.post(
        f"/api/v1/runs/{run_id}/cve-intelligence/CVE-2026-9999/queue-test",
        headers={"X-Actor": "operator"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["task"]["tool"] == "nuclei"
    assert payload["task"]["status"] == "queued"
    assert payload["task"]["params_json"]["on_demand_cve_intelligence"]["operator_approved"] is True
    assert payload["task"]["params_json"]["on_demand_cve_intelligence"]["automatic_tests_started"] is False
    assert payload["run"]["status"] == "queued"


def test_bounded_nvd_lookup_uses_discovered_product_query(client) -> None:
    engagement_id, run_id = _create_service_run(client)
    with client.app.state.session_factory() as session:
        snapshot = create_inventory_snapshot_record(
            engagement_id=UUID(engagement_id),
            requested_by="operator",
            source_tools=["nmap"],
            observations=[
                {
                    "tool": "nmap",
                    "kind": "inventory",
                    "data": {
                        "hosts": ["10.0.20.14"],
                        "services": [
                            {
                                "host": "10.0.20.14",
                                "port": 22,
                                "protocol": "tcp",
                                "service": "ssh",
                                "product": "OpenSSH",
                                "version": "9.0",
                                "confidence": 0.9,
                            }
                        ],
                        "fingerprints": [{"product": "OpenSSH", "version": "9.0"}],
                    },
                }
            ],
            raw_inputs_json={"run_id": run_id},
        )
        session.add(snapshot)
        session.commit()
        run = session.scalar(select(Run).where(Run.id == UUID(run_id)))
        assert run is not None
        captured_queries = []

        def fake_fetcher(*, url: str, headers: dict, params: dict, timeout: float) -> FeedFetchResult:
            captured_queries.append(params["keywordSearch"])
            return FeedFetchResult(
                status_code=200,
                json_data={
                    "vulnerabilities": [
                        {
                            "cve": {
                                "id": "CVE-2026-12345",
                                "descriptions": [{"lang": "en", "value": "OpenSSH 9.0 critical flaw."}],
                                "metrics": {
                                    "cvssMetricV31": [
                                        {"cvssData": {"baseScore": 9.8}, "baseSeverity": "CRITICAL"}
                                    ]
                                },
                                "references": {"referenceData": [{"url": "https://nvd.nist.gov/vuln/detail/CVE-2026-12345"}]},
                            }
                        }
                    ]
                },
            )

        payload = build_run_cve_intelligence(
            session,
            run=run,
            settings=get_settings(),
            allow_live_nvd=True,
            fetcher=fake_fetcher,
        )

    assert captured_queries == ["OpenSSH 9.0"]
    assert payload["boundary"]["live_nvd_lookup_performed"] is True
    assert payload["rows"][0]["cve_id"] == "CVE-2026-12345"
    assert payload["rows"][0]["cvss_score"] == 9.8
    assert payload["rows"][0]["test_status"] == "informational"
    assert payload["rows"][0]["actions"] == []
