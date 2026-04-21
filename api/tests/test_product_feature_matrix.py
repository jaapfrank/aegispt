from __future__ import annotations

from io import BytesIO
from urllib.parse import urlparse

from pypdf import PdfReader


def test_adaptive_pack_pipeline_binds_to_run_and_exports_reports_end_to_end(
    inline_client,
    probe_server: str,
) -> None:
    parsed_target = urlparse(probe_server)
    target_host = parsed_target.hostname or "127.0.0.1"

    engagement = inline_client.post(
        "/api/v1/engagements",
        headers={"X-Actor": "matrix-operator"},
        json={
            "name": "Product Feature Matrix",
            "client": "Acme Corp",
            "roe_ref": "ROE-2026-250",
        },
    ).json()

    inline_client.post(
        f"/api/v1/engagements/{engagement['id']}/scope",
        headers={"X-Actor": "matrix-operator"},
        json={
            "allowlist_json": {"urls": [probe_server], "hosts": [target_host]},
            "denylist_json": {},
        },
    )

    inventory = inline_client.post(
        "/api/v1/inventory/runs",
        headers={"X-Actor": "inventory-operator"},
        json={
            "engagement_id": engagement["id"],
            "source_tools": ["httpx"],
            "observations": [
                {
                    "tool": "httpx",
                    "kind": "inventory",
                    "data": {
                        "hosts": [target_host],
                        "urls": [probe_server],
                        "endpoints": [
                            {
                                "url": probe_server,
                                "methods": ["GET"],
                                "status_code": 200,
                                "title": "Probe",
                            }
                        ],
                        "technologies": [
                            {"name": "Probe Service", "vendor": "AegisPT", "confidence": 0.9}
                        ],
                        "auth_mechanisms": [],
                        "fingerprints": [
                            {"vendor": "AegisPT", "product": "Probe Service", "version": "1.0"}
                        ],
                        "confidence": 0.9,
                    },
                }
            ],
        },
    ).json()

    intel = inline_client.post(
        "/api/v1/threat-intel/ingest",
        headers={"X-Actor": "intel-operator"},
        json={
            "records": [
                {
                    "source": "internal-knowledge",
                    "advisory_id": "AEGIS-UI-0001",
                    "title": "Probe service hardening guidance",
                    "summary": "Baseline HTTP profiling and adaptive review are relevant for this probe target.",
                    "affected_products": ["probe service"],
                    "product_match_hints": ["probe service", "aegispt"],
                    "attack_surface_type": "web",
                    "suggested_test_patterns": ["httpx", "nuclei", "playwright"],
                    "confidence": 0.8,
                    "severity": "medium",
                }
            ]
        },
    ).json()[0]

    relevance = inline_client.post(
        "/api/v1/relevance/analyze",
        headers={"X-Actor": "planner"},
        json={
            "engagement_id": engagement["id"],
            "inventory_snapshot_id": inventory["id"],
            "threat_intel_ids": [intel["id"]],
            "include_prior_findings": False,
        },
    ).json()

    pack = inline_client.post(
        "/api/v1/packs/generate",
        headers={"X-Actor": "planner"},
        json={
            "engagement_id": engagement["id"],
            "relevance_decision_id": relevance["id"],
            "name": "matrix-pack",
        },
    ).json()

    validation = inline_client.post(
        f"/api/v1/packs/{pack['id']}/validate",
        headers={"X-Actor": "validator"},
    ).json()
    assert validation["status"] == "passed"

    approved_pack = inline_client.post(
        f"/api/v1/packs/{pack['id']}/approve?notes=matrix",
        headers={"X-Actor": "approver"},
    ).json()
    assert approved_pack["status"] == "approved"

    deployment = inline_client.post(
        f"/api/v1/packs/{pack['id']}/deploy",
        headers={"X-Actor": "deployer"},
        json={
            "engagement_id": engagement["id"],
            "deployment_target": "engagement-runtime",
            "run_profile_name": "passive-web-baseline",
            "notes": "matrix deployment",
        },
    ).json()
    assert deployment["status"] == "deployed"

    run = inline_client.post(
        f"/api/v1/engagements/{engagement['id']}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "passive-web-baseline",
            "source_inventory_snapshot_id": inventory["id"],
            "configuration_json": {
                "assessment_type": "Website / Web App",
                "test_profile": "Standard",
                "execution_profile": "passive-web-baseline",
                "targets": {"urls": [probe_server]},
                "modules": {
                    "discovery": True,
                    "web_crawling": True,
                    "content_discovery": True,
                    "nuclei_checks": True,
                },
                "safety": {
                    "rate_limit_rps": 1,
                    "concurrency": 1,
                    "time_budget_minutes": 30,
                    "active_checks": "passive-only",
                    "adaptive_generation": True,
                    "max_validation_depth": "light",
                },
                "eta": {
                    "estimated_total_minutes": 30,
                    "estimated_impact": "low",
                    "confidence": "medium",
                },
            },
        },
    ).json()

    assert run["status"] == "queued"
    assert run["pack_binding"] is not None
    assert run["pack_binding"]["pack_id"] == pack["id"]
    assert run["pack_binding"]["pack_version"] == approved_pack["version"]

    dispatch = inline_client.post(
        f"/api/v1/runs/{run['id']}/dispatch",
        headers={"X-Actor": "dispatcher"},
    ).json()
    hydrated_run = dispatch["run"]
    assert hydrated_run["status"] in {"completed", "completed_with_errors"}

    reports = inline_client.get(
        f"/api/v1/runs/{run['id']}/reports",
        headers={"X-Actor": "operator"},
    ).json()
    assert {item["variant"] for item in reports} == {"executive", "technical", "evidence", "retest"}
    technical = next(item for item in reports if item["variant"] == "technical")
    assert technical["export_paths"]["pdf"].endswith("format=pdf&variant=technical")
    assert technical["download_names"]["pdf"].endswith(".pdf")
    assert technical["download_names"]["html"].endswith(".html")
    assert technical["download_names"]["markdown"].endswith(".md")

    markdown = inline_client.get(
        f"/api/v1/runs/{run['id']}/report?format=markdown&variant=technical",
        headers={"X-Actor": "operator"},
    )
    html = inline_client.get(
        f"/api/v1/runs/{run['id']}/report?format=html&variant=technical",
        headers={"X-Actor": "operator"},
    )
    pdf = inline_client.get(
        f"/api/v1/runs/{run['id']}/report?format=pdf&variant=technical",
        headers={"X-Actor": "operator"},
    )

    assert markdown.status_code == 200
    assert markdown.headers["content-disposition"].endswith('-technical.md"')
    assert "AegisPT Run Report" in markdown.text

    assert html.status_code == 200
    assert html.headers["content-disposition"].endswith('-technical.html"')
    assert html.headers["content-type"].startswith("text/html")
    assert "<h1>AegisPT Run Report</h1>" in html.text

    assert pdf.status_code == 200
    assert pdf.headers["content-disposition"].endswith('-technical.pdf"')
    assert pdf.headers["content-type"].startswith("application/pdf")
    assert pdf.content.startswith(b"%PDF")
    pdf_reader = PdfReader(BytesIO(pdf.content))
    extracted = "\n".join(page.extract_text() or "" for page in pdf_reader.pages)
    assert "AegisPT Run Report" in extracted

    binding = inline_client.get(
        f"/api/v1/runs/{run['id']}/pack",
        headers={"X-Actor": "operator"},
    ).json()
    assert binding["pack_id"] == pack["id"]
    assert binding["deployment_id"] == deployment["id"]
