from __future__ import annotations

from io import BytesIO
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from urllib.parse import parse_qs, urlparse

import pytest
from pypdf import PdfReader
from pathlib import Path


@pytest.fixture
def fake_nmap_report_binary(tmp_path: Path) -> str:
    binary_path = tmp_path / "fake-nmap-report"
    binary_path.write_text(
        """#!/usr/bin/env python3
import ipaddress
import sys
from pathlib import Path

args = sys.argv[1:]
if "--version" in args:
    print("Nmap version test-build")
    raise SystemExit(0)

output_path = Path(args[args.index("-oX") + 1])
discovery_only = "-sn" in args
targets = []
skip_next = False
for arg in args:
    if skip_next:
        skip_next = False
        continue
    if arg == "-oX":
        skip_next = True
        continue
    if arg.startswith("-"):
        continue
    targets.append(arg)

hosts = []
for target in targets:
    try:
        network = ipaddress.ip_network(target, strict=False)
        hosts.extend(str(host) for host in list(network.hosts())[:3])
    except ValueError:
        hosts.append(target)

if discovery_only:
    xml = "<?xml version='1.0'?><nmaprun>" + "".join(
        f"<host><status state='up'/><address addr='{host}' addrtype='ipv4'/></host>"
        for host in hosts
    ) + "</nmaprun>"
else:
    xml = "<?xml version='1.0'?><nmaprun>" + "".join(
        f"<host><status state='up'/><address addr='{host}' addrtype='ipv4'/><ports><port protocol='tcp' portid='80'><state state='open'/><service name='http' product='nginx' version='1.25'/></port></ports></host>"
        for host in hosts
    ) + "</nmaprun>"
output_path.write_text(xml, encoding="utf-8")
print(xml)
""",
        encoding="utf-8",
    )
    binary_path.chmod(0o755)
    return str(binary_path)


@pytest.fixture
def fake_zap_server(monkeypatch: pytest.MonkeyPatch) -> str:
    expected_api_key = "test-zap-key"

    class ZapHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            params = parse_qs(parsed.query)
            api_key = params.get("apikey", [""])[0]

            if api_key != expected_api_key:
                self._send_json({"error": "forbidden"}, status_code=403)
                return

            if parsed.path == "/JSON/core/view/version/":
                self._send_json({"version": "2.16.1"})
                return
            if parsed.path == "/JSON/core/action/newSession/":
                self._send_json({"Result": "OK"})
                return
            if parsed.path == "/JSON/core/action/accessUrl/":
                self._send_json({"Result": "OK"})
                return
            if parsed.path == "/JSON/spider/action/scan/":
                self._send_json({"scan": "1"})
                return
            if parsed.path == "/JSON/spider/view/status/":
                self._send_json({"status": "100"})
                return
            if parsed.path == "/JSON/pscan/view/recordsToScan/":
                self._send_json({"recordsToScan": "0"})
                return
            if parsed.path == "/JSON/core/view/urls/":
                baseurl = params.get("baseurl", [""])[0]
                self._send_json({"urls": [baseurl, f"{baseurl}/login"]})
                return
            if parsed.path == "/JSON/core/view/alerts/":
                baseurl = params.get("baseurl", [""])[0]
                self._send_json(
                    {
                        "alerts": [
                            {
                                "alert": "Missing X-Frame-Options Header",
                                "risk": "Low",
                                "url": baseurl,
                            }
                        ]
                    }
                )
                return

            self._send_json({"error": parsed.path}, status_code=404)

        def log_message(self, format: str, *args) -> None:  # noqa: A003
            return

        def _send_json(self, payload: dict[str, object], status_code: int = 200) -> None:
            body = (json.dumps(payload) + "\n").encode("utf-8")
            self.send_response(status_code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), ZapHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    base_url = f"http://{host}:{port}"

    monkeypatch.setenv("ZAP_BASE_URL", base_url)
    monkeypatch.setenv("ZAP_API_KEY", expected_api_key)

    try:
        yield base_url
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _create_codex_reviewed_adaptive_run(inline_client, probe_server: str) -> tuple[str, str, str]:
    parsed_target = urlparse(probe_server)
    target_host = parsed_target.hostname or "127.0.0.1"

    engagement = inline_client.post(
        "/api/v1/engagements",
        headers={"X-Actor": "report-operator"},
        json={
            "name": "Codex Adaptive Reporting",
            "client": "Acme Corp",
            "roe_ref": "ROE-2026-041",
        },
    ).json()

    inline_client.post(
        f"/api/v1/engagements/{engagement['id']}/scope",
        headers={"X-Actor": "report-operator"},
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
                    "advisory_id": "AEGIS-REPORT-0001",
                    "title": "Probe service adaptive follow-up",
                    "summary": "Adaptive auth and content review are relevant for this probe target.",
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
            "name": "report-pack",
        },
    ).json()

    inline_client.post(
        f"/api/v1/packs/{pack['id']}/validate",
        headers={"X-Actor": "validator"},
    )
    approved_pack = inline_client.post(
        f"/api/v1/packs/{pack['id']}/approve?notes=reporting",
        headers={"X-Actor": "approver"},
    ).json()
    inline_client.post(
        f"/api/v1/packs/{pack['id']}/deploy",
        headers={"X-Actor": "deployer"},
        json={
            "engagement_id": engagement["id"],
            "deployment_target": "engagement-runtime",
            "run_profile_name": "passive-web-baseline",
            "notes": "report deployment",
        },
    )

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

    inline_client.post(
        f"/api/v1/runs/{run['id']}/dispatch",
        headers={"X-Actor": "dispatcher"},
    )

    task = inline_client.post(
        "/api/v1/codex/tasks",
        headers={"X-Actor": "codex-planner"},
        json={
            "task_type": "pack_refinement",
            "scope": "Review the bound adaptive pack in the supervised build lane.",
            "inputs": {"review_bundle": True},
            "constraints": {"runtime_mutation": False},
            "expected_output": {"workspace_export": True, "validation_required": True},
            "generation_reason": "Refine report-pack coverage before future promotion decisions.",
            "source_context": {"pack_id": pack["id"]},
        },
    ).json()

    inline_client.post(
        f"/api/v1/codex/tasks/{task['id']}/run",
        headers={"X-Actor": "codex-runner"},
        json={
            "base_url": "http://127.0.0.1:8000",
            "workspace_root": "./codex-workspaces/report-pack",
            "dry_run": True,
        },
    )

    return run["id"], task["id"], approved_pack["version"]


def test_run_report_exports_markdown_and_html(
    inline_client,
    fake_zap_server: str,
) -> None:
    engagement_response = inline_client.post(
        "/api/v1/engagements",
        headers={"X-Actor": "tester"},
        json={
            "name": "Report Validation",
            "client": "Acme Corp",
            "roe_ref": "ROE-2026-008",
        },
    )
    engagement_id = engagement_response.json()["id"]

    inline_client.post(
        f"/api/v1/engagements/{engagement_id}/scope",
        headers={"X-Actor": "tester"},
        json={"allowlist_json": {"urls": ["https://example.com"]}, "denylist_json": {}},
    )

    run_response = inline_client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "tester"},
        json={
            "profile_name": "active-web-safe",
            "configuration_json": {
                "assessment_type": "Website / Web App",
                "test_profile": "Deep",
                "targets": {"urls": ["https://example.com"]},
                "modules": {"web_crawling": True, "zap_active_checks": True},
                "safety": {"rate_limit_rps": 1, "concurrency": 1, "time_budget_minutes": 60},
                "eta": {"estimated_total_minutes": 60, "estimated_impact": "medium", "confidence": "medium"},
            },
        },
    )
    run_id = run_response.json()["id"]

    inline_client.post(
        f"/api/v1/runs/{run_id}/approvals",
        headers={"X-Actor": "approver-1"},
        json={"decision": "approved"},
    )
    inline_client.post(
        f"/api/v1/runs/{run_id}/dispatch",
        headers={"X-Actor": "dispatcher"},
    )

    markdown_response = inline_client.get(f"/api/v1/runs/{run_id}/report?format=markdown")
    html_response = inline_client.get(f"/api/v1/runs/{run_id}/report?format=html")
    pdf_response = inline_client.get(f"/api/v1/runs/{run_id}/report?format=pdf")

    assert fake_zap_server.startswith("http://127.0.0.1:")
    assert markdown_response.status_code == 200
    assert markdown_response.headers["content-type"].startswith("text/markdown")
    assert "# AegisPT Run Report:" in markdown_response.text
    assert "## Methodology" in markdown_response.text
    assert "## Scope" in markdown_response.text
    assert "## Run Configuration" in markdown_response.text
    assert "## Confirmed Findings" in markdown_response.text
    assert "WSTG-CLNT-09" in markdown_response.text
    assert "PTES Phase: Exploitation" in markdown_response.text
    assert "Missing X-Frame-Options Header" in markdown_response.text
    assert "/api/v1/artifacts/" in markdown_response.text

    assert html_response.status_code == 200
    assert html_response.headers["content-type"].startswith("text/html")
    assert "<h1>AegisPT Run Report</h1>" in html_response.text
    assert "report-cover" in html_response.text
    assert "context-chip" in html_response.text
    assert "Methodology Summary" in html_response.text
    assert "Coverage Summary" in html_response.text
    assert "Run Configuration" in html_response.text
    assert "Confirmed Findings" in html_response.text
    assert "WSTG-CLNT-09" in html_response.text
    assert "Missing X-Frame-Options Header" in html_response.text
    assert "/api/v1/artifacts/" in html_response.text

    assert pdf_response.status_code == 200
    assert pdf_response.headers["content-type"].startswith("application/pdf")
    assert pdf_response.content.startswith(b"%PDF")
    pdf_reader = PdfReader(BytesIO(pdf_response.content))
    extracted_text = "\n".join(page.extract_text() or "" for page in pdf_reader.pages)
    assert "AegisPT Run Report" in extracted_text
    assert "Missing X-Frame-Options Header" in extracted_text

    reports_response = inline_client.get(f"/api/v1/runs/{run_id}/reports")
    executive_response = inline_client.get(f"/api/v1/runs/{run_id}/report?format=markdown&variant=executive")
    evidence_response = inline_client.get(f"/api/v1/runs/{run_id}/report?format=html&variant=evidence")

    assert reports_response.status_code == 200
    catalog = reports_response.json()
    assert {item["variant"] for item in catalog} == {"executive", "technical", "evidence", "retest"}
    assert all("pdf" in item["available_formats"] for item in catalog)
    assert all("pdf" in item["export_paths"] for item in catalog)
    assert executive_response.status_code == 200
    assert "# AegisPT Executive Report:" in executive_response.text
    assert "## Risk Highlights" in executive_response.text
    assert evidence_response.status_code == 200
    assert "<h1>AegisPT Evidence Appendix</h1>" in evidence_response.text
    assert "Task Evidence" in evidence_response.text

    findings_payload = inline_client.get(f"/api/v1/runs/{run_id}/findings").json()
    finding_id = findings_payload[0]["id"]
    theater_response = inline_client.get(f"/api/v1/findings/{finding_id}/theater")
    replay_response = inline_client.get(f"/api/v1/findings/{finding_id}/evidence")

    assert theater_response.status_code == 200
    assert theater_response.json()["finding"]["id"] == finding_id
    assert "remediation" in theater_response.json()
    assert replay_response.status_code == 200
    assert replay_response.json()["finding"]["id"] == finding_id
    assert replay_response.json()["related_executions"]


def test_discovery_reports_include_inventory_without_findings(
    inline_client,
    monkeypatch: pytest.MonkeyPatch,
    fake_nmap_report_binary: str,
) -> None:
    monkeypatch.setenv("NMAP_BINARY", fake_nmap_report_binary)

    engagement_response = inline_client.post(
        "/api/v1/engagements",
        headers={"X-Actor": "tester"},
        json={
            "name": "Discovery Report Validation",
            "client": "Acme Corp",
            "roe_ref": "ROE-2026-021",
        },
    )
    engagement_id = engagement_response.json()["id"]

    inline_client.post(
        f"/api/v1/engagements/{engagement_id}/scope",
        headers={"X-Actor": "tester"},
        json={"allowlist_json": {"cidr_ranges": ["10.0.20.0/24"]}, "denylist_json": {}},
    )

    run_response = inline_client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "tester"},
        json={
            "profile_name": "passive-network-discovery",
            "configuration_json": {
                "assessment_type": "Internal Range / LAN",
                "test_profile": "Inventory First",
                "targets": {"cidr_ranges": ["10.0.20.0/24"]},
                "modules": {"discovery": True},
                "safety": {"rate_limit_rps": 1, "concurrency": 1, "time_budget_minutes": 30},
                "eta": {"estimated_total_minutes": 30, "estimated_impact": "low", "confidence": "medium"},
            },
        },
    )
    run_id = run_response.json()["id"]

    dispatch_response = inline_client.post(
        f"/api/v1/runs/{run_id}/dispatch",
        headers={"X-Actor": "dispatcher"},
    )
    assert dispatch_response.status_code == 200

    catalog_response = inline_client.get(f"/api/v1/runs/{run_id}/reports")
    markdown_response = inline_client.get(f"/api/v1/runs/{run_id}/report?format=markdown&variant=technical")
    html_response = inline_client.get(f"/api/v1/runs/{run_id}/report?format=html&variant=technical")

    assert catalog_response.status_code == 200
    catalog = catalog_response.json()
    technical = next(item for item in catalog if item["variant"] == "technical")
    assert technical["included_findings"]["count"] == 0
    assert technical["included_inventory"]["host_count"] == 3
    assert technical["included_inventory"]["service_count"] == 0

    assert markdown_response.status_code == 200
    assert "## Discovery Summary" in markdown_response.text
    assert "Hosts Observed: 3" in markdown_response.text
    assert "No confirmed findings recorded." in markdown_response.text

    assert html_response.status_code == 200
    assert "Discovery Results" in html_response.text
    assert "Hosts Observed:" in html_response.text


def test_follow_up_reports_include_service_inventory_without_findings(
    inline_client,
    monkeypatch: pytest.MonkeyPatch,
    fake_nmap_report_binary: str,
) -> None:
    monkeypatch.setenv("NMAP_BINARY", fake_nmap_report_binary)

    engagement_response = inline_client.post(
        "/api/v1/engagements",
        headers={"X-Actor": "tester"},
        json={
            "name": "Follow-Up Report Validation",
            "client": "Acme Corp",
            "roe_ref": "ROE-2026-022",
        },
    )
    engagement_id = engagement_response.json()["id"]

    inline_client.post(
        f"/api/v1/engagements/{engagement_id}/scope",
        headers={"X-Actor": "tester"},
        json={"allowlist_json": {"cidr_ranges": ["10.0.20.0/24"]}, "denylist_json": {}},
    )

    discovery_run = inline_client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "tester"},
        json={
            "profile_name": "passive-network-discovery",
            "configuration_json": {
                "assessment_type": "Internal Range / LAN",
                "test_profile": "Inventory First",
                "execution_profile": "passive-network-discovery",
                "targets": {"cidr_ranges": ["10.0.20.0/24"]},
                "modules": {"discovery": True},
                "safety": {"rate_limit_rps": 1, "concurrency": 1, "time_budget_minutes": 30},
                "eta": {
                    "estimated_total_minutes": 30,
                    "estimated_impact": "low",
                    "confidence": "medium",
                },
            },
        },
    ).json()

    dispatch_response = inline_client.post(
        f"/api/v1/runs/{discovery_run['id']}/dispatch",
        headers={"X-Actor": "dispatcher"},
    )
    assert dispatch_response.status_code == 200

    inventory_response = inline_client.get(f"/api/v1/engagements/{engagement_id}/inventory")
    assert inventory_response.status_code == 200
    inventory_snapshot = inventory_response.json()[0]
    discovered_hosts = [
        item["host"]
        for item in inventory_snapshot["normalized_inventory_json"]["hosts"]
        if item.get("host")
    ]
    assert discovered_hosts

    follow_up_run = inline_client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "tester"},
        json={
            "profile_name": "passive-network-service-enumeration",
            "source_inventory_snapshot_id": inventory_snapshot["id"],
            "configuration_json": {
                "assessment_type": "Internal Range / LAN",
                "test_profile": "Inventory Follow-Up: Service Identification",
                "execution_profile": "passive-network-service-enumeration",
                "targets": {"ip_addresses": discovered_hosts},
                "modules": {"discovery": True, "inventory_follow_up": True},
                "safety": {
                    "rate_limit_rps": 1,
                    "concurrency": 1,
                    "time_budget_minutes": 20,
                    "active_checks": "passive",
                },
                "eta": {
                    "estimated_total_minutes": 20,
                    "estimated_impact": "low",
                    "confidence": "medium",
                },
                "follow_up": {
                    "strategy": "service-enumeration",
                    "source_run_id": discovery_run["id"],
                    "source_inventory_snapshot_id": inventory_snapshot["id"],
                    "rationale": "Discovery confirmed live hosts and service identification is the next passive step.",
                },
            },
        },
    ).json()

    follow_up_dispatch = inline_client.post(
        f"/api/v1/runs/{follow_up_run['id']}/dispatch",
        headers={"X-Actor": "dispatcher"},
    )
    assert follow_up_dispatch.status_code == 200

    catalog_response = inline_client.get(f"/api/v1/runs/{follow_up_run['id']}/reports")
    markdown_response = inline_client.get(
        f"/api/v1/runs/{follow_up_run['id']}/report?format=markdown&variant=technical"
    )
    evidence_response = inline_client.get(
        f"/api/v1/runs/{follow_up_run['id']}/report?format=html&variant=evidence"
    )

    assert catalog_response.status_code == 200
    catalog = catalog_response.json()
    technical = next(item for item in catalog if item["variant"] == "technical")
    evidence = next(item for item in catalog if item["variant"] == "evidence")
    assert technical["included_findings"]["count"] == 0
    assert technical["included_inventory"]["host_count"] >= 3
    assert technical["included_inventory"]["service_count"] >= 3
    assert evidence["included_inventory"]["service_count"] >= 3

    assert markdown_response.status_code == 200
    assert "## Discovery Summary" in markdown_response.text
    assert "Hosts Observed:" in markdown_response.text
    assert "Services Observed:" in markdown_response.text
    assert "No confirmed findings recorded." in markdown_response.text

    assert evidence_response.status_code == 200
    assert "<h1>AegisPT Evidence Appendix</h1>" in evidence_response.text
    assert "Task Evidence" in evidence_response.text
    assert "Hosts Observed:" in evidence_response.text
    assert "Services Observed:" in evidence_response.text


def test_reports_include_codex_reviewed_adaptive_change_summary(
    inline_client,
    probe_server: str,
) -> None:
    run_id, task_id, pack_version = _create_codex_reviewed_adaptive_run(inline_client, probe_server)

    catalog_response = inline_client.get(f"/api/v1/runs/{run_id}/reports")
    technical_markdown = inline_client.get(f"/api/v1/runs/{run_id}/report?format=markdown&variant=technical")
    executive_markdown = inline_client.get(f"/api/v1/runs/{run_id}/report?format=markdown&variant=executive")
    technical_html = inline_client.get(f"/api/v1/runs/{run_id}/report?format=html&variant=technical")
    technical_pdf = inline_client.get(f"/api/v1/runs/{run_id}/report?format=pdf&variant=technical")

    assert catalog_response.status_code == 200
    technical_catalog = next(item for item in catalog_response.json() if item["variant"] == "technical")
    assert technical_catalog["adaptive_change_summary"]["active"] is True
    assert technical_catalog["adaptive_change_summary"]["pack_label"].endswith(pack_version)
    assert technical_catalog["adaptive_change_summary"]["latest_task"]["id"] == task_id
    assert technical_catalog["adaptive_change_summary"]["latest_task"]["prepared_result_status"] == "prepared"
    assert "Codex-reviewed adaptive coverage" in technical_catalog["adaptive_change_summary"]["summary_line"]

    assert technical_markdown.status_code == 200
    assert "## Adaptive Change Summary" in technical_markdown.text
    assert f"Latest Codex Task: {task_id}" in technical_markdown.text
    assert "Prepared Review Bundle: prepared" in technical_markdown.text

    assert executive_markdown.status_code == 200
    assert "## Adaptive Change Summary" in executive_markdown.text
    assert "Adaptive Change Review:" in executive_markdown.text
    assert task_id in executive_markdown.text

    assert technical_html.status_code == 200
    assert "Adaptive Change Summary" in technical_html.text
    assert task_id in technical_html.text
    assert "Prepared Review Bundle" in technical_html.text

    assert technical_pdf.status_code == 200
    assert technical_pdf.content.startswith(b"%PDF")
    pdf_reader = PdfReader(BytesIO(technical_pdf.content))
    extracted_text = "\n".join(page.extract_text() or "" for page in pdf_reader.pages)
    assert "Adaptive Change Summary" in extracted_text
    assert pack_version in extracted_text
