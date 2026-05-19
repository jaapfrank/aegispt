from __future__ import annotations

import json
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import BytesIO
from pathlib import Path
from threading import Thread
from types import SimpleNamespace
from urllib.parse import parse_qs, urlparse
from uuid import UUID

import pytest
from pypdf import PdfReader
from sqlalchemy import select

from api.app.models import (
    Approval,
    EvidenceArtifact,
    Finding,
    FindingRemediation,
    InventorySnapshot,
    Run,
    RunProfile,
    Task,
    ToolExecution,
)
from api.app.services import reports as report_service
from api.app.services.finding_chains import refresh_finding_chains_for_run


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


def _create_soc2_report_run(inline_client) -> str:
    engagement_response = inline_client.post(
        "/api/v1/engagements",
        headers={"X-Actor": "soc2-operator"},
        json={
            "name": "SOC 2 Report Validation",
            "client": "Acme Corp",
            "roe_ref": "ROE-2026-SOC2",
        },
    )
    engagement_id = engagement_response.json()["id"]

    inline_client.post(
        f"/api/v1/engagements/{engagement_id}/scope",
        headers={"X-Actor": "soc2-operator"},
        json={"allowlist_json": {"urls": ["https://app.example.test"]}, "denylist_json": {}},
    )

    run_response = inline_client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "soc2-operator"},
        json={
            "profile_name": "passive-web-baseline",
            "configuration_json": {
                "assessment_type": "Website / Web App",
                "test_profile": "Standard",
                "targets": {"urls": ["https://app.example.test"]},
                "modules": {"web_crawling": True, "nuclei_checks": True},
                "safety": {"rate_limit_rps": 1, "concurrency": 1, "time_budget_minutes": 30},
                "eta": {"estimated_total_minutes": 30, "estimated_impact": "low", "confidence": "medium"},
            },
        },
    )
    return run_response.json()["id"]


def _assert_no_python_repr(text: str) -> None:
    assert "{'" not in text
    assert "'}" not in text
    assert "{&#x27;" not in text
    assert "&#x27;}" not in text


def _add_report_draft_finding(inline_client, run_id: str) -> str:
    with inline_client.app.state.session_factory() as session:
        finding = Finding(
            run_id=UUID(run_id),
            title="Admin panel exposed",
            severity="high",
            target_id="https://app.example.test/admin",
            evidence_ref="artifact://zap/admin-panel",
            status="open",
            summary="The administrative panel was reachable from the assessed web surface.",
            methodology_tags=["owasp-wstg", "access_control"],
            ptes_phase="exploitation",
            nist_phase="attack",
            wstg_id="WSTG-ATHZ-01",
            wstg_version="v4.2",
            control_family="access_control",
        )
        session.add(finding)
        session.commit()
        return str(finding.id)


def _seed_run_attack_narrative_context(inline_client) -> tuple[str, list[str]]:
    run_id = _create_soc2_report_run(inline_client)
    with inline_client.app.state.session_factory() as session:
        run = session.scalar(select(Run).where(Run.id == UUID(run_id)))
        assert run is not None
        run.status = "completed"
        inventory = InventorySnapshot(
            engagement_id=run.engagement_id,
            requested_by="narrative-operator",
            status="completed",
            source_tools_json=["httpx", "nmap"],
            raw_inputs_json={"run_id": run_id},
            normalized_inventory_json={
                "hosts": [{"host": "app.example.test", "confidence": 0.94}],
                "services": [
                    {
                        "host": "app.example.test",
                        "port": 443,
                        "protocol": "tcp",
                        "service": "https",
                        "confidence": 0.91,
                    }
                ],
                "http_endpoints": [
                    {
                        "url": "https://app.example.test/admin",
                        "status_code": 200,
                        "title": "Admin Console",
                        "confidence": 0.9,
                    }
                ],
            },
            summary_json={
                "host_count": 1,
                "service_count": 1,
                "endpoint_count": 1,
                "technology_count": 1,
                "confidence_score": 0.92,
            },
            confidence_score=0.92,
        )
        task = Task(
            run_id=UUID(run_id),
            tool="httpx",
            target_id="https://app.example.test",
            params_json={"targets": ["https://app.example.test/admin"]},
            status="completed",
        )
        session.add_all([inventory, task])
        session.flush()
        execution = ToolExecution(
            task_id=task.id,
            runner_digest="sha256:narrative-httpx",
            tool_version="httpx-test",
            exit_code=0,
            stdout_text="admin console observed",
        )
        session.add(execution)
        session.flush()
        session.add(
            EvidenceArtifact(
                tool_execution_id=execution.id,
                kind="httpx-json",
                uri="artifact://http/admin-console",
                sha256="a" * 64,
                redaction_state="clean",
                metadata_json={"name": "admin-console-observation"},
            )
        )
        findings = [
            Finding(
                run_id=UUID(run_id),
                source_inventory_snapshot_id=inventory.id,
                title="Admin panel exposed",
                severity="high",
                target_id="https://app.example.test/admin",
                evidence_ref="artifact://http/admin-console",
                status="open",
                summary="The administrative console was reachable from the assessed web surface.",
                methodology_tags=["owasp-wstg", "access_control"],
                ptes_phase="exploitation",
                nist_phase="attack",
                wstg_id="WSTG-ATHZ-01",
                wstg_version="v4.2",
                control_family="access_control",
            ),
            Finding(
                run_id=UUID(run_id),
                source_inventory_snapshot_id=inventory.id,
                title="Default password accepted",
                severity="critical",
                target_id="https://app.example.test/admin",
                evidence_ref="artifact://auth/default-password",
                status="open",
                summary="Operator-provided validation notes indicate default credential exposure for the same management surface.",
                methodology_tags=["owasp-wstg", "authentication"],
                ptes_phase="exploitation",
                nist_phase="attack",
                wstg_id="WSTG-ATHN-02",
                wstg_version="v4.2",
                control_family="authentication",
            ),
        ]
        session.add_all(findings)
        session.flush()
        finding_ids = [str(finding.id) for finding in findings]
        refresh_finding_chains_for_run(session=session, run_id=UUID(run_id))
        session.commit()
    return run_id, finding_ids


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

    with inline_client.app.state.session_factory() as session:
        session.add(
            Finding(
                run_id=UUID(run_id),
                title="Missing X-Frame-Options Header",
                severity="low",
                target_id="https://example.com/login",
                evidence_ref="artifact://zap/x-frame-options-login",
                status="open",
                summary="The login page repeats the same missing clickjacking protection header.",
                methodology_tags=["owasp-wstg"],
                ptes_phase="exploitation",
                nist_phase="attack",
                wstg_id="WSTG-CLNT-09",
                wstg_version="v4.2",
                control_family="client_security",
            )
        )
        session.commit()

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
    assert "Missing X-Frame-Options Header (2 instances)" in markdown_response.text
    assert "## Executive Narrative" in markdown_response.text
    assert "Risk Level:" in markdown_response.text
    assert "| Priority | Finding | Severity | Effort | Impact |" in markdown_response.text
    assert "AegisPT Version: 0.1.0" in markdown_response.text
    assert "This report was generated by AegisPT. It is not a certification or attestation." in markdown_response.text
    assert "/api/v1/artifacts/" in markdown_response.text
    _assert_no_python_repr(markdown_response.text)

    assert html_response.status_code == 200
    assert html_response.headers["content-type"].startswith("text/html")
    assert "<h1>AegisPT Run Report</h1>" in html_response.text
    assert "report-cover" in html_response.text
    assert "context-chip" in html_response.text
    assert "Report Header" in html_response.text
    assert "Remediation Priority Table" in html_response.text
    assert "Methodology Summary" in html_response.text
    assert "Coverage Summary" in html_response.text
    assert "Run Configuration" in html_response.text
    assert "Confirmed Findings" in html_response.text
    assert "WSTG-CLNT-09" in html_response.text
    assert "Missing X-Frame-Options Header" in html_response.text
    assert "Missing X-Frame-Options Header (2 instances)" in html_response.text
    assert "/api/v1/artifacts/" in html_response.text
    _assert_no_python_repr(html_response.text)

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
    assert {item["variant"] for item in catalog} == {"summary", "technical", "compliance", "retest"}
    compliance_catalog = next(item for item in catalog if item["variant"] == "compliance")
    assert compliance_catalog["compliance_summary"]["available_frameworks"] == [
        "nis2",
        "dora",
        "soc2",
        "iso27001",
        "pci_dss",
        "nfir",
    ]
    assert all("pdf" in item["available_formats"] for item in catalog)
    assert all("pdf" in item["export_paths"] for item in catalog)
    assert executive_response.status_code == 200
    assert "# AegisPT Management Summary:" in executive_response.text
    assert "## Executive Narrative" in executive_response.text
    assert "## Exposure Score" in executive_response.text
    assert "## Remediation Priority Table" in executive_response.text
    assert "## Tested / Not Tested" in executive_response.text
    assert "## Risk Highlights" in executive_response.text
    assert "Missing X-Frame-Options Header" in executive_response.text
    _assert_no_python_repr(executive_response.text)
    assert evidence_response.status_code == 200
    assert "<h1>AegisPT Evidence Appendix</h1>" in evidence_response.text
    assert "Task Evidence" in evidence_response.text
    _assert_no_python_repr(evidence_response.text)

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


def test_soc2_report_package_maps_and_retains_unmapped_findings(
    inline_client,
) -> None:
    run_id = _create_soc2_report_run(inline_client)

    with inline_client.app.state.session_factory() as session:
        session.add_all(
            [
                Finding(
                    run_id=UUID(run_id),
                    title="Missing X-Frame-Options Header",
                    severity="low",
                    target_id="https://app.example.test",
                    evidence_ref="artifact://zap/x-frame-options",
                    status="open",
                    summary="The web application did not return the expected clickjacking protection header.",
                    methodology_tags=["owasp-wstg"],
                    ptes_phase="exploitation",
                    nist_phase="attack",
                    wstg_id="WSTG-CLNT-09",
                    wstg_version="v4.2",
                    control_family="client_security",
                ),
                Finding(
                    run_id=UUID(run_id),
                    title="Uncategorized Business Process Risk",
                    severity="medium",
                    target_id="https://app.example.test/workflow",
                    evidence_ref="artifact://manual/business-process",
                    status="triaged",
                    summary="The finding needs human compliance review before a SOC 2 control is assigned.",
                    methodology_tags=["manual-review"],
                    ptes_phase="analysis",
                    nist_phase="analysis",
                    control_family="business_logic",
                ),
            ]
        )
        session.commit()

    catalog_response = inline_client.get(f"/api/v1/runs/{run_id}/reports")
    markdown_response = inline_client.get(f"/api/v1/runs/{run_id}/report?format=markdown&variant=soc2")
    html_response = inline_client.get(f"/api/v1/runs/{run_id}/report?format=html&variant=soc2")
    pdf_response = inline_client.get(f"/api/v1/runs/{run_id}/report?format=pdf&variant=soc2")

    assert catalog_response.status_code == 200
    catalog_by_variant = {item["variant"]: item for item in catalog_response.json()}
    assert set(catalog_by_variant) == {"summary", "technical", "compliance", "retest"}
    compliance_catalog = catalog_by_variant["compliance"]
    assert compliance_catalog["title"] == "Compliance Annex"
    assert "soc2" in compliance_catalog["compliance_summary"]["available_frameworks"]
    assert compliance_catalog["export_paths"]["pdf"].endswith("format=pdf&variant=compliance&framework=nis2")

    assert markdown_response.status_code == 200
    assert markdown_response.headers["content-type"].startswith("text/markdown")
    assert "# AegisPT SOC 2 Report Package:" in markdown_response.text
    assert "## SOC 2 Coverage Summary" in markdown_response.text
    assert "Mapped Findings: 1" in markdown_response.text
    assert "Unmapped Findings: 1" in markdown_response.text
    assert "CC6.6 - Logical Access Security Measures" in markdown_response.text
    assert "Missing X-Frame-Options Header" in markdown_response.text
    assert "Manual SOC 2 Review Queue" in markdown_response.text
    assert "Uncategorized Business Process Risk" in markdown_response.text
    assert "## Compliance Gap Advisor" in markdown_response.text
    assert "### Covered by This Assessment" in markdown_response.text
    assert "### Not Tested in This Run" in markdown_response.text
    assert "### Requires Human Auditor" in markdown_response.text
    assert "### Coverage Percentage" in markdown_response.text
    assert "SOC2 Type II opinion requires a CPA." in markdown_response.text
    assert "This control requires organisational process review, not a technical scan." in markdown_response.text
    assert "Engage a licensed CPA firm for SOC2 Type II attestation" in markdown_response.text

    assert html_response.status_code == 200
    assert html_response.headers["content-type"].startswith("text/html")
    assert "<h1>AegisPT SOC 2 Report Package</h1>" in html_response.text
    assert "SOC 2 Coverage Summary" in html_response.text
    assert "CC6.6 - Logical Access Security Measures" in html_response.text
    assert "Manual SOC 2 Review Queue" in html_response.text
    assert "Compliance Gap Advisor" in html_response.text
    assert "Requires Human Auditor" in html_response.text

    assert pdf_response.status_code == 200
    assert pdf_response.headers["content-type"].startswith("application/pdf")
    assert pdf_response.content.startswith(b"%PDF")
    pdf_reader = PdfReader(BytesIO(pdf_response.content))
    extracted_text = "\n".join(page.extract_text() or "" for page in pdf_reader.pages)
    assert "AegisPT SOC 2 Report Package" in extracted_text
    assert "CC6.6" in extracted_text


def test_soc2_report_package_zero_finding_path(
    inline_client,
) -> None:
    run_id = _create_soc2_report_run(inline_client)

    catalog_response = inline_client.get(f"/api/v1/runs/{run_id}/reports")
    markdown_response = inline_client.get(f"/api/v1/runs/{run_id}/report?format=markdown&variant=soc2")
    html_response = inline_client.get(f"/api/v1/runs/{run_id}/report?format=html&variant=soc2")

    assert catalog_response.status_code == 200
    compliance_catalog = next(item for item in catalog_response.json() if item["variant"] == "compliance")
    assert compliance_catalog["included_findings"]["count"] == 0
    assert compliance_catalog["compliance_summary"]["selected_framework"] == "nis2"
    assert "soc2" in compliance_catalog["compliance_summary"]["available_frameworks"]

    assert markdown_response.status_code == 200
    assert "Total Findings Reviewed: 0" in markdown_response.text
    assert "No confirmed findings were recorded for this run." in markdown_response.text
    assert "does not assert that SOC 2 controls are effective" in markdown_response.text

    assert html_response.status_code == 200
    assert "No confirmed findings were recorded for this run." in html_response.text
    assert "does not assert that SOC 2 controls are effective" in html_response.text


def test_nfir_compliance_annex_maps_seven_phases_authorization_cvss_and_reaudit(
    inline_client,
) -> None:
    run_id = _create_soc2_report_run(inline_client)

    with inline_client.app.state.session_factory() as session:
        run = session.scalar(select(Run).where(Run.id == UUID(run_id)))
        assert run is not None
        assert run.engagement is not None
        run.status = "completed"
        run.engagement.authorization_confirmed_at = datetime(2026, 4, 29, 9, 15, tzinfo=UTC)
        run.engagement.authorization_confirmed_by = "nfir-operator"
        tasks = [
            Task(run_id=UUID(run_id), tool="nmap", target_id="10.0.20.0/24", status="completed"),
            Task(run_id=UUID(run_id), tool="nuclei", target_id="https://app.example.test", status="completed"),
            Task(run_id=UUID(run_id), tool="bloodhound", target_id="corp.example.test", status="completed"),
            Task(run_id=UUID(run_id), tool="metasploit", target_id="10.0.20.10", status="completed"),
        ]
        open_finding = Finding(
            run_id=UUID(run_id),
            title="Critical SQL Injection",
            severity="critical",
            target_id="https://app.example.test/graphql",
            evidence_ref="artifact://nfir/sql-injection",
            status="open",
            summary="Validated SQL injection requires remediation and re-audit tracking.",
            cvss_score=9.8,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            methodology_tags=["owasp-wstg", "nuclei"],
            ptes_phase="vulnerability-analysis",
            nist_phase="analysis",
            wstg_id="WSTG-INPV-05",
            wstg_version="v4.2",
            control_family="input_validation",
        )
        resolved_finding = Finding(
            run_id=UUID(run_id),
            title="Resolved SMB Signing Gap",
            severity="medium",
            target_id="10.0.20.25",
            evidence_ref="artifact://nfir/smb-signing",
            status="resolved",
            summary="The customer supplied re-audit evidence that this issue is resolved.",
            cvss_score=None,
            methodology_tags=["smb", "post-exploitation"],
            ptes_phase="post-exploitation",
            nist_phase="reporting",
            control_family="identity_management",
        )
        session.add_all([*tasks, open_finding, resolved_finding])
        session.flush()
        session.add(
            FindingRemediation(
                finding_id=open_finding.id,
                state="in_progress",
                notes="Fix scheduled before the re-audit window.",
                owner="app-team",
                created_by="nfir-operator",
                updated_by="nfir-operator",
            )
        )
        session.commit()

    catalog_response = inline_client.get(f"/api/v1/runs/{run_id}/reports")
    markdown_response = inline_client.get(
        f"/api/v1/runs/{run_id}/report?format=markdown&variant=compliance&framework=nfir"
    )
    alias_response = inline_client.get(f"/api/v1/runs/{run_id}/report?format=markdown&variant=nfir")
    html_response = inline_client.get(
        f"/api/v1/runs/{run_id}/report?format=html&variant=compliance&framework=nfir"
    )

    assert catalog_response.status_code == 200
    compliance_catalog = next(item for item in catalog_response.json() if item["variant"] == "compliance")
    assert "nfir" in compliance_catalog["compliance_summary"]["available_frameworks"]

    assert markdown_response.status_code == 200
    assert alias_response.status_code == 200
    assert alias_response.text == markdown_response.text
    assert "# AegisPT NFIR Evidence Mapping:" in markdown_response.text
    assert "## NFIR 7-Phase Visibility" in markdown_response.text
    for heading in [
        "Phase 1 - Preparation and Authorization",
        "Phase 2 - Intelligence Gathering",
        "Phase 3 - Vulnerability Analysis",
        "Phase 4 - Exploitation",
        "Phase 5 - Post-Exploitation",
        "Phase 6 - Risk Analysis and Remediation Planning",
        "Phase 7 - Reporting and Re-Audit Tracking",
    ]:
        assert heading in markdown_response.text
    assert "ROE Reference: ROE-2026-SOC2" in markdown_response.text
    assert "Authorization Confirmed At: 2026-04-29T09:15:00" in markdown_response.text
    assert "Authorization Confirmed By: nfir-operator" in markdown_response.text
    assert "CVSS: 9.8" in markdown_response.text
    assert "CVSS: N/A" in markdown_response.text
    assert "## Re-Audit Tracking" in markdown_response.text
    assert "### Open Findings" in markdown_response.text
    assert "Critical SQL Injection" in markdown_response.text
    assert "### Verified / Resolved Findings" in markdown_response.text
    assert "Resolved SMB Signing Gap" in markdown_response.text
    assert "not NFIR certification" in markdown_response.text
    assert "PTES" in markdown_response.text
    assert "OWASP WSTG" in markdown_response.text
    assert "NIST SP 800-115" in markdown_response.text

    assert html_response.status_code == 200
    assert "<h1>AegisPT NFIR Evidence Mapping</h1>" in html_response.text
    assert "NFIR 7-Phase Visibility" in html_response.text
    assert "Critical SQL Injection" in html_response.text
    assert "Resolved SMB Signing Gap" in html_response.text


def test_nfir_compliance_annex_warns_when_authorization_evidence_is_missing(
    inline_client,
) -> None:
    run_id = _create_soc2_report_run(inline_client)

    with inline_client.app.state.session_factory() as session:
        run = session.scalar(select(Run).where(Run.id == UUID(run_id)))
        assert run is not None
        assert run.engagement is not None
        run.engagement.roe_ref = None
        run.engagement.authorization_confirmed_at = None
        run.engagement.authorization_confirmed_by = None
        session.commit()

    markdown_response = inline_client.get(
        f"/api/v1/runs/{run_id}/report?format=markdown&variant=compliance&framework=nfir"
    )

    assert markdown_response.status_code == 200
    assert "Authorization reference not recorded. NFIR requires written authorization before testing begins." in markdown_response.text
    assert "ROE Reference: Not recorded" in markdown_response.text


def test_iso27001_and_pci_dss_packages_are_evidence_backed_without_overclaims(
    inline_client,
) -> None:
    run_id = _create_soc2_report_run(inline_client)

    with inline_client.app.state.session_factory() as session:
        session.add_all(
            [
                Finding(
                    run_id=UUID(run_id),
                    title="Session Cookie Missing HttpOnly",
                    severity="medium",
                    target_id="https://app.example.test/login",
                    evidence_ref="artifact://compliance/session-cookie",
                    status="open",
                    summary="The authenticated application session cookie was missing a defensive flag.",
                    methodology_tags=["session_management"],
                    ptes_phase="exploitation",
                    nist_phase="attack",
                    wstg_id="WSTG-SESS-02",
                    wstg_version="v4.2",
                    control_family="session_management",
                ),
                Finding(
                    run_id=UUID(run_id),
                    title="Missing X-Frame-Options Header",
                    severity="low",
                    target_id="https://app.example.test",
                    evidence_ref="artifact://compliance/x-frame-options",
                    status="triaged",
                    summary="The web application did not return the expected clickjacking protection header.",
                    methodology_tags=["configuration"],
                    ptes_phase="vulnerability-analysis",
                    nist_phase="analysis",
                    wstg_id="WSTG-CLNT-09",
                    wstg_version="v4.2",
                    control_family="client_security",
                ),
                Finding(
                    run_id=UUID(run_id),
                    title="Contractual Review Observation",
                    severity="info",
                    target_id="https://app.example.test/process",
                    evidence_ref="artifact://compliance/manual-review",
                    status="triaged",
                    summary="The observation needs manual compliance interpretation before a framework mapping is assigned.",
                    methodology_tags=["manual-review"],
                    ptes_phase="analysis",
                    nist_phase="analysis",
                    control_family="business_logic",
                ),
            ]
        )
        session.commit()

    catalog_response = inline_client.get(f"/api/v1/runs/{run_id}/reports")

    assert catalog_response.status_code == 200
    catalog_by_variant = {item["variant"]: item for item in catalog_response.json()}
    assert set(catalog_by_variant) == {"summary", "technical", "compliance", "retest"}
    assert catalog_by_variant["compliance"]["title"] == "Compliance Annex"
    assert set(catalog_by_variant["compliance"]["compliance_summary"]["available_frameworks"]) == {
        "nis2",
        "dora",
        "soc2",
        "iso27001",
        "pci_dss",
        "nfir",
    }

    expected = {
        "iso27001": {
            "package": "ISO 27001",
            "heading": "AegisPT ISO 27001 Evidence Package",
            "coverage": "ISO 27001 Coverage Summary",
            "mapped_control": "A.5.15 - Access control",
            "mapped_hardening": "A.8.8 - Management of technical vulnerabilities",
            "manual_queue": "Manual ISO 27001 Review Queue",
            "untested": "ISO 27001 Controls Without Run Findings",
            "zero_or_boundary": "it is not an ISO certification",
        },
        "pci_dss": {
            "package": "PCI DSS",
            "heading": "AegisPT PCI DSS Evidence Package",
            "coverage": "PCI DSS Coverage Summary",
            "mapped_control": "Req. 8.2/8.3 - User identification and authentication",
            "mapped_hardening": "Req. 6.2/6.3 - Vulnerability and secure software management",
            "manual_queue": "Manual PCI DSS Review Queue",
            "untested": "PCI DSS Requirements Without Run Findings",
            "zero_or_boundary": "it is not a QSA assessment",
        },
    }
    forbidden_phrases = (
        "certified compliant",
        "iso 27001 certified",
        "pci certified",
        "soc 2 attested",
        "guaranteed secure",
        "all risk removed",
    )

    for variant, assertions in expected.items():
        markdown_response = inline_client.get(f"/api/v1/runs/{run_id}/report?format=markdown&variant={variant}")
        html_response = inline_client.get(f"/api/v1/runs/{run_id}/report?format=html&variant={variant}")
        pdf_response = inline_client.get(f"/api/v1/runs/{run_id}/report?format=pdf&variant={variant}")

        assert markdown_response.status_code == 200
        assert markdown_response.headers["content-type"].startswith("text/markdown")
        assert assertions["heading"] in markdown_response.text
        assert assertions["coverage"] in markdown_response.text
        assert "Mapped Findings: 2" in markdown_response.text
        assert "Unmapped Findings: 1" in markdown_response.text
        assert assertions["mapped_control"] in markdown_response.text
        assert assertions["mapped_hardening"] in markdown_response.text
        assert assertions["manual_queue"] in markdown_response.text
        assert assertions["untested"] in markdown_response.text
        assert "## Compliance Gap Advisor" in markdown_response.text
        assert "### Covered by This Assessment" in markdown_response.text
        assert "### Not Tested in This Run" in markdown_response.text
        assert "### Requires Human Auditor" in markdown_response.text
        assert "### Coverage Percentage" in markdown_response.text
        assert "This control requires organisational process review, not a technical scan." in markdown_response.text
        assert "ISO27001 certification requires an accredited certification body." in markdown_response.text
        assert "PCI DSS Report on Compliance requires a QSA." in markdown_response.text
        assert "NIS2 compliance declaration requires a broader risk management programme." in markdown_response.text
        assert "Contractual Review Observation" in markdown_response.text
        assert "absence of mapped findings is not control effectiveness or compliance" in markdown_response.text
        assert assertions["zero_or_boundary"] in markdown_response.text

        normalized_markdown = markdown_response.text.lower()
        for phrase in forbidden_phrases:
            assert phrase not in normalized_markdown

        assert html_response.status_code == 200
        assert html_response.headers["content-type"].startswith("text/html")
        assert f"<h1>{assertions['heading']}</h1>" in html_response.text
        assert assertions["coverage"] in html_response.text
        assert assertions["manual_queue"] in html_response.text
        assert assertions["untested"] in html_response.text
        assert "Compliance Gap Advisor" in html_response.text
        assert "Requires Human Auditor" in html_response.text

        assert pdf_response.status_code == 200
        assert pdf_response.headers["content-type"].startswith("application/pdf")
        assert pdf_response.content.startswith(b"%PDF")
        pdf_reader = PdfReader(BytesIO(pdf_response.content))
        extracted_text = "\n".join(page.extract_text() or "" for page in pdf_reader.pages)
        assert assertions["heading"] in extracted_text
        assert "Session Cookie Missing HttpOnly" in extracted_text


def test_nis2_and_dora_packages_map_regulatory_evidence_without_certification_claims(
    inline_client,
) -> None:
    run_id = _create_soc2_report_run(inline_client)

    with inline_client.app.state.session_factory() as session:
        session.add_all(
            [
                Finding(
                    run_id=UUID(run_id),
                    title="Session Cookie Missing HttpOnly",
                    severity="medium",
                    target_id="https://app.example.test/login",
                    evidence_ref="artifact://nis2-dora/session-cookie",
                    status="open",
                    summary="The authenticated application session cookie was missing a defensive flag.",
                    methodology_tags=["session_management"],
                    ptes_phase="exploitation",
                    nist_phase="attack",
                    wstg_id="WSTG-SESS-02",
                    wstg_version="v4.2",
                    control_family="session_management",
                ),
                Finding(
                    run_id=UUID(run_id),
                    title="Missing X-Frame-Options Header",
                    severity="low",
                    target_id="https://app.example.test",
                    evidence_ref="artifact://nis2-dora/x-frame-options",
                    status="triaged",
                    summary="The web application did not return the expected clickjacking protection header.",
                    methodology_tags=["configuration"],
                    ptes_phase="vulnerability-analysis",
                    nist_phase="analysis",
                    wstg_id="WSTG-CLNT-09",
                    wstg_version="v4.2",
                    control_family="client_security",
                ),
                Finding(
                    run_id=UUID(run_id),
                    title="Controlled Exploitability Retest Required",
                    severity="high",
                    target_id="https://app.example.test/admin",
                    evidence_ref="artifact://nis2-dora/controlled-validation",
                    status="open",
                    summary="A high-impact issue requires controlled validation and retest evidence.",
                    methodology_tags=["controlled_validation", "security_testing", "tlpt"],
                    ptes_phase="exploitation",
                    nist_phase="attack",
                    control_family="penetration_testing",
                ),
                Finding(
                    run_id=UUID(run_id),
                    title="Board Reporting Observation",
                    severity="info",
                    target_id="governance-record",
                    evidence_ref="artifact://nis2-dora/manual",
                    status="triaged",
                    summary="This governance observation needs human compliance interpretation.",
                    methodology_tags=["manual-review"],
                    ptes_phase="reporting",
                    nist_phase="reporting",
                    control_family="business_logic",
                ),
            ]
        )
        session.commit()

    catalog_response = inline_client.get(f"/api/v1/runs/{run_id}/reports")

    assert catalog_response.status_code == 200
    catalog_by_variant = {item["variant"]: item for item in catalog_response.json()}
    assert set(catalog_by_variant) == {"summary", "technical", "compliance", "retest"}
    assert catalog_by_variant["compliance"]["title"] == "Compliance Annex"
    assert "Directive (EU) 2022/2555 Article 21" in catalog_by_variant["compliance"]["methodology_references"]
    assert "NCSC NL Cyberbeveiligingswet / NIS2 zorgplicht guidance" in catalog_by_variant["compliance"]["methodology_references"]
    assert "dora" in catalog_by_variant["compliance"]["compliance_summary"]["available_frameworks"]

    expectations = {
        "nis2": {
            "package": "NIS2",
            "heading": "AegisPT NIS2 Evidence Package",
            "coverage": "NIS2 Article 21 Coverage Summary",
            "mapped_primary": "Article 21.2.e - Vulnerability handling and secure systems lifecycle",
            "mapped_secondary": "Article 21.2.i - Access control, identity, and asset-management security",
            "mapped_testing": "Article 21.2.m - Security testing and effectiveness review evidence",
            "boundary": "NIS2 compliance requires a comprehensive risk management programme beyond technical testing",
            "human_requirement": "NIS2 compliance declaration requires a broader risk management programme.",
        },
        "dora": {
            "package": "DORA",
            "heading": "AegisPT DORA Evidence Package",
            "coverage": "DORA ICT Risk Coverage Summary",
            "mapped_primary": "DORA Art. 9 - Protection and prevention controls",
            "mapped_secondary": "DORA Art. 24-26 / TIBER-EU - Digital operational resilience testing and TLPT boundary",
            "mapped_testing": "Manual DORA Review Queue",
            "boundary": "not a complete DORA compliance assessment, supervisory submission, or full TLPT engagement",
            "human_requirement": "A full TIBER-EU test requires the appropriate governance",
        },
    }
    forbidden_phrases = (
        "nis2 certified",
        "dora compliant",
        "tiber certified",
        "tlpt complete",
        "supervisory approved",
        "guaranteed resilient",
    )

    for variant, expected in expectations.items():
        markdown_response = inline_client.get(f"/api/v1/runs/{run_id}/report?format=markdown&variant={variant}")
        html_response = inline_client.get(f"/api/v1/runs/{run_id}/report?format=html&variant={variant}")
        pdf_response = inline_client.get(f"/api/v1/runs/{run_id}/report?format=pdf&variant={variant}")

        assert markdown_response.status_code == 200
        assert markdown_response.headers["content-type"].startswith("text/markdown")
        assert expected["heading"] in markdown_response.text
        assert expected["coverage"] in markdown_response.text
        assert "Mapped Findings: 3" in markdown_response.text
        assert "Unmapped Findings: 1" in markdown_response.text
        assert expected["mapped_primary"] in markdown_response.text
        assert expected["mapped_secondary"] in markdown_response.text
        assert expected["mapped_testing"] in markdown_response.text
        assert expected["boundary"] in markdown_response.text
        assert expected["human_requirement"] in markdown_response.text
        assert "Requires Human Auditor" in markdown_response.text
        assert "This control requires organisational process review, not a technical scan." in markdown_response.text
        assert "Board Reporting Observation" in markdown_response.text

        normalized_markdown = markdown_response.text.lower()
        for phrase in forbidden_phrases:
            assert phrase not in normalized_markdown

        assert html_response.status_code == 200
        assert html_response.headers["content-type"].startswith("text/html")
        assert expected["heading"] in html_response.text
        assert "Compliance Gap Advisor" in html_response.text
        assert "Requires Human Auditor" in html_response.text

        assert pdf_response.status_code == 200
        assert pdf_response.headers["content-type"].startswith("application/pdf")
        assert pdf_response.content.startswith(b"%PDF")
        pdf_reader = PdfReader(BytesIO(pdf_response.content))
        extracted_text = "\n".join(page.extract_text() or "" for page in pdf_reader.pages)
        assert expected["heading"] in extracted_text
        assert "Controlled Exploitability Retest Required" in extracted_text


def test_assurance_package_is_scoped_evidence_backed_without_overclaims(
    inline_client,
) -> None:
    run_id = _create_soc2_report_run(inline_client)

    with inline_client.app.state.session_factory() as session:
        task = session.scalar(select(Task).where(Task.run_id == UUID(run_id)))
        assert task is not None

        open_finding = Finding(
            run_id=UUID(run_id),
            title="Missing Security Header",
            severity="medium",
            target_id="https://app.example.test",
            evidence_ref="artifact://assurance/security-header",
            status="open",
            summary="The response did not include the expected defensive header.",
            methodology_tags=["owasp-wstg", "configuration"],
            ptes_phase="vulnerability-analysis",
            nist_phase="analysis",
            wstg_id="WSTG-CONF-07",
            wstg_version="v4.2",
            control_family="configuration",
        )
        accepted_risk = Finding(
            run_id=UUID(run_id),
            title="Legacy TLS Exception",
            severity="low",
            target_id="https://legacy.example.test",
            evidence_ref="artifact://assurance/legacy-tls",
            status="accepted_risk",
            summary="The legacy endpoint remains documented as accepted residual risk.",
            methodology_tags=["tls", "risk-acceptance"],
            ptes_phase="analysis",
            nist_phase="analysis",
            wstg_id="WSTG-CRYP-01",
            wstg_version="v4.2",
            control_family="transport_security",
        )
        resolved_finding = Finding(
            run_id=UUID(run_id),
            title="Resolved Cookie Flag",
            severity="low",
            target_id="https://app.example.test",
            evidence_ref="artifact://assurance/cookie-flag",
            status="resolved",
            summary="The finding record is marked resolved and retains evidence linkage.",
            methodology_tags=["session_management"],
            ptes_phase="post-exploitation",
            nist_phase="reporting",
            wstg_id="WSTG-SESS-02",
            wstg_version="v4.2",
            control_family="session_management",
        )
        session.add_all([open_finding, accepted_risk, resolved_finding])
        session.flush()
        session.add(
            FindingRemediation(
                finding_id=open_finding.id,
                state="in_progress",
                notes="Header rollout is scheduled.",
                owner="app-team",
                created_by="assurance-tester",
                updated_by="assurance-tester",
            )
        )
        execution = ToolExecution(
            task_id=task.id,
            runner_digest="sha256:assurance",
            tool_version="httpx/test",
            exit_code=0,
            stdout_text="stored output remains outside assurance claims",
            stderr_text="",
        )
        session.add(execution)
        session.flush()
        session.add(
            EvidenceArtifact(
                tool_execution_id=execution.id,
                kind="assurance-proof",
                uri="artifact://assurance/evidence",
                sha256="c" * 64,
                redaction_state="clean",
                metadata_json={"name": "assurance-evidence"},
            )
        )
        session.commit()

    catalog_response = inline_client.get(f"/api/v1/runs/{run_id}/reports")
    markdown_response = inline_client.get(f"/api/v1/runs/{run_id}/report?format=markdown&variant=assurance")
    html_response = inline_client.get(f"/api/v1/runs/{run_id}/report?format=html&variant=assurance")
    pdf_response = inline_client.get(f"/api/v1/runs/{run_id}/report?format=pdf&variant=assurance")

    assert catalog_response.status_code == 200
    catalog_by_variant = {item["variant"]: item for item in catalog_response.json()}
    assert set(catalog_by_variant) == {"summary", "technical", "compliance", "retest"}
    assert "assurance" not in catalog_by_variant

    assert markdown_response.status_code == 200
    assert markdown_response.headers["content-type"].startswith("text/markdown")
    assert "# AegisPT Run Report:" in markdown_response.text
    assert "## Adaptive Technical Sections" in markdown_response.text
    assert "Missing Security Header" in markdown_response.text
    assert "Legacy TLS Exception" in markdown_response.text
    assert "artifact://assurance/evidence" in markdown_response.text
    assert "## Tested / Not Tested" in markdown_response.text

    forbidden_phrases = (
        "hack-proof",
        "guaranteed secure",
        "fully secure",
        "certified compliant",
        "soc 2 attested",
        "iso 27001 certified",
        "all risk removed",
        "all vulnerabilities found",
        "all findings fixed",
    )
    normalized_markdown = markdown_response.text.lower()
    for phrase in forbidden_phrases:
        assert phrase not in normalized_markdown

    assert html_response.status_code == 200
    assert html_response.headers["content-type"].startswith("text/html")
    assert "<h1>AegisPT Run Report</h1>" in html_response.text
    assert "Adaptive Technical Sections" in html_response.text

    assert pdf_response.status_code == 200
    assert pdf_response.headers["content-type"].startswith("application/pdf")
    assert pdf_response.content.startswith(b"%PDF")
    pdf_reader = PdfReader(BytesIO(pdf_response.content))
    extracted_text = "\n".join(page.extract_text() or "" for page in pdf_reader.pages)
    assert "AegisPT Run Report" in extracted_text
    assert "Missing Security Header" in extracted_text


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
    assert technical["included_findings"]["count"] == 0
    assert technical["included_inventory"]["host_count"] >= 3
    assert technical["included_inventory"]["service_count"] >= 3
    assert {item["variant"] for item in catalog} == {"summary", "technical", "compliance", "retest"}

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


def test_iot_reports_include_device_type_security_summary() -> None:
    run = Run(
        profile=RunProfile(name="passive-lan-smart-home-audit", run_class="inventory"),
        configuration_json={
            "assessment_type": "Smart Home / IoT LAN",
            "assessment_mode": {"enabled": True, "mode": "FULL-LAN-IOT"},
            "targets": {"cidr_ranges": ["10.0.20.0/24"]},
        },
    )
    run.tasks = [
        Task(tool="mdns-ssdp", target_id="10.0.20.44", params_json={"profile": "FULL-LAN-IOT"}, status="completed"),
        Task(tool="camera-test", target_id="10.0.20.77", params_json={"profile": "FULL-LAN-IOT"}, status="completed"),
    ]
    sections = report_service.report_sections_for_run(run)

    inventory_snapshot = SimpleNamespace(
        normalized_inventory_json={
            "hosts": [
                {"host": "10.0.20.44", "source": "mdns-ssdp", "device_type": "iot-gateway"},
                {"host": "10.0.20.77", "source": "camera-test", "device_type": "ip-camera"},
            ],
            "services": [
                {"host": "10.0.20.44", "port": 80, "service": "http"},
                {"host": "10.0.20.77", "port": 554, "service": "rtsp"},
            ],
            "http_endpoints": [{"url": "http://10.0.20.44"}],
        }
    )
    context = {
        "inventory_snapshot": inventory_snapshot,
        "inventory_summary": {
            "host_count": 2,
            "service_count": 2,
            "endpoint_count": 1,
            "technology_count": 2,
            "device_types": ["iot-gateway", "ip-camera"],
            "device_type_count": 2,
            "confidence_score": 0.91,
        },
        "findings": [
            Finding(
                title="Camera snapshot accessible without authentication",
                severity="high",
                target_id="10.0.20.77",
                status="open",
                summary="The IP camera exposed a management snapshot without authentication.",
                control_family="authentication",
            ),
            Finding(
                title="Default credential accepted on IoT gateway",
                severity="critical",
                target_id="10.0.20.44",
                status="open",
                summary="The management interface accepted default credentials.",
                control_family="authentication",
            ),
        ],
    }
    iot_lines = report_service._iot_security_summary_lines(context)

    assert "iot_security_summary" in sections
    assert "- Device Types: iot-gateway, ip-camera" in iot_lines
    assert "- Default Credential Findings: 1" in iot_lines
    assert "- 10.0.20.77: ip-camera" in iot_lines


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


def test_run_attack_narrative_is_review_only_grounded_and_non_mutating(
    inline_client,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_id, finding_ids = _seed_run_attack_narrative_context(inline_client)
    monkeypatch.setenv("AI_REPORT_DRAFTING_ENABLED", "false")
    from api.app.config import get_settings

    get_settings.cache_clear()
    before_technical = inline_client.get(f"/api/v1/runs/{run_id}/report?format=markdown&variant=technical")
    catalog_response = inline_client.get(f"/api/v1/runs/{run_id}/reports")
    markdown_response = inline_client.get(
        f"/api/v1/runs/{run_id}/report?format=markdown&variant=attack_narrative"
    )
    html_response = inline_client.get(
        f"/api/v1/runs/{run_id}/report?format=html&variant=attack_narrative"
    )
    pdf_response = inline_client.get(
        f"/api/v1/runs/{run_id}/report?format=pdf&variant=attack_narrative"
    )
    after_technical = inline_client.get(f"/api/v1/runs/{run_id}/report?format=markdown&variant=technical")

    assert before_technical.status_code == 200
    assert catalog_response.status_code == 200
    catalog_by_variant = {item["variant"]: item for item in catalog_response.json()}
    assert set(catalog_by_variant) == {"summary", "technical", "compliance", "retest"}
    assert "attack_narrative" not in catalog_by_variant

    assert markdown_response.status_code == 200
    assert markdown_response.headers["content-type"].startswith("text/markdown")
    assert "# AegisPT Run Report:" in markdown_response.text
    assert "## Adaptive Technical Sections" in markdown_response.text
    assert "Admin panel exposed" in markdown_response.text
    assert "Default password accepted" in markdown_response.text
    assert "artifact://http/admin-console" in markdown_response.text

    assert html_response.status_code == 200
    assert html_response.headers["content-type"].startswith("text/html")
    assert "<h1>AegisPT Run Report</h1>" in html_response.text
    assert "Adaptive Technical Sections" in html_response.text

    assert pdf_response.status_code == 200
    assert pdf_response.headers["content-type"].startswith("application/pdf")
    assert pdf_response.content.startswith(b"%PDF")
    pdf_reader = PdfReader(BytesIO(pdf_response.content))
    extracted_text = "\n".join(page.extract_text() or "" for page in pdf_reader.pages)
    assert "AegisPT Run Report" in extracted_text
    assert "Admin panel exposed" in extracted_text

    assert after_technical.text == before_technical.text
    assert markdown_response.text == before_technical.text
    with inline_client.app.state.session_factory() as session:
        stored_findings = session.scalars(select(Finding).where(Finding.id.in_([UUID(item) for item in finding_ids]))).all()
        assert {finding.title for finding in stored_findings} == {"Admin panel exposed", "Default password accepted"}
        assert {finding.status for finding in stored_findings} == {"open"}
        assert {finding.severity for finding in stored_findings} == {"high", "critical"}


def test_run_attack_narrative_sparse_and_unavailable_paths_are_truthful(
    inline_client,
) -> None:
    queued_run_id = _create_soc2_report_run(inline_client)
    queued_catalog = inline_client.get(f"/api/v1/runs/{queued_run_id}/reports")
    queued_markdown = inline_client.get(
        f"/api/v1/runs/{queued_run_id}/report?format=markdown&variant=attack_narrative"
    )

    assert queued_catalog.status_code == 200
    assert {item["variant"] for item in queued_catalog.json()} == {"summary", "technical", "compliance", "retest"}
    assert "# AegisPT Run Report:" in queued_markdown.text

    completed_run_id = _create_soc2_report_run(inline_client)
    with inline_client.app.state.session_factory() as session:
        run = session.scalar(select(Run).where(Run.id == UUID(completed_run_id)))
        assert run is not None
        run.status = "completed"
        session.commit()

    completed_catalog = inline_client.get(f"/api/v1/runs/{completed_run_id}/reports")
    completed_markdown = inline_client.get(
        f"/api/v1/runs/{completed_run_id}/report?format=markdown&variant=attack_narrative"
    )
    assert completed_catalog.status_code == 200
    assert {item["variant"] for item in completed_catalog.json()} == {"summary", "technical", "compliance", "retest"}
    assert "# AegisPT Run Report:" in completed_markdown.text
    assert "No confirmed findings recorded" in completed_markdown.text


def test_evidence_first_attack_story_has_source_ledger_for_each_claim(inline_client) -> None:
    run_id, _finding_ids = _seed_run_attack_narrative_context(inline_client)
    with inline_client.app.state.session_factory() as session:
        run = session.scalar(select(Run).where(Run.id == UUID(run_id)))
        assert run is not None
        session.add(
            Approval(
                run=run,
                step_id="controlled-proof-review",
                approver_id="narrative-operator",
                decision="approved",
            )
        )
        session.commit()
        context = report_service.report_context_for_run(run, session=session)
        context["assessment_graph"] = {
            "edges": [
                {
                    "id": "edge:finding:one:supported_by_artifact:artifact:one",
                    "source": "finding:one",
                    "target": "artifact:one",
                    "relationship": "supported_by_artifact",
                }
            ]
        }
        context["assessment_hypotheses"] = {
            "hypotheses": [
                {
                    "id": "hypothesis:finding:one:next-observation",
                    "confidence": 0.83,
                }
            ]
        }
        story = report_service.evidence_first_attack_story_context(run, context)

    assert story["claims"]
    assert story["unsupported_claims"] == []
    assert story["execution_contract"]["claims_without_sources_allowed"] is False

    ledger_pairs = {
        (row["claim_id"], row["source_type"], row["source_id"])
        for row in story["source_ledger"]
    }
    allowed_source_types = {
        "approval_event_id",
        "finding_id",
        "graph_edge_id",
        "graph_hypothesis_id",
        "runner_output_id",
    }
    source_types: set[str] = set()
    for claim in story["claims"]:
        assert claim["source_ids"]
        for source in claim["source_ids"]:
            source_types.add(source["source_type"])
            assert (
                claim["claim_id"],
                source["source_type"],
                source["source_id"],
            ) in ledger_pairs
    assert source_types <= allowed_source_types
    assert {"approval_event_id", "finding_id", "graph_edge_id", "graph_hypothesis_id", "runner_output_id"}.issubset(
        source_types
    )

    markdown_response = inline_client.get(f"/api/v1/runs/{run_id}/report?format=markdown&variant=technical")
    assert markdown_response.status_code == 200
    assert "## Evidence-First Attack Story" in markdown_response.text
    assert "### Source Ledger" in markdown_response.text
    assert "finding_id:" in markdown_response.text
    assert "runner_output_id:" in markdown_response.text
    assert "approval_event_id:" in markdown_response.text


def test_evidence_first_attack_story_missing_evidence_becomes_gap(inline_client) -> None:
    run_id = _create_soc2_report_run(inline_client)
    with inline_client.app.state.session_factory() as session:
        run = session.scalar(select(Run).where(Run.id == UUID(run_id)))
        assert run is not None
        run.status = "completed"
        finding = Finding(
            run=run,
            title="Unlinked narrative fixture finding",
            severity="medium",
            target_id="https://app.example.test/profile",
            evidence_ref="",
            status="open",
            summary="Fixture finding intentionally lacks an evidence reference.",
        )
        task = Task(
            run=run,
            tool="httpx",
            target_id="https://app.example.test/profile",
            params_json={},
            status="completed",
        )
        session.add_all([finding, task])
        session.commit()
        context = report_service.report_context_for_run(run, session=session)
        story = report_service.evidence_first_attack_story_context(run, context)

    gap_text = "\n".join(str(gap["text"]) for gap in story["gaps"])
    gap_ids = {str(gap["gap_id"]) for gap in story["gaps"]}
    assert any("missing_evidence_ref" in gap_id for gap_id in gap_ids)
    assert any("missing_runner_output" in gap_id for gap_id in gap_ids)
    assert "cannot claim proof" in gap_text
    assert story["unsupported_claims"] == []
    assert all(claim["source_ids"] for claim in story["claims"])

    markdown_response = inline_client.get(f"/api/v1/runs/{run_id}/report?format=markdown&variant=technical")
    assert markdown_response.status_code == 200
    assert "### Evidence Gaps" in markdown_response.text
    assert "cannot claim proof" in markdown_response.text
    assert "missing_runner_output" in markdown_response.text


def test_ai_report_draft_generates_review_only_grounded_sections(
    inline_client,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_id = _create_soc2_report_run(inline_client)
    finding_id = _add_report_draft_finding(inline_client, run_id)
    before_report = inline_client.get(f"/api/v1/runs/{run_id}/report?format=markdown&variant=technical")
    catalog_response = inline_client.get(f"/api/v1/runs/{run_id}/reports")

    monkeypatch.setenv("AI_REPORT_DRAFTING_ENABLED", "true")
    monkeypatch.setenv("AI_REPORT_DRAFTING_PROVIDER", "deterministic")
    from api.app.config import get_settings

    get_settings.cache_clear()
    draft_response = inline_client.post(
        f"/api/v1/runs/{run_id}/report-draft",
        json={
            "variant": "technical",
            "sections": ["executive_summary", "risk_highlights", "remediation_overview"],
        },
    )
    after_report = inline_client.get(f"/api/v1/runs/{run_id}/report?format=markdown&variant=technical")

    assert before_report.status_code == 200
    assert catalog_response.status_code == 200
    technical_catalog = next(item for item in catalog_response.json() if item["variant"] == "technical")
    assert technical_catalog["ai_draft_summary"]["review_required"] is True
    assert technical_catalog["ai_draft_summary"]["canonical_report_unchanged"] is True

    assert draft_response.status_code == 200
    draft = draft_response.json()
    assert draft["available"] is True
    assert draft["status"] == "draft_ready"
    assert draft["provider"] == "deterministic"
    assert draft["review_required"] is True
    assert draft["canonical_report_unchanged"] is True
    assert "AI-assisted Report Draft" in draft["draft_markdown"]
    assert "Operator review is required" in draft["draft_markdown"]
    assert "artifact://zap/admin-panel" in draft["source_evidence_refs"]
    assert "run.findings" in draft["source_data_categories"]
    assert "finding.evidence_ref" in draft["source_data_categories"]
    assert len(draft["sections"]) == 3
    assert after_report.text == before_report.text

    with inline_client.app.state.session_factory() as session:
        finding = session.scalar(select(Finding).where(Finding.id == UUID(finding_id)))
        assert finding is not None
        assert finding.title == "Admin panel exposed"
        assert finding.severity == "high"
        assert finding.status == "open"
        assert finding.evidence_ref == "artifact://zap/admin-panel"


def test_ai_report_draft_supports_chatgpt_oauth_provider(
    inline_client,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_id = _create_soc2_report_run(inline_client)
    _add_report_draft_finding(inline_client, run_id)

    monkeypatch.setenv("AI_PROVIDER", "chatgpt_oauth")
    monkeypatch.setenv("AI_REPORT_DRAFTING_ENABLED", "true")
    monkeypatch.setenv("CHATGPT_OAUTH_MODEL", "gpt-5.4")
    from api.app.config import get_settings

    get_settings.cache_clear()

    def fake_send_chatgpt_backend_streaming_json_request(*, model, instructions, input_items, **_kwargs):
        assert model == "gpt-5.4"
        assert "strict JSON object" in instructions
        payload = json.loads(input_items[0]["content"][0]["text"])
        assert payload["requested_sections"] == [
            "executive_summary",
            "risk_highlights",
            "remediation_overview",
        ]
        return {
            "status": "draft_ready",
            "draft_markdown": "# AI-assisted Report Draft: technical\n\nOperator review is required.",
            "sections": [
                {
                    "section_id": "executive_summary",
                    "title": "Executive Summary Draft",
                    "draft": "AI-assisted executive summary from ChatGPT OAuth.",
                },
                {
                    "section_id": "risk_highlights",
                    "title": "Risk Highlights Draft",
                    "draft": "AI-assisted risk highlights from stored evidence.",
                },
                {
                    "section_id": "remediation_overview",
                    "title": "Remediation Overview Draft",
                    "draft": "AI-assisted remediation overview for operator review.",
                },
            ],
        }

    monkeypatch.setattr(
        "api.app.services.reports.send_chatgpt_backend_streaming_json_request",
        fake_send_chatgpt_backend_streaming_json_request,
    )

    draft_response = inline_client.post(
        f"/api/v1/runs/{run_id}/report-draft",
        json={
            "variant": "technical",
            "sections": ["executive_summary", "risk_highlights", "remediation_overview"],
        },
    )

    assert draft_response.status_code == 200
    draft = draft_response.json()
    assert draft["available"] is True
    assert draft["status"] == "draft_ready"
    assert draft["provider"] == "chatgpt_oauth"
    assert "AI-assisted Report Draft" in draft["draft_markdown"]
    assert draft["sections"][0]["draft"] == "AI-assisted executive summary from ChatGPT OAuth."


def test_ai_report_draft_disabled_and_failure_leave_reports_unchanged(
    inline_client,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_id = _create_soc2_report_run(inline_client)
    _add_report_draft_finding(inline_client, run_id)
    before_report = inline_client.get(f"/api/v1/runs/{run_id}/report?format=markdown&variant=technical")

    disabled_response = inline_client.post(
        f"/api/v1/runs/{run_id}/report-draft",
        json={"variant": "technical", "sections": ["executive_summary"]},
    )

    monkeypatch.setenv("AI_REPORT_DRAFTING_ENABLED", "true")
    monkeypatch.setenv("AI_REPORT_DRAFTING_PROVIDER", "fail")
    from api.app.config import get_settings

    get_settings.cache_clear()
    failed_response = inline_client.post(
        f"/api/v1/runs/{run_id}/report-draft",
        json={"variant": "technical", "sections": ["executive_summary"]},
    )
    after_report = inline_client.get(f"/api/v1/runs/{run_id}/report?format=markdown&variant=technical")

    assert before_report.status_code == 200
    assert disabled_response.status_code == 200
    assert disabled_response.json()["available"] is False
    assert disabled_response.json()["status"] == "disabled"
    assert "disabled" in disabled_response.json()["failure_reason"].lower()
    assert failed_response.status_code == 200
    assert failed_response.json()["available"] is False
    assert failed_response.json()["status"] == "failed"
    assert "failed deterministically" in failed_response.json()["failure_reason"]
    assert after_report.text == before_report.text


def test_evidence_gap_report_separates_states_and_excludes_unsupported_claims(inline_client) -> None:
    run_id = _create_soc2_report_run(inline_client)
    with inline_client.app.state.session_factory() as session:
        run = session.scalar(select(Run).where(Run.id == UUID(run_id)))
        assert run is not None
        run.status = "completed"
        confirmed = Finding(
            run=run,
            title="Confirmed access-control finding",
            severity="high",
            target_id="https://app.example.test/admin",
            evidence_ref="artifact://confirmed-access-control",
            status="open",
            validation_status="validated",
            summary="Evidence-backed access-control claim.",
        )
        suspected = Finding(
            run=run,
            title="Suspected session weakness",
            severity="medium",
            target_id="https://app.example.test/login",
            evidence_ref="",
            status="open",
            validation_status="needs_review",
            summary="No evidence ref is attached yet.",
        )
        contradicted = Finding(
            run=run,
            title="Contradicted weak TLS claim",
            severity="low",
            target_id="https://app.example.test",
            evidence_ref="artifact://tls-strong",
            status="false_positive",
            validation_status="false_positive",
            summary="Stored evidence contradicted the claim.",
        )
        task = Task(
            run=run,
            source_finding=confirmed,
            tool="httpx",
            target_id="https://app.example.test/admin",
            status="completed",
            params_json={},
        )
        execution = ToolExecution(
            task=task,
            runner_digest="sha256:gap-report",
            tool_version="2026.05",
            exit_code=0,
            stdout_text="confirmed",
        )
        EvidenceArtifact(
            execution=execution,
            kind="json",
            uri="artifact://confirmed-access-control",
            sha256="b" * 64,
            redaction_state="redacted",
            metadata_json={},
        )
        session.add_all([confirmed, suspected, contradicted, task, execution])
        session.commit()
        context = report_service.report_context_for_run(run, session=session)

    context["coverage"] = {
        "not_tested": [
            {
                "surface": "OAuth connector export path",
                "evidence_refs": [],
            }
        ]
    }
    gap_report = report_service.build_evidence_gap_report_from_context(context)

    assert gap_report["execution_contract"]["runs_scans"] is False
    assert gap_report["execution_contract"]["changes_findings"] is False
    assert gap_report["summary"]["confirmed"] >= 1
    assert gap_report["summary"]["suspected"] >= 1
    assert gap_report["summary"]["untested"] >= 1
    assert gap_report["summary"]["contradicted"] >= 1
    for section in gap_report["sections"].values():
        for claim in section:
            assert claim["evidence_refs"] or claim["customer_report_allowed"] is False
    unsupported_ids = {
        claim["claim_id"]
        for claim in gap_report["unsupported_claims_excluded_from_customer_report"]
    }
    assert any("Suspected session weakness" in claim["text"] for claim in gap_report["sections"]["suspected"])
    assert any("coverage:not_tested" in claim_id for claim_id in unsupported_ids)

    markdown_response = inline_client.get(f"/api/v1/runs/{run_id}/report?format=markdown&variant=technical")
    assert markdown_response.status_code == 200
    assert "## Evidence Gap Report" in markdown_response.text
    assert "### Confirmed" in markdown_response.text
    assert "### Suspected" in markdown_response.text
    assert "### Contradicted" in markdown_response.text
    assert "Unsupported Claims Excluded From Customer Prose" in markdown_response.text
    assert "Unsupported because no evidence reference is attached." in markdown_response.text
