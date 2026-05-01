from __future__ import annotations

import json

import pytest

from workers.runners.base.contracts import EvidenceArtifact, RunnerExecution
from workers.runners.external_infra.runner import (
    EXTERNAL_INFRA_RESULTS_ARTIFACT_NAME,
    execute_external_infra_assessment,
)
from workers.runners.netexec.runner import NETEXEC_RESULTS_ARTIFACT_NAME

NMAP_XML = b"""<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up" />
    <address addr="203.0.113.10" addrtype="ipv4" />
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" />
        <service name="ssh" product="OpenSSH" version="8.2" />
      </port>
      <port protocol="tcp" portid="8443">
        <state state="open" />
        <service name="https" product="nginx" version="1.25" />
      </port>
      <port protocol="tcp" portid="5432">
        <state state="open" />
        <service name="postgresql" product="PostgreSQL" version="14" />
      </port>
      <port protocol="tcp" portid="445">
        <state state="open" />
        <service name="microsoft-ds" product="SMB" version="3.1.1" />
      </port>
    </ports>
  </host>
</nmaprun>
"""


def _artifact(name: str, payload: object, *, content_type: str = "application/json", kind: str = "raw") -> EvidenceArtifact:
    data = payload if isinstance(payload, bytes) else (json.dumps(payload, sort_keys=True) + "\n").encode("utf-8")
    return EvidenceArtifact(
        name=name,
        content_type=content_type,
        data=data,
        kind=kind,
    )


def test_passive_external_infra_runner_expands_domains_and_emits_service_findings() -> None:
    captured: dict[str, object] = {}

    def fake_easm(*, targets, scope_allowlist, timeout_seconds):
        assert targets == ["example.com"]
        assert scope_allowlist == {"domains": ["example.com"], "cidrs": ["203.0.113.0/28"]}
        return RunnerExecution(
            tool="easm-discover",
            exit_code=0,
            stdout="",
            stderr="",
            metadata={"status": "ok"},
            artifacts=[
                _artifact(
                    "easm-results.json",
                    {
                        "summary": {"asset_count": 2},
                        "results": [
                            {
                                "root_domain": "example.com",
                                "assets": [
                                    {
                                        "host": "edge.example.com",
                                        "resolved_ips": ["203.0.113.10"],
                                        "http_endpoints": [{"url": "https://edge.example.com"}],
                                    },
                                    {
                                        "host": "vpn.example.com",
                                        "resolved_ips": ["203.0.113.11"],
                                        "http_endpoints": [],
                                    },
                                ],
                            }
                        ],
                    },
                    kind="inventory-results",
                )
            ],
        )

    def fake_nmap(*, targets, binary, discovery_only, service_detection, skip_discovery, full_port_scan):
        captured["nmap_targets"] = list(targets)
        assert binary == "nmap"
        assert discovery_only is False
        assert service_detection is True
        assert skip_discovery is True
        assert full_port_scan is True
        return RunnerExecution(
            tool="nmap",
            exit_code=0,
            stdout="",
            stderr="",
            metadata={"status": "ok"},
            artifacts=[
                EvidenceArtifact(
                    name="nmap-results.xml",
                    content_type="application/xml",
                    data=NMAP_XML,
                    kind="network-scan-results",
                )
            ],
        )

    def fake_httpx(*, targets, rate_limit, timeout_seconds):
        captured["httpx_targets"] = list(targets)
        assert rate_limit == 3
        return RunnerExecution(
            tool="httpx",
            exit_code=0,
            stdout="",
            stderr="",
            metadata={"status": "ok"},
            artifacts=[
                EvidenceArtifact(
                    name="httpx-results.jsonl",
                    content_type="application/x-ndjson",
                    data=(
                        json.dumps(
                            {
                                "input_target": "https://203.0.113.10:8443",
                                "request_url": "https://203.0.113.10:8443",
                                "final_url": "https://203.0.113.10:8443",
                                "status_code": 200,
                                "content_type": "text/html",
                                "ok": True,
                            },
                            sort_keys=True,
                        )
                        + "\n"
                    ).encode("utf-8"),
                    kind="probe-results",
                )
            ],
        )

    def fake_ssh(*, host, port, binary, timeout_seconds):
        assert binary == "ssh-audit"
        return RunnerExecution(
            tool="ssh-audit",
            exit_code=0,
            stdout="",
            stderr="",
            metadata={"status": "ok"},
            artifacts=[
                _artifact(
                    f"ssh-audit-{host}-{port}.json",
                    {
                        "host": host,
                        "port": port,
                        "analysis_findings": [
                            {
                                "title": f"Weak SSH ciphers and algorithms on {host}:{port}",
                                "severity": "high",
                                "target_id": f"{host}:{port}",
                                "summary": "Legacy CBC ciphers observed.",
                                "methodology_tags": ["owasp-wstg", "WSTG-CRYP", "cryptography", "ssh"],
                                "ptes_phase": "vulnerability_analysis",
                                "nist_phase": "discovery",
                                "control_family": "cryptography",
                            }
                        ],
                    },
                    kind="ssh-audit-results",
                )
            ],
        )

    def fake_netexec(*, targets, mode, binary, scope_allowlist, timeout_seconds):
        captured["netexec_targets"] = list(targets)
        assert mode == "passive"
        assert "203.0.113.10" in scope_allowlist["hosts"]
        return RunnerExecution(
            tool="netexec",
            exit_code=0,
            stdout="",
            stderr="",
            metadata={"status": "ok"},
            artifacts=[
                _artifact(
                    NETEXEC_RESULTS_ARTIFACT_NAME,
                    {
                        "targets": [
                            {
                                "target": "203.0.113.10",
                                "status": "ok",
                                "analysis_findings": [
                                    {
                                        "title": "SMB signing disabled on 203.0.113.10",
                                        "severity": "medium",
                                        "target_id": "203.0.113.10",
                                        "summary": "Signing disabled.",
                                        "methodology_tags": ["owasp-wstg", "WSTG-CONFIG", "configuration"],
                                        "ptes_phase": "vulnerability_analysis",
                                        "nist_phase": "discovery",
                                        "control_family": "configuration",
                                    }
                                ],
                            }
                        ]
                    },
                    kind="smb-results",
                )
            ],
        )

    execution = execute_external_infra_assessment(
        ["https://example.com", "203.0.113.0/28"],
        mode="passive",
        scope_allowlist={"domains": ["example.com"], "cidrs": ["203.0.113.0/28"]},
        timeout_seconds=12.0,
        rate_limit=3,
        execute_easm=fake_easm,
        execute_nmap=fake_nmap,
        execute_httpx=fake_httpx,
        execute_ssh=fake_ssh,
        execute_netexec=fake_netexec,
    )

    assert execution.tool == "external-infra"
    assert execution.exit_code == 0
    assert execution.metadata["mode"] == "passive"
    assert captured["nmap_targets"] == ["203.0.113.0/28", "203.0.113.10", "203.0.113.11"]
    assert "https://203.0.113.10:8443" in captured["httpx_targets"]
    assert captured["netexec_targets"] == ["203.0.113.10"]

    results_artifact = next(
        artifact
        for artifact in execution.artifacts
        if artifact.name == EXTERNAL_INFRA_RESULTS_ARTIFACT_NAME
    )
    payload = json.loads(results_artifact.data.decode("utf-8"))
    titles = {finding["title"] for finding in payload["analysis_findings"]}
    assert "Weak SSH ciphers and algorithms on 203.0.113.10:22" in titles
    assert "Externally exposed database service on 203.0.113.10:5432" in titles
    assert "Externally exposed management service on 203.0.113.10:22" in titles
    assert "SMB signing disabled on 203.0.113.10" in titles
    assert payload["inventory"]["services"]


def test_active_external_infra_runner_adds_infrastructure_nuclei_followup() -> None:
    captured: dict[str, object] = {}

    def fake_nmap(**kwargs):
        return RunnerExecution(
            tool="nmap",
            exit_code=0,
            stdout="",
            stderr="",
            metadata={"status": "ok"},
            artifacts=[
                EvidenceArtifact(
                    name="nmap-results.xml",
                    content_type="application/xml",
                    data=NMAP_XML,
                    kind="network-scan-results",
                )
            ],
        )

    def fake_httpx(**kwargs):
        return RunnerExecution(
            tool="httpx",
            exit_code=0,
            stdout="",
            stderr="",
            metadata={"status": "ok"},
            artifacts=[
                EvidenceArtifact(
                    name="httpx-results.jsonl",
                    content_type="application/x-ndjson",
                    data=(
                        json.dumps(
                            {
                                "input_target": "https://203.0.113.10:8443",
                                "request_url": "https://203.0.113.10:8443",
                                "final_url": "https://203.0.113.10:8443",
                                "status_code": 200,
                                "content_type": "text/html",
                                "ok": True,
                            },
                            sort_keys=True,
                        )
                        + "\n"
                    ).encode("utf-8"),
                    kind="probe-results",
                )
            ],
        )

    def fake_ssh(**kwargs):
        return RunnerExecution(
            tool="ssh-audit",
            exit_code=0,
            stdout="",
            stderr="",
            metadata={"status": "ok"},
            artifacts=[],
        )

    def fake_netexec(**kwargs):
        return RunnerExecution(
            tool="netexec",
            exit_code=0,
            stdout="",
            stderr="",
            metadata={"status": "ok"},
            artifacts=[],
        )

    def fake_nuclei(*, targets, rate_limit, timeout_seconds, binary, template_body, template_id, template_source, template_filename):
        captured["nuclei_targets"] = list(targets)
        captured["template_id"] = template_id
        captured["template_source"] = template_source
        assert "Infrastructure Management Surface" in template_body
        return RunnerExecution(
            tool="nuclei",
            exit_code=0,
            stdout="",
            stderr="",
            metadata={
                "status": "ok",
                "template_id": template_id,
                "template_source": template_source,
            },
            artifacts=[
                EvidenceArtifact(
                    name="nuclei-results.jsonl",
                    content_type="application/x-ndjson",
                    data=(
                        json.dumps(
                            {
                                "template-id": "infra-vpn-exposure",
                                "matched-at": "https://203.0.113.10:8443",
                                "matcher-name": "vpn-login",
                                "info": {"name": "VPN management surface exposed", "severity": "high"},
                            },
                            sort_keys=True,
                        )
                        + "\n"
                    ).encode("utf-8"),
                    kind="scan-results",
                )
            ],
        )

    execution = execute_external_infra_assessment(
        ["203.0.113.10"],
        mode="active",
        scope_allowlist={"hosts": ["203.0.113.10"]},
        execute_nmap=fake_nmap,
        execute_httpx=fake_httpx,
        execute_ssh=fake_ssh,
        execute_netexec=fake_netexec,
        execute_nuclei=fake_nuclei,
    )

    assert execution.exit_code == 0
    assert execution.metadata["mode"] == "active"
    assert captured["nuclei_targets"] == ["https://203.0.113.10:8443"]
    assert captured["template_id"] == "aegispt-infrastructure-management-surfaces"
    assert captured["template_source"] == "aegispt-curated-infrastructure"

    results_artifact = next(
        artifact
        for artifact in execution.artifacts
        if artifact.name == EXTERNAL_INFRA_RESULTS_ARTIFACT_NAME
    )
    payload = json.loads(results_artifact.data.decode("utf-8"))
    titles = {finding["title"] for finding in payload["analysis_findings"]}
    assert "VPN management surface exposed" in titles
    assert payload["substeps"]["nuclei"]["finding_count"] == 1


def test_external_infra_runner_rejects_targets_outside_scope() -> None:
    with pytest.raises(ValueError, match="target outside scope"):
        execute_external_infra_assessment(
            ["198.51.100.10"],
            mode="passive",
            scope_allowlist={"hosts": ["203.0.113.10"]},
        )


def test_external_infra_runner_returns_failed_execution_when_nmap_fails() -> None:
    def fake_nmap(**kwargs):
        return RunnerExecution(
            tool="nmap",
            exit_code=1,
            stdout="",
            stderr="nmap failed",
            metadata={"status": "failed"},
            artifacts=[],
        )

    execution = execute_external_infra_assessment(
        ["203.0.113.10"],
        mode="passive",
        scope_allowlist={"hosts": ["203.0.113.10"]},
        execute_nmap=fake_nmap,
    )

    assert execution.exit_code == 1
    artifact = next(
        artifact
        for artifact in execution.artifacts
        if artifact.name == EXTERNAL_INFRA_RESULTS_ARTIFACT_NAME
    )
    payload = json.loads(artifact.data.decode("utf-8"))
    assert payload["status"] == "failed"
