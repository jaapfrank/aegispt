from __future__ import annotations

import json

from api.app.services.inventory import network_capture_observation_from_json
from workers.orchestration.findings import extract_network_capture_findings
from workers.orchestration.tasks import SUPPORTED_TOOLS, dispatch_runner
from workers.runners.base.contracts import RunnerRequest
from workers.runners.network_capture.runner import (
    NETWORK_CAPTURE_RESULTS_ARTIFACT_NAME,
    CommandResult,
    build_arping_command,
    build_arpspoof_command,
    build_tcpdump_command,
    execute_network_capture_assessment,
)


def _artifact_payload(execution):
    artifact = next(
        item for item in execution.artifacts if item.name == NETWORK_CAPTURE_RESULTS_ARTIFACT_NAME
    )
    return json.loads(artifact.data.decode("utf-8"))


def test_passive_packet_fixture_detects_http_basic_and_redacts_secret_material() -> None:
    packet_text = "\n".join(
        [
            "IP 10.0.20.25.52344 > 10.0.20.10.80: Flags [P.], length 92",
            "GET /admin HTTP/1.1",
            "Host: app.local",
            "Authorization: Basic YWRtaW46c2VjcmV0MTIz",
        ]
    )

    execution = execute_network_capture_assessment(
        targets=["10.0.20.0/24"],
        scope_allowlist={"cidr_ranges": ["10.0.20.0/24"]},
        packet_text=packet_text,
        arp_probe_enabled=False,
    )
    payload = _artifact_payload(execution)
    artifact_text = execution.artifacts[0].data.decode("utf-8")

    assert execution.exit_code == 0
    assert payload["capture"]["raw_payload_stored"] is False
    assert payload["capture"]["credential_values_stored"] is False
    assert payload["credential_signals"][0]["credential_type"] == "basic-auth"
    assert payload["credential_signals"][0]["username_hint"] == "a***"
    assert payload["analysis_findings"][0]["title"] == (
        "Cleartext Credentials Captured in Network Traffic (HTTP Basic Auth)"
    )
    assert "secret123" not in artifact_text
    assert "YWRtaW46c2VjcmV0MTIz" not in artifact_text


def test_arp_consistency_duplicate_mac_and_gateway_mismatch_create_finding() -> None:
    execution = execute_network_capture_assessment(
        targets=["10.0.20.0/24"],
        scope_allowlist={"cidr_ranges": ["10.0.20.0/24"]},
        inventory={
            "arp_table": [
                {"ip": "10.0.20.1", "mac": "00:11:22:33:44:55", "source": "snmp"},
                {"ip": "10.0.20.44", "mac": "00:11:22:33:44:55", "source": "snmp"},
            ]
        },
        packet_text="",
        ip_neigh_text="10.0.20.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE",
        arp_probe_enabled=False,
        gateway_ip="10.0.20.1",
        expected_gateway_mac="de:ad:be:ef:00:01",
    )
    payload = _artifact_payload(execution)

    assert execution.exit_code == 0
    assert {item["type"] for item in payload["arp_consistency"]["anomalies"]} == {
        "duplicate_mac_multiple_ips",
        "multiple_macs_single_ip",
        "gateway_mac_mismatch",
    }
    assert any(
        finding["title"] == "ARP Poisoning Possible - No ARP Inspection Detected"
        for finding in payload["analysis_findings"]
    )


def test_bounded_live_command_path_uses_scope_filter_and_packet_cap() -> None:
    calls: list[tuple[list[str], float]] = []

    def fake_runner(command: list[str], timeout_seconds: float) -> CommandResult:
        calls.append((command, timeout_seconds))
        if command[0].endswith("tcpdump"):
            return CommandResult(
                exit_code=0,
                stdout=(
                    "IP 10.0.20.25.52344 > 10.0.20.10.80: Flags [P.], length 20\n"
                    "Authorization: Bearer redacted-by-runner\n"
                ),
            )
        return CommandResult(exit_code=0, stdout="")

    execution = execute_network_capture_assessment(
        targets=["10.0.20.0/24"],
        scope_allowlist={"cidr_ranges": ["10.0.20.0/24"]},
        interface="eth0",
        capture_seconds=999,
        packet_limit=999999,
        arp_probe_enabled=False,
        tcpdump_binary="tcpdump",
        ip_binary="ip",
        command_runner=fake_runner,
    )
    payload = _artifact_payload(execution)

    tcpdump_call = calls[0][0]
    assert tcpdump_call[0].endswith("tcpdump")
    assert tcpdump_call[1:10] == ["-i", "eth0", "-nn", "-s", "0", "-A", "-l", "-c", "10000"]
    assert "net" in tcpdump_call
    assert "10.0.20.0/24" in tcpdump_call
    assert calls[0][1] == 122.0
    assert payload["capture"]["duration_seconds"] == 120
    assert payload["capture"]["packet_limit"] == 10000
    assert payload["credential_signals"][0]["credential_type"] == "bearer-token"


def test_arp_spoof_proof_is_fail_closed_without_intrusive_gate() -> None:
    execution = execute_network_capture_assessment(
        targets=["10.0.20.0/24"],
        scope_allowlist={"cidr_ranges": ["10.0.20.0/24"]},
        packet_text="fixture no credential material",
        arp_probe_enabled=False,
        mode="arp-spoof-proof",
        arp_spoof_proof_requested=True,
        allow_arp_spoof_proof=False,
        intrusive_authorized=False,
        arp_spoof_target="10.0.20.44",
        gateway_ip="10.0.20.1",
    )
    payload = _artifact_payload(execution)

    assert payload["arp_spoof_proof"]["requested"] is True
    assert payload["arp_spoof_proof"]["status"] == "blocked_requires_intrusive_gate"
    assert payload["arp_spoof_proof"]["executed"] is False
    assert payload["arp_spoof_proof"]["duration_seconds"] <= 30


def test_arp_spoof_proof_executes_only_with_explicit_intrusive_gate() -> None:
    calls: list[tuple[list[str], int]] = []

    def fake_spoof_executor(command: list[str], duration_seconds: int) -> dict:
        calls.append((command, duration_seconds))
        return {
            "exit_code": -2,
            "stdout": "restored",
            "stderr": "",
            "duration_seconds": duration_seconds,
            "restoration_signal_sent": True,
        }

    execution = execute_network_capture_assessment(
        targets=["10.0.20.0/24"],
        scope_allowlist={"cidr_ranges": ["10.0.20.0/24"]},
        packet_text="",
        arp_probe_enabled=False,
        mode="arp-spoof-proof",
        interface="eth0",
        arp_spoof_proof_requested=True,
        allow_arp_spoof_proof=True,
        intrusive_authorized=True,
        arp_spoof_target="10.0.20.44",
        gateway_ip="10.0.20.1",
        arp_spoof_duration_seconds=999,
        arpspoof_binary="arpspoof",
        arpspoof_executor=fake_spoof_executor,
    )
    payload = _artifact_payload(execution)

    assert len(calls) == 1
    command, duration_seconds = calls[0]
    assert command[0].endswith("arpspoof")
    assert command[1:] == ["-i", "eth0", "-t", "10.0.20.44", "10.0.20.1"]
    assert duration_seconds == 30
    assert payload["arp_spoof_proof"]["status"] == "completed"
    assert payload["arp_spoof_proof"]["authorized"] is True
    assert payload["arp_spoof_proof"]["executed"] is True
    assert payload["arp_spoof_proof"]["restoration_attempted"] is True


def test_network_capture_inventory_and_findings_use_normalized_payload() -> None:
    execution = execute_network_capture_assessment(
        targets=["10.0.20.0/24"],
        scope_allowlist={"cidr_ranges": ["10.0.20.0/24"]},
        packet_text=(
            "IP 10.0.20.25.52344 > 10.0.20.10.80: Flags [P.], length 92\n"
            "Authorization: Basic YWRtaW46c2VjcmV0MTIz\n"
        ),
        arp_probe_enabled=False,
    )
    artifact = execution.artifacts[0]
    observation = network_capture_observation_from_json(
        json_bytes=artifact.data,
        target_id="10.0.20.0/24",
    )
    artifact_record = type(
        "ArtifactRecord",
        (),
        {"uri": "artifact://network-capture", "id": "artifact-id", "sha256": artifact.digest},
    )()

    findings = extract_network_capture_findings(
        target_id="10.0.20.0/24",
        artifact=artifact,
        artifact_record=artifact_record,
    )

    assert observation["tool"] == "network-capture"
    assert observation["data"]["services"][0]["service"] == "http"
    assert findings[0].evidence_ref == "artifact://network-capture"
    assert "network-capture" in findings[0].methodology_tags


def test_dispatch_supports_network_capture_without_live_target_activity() -> None:
    assert "network-capture" in SUPPORTED_TOOLS

    execution = dispatch_runner(
        RunnerRequest(
            tool="network-capture",
            targets=["10.0.20.0/24"],
            scope_allowlist={"cidr_ranges": ["10.0.20.0/24"]},
            params={
                "fixture_packet_text": "Authorization: Basic YWRtaW46c2VjcmV0MTIz",
                "arp_probe_enabled": False,
            },
        )
    )
    payload = _artifact_payload(execution)

    assert execution.tool == "network-capture"
    assert execution.exit_code == 0
    assert payload["credential_signals"][0]["credential_type"] == "basic-auth"


def test_command_builders_are_structured() -> None:
    tcpdump = build_tcpdump_command(
        binary="tcpdump",
        interface="eth0",
        packet_limit=100,
        filter_tokens=["(", "net", "10.0.20.0/24", ")"],
    )
    arping = build_arping_command(
        binary="arping",
        interface="eth0",
        target="10.0.20.1",
        probe_count=2,
    )
    arpspoof = build_arpspoof_command(
        binary="arpspoof",
        interface="eth0",
        target="10.0.20.44",
        gateway="10.0.20.1",
    )

    assert tcpdump == [
        "tcpdump",
        "-i",
        "eth0",
        "-nn",
        "-s",
        "0",
        "-A",
        "-l",
        "-c",
        "100",
        "(",
        "net",
        "10.0.20.0/24",
        ")",
    ]
    assert arping == ["arping", "-c", "2", "-I", "eth0", "10.0.20.1"]
    assert arpspoof == ["arpspoof", "-i", "eth0", "-t", "10.0.20.44", "10.0.20.1"]
