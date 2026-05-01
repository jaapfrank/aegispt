from __future__ import annotations

import json

from api.app.services.inventory import ipv6_discovery_observation_from_json
from workers.orchestration.findings import extract_ipv6_discovery_findings
from workers.orchestration.tasks import SUPPORTED_TOOLS, dispatch_runner
from workers.runners.base.contracts import EvidenceArtifact, RunnerExecution, RunnerRequest
from workers.runners.ipv6_discovery.runner import (
    CommandResult,
    IPV6_DISCOVERY_RESULTS_ARTIFACT_NAME,
    execute_ipv6_discovery,
    parse_ip_neigh_output,
    parse_ip_route_output,
)


def _payload(execution: RunnerExecution) -> dict:
    artifact = next(
        item for item in execution.artifacts if item.name == IPV6_DISCOVERY_RESULTS_ARTIFACT_NAME
    )
    return json.loads(artifact.data.decode("utf-8"))


def test_ipv6_neighbor_and_route_output_are_normalized() -> None:
    neighbors = parse_ip_neigh_output(
        "fe80::1 dev eth0 lladdr aa:bb:cc:dd:ee:ff router REACHABLE\n"
        "fd00:20::44 dev eth0 lladdr 00:11:22:33:44:55 STALE\n"
        "fe80::dead dev eth0 FAILED\n"
    )
    prefixes = parse_ip_route_output(
        "fd00:20::/64 dev eth0 proto ra metric 1024 pref medium\n"
        "fe80::/64 dev eth0 proto kernel metric 256 pref medium\n"
    )

    assert len(neighbors) == 2
    assert neighbors[0]["router"] is True
    assert neighbors[0]["address_type"] == "link-local"
    assert neighbors[1]["address_type"] == "unique-local"
    assert prefixes[0]["prefix"] == "fd00:20::/64"


def test_execute_ipv6_discovery_uses_injected_commands_and_bounded_nmap6() -> None:
    commands: list[list[str]] = []
    nmap_kwargs: dict[str, object] = {}

    def fake_command_runner(command: list[str], timeout_seconds: float) -> CommandResult:
        commands.append(command)
        if command[:3] == ["ip", "-6", "neigh"]:
            return CommandResult(
                0,
                "fe80::1 dev eth0 lladdr aa:bb:cc:dd:ee:ff router REACHABLE\n"
                "fd00:20::44 dev eth0 lladdr 00:11:22:33:44:55 STALE\n",
            )
        if command[:3] == ["ip", "-6", "route"]:
            return CommandResult(0, "fd00:20::/64 dev eth0 proto ra metric 1024\n")
        return CommandResult(0)

    def fake_nmap_executor(targets: list[str], **kwargs) -> RunnerExecution:
        nmap_kwargs.update(kwargs)
        assert targets == ["fe80::1", "fd00:20::44"]
        return RunnerExecution(
            tool="nmap",
            exit_code=0,
            stdout="nmap -6 complete",
            stderr="",
            metadata={"ipv6": kwargs.get("ipv6")},
            artifacts=[
                EvidenceArtifact(
                    name="nmap-results.xml",
                    content_type="application/xml",
                    data=b"<nmaprun />",
                )
            ],
        )

    execution = execute_ipv6_discovery(
        ["10.0.20.0/24"],
        scope_allowlist={"cidr_ranges": ["10.0.20.0/24"]},
        inventory={"hosts": [{"host": "10.0.20.10"}]},
        interface=None,
        command_runner=fake_command_runner,
        nmap_executor=fake_nmap_executor,
    )
    payload = _payload(execution)

    assert execution.exit_code == 0
    assert ["ip", "-6", "neigh", "show"] in commands
    assert payload["neighbor_solicitation"]["status"] == "skipped"
    assert payload["nmap_ipv6"]["targets"] == ["fe80::1", "fd00:20::44"]
    assert nmap_kwargs["ipv6"] is True
    assert nmap_kwargs["skip_discovery"] is True
    assert payload["inventory"]["ipv6_addresses"][0]["address"] == "fe80::1"
    assert payload["analysis_findings"][0]["title"] == (
        "IPv6 reachable host lacks matching IPv4 inventory evidence"
    )


def test_inventory_import_and_finding_extraction_use_ipv6_payload() -> None:
    execution = execute_ipv6_discovery(
        ["10.0.20.0/24"],
        inventory={"hosts": [{"host": "10.0.20.10"}]},
        command_runner=lambda command, timeout_seconds: CommandResult(
            0,
            (
                "fe80::1 dev eth0 lladdr aa:bb:cc:dd:ee:ff router REACHABLE\n"
                if command[:3] == ["ip", "-6", "neigh"]
                else "fd00:20::/64 dev eth0 proto ra metric 1024\n"
            ),
        ),
        nmap_executor=lambda targets, **kwargs: RunnerExecution(
            tool="nmap",
            exit_code=0,
            stdout="ok",
            stderr="",
            artifacts=[],
        ),
    )
    artifact = execution.artifacts[0]
    observation = ipv6_discovery_observation_from_json(
        json_bytes=artifact.data,
        target_id="10.0.20.0/24",
    )
    artifact_record = type(
        "ArtifactRecord",
        (),
        {"uri": "artifact://ipv6-discovery", "id": "artifact-id", "sha256": artifact.digest},
    )()

    findings = extract_ipv6_discovery_findings(
        target_id="10.0.20.0/24",
        artifact=artifact,
        artifact_record=artifact_record,
    )

    assert observation["tool"] == "ipv6-discovery"
    assert observation["data"]["ipv6_addresses"][0]["address"] == "fe80::1"
    assert len(findings) == 1
    assert findings[0].evidence_ref == "artifact://ipv6-discovery"


def test_dispatch_supports_ipv6_discovery_without_live_multicast() -> None:
    assert "ipv6-discovery" in SUPPORTED_TOOLS

    execution = dispatch_runner(
        RunnerRequest(
            tool="ipv6-discovery",
            targets=[],
            scope_allowlist={},
            params={"run_nmap": False},
        )
    )

    payload = _payload(execution)
    assert execution.tool == "ipv6-discovery"
    assert payload["neighbor_solicitation"]["status"] == "skipped"
