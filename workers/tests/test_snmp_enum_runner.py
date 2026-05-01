from __future__ import annotations

import json

from api.app.services.inventory import snmp_enum_observation_from_json
from workers.orchestration.findings import extract_snmp_enum_findings
from workers.orchestration.tasks import SUPPORTED_TOOLS, dispatch_runner
from workers.runners.base.contracts import RunnerRequest
from workers.runners.snmp_enum.runner import (
    DEFAULT_COMMUNITIES,
    SNMP_ENUM_RESULTS_ARTIFACT_NAME,
    execute_snmp_enumeration,
)


def _artifact_payload(execution):
    artifact = next(item for item in execution.artifacts if item.name == SNMP_ENUM_RESULTS_ARTIFACT_NAME)
    return json.loads(artifact.data.decode("utf-8"))


def test_default_community_detection_collects_system_interface_arp_and_routes() -> None:
    calls: list[tuple[str, str, str]] = []

    def fake_client(host: str, community: str, oid: str, timeout_seconds: float):
        calls.append((host, community, oid))
        if community != "public":
            return []
        if oid == "1.3.6.1.2.1.1":
            return [
                {"oid": "1.3.6.1.2.1.1.1.0", "value": "UniFi Switch 24"},
                {"oid": "1.3.6.1.2.1.1.5.0", "value": "switch-core"},
            ]
        if oid == "1.3.6.1.2.1.2.2":
            return [
                {"oid": "1.3.6.1.2.1.2.2.1.2.1", "value": "br0"},
                {"oid": "1.3.6.1.2.1.2.2.1.6.1", "value": "aa:bb:cc:dd:ee:ff"},
                {"oid": "1.3.6.1.2.1.2.2.1.8.1", "value": "1"},
            ]
        if oid == "1.3.6.1.2.1.4.22":
            return [
                {"oid": "1.3.6.1.2.1.4.22.1.2.1.10.0.20.55", "value": "00:11:22:33:44:55"},
                {"oid": "1.3.6.1.2.1.4.22.1.3.1.10.0.20.55", "value": "10.0.20.55"},
            ]
        if oid == "1.3.6.1.2.1.4.21":
            return [
                {"oid": "1.3.6.1.2.1.4.21.1.1.192.168.10.0", "value": "192.168.10.0"},
                {"oid": "1.3.6.1.2.1.4.21.1.7.192.168.10.0", "value": "10.0.20.1"},
                {"oid": "1.3.6.1.2.1.4.21.1.11.192.168.10.0", "value": "255.255.255.0"},
            ]
        return []

    execution = execute_snmp_enumeration(
        targets=["10.0.20.1"],
        scope_allowlist={"hosts": ["10.0.20.1"]},
        snmp_client=fake_client,
    )
    payload = _artifact_payload(execution)

    assert execution.exit_code == 0
    assert payload["hosts"][0]["accepted_communities"] == ["public"]
    assert payload["hosts"][0]["system"]["sysDescr"] == "UniFi Switch 24"
    assert payload["inventory"]["services"][0]["service"] == "snmp"
    assert payload["inventory"]["network_interfaces"][0]["description"] == "br0"
    assert payload["inventory"]["arp_table"][0]["ip"] == "10.0.20.55"
    assert payload["inventory"]["routes"][0]["destination_cidr"] == "192.168.10.0/24"
    assert payload["analysis_findings"][0]["severity"] == "medium"
    assert payload["analysis_findings"][0]["title"] == "SNMP community string accepted"
    assert ("10.0.20.1", "public", "1.3.6.1.2.1.1") in calls


def test_community_testing_is_limited_to_task_package_defaults() -> None:
    calls: list[str] = []

    def fake_client(host: str, community: str, oid: str, timeout_seconds: float):
        calls.append(community)
        return []

    execution = execute_snmp_enumeration(
        targets=["10.0.20.1"],
        scope_allowlist={"hosts": ["10.0.20.1"]},
        communities=[*DEFAULT_COMMUNITIES, "not-allowed"],
        snmp_client=fake_client,
    )
    payload = _artifact_payload(execution)

    assert execution.exit_code == 0
    assert payload["community_strings_tested"] == list(DEFAULT_COMMUNITIES)
    assert calls == list(DEFAULT_COMMUNITIES)
    assert payload["analysis_findings"] == []


def test_inventory_import_and_finding_extraction_use_normalized_payload() -> None:
    execution = execute_snmp_enumeration(
        targets=["10.0.20.1"],
        scope_allowlist={"hosts": ["10.0.20.1"]},
        snmp_client=lambda host, community, oid, timeout_seconds: (
            [{"oid": "1.3.6.1.2.1.1.5.0", "value": "router"}]
            if community == "public" and oid == "1.3.6.1.2.1.1"
            else []
        ),
    )
    artifact = execution.artifacts[0]
    observation = snmp_enum_observation_from_json(
        json_bytes=artifact.data,
        target_id="10.0.20.1",
    )
    artifact_record = type(
        "ArtifactRecord",
        (),
        {"uri": "artifact://snmp-enum", "id": "artifact-id", "sha256": artifact.digest},
    )()

    findings = extract_snmp_enum_findings(
        target_id="10.0.20.1",
        artifact=artifact,
        artifact_record=artifact_record,
    )

    assert observation["tool"] == "snmp-enum"
    assert observation["data"]["hosts"] == ["10.0.20.1"]
    assert observation["data"]["services"][0]["port"] == 161
    assert len(findings) == 1
    assert findings[0].severity == "medium"
    assert findings[0].evidence_ref == "artifact://snmp-enum"


def test_dispatch_supports_snmp_enum_without_live_target_activity() -> None:
    assert "snmp-enum" in SUPPORTED_TOOLS

    execution = dispatch_runner(
        RunnerRequest(
            tool="snmp-enum",
            targets=[],
            scope_allowlist={},
            params={"community_strings": list(DEFAULT_COMMUNITIES), "max_target_hosts": 1},
        )
    )

    payload = _artifact_payload(execution)
    assert execution.tool == "snmp-enum"
    assert execution.exit_code == 0
    assert payload["targets"] == []
