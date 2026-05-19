from __future__ import annotations

import json

from workers.orchestration.findings import extract_network_segmentation_findings
from workers.runners.network_segmentation.runner import (
    NETWORK_SEGMENTATION_ARTIFACT_NAME,
    execute_network_segmentation_assessment,
)


def _artifact_payload(execution):
    artifact = next(
        item for item in execution.artifacts if item.name == NETWORK_SEGMENTATION_ARTIFACT_NAME
    )
    return json.loads(artifact.data.decode("utf-8"))


def test_subnet_discovery_from_inventory_routes_creates_info_finding() -> None:
    execution = execute_network_segmentation_assessment(
        targets=["10.0.20.0/24"],
        scope_allowlist={"cidr_ranges": ["10.0.20.0/24"]},
        inventory={
            "routes": [
                {
                    "destination_cidr": "192.168.10.0/24",
                    "gateway": "10.0.20.1",
                    "source": "router-route",
                }
            ]
        },
        reachability_checker=lambda host, port, timeout_seconds: False,
    )
    payload = _artifact_payload(execution)

    assert execution.exit_code == 0
    assert payload["discovered_subnets"][0]["subnet"] == "192.168.10.0/24"
    assert payload["analysis_findings"][0]["severity"] == "info"
    assert payload["analysis_findings"][0]["title"] == (
        "Additional network segment discovered: 192.168.10.0/24"
    )
    assert payload["vlan_double_tag_probe"]["status"] == "not_requested"


def test_snmp_public_routes_and_lateral_reachability_create_medium_finding() -> None:
    calls = []

    def fake_snmp_reader(host, timeout_seconds):
        calls.append(host)
        return [
            {
                "destination_cidr": "192.168.50.0/24",
                "source_host": host,
                "source": "snmp-public",
            }
        ]

    def fake_reachability(host, port, timeout_seconds):
        return host == "192.168.50.1" and port is None

    execution = execute_network_segmentation_assessment(
        targets=["10.0.20.0/24"],
        scope_allowlist={"cidr_ranges": ["10.0.20.0/24"]},
        inventory={"services": [{"host": "10.0.20.1", "port": 161, "service": "snmp"}]},
        snmp_route_reader=fake_snmp_reader,
        reachability_checker=fake_reachability,
    )
    payload = _artifact_payload(execution)

    assert calls == ["10.0.20.1"]
    assert any(item["subnet"] == "192.168.50.0/24" for item in payload["discovered_subnets"])
    assert any(
        finding["severity"] == "medium"
        and finding["title"] == "Cross-segment access detected: 192.168.50.1 is reachable"
        for finding in payload["analysis_findings"]
    )


def test_active_vlan_probe_critical_finding_when_response_observed() -> None:
    def fake_vlan_probe(params):
        assert params["probe_count"] == 10
        return {
            "status": "completed",
            "response_observed": True,
            "native_vlan": params["native_vlan"],
            "target_vlan": params["target_vlan"],
        }

    execution = execute_network_segmentation_assessment(
        targets=["10.0.20.0/24"],
        scope_allowlist={"cidr_ranges": ["10.0.20.0/24"]},
        inventory={},
        mode="active",
        vlan_probe_count=99,
        native_vlan=1,
        target_vlan=20,
        reachability_checker=lambda host, port, timeout_seconds: False,
        vlan_probe_func=fake_vlan_probe,
    )
    payload = _artifact_payload(execution)

    assert execution.exit_code == 0
    assert payload["vlan_double_tag_probe"]["response_observed"] is True
    assert any(
        finding["severity"] == "critical"
        and finding["title"] == "VLAN hopping via 802.1Q double-tagging is possible"
        for finding in payload["analysis_findings"]
    )


def test_active_vlan_probe_capability_unavailable_fails_clearly() -> None:
    execution = execute_network_segmentation_assessment(
        targets=["10.0.20.0/24"],
        scope_allowlist={"cidr_ranges": ["10.0.20.0/24"]},
        inventory={},
        mode="active",
        vlan_probe_func=lambda params: {
            "status": "capability_unavailable",
            "response_observed": False,
            "error": "raw packet permission denied",
        },
    )

    assert execution.exit_code == 2
    assert "raw packet permission denied" in execution.stderr
    assert execution.metadata["vlan_probe_status"] == "capability_unavailable"


def test_orchestration_extracts_network_segmentation_findings() -> None:
    execution = execute_network_segmentation_assessment(
        targets=["10.0.20.0/24"],
        scope_allowlist={"cidr_ranges": ["10.0.20.0/24"]},
        inventory={"arp_table": [{"ip": "192.168.77.10", "source": "nmap-arp"}]},
        reachability_checker=lambda host, port, timeout_seconds: False,
    )
    artifact = execution.artifacts[0]
    artifact_record = type(
        "ArtifactRecord",
        (),
        {"uri": "artifact://network-segmentation", "id": "artifact-id", "sha256": artifact.digest},
    )()

    findings = extract_network_segmentation_findings(
        target_id="10.0.20.0/24",
        artifact=artifact,
        artifact_record=artifact_record,
    )

    assert findings
    assert findings[0].title == "Additional network segment discovered: 192.168.77.0/24"
    assert findings[0].severity == "info"
