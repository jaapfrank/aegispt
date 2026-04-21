from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture
def fake_nmap_binary(tmp_path: Path) -> str:
    binary_path = tmp_path / "fake-nmap"
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
service_detection = "-sV" in args
skip_next = False
targets = []
for arg in args:
    if skip_next:
        skip_next = False
        continue
    if arg in {"-oX", "--top-ports"}:
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
        f"<host><status state='up'/><address addr='{host}' addrtype='ipv4'/><ports><port protocol='tcp' portid='80'><state state='open'/><service name='http' product='nginx' version='1.25'/></port>{'<port protocol=\\'tcp\\' portid=\\'22\\'><state state=\\'open\\'/><service name=\\'ssh\\' product=\\'OpenSSH\\' version=\\'9.0\\'/></port>' if service_detection else ''}</ports></host>"
        for host in hosts
    ) + "</nmaprun>"
output_path.write_text(xml, encoding="utf-8")
print(xml)
""",
        encoding="utf-8",
    )
    binary_path.chmod(0o755)
    return str(binary_path)


def test_inline_dispatch_executes_nmap_task(
    inline_client,
    monkeypatch: pytest.MonkeyPatch,
    fake_nmap_binary: str,
) -> None:
    monkeypatch.setenv("NMAP_BINARY", fake_nmap_binary)

    engagement_response = inline_client.post(
        "/api/v1/engagements",
        headers={"X-Actor": "tester"},
        json={
            "name": "Inline Nmap Validation",
            "client": "Acme Corp",
            "roe_ref": "ROE-2026-012",
        },
    )
    engagement_id = engagement_response.json()["id"]

    inline_client.post(
        f"/api/v1/engagements/{engagement_id}/scope",
        headers={"X-Actor": "tester"},
        json={
            "allowlist_json": {
                "cidrs": ["10.10.0.0/24"],
                "hosts": ["10.10.1.15"],
            },
            "denylist_json": {},
        },
    )

    run_response = inline_client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "tester"},
        json={"profile_name": "passive-network-discovery"},
    )
    run_payload = run_response.json()
    task_id = run_payload["tasks"][0]["id"]

    dispatch_response = inline_client.post(
        f"/api/v1/runs/{run_payload['id']}/dispatch",
        headers={"X-Actor": "dispatcher"},
    )

    assert dispatch_response.status_code == 200
    dispatch_payload = dispatch_response.json()
    assert dispatch_payload["dispatch_mode"] == "inline"
    assert dispatch_payload["run"]["status"] == "completed"
    assert dispatch_payload["run"]["tasks"][0]["tool"] == "nmap"
    assert dispatch_payload["run"]["tasks"][0]["status"] == "completed"

    task_response = inline_client.get(f"/api/v1/tasks/{task_id}")
    assert task_response.status_code == 200
    task_payload = task_response.json()
    assert task_payload["status"] == "completed"
    assert task_payload["executions"][0]["tool_version"] == "Nmap version test-build"
    assert task_payload["executions"][0]["artifacts"][0]["metadata_json"]["name"] == "nmap-results.xml"

    inventory_response = inline_client.get(f"/api/v1/engagements/{engagement_id}/inventory")
    assert inventory_response.status_code == 200
    inventory_payload = inventory_response.json()
    assert len(inventory_payload) >= 1
    assert inventory_payload[0]["source_tools_json"] == ["nmap"]
    assert inventory_payload[0]["summary_json"]["host_count"] >= 1


def test_discovery_inventory_sorts_ahead_of_same_run_seed_snapshot(
    inline_client,
    monkeypatch: pytest.MonkeyPatch,
    fake_nmap_binary: str,
) -> None:
    monkeypatch.setenv("NMAP_BINARY", fake_nmap_binary)

    engagement_response = inline_client.post(
        "/api/v1/engagements",
        headers={"X-Actor": "tester"},
        json={
            "name": "Wizard Seed Ordering",
            "client": "Acme Corp",
            "roe_ref": "ROE-2026-013",
        },
    )
    engagement_id = engagement_response.json()["id"]

    inline_client.post(
        f"/api/v1/engagements/{engagement_id}/scope",
        headers={"X-Actor": "tester"},
        json={
            "allowlist_json": {"cidrs": ["10.0.20.0/24"]},
            "denylist_json": {},
        },
    )

    seed_response = inline_client.post(
        "/api/v1/inventory/runs",
        headers={"X-Actor": "operator-ui"},
        json={
            "engagement_id": engagement_id,
            "source_tools": ["wizard-input"],
            "observations": [
                {
                    "tool": "wizard-input",
                    "kind": "inventory-seed",
                    "data": {
                        "hosts": [],
                        "urls": [],
                        "endpoints": [],
                        "confidence": 0.72,
                    },
                }
            ],
            "environment_notes": ["Wizard seeded assessment type: Internal Range / LAN"],
            "assumptions": ["Seed inventory was created from operator-reviewed wizard input before active discovery."],
        },
    )
    seed_id = seed_response.json()["id"]

    run_response = inline_client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator-ui"},
        json={
            "profile_name": "passive-network-discovery",
            "source_inventory_snapshot_id": seed_id,
            "configuration_json": {
                "assessment_type": "Internal Range / LAN",
                "test_profile": "Standard",
                "targets": {"cidr_ranges": ["10.0.20.0/24"]},
            },
        },
    )
    run_id = run_response.json()["id"]

    dispatch_response = inline_client.post(
        f"/api/v1/runs/{run_id}/dispatch",
        headers={"X-Actor": "dispatcher"},
    )
    assert dispatch_response.status_code == 200

    inventory_response = inline_client.get(f"/api/v1/engagements/{engagement_id}/inventory")
    assert inventory_response.status_code == 200
    inventory_payload = inventory_response.json()
    assert len(inventory_payload) >= 2
    assert inventory_payload[0]["source_tools_json"] == ["nmap"]
    assert inventory_payload[0]["summary_json"]["host_count"] >= 1
    assert inventory_payload[1]["id"] == seed_id


def test_service_enumeration_uses_configured_hosts_and_records_services(
    inline_client,
    monkeypatch: pytest.MonkeyPatch,
    fake_nmap_binary: str,
) -> None:
    monkeypatch.setenv("NMAP_BINARY", fake_nmap_binary)

    engagement_response = inline_client.post(
        "/api/v1/engagements",
        headers={"X-Actor": "tester"},
        json={
            "name": "Service Enumeration",
            "client": "Acme Corp",
            "roe_ref": "ROE-2026-014",
        },
    )
    engagement_id = engagement_response.json()["id"]

    inline_client.post(
        f"/api/v1/engagements/{engagement_id}/scope",
        headers={"X-Actor": "tester"},
        json={
            "allowlist_json": {"cidrs": ["10.0.20.0/24"]},
            "denylist_json": {},
        },
    )

    run_response = inline_client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "tester"},
        json={
            "profile_name": "passive-network-service-enumeration",
            "configuration_json": {
                "assessment_type": "Internal Range / LAN",
                "test_profile": "Follow-up Service Enumeration",
                "targets": {"ip_addresses": ["10.0.20.8", "10.0.20.14"]},
            },
        },
    )
    assert run_response.status_code == 201
    run_payload = run_response.json()
    assert [task["target_id"] for task in run_payload["tasks"]] == ["10.0.20.14", "10.0.20.8"]

    dispatch_response = inline_client.post(
        f"/api/v1/runs/{run_payload['id']}/dispatch",
        headers={"X-Actor": "dispatcher"},
    )
    assert dispatch_response.status_code == 200

    inventory_response = inline_client.get(f"/api/v1/engagements/{engagement_id}/inventory")
    inventory_payload = inventory_response.json()
    assert inventory_payload[0]["source_tools_json"] == ["nmap"]
    assert inventory_payload[0]["summary_json"]["service_count"] >= 2
