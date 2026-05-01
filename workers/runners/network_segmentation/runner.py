from __future__ import annotations

from collections.abc import Callable, Iterable
import ipaddress
import json
import os
import shutil
import socket
import subprocess
import time
from typing import Any

from workers.runners.base.contracts import EvidenceArtifact, RunnerExecution

NETWORK_SEGMENTATION_ARTIFACT_NAME = "network-segmentation-results.json"
NETWORK_SEGMENTATION_RUNNER_DIGEST = "workers.network_segmentation.runner:v1"
DEFAULT_REACHABILITY_PORTS = (22, 80, 443, 8080, 8123)

SnmpRouteReader = Callable[[str, float], list[dict[str, Any]]]
ReachabilityChecker = Callable[[str, int | None, float], bool]
VlanProbeFunc = Callable[[dict[str, Any]], dict[str, Any]]


def _normalized_string_list(values: Iterable[object] | None) -> list[str]:
    normalized: list[str] = []
    seen: set[str] = set()
    for value in values or []:
        candidate = str(value or "").strip()
        if candidate and candidate not in seen:
            seen.add(candidate)
            normalized.append(candidate)
    return normalized


def _network_from_value(value: object) -> ipaddress._BaseNetwork | None:
    candidate = str(value or "").strip()
    if not candidate:
        return None
    try:
        return ipaddress.ip_network(candidate, strict=False)
    except ValueError:
        pass
    try:
        address = ipaddress.ip_address(candidate)
    except ValueError:
        return None
    return ipaddress.ip_network(f"{address}/{address.max_prefixlen}", strict=False)


def _scope_values(targets: list[str], scope_allowlist: dict[str, Any]) -> list[str]:
    values = list(targets)
    for key in ("cidrs", "cidr_ranges", "hosts", "ip_addresses", "targets"):
        raw = scope_allowlist.get(key)
        if isinstance(raw, list):
            values.extend(str(item) for item in raw)
    return _normalized_string_list(values)


def _scope_networks(targets: list[str], scope_allowlist: dict[str, Any]) -> list[ipaddress._BaseNetwork]:
    networks: list[ipaddress._BaseNetwork] = []
    for value in _scope_values(targets, scope_allowlist):
        network = _network_from_value(value)
        if network is not None:
            networks.append(network)
    return networks


def _host_in_scope(host: str, networks: list[ipaddress._BaseNetwork]) -> bool:
    if not networks:
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return True
    return any(address in network for network in networks)


def _subnet_in_scope(subnet: ipaddress._BaseNetwork, scope_networks: list[ipaddress._BaseNetwork]) -> bool:
    if not scope_networks:
        return False
    return any(
        subnet.subnet_of(scope_network) or subnet == scope_network
        for scope_network in scope_networks
        if subnet.version == scope_network.version
    )


def _safe_ip(value: object) -> ipaddress._BaseAddress | None:
    try:
        return ipaddress.ip_address(str(value or "").strip())
    except ValueError:
        return None


def _safe_port(value: object) -> int | None:
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    if 0 < port <= 65535:
        return port
    return None


def _route_to_network(route: dict[str, Any]) -> ipaddress._BaseNetwork | None:
    for key in ("destination_cidr", "destination", "cidr", "network", "subnet", "prefix"):
        network = _network_from_value(route.get(key))
        if network is not None:
            return network
    destination = _safe_ip(route.get("destination_ip") or route.get("destination"))
    netmask = route.get("netmask") or route.get("mask")
    if destination is not None and netmask:
        try:
            return ipaddress.ip_network(f"{destination}/{netmask}", strict=False)
        except ValueError:
            return None
    return None


def _inventory_routes(inventory: dict[str, Any]) -> list[dict[str, Any]]:
    routes: list[dict[str, Any]] = []
    for key in ("routes", "routing_table", "routing_tables", "snmp_routes", "router_routes"):
        raw = inventory.get(key)
        if isinstance(raw, list):
            routes.extend(item for item in raw if isinstance(item, dict))
    network_devices = inventory.get("network_devices")
    if isinstance(network_devices, list):
        for device in network_devices:
            if not isinstance(device, dict):
                continue
            raw_routes = device.get("routes") or device.get("routing_table")
            if isinstance(raw_routes, list):
                for route in raw_routes:
                    if isinstance(route, dict):
                        routes.append({**route, "source_host": device.get("ip") or device.get("host")})
    return routes


def _inventory_hosts(inventory: dict[str, Any]) -> list[str]:
    hosts: list[str] = []
    for key in ("hosts", "devices", "services", "http_endpoints"):
        raw = inventory.get(key)
        if not isinstance(raw, list):
            continue
        for item in raw:
            if isinstance(item, str):
                hosts.append(item)
                continue
            if not isinstance(item, dict):
                continue
            for host_key in ("ip", "address", "host", "hostname"):
                value = str(item.get(host_key) or "").strip()
                if value:
                    hosts.append(value)
                    break
    return _normalized_string_list(hosts)


def _inventory_snmp_hosts(inventory: dict[str, Any], scope_networks: list[ipaddress._BaseNetwork]) -> list[str]:
    hosts: list[str] = []
    for service in inventory.get("services", []) if isinstance(inventory.get("services"), list) else []:
        if not isinstance(service, dict):
            continue
        port = _safe_port(service.get("port"))
        name = str(service.get("service") or service.get("name") or "").lower()
        if port == 161 or "snmp" in name:
            host = str(service.get("ip") or service.get("host") or service.get("address") or "").strip()
            if host and _host_in_scope(host, scope_networks):
                hosts.append(host)
    return _normalized_string_list(hosts)


def _subnets_from_arp(inventory: dict[str, Any]) -> list[dict[str, Any]]:
    discovered: list[dict[str, Any]] = []
    raw_tables: list[Any] = []
    for key in ("arp_table", "arp_tables", "nmap_arp_table", "neighbors"):
        raw = inventory.get(key)
        if isinstance(raw, list):
            raw_tables.extend(raw)
    for item in raw_tables:
        if isinstance(item, str):
            address = _safe_ip(item)
            source = "arp"
        elif isinstance(item, dict):
            address = _safe_ip(item.get("ip") or item.get("address") or item.get("neighbor"))
            source = str(item.get("source") or "arp").strip() or "arp"
        else:
            continue
        if address is None:
            continue
        if address.version == 4:
            network = ipaddress.ip_network(f"{address}/24", strict=False)
        else:
            network = ipaddress.ip_network(f"{address}/64", strict=False)
        discovered.append(
            {
                "subnet": str(network),
                "source": source,
                "evidence": f"ARP/neighbor hint {address}",
            }
        )
    return discovered


def _default_snmp_route_reader(host: str, timeout_seconds: float) -> list[dict[str, Any]]:
    snmpwalk = shutil.which(os.getenv("SNMPWALK_BINARY", "snmpwalk"))
    if not snmpwalk:
        return []
    command = [
        snmpwalk,
        "-v2c",
        "-c",
        "public",
        "-t",
        str(max(1, int(timeout_seconds))),
        "-r",
        "0",
        host,
        "IP-MIB::ipRouteDest",
    ]
    process = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=max(float(timeout_seconds), 1.0) + 1,
        check=False,
    )
    routes: list[dict[str, Any]] = []
    for line in (process.stdout or "").splitlines():
        parts = line.rsplit(" ", 1)
        address = _safe_ip(parts[-1] if parts else "")
        if address is None or address.is_unspecified:
            continue
        if address.version == 4:
            routes.append({"destination_cidr": f"{address}/24", "source_host": host, "source": "snmp-public"})
    return routes


def _default_reachability_checker(host: str, port: int | None, timeout_seconds: float) -> bool:
    if port is None:
        ping = shutil.which("ping")
        if not ping:
            return False
        try:
            process = subprocess.run(
                [ping, "-c", "1", "-W", str(max(1, int(timeout_seconds))), host],
                capture_output=True,
                text=True,
                timeout=max(float(timeout_seconds), 1.0) + 1,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return False
        return process.returncode == 0
    try:
        with socket.create_connection((host, port), timeout=max(float(timeout_seconds), 0.2)):
            return True
    except OSError:
        return False


def _default_vlan_probe(params: dict[str, Any]) -> dict[str, Any]:
    try:
        from scapy.all import Dot1Q, Ether, ICMP, IP, conf, sendp, sniff  # type: ignore
    except Exception as exc:  # pragma: no cover - depends on optional local package/capability
        return {
            "status": "capability_unavailable",
            "response_observed": False,
            "error": f"scapy unavailable: {exc}",
        }

    interface = str(params.get("interface") or conf.iface or "").strip()
    if not interface:
        return {
            "status": "capability_unavailable",
            "response_observed": False,
            "error": "no network interface available for VLAN probe",
        }
    native_vlan = int(params.get("native_vlan") or 1)
    target_vlan = int(params.get("target_vlan") or 2)
    target_ip = str(params.get("target_ip") or "224.0.0.1")
    probe_count = max(1, min(int(params.get("probe_count") or 1), 10))
    timeout_seconds = max(float(params.get("timeout_seconds") or 10), 1.0)
    frame = (
        Ether(dst="ff:ff:ff:ff:ff:ff")
        / Dot1Q(vlan=native_vlan)
        / Dot1Q(vlan=target_vlan)
        / IP(dst=target_ip)
        / ICMP()
    )
    try:
        sendp(frame, iface=interface, count=probe_count, inter=0.2, verbose=False)
        packets = sniff(iface=interface, timeout=timeout_seconds, count=1, store=True)
    except PermissionError as exc:
        return {
            "status": "capability_unavailable",
            "response_observed": False,
            "error": f"raw packet permission denied: {exc}",
        }
    except Exception as exc:  # pragma: no cover - hardware/driver dependent
        return {"status": "failed", "response_observed": False, "error": str(exc)}
    return {
        "status": "completed",
        "response_observed": bool(packets),
        "interface": interface,
        "native_vlan": native_vlan,
        "target_vlan": target_vlan,
        "probe_count": probe_count,
    }


def _representative_hosts(subnet: ipaddress._BaseNetwork, limit: int = 6) -> list[str]:
    if subnet.num_addresses <= 2:
        return [str(address) for address in subnet.hosts()]
    hosts: list[str] = []
    for address in subnet.hosts():
        hosts.append(str(address))
        if len(hosts) >= limit:
            break
    return hosts


def _dedupe_subnets(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    deduped: list[dict[str, Any]] = []
    for item in items:
        subnet = str(item.get("subnet") or "").strip()
        if not subnet or subnet in seen:
            continue
        seen.add(subnet)
        deduped.append(item)
    return deduped


def _finding(
    *,
    title: str,
    severity: str,
    target_id: str,
    summary: str,
    tags: list[str],
) -> dict[str, Any]:
    return {
        "title": title,
        "severity": severity,
        "target_id": target_id,
        "summary": summary,
        "methodology_tags": tags,
        "ptes_phase": "post-exploitation",
        "nist_phase": "analysis",
        "control_family": "network-segmentation",
    }


def execute_network_segmentation_assessment(
    targets: list[str],
    *,
    scope_allowlist: dict[str, Any] | None = None,
    inventory: dict[str, Any] | None = None,
    mode: str = "passive",
    timeout_seconds: float = 10.0,
    reachability_ports: list[int] | None = None,
    vlan_probe_count: int = 10,
    native_vlan: int = 1,
    target_vlan: int = 2,
    vlan_interface: str | None = None,
    vlan_target_ip: str | None = None,
    snmp_route_reader: SnmpRouteReader | None = None,
    reachability_checker: ReachabilityChecker | None = None,
    vlan_probe_func: VlanProbeFunc | None = None,
) -> RunnerExecution:
    normalized_targets = _normalized_string_list(targets)
    if not normalized_targets:
        raise ValueError("at least one target is required")

    started_at = time.time()
    scope = scope_allowlist or {}
    normalized_inventory = inventory if isinstance(inventory, dict) else {}
    scope_networks = _scope_networks(normalized_targets, scope)
    run_mode = str(mode or "passive").strip().lower()
    active_mode = run_mode == "active"
    ports = [
        int(port)
        for port in (reachability_ports or list(DEFAULT_REACHABILITY_PORTS))
        if isinstance(port, int) and 0 < port <= 65535
    ]
    snmp_reader = snmp_route_reader or _default_snmp_route_reader
    reachability = reachability_checker or _default_reachability_checker
    vlan_probe = vlan_probe_func or _default_vlan_probe

    subnet_records: list[dict[str, Any]] = []
    analysis_findings: list[dict[str, Any]] = []
    notes: list[str] = []

    for route in _inventory_routes(normalized_inventory):
        network = _route_to_network(route)
        if network is None or network.is_unspecified:
            continue
        if _subnet_in_scope(network, scope_networks):
            continue
        subnet_records.append(
            {
                "subnet": str(network),
                "source": str(route.get("source") or "inventory-route").strip() or "inventory-route",
                "source_host": route.get("source_host") or route.get("gateway") or route.get("host"),
                "evidence": route,
            }
        )

    subnet_records.extend(_subnets_from_arp(normalized_inventory))

    for host in _inventory_snmp_hosts(normalized_inventory, scope_networks):
        try:
            snmp_routes = snmp_reader(host, min(float(timeout_seconds), 5.0))
        except Exception as exc:
            notes.append(f"SNMP route read failed for {host}: {exc}")
            continue
        for route in snmp_routes:
            if not isinstance(route, dict):
                continue
            network = _route_to_network(route)
            if network is None or network.is_unspecified:
                continue
            if _subnet_in_scope(network, scope_networks):
                continue
            subnet_records.append(
                {
                    "subnet": str(network),
                    "source": str(route.get("source") or "snmp-public").strip() or "snmp-public",
                    "source_host": route.get("source_host") or host,
                    "evidence": route,
                }
            )

    discovered_subnets = _dedupe_subnets(subnet_records)
    for item in discovered_subnets:
        subnet = str(item["subnet"])
        analysis_findings.append(
            _finding(
                title=f"Additional network segment discovered: {subnet}",
                severity="info",
                target_id=subnet,
                summary=(
                    "A network segment outside the approved assessment CIDR was observed from "
                    f"{item.get('source') or 'inventory'} evidence."
                ),
                tags=["network-segmentation", "subnet-discovery", "PTES-POST"],
            )
        )

    lateral_checks: list[dict[str, Any]] = []
    for item in discovered_subnets:
        subnet_text = str(item["subnet"])
        try:
            subnet = ipaddress.ip_network(subnet_text, strict=False)
        except ValueError:
            continue
        for host in _representative_hosts(subnet, limit=6):
            ping_reachable = reachability(host, None, min(float(timeout_seconds), 2.0))
            check = {"host": host, "subnet": subnet_text, "port": None, "reachable": ping_reachable}
            lateral_checks.append(check)
            if ping_reachable:
                analysis_findings.append(
                    _finding(
                        title=f"Cross-segment access detected: {host} is reachable",
                        severity="medium",
                        target_id=host,
                        summary=(
                            f"Host {host} in discovered segment {subnet_text} responded to a "
                            "bounded reachability check from the assessment position."
                        ),
                        tags=["network-segmentation", "lateral-reachability", "PTES-POST"],
                    )
                )
                continue
            for port in ports:
                reachable = reachability(host, port, min(float(timeout_seconds), 2.0))
                lateral_checks.append(
                    {"host": host, "subnet": subnet_text, "port": port, "reachable": reachable}
                )
                if reachable:
                    analysis_findings.append(
                        _finding(
                            title=f"Cross-segment service reachable: {host}:{port}",
                            severity="medium",
                            target_id=f"{host}:{port}",
                            summary=(
                                f"Port {port} on host {host} in discovered segment {subnet_text} "
                                "was reachable from the assessment position."
                            ),
                            tags=["network-segmentation", "lateral-reachability", "PTES-POST"],
                        )
                    )
                    break

    vlan_result: dict[str, Any] = {
        "enabled": active_mode,
        "status": "not_requested" if not active_mode else "not_started",
        "response_observed": False,
    }
    exit_code = 0
    stderr = ""
    if active_mode:
        probe_params = {
            "targets": normalized_targets,
            "native_vlan": native_vlan,
            "target_vlan": target_vlan,
            "probe_count": max(1, min(int(vlan_probe_count), 10)),
            "interface": vlan_interface,
            "target_ip": vlan_target_ip or (normalized_targets[0] if normalized_targets else None),
            "timeout_seconds": min(float(timeout_seconds), 10.0),
        }
        vlan_result = {"enabled": True, **vlan_probe(probe_params)}
        if vlan_result.get("status") in {"capability_unavailable", "failed"}:
            exit_code = 2
            stderr = str(vlan_result.get("error") or vlan_result.get("status") or "VLAN probe failed")
        if bool(vlan_result.get("response_observed")):
            analysis_findings.append(
                _finding(
                    title="VLAN hopping via 802.1Q double-tagging is possible",
                    severity="critical",
                    target_id=f"vlan:{native_vlan}->{target_vlan}",
                    summary=(
                        "A bounded double-tagged 802.1Q probe observed a response, indicating "
                        "traffic may cross VLAN boundaries."
                    ),
                    tags=["network-segmentation", "vlan-hopping", "PTES-POST"],
                )
            )

    payload = {
        "runner": "network-segmentation",
        "runner_digest": NETWORK_SEGMENTATION_RUNNER_DIGEST,
        "mode": run_mode,
        "targets": normalized_targets,
        "scope_networks": [str(network) for network in scope_networks],
        "discovered_subnets": discovered_subnets,
        "lateral_reachability_checks": lateral_checks,
        "vlan_double_tag_probe": vlan_result,
        "analysis_findings": analysis_findings,
        "notes": notes,
        "elapsed_seconds": round(time.time() - started_at, 3),
    }
    artifact = EvidenceArtifact(
        name=NETWORK_SEGMENTATION_ARTIFACT_NAME,
        content_type="application/json",
        data=json.dumps(payload, indent=2, sort_keys=True).encode("utf-8"),
        kind="network-segmentation-results",
    )
    stdout = (
        f"network-segmentation {run_mode}: "
        f"{len(discovered_subnets)} additional subnets, "
        f"{sum(1 for item in lateral_checks if item.get('reachable'))} reachable checks, "
        f"{len(analysis_findings)} findings"
    )
    return RunnerExecution(
        tool="network-segmentation",
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        metadata={
            "status": "ok" if exit_code == 0 else "failed",
            "mode": run_mode,
            "subnet_count": len(discovered_subnets),
            "finding_count": len(analysis_findings),
            "vlan_probe_status": vlan_result.get("status"),
            "runner_digest": NETWORK_SEGMENTATION_RUNNER_DIGEST,
        },
        artifacts=[artifact],
    )
