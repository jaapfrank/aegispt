from __future__ import annotations

import ipaddress
import json
import time
from collections.abc import Callable, Iterable
from typing import Any

from workers.runners.base.contracts import EvidenceArtifact, RunnerExecution

SNMP_ENUM_RESULTS_ARTIFACT_NAME = "snmp-enum-results.json"
SNMP_ENUM_RUNNER_DIGEST = "workers.snmp_enum.runner:v1"
DEFAULT_SNMP_PORTS = (161,)
DEFAULT_COMMUNITIES = (
    "public",
    "private",
    "community",
    "manager",
    "admin",
    "snmpd",
    "cisco",
    "ubiquiti",
)
SYSTEM_OID = "1.3.6.1.2.1.1"
INTERFACES_OID = "1.3.6.1.2.1.2.2"
ARP_OID = "1.3.6.1.2.1.4.22"
ROUTES_OID = "1.3.6.1.2.1.4.21"

SnmpClient = Callable[[str, int, str, str, float], list[dict[str, Any]]]


def _normalized_string_list(values: Iterable[object] | None) -> list[str]:
    normalized: list[str] = []
    seen: set[str] = set()
    for value in values or []:
        candidate = str(value or "").strip()
        if candidate and candidate not in seen:
            seen.add(candidate)
            normalized.append(candidate)
    return normalized


def _coerce_port(value: object) -> int | None:
    try:
        port = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    if 1 <= port <= 65535:
        return port
    return None


def _normalized_ports(values: Iterable[object] | object | None) -> list[int]:
    raw_values: list[object] = []
    if values is None:
        raw_values = list(DEFAULT_SNMP_PORTS)
    elif isinstance(values, str):
        raw_values = [item.strip() for item in values.split(",")]
    elif isinstance(values, Iterable):
        for value in values:
            if isinstance(value, str) and "," in value:
                raw_values.extend(item.strip() for item in value.split(","))
            else:
                raw_values.append(value)
    else:
        raw_values = [values]

    normalized: list[int] = []
    seen: set[int] = set()
    for value in raw_values:
        port = _coerce_port(value)
        if port is None or port in seen:
            continue
        seen.add(port)
        normalized.append(port)
        if len(normalized) >= 32:
            break
    return normalized or list(DEFAULT_SNMP_PORTS)


def _scope_values(targets: list[str], scope_allowlist: dict[str, Any]) -> list[str]:
    values = list(targets)
    for key in ("hosts", "ip_addresses", "cidrs", "cidr_ranges", "targets"):
        raw = scope_allowlist.get(key)
        if isinstance(raw, list):
            values.extend(str(item) for item in raw)
    return _normalized_string_list(values)


def _scope_networks(values: Iterable[str]) -> list[ipaddress._BaseNetwork]:
    networks: list[ipaddress._BaseNetwork] = []
    for value in values:
        try:
            networks.append(ipaddress.ip_network(value, strict=False))
            continue
        except ValueError:
            pass
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            continue
        networks.append(ipaddress.ip_network(f"{address}/{address.max_prefixlen}", strict=False))
    return networks


def _host_in_scope(host: str, networks: list[ipaddress._BaseNetwork]) -> bool:
    if not networks:
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return True
    return any(address in network for network in networks)


def _expand_targets(values: Iterable[str], *, host_limit: int) -> list[str]:
    hosts: list[str] = []
    seen: set[str] = set()
    for value in values:
        candidate = str(value or "").strip()
        if not candidate:
            continue
        try:
            network = ipaddress.ip_network(candidate, strict=False)
        except ValueError:
            network = None
        if network is not None:
            for address in network.hosts():
                host = str(address)
                if host in seen:
                    continue
                seen.add(host)
                hosts.append(host)
                if len(hosts) >= host_limit:
                    return hosts
            continue
        host = candidate.removeprefix("snmp://").split("/", 1)[0].split(":", 1)[0]
        if host and host not in seen:
            seen.add(host)
            hosts.append(host)
            if len(hosts) >= host_limit:
                return hosts
    return hosts


def _inventory_snmp_targets(
    inventory: dict[str, Any] | None,
    *,
    configured_ports: list[int],
) -> list[tuple[str, int]]:
    targets: list[tuple[str, int]] = []
    seen: set[tuple[str, int]] = set()
    for service in (
        inventory.get("services", [])
        if isinstance(inventory, dict) and isinstance(inventory.get("services"), list)
        else []
    ):
        if not isinstance(service, dict):
            continue
        port = _coerce_port(service.get("port"))
        service_name = str(service.get("service") or "").lower()
        if port is None:
            continue
        if port not in configured_ports and "snmp" not in service_name:
            continue
        host = str(service.get("host") or "").strip()
        key = (host, port)
        if host and key not in seen:
            seen.add(key)
            targets.append(key)
    return targets


def _expand_target_ports(
    values: Iterable[str],
    *,
    ports: list[int],
    host_limit: int,
) -> list[tuple[str, int]]:
    return [(host, port) for host in _expand_targets(values, host_limit=host_limit) for port in ports]


def _bounded_targets(
    targets: Iterable[tuple[str, int]],
    *,
    scope_networks: list[ipaddress._BaseNetwork],
    host_limit: int,
) -> list[tuple[str, int]]:
    bounded: list[tuple[str, int]] = []
    seen_targets: set[tuple[str, int]] = set()
    seen_hosts: set[str] = set()
    for host, port in targets:
        if not host or port < 1 or port > 65535:
            continue
        if not _host_in_scope(host, scope_networks):
            continue
        if host not in seen_hosts and len(seen_hosts) >= host_limit:
            continue
        key = (host, port)
        if key in seen_targets:
            continue
        seen_hosts.add(host)
        seen_targets.add(key)
        bounded.append(key)
    return bounded


def _target_label(host: str, port: int) -> str:
    return f"{host}:{port}"


def _pysnmp_walk(
    host: str,
    port: int,
    community: str,
    oid: str,
    timeout_seconds: float,
) -> list[dict[str, Any]]:
    try:
        from pysnmp.hlapi import (  # type: ignore[import-not-found]
            CommunityData,
            ContextData,
            ObjectIdentity,
            ObjectType,
            SnmpEngine,
            UdpTransportTarget,
            nextCmd,
        )
    except ImportError as exc:  # pragma: no cover - exercised by live environments, not unit tests
        raise RuntimeError("pysnmp is not installed") from exc

    rows: list[dict[str, Any]] = []
    iterator = nextCmd(
        SnmpEngine(),
        CommunityData(community, mpModel=1),
        UdpTransportTarget((host, port), timeout=max(float(timeout_seconds), 0.1), retries=0),
        ContextData(),
        ObjectType(ObjectIdentity(oid)),
        lexicographicMode=False,
    )
    for error_indication, error_status, error_index, var_binds in iterator:
        if error_indication:
            raise RuntimeError(str(error_indication))
        if error_status:
            raise RuntimeError(
                f"{error_status.prettyPrint()} at {error_index and var_binds[int(error_index) - 1][0] or '?'}"
            )
        for var_bind in var_binds:
            rows.append({"oid": str(var_bind[0]), "value": str(var_bind[1])})
    return rows


def _snmp_walk(
    client: SnmpClient,
    *,
    host: str,
    port: int,
    community: str,
    oid: str,
    timeout_seconds: float,
) -> tuple[list[dict[str, Any]], str | None]:
    try:
        rows = client(host, port, community, oid, timeout_seconds)
    except Exception as exc:  # noqa: BLE001 - runner must preserve bounded evidence on client failure
        return [], str(exc)
    normalized = [
        {"oid": str(row.get("oid") or "").strip(), "value": row.get("value")}
        for row in rows
        if isinstance(row, dict) and str(row.get("oid") or "").strip()
    ]
    return normalized, None


def _suffix(oid: str, prefix: str) -> str:
    normalized = oid.strip()
    return normalized.removeprefix(prefix).lstrip(".")


def _parse_system(rows: list[dict[str, Any]]) -> dict[str, Any]:
    mapping = {
        "1.0": "sysDescr",
        "3.0": "sysUpTime",
        "4.0": "sysContact",
        "5.0": "sysName",
        "6.0": "sysLocation",
    }
    system: dict[str, Any] = {}
    for row in rows:
        key = mapping.get(_suffix(str(row.get("oid") or ""), SYSTEM_OID))
        if key:
            system[key] = row.get("value")
    return system


def _parse_interfaces(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    columns = {
        "1.3.6.1.2.1.2.2.1.2.": "description",
        "1.3.6.1.2.1.2.2.1.3.": "type",
        "1.3.6.1.2.1.2.2.1.6.": "mac",
        "1.3.6.1.2.1.2.2.1.8.": "oper_status",
    }
    by_index: dict[str, dict[str, Any]] = {}
    for row in rows:
        oid = str(row.get("oid") or "")
        for prefix, field in columns.items():
            if oid.startswith(prefix):
                index = oid.removeprefix(prefix)
                by_index.setdefault(index, {"index": index})[field] = row.get("value")
                break
    return [by_index[index] for index in sorted(by_index, key=lambda item: int(item) if item.isdigit() else item)]


def _parse_arp(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    mac_by_key: dict[str, Any] = {}
    ip_by_key: dict[str, Any] = {}
    for row in rows:
        oid = str(row.get("oid") or "")
        if oid.startswith("1.3.6.1.2.1.4.22.1.2."):
            mac_by_key[oid.removeprefix("1.3.6.1.2.1.4.22.1.2.")] = row.get("value")
        elif oid.startswith("1.3.6.1.2.1.4.22.1.3."):
            ip_by_key[oid.removeprefix("1.3.6.1.2.1.4.22.1.3.")] = row.get("value")
    entries: list[dict[str, Any]] = []
    for key in sorted(set(mac_by_key) | set(ip_by_key)):
        ip_value = str(ip_by_key.get(key) or ".".join(key.split(".")[1:]) or "").strip()
        entries.append({"ip": ip_value, "mac": mac_by_key.get(key), "source": "snmp-arp"})
    return entries


def _parse_routes(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    destinations: dict[str, str] = {}
    gateways: dict[str, Any] = {}
    masks: dict[str, Any] = {}
    for row in rows:
        oid = str(row.get("oid") or "")
        value = row.get("value")
        if oid.startswith("1.3.6.1.2.1.4.21.1.1."):
            destinations[oid.removeprefix("1.3.6.1.2.1.4.21.1.1.")] = str(value or "")
        elif oid.startswith("1.3.6.1.2.1.4.21.1.7."):
            gateways[oid.removeprefix("1.3.6.1.2.1.4.21.1.7.")] = value
        elif oid.startswith("1.3.6.1.2.1.4.21.1.11."):
            masks[oid.removeprefix("1.3.6.1.2.1.4.21.1.11.")] = value
    routes: list[dict[str, Any]] = []
    for key, destination in sorted(destinations.items()):
        route: dict[str, Any] = {
            "destination": destination,
            "gateway": gateways.get(key),
            "netmask": masks.get(key),
            "source": "snmp-route",
        }
        try:
            if masks.get(key):
                route["destination_cidr"] = str(
                    ipaddress.ip_network(f"{destination}/{masks[key]}", strict=False)
                )
        except ValueError:
            pass
        routes.append(route)
    return routes


def _finding_for_default_community(host: str, port: int, community: str) -> dict[str, Any]:
    target_label = _target_label(host, port)
    return {
        "title": "SNMP community string accepted",
        "severity": "medium",
        "target_id": host if port == 161 else target_label,
        "summary": (
            f"Read-only SNMP accepted the default community string '{community}' on {target_label}. "
            "Default SNMP communities can expose device identity, interfaces, ARP neighbors, "
            "and routing data."
        ),
        "methodology_tags": ["PTES-INTELLIGENCE_GATHERING", "snmp", "default-community"],
        "ptes_phase": "intelligence_gathering",
        "nist_phase": "discovery",
        "control_family": "network-device-hardening",
    }


def execute_snmp_enumeration(
    *,
    targets: list[str],
    scope_allowlist: dict[str, Any] | None = None,
    inventory: dict[str, Any] | None = None,
    communities: Iterable[object] | None = None,
    ports: Iterable[object] | object | None = None,
    timeout_seconds: float = 5.0,
    max_target_hosts: int = 256,
    snmp_client: SnmpClient | None = None,
) -> RunnerExecution:
    started_at = time.time()
    scope = scope_allowlist or {}
    community_list = [
        community
        for community in _normalized_string_list(communities or DEFAULT_COMMUNITIES)
        if community in DEFAULT_COMMUNITIES
    ] or list(DEFAULT_COMMUNITIES)
    port_list = _normalized_ports(ports)
    host_limit = max(1, min(int(max_target_hosts or 256), 1024))
    scope_values = _scope_values(targets, scope)
    scope_networks = _scope_networks(scope_values)
    candidate_targets = _bounded_targets(
        [
            *_inventory_snmp_targets(inventory, configured_ports=port_list),
            *_expand_target_ports(scope_values, ports=port_list, host_limit=host_limit),
        ],
        scope_networks=scope_networks,
        host_limit=host_limit,
    )
    client = snmp_client or _pysnmp_walk

    hosts: list[dict[str, Any]] = []
    services: list[dict[str, Any]] = []
    fingerprints: list[dict[str, Any]] = []
    arp_table: list[dict[str, Any]] = []
    routes: list[dict[str, Any]] = []
    interfaces: list[dict[str, Any]] = []
    analysis_findings: list[dict[str, Any]] = []
    notes: list[str] = []
    missing_dependency = False

    for host, port in candidate_targets:
        host_errors: list[str] = []
        accepted: list[str] = []
        community_system_rows: dict[str, list[dict[str, Any]]] = {}
        for community in community_list:
            rows, error = _snmp_walk(
                client,
                host=host,
                port=port,
                community=community,
                oid=SYSTEM_OID,
                timeout_seconds=timeout_seconds,
            )
            if error:
                if "pysnmp is not installed" in error:
                    missing_dependency = True
                host_errors.append(f"{community}: {error}")
                continue
            if rows:
                accepted.append(community)
                community_system_rows[community] = rows
                analysis_findings.append(_finding_for_default_community(host, port, community))

        selected_community = accepted[0] if accepted else None
        system_rows = community_system_rows.get(selected_community or "", [])
        interface_rows: list[dict[str, Any]] = []
        arp_rows: list[dict[str, Any]] = []
        route_rows: list[dict[str, Any]] = []
        if selected_community:
            for oid, bucket in (
                (INTERFACES_OID, "interfaces"),
                (ARP_OID, "arp"),
                (ROUTES_OID, "routes"),
            ):
                rows, error = _snmp_walk(
                    client,
                    host=host,
                    port=port,
                    community=selected_community,
                    oid=oid,
                    timeout_seconds=timeout_seconds,
                )
                if error:
                    host_errors.append(f"{oid}: {error}")
                    continue
                if bucket == "interfaces":
                    interface_rows = rows
                elif bucket == "arp":
                    arp_rows = rows
                else:
                    route_rows = rows

        parsed_system = _parse_system(system_rows)
        parsed_interfaces = _parse_interfaces(interface_rows)
        parsed_arp = _parse_arp(arp_rows)
        parsed_routes = _parse_routes(route_rows)
        for interface in parsed_interfaces:
            interfaces.append({"host": host, "source_port": port, **interface})
        for entry in parsed_arp:
            arp_table.append({"source_host": host, "source_port": port, **entry})
        for route in parsed_routes:
            routes.append({"source_host": host, "source_port": port, **route})
        if selected_community:
            services.append(
                {
                    "host": host,
                    "port": port,
                    "protocol": "udp",
                    "service": "snmp",
                    "product": parsed_system.get("sysDescr"),
                    "version": None,
                    "confidence": 0.88,
                }
            )
        if parsed_system:
            fingerprints.append(
                {
                    "vendor": None,
                    "product": parsed_system.get("sysDescr") or parsed_system.get("sysName"),
                    "version": None,
                    "confidence": 0.8,
                }
            )
        hosts.append(
            {
                "host": host,
                "port": port,
                "target": _target_label(host, port),
                "status": "ok" if accepted else "no-snmp-response",
                "accepted_communities": accepted,
                "system": parsed_system,
                "interfaces": parsed_interfaces,
                "arp_table": parsed_arp,
                "routes": parsed_routes,
                "errors": host_errors[:5],
            }
        )

    if missing_dependency:
        notes.append("pysnmp is not installed; SNMP enumeration could not execute in this environment.")
    if len(_expand_targets(scope_values, host_limit=host_limit + 1)) > host_limit:
        notes.append(f"Target expansion capped at {host_limit} hosts for bounded passive execution.")

    inventory_payload = {
        "hosts": _normalized_string_list(host["host"] for host in hosts),
        "services": services,
        "fingerprints": fingerprints,
        "network_interfaces": interfaces,
        "arp_table": arp_table,
        "routes": routes,
        "confidence": 0.78 if services else 0.45,
    }
    payload = {
        "runner": "snmp-enum",
        "runner_digest": SNMP_ENUM_RUNNER_DIGEST,
        "community_strings_tested": community_list,
        "ports_tested": port_list,
        "targets": [_target_label(host, port) for host, port in candidate_targets],
        "hosts": hosts,
        "inventory": inventory_payload,
        "analysis_findings": analysis_findings,
        "notes": notes,
        "elapsed_seconds": round(time.time() - started_at, 3),
    }
    artifact = EvidenceArtifact(
        name=SNMP_ENUM_RESULTS_ARTIFACT_NAME,
        content_type="application/json",
        data=json.dumps(payload, indent=2, sort_keys=True).encode("utf-8"),
        kind="snmp-enum-results",
    )
    stdout = (
        f"snmp-enum: {len(candidate_targets)} targets, "
        f"{sum(1 for host in hosts if host.get('accepted_communities'))} responding targets, "
        f"{len(analysis_findings)} findings"
    )
    responding_hosts = {
        str(host.get("host") or "")
        for host in hosts
        if host.get("accepted_communities") and str(host.get("host") or "")
    }
    return RunnerExecution(
        tool="snmp-enum",
        exit_code=0,
        stdout=stdout,
        stderr="",
        metadata={
            "status": "ok",
            "target_count": len(candidate_targets),
            "responding_host_count": len(responding_hosts),
            "responding_target_count": sum(
                1 for host in hosts if host.get("accepted_communities")
            ),
            "finding_count": len(analysis_findings),
            "runner_digest": SNMP_ENUM_RUNNER_DIGEST,
            "read_only": True,
        },
        artifacts=[artifact],
    )
