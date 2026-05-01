from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import json
import re
import subprocess
from typing import Any, Callable

from workers.runners.base.contracts import EvidenceArtifact, RunnerExecution
from workers.runners.nmap.runner import LAN_IOT_PORTS, execute_nmap_scan

IPV6_DISCOVERY_RESULTS_ARTIFACT_NAME = "ipv6-discovery-results.json"

_MAC_RE = re.compile(r"^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$", re.IGNORECASE)


@dataclass(slots=True, frozen=True)
class CommandResult:
    exit_code: int
    stdout: str = ""
    stderr: str = ""


CommandRunner = Callable[[list[str], float], CommandResult]
NmapExecutor = Callable[..., RunnerExecution]


def _default_command_runner(command: list[str], timeout_seconds: float) -> CommandResult:
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
            timeout=max(float(timeout_seconds), 1.0),
        )
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout or ""
        stderr = exc.stderr or ""
        if isinstance(stdout, bytes):
            stdout = stdout.decode("utf-8", errors="replace")
        if isinstance(stderr, bytes):
            stderr = stderr.decode("utf-8", errors="replace")
        return CommandResult(
            exit_code=124,
            stdout=stdout,
            stderr=f"{stderr}\ncommand timed out after {timeout_seconds:.1f}s".strip(),
        )
    return CommandResult(exit_code=result.returncode, stdout=result.stdout, stderr=result.stderr)


def classify_ipv6_address(address: str) -> str:
    try:
        parsed = ipaddress.IPv6Address(address.split("%", 1)[0])
    except ValueError:
        return "invalid"
    if parsed.is_loopback:
        return "loopback"
    if parsed.is_multicast:
        return "multicast"
    if parsed.is_link_local:
        return "link-local"
    if parsed.is_private:
        return "unique-local"
    if parsed.is_global:
        return "global"
    return "other"


def _normalize_mac(value: str | None) -> str | None:
    normalized = str(value or "").strip().lower()
    return normalized if _MAC_RE.match(normalized) else None


def parse_ip_neigh_output(output: str) -> list[dict[str, Any]]:
    neighbors: list[dict[str, Any]] = []
    seen: set[tuple[str, str | None]] = set()
    for raw_line in output.splitlines():
        parts = raw_line.strip().split()
        if not parts:
            continue
        address = parts[0]
        if classify_ipv6_address(address) in {"invalid", "loopback", "multicast"}:
            continue
        interface = parts[parts.index("dev") + 1] if "dev" in parts and parts.index("dev") + 1 < len(parts) else None
        mac = _normalize_mac(parts[parts.index("lladdr") + 1]) if "lladdr" in parts and parts.index("lladdr") + 1 < len(parts) else None
        state = parts[-1].lower() if parts else "unknown"
        if state in {"failed", "incomplete"}:
            continue
        key = (address.lower(), interface)
        if key in seen:
            continue
        seen.add(key)
        neighbors.append(
            {
                "address": address,
                "interface": interface,
                "mac": mac,
                "state": state,
                "router": "router" in {part.lower() for part in parts},
                "address_type": classify_ipv6_address(address),
                "confidence": 0.76,
            }
        )
    return neighbors


def parse_ip_route_output(output: str) -> list[dict[str, Any]]:
    prefixes: list[dict[str, Any]] = []
    seen: set[tuple[str, str | None]] = set()
    for raw_line in output.splitlines():
        parts = raw_line.strip().split()
        if not parts:
            continue
        destination = parts[0]
        if destination == "default":
            destination = parts[parts.index("via") + 1] if "via" in parts and parts.index("via") + 1 < len(parts) else destination
        if "/" not in destination:
            continue
        try:
            network = ipaddress.IPv6Network(destination, strict=False)
        except ValueError:
            continue
        interface = parts[parts.index("dev") + 1] if "dev" in parts and parts.index("dev") + 1 < len(parts) else None
        key = (str(network), interface)
        if key in seen:
            continue
        seen.add(key)
        prefixes.append(
            {
                "prefix": str(network),
                "interface": interface,
                "source": "route-table",
                "confidence": 0.7,
            }
        )
    return prefixes


def _inventory_ipv4_hosts(inventory: dict[str, Any] | None) -> set[str]:
    hosts: set[str] = set()
    if not isinstance(inventory, dict):
        return hosts
    for entry in inventory.get("hosts", []):
        value = entry.get("host") if isinstance(entry, dict) else entry
        try:
            parsed = ipaddress.ip_address(str(value or "").strip())
        except ValueError:
            continue
        if parsed.version == 4:
            hosts.add(str(parsed))
    return hosts


def _inventory_macs(inventory: dict[str, Any] | None) -> set[str]:
    macs: set[str] = set()
    if not isinstance(inventory, dict):
        return macs
    for key in ("network_interfaces", "arp_table"):
        for entry in inventory.get(key, []):
            if not isinstance(entry, dict):
                continue
            mac = _normalize_mac(str(entry.get("mac") or entry.get("mac_address") or ""))
            if mac:
                macs.add(mac)
    return macs


def _build_inventory(
    *,
    neighbors: list[dict[str, Any]],
    prefixes: list[dict[str, Any]],
    nmap_execution: RunnerExecution | None,
) -> dict[str, Any]:
    services: list[dict[str, Any]] = []
    for neighbor in neighbors:
        address = str(neighbor.get("address") or "").strip()
        if not address:
            continue
        services.append(
            {
                "host": address,
                "port": 0,
                "protocol": "ipv6",
                "service": "ipv6-neighbor",
                "confidence": 0.68,
            }
        )
    return {
        "hosts": [
            {
                "host": neighbor["address"],
                "source": "ipv6-discovery",
                "confidence": neighbor.get("confidence", 0.76),
                "notes": [f"ICMPv6 neighbor state: {neighbor.get('state', 'unknown')}"],
            }
            for neighbor in neighbors
        ],
        "ipv6_addresses": [
            {
                "address": neighbor["address"],
                "interface": neighbor.get("interface"),
                "mac": neighbor.get("mac"),
                "address_type": neighbor.get("address_type"),
                "router": bool(neighbor.get("router")),
                "reachable": bool(nmap_execution and nmap_execution.exit_code == 0),
                "source": "ipv6-discovery",
                "confidence": neighbor.get("confidence", 0.76),
            }
            for neighbor in neighbors
        ],
        "ipv6_prefixes": prefixes,
        "services": services,
        "confidence": 0.74,
    }


def _build_findings(
    *,
    neighbors: list[dict[str, Any]],
    inventory: dict[str, Any] | None,
    nmap_execution: RunnerExecution | None,
) -> list[dict[str, Any]]:
    if not nmap_execution or nmap_execution.exit_code != 0:
        return []
    known_ipv4_hosts = _inventory_ipv4_hosts(inventory)
    known_macs = _inventory_macs(inventory)
    findings: list[dict[str, Any]] = []
    for neighbor in neighbors:
        address = str(neighbor.get("address") or "").strip()
        if not address:
            continue
        mac = _normalize_mac(str(neighbor.get("mac") or ""))
        if mac and mac in known_macs:
            continue
        if known_ipv4_hosts and neighbor.get("address_type") in {"link-local", "global", "unique-local"}:
            findings.append(
                {
                    "title": "IPv6 reachable host lacks matching IPv4 inventory evidence",
                    "severity": "info",
                    "target": address,
                    "summary": (
                        "A host responded over IPv6 and was accepted for bounded nmap -6 scanning, "
                        "but the current inventory did not contain matching IPv4 evidence for the same device. "
                        "Review firewall and management-plane policy parity."
                    ),
                    "evidence": {"ipv6_address": address, "mac": mac},
                }
            )
    return findings


def execute_ipv6_discovery(
    targets: list[str],
    *,
    scope_allowlist: dict[str, Any] | None = None,
    inventory: dict[str, Any] | None = None,
    interface: str | None = None,
    timeout_seconds: float = 6.0,
    max_discovered_hosts: int = 128,
    run_nmap: bool = True,
    ports: list[str] | tuple[str, ...] | str | None = LAN_IOT_PORTS,
    ip_binary: str = "ip",
    ping_binary: str = "ping",
    nmap_binary: str = "nmap",
    command_runner: CommandRunner | None = None,
    nmap_executor: NmapExecutor | None = None,
) -> RunnerExecution:
    runner = command_runner or _default_command_runner
    executed_commands: list[list[str]] = []
    probe_results: dict[str, dict[str, Any]] = {}

    if interface:
        for name, destination in (
            ("neighbor_solicitation", f"ff02::1%{interface}"),
            ("router_solicitation", f"ff02::2%{interface}"),
        ):
            command = [ping_binary, "-6", "-c", "1", "-W", str(max(1, int(timeout_seconds))), destination]
            executed_commands.append(command)
            result = runner(command, timeout_seconds)
            probe_results[name] = {
                "status": "completed" if result.exit_code == 0 else "no-response",
                "exit_code": result.exit_code,
                "stderr": result.stderr,
            }
    else:
        probe_results["neighbor_solicitation"] = {
            "status": "skipped",
            "reason": "No interface was explicitly authorized for local-segment multicast.",
        }
        probe_results["router_solicitation"] = {
            "status": "skipped",
            "reason": "No interface was explicitly authorized for local-segment multicast.",
        }

    neigh_command = [ip_binary, "-6", "neigh", "show"]
    route_command = [ip_binary, "-6", "route", "show"]
    executed_commands.extend([neigh_command, route_command])
    neigh_result = runner(neigh_command, timeout_seconds)
    route_result = runner(route_command, timeout_seconds)
    neighbors = parse_ip_neigh_output(neigh_result.stdout)[: max(1, int(max_discovered_hosts))]
    prefixes = parse_ip_route_output(route_result.stdout)
    nmap_targets = [neighbor["address"] for neighbor in neighbors if neighbor.get("address")]

    nmap_execution: RunnerExecution | None = None
    if run_nmap and nmap_targets:
        executor = nmap_executor or execute_nmap_scan
        nmap_execution = executor(
            nmap_targets,
            binary=nmap_binary,
            discovery_only=False,
            service_detection=True,
            skip_discovery=True,
            ports=ports,
            ipv6=True,
            timeout_seconds=timeout_seconds,
        )

    payload = {
        "targets": targets,
        "scope_allowlist": scope_allowlist or {},
        "interface": interface,
        "commands": [" ".join(command) for command in executed_commands],
        "neighbor_solicitation": probe_results["neighbor_solicitation"],
        "router_solicitation": probe_results["router_solicitation"],
        "neighbors": neighbors,
        "routers": [neighbor for neighbor in neighbors if neighbor.get("router")],
        "prefixes": prefixes,
        "nmap_ipv6": {
            "status": (
                "skipped"
                if not nmap_targets
                else "completed"
                if nmap_execution and nmap_execution.exit_code == 0
                else "failed"
            ),
            "targets": nmap_targets,
            "exit_code": nmap_execution.exit_code if nmap_execution else None,
        },
    }
    payload["inventory"] = _build_inventory(
        neighbors=neighbors,
        prefixes=prefixes,
        nmap_execution=nmap_execution,
    )
    payload["analysis_findings"] = _build_findings(
        neighbors=neighbors,
        inventory=inventory,
        nmap_execution=nmap_execution,
    )

    artifact_data = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
    stdout_lines = [
        f"IPv6 discovery observed {len(neighbors)} neighbor addresses.",
        f"IPv6 route table yielded {len(prefixes)} prefixes.",
    ]
    if nmap_targets:
        stdout_lines.append(f"Bounded nmap -6 targets: {', '.join(nmap_targets[:8])}")
    return RunnerExecution(
        tool="ipv6-discovery",
        exit_code=0 if neigh_result.exit_code in {0, 1} and route_result.exit_code in {0, 1} else 1,
        stdout="\n".join(stdout_lines),
        stderr="\n".join(filter(None, [neigh_result.stderr, route_result.stderr])),
        metadata={
            "status": "ok",
            "neighbor_count": len(neighbors),
            "prefix_count": len(prefixes),
            "nmap_target_count": len(nmap_targets),
            "multicast_probe_authorized": bool(interface),
            "runner_digest": "workers.ipv6_discovery.runner:v1",
        },
        artifacts=[
            EvidenceArtifact(
                name=IPV6_DISCOVERY_RESULTS_ARTIFACT_NAME,
                content_type="application/json",
                data=artifact_data,
                kind="network-discovery-results",
            )
        ],
    )
