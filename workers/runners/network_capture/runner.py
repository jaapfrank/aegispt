from __future__ import annotations

import base64
import ipaddress
import json
import re
import signal
import shutil
import subprocess
import time
from collections import defaultdict
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any

from workers.runners.base.contracts import EvidenceArtifact, RunnerExecution

NETWORK_CAPTURE_RESULTS_ARTIFACT_NAME = "network-capture-results.json"
NETWORK_CAPTURE_RUNNER_DIGEST = "workers.network_capture.runner:v1"

DEFAULT_CAPTURE_SECONDS = 60
MAX_CAPTURE_SECONDS = 120
DEFAULT_PACKET_LIMIT = 10000
MAX_PACKET_LIMIT = 10000
MAX_ARP_PROBE_COUNT = 3
MAX_ARP_SPOOF_SECONDS = 30

_MAC_RE = re.compile(r"^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$", re.IGNORECASE)
_TCPDUMP_FLOW_RE = re.compile(r"\bIP6?\s+([^\s]+)\s+>\s+([^:\s]+)")
_HTTP_BASIC_RE = re.compile(r"authorization:\s*basic\s+([A-Za-z0-9+/=]+)", re.IGNORECASE)
_BEARER_RE = re.compile(r"authorization:\s*bearer\s+([^\s;]+)", re.IGNORECASE)
_API_KEY_RE = re.compile(r"\b(x-api-key|api-key|token):\s*([^\s;]+)", re.IGNORECASE)
_QUERY_SECRET_RE = re.compile(
    r"\b(password|passwd|pwd|token|access_token|api_key|apikey)=([^&\s]+)",
    re.IGNORECASE,
)
_FTP_USER_RE = re.compile(r"^\s*USER\s+(.+?)\s*$", re.IGNORECASE)
_FTP_PASS_RE = re.compile(r"^\s*PASS\s+(.+?)\s*$", re.IGNORECASE)
_TELNET_PASSWORD_RE = re.compile(r"\b(password|login):\s*([^\s]+)", re.IGNORECASE)
_ARP_REPLY_RE = re.compile(
    r"(?:from|reply from)\s+(?P<ip>(?:\d{1,3}\.){3}\d{1,3})\s+\[(?P<mac>[0-9a-f:.-]{11,17})\]",
    re.IGNORECASE,
)


@dataclass(slots=True, frozen=True)
class CommandResult:
    exit_code: int
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False


CommandRunner = Callable[[list[str], float], CommandResult]
ArpSpoofExecutor = Callable[[list[str], int], dict[str, Any]]


def _default_command_runner(command: list[str], timeout_seconds: float) -> CommandResult:
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
            timeout=max(float(timeout_seconds), 1.0),
        )
    except OSError as exc:
        return CommandResult(exit_code=127, stdout="", stderr=str(exc))
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
            timed_out=True,
        )
    return CommandResult(exit_code=result.returncode, stdout=result.stdout, stderr=result.stderr)


def _default_arpspoof_executor(command: list[str], duration_seconds: int) -> dict[str, Any]:
    started = time.time()
    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except OSError as exc:
        return {
            "exit_code": 127,
            "stdout": "",
            "stderr": str(exc),
            "duration_seconds": 0,
            "restoration_signal_sent": False,
        }
    time.sleep(max(1, int(duration_seconds)))
    restoration_signal_sent = False
    if process.poll() is None:
        process.send_signal(signal.SIGINT)
        restoration_signal_sent = True
        try:
            stdout, stderr = process.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            process.terminate()
            try:
                stdout, stderr = process.communicate(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                stdout, stderr = process.communicate(timeout=2)
    else:
        stdout, stderr = process.communicate(timeout=1)
    return {
        "exit_code": process.returncode,
        "stdout": (stdout or "")[:2000],
        "stderr": (stderr or "")[:2000],
        "duration_seconds": round(time.time() - started, 3),
        "restoration_signal_sent": restoration_signal_sent,
    }


def _bounded_int(value: object, *, default: int, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return max(minimum, min(parsed, maximum))


def _normalized_string_list(values: Iterable[object] | None) -> list[str]:
    normalized: list[str] = []
    seen: set[str] = set()
    for value in values or []:
        item = str(value or "").strip()
        if item and item not in seen:
            seen.add(item)
            normalized.append(item)
    return normalized


def _scope_values(targets: list[str], scope_allowlist: dict[str, Any]) -> list[str]:
    values = list(targets)
    for key in ("cidrs", "cidr_ranges", "hosts", "ip_addresses", "targets"):
        raw = scope_allowlist.get(key)
        if isinstance(raw, list):
            values.extend(str(item) for item in raw)
    return _normalized_string_list(values)


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
        address = ipaddress.ip_address(str(host or "").strip())
    except ValueError:
        return True
    return any(address.version == network.version and address in network for network in networks)


def _normalize_mac(value: object) -> str | None:
    candidate = str(value or "").strip().lower().replace("-", ":").replace(".", "")
    if "." in str(value or "") and len(candidate) == 12:
        candidate = ":".join(candidate[index : index + 2] for index in range(0, 12, 2))
    if re.fullmatch(r"[0-9a-f]{12}", candidate):
        candidate = ":".join(candidate[index : index + 2] for index in range(0, 12, 2))
    return candidate if _MAC_RE.match(candidate) else None


def _safe_ip(value: object) -> str | None:
    try:
        return str(ipaddress.ip_address(str(value or "").strip()))
    except ValueError:
        return None


def _mask_value(value: str | None) -> str | None:
    if not value:
        return None
    if len(value) <= 2:
        return "*" * len(value)
    if len(value) <= 6:
        return f"{value[0]}***"
    return f"{value[0]}***{value[-1]}"


def _tcpdump_endpoint_host(endpoint: str) -> tuple[str | None, int | None]:
    value = endpoint.strip().rstrip(":")
    if not value:
        return None, None
    if "." in value:
        parts = value.split(".")
        if len(parts) > 4:
            host_candidate = ".".join(parts[:4])
            port_candidate = parts[4]
            host = _safe_ip(host_candidate)
            try:
                port = int(port_candidate)
            except ValueError:
                port = None
            return host, port
        return _safe_ip(value), None
    if value.count(":") >= 2:
        return value.rsplit(".", 1)[0] if "." in value else value, None
    return value, None


def _scope_filter_tokens(targets: list[str], scope_allowlist: dict[str, Any]) -> list[str]:
    filters: list[list[str]] = []
    seen: set[str] = set()
    for value in _scope_values(targets, scope_allowlist):
        network = _network_from_value(value)
        if network is None:
            continue
        if network.prefixlen == network.max_prefixlen:
            token = f"host {network.network_address}"
            fragment = ["host", str(network.network_address)]
        else:
            token = f"net {network}"
            fragment = ["net", str(network)]
        if token in seen:
            continue
        seen.add(token)
        filters.append(fragment)
    if not filters:
        return []
    tokens: list[str] = []
    for index, fragment in enumerate(filters):
        if index:
            tokens.append("or")
        tokens.extend(["(", *fragment, ")"])
    return tokens


def build_tcpdump_command(
    *,
    binary: str,
    interface: str,
    packet_limit: int,
    filter_tokens: list[str] | None = None,
) -> list[str]:
    command = [
        binary,
        "-i",
        interface,
        "-nn",
        "-s",
        "0",
        "-A",
        "-l",
        "-c",
        str(packet_limit),
    ]
    command.extend(filter_tokens or [])
    return command


def build_arping_command(
    *,
    binary: str,
    interface: str,
    target: str,
    probe_count: int,
) -> list[str]:
    return [binary, "-c", str(probe_count), "-I", interface, target]


def build_arpspoof_command(
    *,
    binary: str,
    interface: str,
    target: str,
    gateway: str,
) -> list[str]:
    return [binary, "-i", interface, "-t", target, gateway]


def _credential_signal(
    *,
    protocol: str,
    credential_type: str,
    target_id: str,
    detail: str,
    username_hint: str | None = None,
) -> dict[str, Any]:
    return {
        "protocol": protocol,
        "credential_type": credential_type,
        "target_id": target_id,
        "detail": detail,
        "username_hint": username_hint,
        "secret_redacted": True,
    }


def _detect_cleartext_signals(packet_text: str, default_target: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    signals: list[dict[str, Any]] = []
    cleartext_protocols: list[dict[str, Any]] = []
    seen_protocols: set[tuple[str, str]] = set()
    current_dst = default_target
    current_dst_port: int | None = None
    ftp_user_hint: str | None = None

    def add_protocol(protocol: str, target: str, port: int | None = None) -> None:
        key = (protocol, target)
        if key in seen_protocols:
            return
        seen_protocols.add(key)
        cleartext_protocols.append(
            {
                "protocol": protocol,
                "target_id": target,
                "port": port,
                "encrypted": False,
            }
        )

    for raw_line in packet_text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        flow_match = _TCPDUMP_FLOW_RE.search(line)
        if flow_match:
            dst, dst_port = _tcpdump_endpoint_host(flow_match.group(2))
            if dst:
                current_dst = dst
            current_dst_port = dst_port
            if dst_port == 80:
                add_protocol("http", current_dst, dst_port)
            elif dst_port == 21:
                add_protocol("ftp", current_dst, dst_port)
            elif dst_port == 23:
                add_protocol("telnet", current_dst, dst_port)
            elif dst_port == 25:
                add_protocol("smtp", current_dst, dst_port)
            continue

        lowered = line.lower()
        if "http/" in lowered or lowered.startswith(("get ", "post ", "put ", "head ")):
            add_protocol("http", current_dst, current_dst_port or 80)
        if lowered.startswith("user ") or lowered.startswith("pass "):
            add_protocol("ftp", current_dst, current_dst_port or 21)
        if "telnet" in lowered or "login:" in lowered:
            add_protocol("telnet", current_dst, current_dst_port or 23)
        if "smtp" in lowered or lowered.startswith("auth "):
            add_protocol("smtp", current_dst, current_dst_port or 25)

        basic_match = _HTTP_BASIC_RE.search(line)
        if basic_match:
            username_hint = None
            try:
                decoded = base64.b64decode(basic_match.group(1), validate=True).decode(
                    "utf-8",
                    errors="replace",
                )
            except Exception:
                decoded = ""
            if ":" in decoded:
                username_hint = _mask_value(decoded.split(":", 1)[0])
            signals.append(
                _credential_signal(
                    protocol="http",
                    credential_type="basic-auth",
                    target_id=current_dst,
                    detail="HTTP Basic Authorization header observed over cleartext traffic.",
                    username_hint=username_hint,
                )
            )
            continue

        bearer_match = _BEARER_RE.search(line)
        if bearer_match:
            signals.append(
                _credential_signal(
                    protocol="http",
                    credential_type="bearer-token",
                    target_id=current_dst,
                    detail="Bearer token observed over cleartext traffic.",
                )
            )
            continue

        api_key_match = _API_KEY_RE.search(line)
        if api_key_match:
            signals.append(
                _credential_signal(
                    protocol="http",
                    credential_type=api_key_match.group(1).lower(),
                    target_id=current_dst,
                    detail="Token-like HTTP header observed over cleartext traffic.",
                )
            )
            continue

        user_match = _FTP_USER_RE.match(line)
        if user_match:
            ftp_user_hint = _mask_value(user_match.group(1).strip())
            continue
        if _FTP_PASS_RE.match(line):
            signals.append(
                _credential_signal(
                    protocol="ftp",
                    credential_type="ftp-password",
                    target_id=current_dst,
                    detail="FTP USER/PASS credential exchange observed over cleartext traffic.",
                    username_hint=ftp_user_hint,
                )
            )
            continue

        query_match = _QUERY_SECRET_RE.search(line)
        if query_match:
            signals.append(
                _credential_signal(
                    protocol="http",
                    credential_type=query_match.group(1).lower(),
                    target_id=current_dst,
                    detail="Credential or token parameter observed in cleartext HTTP traffic.",
                )
            )
            continue

        if "password:" in lowered or "login:" in lowered:
            telnet_match = _TELNET_PASSWORD_RE.search(line)
            if telnet_match:
                signals.append(
                    _credential_signal(
                        protocol="telnet",
                        credential_type=telnet_match.group(1).lower(),
                        target_id=current_dst,
                        detail="Interactive login prompt with credential material observed in cleartext traffic.",
                    )
                )

    deduped_signals: list[dict[str, Any]] = []
    seen_signals: set[tuple[str, str, str]] = set()
    for signal in signals:
        key = (
            str(signal.get("protocol") or ""),
            str(signal.get("credential_type") or ""),
            str(signal.get("target_id") or ""),
        )
        if key in seen_signals:
            continue
        seen_signals.add(key)
        deduped_signals.append(signal)
    return deduped_signals, cleartext_protocols


def _arp_entries_from_inventory(inventory: dict[str, Any]) -> list[dict[str, Any]]:
    raw_entries: list[Any] = []
    for key in ("arp_table", "arp_tables", "neighbors", "nmap_arp_table"):
        value = inventory.get(key)
        if isinstance(value, list):
            raw_entries.extend(value)
    entries: list[dict[str, Any]] = []
    for item in raw_entries:
        if not isinstance(item, dict):
            continue
        ip = _safe_ip(item.get("ip") or item.get("address") or item.get("neighbor"))
        mac = _normalize_mac(item.get("mac") or item.get("mac_address") or item.get("lladdr"))
        if not ip or not mac:
            continue
        entries.append(
            {
                "ip": ip,
                "mac": mac,
                "interface": item.get("interface") or item.get("dev"),
                "source": str(item.get("source") or "inventory-arp").strip() or "inventory-arp",
            }
        )
    return entries


def parse_ip_neigh_output(output: str) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for line in output.splitlines():
        parts = line.strip().split()
        if not parts:
            continue
        ip = _safe_ip(parts[0])
        if not ip or "lladdr" not in parts:
            continue
        index = parts.index("lladdr")
        if index + 1 >= len(parts):
            continue
        mac = _normalize_mac(parts[index + 1])
        if not mac:
            continue
        interface = parts[parts.index("dev") + 1] if "dev" in parts and parts.index("dev") + 1 < len(parts) else None
        state = parts[-1].lower() if parts else "unknown"
        if state in {"failed", "incomplete"}:
            continue
        entries.append(
            {
                "ip": ip,
                "mac": mac,
                "interface": interface,
                "state": state,
                "source": "ip-neigh",
            }
        )
    return entries


def parse_arp_probe_output(output: str, *, interface: str | None = None) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for match in _ARP_REPLY_RE.finditer(output):
        ip = _safe_ip(match.group("ip"))
        mac = _normalize_mac(match.group("mac"))
        if ip and mac:
            entries.append(
                {
                    "ip": ip,
                    "mac": mac,
                    "interface": interface,
                    "source": "arp-probe",
                }
            )
    return entries


def _dedupe_arp_entries(
    entries: list[dict[str, Any]],
    *,
    scope_networks: list[ipaddress._BaseNetwork],
) -> list[dict[str, Any]]:
    deduped: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for entry in entries:
        ip = _safe_ip(entry.get("ip"))
        mac = _normalize_mac(entry.get("mac"))
        if not ip or not mac or not _host_in_scope(ip, scope_networks):
            continue
        key = (ip, mac, str(entry.get("source") or ""))
        if key in seen:
            continue
        seen.add(key)
        deduped.append({**entry, "ip": ip, "mac": mac})
    return deduped


def _build_network_capture_findings(
    *,
    credential_signals: list[dict[str, Any]],
    arp_anomalies: list[dict[str, Any]],
    default_target: str,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for signal in credential_signals:
        protocol = str(signal.get("protocol") or "traffic").upper()
        credential_type = str(signal.get("credential_type") or "credential")
        if credential_type == "basic-auth":
            title = "Cleartext Credentials Captured in Network Traffic (HTTP Basic Auth)"
        elif "token" in credential_type or "key" in credential_type:
            title = "Cleartext Token Captured in Network Traffic"
        else:
            title = f"Cleartext Credentials Captured in Network Traffic ({protocol})"
        target_id = str(signal.get("target_id") or default_target).strip() or default_target
        findings.append(
            {
                "title": title,
                "severity": "high",
                "target_id": target_id,
                "summary": (
                    f"Bounded passive capture observed {signal.get('detail') or 'cleartext credential material'}. "
                    "Captured secret values were redacted from stored evidence."
                ),
                "methodology_tags": [
                    "network-capture",
                    "cleartext-credentials",
                    "traffic-sniffing",
                    "PTES-POST",
                    "OWASP-A02",
                ],
                "ptes_phase": "post-exploitation",
                "nist_phase": "analysis",
                "control_family": "network-traffic-capture",
            }
        )

    if arp_anomalies:
        target_id = str(arp_anomalies[0].get("target_id") or default_target).strip() or default_target
        anomaly_types = ", ".join(
            dict.fromkeys(str(item.get("type") or "arp-anomaly") for item in arp_anomalies)
        )
        findings.append(
            {
                "title": "ARP Poisoning Possible - No ARP Inspection Detected",
                "severity": "medium",
                "target_id": target_id,
                "summary": (
                    "ARP consistency checks observed MAC/IP inconsistency "
                    f"({anomaly_types}). This can indicate ARP poisoning exposure, proxy ARP, or missing Dynamic ARP Inspection enforcement."
                ),
                "methodology_tags": [
                    "network-capture",
                    "arp-poisoning-detection",
                    "dynamic-arp-inspection",
                    "PTES-POST",
                ],
                "ptes_phase": "post-exploitation",
                "nist_phase": "analysis",
                "control_family": "network-traffic-capture",
            }
        )
    return findings


def _arp_anomalies(
    entries: list[dict[str, Any]],
    *,
    gateway_ip: str | None,
    expected_gateway_mac: str | None,
    default_target: str,
) -> list[dict[str, Any]]:
    anomalies: list[dict[str, Any]] = []
    ips_by_mac: dict[str, set[str]] = defaultdict(set)
    macs_by_ip: dict[str, set[str]] = defaultdict(set)
    for entry in entries:
        ip = str(entry.get("ip") or "")
        mac = str(entry.get("mac") or "")
        if ip and mac:
            ips_by_mac[mac].add(ip)
            macs_by_ip[ip].add(mac)

    for mac, ips in sorted(ips_by_mac.items()):
        if len(ips) > 1:
            anomalies.append(
                {
                    "type": "duplicate_mac_multiple_ips",
                    "mac": mac,
                    "ips": sorted(ips),
                    "target_id": sorted(ips)[0],
                }
            )
    for ip, macs in sorted(macs_by_ip.items()):
        if len(macs) > 1:
            anomalies.append(
                {
                    "type": "multiple_macs_single_ip",
                    "ip": ip,
                    "macs": sorted(macs),
                    "target_id": ip,
                }
            )

    normalized_gateway_ip = _safe_ip(gateway_ip)
    normalized_expected_mac = _normalize_mac(expected_gateway_mac)
    if normalized_gateway_ip and normalized_expected_mac:
        observed = sorted(macs_by_ip.get(normalized_gateway_ip, set()))
        if observed and normalized_expected_mac not in observed:
            anomalies.append(
                {
                    "type": "gateway_mac_mismatch",
                    "gateway_ip": normalized_gateway_ip,
                    "expected_mac": normalized_expected_mac,
                    "observed_macs": observed,
                    "target_id": normalized_gateway_ip,
                }
            )
    if not anomalies and entries and not normalized_gateway_ip:
        return []
    return anomalies


def _build_inventory(
    *,
    arp_entries: list[dict[str, Any]],
    cleartext_protocols: list[dict[str, Any]],
) -> dict[str, Any]:
    hosts = sorted({str(entry.get("ip")) for entry in arp_entries if entry.get("ip")})
    services: list[dict[str, Any]] = []
    seen_services: set[tuple[str, str, int | None]] = set()
    for protocol in cleartext_protocols:
        host = str(protocol.get("target_id") or "").strip()
        name = str(protocol.get("protocol") or "").strip()
        port = protocol.get("port") if isinstance(protocol.get("port"), int) else None
        if not host or not name:
            continue
        key = (host, name, port)
        if key in seen_services:
            continue
        seen_services.add(key)
        services.append(
            {
                "host": host,
                "port": port or 0,
                "protocol": "tcp",
                "service": name,
                "encrypted": False,
                "source": "network-capture",
                "confidence": 0.66,
            }
        )
    return {
        "hosts": hosts,
        "services": services,
        "arp_table": arp_entries,
        "confidence": 0.68 if arp_entries or services else 0.45,
    }


def execute_network_capture_assessment(
    targets: list[str],
    *,
    scope_allowlist: dict[str, Any] | None = None,
    inventory: dict[str, Any] | None = None,
    mode: str = "passive",
    interface: str | None = None,
    capture_seconds: int = DEFAULT_CAPTURE_SECONDS,
    packet_limit: int = DEFAULT_PACKET_LIMIT,
    tcpdump_binary: str = "tcpdump",
    ip_binary: str = "ip",
    arping_binary: str = "arping",
    command_runner: CommandRunner | None = None,
    packet_text: str | None = None,
    ip_neigh_text: str | None = None,
    arp_probe_text: str | None = None,
    arp_table: list[dict[str, Any]] | None = None,
    arp_probe_enabled: bool = True,
    arp_probe_count: int = 1,
    gateway_ip: str | None = None,
    expected_gateway_mac: str | None = None,
    arp_spoof_proof_requested: bool = False,
    allow_arp_spoof_proof: bool = False,
    intrusive_authorized: bool = False,
    arp_spoof_duration_seconds: int = 10,
    arp_spoof_target: str | None = None,
    arpspoof_binary: str = "arpspoof",
    arpspoof_executor: ArpSpoofExecutor | None = None,
) -> RunnerExecution:
    normalized_targets = _normalized_string_list(targets)
    scope = scope_allowlist or {}
    normalized_inventory = inventory if isinstance(inventory, dict) else {}
    scope_networks = _scope_networks(normalized_targets, scope)
    run_mode = str(mode or "passive").strip().lower() or "passive"
    effective_capture_seconds = _bounded_int(
        capture_seconds,
        default=DEFAULT_CAPTURE_SECONDS,
        minimum=1,
        maximum=MAX_CAPTURE_SECONDS,
    )
    effective_packet_limit = _bounded_int(
        packet_limit,
        default=DEFAULT_PACKET_LIMIT,
        minimum=1,
        maximum=MAX_PACKET_LIMIT,
    )
    effective_arp_probe_count = _bounded_int(
        arp_probe_count,
        default=1,
        minimum=1,
        maximum=MAX_ARP_PROBE_COUNT,
    )
    runner = command_runner or _default_command_runner
    spoof_executor = arpspoof_executor or _default_arpspoof_executor
    default_target = normalized_targets[0] if normalized_targets else "approved-local-network"
    notes: list[str] = []
    commands: list[str] = []
    capture_status = "fixture"
    capture_exit_code = 0
    capture_stderr = ""
    started_at = time.time()

    captured_text = packet_text or ""
    filter_tokens = _scope_filter_tokens(normalized_targets, scope)
    normalized_interface = str(interface or "").strip() or None
    if not captured_text:
        tcpdump_path = shutil.which(tcpdump_binary) or tcpdump_binary
        if not normalized_interface:
            capture_status = "skipped_no_interface"
            notes.append("Passive tcpdump capture skipped because no approved interface was configured.")
        elif not filter_tokens:
            capture_status = "skipped_no_scope_filter"
            notes.append("Passive tcpdump capture skipped because no approved host/CIDR scope filter was available.")
        else:
            command = build_tcpdump_command(
                binary=tcpdump_path,
                interface=normalized_interface,
                packet_limit=effective_packet_limit,
                filter_tokens=filter_tokens,
            )
            commands.append(" ".join(command))
            result = runner(command, float(effective_capture_seconds) + 2.0)
            captured_text = result.stdout or ""
            capture_exit_code = result.exit_code
            capture_stderr = result.stderr
            if result.timed_out and captured_text:
                capture_status = "completed_time_bounded"
            elif result.exit_code == 0:
                capture_status = "completed"
            elif result.timed_out:
                capture_status = "timed_out_no_packets"
                notes.append("tcpdump capture reached the time bound before packet limit completion.")
            else:
                capture_status = "failed"
                notes.append("tcpdump capture did not complete successfully; stderr was recorded in runner stderr only.")
    else:
        notes.append("Packet analysis used provided fixture text; raw packet content was not stored in the artifact.")

    credential_signals, cleartext_protocols = _detect_cleartext_signals(captured_text, default_target)

    arp_entries = _arp_entries_from_inventory(normalized_inventory)
    if isinstance(arp_table, list):
        arp_entries.extend(
            _arp_entries_from_inventory({"arp_table": [item for item in arp_table if isinstance(item, dict)]})
        )
    if ip_neigh_text:
        arp_entries.extend(parse_ip_neigh_output(ip_neigh_text))
    elif normalized_interface:
        ip_path = shutil.which(ip_binary) or ip_binary
        command = [ip_path, "neigh", "show", "dev", normalized_interface]
        commands.append(" ".join(command))
        result = runner(command, 3.0)
        if result.stdout:
            arp_entries.extend(parse_ip_neigh_output(result.stdout))
        elif result.exit_code not in {0, 1}:
            notes.append("ip neigh ARP table read failed or returned no usable entries.")

    if arp_probe_text:
        arp_entries.extend(parse_arp_probe_output(arp_probe_text, interface=normalized_interface))
    elif arp_probe_enabled and normalized_interface:
        arping_path = shutil.which(arping_binary) or arping_binary
        probe_targets = [
            str(network.network_address + 1)
            for network in scope_networks
            if network.version == 4 and network.num_addresses > 2
        ][:8]
        if gateway_ip:
            probe_targets.insert(0, str(gateway_ip))
        for probe_target in _normalized_string_list(probe_targets):
            command = build_arping_command(
                binary=arping_path,
                interface=normalized_interface,
                target=probe_target,
                probe_count=effective_arp_probe_count,
            )
            commands.append(" ".join(command))
            result = runner(command, 3.0)
            if result.stdout:
                arp_entries.extend(parse_arp_probe_output(result.stdout, interface=normalized_interface))

    arp_entries = _dedupe_arp_entries(arp_entries, scope_networks=scope_networks)
    arp_anomaly_records = _arp_anomalies(
        arp_entries,
        gateway_ip=gateway_ip,
        expected_gateway_mac=expected_gateway_mac,
        default_target=default_target,
    )
    analysis_findings = _build_network_capture_findings(
        credential_signals=credential_signals,
        arp_anomalies=arp_anomaly_records,
        default_target=default_target,
    )

    proof_requested = arp_spoof_proof_requested or run_mode == "arp-spoof-proof"
    proof_duration = _bounded_int(
        arp_spoof_duration_seconds,
        default=10,
        minimum=1,
        maximum=MAX_ARP_SPOOF_SECONDS,
    )
    arp_spoof_proof = {
        "requested": proof_requested,
        "status": "not_requested",
        "authorized": False,
        "duration_seconds": proof_duration,
        "single_target": _safe_ip(arp_spoof_target) if arp_spoof_target else None,
        "restoration_required": True,
        "executed": False,
    }
    if proof_requested:
        if not allow_arp_spoof_proof or not intrusive_authorized:
            arp_spoof_proof.update(
                {
                    "status": "blocked_requires_intrusive_gate",
                    "reason": "ARP spoof proof requires explicit intrusive authorization and remains disabled for passive profiles.",
                }
            )
        elif not normalized_interface or not arp_spoof_target or not gateway_ip:
            arp_spoof_proof.update(
                {
                    "status": "blocked_missing_single_target_context",
                    "reason": "ARP spoof proof requires one approved target host, gateway IP, and interface.",
                    "authorized": True,
                }
            )
        elif not _host_in_scope(str(arp_spoof_target), scope_networks) or not _host_in_scope(
            str(gateway_ip),
            scope_networks,
        ):
            arp_spoof_proof.update(
                {
                    "status": "blocked_out_of_scope",
                    "authorized": True,
                    "reason": "ARP spoof proof target and gateway must both be inside the approved scope.",
                }
            )
        else:
            arpspoof_path = shutil.which(arpspoof_binary) or arpspoof_binary
            if arpspoof_executor is None and not shutil.which(arpspoof_binary):
                arp_spoof_proof.update(
                    {
                        "status": "blocked_capability_unavailable",
                        "authorized": True,
                        "reason": "arpspoof binary is unavailable on this runner host.",
                    }
                )
                arpspoof_path = ""
            if not arpspoof_path:
                pass
            else:
                command = build_arpspoof_command(
                    binary=arpspoof_path,
                    interface=normalized_interface,
                    target=str(arp_spoof_target),
                    gateway=str(gateway_ip),
                )
                commands.append(" ".join(command))
                proof_result = spoof_executor(command, proof_duration)
                proof_exit = proof_result.get("exit_code")
                proof_completed = proof_exit in {0, -signal.SIGINT, 130}
                arp_spoof_proof.update(
                    {
                        "status": "completed" if proof_completed else "failed",
                        "authorized": True,
                        "executed": True,
                        "command": " ".join(command),
                        "exit_code": proof_exit,
                        "observed_duration_seconds": proof_result.get("duration_seconds"),
                        "restoration_attempted": bool(proof_result.get("restoration_signal_sent")),
                        "restoration_method": "graceful SIGINT to arpspoof for immediate ARP cache repair",
                        "stdout_excerpt": proof_result.get("stdout") or "",
                        "stderr_excerpt": proof_result.get("stderr") or "",
                    }
                )

    inventory_payload = _build_inventory(
        arp_entries=arp_entries,
        cleartext_protocols=cleartext_protocols,
    )
    payload = {
        "runner": "network-capture",
        "runner_digest": NETWORK_CAPTURE_RUNNER_DIGEST,
        "mode": run_mode,
        "targets": normalized_targets,
        "scope_networks": [str(network) for network in scope_networks],
        "interface": normalized_interface,
        "capture": {
            "status": capture_status,
            "duration_seconds": effective_capture_seconds,
            "packet_limit": effective_packet_limit,
            "raw_payload_stored": False,
            "credential_values_stored": False,
            "tcpdump_filter": " ".join(filter_tokens),
            "exit_code": capture_exit_code,
        },
        "cleartext_protocols": cleartext_protocols,
        "credential_signals": credential_signals,
        "arp_consistency": {
            "entries": arp_entries,
            "anomalies": arp_anomaly_records,
            "dynamic_arp_inspection_status": (
                "possible_missing_or_ineffective" if arp_anomaly_records else "not_indicated"
            ),
            "gateway_ip": _safe_ip(gateway_ip) if gateway_ip else None,
            "expected_gateway_mac": _normalize_mac(expected_gateway_mac),
            "arp_probe_enabled": bool(arp_probe_enabled),
            "arp_probe_count": effective_arp_probe_count,
        },
        "arp_spoof_proof": arp_spoof_proof,
        "inventory": inventory_payload,
        "analysis_findings": analysis_findings,
        "commands": commands,
        "notes": notes,
        "elapsed_seconds": round(time.time() - started_at, 3),
    }
    artifact = EvidenceArtifact(
        name=NETWORK_CAPTURE_RESULTS_ARTIFACT_NAME,
        content_type="application/json",
        data=json.dumps(payload, indent=2, sort_keys=True).encode("utf-8"),
        kind="network-capture-results",
    )
    stdout = (
        f"network-capture {run_mode}: capture={capture_status}, "
        f"{len(credential_signals)} credential/token signals, "
        f"{len(arp_anomaly_records)} ARP anomalies, "
        f"{len(analysis_findings)} findings"
    )
    return RunnerExecution(
        tool="network-capture",
        exit_code=0,
        stdout=stdout,
        stderr=capture_stderr if capture_status == "failed" else "",
        metadata={
            "status": "ok" if capture_status != "failed" else "completed_with_gaps",
            "mode": run_mode,
            "capture_status": capture_status,
            "credential_signal_count": len(credential_signals),
            "arp_anomaly_count": len(arp_anomaly_records),
            "finding_count": len(analysis_findings),
            "runner_digest": NETWORK_CAPTURE_RUNNER_DIGEST,
        },
        artifacts=[artifact],
    )
