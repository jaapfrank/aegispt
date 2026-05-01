from __future__ import annotations

import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from workers.runners.base.contracts import EvidenceArtifact, RunnerExecution

PASSIVE_LAN_NSE_DISCOVERY_SCRIPTS = (
    "banner",
    "http-title",
    "http-server-header",
    "ssl-cert",
    "ike-version",
    "ftp-anon",
    "snmp-info",
    "snmp-sysdescr",
    "nbstat",
    "smb-security-mode",
    "msrpc-enum",
    "upnp-info",
)
IOT_NSE_DISCOVERY_SCRIPTS = (
    "http-title",
    "http-server-header",
    "rtsp-url-brute",
    "upnp-info",
)
ACTIVE_DEFAULT_CREDENTIAL_NSE_SCRIPTS = (
    "http-default-accounts",
    "telnet-brute",
    "ftp-brute",
    "http-auth-finder",
)
ALLOWED_NSE_SCRIPTS = frozenset(
    (*PASSIVE_LAN_NSE_DISCOVERY_SCRIPTS, *IOT_NSE_DISCOVERY_SCRIPTS, *ACTIVE_DEFAULT_CREDENTIAL_NSE_SCRIPTS)
)
LAN_IOT_PORTS = (
    "21",
    "22",
    "23",
    "25",
    "53",
    "80",
    "81",
    "443",
    "554",
    "1883",
    "1900",
    "3260",
    "4443",
    "5353",
    "7547",
    "8008",
    "8080",
    "8083",
    "8086",
    "8123",
    "8443",
    "8554",
    "9000",
    "49152-49157",
)
_SAFE_SCRIPT_ARG_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
_SAFE_SCRIPT_ARG_VALUE_RE = re.compile(r"^[A-Za-z0-9_.,:/@+= -]+$")
_PORT_TOKEN_RE = re.compile(r"^\d{1,5}(?:-\d{1,5})?$")


def normalize_nse_scripts(scripts: list[str] | tuple[str, ...] | None) -> list[str]:
    normalized: list[str] = []
    seen: set[str] = set()
    for raw_script in scripts or []:
        script = str(raw_script or "").strip()
        if not script:
            continue
        if script not in ALLOWED_NSE_SCRIPTS:
            raise ValueError(f"NSE script is not allowlisted: {script}")
        if script not in seen:
            seen.add(script)
            normalized.append(script)
    return normalized


def normalize_nmap_ports(ports: list[str] | tuple[str, ...] | str | None) -> str | None:
    if ports is None:
        return None
    raw_items = ports.split(",") if isinstance(ports, str) else list(ports)
    normalized: list[str] = []
    seen: set[str] = set()
    for raw_port in raw_items:
        item = str(raw_port or "").strip()
        if not item:
            continue
        if not _PORT_TOKEN_RE.match(item):
            raise ValueError(f"invalid nmap port token: {item}")
        parts = item.split("-", 1)
        for part in parts:
            port_number = int(part)
            if not 1 <= port_number <= 65535:
                raise ValueError(f"invalid nmap port token: {item}")
        if len(parts) == 2 and int(parts[0]) > int(parts[1]):
            raise ValueError(f"invalid nmap port range: {item}")
        if item not in seen:
            seen.add(item)
            normalized.append(item)
    return ",".join(normalized) if normalized else None


def normalize_script_args(script_args: dict[str, object] | None) -> str | None:
    if not isinstance(script_args, dict):
        return None
    normalized: list[str] = []
    for raw_key, raw_value in sorted(script_args.items()):
        key = str(raw_key or "").strip()
        value = str(raw_value or "").strip()
        if not key or not value:
            continue
        if not _SAFE_SCRIPT_ARG_RE.match(key) or not _SAFE_SCRIPT_ARG_VALUE_RE.match(value):
            raise ValueError(f"invalid NSE script argument: {key}")
        normalized.append(f"{key}={value}")
    return ",".join(normalized) if normalized else None


def build_nmap_command(
    binary: str,
    *,
    output_file: Path,
    targets: list[str],
    discovery_only: bool = True,
    service_detection: bool = False,
    skip_discovery: bool = False,
    top_ports: int | None = None,
    full_port_scan: bool = False,
    version_intensity: int | None = None,
    timing_template: str | None = None,
    max_retries: int | None = None,
    host_timeout_seconds: float | None = None,
    ports: list[str] | tuple[str, ...] | str | None = None,
    scripts: list[str] | tuple[str, ...] | None = None,
    script_args: dict[str, object] | None = None,
    ipv6: bool = False,
) -> list[str]:
    if not binary.strip():
        raise ValueError("binary must not be blank")
    normalized_targets = [target.strip() for target in targets if target.strip()]
    if not normalized_targets:
        raise ValueError("at least one target is required")

    command = [binary, "-n"]
    if ipv6:
        command.append("-6")
    command.extend(["-oX", str(output_file)])
    if discovery_only:
        command.append("-sn")
    else:
        if skip_discovery:
            command.append("-Pn")
        if service_detection:
            command.append("-sV")
            if isinstance(version_intensity, int) and 0 <= version_intensity <= 9:
                command.extend(["--version-intensity", str(version_intensity)])
        normalized_ports = normalize_nmap_ports(ports)
        if full_port_scan:
            command.append("-p-")
        elif normalized_ports:
            command.extend(["-p", normalized_ports])
        elif isinstance(top_ports, int) and top_ports > 0:
            command.extend(["--top-ports", str(top_ports)])
        normalized_scripts = normalize_nse_scripts(scripts)
        if normalized_scripts:
            command.extend(["--script", ",".join(normalized_scripts)])
            normalized_script_args = normalize_script_args(script_args)
            if normalized_script_args:
                command.extend(["--script-args", normalized_script_args])
        normalized_timing = str(timing_template or "").strip().upper()
        if normalized_timing in {f"T{value}" for value in range(0, 6)}:
            command.append(f"-{normalized_timing}")
        if isinstance(max_retries, int) and max_retries >= 0:
            command.extend(["--max-retries", str(max_retries)])
        if isinstance(host_timeout_seconds, (int, float)) and host_timeout_seconds > 0:
            command.extend(["--host-timeout", f"{int(host_timeout_seconds)}s"])
    command.extend(normalized_targets)
    return command


def get_nmap_version(binary: str) -> str:
    result = subprocess.run(
        [binary, "--version"],
        capture_output=True,
        text=True,
        check=False,
    )
    output = (result.stdout or result.stderr).strip()
    if not output:
        return "nmap"
    return output.splitlines()[0].strip() or "nmap"


def execute_nmap_scan(
    targets: list[str],
    *,
    binary: str = "nmap",
    discovery_only: bool = True,
    service_detection: bool = False,
    skip_discovery: bool = False,
    top_ports: int | None = None,
    full_port_scan: bool = False,
    version_intensity: int | None = None,
    timing_template: str | None = None,
    max_retries: int | None = None,
    host_timeout_seconds: float | None = None,
    ports: list[str] | tuple[str, ...] | str | None = None,
    scripts: list[str] | tuple[str, ...] | None = None,
    script_args: dict[str, object] | None = None,
    ipv6: bool = False,
    timeout_seconds: float = 10.0,
) -> RunnerExecution:
    normalized_targets = [target.strip() for target in targets if target.strip()]
    if not normalized_targets:
        raise ValueError("at least one target is required")

    with tempfile.TemporaryDirectory(prefix="aegispt-nmap-") as temp_dir_name:
        temp_dir = Path(temp_dir_name)
        output_file = temp_dir / "nmap-results.xml"
        command = build_nmap_command(
            binary=binary,
            output_file=output_file,
            targets=normalized_targets,
            discovery_only=discovery_only,
            service_detection=service_detection,
            skip_discovery=skip_discovery,
            top_ports=top_ports,
            full_port_scan=full_port_scan,
            version_intensity=version_intensity,
            timing_template=timing_template,
            max_retries=max_retries,
            host_timeout_seconds=host_timeout_seconds,
            ports=ports,
            scripts=scripts,
            script_args=script_args,
            ipv6=ipv6,
        )
        timed_out = False
        try:
            process = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=False,
                timeout=max(float(timeout_seconds), 1.0),
            )
            stdout = process.stdout
            stderr = process.stderr
            exit_code = process.returncode
        except subprocess.TimeoutExpired as exc:
            timed_out = True
            stdout = exc.stdout or ""
            stderr = exc.stderr or ""
            if isinstance(stdout, bytes):
                stdout = stdout.decode("utf-8", errors="replace")
            if isinstance(stderr, bytes):
                stderr = stderr.decode("utf-8", errors="replace")
            stderr = (
                f"{stderr}\n"
                f"nmap timed out after {max(float(timeout_seconds), 1.0):.1f} seconds"
            ).strip()
            exit_code = 124

        artifact_data = output_file.read_bytes() if output_file.exists() else b""
        artifact = EvidenceArtifact(
            name="nmap-results.xml",
            content_type="application/xml",
            data=artifact_data,
            kind="network-scan-results",
        )

        return RunnerExecution(
            tool="nmap",
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            metadata={
                "status": "timeout" if timed_out else ("ok" if exit_code == 0 else "failed"),
                "normalized_targets": normalized_targets,
                "discovery_only": discovery_only,
                "service_detection": service_detection,
                "skip_discovery": skip_discovery,
                "top_ports": top_ports,
                "ports": normalize_nmap_ports(ports),
                "scripts": normalize_nse_scripts(scripts),
                "script_args": normalize_script_args(script_args),
                "ipv6": ipv6,
                "full_port_scan": full_port_scan,
                "version_intensity": version_intensity,
                "timing_template": timing_template,
                "max_retries": max_retries,
                "host_timeout_seconds": host_timeout_seconds,
                "timeout_seconds": timeout_seconds,
                "timed_out": timed_out,
                "tool_version": get_nmap_version(binary),
                "runner_digest": "workers.nmap.runner:v1",
            },
            artifacts=[artifact],
        )
