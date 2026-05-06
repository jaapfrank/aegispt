from __future__ import annotations

import json
import os
import re
import subprocess
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from api.app.services.runs import target_value_is_allowed
from workers.runners.base.contracts import (
    EvidenceArtifact,
    ProtectedSecretMaterial,
    RunnerExecution,
)

SSH_BRUTE_RESULTS_ARTIFACT_NAME = "ssh-brute-results.json"
SSH_BRUTE_RUNNER_DIGEST = "workers.ssh_brute.runner:v1"
DEFAULT_TIMEOUT_SECONDS = 20.0
DEFAULT_RATE_LIMIT_PER_SECOND = 5.0
DEFAULT_LOCKOUT_STOP_THRESHOLD = 3
SUPPORTED_PROTOCOLS = {"ssh", "ftp", "telnet", "rdp"}
DEFAULT_PORTS_BY_PROTOCOL = {
    "ssh": 22,
    "ftp": 21,
    "telnet": 23,
    "rdp": 3389,
}
SERVICE_BY_PORT = {port: service for service, port in DEFAULT_PORTS_BY_PROTOCOL.items()}
SERVICE_ALIASES = {
    "ms-wbt-server": "rdp",
    "microsoft-rdp": "rdp",
    "remote-desktop": "rdp",
    "remote desktop": "rdp",
    "terminal-services": "rdp",
}
DEFAULT_USERNAMES = (
    "root",
    "admin",
    "administrator",
    "user",
    "test",
    "ubuntu",
    "pi",
    "ftp",
    "guest",
)
TOP_50_COMMON_PASSWORDS = (
    "password",
    "123456",
    "admin",
    "root",
    "toor",
    "12345678",
    "qwerty",
    "123456789",
    "12345",
    "1234",
    "111111",
    "123123",
    "password1",
    "letmein",
    "welcome",
    "monkey",
    "dragon",
    "abc123",
    "iloveyou",
    "admin123",
    "changeme",
    "default",
    "test",
    "guest",
    "user",
    "passw0rd",
    "p@ssw0rd",
    "Password1",
    "qwerty123",
    "1q2w3e4r",
    "000000",
    "123321",
    "654321",
    "666666",
    "7777777",
    "888888",
    "999999",
    "sunshine",
    "princess",
    "football",
    "baseball",
    "login",
    "master",
    "superuser",
    "support",
    "cisco",
    "ubnt",
    "raspberry",
    "openelec",
    "kali",
)
SUCCESS_RE = re.compile(
    r"(?:\[(?P<port>\d+)\]\[(?P<service>[^\]]+)\]\s*)?"
    r"host:\s*(?P<host>\S+).*?login:\s*(?P<username>\S+).*?password:\s*(?P<password>\S+)",
    flags=re.IGNORECASE | re.DOTALL,
)
LOCKOUT_MARKERS = (
    "account locked",
    "account is locked",
    "locked out",
    "too many authentication failures",
    "max auth tries",
    "temporarily locked",
    "user locked",
    "login locked",
    "exceeded maximum login attempts",
)


@dataclass(frozen=True, slots=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False
    terminated_by_kill_switch: bool = False


HydraExecutor = Callable[[list[str], float], CommandResult]
SleepFunc = Callable[[float], None]
TimeFunc = Callable[[], float]


def _json_artifact(payload: dict[str, Any]) -> EvidenceArtifact:
    return EvidenceArtifact(
        name=SSH_BRUTE_RESULTS_ARTIFACT_NAME,
        content_type="application/json",
        data=(json.dumps(payload, sort_keys=True) + "\n").encode("utf-8"),
        kind="runner-results",
    )


def _normalize_string_list(values: Iterable[object] | object | None) -> list[str]:
    if values is None:
        return []
    raw_items = values if isinstance(values, list | tuple | set) else [values]
    normalized: list[str] = []
    seen: set[str] = set()
    for item in raw_items:
        value = str(item or "").strip()
        if not value or value in seen:
            continue
        seen.add(value)
        normalized.append(value)
    return normalized


def _safe_port(value: object, default: int | None = None) -> int | None:
    try:
        port = int(value)
    except (TypeError, ValueError):
        return default
    return port if 0 < port <= 65535 else default


def _normalize_protocol(service: object, port: int | None = None) -> str | None:
    raw = str(service or "").strip().lower()
    raw = SERVICE_ALIASES.get(raw, raw)
    if raw in SUPPORTED_PROTOCOLS:
        return raw
    for protocol in SUPPORTED_PROTOCOLS:
        if protocol in raw:
            return protocol
    if port in SERVICE_BY_PORT:
        return SERVICE_BY_PORT[port]
    return None


def _parse_host_port(value: str, default_port: int = 22) -> tuple[str, int] | None:
    candidate = str(value or "").strip()
    if not candidate:
        return None
    parsed = urlparse(candidate if "://" in candidate else f"//{candidate}")
    host = str(parsed.hostname or "").strip()
    if not host and "/" not in candidate:
        host = candidate.split(":", 1)[0].strip()
    if not host or "/" in host:
        return None
    port = _safe_port(parsed.port, default_port) or default_port
    return host, port


def _service_key(host: str, port: int, protocol: str) -> tuple[str, int, str]:
    return (host.strip().lower(), int(port), protocol.strip().lower())


def _add_service(
    services: dict[tuple[str, int, str], dict[str, Any]],
    *,
    host: str,
    port: int,
    protocol: str,
    source: str,
    metadata: dict[str, Any] | None = None,
) -> None:
    normalized_host = str(host or "").strip()
    normalized_protocol = _normalize_protocol(protocol, port)
    if not normalized_host or normalized_protocol is None:
        return
    key = _service_key(normalized_host, int(port), normalized_protocol)
    existing = services.get(key, {})
    services[key] = {
        **existing,
        **(metadata or {}),
        "host": normalized_host,
        "port": int(port),
        "service": normalized_protocol,
        "source": existing.get("source") or source,
    }


def _services_from_records(
    records: Iterable[Any],
    *,
    source: str,
    services: dict[tuple[str, int, str], dict[str, Any]],
) -> None:
    for record in records:
        if isinstance(record, str):
            parsed = _parse_host_port(record)
            if parsed is None:
                continue
            host, port = parsed
            protocol = _normalize_protocol("", port)
            if protocol:
                _add_service(services, host=host, port=port, protocol=protocol, source=source)
            continue
        if not isinstance(record, dict):
            continue
        host = str(
            record.get("host")
            or record.get("ip")
            or record.get("address")
            or record.get("target")
            or record.get("value")
            or ""
        ).strip()
        service = str(
            record.get("service")
            or record.get("service_name")
            or record.get("protocol")
            or record.get("name")
            or ""
        ).strip()
        port = _safe_port(record.get("port"))
        if not host and isinstance(record.get("url"), str):
            parsed = urlparse(str(record["url"]))
            host = str(parsed.hostname or "").strip()
            port = port or _safe_port(parsed.port)
        if not host:
            continue
        protocol = _normalize_protocol(service, port)
        if protocol is None:
            continue
        _add_service(
            services,
            host=host,
            port=port or DEFAULT_PORTS_BY_PROTOCOL[protocol],
            protocol=protocol,
            source=source,
            metadata=record,
        )


def _normalize_services(
    targets: list[str],
    *,
    inventory: dict[str, Any] | None,
    service_targets: list[Any] | None,
    discovered_services: list[Any] | None,
    scope_allowlist: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    services: dict[tuple[str, int, str], dict[str, Any]] = {}
    _services_from_records(service_targets or [], source="configuration", services=services)
    _services_from_records(discovered_services or [], source="configuration", services=services)
    source_inventory = inventory if isinstance(inventory, dict) else {}
    for key in ("services", "open_services", "ports"):
        raw_services = source_inventory.get(key)
        if isinstance(raw_services, list):
            _services_from_records(raw_services, source=f"inventory.{key}", services=services)
    if not services:
        for target in targets:
            parsed = _parse_host_port(target, default_port=22)
            if parsed is None:
                continue
            host, port = parsed
            protocol = _normalize_protocol("", port) or "ssh"
            _add_service(services, host=host, port=port, protocol=protocol, source="target")

    scope = scope_allowlist or {}
    filtered: list[dict[str, Any]] = []
    for service in services.values():
        host = str(service.get("host") or "").strip()
        if scope and not target_value_is_allowed(scope, host):
            continue
        filtered.append(service)
    return sorted(filtered, key=lambda item: (str(item["host"]), int(item["port"]), str(item["service"])))


def _normalize_password_tiers(
    configured_passwords: Iterable[object] | object | None,
    *,
    max_custom_passwords: int,
) -> list[dict[str, Any]]:
    top_passwords = _normalize_string_list(TOP_50_COMMON_PASSWORDS)
    custom = [
        password
        for password in _normalize_string_list(configured_passwords)
        if password not in top_passwords
    ][: max(max_custom_passwords, 0)]
    tiers = [{"name": "top-50-common", "passwords": top_passwords}]
    if custom:
        tiers.append({"name": "operator-configured", "passwords": custom})
    return tiers


def _iter_attempts(
    usernames: list[str],
    password_tiers: list[dict[str, Any]],
    *,
    max_attempts: int,
) -> Iterable[tuple[str, str, str]]:
    count = 0
    for tier in password_tiers:
        tier_name = str(tier.get("name") or "password-tier")
        passwords = _normalize_string_list(tier.get("passwords"))
        for password in passwords:
            for username in usernames:
                if count >= max_attempts:
                    return
                count += 1
                yield username, password, tier_name


def build_hydra_command(
    *,
    binary: str,
    host: str,
    port: int,
    protocol: str,
    username: str,
    password: str,
) -> list[str]:
    normalized_binary = str(binary or "").strip() or "hydra"
    normalized_protocol = _normalize_protocol(protocol, port)
    if normalized_protocol is None:
        raise ValueError(f"unsupported Hydra protocol: {protocol}")
    return [
        normalized_binary,
        "-I",
        "-l",
        username,
        "-p",
        password,
        "-s",
        str(port),
        "-t",
        "1",
        "-f",
        host,
        normalized_protocol,
    ]


def _default_hydra_executor(command: list[str], timeout_seconds: float) -> CommandResult:
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
            timeout=max(float(timeout_seconds), 1.0),
            env=os.environ.copy(),
        )
    except subprocess.TimeoutExpired as exc:
        return CommandResult(
            returncode=124,
            stdout=exc.stdout or "",
            stderr=exc.stderr or "",
            timed_out=True,
        )
    except OSError as exc:
        return CommandResult(returncode=127, stdout="", stderr=str(exc))
    return CommandResult(
        returncode=int(result.returncode),
        stdout=result.stdout or "",
        stderr=result.stderr or "",
    )


def get_hydra_version(binary: str) -> str:
    try:
        result = subprocess.run(
            [str(binary or "hydra"), "-h"],
            capture_output=True,
            text=True,
            check=False,
            timeout=5.0,
        )
    except (OSError, subprocess.TimeoutExpired):
        return Path(str(binary or "hydra")).name or "hydra"
    output = (result.stdout or result.stderr or "").strip()
    for line in output.splitlines():
        if "hydra" in line.lower():
            return line.strip()
    return Path(str(binary or "hydra")).name or "hydra"


def _contains_lockout_signal(text: str) -> bool:
    lowered = str(text or "").lower()
    return any(marker in lowered for marker in LOCKOUT_MARKERS)


def _parse_successes(text: str, *, fallback_host: str, fallback_port: int, fallback_protocol: str) -> list[dict[str, Any]]:
    successes: list[dict[str, Any]] = []
    for match in SUCCESS_RE.finditer(text or ""):
        username = str(match.group("username") or "").strip()
        password = str(match.group("password") or "").strip()
        if not username or not password:
            continue
        service = _normalize_protocol(match.group("service") or fallback_protocol, fallback_port) or fallback_protocol
        port = _safe_port(match.group("port"), fallback_port) or fallback_port
        host = str(match.group("host") or fallback_host).strip() or fallback_host
        successes.append(
            {
                "host": host,
                "port": port,
                "service": service,
                "username": username,
                "password": password,
            }
        )
    return successes


def _maybe_rate_limit(
    *,
    last_attempt_at: float | None,
    rate_limit_per_second: float,
    sleep_func: SleepFunc,
    time_func: TimeFunc,
) -> float:
    now = time_func()
    if last_attempt_at is None:
        return now
    interval = 1.0 / max(float(rate_limit_per_second), 0.1)
    elapsed = now - last_attempt_at
    if elapsed < interval:
        sleep_func(interval - elapsed)
        now = time_func()
    return now


def _finding_for_success(success: dict[str, Any]) -> dict[str, Any]:
    host = str(success.get("host") or "target")
    port = int(success.get("port") or 0)
    service = str(success.get("service") or "service").upper()
    username = str(success.get("username") or "")
    password = str(success.get("password") or "")
    return {
        "type": "weak_service_credential",
        "title": f"Weak Credential: {service} {username}:{password} on {host}:{port}",
        "severity": "critical",
        "target": f"{host}:{port}",
        "summary": (
            f"Hydra authenticated to {service} on {host}:{port} with a bounded "
            "top-50/operator-configured password tier inside the approved scope."
        ),
        "methodology_tags": [
            "authentication",
            "credential_attack",
            "ssh-brute-validation",
            service.lower(),
        ],
        "ptes_phase": "Exploitation",
        "nist_phase": "Attack",
        "wstg_id": "WSTG-ATHN",
        "control_family": "authentication",
    }


def execute_ssh_brute_force(
    targets: list[str],
    *,
    scope_allowlist: dict[str, Any] | None = None,
    inventory: dict[str, Any] | None = None,
    service_targets: list[Any] | None = None,
    discovered_services: list[Any] | None = None,
    usernames: Iterable[object] | object | None = None,
    password_candidates: Iterable[object] | object | None = None,
    max_usernames: int = 10,
    max_custom_passwords: int = 50,
    max_attempts_per_service: int = 200,
    rate_limit_per_second: float = DEFAULT_RATE_LIMIT_PER_SECOND,
    lockout_stop_threshold: int = DEFAULT_LOCKOUT_STOP_THRESHOLD,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    hydra_binary: str = "hydra",
    hydra_executor: HydraExecutor | None = None,
    sleep_func: SleepFunc = time.sleep,
    time_func: TimeFunc = time.monotonic,
    kill_switch_check: Callable[[], bool] | None = None,
) -> RunnerExecution:
    normalized_targets = [str(target).strip() for target in targets if str(target).strip()]
    if not normalized_targets and not service_targets and not discovered_services and not inventory:
        raise ValueError("ssh-brute requires at least one target, service target, or inventory service")

    services = _normalize_services(
        normalized_targets,
        inventory=inventory,
        service_targets=service_targets,
        discovered_services=discovered_services,
        scope_allowlist=scope_allowlist,
    )
    normalized_usernames = (_normalize_string_list(usernames) or list(DEFAULT_USERNAMES))[: max(max_usernames, 1)]
    password_tiers = _normalize_password_tiers(
        password_candidates,
        max_custom_passwords=max_custom_passwords,
    )
    attempts_limit = max(int(max_attempts_per_service), 1)
    rate_limit = min(max(float(rate_limit_per_second), 0.1), DEFAULT_RATE_LIMIT_PER_SECOND)
    lockout_threshold = max(int(lockout_stop_threshold), 1)
    executor = hydra_executor or _default_hydra_executor
    tool_version = get_hydra_version(hydra_binary)

    payload: dict[str, Any] = {
        "tool": "ssh-brute",
        "schema_version": 1,
        "targets": [],
        "findings": [],
        "wordlists": [
            {"name": str(tier.get("name")), "count": len(_normalize_string_list(tier.get("passwords")))}
            for tier in password_tiers
        ],
        "safety": {
            "approved_scope_enforced": bool(scope_allowlist),
            "supported_protocols": sorted(SUPPORTED_PROTOCOLS),
            "rate_limit_per_second": rate_limit,
            "max_attempts_per_service": attempts_limit,
            "lockout_stop_threshold": lockout_threshold,
            "large_wordlists_enabled": False,
            "rockyou_used": False,
            "hydra_invoked": False,
        },
    }
    protected_outputs: list[ProtectedSecretMaterial] = []
    stdout_lines: list[str] = []
    stderr_lines: list[str] = []
    last_attempt_at: float | None = None
    global_lockouts = 0
    terminated_by_kill_switch = False

    if not services:
        stderr_lines.append("No approved SSH/FTP/Telnet/RDP services were available for ssh-brute.")

    for service in services:
        host = str(service["host"])
        port = int(service["port"])
        protocol = str(service["service"])
        result: dict[str, Any] = {
            "host": host,
            "port": port,
            "service": protocol,
            "source": service.get("source"),
            "status": "ok",
            "attempt_count": 0,
            "lockout_signal_count": 0,
            "attempts": [],
            "successes": [],
            "errors": [],
        }
        payload["targets"].append(result)

        for username, password, tier_name in _iter_attempts(
            normalized_usernames,
            password_tiers,
            max_attempts=attempts_limit,
        ):
            if kill_switch_check is not None and bool(kill_switch_check()):
                result["status"] = "stopped"
                result["errors"].append("Kill switch enabled before next Hydra attempt")
                terminated_by_kill_switch = True
                break
            if global_lockouts >= lockout_threshold:
                result["status"] = "stopped"
                result["errors"].append("Stopped after consecutive account lockout signals")
                break
            last_attempt_at = _maybe_rate_limit(
                last_attempt_at=last_attempt_at,
                rate_limit_per_second=rate_limit,
                sleep_func=sleep_func,
                time_func=time_func,
            )
            command = build_hydra_command(
                binary=hydra_binary,
                host=host,
                port=port,
                protocol=protocol,
                username=username,
                password=password,
            )
            payload["safety"]["hydra_invoked"] = True
            command_result = executor(command, timeout_seconds)
            combined_output = "\n".join(
                part for part in (command_result.stdout, command_result.stderr) if part
            )
            lockout_detected = _contains_lockout_signal(combined_output)
            if lockout_detected:
                global_lockouts += 1
                result["lockout_signal_count"] += 1
            else:
                global_lockouts = 0
            successes = _parse_successes(
                combined_output,
                fallback_host=host,
                fallback_port=port,
                fallback_protocol=protocol,
            )
            accepted = bool(successes)
            result["attempt_count"] += 1
            result["attempts"].append(
                {
                    "username": username,
                    "password": "[REDACTED]",
                    "password_tier": tier_name,
                    "result": "accepted" if accepted else "lockout" if lockout_detected else "rejected",
                    "returncode": command_result.returncode,
                }
            )
            if command_result.timed_out:
                result["errors"].append(f"Hydra attempt timed out for {username}@{host}:{port}")
            if command_result.terminated_by_kill_switch:
                terminated_by_kill_switch = True
                result["errors"].append("Hydra attempt terminated by kill switch")

            if accepted:
                for success in successes:
                    result["successes"].append(success)
                    finding = _finding_for_success(success)
                    payload["findings"].append(finding)
                    protected_outputs.append(
                        ProtectedSecretMaterial(
                            artifact_name=SSH_BRUTE_RESULTS_ARTIFACT_NAME,
                            value=json.dumps(
                                {
                                    "target": finding["target"],
                                    "service": success["service"],
                                    "username": success["username"],
                                    "password": success["password"],
                                },
                                sort_keys=True,
                            ),
                            secret_kind="validated_service_credential",
                            purpose="task.ssh_brute.validated_credential",
                            display_label=(
                                f"{success['service']} credential for "
                                f"{success['username']}@{success['host']}:{success['port']}"
                            ),
                            content_type="application/json",
                            metadata={
                                "target": finding["target"],
                                "service": success["service"],
                                "username": success["username"],
                            },
                        )
                    )
                result["status"] = "credential_found"
                break
            if global_lockouts >= lockout_threshold:
                result["status"] = "stopped"
                result["errors"].append("Stopped after consecutive account lockout signals")
                break
            if command_result.terminated_by_kill_switch:
                result["status"] = "stopped"
                break
        stdout_lines.append(
            f"{protocol.upper()} {host}:{port}: "
            f"{len(result['successes'])} credential(s), {result['attempt_count']} attempt(s)"
        )
        if terminated_by_kill_switch or global_lockouts >= lockout_threshold:
            break

    finding_count = len(payload["findings"])
    payload["summary"] = {
        "service_count": len(services),
        "finding_count": finding_count,
        "lockout_signal_count": sum(int(item.get("lockout_signal_count") or 0) for item in payload["targets"]),
        "attempt_count": sum(int(item.get("attempt_count") or 0) for item in payload["targets"]),
        "terminated_by_kill_switch": terminated_by_kill_switch,
    }
    exit_code = 0 if not terminated_by_kill_switch else 2
    return RunnerExecution(
        tool="ssh-brute",
        exit_code=exit_code,
        stdout="\n".join(stdout_lines),
        stderr="\n".join(stderr_lines),
        metadata={
            "runner_digest": SSH_BRUTE_RUNNER_DIGEST,
            "tool_version": tool_version,
            "finding_count": finding_count,
            "rate_limit_per_second": rate_limit,
            "lockout_stop_threshold": lockout_threshold,
        },
        artifacts=[_json_artifact(payload)],
        protected_outputs=protected_outputs,
    )
