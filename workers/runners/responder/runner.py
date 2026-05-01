from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import time
from ipaddress import ip_network
from pathlib import Path
from typing import Callable

from api.app.config import get_settings
from api.app.policy.engine import execution_kill_switch_enabled
from api.app.services.runs import target_value_is_allowed
from workers.runners.base.contracts import (
    EvidenceArtifact,
    ProtectedSecretMaterial,
    RunnerExecution,
)

RESPONDER_RESULTS_ARTIFACT_NAME = "responder-results.json"
RESPONDER_LOG_ARTIFACT_NAME = "responder-session.log"
DEFAULT_DURATION_MINUTES = 10.0
MAX_DURATION_MINUTES = 60.0
DEFAULT_POLL_INTERVAL_SECONDS = 0.25

_INTERFACE_PATTERN = re.compile(r"^[A-Za-z0-9_.:-]+$")
_HOST_FROM_FILENAME_PATTERN = re.compile(r"(?P<host>(?:\d{1,3}\.){3}\d{1,3}|[0-9A-Fa-f:]+)\.txt$")
_CAPTURE_LINE_PATTERN = re.compile(
    r"(?P<username>[^\s:]+)::(?P<domain>[^:\r\n]*):(?P<body>[A-Fa-f0-9]{16,}:[A-Fa-f0-9]{16,}:[^\r\n]+)"
)
_SESSION_HASH_PATTERN = re.compile(r"(?i)(NTLMv2(?:-SSP)?\s+Hash\s*:\s*)([^\r\n]+)")
_RAW_HASH_PATTERN = re.compile(
    r"(?i)([A-Za-z0-9._$-]+::[A-Za-z0-9._$ -]*:)([A-Fa-f0-9]{16,}:[A-Fa-f0-9]{16,}:[^\r\n]+)"
)


def _normalize_binary(binary: str) -> str:
    normalized = str(binary or "").strip()
    if not normalized:
        raise ValueError("Responder binary must not be blank")
    return normalized


def normalize_interface(interface: str) -> str:
    normalized = str(interface or "").strip()
    if not normalized:
        raise ValueError("Responder requires a network interface")
    if not _INTERFACE_PATTERN.fullmatch(normalized):
        raise ValueError("Responder interface contains unsupported characters")
    return normalized


def normalize_duration_minutes(duration_minutes: float | int | None) -> float:
    if duration_minutes is None:
        return DEFAULT_DURATION_MINUTES
    try:
        normalized = float(duration_minutes)
    except (TypeError, ValueError) as exc:
        raise ValueError("Responder duration must be numeric minutes") from exc
    if normalized <= 0:
        raise ValueError("Responder duration must be greater than zero")
    return min(normalized, MAX_DURATION_MINUTES)


def build_responder_command(binary: str, *, interface: str) -> list[str]:
    return [
        _normalize_binary(binary),
        "-I",
        normalize_interface(interface),
        "-r",
        "-d",
        "-f",
    ]


def get_responder_version(binary: str) -> str:
    try:
        result = subprocess.run(
            [_normalize_binary(binary), "--version"],
            capture_output=True,
            text=True,
            check=False,
            timeout=5.0,
        )
    except (OSError, subprocess.TimeoutExpired):
        return Path(binary).name or "responder"

    output = (result.stdout or result.stderr).strip()
    if not output:
        return Path(binary).name or "responder"
    return output.splitlines()[0].strip()


def _sanitize_responder_text(value: str) -> str:
    sanitized = _SESSION_HASH_PATTERN.sub(r"\1[REDACTED]", value or "")
    sanitized = _RAW_HASH_PATTERN.sub(r"\1[REDACTED]", sanitized)
    return sanitized


def _host_from_capture_file(path: Path) -> str | None:
    match = _HOST_FROM_FILENAME_PATTERN.search(path.name)
    if match is None:
        return None
    return str(match.group("host")).strip() or None


def _collect_captures(logs_dir: Path) -> list[dict[str, str]]:
    captures: list[dict[str, str]] = []
    seen_hashes: set[str] = set()
    if not logs_dir.exists():
        return captures

    for path in sorted(logs_dir.rglob("*.txt")):
        host = _host_from_capture_file(path)
        if not host:
            continue
        for line in path.read_text("utf-8", errors="replace").splitlines():
            match = _CAPTURE_LINE_PATTERN.search(line.strip())
            if match is None:
                continue
            raw_hash = line.strip()
            if raw_hash in seen_hashes:
                continue
            seen_hashes.add(raw_hash)
            username = str(match.group("username") or "").strip() or "unknown"
            domain = str(match.group("domain") or "").strip()
            captures.append(
                {
                    "host": host,
                    "username": username,
                    "domain": domain,
                    "hash_type": "NTLMv2",
                    "source_file": path.name,
                    "raw_hash": raw_hash,
                }
            )
    return captures


def _sanitize_log_output(logs_dir: Path, *, stdout: str, stderr: str) -> str:
    session_log = logs_dir / "Responder-Session.log"
    if session_log.exists():
        raw = session_log.read_text("utf-8", errors="replace")
    else:
        raw_parts = [part for part in (stdout, stderr) if part.strip()]
        raw = "\n".join(raw_parts)
    return _sanitize_responder_text(raw).strip() + ("\n" if raw.strip() else "")


def _protected_hash_bundle(
    *,
    captures: list[dict[str, str]],
    interface: str,
    scope_cidrs: list[str],
) -> str:
    bundle = {
        "interface": interface,
        "scope_cidrs": list(scope_cidrs),
        "captured_hash_count": len(captures),
        "captures": captures,
    }
    return json.dumps(bundle, indent=2, sort_keys=True)


def _summary_payload(
    *,
    captures: list[dict[str, str]],
    interface: str,
    scope_cidrs: list[str],
    duration_minutes: float,
    kill_switch_terminated: bool,
) -> dict[str, object]:
    sanitized_captures = [
        {
            "host": capture["host"],
            "username": capture["username"],
            "domain": capture["domain"],
            "hash_type": capture["hash_type"],
            "source_file": capture["source_file"],
            "summary": (
                f"Captured {capture['hash_type']} material for {capture['username']}"
                f"{'@' + capture['domain'] if capture['domain'] else ''} from {capture['host']}."
            ),
        }
        for capture in captures
    ]
    return {
        "summary": {
            "interface": interface,
            "scope_cidrs": list(scope_cidrs),
            "capture_count": len(sanitized_captures),
            "duration_minutes": duration_minutes,
            "kill_switch_terminated": kill_switch_terminated,
            "hash_material_stored_as": "protected_secret_ref",
        },
        "captures": sanitized_captures,
    }


def _terminate_process(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=3.0)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=3.0)


def execute_responder_capture(
    targets: list[str],
    *,
    interface: str,
    duration_minutes: float | int | None = None,
    binary: str = "responder",
    scope_allowlist: dict[str, object] | None = None,
    kill_switch_check: Callable[[], bool] | None = None,
    poll_interval_seconds: float = DEFAULT_POLL_INTERVAL_SECONDS,
) -> RunnerExecution:
    normalized_targets = [str(target).strip() for target in targets if str(target).strip()]
    if not normalized_targets:
        raise ValueError("Responder requires at least one approved CIDR target")

    scope_allowlist = scope_allowlist or {}
    for target in normalized_targets:
        try:
            ip_network(target, strict=False)
        except ValueError as exc:
            raise ValueError("Responder requires CIDR targets only") from exc
        if not target_value_is_allowed(scope_allowlist, target):
            raise ValueError(f"target outside scope: {target}")

    normalized_interface = normalize_interface(interface)
    normalized_duration_minutes = normalize_duration_minutes(duration_minutes)
    binary_path = _normalize_binary(binary)
    kill_switch = (
        kill_switch_check
        if kill_switch_check is not None
        else lambda: execution_kill_switch_enabled(get_settings())
    )

    with tempfile.TemporaryDirectory(prefix="aegispt-responder-") as temp_dir_name:
        temp_dir = Path(temp_dir_name)
        logs_dir = temp_dir / "logs"
        logs_dir.mkdir(parents=True, exist_ok=True)

        command = build_responder_command(binary_path, interface=normalized_interface)
        process = subprocess.Popen(
            command,
            cwd=temp_dir,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        kill_switch_terminated = False
        deadline = time.monotonic() + (normalized_duration_minutes * 60.0)
        while time.monotonic() < deadline:
            if process.poll() is not None:
                break
            if kill_switch():
                kill_switch_terminated = True
                _terminate_process(process)
                break
            time.sleep(max(poll_interval_seconds, 0.05))
        else:
            _terminate_process(process)

        stdout, stderr = process.communicate()
        captures = _collect_captures(logs_dir)
        sanitized_stdout = _sanitize_responder_text(stdout)
        sanitized_stderr = _sanitize_responder_text(stderr)
        sanitized_log = _sanitize_log_output(logs_dir, stdout=stdout, stderr=stderr)
        if kill_switch_terminated and "terminated cleanly" not in sanitized_log.lower():
            sanitized_log = f"{sanitized_log.rstrip()}\nterminated cleanly by kill switch\n"
        summary_payload = _summary_payload(
            captures=captures,
            interface=normalized_interface,
            scope_cidrs=normalized_targets,
            duration_minutes=normalized_duration_minutes,
            kill_switch_terminated=kill_switch_terminated,
        )
        protected_outputs = []
        if captures:
            protected_outputs.append(
                ProtectedSecretMaterial(
                    artifact_name=RESPONDER_RESULTS_ARTIFACT_NAME,
                    value=_protected_hash_bundle(
                        captures=captures,
                        interface=normalized_interface,
                        scope_cidrs=normalized_targets,
                    ),
                    secret_kind="ntlmv2_hash_bundle",
                    purpose="task.responder.captured_hashes",
                    display_label=f"Responder captured NTLMv2 hashes ({len(captures)})",
                    content_type="application/json",
                    metadata={
                        "capture_count": len(captures),
                        "interface": normalized_interface,
                        "scope_cidrs": list(normalized_targets),
                        "raw_secret_material_exposed": False,
                    },
                )
            )

        returncode = process.returncode if process.returncode is not None else 0
        exit_code = 0 if kill_switch_terminated or returncode == 0 else returncode
        status = "cancelled" if kill_switch_terminated else ("ok" if exit_code == 0 else "failed")

        return RunnerExecution(
            tool="responder",
            exit_code=exit_code,
            stdout=sanitized_stdout,
            stderr=sanitized_stderr,
            metadata={
                "status": status,
                "normalized_targets": normalized_targets,
                "interface": normalized_interface,
                "duration_minutes": normalized_duration_minutes,
                "capture_count": len(captures),
                "hash_material_protected": bool(captures),
                "terminated_by_kill_switch": kill_switch_terminated,
                "tool_version": get_responder_version(binary_path),
                "runner_digest": "workers.responder.runner:v1",
            },
            artifacts=[
                EvidenceArtifact(
                    name=RESPONDER_RESULTS_ARTIFACT_NAME,
                    content_type="application/json",
                    data=(json.dumps(summary_payload, indent=2, sort_keys=True) + "\n").encode("utf-8"),
                    kind="credential-capture-results",
                ),
                EvidenceArtifact(
                    name=RESPONDER_LOG_ARTIFACT_NAME,
                    content_type="text/plain",
                    data=sanitized_log.encode("utf-8"),
                    kind="execution-log",
                ),
            ],
            protected_outputs=protected_outputs,
        )
