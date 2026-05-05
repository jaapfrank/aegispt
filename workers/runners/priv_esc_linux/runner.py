from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import time
from pathlib import PurePosixPath
from typing import Any, Callable

from api.app.services.runs import target_value_is_allowed
from workers.runners.base.contracts import EvidenceArtifact, RunnerExecution

PRIV_ESC_LINUX_RESULTS_ARTIFACT_NAME = "priv-esc-linux-results.json"
DEFAULT_TIMEOUT_SECONDS = 60.0
DEFAULT_POLL_INTERVAL_SECONDS = 0.1

DANGEROUS_GTFOBINS = {
    "awk",
    "bash",
    "busybox",
    "cp",
    "dash",
    "docker",
    "env",
    "find",
    "gdb",
    "gcc",
    "less",
    "make",
    "more",
    "nano",
    "nmap",
    "node",
    "openssl",
    "perl",
    "php",
    "python",
    "python2",
    "python3",
    "rsync",
    "ruby",
    "screen",
    "service",
    "sh",
    "socat",
    "systemctl",
    "tar",
    "tcpdump",
    "tmux",
    "vi",
    "vim",
    "zip",
    "zsh",
}
DANGEROUS_SUDO_COMMANDS = {
    "awk",
    "bash",
    "find",
    "less",
    "more",
    "nmap",
    "perl",
    "python",
    "python2",
    "python3",
    "ruby",
    "sh",
    "vi",
    "vim",
}
SYSTEM_PATHS = {
    "/bin",
    "/sbin",
    "/usr/bin",
    "/usr/sbin",
    "/usr/local/bin",
    "/usr/local/sbin",
}
SECRET_VALUE_PATTERN = re.compile(
    r"(?i)(password|passwd|secret|token|api[_-]?key)\s*[:=]\s*[^\s,;\"'<>]+"
)
VERSION_PATTERN = re.compile(r"(\d+)\.(\d+)(?:\.(\d+))?(?:[-+~][A-Za-z0-9_.-]+)?")

ENUMERATION_COMMANDS: tuple[tuple[str, str], ...] = (
    (
        "suid_sgid",
        "find / -xdev \\( -perm -4000 -o -perm -2000 \\) -type f "
        "-printf '%m %u %g %p\\n' 2>/dev/null | head -n 300",
    ),
    ("sudo_l", "sudo -n -l 2>&1 || true"),
    (
        "cron",
        "find /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly "
        "/etc/cron.monthly /var/spool/cron -xdev -type f -perm -0002 "
        "-printf '%m %u %g %p\\n' 2>/dev/null | head -n 300",
    ),
    (
        "path",
        "printf 'PATH=%s\\n' \"$PATH\"; i=0; oldifs=$IFS; IFS=:; "
        'for d in $PATH; do i=$((i+1)); [ -n "$d" ] || continue; '
        '[ -d "$d" ] || continue; '
        'if [ -w "$d" ]; then printf \'writable %s %s\\n\' "$i" "$d"; '
        'else printf \'not_writable %s %s\\n\' "$i" "$d"; fi; done; IFS=$oldifs',
    ),
    (
        "permissions",
        "for f in /etc/passwd /etc/shadow; do "
        'if [ -e "$f" ]; then stat -Lc \'%a %U %G %n\' "$f" 2>/dev/null; fi; done; '
        "find /etc /var/backups /home -xdev -type f "
        "\\( -name '*~' -o -name '*.bak' -o -name '*.backup' -o -name '*.old' \\) "
        "-readable -printf '%m %u %g %p\\n' "
        '-exec sh -c \'grep -Im1 -E "(password|passwd|secret|token|api[_-]?key)" "$1" '
        '>/dev/null && printf "contains_secret_marker %s\\n" "$1"\' sh {} \\; '
        "2>/dev/null | head -n 300",
    ),
    (
        "versions",
        "printf 'Linux kernel release: '; uname -r; sudo --version 2>/dev/null | head -n1; "
        "cat /etc/os-release 2>/dev/null | head -n 6",
    ),
)


def _json_artifact(payload: dict[str, Any]) -> EvidenceArtifact:
    return EvidenceArtifact(
        name=PRIV_ESC_LINUX_RESULTS_ARTIFACT_NAME,
        content_type="application/json",
        data=(json.dumps(payload, sort_keys=True) + "\n").encode("utf-8"),
        kind="runner-results",
    )


def _normalize_targets(targets: list[str], scope_allowlist: dict[str, Any] | None) -> list[str]:
    normalized: list[str] = []
    seen: set[str] = set()
    for target in targets:
        candidate = str(target or "").strip()
        if not candidate:
            continue
        if not target_value_is_allowed(scope_allowlist or {}, candidate):
            raise ValueError(
                f"target outside approved Linux privilege escalation scope: {candidate}"
            )
        if candidate not in seen:
            seen.add(candidate)
            normalized.append(candidate)
    if not normalized:
        raise ValueError("at least one Linux host target is required")
    return normalized


def _normalize_auth_contexts(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    normalized: list[dict[str, Any]] = []
    for raw_context in value:
        if not isinstance(raw_context, dict):
            continue
        username = str(raw_context.get("username") or "").strip()
        password = str(raw_context.get("password") or "").strip()
        identity_file = str(raw_context.get("ssh_identity_file") or "").strip()
        if not username or (not password and not identity_file):
            continue
        normalized.append(
            {
                "label": str(raw_context.get("label") or username).strip() or username,
                "username": username,
                "password": password or None,
                "ssh_identity_file": identity_file or None,
                "port": _normalize_port(raw_context.get("ssh_port") or raw_context.get("port")),
            }
        )
    return normalized


def _normalize_port(value: object) -> int | None:
    if value in (None, ""):
        return None
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    if 1 <= port <= 65535:
        return port
    return None


def _redact(value: str, secrets: list[str]) -> str:
    redacted = str(value or "")
    for secret in secrets:
        candidate = str(secret or "").strip()
        if candidate:
            redacted = redacted.replace(candidate, "[REDACTED]")
    return SECRET_VALUE_PATTERN.sub(r"\1=[REDACTED]", redacted)


def _mode_bits(value: object) -> int:
    mode_text = str(value or "").strip()
    if mode_text.isdigit():
        try:
            return int(mode_text, 8)
        except ValueError:
            return 0
    mode_bits = 0
    if len(mode_text) >= 10:
        if mode_text[3] in {"s", "S"}:
            mode_bits |= 0o4000
        if mode_text[6] in {"s", "S"}:
            mode_bits |= 0o2000
    return mode_bits


def _is_world_writable(mode: object) -> bool:
    mode_text = str(mode or "").strip()
    if not mode_text:
        return False
    if mode_text.isdigit():
        return bool(int(mode_text[-1]) & 2)
    return len(mode_text) >= 9 and mode_text[-1] == "w"


def _is_world_readable(mode: object) -> bool:
    mode_text = str(mode or "").strip()
    if not mode_text:
        return False
    if mode_text.isdigit():
        return bool(int(mode_text[-1]) & 4)
    return len(mode_text) >= 9 and mode_text[-3] == "r"


def _finding(
    *,
    target: str,
    title: str,
    severity: str,
    summary: str,
    evidence: dict[str, Any],
    control_family: str = "authorization",
) -> dict[str, Any]:
    return {
        "title": title,
        "severity": severity,
        "target": target,
        "summary": summary,
        "evidence": evidence,
        "methodology_tags": [
            "linux-privilege-escalation",
            "priv-esc-linux-validation",
            "post-exploitation-enumeration",
        ],
        "ptes_phase": "Post-Exploitation",
        "nist_phase": "Attack",
        "wstg_id": "WSTG-ATHZ-03",
        "control_family": control_family,
    }


def _path_basename(path: str) -> str:
    return PurePosixPath(str(path or "").strip()).name.lower()


def _parse_mode_owner_path(line: str) -> tuple[str, str, str, str] | None:
    parts = str(line or "").strip().split(maxsplit=3)
    if len(parts) < 4:
        return None
    mode, owner, group, path = parts
    if not path.startswith("/"):
        return None
    return mode, owner, group, path


def _parse_suid_sgid(target: str, output: str, secrets: list[str]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()
    for line in output.splitlines():
        parsed = _parse_mode_owner_path(line)
        if parsed is None:
            continue
        mode, owner, group, path = parsed
        basename = _path_basename(path)
        if basename not in DANGEROUS_GTFOBINS:
            continue
        mode_value = _mode_bits(mode)
        if mode_value & 0o4000:
            title = f"SUID Binary Exploitable via GTFOBins: {path}"
            severity = "critical" if owner == "root" else "high"
        elif mode_value & 0o2000:
            title = f"SGID Binary Exploitable via GTFOBins: {path}"
            severity = "high"
        else:
            continue
        if title in seen:
            continue
        seen.add(title)
        findings.append(
            _finding(
                target=target,
                title=title,
                severity=severity,
                summary=(
                    f"{path} has privileged mode {mode} and maps to a GTFOBins "
                    "privilege-escalation technique. The runner only enumerated the binary."
                ),
                evidence={
                    "mode": mode,
                    "owner": owner,
                    "group": group,
                    "path": path,
                    "line": _redact(line, secrets),
                },
            )
        )
    return findings


def _parse_sudo(target: str, output: str, secrets: list[str]) -> list[dict[str, Any]]:
    output_text = _redact(output, secrets)
    if not output_text.strip():
        return []

    findings: list[dict[str, Any]] = []
    if "NOPASSWD" in output_text:
        findings.append(
            _finding(
                target=target,
                title="Sudo NOPASSWD - Privilege Escalation Possible",
                severity="critical",
                summary=(
                    "sudo -l reported at least one NOPASSWD rule. The runner did not execute "
                    "the allowed command."
                ),
                evidence={"sudo_l_excerpt": output_text[:2000]},
            )
        )

    if re.search(r"\bALL\s*=\s*\(ALL(?::ALL)?\)\s*ALL\b", output_text):
        findings.append(
            _finding(
                target=target,
                title="Sudo Broad ALL Privileges Granted",
                severity="critical",
                summary="sudo -l reported broad ALL privileges for the configured account.",
                evidence={"sudo_l_excerpt": output_text[:2000]},
            )
        )

    dangerous_paths: set[str] = set()
    for match in re.finditer(r"(?:/[\w./+-]+)", output_text):
        command_path = match.group(0)
        if _path_basename(command_path) in DANGEROUS_SUDO_COMMANDS:
            dangerous_paths.add(command_path)
    for command_path in sorted(dangerous_paths):
        findings.append(
            _finding(
                target=target,
                title=f"Sudo Dangerous Command Allowed: {command_path}",
                severity="high",
                summary=(
                    f"sudo -l lists {command_path}, a command family with known local "
                    "privilege-escalation techniques. The command was not executed."
                ),
                evidence={"command": command_path, "sudo_l_excerpt": output_text[:2000]},
            )
        )
    return findings


def _parse_writable_cron(target: str, output: str, secrets: list[str]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for line in output.splitlines():
        parsed = _parse_mode_owner_path(line)
        if parsed is None:
            continue
        mode, owner, group, path = parsed
        if not _is_world_writable(mode):
            continue
        findings.append(
            _finding(
                target=target,
                title="Writable Cron Script - Privilege Escalation via Cron",
                severity="critical" if owner == "root" else "high",
                summary=f"{path} is writable by unprivileged users and is located under a cron path.",
                evidence={
                    "mode": mode,
                    "owner": owner,
                    "group": group,
                    "path": path,
                    "line": _redact(line, secrets),
                },
                control_family="configuration",
            )
        )
    return findings


def _parse_path_hijack(target: str, output: str, secrets: list[str]) -> list[dict[str, Any]]:
    path_dirs: list[str] = []
    writable_indexes: dict[int, str] = {}
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("PATH="):
            path_dirs = [item for item in line.removeprefix("PATH=").split(":") if item]
            continue
        parts = line.split(maxsplit=2)
        if len(parts) == 3 and parts[0] == "writable":
            try:
                writable_indexes[int(parts[1])] = parts[2]
            except ValueError:
                continue

    if not path_dirs:
        return []
    first_system_index = next(
        (index + 1 for index, directory in enumerate(path_dirs) if directory in SYSTEM_PATHS),
        len(path_dirs) + 1,
    )
    findings = []
    for index, directory in sorted(writable_indexes.items()):
        if index >= first_system_index:
            continue
        findings.append(
            _finding(
                target=target,
                title="Writable Directory Precedes System Path - PATH Hijacking Possible",
                severity="high",
                summary=(
                    f"{directory} is writable and appears before the first standard system "
                    "directory in PATH."
                ),
                evidence={
                    "path": _redact(":".join(path_dirs), secrets),
                    "directory": directory,
                    "position": index,
                },
                control_family="configuration",
            )
        )
    return findings


def _parse_weak_permissions(target: str, output: str, secrets: list[str]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    backup_markers: set[str] = set()
    for line in output.splitlines():
        if line.startswith("contains_secret_marker "):
            backup_markers.add(line.removeprefix("contains_secret_marker ").strip())

    for line in output.splitlines():
        parsed = _parse_mode_owner_path(line)
        if parsed is None:
            continue
        mode, owner, group, path = parsed
        if path == "/etc/passwd" and _is_world_writable(mode):
            findings.append(
                _finding(
                    target=target,
                    title="World-Writable /etc/passwd - Privilege Escalation Possible",
                    severity="critical",
                    summary="/etc/passwd is world-writable, allowing local account or password hash tampering.",
                    evidence={"mode": mode, "owner": owner, "group": group, "path": path},
                    control_family="configuration",
                )
            )
        if path == "/etc/shadow" and _is_world_readable(mode):
            findings.append(
                _finding(
                    target=target,
                    title="Readable /etc/shadow - Credential Exposure",
                    severity="critical",
                    summary="/etc/shadow is readable by unprivileged users, exposing password hashes.",
                    evidence={"mode": mode, "owner": owner, "group": group, "path": path},
                    control_family="configuration",
                )
            )
        if path in backup_markers:
            findings.append(
                _finding(
                    target=target,
                    title="Credential Backup File Exposed",
                    severity="high",
                    summary=f"{path} is readable and contains credential-like markers.",
                    evidence={
                        "mode": mode,
                        "owner": owner,
                        "group": group,
                        "path": path,
                        "secret_values_redacted": True,
                    },
                    control_family="configuration",
                )
            )
    return findings


def _version_tuple(text: str) -> tuple[int, int, int] | None:
    match = VERSION_PATTERN.search(text)
    if not match:
        return None
    return (int(match.group(1)), int(match.group(2)), int(match.group(3) or 0))


def _version_gte(value: tuple[int, int, int], minimum: tuple[int, int, int]) -> bool:
    return value >= minimum


def _version_lt(value: tuple[int, int, int], maximum: tuple[int, int, int]) -> bool:
    return value < maximum


def _parse_versions(target: str, output: str, secrets: list[str]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    redacted_output = _redact(output, secrets)
    kernel_line = next(
        (
            line
            for line in redacted_output.splitlines()
            if "kernel" in line.lower() or re.match(r"^\d+\.\d+", line.strip())
        ),
        "",
    )
    kernel_version = _version_tuple(kernel_line)
    if (
        kernel_version
        and _version_gte(kernel_version, (5, 8, 0))
        and _version_lt(kernel_version, (5, 16, 11))
    ):
        findings.append(
            _finding(
                target=target,
                title="Kernel Version Potentially Affected by CVE-2022-0847 DirtyPipe",
                severity="high",
                summary=(
                    "The reported Linux kernel version falls in the DirtyPipe affected range. "
                    "Backported vendor fixes must be verified before closure."
                ),
                evidence={"kernel_line": kernel_line},
                control_family="configuration",
            )
        )

    sudo_line = next(
        (line for line in redacted_output.splitlines() if line.lower().startswith("sudo version")),
        "",
    )
    sudo_version = _version_tuple(sudo_line)
    vulnerable_sudo_195 = bool(re.search(r"\b1\.9\.5p[01]\b", sudo_line))
    if sudo_version and (_version_lt(sudo_version, (1, 9, 5)) or vulnerable_sudo_195):
        findings.append(
            _finding(
                target=target,
                title="Sudo Version Potentially Affected by CVE-2021-3156 Baron Samedit",
                severity="high",
                summary=(
                    "sudo reports a version before 1.9.5p2, which may be affected by Baron "
                    "Samedit unless patched by the distribution."
                ),
                evidence={"sudo_line": sudo_line},
                control_family="configuration",
            )
        )
    return findings


def _parse_target_outputs(
    *,
    target: str,
    outputs: dict[str, str],
    secrets: list[str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    checks = [
        {
            "check": check_name,
            "output_excerpt": _redact(outputs.get(check_name, ""), secrets)[:2000],
            "output_lines": len(outputs.get(check_name, "").splitlines()),
        }
        for check_name, _command in ENUMERATION_COMMANDS
    ]
    findings = []
    findings.extend(_parse_suid_sgid(target, outputs.get("suid_sgid", ""), secrets))
    findings.extend(_parse_sudo(target, outputs.get("sudo_l", ""), secrets))
    findings.extend(_parse_writable_cron(target, outputs.get("cron", ""), secrets))
    findings.extend(_parse_path_hijack(target, outputs.get("path", ""), secrets))
    findings.extend(_parse_weak_permissions(target, outputs.get("permissions", ""), secrets))
    findings.extend(_parse_versions(target, outputs.get("versions", ""), secrets))
    return findings, checks


def _command_output_fixture(
    command_outputs: Any,
    *,
    target: str,
    check_name: str,
) -> str | None:
    if not isinstance(command_outputs, dict):
        return None
    nested = command_outputs.get(target)
    if isinstance(nested, dict) and isinstance(nested.get(check_name), str):
        return nested[check_name]
    composite = command_outputs.get(f"{target}:{check_name}")
    if isinstance(composite, str):
        return composite
    direct = command_outputs.get(check_name)
    if isinstance(direct, str):
        return direct
    return None


def _build_ssh_command(
    *,
    target: str,
    auth_context: dict[str, Any],
    remote_command: str,
    ssh_binary: str,
    sshpass_binary: str,
    default_ssh_port: int,
) -> tuple[list[str], dict[str, str], str]:
    username = str(auth_context.get("username") or "").strip()
    password = str(auth_context.get("password") or "").strip()
    identity_file = str(auth_context.get("ssh_identity_file") or "").strip()
    port = int(auth_context.get("port") or default_ssh_port)
    destination = f"{username}@{target}"
    ssh_args = [
        ssh_binary,
        "-o",
        "BatchMode=no" if password else "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-o",
        "ConnectTimeout=5",
        "-p",
        str(port),
    ]
    if identity_file:
        ssh_args.extend(["-i", identity_file])
    ssh_args.extend([destination, "sh", "-lc", remote_command])

    env = os.environ.copy()
    command = list(ssh_args)
    display_command = " ".join(shlex.quote(part) for part in ssh_args)
    if password:
        env["SSHPASS"] = password
        command = [sshpass_binary, "-e", *ssh_args]
        display_command = " ".join(shlex.quote(part) for part in [sshpass_binary, "-e", *ssh_args])
    return command, env, f"$ {display_command}"


def _run_command(
    command: list[str],
    *,
    env: dict[str, str],
    timeout_seconds: float,
    kill_switch_check: Callable[[], bool] | None,
    poll_interval_seconds: float,
) -> tuple[int, str, str, bool]:
    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
        )
    except OSError as exc:
        return 127, "", str(exc), False

    terminated_by_kill_switch = False
    started_at = time.monotonic()
    while process.poll() is None:
        if kill_switch_check is not None and bool(kill_switch_check()):
            terminated_by_kill_switch = True
            process.terminate()
            break
        if time.monotonic() - started_at >= max(timeout_seconds, 1.0):
            process.terminate()
            break
        time.sleep(max(poll_interval_seconds, 0.05))
    stdout, stderr = process.communicate()
    return int(process.returncode or 0), stdout or "", stderr or "", terminated_by_kill_switch


def execute_priv_esc_linux(
    targets: list[str],
    *,
    auth_contexts: list[dict[str, Any]] | object = None,
    scope_allowlist: dict[str, Any] | None = None,
    command_outputs: dict[str, Any] | None = None,
    ssh_binary: str = "ssh",
    sshpass_binary: str = "sshpass",
    ssh_port: int = 22,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    kill_switch_check: Callable[[], bool] | None = None,
    command_runner: (
        Callable[[list[str], dict[str, str], float], tuple[int, str, str]] | None
    ) = None,
    poll_interval_seconds: float = DEFAULT_POLL_INTERVAL_SECONDS,
) -> RunnerExecution:
    normalized_targets = _normalize_targets(targets, scope_allowlist)
    normalized_auth_contexts = _normalize_auth_contexts(auth_contexts)
    if not normalized_auth_contexts:
        raise ValueError(
            "priv-esc-linux requires at least one low-privileged SSH account with stored credentials"
        )
    bounded_timeout = max(min(float(timeout_seconds), DEFAULT_TIMEOUT_SECONDS), 1.0)
    bounded_ssh_port = _normalize_port(ssh_port) or 22
    secrets = [
        str(context.get("password") or "")
        for context in normalized_auth_contexts
        if str(context.get("password") or "").strip()
    ]

    all_findings: list[dict[str, Any]] = []
    all_checks: list[dict[str, Any]] = []
    target_results: list[dict[str, Any]] = []
    exit_code = 0
    killed = False

    for target in normalized_targets:
        auth_context = normalized_auth_contexts[0]
        outputs: dict[str, str] = {}
        commands: list[dict[str, Any]] = []
        target_errors: list[str] = []

        for check_name, remote_command in ENUMERATION_COMMANDS:
            fixture_output = _command_output_fixture(
                command_outputs, target=target, check_name=check_name
            )
            if fixture_output is not None:
                outputs[check_name] = fixture_output
                commands.append(
                    {
                        "check": check_name,
                        "mode": "fixture",
                        "read_only": True,
                        "exploitation_attempted": False,
                    }
                )
                continue

            command, env, display_command = _build_ssh_command(
                target=target,
                auth_context=auth_context,
                remote_command=remote_command,
                ssh_binary=ssh_binary,
                sshpass_binary=sshpass_binary,
                default_ssh_port=bounded_ssh_port,
            )
            if command_runner is not None:
                return_code, stdout, stderr = command_runner(command, env, bounded_timeout)
                terminated_by_kill_switch = False
            else:
                return_code, stdout, stderr, terminated_by_kill_switch = _run_command(
                    command,
                    env=env,
                    timeout_seconds=bounded_timeout,
                    kill_switch_check=kill_switch_check,
                    poll_interval_seconds=poll_interval_seconds,
                )
            killed = killed or terminated_by_kill_switch
            outputs[check_name] = stdout
            if return_code not in (0, 1):
                exit_code = max(exit_code, 1)
                target_errors.append(
                    _redact(stderr or f"{check_name} exited {return_code}", secrets)[:500]
                )
            commands.append(
                {
                    "check": check_name,
                    "mode": "ssh",
                    "command_preview": _redact(display_command, secrets),
                    "exit_code": return_code,
                    "read_only": True,
                    "exploitation_attempted": False,
                }
            )
            if terminated_by_kill_switch:
                break

        findings, checks = _parse_target_outputs(target=target, outputs=outputs, secrets=secrets)
        all_findings.extend(findings)
        all_checks.extend({"target": target, **check} for check in checks)
        target_results.append(
            {
                "target": target,
                "status": "kill_switch_halted" if killed else "completed",
                "account_label": str(
                    auth_context.get("label") or auth_context.get("username") or "SSH account"
                ),
                "checks_executed": [command["check"] for command in commands],
                "commands": commands,
                "errors": target_errors,
            }
        )
        if killed:
            exit_code = 130
            break

    payload = {
        "tool": "priv-esc-linux",
        "runner": "workers.runners.priv_esc_linux.runner",
        "targets": target_results,
        "checks": all_checks,
        "findings": all_findings,
        "safety": {
            "approval_gated": True,
            "intrusive_credential_required": True,
            "read_only_enumeration": True,
            "exploitation_attempted": False,
            "privilege_escalation_attempted": False,
            "target_filesystem_write_attempted": False,
            "suid_binary_executed": False,
            "sudo_privileged_command_executed": False,
            "sudo_policy_query_only": True,
            "runtime_self_modification": False,
            "kill_switch_halted": killed,
        },
    }
    return RunnerExecution(
        tool="priv-esc-linux",
        exit_code=exit_code,
        stdout=(
            f"Linux privilege escalation enumeration completed for {len(target_results)} "
            f"target(s); findings={len(all_findings)}."
        ),
        stderr="",
        metadata={
            "runner_digest": "workers.runners.priv_esc_linux.runner:v1",
            "tool_version": "priv-esc-linux-read-only",
            "read_only_enumeration": True,
            "intrusive_credential_required": True,
        },
        artifacts=[_json_artifact(payload)],
    )
