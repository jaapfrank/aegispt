from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Callable

from api.app.config import get_settings
from api.app.policy.engine import execution_kill_switch_enabled
from api.app.services.runs import target_value_is_allowed
from workers.runners.base.contracts import (
    EvidenceArtifact,
    ProtectedSecretMaterial,
    RunnerExecution,
)

NETEXEC_RESULTS_ARTIFACT_NAME = "netexec-results.json"
NETEXEC_LOG_ARTIFACT_NAME = "netexec-session.log"
DEFAULT_MODE = "passive"
DEFAULT_TIMEOUT_SECONDS = 180.0
DEFAULT_POLL_INTERVAL_SECONDS = 0.2
DEFAULT_SENSITIVE_PATTERNS = (
    "password",
    "credential",
    "secret",
    "finance",
    "payroll",
    "hr",
    "backup",
    "private",
    "vpn",
    "id_rsa",
    ".kdbx",
    ".pem",
    ".pfx",
    ".ovpn",
)

_FILENAME_SAFE_PATTERN = re.compile(r"[^A-Za-z0-9._-]+")
_SIGNING_PATTERN = re.compile(
    r"(?i)\b(?:signing|smb signing)\s*[:=]\s*(?P<value>true|false|enabled|disabled|required)\b"
)
_SMBV1_PATTERN = re.compile(
    r"(?i)\b(?:smbv1|smb1)\s*[:=]\s*(?P<value>true|false|enabled|disabled)\b"
)
_HOST_LINE_PATTERN = re.compile(
    r"(?i)\bSMB\b\s+(?P<target>\S+)\s+\d+\s+(?P<hostname>\S+)\s+\[[*+\-]\]\s*(?P<details>.*)"
)


def _normalize_binary(binary: str) -> str:
    normalized = str(binary or "").strip()
    if not normalized:
        raise ValueError("NetExec binary must not be blank")
    return normalized


def _normalize_mode(mode: str | None) -> str:
    normalized = str(mode or DEFAULT_MODE).strip().lower()
    if normalized not in {"passive", "intrusive"}:
        raise ValueError("NetExec mode must be passive or intrusive")
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
        ntlm_hash = str(raw_context.get("ntlm_hash") or "").strip()
        if not username or (not password and not ntlm_hash):
            continue
        normalized.append(
            {
                "label": str(raw_context.get("label") or username).strip() or username,
                "username": username,
                "password": password or None,
                "ntlm_hash": ntlm_hash or None,
                "domain": str(raw_context.get("domain") or "").strip() or None,
                "local_auth": bool(raw_context.get("local_auth", False)),
            }
        )
    return normalized


def _normalize_sensitive_patterns(value: Any) -> list[str]:
    if not isinstance(value, list):
        return list(DEFAULT_SENSITIVE_PATTERNS)
    normalized: list[str] = []
    for item in value:
        candidate = str(item or "").strip().lower()
        if candidate and candidate not in normalized:
            normalized.append(candidate)
    return normalized or list(DEFAULT_SENSITIVE_PATTERNS)


def _auth_args(auth_context: dict[str, Any] | None) -> list[str]:
    if auth_context is None:
        return ["-u", "", "-p", ""]

    username = str(auth_context.get("username") or "").strip()
    ntlm_hash = str(auth_context.get("ntlm_hash") or "").strip()
    password = str(auth_context.get("password") or "").strip()
    if not username or (not ntlm_hash and not password):
        raise ValueError("NetExec authenticated actions require username plus password or NTLM hash")

    args = ["-u", username]
    if ntlm_hash:
        args.extend(["-H", ntlm_hash])
    else:
        args.extend(["-p", password])

    domain = str(auth_context.get("domain") or "").strip()
    if domain and "\\" not in username and "@" not in username:
        args.extend(["-d", domain])
    if bool(auth_context.get("local_auth")):
        args.append("--local-auth")
    return args


def build_netexec_command(
    *,
    binary: str,
    target: str,
    action: str,
    auth_context: dict[str, Any] | None = None,
) -> list[str]:
    normalized_action = str(action or "").strip().lower()
    if normalized_action not in {
        "base",
        "shares",
        "loggedon-users",
        "local-group",
        "spider-plus",
    }:
        raise ValueError(f"Unsupported NetExec action: {action}")

    command = [_normalize_binary(binary), "smb", str(target).strip()]
    if normalized_action == "base":
        return command

    command.extend(_auth_args(auth_context))
    if normalized_action == "shares":
        command.append("--shares")
    elif normalized_action == "loggedon-users":
        command.append("--loggedon-users")
    elif normalized_action == "local-group":
        command.append("--local-group")
    elif normalized_action == "spider-plus":
        command.extend(["-M", "spider_plus"])
    return command


def get_netexec_version(binary: str) -> str:
    try:
        result = subprocess.run(
            [_normalize_binary(binary), "--version"],
            capture_output=True,
            text=True,
            check=False,
            timeout=5.0,
        )
    except (OSError, subprocess.TimeoutExpired):
        return Path(binary).name or "nxc"

    output = (result.stdout or result.stderr).strip()
    if not output:
        return Path(binary).name or "nxc"
    return output.splitlines()[0].strip()


def _safe_target_slug(value: str) -> str:
    return _FILENAME_SAFE_PATTERN.sub("-", str(value or "").strip()).strip("-") or "target"


def _sanitize_text(value: str, secrets: list[str]) -> str:
    sanitized = value or ""
    for secret in secrets:
        candidate = str(secret or "").strip()
        if candidate:
            sanitized = sanitized.replace(candidate, "[REDACTED]")
    return sanitized


def _bool_from_value(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    normalized = str(value or "").strip().lower()
    if normalized in {"true", "enabled", "yes", "required"}:
        return True
    if normalized in {"false", "disabled", "no"}:
        return False
    return None


def _empty_target_result(target: str, *, mode: str) -> dict[str, Any]:
    return {
        "target": target,
        "mode": mode,
        "status": "ok",
        "host": {
            "reachable": False,
            "hostname": None,
            "domain": None,
            "os": None,
            "signing": None,
            "smb_v1": None,
        },
        "null_session_enabled": False,
        "auth_attempts": [],
        "shares": [],
        "loggedon_users": [],
        "local_groups": [],
        "spider_files": [],
        "analysis_findings": [],
        "errors": [],
    }


def _append_unique(rows: list[dict[str, Any]], item: dict[str, Any], signature: tuple[Any, ...]) -> None:
    if any(
        tuple(existing.get(key) for key in item.keys()) == signature
        for existing in rows
        if isinstance(existing, dict)
    ):
        return
    rows.append(item)


def _append_auth_attempt(target_result: dict[str, Any], *, auth_context: dict[str, Any], success: bool, admin_access: bool) -> None:
    credential_type = "ntlm_hash" if auth_context.get("ntlm_hash") else "password"
    item = {
        "label": str(auth_context.get("label") or auth_context.get("username") or "Account").strip()
        or "Account",
        "username": str(auth_context.get("username") or "").strip(),
        "credential_type": credential_type,
        "domain": str(auth_context.get("domain") or "").strip() or None,
        "local_auth": bool(auth_context.get("local_auth", False)),
        "success": bool(success),
        "admin_access": bool(admin_access),
    }
    signature = (
        item["label"],
        item["username"],
        item["credential_type"],
        item["domain"],
        item["local_auth"],
        item["success"],
        item["admin_access"],
    )
    if not any(
        isinstance(existing, dict)
        and (
            existing.get("label"),
            existing.get("username"),
            existing.get("credential_type"),
            existing.get("domain"),
            existing.get("local_auth"),
            existing.get("success"),
            existing.get("admin_access"),
        )
        == signature
        for existing in target_result["auth_attempts"]
    ):
        target_result["auth_attempts"].append(item)


def _append_share(target_result: dict[str, Any], *, name: str, permissions: list[str], anonymous: bool = False) -> None:
    normalized_permissions = []
    for permission in permissions:
        candidate = str(permission or "").strip().upper()
        if candidate and candidate not in normalized_permissions:
            normalized_permissions.append(candidate)
    item = {
        "name": name,
        "permissions": normalized_permissions,
        "anonymous": bool(anonymous),
    }
    signature = (item["name"], tuple(item["permissions"]), item["anonymous"])
    if not any(
        isinstance(existing, dict)
        and (
            existing.get("name"),
            tuple(existing.get("permissions") or []),
            bool(existing.get("anonymous")),
        )
        == signature
        for existing in target_result["shares"]
    ):
        target_result["shares"].append(item)


def _append_loggedon_user(target_result: dict[str, Any], *, username: str) -> None:
    candidate = str(username or "").strip()
    if not candidate:
        return
    if not any(existing == candidate for existing in target_result["loggedon_users"]):
        target_result["loggedon_users"].append(candidate)


def _append_local_group(target_result: dict[str, Any], *, name: str, members: list[str]) -> None:
    candidate_name = str(name or "").strip()
    if not candidate_name:
        return
    normalized_members = [
        str(member).strip()
        for member in members
        if str(member).strip()
    ]
    signature = (candidate_name, tuple(normalized_members))
    if not any(
        isinstance(existing, dict)
        and (existing.get("name"), tuple(existing.get("members") or [])) == signature
        for existing in target_result["local_groups"]
    ):
        target_result["local_groups"].append({"name": candidate_name, "members": normalized_members})


def _append_spider_file(target_result: dict[str, Any], *, share: str, path: str) -> None:
    candidate_share = str(share or "").strip() or "UNKNOWN"
    candidate_path = str(path or "").strip()
    if not candidate_path:
        return
    signature = (candidate_share, candidate_path)
    if not any(
        isinstance(existing, dict)
        and (existing.get("share"), existing.get("path")) == signature
        for existing in target_result["spider_files"]
    ):
        target_result["spider_files"].append({"share": candidate_share, "path": candidate_path})


def _apply_structured_record(
    target_result: dict[str, Any],
    record: dict[str, Any],
    *,
    default_target: str,
    auth_context: dict[str, Any] | None,
) -> None:
    record_type = str(record.get("record_type") or "").strip().lower()
    host_target = str(record.get("target") or default_target).strip() or default_target
    target_result["target"] = host_target

    if record_type in {"host", ""} and any(
        field in record for field in ("hostname", "os", "signing", "smb_v1", "reachable")
    ):
        host = target_result["host"]
        host["reachable"] = bool(record.get("reachable", host["reachable"]))
        for field_name in ("hostname", "domain", "os"):
            value = str(record.get(field_name) or "").strip()
            if value:
                host[field_name] = value
        for field_name in ("signing", "smb_v1"):
            if field_name in record:
                normalized_bool = _bool_from_value(record.get(field_name))
                if normalized_bool is not None:
                    host[field_name] = normalized_bool
        return

    if record_type == "share":
        permissions = record.get("permissions")
        _append_share(
            target_result,
            name=str(record.get("name") or "").strip(),
            permissions=permissions if isinstance(permissions, list) else [str(permissions or "").strip()],
            anonymous=bool(record.get("anonymous", False)),
        )
        if bool(record.get("anonymous", False)):
            target_result["null_session_enabled"] = True
        return

    if record_type == "null_session":
        target_result["null_session_enabled"] = bool(record.get("enabled", False))
        return

    if record_type == "auth" and auth_context is not None:
        _append_auth_attempt(
            target_result,
            auth_context=auth_context,
            success=bool(record.get("success", False)),
            admin_access=bool(record.get("admin_access", False) or record.get("pwned", False)),
        )
        return

    if record_type == "loggedon_user":
        _append_loggedon_user(
            target_result,
            username=str(record.get("username") or "").strip(),
        )
        return

    if record_type == "local_group":
        members = record.get("members")
        _append_local_group(
            target_result,
            name=str(record.get("name") or "").strip(),
            members=members if isinstance(members, list) else [],
        )
        return

    if record_type == "spider_file":
        _append_spider_file(
            target_result,
            share=str(record.get("share") or "").strip(),
            path=str(record.get("path") or "").strip(),
        )


def _parse_structured_records(text: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for raw_line in (text or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            records.append(payload)
        elif isinstance(payload, list):
            records.extend(item for item in payload if isinstance(item, dict))
    return records


def _apply_heuristic_line(
    target_result: dict[str, Any],
    line: str,
    *,
    action: str,
    auth_context: dict[str, Any] | None,
) -> None:
    candidate = line.strip()
    if not candidate:
        return

    host_match = _HOST_LINE_PATTERN.search(candidate)
    if host_match is not None:
        target_result["host"]["reachable"] = True
        hostname = str(host_match.group("hostname") or "").strip()
        if hostname:
            target_result["host"]["hostname"] = hostname

    signing_match = _SIGNING_PATTERN.search(candidate)
    if signing_match is not None:
        signing_value = _bool_from_value(signing_match.group("value"))
        if signing_value is not None:
            target_result["host"]["signing"] = signing_value
            target_result["host"]["reachable"] = True

    smbv1_match = _SMBV1_PATTERN.search(candidate)
    if smbv1_match is not None:
        smbv1_value = _bool_from_value(smbv1_match.group("value"))
        if smbv1_value is not None:
            target_result["host"]["smb_v1"] = smbv1_value

    if action == "shares" and auth_context is None:
        if "anonymous" in candidate.lower() or "null session" in candidate.lower():
            target_result["null_session_enabled"] = True

    if auth_context is not None and "[+]" in candidate:
        _append_auth_attempt(
            target_result,
            auth_context=auth_context,
            success=True,
            admin_access="pwn3d!" in candidate.lower(),
        )


def _merge_command_output(
    target_result: dict[str, Any],
    *,
    stdout: str,
    stderr: str,
    action: str,
    auth_context: dict[str, Any] | None,
) -> None:
    combined_text = "\n".join(part for part in (stdout, stderr) if part).strip()
    for record in _parse_structured_records(combined_text):
        _apply_structured_record(
            target_result,
            record,
            default_target=str(target_result["target"]),
            auth_context=auth_context,
        )

    for line in combined_text.splitlines():
        _apply_heuristic_line(
            target_result,
            line,
            action=action,
            auth_context=auth_context,
        )


def _extract_spider_file_records(payload: Any, *, default_target: str) -> list[dict[str, str]]:
    records: list[dict[str, str]] = []

    if isinstance(payload, dict):
        files = payload.get("files")
        if isinstance(files, list):
            for item in files:
                if not isinstance(item, dict):
                    continue
                share = str(item.get("share") or payload.get("share") or "UNKNOWN").strip()
                path = str(item.get("path") or item.get("name") or "").strip()
                if path:
                    records.append(
                        {
                            "target": str(payload.get("target") or default_target).strip() or default_target,
                            "share": share or "UNKNOWN",
                            "path": path,
                        }
                    )
        for key in ("shares", "results"):
            value = payload.get(key)
            if isinstance(value, list):
                records.extend(_extract_spider_file_records(value, default_target=default_target))
        return records

    if isinstance(payload, list):
        for item in payload:
            records.extend(_extract_spider_file_records(item, default_target=default_target))

    return records


def _load_spider_results(directory: Path, *, existing_files: set[Path], default_target: str) -> list[dict[str, str]]:
    spider_records: list[dict[str, str]] = []
    for path in sorted(directory.glob("*.json")):
        if path in existing_files:
            continue
        try:
            payload = json.loads(path.read_text("utf-8", errors="replace"))
        except json.JSONDecodeError:
            continue
        spider_records.extend(_extract_spider_file_records(payload, default_target=default_target))
    return spider_records


def _run_command(
    command: list[str],
    *,
    cwd: Path,
    timeout_seconds: float,
    kill_switch_check: Callable[[], bool],
    poll_interval_seconds: float,
) -> tuple[int, str, str, bool, bool]:
    process = subprocess.Popen(
        command,
        cwd=str(cwd),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=os.environ.copy(),
    )
    started_at = time.monotonic()
    timed_out = False
    terminated_by_kill_switch = False
    while process.poll() is None:
        if kill_switch_check():
            terminated_by_kill_switch = True
            process.terminate()
            break
        if time.monotonic() - started_at >= max(timeout_seconds, 1.0):
            timed_out = True
            process.terminate()
            break
        time.sleep(max(poll_interval_seconds, 0.05))

    stdout, stderr = process.communicate()
    return int(process.returncode or 0), stdout, stderr, timed_out, terminated_by_kill_switch


def _target_findings(
    target_result: dict[str, Any],
    *,
    sensitive_patterns: list[str],
) -> tuple[list[dict[str, Any]], ProtectedSecretMaterial | None]:
    target = str(target_result.get("target") or "").strip() or "target"
    findings: list[dict[str, Any]] = []
    protected_output = None

    host = target_result.get("host", {})
    signing_disabled = isinstance(host, dict) and host.get("signing") is False
    if signing_disabled:
        findings.append(
            {
                "title": f"SMB signing disabled on {target}",
                "severity": "high",
                "target_id": target,
                "summary": (
                    f"NetExec SMB enumeration observed signing disabled on {target}, which increases relay and tampering risk on the internal network."
                ),
                "methodology_tags": ["internal_network", "smb", "signing"],
                "control_family": "configuration",
            }
        )

    anonymous_shares = [
        share
        for share in target_result.get("shares", [])
        if isinstance(share, dict) and bool(share.get("anonymous", False))
    ]
    if bool(target_result.get("null_session_enabled")) or anonymous_shares:
        severity = "high" if anonymous_shares else "medium"
        share_suffix = ""
        if anonymous_shares:
            share_suffix = " Anonymous access was observed on: " + ", ".join(
                str(share.get("name") or "UNKNOWN") for share in anonymous_shares[:5]
            ) + "."
        findings.append(
            {
                "title": f"Anonymous SMB null session access on {target}",
                "severity": severity,
                "target_id": target,
                "summary": (
                    f"NetExec SMB enumeration observed null-session or anonymous access on {target}.{share_suffix}"
                ).strip(),
                "methodology_tags": ["internal_network", "smb", "null_session"],
                "control_family": "authorization",
            }
        )

    sensitive_matches_by_share: dict[str, list[str]] = {}
    for spider_file in target_result.get("spider_files", []):
        if not isinstance(spider_file, dict):
            continue
        path = str(spider_file.get("path") or "").strip()
        share = str(spider_file.get("share") or "UNKNOWN").strip() or "UNKNOWN"
        haystack = f"{share} {path}".lower()
        if any(pattern in haystack for pattern in sensitive_patterns):
            sensitive_matches_by_share.setdefault(share, [])
            if path not in sensitive_matches_by_share[share]:
                sensitive_matches_by_share[share].append(path)

    for share, paths in sorted(sensitive_matches_by_share.items()):
        findings.append(
            {
                "title": f"Sensitive SMB share content exposed on {target}",
                "severity": "high",
                "target_id": target,
                "summary": (
                    f"NetExec spider_plus enumeration identified potentially sensitive content in share {share} on {target}: "
                    + ", ".join(paths[:3])
                    + "."
                ),
                "methodology_tags": ["internal_network", "smb", "share_exposure"],
                "control_family": "authorization",
            }
        )

    successful_pth_attempt = next(
        (
            attempt
            for attempt in target_result.get("auth_attempts", [])
            if isinstance(attempt, dict)
            and attempt.get("credential_type") == "ntlm_hash"
            and bool(attempt.get("success", False))
        ),
        None,
    )
    if successful_pth_attempt is not None:
        findings.append(
            {
                "title": f"Pass-the-hash SMB access succeeded on {target}",
                "severity": "critical",
                "target_id": target,
                "summary": (
                    f"NetExec validated NTLM hash reuse against {target} using account {successful_pth_attempt.get('label') or successful_pth_attempt.get('username') or 'hash-backed account'}."
                ),
                "methodology_tags": ["internal_network", "smb", "pass_the_hash"],
                "control_family": "authentication",
            }
        )
        auth_context = target_result.get("_successful_hash_context")
        if isinstance(auth_context, dict):
            ntlm_hash = str(auth_context.get("ntlm_hash") or "").strip()
            if ntlm_hash:
                protected_output = ProtectedSecretMaterial(
                    artifact_name=f"netexec-{_safe_target_slug(target)}.json",
                    value=json.dumps(
                        {
                            "target": target,
                            "username": str(auth_context.get("username") or "").strip(),
                            "domain": str(auth_context.get("domain") or "").strip() or None,
                            "ntlm_hash": ntlm_hash,
                            "local_auth": bool(auth_context.get("local_auth", False)),
                            "admin_access": bool(successful_pth_attempt.get("admin_access", False)),
                            "share_count": len(target_result.get("shares", [])),
                            "loggedon_user_count": len(target_result.get("loggedon_users", [])),
                            "raw_secret_material_exposed": False,
                        },
                        indent=2,
                        sort_keys=True,
                    ),
                    secret_kind="ntlm_hash_validation_bundle",
                    purpose=f"task.netexec.pass_the_hash.{_safe_target_slug(target)}",
                    display_label=f"Validated NTLM hash evidence for {target}",
                    content_type="application/json",
                    metadata={"raw_secret_material_exposed": False},
                )

    return findings, protected_output


def execute_netexec_smb(
    targets: list[str],
    *,
    mode: str = DEFAULT_MODE,
    auth_contexts: list[dict[str, Any]] | object = None,
    scope_allowlist: dict[str, Any] | None = None,
    binary: str = "nxc",
    sensitive_patterns: list[str] | object = None,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    kill_switch_check: Callable[[], bool] | None = None,
    poll_interval_seconds: float = DEFAULT_POLL_INTERVAL_SECONDS,
) -> RunnerExecution:
    normalized_targets = [str(target).strip() for target in targets if str(target).strip()]
    if not normalized_targets:
        raise ValueError("netexec requires at least one target")

    normalized_mode = _normalize_mode(mode)
    normalized_auth_contexts = _normalize_auth_contexts(auth_contexts)
    if normalized_mode == "intrusive" and not normalized_auth_contexts:
        raise ValueError("intrusive NetExec requires at least one authenticated SMB context")

    scope_allowlist = scope_allowlist or {}
    for target in normalized_targets:
        if not target_value_is_allowed(scope_allowlist, target):
            raise ValueError(f"target outside scope: {target}")

    kill_switch = (
        kill_switch_check
        if kill_switch_check is not None
        else lambda: execution_kill_switch_enabled(get_settings())
    )
    binary_path = _normalize_binary(binary)
    normalized_patterns = _normalize_sensitive_patterns(sensitive_patterns)
    tool_version = get_netexec_version(binary_path)

    target_results: list[dict[str, Any]] = []
    protected_outputs: list[ProtectedSecretMaterial] = []
    log_sections: list[str] = []
    terminated_by_kill_switch = False

    with tempfile.TemporaryDirectory(prefix="aegispt-netexec-") as temp_dir_name:
        temp_dir = Path(temp_dir_name)

        for target in normalized_targets:
            target_result = _empty_target_result(target, mode=normalized_mode)
            host_dir = temp_dir / _safe_target_slug(target)
            host_dir.mkdir(parents=True, exist_ok=True)
            secrets_to_redact = []
            for auth_context in normalized_auth_contexts:
                secrets_to_redact.extend(
                    [
                        str(auth_context.get("username") or ""),
                        str(auth_context.get("password") or ""),
                        str(auth_context.get("ntlm_hash") or ""),
                    ]
                )

            base_command = build_netexec_command(
                binary=binary_path,
                target=target,
                action="base",
            )
            base_returncode, base_stdout, base_stderr, base_timed_out, base_killed = _run_command(
                base_command,
                cwd=host_dir,
                timeout_seconds=timeout_seconds,
                kill_switch_check=kill_switch,
                poll_interval_seconds=poll_interval_seconds,
            )
            terminated_by_kill_switch = terminated_by_kill_switch or base_killed
            _merge_command_output(
                target_result,
                stdout=base_stdout,
                stderr=base_stderr,
                action="base",
                auth_context=None,
            )
            sanitized_base_log = _sanitize_text(
                "\n".join(part for part in (base_stdout, base_stderr) if part).strip(),
                secrets_to_redact,
            )
            if sanitized_base_log:
                log_sections.append(f"## {target} / base\n{sanitized_base_log}")
            if base_timed_out:
                target_result["errors"].append("NetExec base SMB probe timed out")
            elif base_returncode != 0 and not sanitized_base_log:
                target_result["errors"].append("NetExec base SMB probe returned a non-zero exit code")

            if normalized_mode == "passive":
                shares_command = build_netexec_command(
                    binary=binary_path,
                    target=target,
                    action="shares",
                    auth_context=None,
                )
                shares_returncode, shares_stdout, shares_stderr, shares_timed_out, shares_killed = _run_command(
                    shares_command,
                    cwd=host_dir,
                    timeout_seconds=timeout_seconds,
                    kill_switch_check=kill_switch,
                    poll_interval_seconds=poll_interval_seconds,
                )
                terminated_by_kill_switch = terminated_by_kill_switch or shares_killed
                _merge_command_output(
                    target_result,
                    stdout=shares_stdout,
                    stderr=shares_stderr,
                    action="shares",
                    auth_context=None,
                )
                sanitized_shares_log = _sanitize_text(
                    "\n".join(part for part in (shares_stdout, shares_stderr) if part).strip(),
                    secrets_to_redact,
                )
                if sanitized_shares_log:
                    log_sections.append(f"## {target} / shares\n{sanitized_shares_log}")
                if shares_timed_out:
                    target_result["errors"].append("NetExec passive SMB share enumeration timed out")
                elif shares_returncode != 0 and not sanitized_shares_log:
                    target_result["errors"].append("NetExec passive SMB share enumeration failed")
            else:
                successful_context: dict[str, Any] | None = None
                for auth_context in normalized_auth_contexts:
                    shares_command = build_netexec_command(
                        binary=binary_path,
                        target=target,
                        action="shares",
                        auth_context=auth_context,
                    )
                    shares_returncode, shares_stdout, shares_stderr, shares_timed_out, shares_killed = _run_command(
                        shares_command,
                        cwd=host_dir,
                        timeout_seconds=timeout_seconds,
                        kill_switch_check=kill_switch,
                        poll_interval_seconds=poll_interval_seconds,
                    )
                    terminated_by_kill_switch = terminated_by_kill_switch or shares_killed
                    _merge_command_output(
                        target_result,
                        stdout=shares_stdout,
                        stderr=shares_stderr,
                        action="shares",
                        auth_context=auth_context,
                    )

                    sanitized_shares_log = _sanitize_text(
                        "\n".join(part for part in (shares_stdout, shares_stderr) if part).strip(),
                        secrets_to_redact,
                    )
                    if sanitized_shares_log:
                        label = str(auth_context.get("label") or auth_context.get("username") or "account").strip()
                        log_sections.append(f"## {target} / shares / {label}\n{sanitized_shares_log}")

                    if shares_timed_out:
                        target_result["errors"].append(
                            f"NetExec authenticated SMB share enumeration timed out for {auth_context.get('label') or auth_context.get('username') or 'account'}"
                        )
                        continue

                    matching_attempts = [
                        attempt
                        for attempt in target_result["auth_attempts"]
                        if isinstance(attempt, dict)
                        and attempt.get("username") == str(auth_context.get("username") or "").strip()
                        and attempt.get("credential_type")
                        == ("ntlm_hash" if auth_context.get("ntlm_hash") else "password")
                    ]
                    if not matching_attempts and shares_returncode == 0 and target_result["shares"]:
                        _append_auth_attempt(
                            target_result,
                            auth_context=auth_context,
                            success=True,
                            admin_access=False,
                        )
                        matching_attempts = [
                            attempt
                            for attempt in target_result["auth_attempts"]
                            if isinstance(attempt, dict)
                            and attempt.get("username") == str(auth_context.get("username") or "").strip()
                            and attempt.get("credential_type")
                            == ("ntlm_hash" if auth_context.get("ntlm_hash") else "password")
                        ]

                    successful_attempt = next(
                        (
                            attempt
                            for attempt in matching_attempts
                            if bool(attempt.get("success", False))
                        ),
                        None,
                    )
                    if successful_attempt is None:
                        if shares_returncode != 0 and not sanitized_shares_log:
                            target_result["errors"].append(
                                f"NetExec authenticated SMB share enumeration failed for {auth_context.get('label') or auth_context.get('username') or 'account'}"
                            )
                        continue

                    successful_context = auth_context
                    if auth_context.get("ntlm_hash"):
                        target_result["_successful_hash_context"] = dict(auth_context)

                    for action in ("loggedon-users", "local-group", "spider-plus"):
                        existing_json_files = set(host_dir.glob("*.json"))
                        command = build_netexec_command(
                            binary=binary_path,
                            target=target,
                            action=action,
                            auth_context=auth_context,
                        )
                        action_returncode, action_stdout, action_stderr, action_timed_out, action_killed = _run_command(
                            command,
                            cwd=host_dir,
                            timeout_seconds=timeout_seconds,
                            kill_switch_check=kill_switch,
                            poll_interval_seconds=poll_interval_seconds,
                        )
                        terminated_by_kill_switch = terminated_by_kill_switch or action_killed
                        _merge_command_output(
                            target_result,
                            stdout=action_stdout,
                            stderr=action_stderr,
                            action=action,
                            auth_context=auth_context,
                        )
                        if action == "spider-plus":
                            for spider_record in _load_spider_results(
                                host_dir,
                                existing_files=existing_json_files,
                                default_target=target,
                            ):
                                _append_spider_file(
                                    target_result,
                                    share=spider_record["share"],
                                    path=spider_record["path"],
                                )
                        sanitized_action_log = _sanitize_text(
                            "\n".join(part for part in (action_stdout, action_stderr) if part).strip(),
                            secrets_to_redact,
                        )
                        if sanitized_action_log:
                            label = str(auth_context.get("label") or auth_context.get("username") or "account").strip()
                            log_sections.append(f"## {target} / {action} / {label}\n{sanitized_action_log}")
                        if action_timed_out:
                            target_result["errors"].append(
                                f"NetExec {action} timed out for {auth_context.get('label') or auth_context.get('username') or 'account'}"
                            )
                        elif action_returncode != 0 and not sanitized_action_log:
                            target_result["errors"].append(
                                f"NetExec {action} failed for {auth_context.get('label') or auth_context.get('username') or 'account'}"
                            )
                    break

                if successful_context is None:
                    target_result["errors"].append("No authenticated SMB context succeeded on this host")

            target_result["host"]["reachable"] = bool(
                target_result["host"]["reachable"]
                or target_result["host"]["hostname"]
                or target_result["shares"]
                or target_result["auth_attempts"]
            )
            analysis_findings, protected_output = _target_findings(
                target_result,
                sensitive_patterns=normalized_patterns,
            )
            target_result["analysis_findings"] = analysis_findings
            if protected_output is not None:
                protected_outputs.append(protected_output)

            if target_result["errors"] and (
                target_result["analysis_findings"]
                or target_result["shares"]
                or target_result["auth_attempts"]
                or target_result["host"]["reachable"]
            ):
                target_result["status"] = "partial"
            elif target_result["errors"]:
                target_result["status"] = "failed"

            target_result.pop("_successful_hash_context", None)
            target_results.append(target_result)

    aggregate_payload = {
        "summary": {
            "mode": normalized_mode,
            "target_count": len(target_results),
            "finding_count": sum(len(result["analysis_findings"]) for result in target_results),
            "successful_auth_count": sum(
                1
                for result in target_results
                for attempt in result.get("auth_attempts", [])
                if isinstance(attempt, dict) and bool(attempt.get("success", False))
            ),
            "pass_the_hash_success_count": sum(
                1
                for result in target_results
                for attempt in result.get("auth_attempts", [])
                if isinstance(attempt, dict)
                and bool(attempt.get("success", False))
                and attempt.get("credential_type") == "ntlm_hash"
            ),
            "terminated_by_kill_switch": terminated_by_kill_switch,
        },
        "targets": target_results,
    }
    per_host_artifacts = [
        EvidenceArtifact(
            name=f"netexec-{_safe_target_slug(result['target'])}.json",
            content_type="application/json",
            data=json.dumps(result, indent=2, sort_keys=True).encode("utf-8"),
            kind="smb-host-results",
        )
        for result in target_results
    ]
    artifacts = [
        EvidenceArtifact(
            name=NETEXEC_RESULTS_ARTIFACT_NAME,
            content_type="application/json",
            data=json.dumps(aggregate_payload, indent=2, sort_keys=True).encode("utf-8"),
            kind="smb-results",
        ),
        *per_host_artifacts,
        EvidenceArtifact(
            name=NETEXEC_LOG_ARTIFACT_NAME,
            content_type="text/plain",
            data="\n\n".join(section for section in log_sections if section).encode("utf-8"),
            kind="execution-log",
        ),
    ]

    exit_code = 0 if any(result["status"] in {"ok", "partial"} for result in target_results) else 1
    return RunnerExecution(
        tool="netexec",
        exit_code=exit_code,
        stdout="NetExec SMB validation completed.\n" if exit_code == 0 else "",
        stderr="" if exit_code == 0 else "NetExec SMB validation failed.\n",
        metadata={
            "status": "ok" if exit_code == 0 else "failed",
            "mode": normalized_mode,
            "tool_version": tool_version,
            "runner_digest": "workers.netexec.runner:v1",
            "finding_count": aggregate_payload["summary"]["finding_count"],
            "successful_auth_count": aggregate_payload["summary"]["successful_auth_count"],
            "pass_the_hash_success_count": aggregate_payload["summary"]["pass_the_hash_success_count"],
            "terminated_by_kill_switch": terminated_by_kill_switch,
            "read_only": normalized_mode == "passive",
        },
        artifacts=artifacts,
        protected_outputs=protected_outputs,
    )
