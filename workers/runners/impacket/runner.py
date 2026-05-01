from __future__ import annotations

import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
from typing import Any, Callable

from api.app.config import get_settings
from api.app.policy.engine import execution_kill_switch_enabled
from api.app.services.runs import target_value_is_allowed
from workers.runners.base.contracts import (
    EvidenceArtifact,
    ProtectedSecretMaterial,
    RunnerExecution,
)
from workers.runners.impacket.dcsync import build_dcsync_command
from workers.runners.impacket.remote_exec import (
    BOUNDED_REMOTE_COMMAND,
    build_remote_exec_command,
    parse_remote_exec_output,
)
from workers.runners.impacket.secretsdump import build_secretsdump_command, extract_hash_records

IMPACKET_RESULTS_ARTIFACT_NAME = "impacket-lateral-results.json"
IMPACKET_LOG_ARTIFACT_NAME = "impacket-lateral-session.log"
DEFAULT_MODE = "remote_exec"
DEFAULT_TIMEOUT_SECONDS = 180.0
DEFAULT_POLL_INTERVAL_SECONDS = 0.1
_SAFE_SLUG_PATTERN = re.compile(r"[^A-Za-z0-9._-]+")


def _safe_slug(value: str) -> str:
    return _SAFE_SLUG_PATTERN.sub("-", str(value or "").strip()).strip("-") or "target"


def _normalize_mode(value: object) -> str:
    normalized = str(value or DEFAULT_MODE).strip().lower()
    if normalized not in {"secretsdump", "remote_exec", "dcsync"}:
        raise ValueError("impacket-lateral mode must be secretsdump, remote_exec, or dcsync")
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


def _sanitize_text(value: str, secrets: list[str]) -> str:
    sanitized = str(value or "")
    for secret in secrets:
        candidate = str(secret or "").strip()
        if candidate:
            sanitized = sanitized.replace(candidate, "[REDACTED]")
    return sanitized


def _hash_redaction_tokens(records: list[dict[str, Any]]) -> list[str]:
    tokens: list[str] = []
    for record in records:
        if not isinstance(record, dict):
            continue
        for field_name in ("lm_hash", "nt_hash"):
            candidate = str(record.get(field_name) or "").strip()
            if candidate:
                tokens.append(candidate)
    return tokens


def _run_command(
    command: list[str],
    *,
    cwd: Path,
    timeout_seconds: float,
    kill_switch_check: Callable[[], bool] | None,
    poll_interval_seconds: float,
) -> tuple[int, str, str, bool]:
    process = subprocess.Popen(
        command,
        cwd=str(cwd),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=os.environ.copy(),
    )
    terminated_by_kill_switch = False
    started_at = time.monotonic()
    while process.poll() is None:
        if kill_switch_check is not None and bool(kill_switch_check()):
            terminated_by_kill_switch = True
            process.terminate()
            break
        if time.monotonic() - started_at >= max(float(timeout_seconds), 1.0):
            process.terminate()
            break
        time.sleep(max(float(poll_interval_seconds), 0.05))
    stdout, stderr = process.communicate()
    return int(process.returncode or 0), stdout or "", stderr or "", terminated_by_kill_switch


def _protected_hash_bundle(
    *,
    target: str,
    mode: str,
    records: list[dict[str, Any]],
    auth_context: dict[str, Any],
) -> str:
    return json.dumps(
        {
            "target": target,
            "mode": mode,
            "username": str(auth_context.get("username") or "").strip(),
            "domain": str(auth_context.get("domain") or "").strip() or None,
            "records": records,
            "raw_secret_material_exposed": False,
        },
        indent=2,
        sort_keys=True,
    )


def execute_impacket_lateral(
    targets: list[str],
    *,
    mode: str = DEFAULT_MODE,
    auth_contexts: list[dict[str, Any]] | object = None,
    remote_exec_method: str = "psexec",
    scope_allowlist: dict[str, Any] | None = None,
    secretsdump_binary: str = "secretsdump.py",
    psexec_binary: str = "psexec.py",
    wmiexec_binary: str = "wmiexec.py",
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    kill_switch_check: Callable[[], bool] | None = None,
    poll_interval_seconds: float = DEFAULT_POLL_INTERVAL_SECONDS,
) -> RunnerExecution:
    normalized_targets = [str(target).strip() for target in targets if str(target).strip()]
    if not normalized_targets:
        raise ValueError("impacket-lateral requires at least one approved host target")
    normalized_mode = _normalize_mode(mode)
    normalized_auth_contexts = _normalize_auth_contexts(auth_contexts)
    if not normalized_auth_contexts:
        raise ValueError(
            "impacket-lateral requires at least one credential context with password or NTLM hash"
        )

    scope_allowlist = scope_allowlist or {}
    for target in normalized_targets:
        if not target_value_is_allowed(scope_allowlist, target):
            raise ValueError(f"target outside scope: {target}")

    normalized_remote_exec_method = str(remote_exec_method or "psexec").strip().lower()
    if normalized_remote_exec_method not in {"psexec", "wmiexec"}:
        raise ValueError("remote_exec_method must be psexec or wmiexec")

    kill_switch = (
        kill_switch_check
        if kill_switch_check is not None
        else lambda: execution_kill_switch_enabled(get_settings())
    )
    secrets_to_redact = [
        str(value)
        for auth_context in normalized_auth_contexts
        for value in (
            auth_context.get("username"),
            auth_context.get("password"),
            auth_context.get("ntlm_hash"),
        )
        if value
    ]

    target_results: list[dict[str, Any]] = []
    protected_outputs: list[ProtectedSecretMaterial] = []
    log_sections: list[str] = []
    terminated_by_kill_switch = False

    with tempfile.TemporaryDirectory(prefix="aegispt-impacket-") as temp_dir_name:
        temp_dir = Path(temp_dir_name)
        for target in normalized_targets:
            auth_context = normalized_auth_contexts[0]
            host_dir = temp_dir / _safe_slug(target)
            host_dir.mkdir(parents=True, exist_ok=True)

            if normalized_mode == "secretsdump":
                command = build_secretsdump_command(
                    secretsdump_binary,
                    target=target,
                    auth_context=auth_context,
                )
                protected_kind = "impacket_hash_bundle"
                finding_title = f"Credential extraction confirmed on {target}"
                finding_severity = "high"
                protected_purpose = f"task.impacket.secretsdump.{_safe_slug(target)}"
                protected_label = f"Impacket secretsdump evidence for {target}"
            elif normalized_mode == "dcsync":
                command = build_dcsync_command(
                    secretsdump_binary,
                    target=target,
                    auth_context=auth_context,
                )
                protected_kind = "dcsync_hash_bundle"
                finding_title = "Domain compromise confirmed — DCSync successful"
                finding_severity = "critical"
                protected_purpose = f"task.impacket.dcsync.{_safe_slug(target)}"
                protected_label = f"Impacket DCSync evidence for {target}"
            else:
                remote_binary = (
                    psexec_binary if normalized_remote_exec_method == "psexec" else wmiexec_binary
                )
                command = build_remote_exec_command(
                    remote_binary,
                    method=normalized_remote_exec_method,
                    target=target,
                    auth_context=auth_context,
                )
                protected_kind = ""
                finding_title = (
                    f"Confirmed lateral movement to {target} as "
                    f"{str(auth_context.get('username') or '').strip() or 'unknown'}"
                )
                finding_severity = "critical"
                protected_purpose = ""
                protected_label = ""

            returncode, stdout, stderr, killed = _run_command(
                command,
                cwd=host_dir,
                timeout_seconds=timeout_seconds,
                kill_switch_check=kill_switch,
                poll_interval_seconds=poll_interval_seconds,
            )
            terminated_by_kill_switch = terminated_by_kill_switch or killed
            raw_output = "\n".join(part for part in (stdout, stderr) if part).strip()

            result: dict[str, Any] = {
                "target": target,
                "mode": normalized_mode,
                "status": "ok" if returncode == 0 or killed else "failed",
                "credential_label": str(
                    auth_context.get("label") or auth_context.get("username") or ""
                ).strip()
                or "Credential",
                "remote_exec_method": (
                    normalized_remote_exec_method if normalized_mode == "remote_exec" else None
                ),
                "analysis_findings": [],
                "protected_material_stored_as": (
                    "protected_secret_ref" if normalized_mode != "remote_exec" else "not_applicable"
                ),
            }

            if normalized_mode in {"secretsdump", "dcsync"}:
                records = extract_hash_records(raw_output, source=normalized_mode)
                visible_accounts = [record["account_name"] for record in records]
                if records:
                    protected_outputs.append(
                        ProtectedSecretMaterial(
                            artifact_name=f"impacket-{_safe_slug(target)}.json",
                            value=_protected_hash_bundle(
                                target=target,
                                mode=normalized_mode,
                                records=records,
                                auth_context=auth_context,
                            ),
                            secret_kind=protected_kind,
                            purpose=protected_purpose,
                            display_label=protected_label,
                            content_type="application/json",
                            metadata={"raw_secret_material_exposed": False},
                        )
                    )
                    result.update(
                        {
                            "extracted_account_count": len(records),
                            "extracted_accounts": visible_accounts,
                            "summary": (
                                "DCSync confirmed privileged directory replication access and stored protected krbtgt material."
                                if normalized_mode == "dcsync"
                                else f"Impacket secretsdump confirmed credential extraction on {target}; raw hash material remains encrypted outside the visible artifact trail."
                            ),
                            "analysis_findings": [
                                {
                                    "title": finding_title,
                                    "severity": finding_severity,
                                    "target_id": target,
                                    "summary": (
                                        "Impacket DCSync extracted protected krbtgt material and confirmed domain compromise without exposing raw hashes in visible logs or artifacts."
                                        if normalized_mode == "dcsync"
                                        else f"Impacket secretsdump extracted protected credential material from {target}; raw hashes remain encrypted outside the visible artifact trail."
                                    ),
                                    "methodology_tags": [
                                        "impacket",
                                        normalized_mode,
                                        "credential_access",
                                        "no_plaintext_hashes",
                                    ],
                                    "ptes_phase": "exploitation",
                                    "nist_phase": "credential_access",
                                    "control_family": "authentication",
                                }
                            ],
                        }
                    )
                else:
                    result["summary"] = (
                        f"Impacket {normalized_mode} did not return protected credential material for {target}."
                    )
            else:
                records = []
                output = parse_remote_exec_output(raw_output)
                whoami_value = str(output.get("whoami") or "").strip()
                hostname_value = str(output.get("hostname") or "").strip()
                if whoami_value and hostname_value:
                    result.update(
                        {
                            "summary": (
                                f"Impacket {normalized_remote_exec_method} confirmed bounded remote execution on {target} as {whoami_value} ({hostname_value})."
                            ),
                            "whoami": whoami_value,
                            "hostname": hostname_value,
                            "bounded_command": BOUNDED_REMOTE_COMMAND,
                            "analysis_findings": [
                                {
                                    "title": finding_title,
                                    "severity": finding_severity,
                                    "target_id": target,
                                    "summary": (
                                        f"Impacket {normalized_remote_exec_method} executed only whoami/hostname on {target}, confirmed execution context as {whoami_value}, and closed immediately."
                                    ),
                                    "methodology_tags": [
                                        "impacket",
                                        normalized_remote_exec_method,
                                        "lateral_movement",
                                        "bounded_remote_exec",
                                    ],
                                    "ptes_phase": "exploitation",
                                    "nist_phase": "lateral_movement",
                                    "control_family": "execution",
                                }
                            ],
                        }
                    )
                else:
                    result["summary"] = (
                        f"Impacket {normalized_remote_exec_method} did not return bounded execution proof for {target}."
                    )

            sanitized_log = _sanitize_text(
                raw_output,
                [*secrets_to_redact, *_hash_redaction_tokens(records)],
            )
            if sanitized_log:
                log_sections.append(f"## {target}\n{sanitized_log}")

            target_results.append(result)
            if terminated_by_kill_switch:
                break

        aggregate_payload = {
            "summary": {
                "mode": normalized_mode,
                "status": (
                    "cancelled"
                    if terminated_by_kill_switch
                    else (
                        "ok"
                        if any(result["analysis_findings"] for result in target_results)
                        else "failed"
                    )
                ),
                "target_count": len(target_results),
                "finding_count": sum(len(result["analysis_findings"]) for result in target_results),
                "terminated_by_kill_switch": terminated_by_kill_switch,
                "no_plaintext_hashes": normalized_mode != "remote_exec",
                "no_destructive_execution": normalized_mode == "remote_exec",
            },
            "targets": target_results,
        }
        artifacts = [
            EvidenceArtifact(
                name=IMPACKET_RESULTS_ARTIFACT_NAME,
                content_type="application/json",
                data=(json.dumps(aggregate_payload, indent=2, sort_keys=True) + "\n").encode(
                    "utf-8"
                ),
                kind="impacket-results",
            ),
            *[
                EvidenceArtifact(
                    name=f"impacket-{_safe_slug(result['target'])}.json",
                    content_type="application/json",
                    data=(json.dumps(result, indent=2, sort_keys=True) + "\n").encode("utf-8"),
                    kind="impacket-result",
                )
                for result in target_results
            ],
            EvidenceArtifact(
                name=IMPACKET_LOG_ARTIFACT_NAME,
                content_type="text/plain",
                data="\n\n".join(section for section in log_sections if section).encode("utf-8"),
                kind="execution-log",
            ),
        ]
        exit_code = (
            0
            if terminated_by_kill_switch
            or any(result["analysis_findings"] for result in target_results)
            else 1
        )
        return RunnerExecution(
            tool="impacket-lateral",
            exit_code=exit_code,
            stdout=(
                "Impacket lateral movement validation completed.\n"
                if exit_code == 0 and not terminated_by_kill_switch
                else ""
            ),
            stderr=(
                ""
                if exit_code == 0 or terminated_by_kill_switch
                else "Impacket lateral movement validation failed.\n"
            ),
            metadata={
                "status": aggregate_payload["summary"]["status"],
                "mode": normalized_mode,
                "tool_version": "impacket",
                "runner_digest": "workers.impacket.runner:v1",
                "terminated_by_kill_switch": terminated_by_kill_switch,
                "finding_count": aggregate_payload["summary"]["finding_count"],
                "no_plaintext_hashes": normalized_mode != "remote_exec",
                "no_destructive_execution": normalized_mode == "remote_exec",
            },
            artifacts=artifacts,
            protected_outputs=protected_outputs,
        )
