from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
from typing import Any

from api.app.services.bloodhound_analysis import analyze_bloodhound_collection
from api.app.services.runs import target_value_is_allowed
from workers.runners.base.contracts import EvidenceArtifact, ProtectedSecretMaterial, RunnerExecution

BLOODHOUND_COLLECTION_ARTIFACT_NAME = "bloodhound-collection.zip"
BLOODHOUND_RESULTS_ARTIFACT_NAME = "bloodhound-results.json"
BLOODHOUND_LOG_ARTIFACT_NAME = "bloodhound-session.log"
DEFAULT_COLLECTION_METHODS = ("All",)
DEFAULT_TIMEOUT_SECONDS = 300.0


def _normalize_collection_methods(value: Any) -> list[str]:
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list):
        return list(DEFAULT_COLLECTION_METHODS)
    normalized: list[str] = []
    for item in value:
        candidate = str(item or "").strip()
        if candidate and candidate not in normalized:
            normalized.append(candidate)
    return normalized or list(DEFAULT_COLLECTION_METHODS)


def _normalize_auth_contexts(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    normalized: list[dict[str, Any]] = []
    for raw_context in value:
        if not isinstance(raw_context, dict):
            continue
        username = str(raw_context.get("username") or "").strip()
        password = str(raw_context.get("password") or "").strip()
        domain = str(raw_context.get("domain") or "").strip()
        if not username or not password:
            continue
        normalized.append(
            {
                "label": str(raw_context.get("label") or username).strip() or username,
                "username": username,
                "password": password,
                "domain": domain or None,
            }
        )
    return normalized


def _looks_like_ip(value: str) -> bool:
    if not value or any(char not in "0123456789.:" for char in value):
        return False
    return any(char.isdigit() for char in value)


def _domain_for_target(
    *,
    target: str,
    auth_context: dict[str, Any],
    configured_domain: str | None,
) -> str:
    if configured_domain:
        return configured_domain
    username = str(auth_context.get("username") or "")
    if "@" in username:
        return username.split("@", 1)[1].strip().lower()
    if target and not _looks_like_ip(target):
        return target.strip().lower()
    raise ValueError("bloodhound-collect requires a domain hint via access.accounts[].username or bloodhound.domain")


def build_bloodhound_command(
    *,
    binary: str,
    target: str,
    auth_context: dict[str, Any],
    domain: str | None = None,
    domain_controller: str | None = None,
    nameserver: str | None = None,
    collection_methods: list[str] | None = None,
    dns_tcp: bool = False,
    use_ldaps: bool = False,
) -> list[str]:
    effective_domain = _domain_for_target(
        target=target,
        auth_context=auth_context,
        configured_domain=domain,
    )
    methods = _normalize_collection_methods(collection_methods)
    command = [
        binary,
        "-u",
        str(auth_context.get("username") or ""),
        "-p",
        str(auth_context.get("password") or ""),
        "-d",
        effective_domain,
        "-c",
        ",".join(methods),
        "--zip",
    ]
    if domain_controller:
        command.extend(["-dc", domain_controller])
    elif target and not _looks_like_ip(target) and target != effective_domain:
        command.extend(["-dc", target])
    if nameserver:
        command.extend(["-ns", nameserver])
    if dns_tcp:
        command.append("--dns-tcp")
    if use_ldaps:
        command.append("--use-ldaps")
    return command


def _sanitize_log_text(value: str, secrets: list[str]) -> str:
    sanitized = value
    for secret in secrets:
        if secret:
            sanitized = sanitized.replace(secret, "[REDACTED]")
    return sanitized


def _latest_zip_file(directory: Path) -> Path | None:
    candidates = sorted(directory.glob("*.zip"), key=lambda path: (path.stat().st_mtime, path.name))
    return candidates[-1] if candidates else None


def execute_bloodhound_collect(
    targets: list[str],
    *,
    auth_contexts: list[dict[str, Any]] | object,
    scope_allowlist: dict[str, Any] | None = None,
    binary: str = "bloodhound-python",
    domain: str | None = None,
    domain_controller: str | None = None,
    nameserver: str | None = None,
    collection_methods: list[str] | None = None,
    dns_tcp: bool = False,
    use_ldaps: bool = False,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    kill_switch_check: Any = None,
    poll_interval_seconds: float = 0.2,
) -> RunnerExecution:
    normalized_targets = [str(target).strip() for target in targets if str(target).strip()]
    if not normalized_targets:
        raise ValueError("bloodhound-collect requires at least one target")
    target = normalized_targets[0]
    if scope_allowlist is not None and not target_value_is_allowed(scope_allowlist, target):
        raise ValueError(f"target outside scope: {target}")

    normalized_auth_contexts = _normalize_auth_contexts(auth_contexts)
    if not normalized_auth_contexts:
        raise ValueError("bloodhound-collect requires at least one authenticated domain-read account")
    auth_context = normalized_auth_contexts[0]
    command = build_bloodhound_command(
        binary=binary,
        target=target,
        auth_context=auth_context,
        domain=domain,
        domain_controller=domain_controller,
        nameserver=nameserver,
        collection_methods=collection_methods,
        dns_tcp=dns_tcp,
        use_ldaps=use_ldaps,
    )

    combined_log = ""
    terminated_by_kill_switch = False
    with tempfile.TemporaryDirectory(prefix="aegispt-bloodhound-") as temp_dir:
        cwd = Path(temp_dir)
        process = subprocess.Popen(
            command,
            cwd=str(cwd),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=os.environ.copy(),
        )
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
        combined_log = "\n".join(part for part in [stdout, stderr] if part).strip()
        zip_path = _latest_zip_file(cwd)
        if zip_path is None:
            raise ValueError("bloodhound-collect did not produce a collection zip")
        zip_bytes = zip_path.read_bytes()
        analysis = analyze_bloodhound_collection(
            zip_bytes=zip_bytes,
            target_id=target,
            collection_methods=_normalize_collection_methods(collection_methods),
            collector_label=str(auth_context.get("label") or auth_context.get("username") or "").strip() or None,
        )
        placeholder_payload = {
            "stored_as": "protected_secret_ref",
            "artifact_name": BLOODHOUND_COLLECTION_ARTIFACT_NAME,
            "content_type": "application/zip",
            "byte_length": len(zip_bytes),
            "raw_collection_exposed": False,
        }
        protected_output = ProtectedSecretMaterial(
            artifact_name=BLOODHOUND_COLLECTION_ARTIFACT_NAME,
            value=base64.b64encode(zip_bytes).decode("ascii"),
            secret_kind="bloodhound_collection_zip",
            purpose="task.bloodhound.collection_zip",
            display_label=f"BloodHound collection ZIP for {target}",
            content_type="application/zip+base64",
            metadata={
                "encoding": "base64",
                "byte_length": len(zip_bytes),
                "raw_collection_exposed": False,
            },
        )
        sanitized_log = _sanitize_log_text(
            combined_log,
            [
                str(auth_context.get("password") or ""),
                str(auth_context.get("username") or ""),
            ],
        )
        exit_code = 0 if zip_bytes and not terminated_by_kill_switch else int(process.returncode or 0)
        return RunnerExecution(
            tool="bloodhound-collect",
            exit_code=exit_code,
            stdout=sanitized_log,
            stderr="" if exit_code == 0 else sanitized_log,
            metadata={
                "status": "ok" if exit_code == 0 else "failed",
                "read_only": True,
                "tool_version": "bloodhound-python",
                "runner_digest": "workers.bloodhound.runner:v1",
                "collection_methods": _normalize_collection_methods(collection_methods),
                "confirmed_edge_count": analysis["summary"]["confirmed_edge_count"],
                "attack_path_count": analysis["summary"]["attack_path_count"],
                "terminated_by_kill_switch": terminated_by_kill_switch,
            },
            artifacts=[
                EvidenceArtifact(
                    name=BLOODHOUND_COLLECTION_ARTIFACT_NAME,
                    content_type="application/vnd.aegispt.protected-artifact-reference+json",
                    data=json.dumps(placeholder_payload).encode("utf-8"),
                    kind="protected-collection-reference",
                ),
                EvidenceArtifact(
                    name=BLOODHOUND_RESULTS_ARTIFACT_NAME,
                    content_type="application/json",
                    data=(json.dumps(analysis, sort_keys=True) + "\n").encode("utf-8"),
                    kind="identity-graph-results",
                ),
                EvidenceArtifact(
                    name=BLOODHOUND_LOG_ARTIFACT_NAME,
                    content_type="text/plain",
                    data=(sanitized_log + ("\n" if sanitized_log else "")).encode("utf-8"),
                    kind="execution-log",
                ),
            ],
            protected_outputs=[protected_output],
        )
