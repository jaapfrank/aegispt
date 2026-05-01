from __future__ import annotations

import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
from typing import Any

from api.app.services.runs import target_value_is_allowed
from workers.runners.base.contracts import (
    EvidenceArtifact,
    ProtectedSecretMaterial,
    RunnerExecution,
)
from workers.runners.credential_attacks.asreproast import (
    build_asreproast_command,
    extract_asreproast_records,
)
from workers.runners.credential_attacks.hashcat import (
    build_hashcat_command,
    extract_hash_records,
    parse_hashcat_output,
    resolve_wordlist_path,
)
from workers.runners.credential_attacks.kerberoast import (
    build_kerberoast_command,
    extract_kerberoast_records,
)
from workers.runners.credential_attacks.spray import (
    build_password_spray_command,
    parse_password_spray_successes,
)

CREDENTIAL_ATTACK_RESULTS_ARTIFACT_NAME = "credential-attack-results.json"
CREDENTIAL_ATTACK_LOG_ARTIFACT_NAME = "credential-attack-session.log"
DEFAULT_MODE = "kerberoast"
DEFAULT_TIMEOUT_SECONDS = 300.0
DEFAULT_ATTEMPTS_PER_WINDOW = 1
DEFAULT_WINDOW_MINUTES = 30
_SAFE_SLUG_PATTERN = re.compile(r"[^A-Za-z0-9._-]+")


def _safe_slug(value: str) -> str:
    return _SAFE_SLUG_PATTERN.sub("-", str(value or "").strip()).strip("-") or "item"


def _normalize_mode(value: Any) -> str:
    normalized = str(value or DEFAULT_MODE).strip().lower()
    if normalized not in {"kerberoast", "asreproast", "hashcat", "spray"}:
        raise ValueError("credential-attacks mode must be kerberoast, asreproast, hashcat, or spray")
    return normalized


def _normalize_accounts(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    normalized: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for raw_account in value:
        if not isinstance(raw_account, dict):
            continue
        account_name = str(raw_account.get("account_name") or "").strip()
        principal = str(raw_account.get("user_principal_name") or "").strip()
        key = ((account_name or principal).lower(), principal.lower())
        if not (account_name or principal) or key in seen:
            continue
        seen.add(key)
        normalized.append(
            {
                "account_name": account_name or principal,
                "user_principal_name": principal or None,
                "service_principal_names": [
                    str(item).strip()
                    for item in list(raw_account.get("service_principal_names") or [])
                    if str(item).strip()
                ],
                "privilege_level": str(raw_account.get("privilege_level") or "standard").strip()
                or "standard",
            }
        )
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
        if not username or not password:
            continue
        normalized.append(
            {
                "label": str(raw_context.get("label") or username).strip() or username,
                "username": username,
                "password": password,
                "domain": str(raw_context.get("domain") or "").strip() or None,
            }
        )
    return normalized


def _normalize_hash_inputs(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    normalized: list[dict[str, Any]] = []
    for raw_input in value:
        if not isinstance(raw_input, dict):
            continue
        bundle_value = str(raw_input.get("value") or "").strip()
        secret_kind = str(raw_input.get("secret_kind") or "").strip()
        if not bundle_value or not secret_kind:
            continue
        normalized.append(
            {
                "label": str(raw_input.get("label") or secret_kind).strip() or secret_kind,
                "secret_kind": secret_kind,
                "value": bundle_value,
            }
        )
    return normalized


def _normalize_password_candidates(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    normalized: list[dict[str, Any]] = []
    seen_passwords: set[str] = set()
    for raw_candidate in value:
        if not isinstance(raw_candidate, dict):
            continue
        password = str(raw_candidate.get("value") or "").strip()
        if not password or password in seen_passwords:
            continue
        seen_passwords.add(password)
        normalized.append(
            {
                "label": str(raw_candidate.get("label") or "Password candidate").strip()
                or "Password candidate",
                "value": password,
            }
        )
    return normalized


def _looks_like_ip(value: str) -> bool:
    if not value or any(char not in "0123456789.:" for char in value):
        return False
    return any(char.isdigit() for char in value)


def _domain_from_target(target: str) -> str | None:
    normalized = str(target or "").strip()
    if not normalized or _looks_like_ip(normalized):
        return None
    return normalized.lower()


def _domain_for_operation(
    *,
    target: str,
    configured_domain: str | None,
    auth_context: dict[str, Any] | None,
    candidate_accounts: list[dict[str, Any]],
) -> str:
    if configured_domain:
        return configured_domain.lower()
    if auth_context is not None:
        auth_domain = str(auth_context.get("domain") or "").strip()
        if auth_domain:
            return auth_domain.lower()
        username = str(auth_context.get("username") or "").strip()
        if "@" in username:
            return username.split("@", 1)[1].strip().lower()
        if "\\" in username:
            return username.split("\\", 1)[0].strip().lower()
    for account in candidate_accounts:
        principal = str(account.get("user_principal_name") or "").strip()
        if "@" in principal:
            return principal.split("@", 1)[1].strip().lower()
    inferred = _domain_from_target(target)
    if inferred:
        return inferred
    raise ValueError("credential-attacks requires a domain hint via credential_attacks.domain, target, or account UPN")


def _sanitize_text(value: str, secrets: list[str]) -> str:
    sanitized = str(value or "")
    for secret in secrets:
        candidate = str(secret or "").strip()
        if candidate:
            sanitized = sanitized.replace(candidate, "[REDACTED]")
    return sanitized


def _severity_for_privilege(privilege_level: str, *, success_mode: bool = False) -> str:
    normalized = str(privilege_level or "").strip().lower()
    if normalized in {"tier0", "privileged", "critical"}:
        return "critical"
    if normalized in {"high", "service", "admin"}:
        return "high"
    if success_mode:
        return "high"
    return "medium"


def _run_command(
    command: list[str],
    *,
    cwd: Path,
    timeout_seconds: float,
    kill_switch_check: Any,
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
        time.sleep(0.1)
    stdout, stderr = process.communicate()
    return int(process.returncode or 0), stdout or "", stderr or "", terminated_by_kill_switch


def _protected_reference_artifact(
    *,
    artifact_name: str,
    content_type: str,
    metadata: dict[str, Any],
    kind: str,
) -> EvidenceArtifact:
    payload = {
        "stored_as": "protected_secret_ref",
        "artifact_name": artifact_name,
        "content_type": content_type,
        "raw_secret_material_exposed": False,
        **metadata,
    }
    return EvidenceArtifact(
        name=artifact_name,
        content_type="application/vnd.aegispt.protected-artifact-reference+json",
        data=(json.dumps(payload, sort_keys=True) + "\n").encode("utf-8"),
        kind=kind,
    )


def _result_payload(
    *,
    target: str,
    mode: str,
    findings: list[dict[str, Any]],
    summary: dict[str, Any],
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload = {
        "tool": "credential-attacks",
        "mode": mode,
        "status": "ok",
        "summary": summary,
        "targets": [
            {
                "target": target,
                "mode": mode,
                "status": "ok",
                "analysis_findings": findings,
                **(extra or {}),
                "errors": [],
            }
        ],
    }
    return payload


def _bundle_protected_output(
    *,
    artifact_name: str,
    secret_kind: str,
    purpose: str,
    display_label: str,
    bundle_payload: dict[str, Any],
) -> ProtectedSecretMaterial:
    return ProtectedSecretMaterial(
        artifact_name=artifact_name,
        value=json.dumps(bundle_payload, sort_keys=True),
        secret_kind=secret_kind,
        purpose=purpose,
        display_label=display_label,
        content_type="application/json",
        metadata={
            "record_count": len(bundle_payload.get("records", []))
            if isinstance(bundle_payload.get("records"), list)
            else None,
            "raw_secret_material_exposed": False,
        },
    )


def _cracked_password_protected_output(
    *,
    artifact_name: str,
    account_name: str,
    password: str,
    privilege_level: str,
    target: str,
    purpose_prefix: str,
) -> ProtectedSecretMaterial:
    return ProtectedSecretMaterial(
        artifact_name=artifact_name,
        value=password,
        secret_kind="password",
        purpose=f"{purpose_prefix}.{_safe_slug(account_name)}",
        display_label=f"Protected password for {account_name}",
        metadata={
            "account_name": account_name,
            "target": target,
            "privilege_level": privilege_level,
            "raw_secret_material_exposed": False,
        },
    )


def execute_credential_attacks(
    targets: list[str],
    *,
    mode: str = DEFAULT_MODE,
    scope_allowlist: dict[str, Any] | None = None,
    auth_contexts: list[dict[str, Any]] | object = None,
    candidate_accounts: list[dict[str, Any]] | object = None,
    hash_inputs: list[dict[str, Any]] | object = None,
    password_candidates: list[dict[str, Any]] | object = None,
    configured_domain: str | None = None,
    domain_controller: str | None = None,
    wordlist_path: str | None = None,
    attempts_per_window: int = DEFAULT_ATTEMPTS_PER_WINDOW,
    window_minutes: int = DEFAULT_WINDOW_MINUTES,
    lockout_threshold: int | None = None,
    getuserspns_binary: str = "GetUserSPNs.py",
    getnpusers_binary: str = "GetNPUsers.py",
    hashcat_binary: str = "hashcat",
    spray_binary: str = "kerbrute",
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    kill_switch_check: Any = None,
) -> RunnerExecution:
    normalized_targets = [str(target).strip() for target in targets if str(target).strip()]
    if not normalized_targets:
        raise ValueError("credential-attacks requires at least one target")
    target = normalized_targets[0]
    if scope_allowlist is not None and not target_value_is_allowed(scope_allowlist, target):
        raise ValueError(f"target outside scope: {target}")

    normalized_mode = _normalize_mode(mode)
    normalized_accounts = _normalize_accounts(candidate_accounts)
    normalized_auth_contexts = _normalize_auth_contexts(auth_contexts)
    normalized_hash_inputs = _normalize_hash_inputs(hash_inputs)
    normalized_password_candidates = _normalize_password_candidates(password_candidates)
    auth_context = normalized_auth_contexts[0] if normalized_auth_contexts else None
    domain = _domain_for_operation(
        target=target,
        configured_domain=configured_domain,
        auth_context=auth_context,
        candidate_accounts=normalized_accounts,
    )

    if normalized_mode == "kerberoast" and auth_context is None:
        raise ValueError("Kerberoast requires at least one authenticated domain account")
    if normalized_mode in {"kerberoast", "asreproast"} and not normalized_accounts:
        raise ValueError(f"{normalized_mode} requires at least one candidate account")
    if normalized_mode == "hashcat" and not normalized_hash_inputs:
        raise ValueError("Hashcat cracking requires at least one protected hash input")
    if normalized_mode == "spray":
        if not normalized_accounts:
            raise ValueError("Password spray requires at least one candidate account")
        if not normalized_password_candidates:
            raise ValueError("Password spray requires at least one protected password candidate")
        if lockout_threshold is None or int(lockout_threshold) <= 1:
            raise ValueError("Password spray requires a confirmed lockout threshold greater than 1")
        if int(attempts_per_window) >= int(lockout_threshold):
            raise ValueError("Password spray attempts per window must stay below the confirmed lockout threshold")

    combined_log_parts: list[str] = []
    protected_outputs: list[ProtectedSecretMaterial] = []
    artifacts: list[EvidenceArtifact] = []
    findings: list[dict[str, Any]] = []
    summary: dict[str, Any]
    secrets_to_redact: list[str] = []
    if auth_context is not None:
        secrets_to_redact.extend(
            [
                str(auth_context.get("username") or ""),
                str(auth_context.get("password") or ""),
            ]
        )

    with tempfile.TemporaryDirectory(prefix="aegispt-credential-attacks-") as temp_dir:
        cwd = Path(temp_dir)

        if normalized_mode == "kerberoast":
            output_file = cwd / "kerberoast.hashes"
            command = build_kerberoast_command(
                binary=getuserspns_binary,
                auth_context=auth_context or {},
                domain=domain,
                output_file=output_file,
                domain_controller=domain_controller,
            )
            exit_code, stdout, stderr, terminated = _run_command(
                command,
                cwd=cwd,
                timeout_seconds=timeout_seconds,
                kill_switch_check=kill_switch_check,
            )
            combined_log_parts.extend([stdout, stderr])
            hash_lines = output_file.read_text(encoding="utf-8").splitlines() if output_file.exists() else []
            records = extract_kerberoast_records(hash_lines, candidate_accounts=normalized_accounts, target=target)
            secrets_to_redact.extend([record["hash"] for record in records])
            severity_counts = 0
            for record in records:
                title = f"Kerberoast hash extracted for account {record['account_name']}"
                findings.append(
                    {
                        "title": title,
                        "severity": _severity_for_privilege(record["privilege_level"]),
                        "target_id": target,
                        "summary": (
                            f"Impacket GetUserSPNs requested a Kerberos service ticket for {record['account_name']} "
                            f"on {target} and stored the crackable TGS material only through protected secret storage."
                        ),
                        "methodology_tags": [
                            "credential_attack",
                            "kerberoast",
                            "active_directory",
                        ],
                    }
                )
                severity_counts += 1
            artifact_name = f"credential-attack-kerberoast-{_safe_slug(target)}.json"
            bundle_payload = {"target": target, "domain": domain, "records": records}
            artifacts.append(
                _protected_reference_artifact(
                    artifact_name=artifact_name,
                    content_type="application/json",
                    metadata={"record_count": len(records)},
                    kind="protected-hash-reference",
                )
            )
            protected_outputs.append(
                _bundle_protected_output(
                    artifact_name=artifact_name,
                    secret_kind="kerberoast_tgs_hash_bundle",
                    purpose=f"task.credential_attacks.kerberoast.{_safe_slug(target)}",
                    display_label=f"Kerberoast TGS hashes for {target}",
                    bundle_payload=bundle_payload,
                )
            )
            summary = {
                "candidate_account_count": len(normalized_accounts),
                "hash_capture_count": len(records),
                "finding_count": len(findings),
                "terminated_by_kill_switch": terminated,
            }
            exit_code = 0 if records or exit_code == 0 else exit_code
            extra = {
                "candidate_accounts": [
                    {
                        "account_name": record["account_name"],
                        "user_principal_name": record["user_principal_name"],
                        "service_principal_names": record["service_principal_names"],
                        "privilege_level": record["privilege_level"],
                        "hash_extracted": True,
                    }
                    for record in records
                ]
            }
        elif normalized_mode == "asreproast":
            users_file = cwd / "asreproast-users.txt"
            users_file.write_text(
                "\n".join(
                    account.get("user_principal_name") or account.get("account_name") or ""
                    for account in normalized_accounts
                )
                + "\n",
                encoding="utf-8",
            )
            output_file = cwd / "asreproast.hashes"
            command = build_asreproast_command(
                binary=getnpusers_binary,
                domain=domain,
                users_file=users_file,
                output_file=output_file,
                domain_controller=domain_controller,
            )
            exit_code, stdout, stderr, terminated = _run_command(
                command,
                cwd=cwd,
                timeout_seconds=timeout_seconds,
                kill_switch_check=kill_switch_check,
            )
            combined_log_parts.extend([stdout, stderr])
            hash_lines = output_file.read_text(encoding="utf-8").splitlines() if output_file.exists() else []
            records = extract_asreproast_records(
                hash_lines,
                candidate_accounts=normalized_accounts,
                target=target,
            )
            secrets_to_redact.extend([record["hash"] for record in records])
            for record in records:
                findings.append(
                    {
                        "title": f"AS-REP hash extracted for account {record['account_name']}",
                        "severity": _severity_for_privilege(record["privilege_level"]),
                        "target_id": target,
                        "summary": (
                            f"Impacket GetNPUsers obtained crackable AS-REP material for {record['account_name']} "
                            f"on {target} and stored it only through protected secret storage."
                        ),
                        "methodology_tags": [
                            "credential_attack",
                            "asreproast",
                            "active_directory",
                        ],
                    }
                )
            artifact_name = f"credential-attack-asreproast-{_safe_slug(target)}.json"
            bundle_payload = {"target": target, "domain": domain, "records": records}
            artifacts.append(
                _protected_reference_artifact(
                    artifact_name=artifact_name,
                    content_type="application/json",
                    metadata={"record_count": len(records)},
                    kind="protected-hash-reference",
                )
            )
            protected_outputs.append(
                _bundle_protected_output(
                    artifact_name=artifact_name,
                    secret_kind="asrep_hash_bundle",
                    purpose=f"task.credential_attacks.asreproast.{_safe_slug(target)}",
                    display_label=f"AS-REP hashes for {target}",
                    bundle_payload=bundle_payload,
                )
            )
            summary = {
                "candidate_account_count": len(normalized_accounts),
                "hash_capture_count": len(records),
                "finding_count": len(findings),
                "terminated_by_kill_switch": terminated,
            }
            exit_code = 0 if records or exit_code == 0 else exit_code
            extra = {
                "candidate_accounts": [
                    {
                        "account_name": record["account_name"],
                        "user_principal_name": record["user_principal_name"],
                        "privilege_level": record["privilege_level"],
                        "hash_extracted": True,
                    }
                    for record in records
                ]
            }
        elif normalized_mode == "hashcat":
            wordlist = resolve_wordlist_path(wordlist_path)
            cracked_records: list[dict[str, Any]] = []
            terminated_any = False
            for index, hash_input in enumerate(normalized_hash_inputs, start=1):
                bundle_records = extract_hash_records(
                    source_label=str(hash_input.get("label") or f"bundle-{index}"),
                    source_kind=str(hash_input.get("secret_kind") or ""),
                    bundle_value=str(hash_input.get("value") or ""),
                )
                grouped: dict[int, list[dict[str, Any]]] = {}
                for record in bundle_records:
                    grouped.setdefault(int(record["hashcat_mode"]), []).append(record)
                for hash_mode, mode_records in grouped.items():
                    hash_file = cwd / f"hashcat-input-{index}-{hash_mode}.txt"
                    hash_file.write_text(
                        "\n".join(str(record["hash"]) for record in mode_records) + "\n",
                        encoding="utf-8",
                    )
                    output_file = cwd / f"hashcat-output-{index}-{hash_mode}.txt"
                    command = build_hashcat_command(
                        binary=hashcat_binary,
                        hash_mode=hash_mode,
                        hash_file=hash_file,
                        wordlist_path=wordlist,
                        output_file=output_file,
                    )
                    exit_code, stdout, stderr, terminated = _run_command(
                        command,
                        cwd=cwd,
                        timeout_seconds=timeout_seconds,
                        kill_switch_check=kill_switch_check,
                    )
                    terminated_any = terminated_any or terminated
                    combined_log_parts.extend([stdout, stderr])
                    cracked_lines = (
                        output_file.read_text(encoding="utf-8").splitlines()
                        if output_file.exists()
                        else []
                    )
                    cracked_records.extend(
                        parse_hashcat_output(cracked_lines, records=mode_records)
                    )
                    exit_code = 0 if exit_code in {0, 1} else exit_code
            seen_accounts: set[tuple[str, str]] = set()
            cracked_accounts_sanitized: list[dict[str, Any]] = []
            for record in cracked_records:
                password = str(record.get("password") or "").strip()
                account_name = str(
                    record.get("account_name")
                    or record.get("user_principal_name")
                    or record.get("source_label")
                    or "credential"
                ).strip()
                if not password or not account_name:
                    continue
                secrets_to_redact.extend([str(record.get("hash") or ""), password])
                key = (account_name.lower(), password)
                if key in seen_accounts:
                    continue
                seen_accounts.add(key)
                artifact_name = f"credential-attack-cracked-{_safe_slug(account_name)}.json"
                artifacts.append(
                    _protected_reference_artifact(
                        artifact_name=artifact_name,
                        content_type="text/plain",
                        metadata={
                            "account_name": account_name,
                            "source_kind": str(record.get("source_kind") or ""),
                        },
                        kind="protected-password-reference",
                    )
                )
                protected_outputs.append(
                    _cracked_password_protected_output(
                        artifact_name=artifact_name,
                        account_name=account_name,
                        password=password,
                        privilege_level=str(record.get("privilege_level") or "standard"),
                        target=target,
                        purpose_prefix="task.credential_attacks.cracked_password",
                    )
                )
                cracked_accounts_sanitized.append(
                    {
                        "account_name": account_name,
                        "user_principal_name": record.get("user_principal_name"),
                        "source_kind": record.get("source_kind"),
                        "privilege_level": record.get("privilege_level"),
                        "password_stored_as": "protected_secret_ref",
                    }
                )
                findings.append(
                    {
                        "title": f"Weak password cracked for account {account_name}",
                        "severity": _severity_for_privilege(
                            str(record.get("privilege_level") or "standard")
                        ),
                        "target_id": target,
                        "summary": (
                            f"Offline hash cracking recovered a reusable password for {account_name}. "
                            "The plaintext password is stored only through protected secret storage."
                        ),
                        "methodology_tags": [
                            "credential_attack",
                            "offline_cracking",
                            "password_strength",
                        ],
                    }
                )
            summary = {
                "hash_source_count": len(normalized_hash_inputs),
                "cracked_password_count": len(cracked_accounts_sanitized),
                "finding_count": len(findings),
                "terminated_by_kill_switch": terminated_any,
            }
            exit_code = 0
            extra = {"cracked_accounts": cracked_accounts_sanitized}
        else:
            users = [
                account.get("user_principal_name") or account.get("account_name") or ""
                for account in normalized_accounts
            ]
            users_file = cwd / "spray-users.txt"
            users_file.write_text("\n".join(users) + "\n", encoding="utf-8")
            successful_accounts: list[dict[str, Any]] = []
            account_index = {
                (
                    str(account.get("user_principal_name") or account.get("account_name") or "").strip().lower()
                ): account
                for account in normalized_accounts
            }
            terminated_any = False
            for password_candidate in normalized_password_candidates[: max(int(attempts_per_window), 1)]:
                password = str(password_candidate.get("value") or "").strip()
                command = build_password_spray_command(
                    binary=spray_binary,
                    domain=domain,
                    users_file=users_file,
                    password=password,
                    domain_controller=domain_controller,
                )
                exit_code, stdout, stderr, terminated = _run_command(
                    command,
                    cwd=cwd,
                    timeout_seconds=timeout_seconds,
                    kill_switch_check=kill_switch_check,
                )
                terminated_any = terminated_any or terminated
                combined_log_parts.extend([stdout, stderr])
                successes = parse_password_spray_successes((stdout + "\n" + stderr).splitlines())
                secrets_to_redact.append(password)
                for success in successes:
                    normalized_success = success.strip().lower()
                    matched_account = account_index.get(normalized_success)
                    if matched_account is None and "@" in normalized_success:
                        matched_account = account_index.get(normalized_success)
                    if matched_account is None:
                        continue
                    account_name = str(
                        matched_account.get("account_name")
                        or matched_account.get("user_principal_name")
                        or success
                    ).strip()
                    if any(
                        existing.get("account_name") == account_name
                        for existing in successful_accounts
                    ):
                        continue
                    artifact_name = f"credential-attack-spray-{_safe_slug(account_name)}.json"
                    artifacts.append(
                        _protected_reference_artifact(
                            artifact_name=artifact_name,
                            content_type="text/plain",
                            metadata={
                                "account_name": account_name,
                                "spray_label": str(password_candidate.get("label") or ""),
                            },
                            kind="protected-password-reference",
                        )
                    )
                    protected_outputs.append(
                        _cracked_password_protected_output(
                            artifact_name=artifact_name,
                            account_name=account_name,
                            password=password,
                            privilege_level=str(
                                matched_account.get("privilege_level") or "standard"
                            ),
                            target=target,
                            purpose_prefix="task.credential_attacks.sprayed_password",
                        )
                    )
                    successful_accounts.append(
                        {
                            "account_name": account_name,
                            "user_principal_name": matched_account.get("user_principal_name"),
                            "privilege_level": matched_account.get("privilege_level"),
                            "password_stored_as": "protected_secret_ref",
                        }
                    )
                    findings.append(
                        {
                            "title": f"Password spray succeeded for account {account_name}",
                            "severity": _severity_for_privilege(
                                str(matched_account.get("privilege_level") or "standard"),
                                success_mode=True,
                            ),
                            "target_id": target,
                            "summary": (
                                f"A bounded password spray validated a reusable password for {account_name} "
                                f"while staying within the confirmed lockout window for {target}. "
                                "The plaintext password is stored only through protected secret storage."
                            ),
                            "methodology_tags": [
                                "credential_attack",
                                "password_spray",
                                "authentication",
                            ],
                        }
                    )
            summary = {
                "candidate_account_count": len(normalized_accounts),
                "successful_account_count": len(successful_accounts),
                "attempts_per_window": max(int(attempts_per_window), 1),
                "window_minutes": max(int(window_minutes), 1),
                "lockout_threshold": int(lockout_threshold or 0),
                "finding_count": len(findings),
                "terminated_by_kill_switch": terminated_any,
            }
            exit_code = 0
            extra = {"spray_successes": successful_accounts}

        sanitized_log = _sanitize_text(
            "\n".join(part for part in combined_log_parts if part).strip(),
            secrets_to_redact,
        )
        results_payload = _result_payload(
            target=target,
            mode=normalized_mode,
            findings=findings,
            summary=summary,
            extra=extra,
        )
        artifacts.extend(
            [
                EvidenceArtifact(
                    name=CREDENTIAL_ATTACK_RESULTS_ARTIFACT_NAME,
                    content_type="application/json",
                    data=(json.dumps(results_payload, sort_keys=True) + "\n").encode("utf-8"),
                    kind="credential-attack-results",
                ),
                EvidenceArtifact(
                    name=CREDENTIAL_ATTACK_LOG_ARTIFACT_NAME,
                    content_type="text/plain",
                    data=(sanitized_log + ("\n" if sanitized_log else "")).encode("utf-8"),
                    kind="execution-log",
                ),
            ]
        )
        return RunnerExecution(
            tool="credential-attacks",
            exit_code=exit_code,
            stdout=sanitized_log,
            stderr="" if exit_code == 0 else sanitized_log,
            metadata={
                "status": "ok" if exit_code == 0 else "failed",
                "mode": normalized_mode,
                "tool_version": "credential-attacks",
                "runner_digest": "workers.credential_attacks.runner:v1",
                **summary,
            },
            artifacts=artifacts,
            protected_outputs=protected_outputs,
        )
