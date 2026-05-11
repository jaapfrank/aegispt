from __future__ import annotations

import json
from hashlib import sha256
from typing import Any

from workers.runners.base.contracts import EvidenceArtifact, RunnerExecution

TOOL_NAME = "leak-check"
LEAK_CHECK_RESULTS_ARTIFACT_NAME = "leak-check-results.json"
_REDACTED = "[redacted]"
_SECRET_MARKERS = ("password", "passwd", "secret", "token", "hash", "credential", "key")


def _json_artifact(payload: dict[str, Any]) -> EvidenceArtifact:
    return EvidenceArtifact(
        name=LEAK_CHECK_RESULTS_ARTIFACT_NAME,
        content_type="application/json",
        data=(json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8"),
        kind="runner-results",
    )


def _sha256_text(value: str) -> str:
    return sha256(value.strip().lower().encode("utf-8")).hexdigest()


def _email_domain(value: str) -> str:
    email = value.strip().lower()
    return email.rsplit("@", 1)[1] if "@" in email else ""


def _redact_payload(value: Any) -> Any:
    if isinstance(value, dict):
        redacted: dict[str, Any] = {}
        for key, item in value.items():
            key_text = str(key)
            if any(marker in key_text.lower() for marker in _SECRET_MARKERS):
                redacted[key_text] = _REDACTED
            elif key_text.lower() in {"email", "username", "account"}:
                account = str(item or "").strip()
                redacted[f"{key_text}_hash"] = _sha256_text(account) if account else ""
                domain = _email_domain(account)
                if domain:
                    redacted[f"{key_text}_domain"] = domain
            else:
                redacted[key_text] = _redact_payload(item)
        return redacted
    if isinstance(value, list):
        return [_redact_payload(item) for item in value]
    return value


def _records(leak_export: dict[str, Any]) -> list[dict[str, Any]]:
    records = leak_export.get("records")
    if not isinstance(records, list):
        records = leak_export.get("leaks")
    if not isinstance(records, list):
        records = leak_export.get("results")
    return [record for record in records if isinstance(record, dict)] if isinstance(records, list) else []


def _has_secret_material(value: Any) -> bool:
    if isinstance(value, dict):
        return any(
            any(marker in str(key).lower() for marker in _SECRET_MARKERS)
            or _has_secret_material(item)
            for key, item in value.items()
        )
    if isinstance(value, list):
        return any(_has_secret_material(item) for item in value)
    return False


def _normalize_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    for record in records:
        account = str(
            record.get("email")
            or record.get("username")
            or record.get("account")
            or record.get("login")
            or ""
        ).strip()
        domain = _email_domain(account)
        normalized.append(
            {
                "account_hash": _sha256_text(account) if account else "",
                "account_domain": domain,
                "source": str(record.get("source") or record.get("breach") or "imported")[:120],
                "breach_date": str(record.get("breach_date") or record.get("date") or "")[:40],
                "password_present": any(
                    key in record and bool(record.get(key))
                    for key in ("password", "passwd", "plaintext_password")
                ),
                "hash_present": any(key in record and bool(record.get(key)) for key in ("hash", "password_hash")),
                "record_hash": sha256(
                    json.dumps(record, sort_keys=True, default=str).encode("utf-8")
                ).hexdigest(),
            }
        )
    return normalized


def _append_finding(
    findings: list[dict[str, Any]],
    *,
    finding_type: str,
    title: str,
    severity: str,
    target: str,
    summary: str,
    evidence: dict[str, Any],
) -> None:
    findings.append(
        {
            "type": finding_type,
            "title": title,
            "severity": severity,
            "target": target,
            "summary": summary,
            "methodology_tags": [
                "credential_leak_review",
                "osint_metadata",
                "identity_exposure",
            ],
            "ptes_phase": "Intelligence Gathering",
            "nist_phase": "Discovery",
            "control_family": "identity_management",
            "evidence": evidence,
            "replay_recipe": {
                "tool": TOOL_NAME,
                "mode": "metadata-only-import",
                "credential_values_stored": False,
                "credential_attack_auto_queue_created": False,
            },
        }
    )


def execute_leak_check_review(
    targets: list[str],
    *,
    leak_export: dict[str, Any] | None = None,
    credential_attack_auto_queue_requested: bool = False,
    login_attempt_requested: bool = False,
) -> RunnerExecution:
    if credential_attack_auto_queue_requested or login_attempt_requested:
        raise ValueError("leak-check is metadata-only and cannot queue credential attacks or login attempts")
    if leak_export is None or not isinstance(leak_export, dict):
        raise ValueError("leak-check requires imported leak metadata or authorized lookup results")

    normalized_targets = [str(target).strip().lower() for target in targets if str(target).strip()]
    normalized_records = _normalize_records(_records(leak_export))
    target_domains = {target for target in normalized_targets if "." in target and "://" not in target}
    affected_domains = {record["account_domain"] for record in normalized_records if record["account_domain"]}
    in_scope_records = [
        record
        for record in normalized_records
        if not target_domains or record["account_domain"] in target_domains
    ]
    plaintext_count = sum(1 for record in in_scope_records if record["password_present"])
    hash_count = sum(1 for record in in_scope_records if record["hash_present"])
    findings: list[dict[str, Any]] = []
    target = sorted(target_domains)[0] if target_domains else (normalized_targets[0] if normalized_targets else "leak-import")
    if in_scope_records:
        _append_finding(
            findings,
            finding_type="credential_leak_metadata_observed",
            title="Credential Leak Metadata Observed",
            severity="medium",
            target=target,
            summary=f"Imported leak metadata references {len(in_scope_records)} in-scope account record(s).",
            evidence={
                "affected_account_count": len(in_scope_records),
                "affected_domains": sorted(affected_domains & target_domains) if target_domains else sorted(affected_domains),
            },
        )
    if plaintext_count:
        _append_finding(
            findings,
            finding_type="plaintext_credential_exposure_reported",
            title="Plaintext Credential Exposure Reported",
            severity="high",
            target=target,
            summary=(
                f"Imported metadata indicates {plaintext_count} in-scope account record(s) had "
                "plaintext credential material in the source feed. Values were redacted."
            ),
            evidence={"plaintext_record_count": plaintext_count, "credential_values_stored": False},
        )
    if hash_count:
        _append_finding(
            findings,
            finding_type="credential_hash_exposure_reported",
            title="Credential Hash Exposure Reported",
            severity="medium",
            target=target,
            summary=(
                f"Imported metadata indicates {hash_count} in-scope account record(s) had "
                "credential hash material in the source feed. Values were redacted."
            ),
            evidence={"hash_record_count": hash_count, "hash_values_stored": False},
        )

    payload = {
        "tool": TOOL_NAME,
        "mode": "metadata-only-import",
        "targets": normalized_targets,
        "summary": {
            "finding_count": len(findings),
            "record_count": len(normalized_records),
            "in_scope_record_count": len(in_scope_records),
            "plaintext_record_count": plaintext_count,
            "hash_record_count": hash_count,
        },
        "records": in_scope_records,
        "out_of_scope_domain_count": len(affected_domains - target_domains) if target_domains else 0,
        "findings": findings,
        "redacted_import": _redact_payload(leak_export),
        "safety": {
            "metadata_only": True,
            "credential_values_stored": False,
            "raw_passwords_stored": False,
            "raw_hashes_stored": False,
            "credential_attack_auto_queue_created": False,
            "login_attempts_performed": False,
            "credential_materialization_performed": False,
            "automatic_approval_created": False,
            "runtime_binding_bypassed": False,
            "secret_material_seen_in_import": _has_secret_material(leak_export),
        },
        "provenance": {
            "source": "imported_leak_metadata",
            "source_sha256": sha256(
                json.dumps(leak_export, sort_keys=True, default=str).encode("utf-8")
            ).hexdigest(),
            "runner_digest": "workers.leak_check.runner:v1",
        },
    }
    return RunnerExecution(
        tool=TOOL_NAME,
        exit_code=0,
        stdout=f"leak-check metadata import complete: {len(findings)} finding(s)",
        stderr="",
        metadata={
            "mode": "metadata-only-import",
            "credential_values_stored": False,
            "credential_attack_auto_queue_created": False,
            "finding_count": len(findings),
        },
        artifacts=[_json_artifact(payload)],
        protected_outputs=[],
    )
