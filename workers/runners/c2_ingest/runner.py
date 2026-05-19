from __future__ import annotations

import json
import re
from hashlib import sha256
from typing import Any

from workers.runners.base.contracts import EvidenceArtifact, RunnerExecution

TOOL_NAME = "c2-ingest"
C2_INGEST_RESULTS_ARTIFACT_NAME = "c2-ingest-results.json"
_REDACTED = "[redacted]"
_SECRET_MARKERS = ("password", "passwd", "secret", "token", "hash", "credential", "key")
_IDENTITY_KEYS = {"user", "username", "operator", "email"}
_LATERAL_MARKERS = ("psexec", "wmiexec", "smbexec", "ssh ", "winrm", "remote-exec")
_CREDENTIAL_MARKERS = ("secretsdump", "dcsync", "mimikatz", "lsass", "kerberoast", "hashdump")
_DISCOVERY_MARKERS = ("whoami", "hostname", "ipconfig", "ifconfig", "net user", "net group")


def _json_artifact(payload: dict[str, Any]) -> EvidenceArtifact:
    return EvidenceArtifact(
        name=C2_INGEST_RESULTS_ARTIFACT_NAME,
        content_type="application/json",
        data=(json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8"),
        kind="runner-results",
    )


def _sha256_text(value: str) -> str:
    return sha256(value.strip().lower().encode("utf-8")).hexdigest()


def _redact_text(value: str) -> str:
    redacted = value
    for marker in _SECRET_MARKERS:
        redacted = re.sub(
            rf"(?i)({marker}\s*[:=]\s*)\S+",
            rf"\1{_REDACTED}",
            redacted,
        )
    return redacted[:240]


def _redact_payload(value: Any) -> Any:
    if isinstance(value, dict):
        output: dict[str, Any] = {}
        for key, item in value.items():
            key_text = str(key)
            if any(marker in key_text.lower() for marker in _SECRET_MARKERS):
                output[key_text] = _REDACTED
            elif key_text.strip().lower() in _IDENTITY_KEYS:
                identity = str(item or "").strip()
                output[f"{key_text}_hash"] = _sha256_text(identity) if identity else ""
            else:
                output[key_text] = _redact_payload(item)
        return output
    if isinstance(value, list):
        return [_redact_payload(item) for item in value]
    if isinstance(value, str):
        return _redact_text(value)
    return value


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _framework(payload: dict[str, Any], explicit_framework: str | None) -> str:
    value = str(explicit_framework or payload.get("framework") or payload.get("source") or "").strip()
    normalized = value.lower()
    if "mythic" in normalized:
        return "mythic"
    if "sliver" in normalized:
        return "sliver"
    return value or "c2-import"


def _session_id(session: dict[str, Any]) -> str:
    return str(
        session.get("id")
        or session.get("session_id")
        or session.get("beacon_id")
        or session.get("agent_id")
        or session.get("uuid")
        or ""
    ).strip()


def _session_hash(session: dict[str, Any]) -> str:
    raw_id = _session_id(session) or json.dumps(session, sort_keys=True, default=str)
    return _sha256_text(raw_id)


def _command_text(command: dict[str, Any]) -> str:
    return str(
        command.get("command")
        or command.get("cmd")
        or command.get("input")
        or command.get("task")
        or command.get("name")
        or ""
    ).strip()


def _command_family(command_text: str) -> str:
    normalized = command_text.lower()
    if any(marker in normalized for marker in _CREDENTIAL_MARKERS):
        return "credential_access"
    if any(marker in normalized for marker in _LATERAL_MARKERS):
        return "lateral_movement"
    if any(marker in normalized for marker in _DISCOVERY_MARKERS):
        return "discovery"
    return "operator_command"


def _normalize_sessions(payload: dict[str, Any]) -> list[dict[str, Any]]:
    sessions = _as_list(payload.get("sessions")) or _as_list(payload.get("beacons"))
    normalized: list[dict[str, Any]] = []
    for session in sessions:
        if not isinstance(session, dict):
            continue
        session_hash = _session_hash(session)
        user = str(session.get("user") or session.get("username") or session.get("operator") or "")
        host = str(session.get("host") or session.get("hostname") or session.get("computer") or "")
        normalized.append(
            {
                "session_hash": session_hash,
                "host": host[:120],
                "user_hash": _sha256_text(user) if user else "",
                "ip": str(session.get("ip") or session.get("remote_address") or "")[:80],
                "platform": str(session.get("platform") or session.get("os") or "")[:80],
                "status": str(session.get("status") or session.get("state") or "imported")[:80],
            }
        )
    return normalized


def _normalize_commands(payload: dict[str, Any], sessions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    commands = _as_list(payload.get("commands")) or _as_list(payload.get("tasks"))
    session_hashes = {session["session_hash"] for session in sessions}
    normalized: list[dict[str, Any]] = []
    for command in commands:
        if not isinstance(command, dict):
            continue
        command_text = _command_text(command)
        raw_session = str(
            command.get("session_id") or command.get("beacon_id") or command.get("agent_id") or ""
        ).strip()
        session_hash = _sha256_text(raw_session) if raw_session else ""
        if session_hash and session_hash not in session_hashes:
            session_hashes.add(session_hash)
        redacted = _redact_text(command_text)
        normalized.append(
            {
                "command_hash": _sha256_text(command_text or json.dumps(command, sort_keys=True)),
                "session_hash": session_hash,
                "timestamp": str(command.get("timestamp") or command.get("time") or "")[:80],
                "family": _command_family(command_text),
                "status": str(command.get("status") or command.get("state") or "imported")[:80],
                "command_excerpt": redacted,
                "command_sha256": sha256(command_text.encode("utf-8")).hexdigest(),
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
                "c2_ingest",
                "read_only_timeline",
                "assumed_breach_evidence",
            ],
            "ptes_phase": "Post-Exploitation",
            "nist_phase": "Reporting",
            "control_family": "authorization",
            "evidence": evidence,
            "replay_recipe": {
                "tool": TOOL_NAME,
                "mode": "read-only-import",
                "c2_command_execution_performed": False,
            },
        }
    )


def execute_c2_ingest(
    targets: list[str],
    *,
    c2_export: dict[str, Any] | None = None,
    framework: str | None = None,
    command_execution_requested: bool = False,
    session_mutation_requested: bool = False,
) -> RunnerExecution:
    if command_execution_requested or session_mutation_requested:
        raise ValueError("c2-ingest is read-only and cannot execute C2 commands or mutate sessions")
    if c2_export is None or not isinstance(c2_export, dict):
        raise ValueError("c2-ingest requires an imported Mythic/Sliver session export")

    normalized_targets = [str(target).strip() for target in targets if str(target).strip()]
    framework_name = _framework(c2_export, framework)
    sessions = _normalize_sessions(c2_export)
    commands = _normalize_commands(c2_export, sessions)
    families = {command["family"] for command in commands}
    target = normalized_targets[0] if normalized_targets else framework_name
    findings: list[dict[str, Any]] = []
    if sessions:
        _append_finding(
            findings,
            finding_type="c2_session_evidence_imported",
            title="C2 Session Evidence Imported",
            severity="info",
            target=target,
            summary=f"Imported {len(sessions)} read-only {framework_name} session record(s).",
            evidence={"session_count": len(sessions), "framework": framework_name},
        )
    if "lateral_movement" in families:
        _append_finding(
            findings,
            finding_type="c2_lateral_movement_command_evidence",
            title="C2 Lateral Movement Command Evidence",
            severity="high",
            target=target,
            summary="Imported C2 command history includes lateral movement command evidence.",
            evidence={
                "command_count": sum(1 for command in commands if command["family"] == "lateral_movement")
            },
        )
    if "credential_access" in families:
        _append_finding(
            findings,
            finding_type="c2_credential_access_command_evidence",
            title="C2 Credential Access Command Evidence",
            severity="high",
            target=target,
            summary="Imported C2 command history includes credential access command evidence.",
            evidence={
                "command_count": sum(1 for command in commands if command["family"] == "credential_access")
            },
        )

    payload = {
        "tool": TOOL_NAME,
        "mode": "read-only-import",
        "framework": framework_name,
        "targets": normalized_targets,
        "summary": {
            "finding_count": len(findings),
            "session_count": len(sessions),
            "command_count": len(commands),
            "credential_access_command_count": sum(
                1 for command in commands if command["family"] == "credential_access"
            ),
            "lateral_movement_command_count": sum(
                1 for command in commands if command["family"] == "lateral_movement"
            ),
        },
        "sessions": sessions,
        "commands": commands,
        "findings": findings,
        "redacted_import": _redact_payload(c2_export),
        "safety": {
            "read_only_import": True,
            "c2_command_execution_performed": False,
            "session_mutation_performed": False,
            "payload_deployment_performed": False,
            "credential_materialization_performed": False,
            "automatic_approval_created": False,
            "runtime_binding_bypassed": False,
        },
        "provenance": {
            "source": "imported_c2_export",
            "source_sha256": sha256(
                json.dumps(c2_export, sort_keys=True, default=str).encode("utf-8")
            ).hexdigest(),
            "runner_digest": "workers.c2_ingest.runner:v1",
        },
    }
    return RunnerExecution(
        tool=TOOL_NAME,
        exit_code=0,
        stdout=f"c2-ingest read-only import complete: {len(findings)} finding(s)",
        stderr="",
        metadata={
            "mode": "read-only-import",
            "c2_command_execution_performed": False,
            "session_mutation_performed": False,
            "finding_count": len(findings),
        },
        artifacts=[_json_artifact(payload)],
        protected_outputs=[],
    )
