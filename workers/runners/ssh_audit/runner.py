from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from workers.runners.base.contracts import EvidenceArtifact, RunnerExecution

SSH_AUDIT_ARTIFACT_PREFIX = "ssh-audit"


def build_ssh_audit_command(
    *,
    binary: str,
    host: str,
    port: int = 22,
    timeout_seconds: float = 5.0,
) -> list[str]:
    normalized_binary = str(binary or "").strip()
    normalized_host = str(host or "").strip()
    if not normalized_binary:
        raise ValueError("binary must not be blank")
    if not normalized_host:
        raise ValueError("host must not be blank")
    if port <= 0:
        raise ValueError("port must be greater than zero")
    return [
        normalized_binary,
        "-j",
        "-p",
        str(port),
        "-t",
        str(max(int(timeout_seconds), 1)),
        normalized_host,
    ]


def _safe_slug(value: str) -> str:
    return "".join(character if character.isalnum() or character in {"-", "_", "."} else "-" for character in value).strip("-") or "target"


def _collect_algorithm_names(payload: Any) -> set[str]:
    names: set[str] = set()

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                normalized_key = str(key or "").strip().lower()
                if normalized_key in {"algorithm", "name"} and isinstance(value, str) and value.strip():
                    names.add(value.strip().lower())
                walk(value)
            return
        if isinstance(node, list):
            for item in node:
                walk(item)
            return
        if isinstance(node, str) and node.strip():
            names.add(node.strip().lower())

    walk(payload)
    return names


def _severity_from_cvss(value: Any) -> str:
    try:
        score = float(value)
    except (TypeError, ValueError):
        return "medium"
    if score >= 9:
        return "critical"
    if score >= 7:
        return "high"
    if score >= 4:
        return "medium"
    return "low"


def _extract_findings(payload: dict[str, Any], *, host: str, port: int) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    target_id = f"{host}:{port}"
    algorithm_names = _collect_algorithm_names(
        {
            "enc": payload.get("enc"),
            "kex": payload.get("kex"),
            "mac": payload.get("mac"),
            "key": payload.get("key"),
        }
    )

    weak_cipher_markers = {
        "3des-cbc",
        "aes128-cbc",
        "aes192-cbc",
        "aes256-cbc",
        "arcfour",
        "arcfour128",
        "arcfour256",
        "blowfish-cbc",
        "cast128-cbc",
        "des-cbc",
    }
    weak_kex_markers = {
        "diffie-hellman-group1-sha1",
        "diffie-hellman-group14-sha1",
        "diffie-hellman-group-exchange-sha1",
    }
    weak_mac_markers = {
        "hmac-md5",
        "hmac-md5-96",
        "hmac-sha1",
        "hmac-sha1-96",
    }

    weak_ciphers = sorted(marker for marker in weak_cipher_markers if marker in algorithm_names)
    weak_kex = sorted(marker for marker in weak_kex_markers if marker in algorithm_names)
    weak_macs = sorted(marker for marker in weak_mac_markers if marker in algorithm_names)

    if weak_ciphers or weak_kex or weak_macs:
        details: list[str] = []
        if weak_ciphers:
            details.append(f"ciphers: {', '.join(weak_ciphers)}")
        if weak_kex:
            details.append(f"kex: {', '.join(weak_kex)}")
        if weak_macs:
            details.append(f"macs: {', '.join(weak_macs)}")
        findings.append(
            {
                "title": f"Weak SSH ciphers and algorithms on {target_id}",
                "severity": "high" if weak_ciphers or weak_kex else "medium",
                "target_id": target_id,
                "summary": (
                    "SSH audit observed legacy or weak cryptographic support on "
                    f"{target_id} ({'; '.join(details)})."
                ),
                "methodology_tags": ["owasp-wstg", "WSTG-CRYP", "cryptography", "ssh"],
                "ptes_phase": "vulnerability_analysis",
                "nist_phase": "discovery",
                "control_family": "cryptography",
            }
        )

    cves = payload.get("cves", [])
    if isinstance(cves, list):
        for cve in cves:
            if not isinstance(cve, dict):
                continue
            cve_id = str(cve.get("id") or cve.get("cve") or "").strip()
            if not cve_id:
                continue
            findings.append(
                {
                    "title": f"{cve_id} exposure reported by SSH audit on {target_id}",
                    "severity": _severity_from_cvss(cve.get("cvssv2") or cve.get("cvss") or cve.get("cvssv3")),
                    "target_id": target_id,
                    "summary": str(cve.get("description") or f"ssh-audit reported {cve_id} for {target_id}.").strip(),
                    "methodology_tags": ["owasp-wstg", "WSTG-CONFIG", "configuration", "ssh"],
                    "ptes_phase": "vulnerability_analysis",
                    "nist_phase": "discovery",
                    "control_family": "configuration",
                }
            )

    return findings


def execute_ssh_audit(
    *,
    host: str,
    port: int = 22,
    binary: str = "ssh-audit",
    timeout_seconds: float = 10.0,
) -> RunnerExecution:
    command = build_ssh_audit_command(
        binary=binary,
        host=host,
        port=port,
        timeout_seconds=timeout_seconds,
    )
    with tempfile.TemporaryDirectory(prefix="aegispt-ssh-audit-") as temp_dir_name:
        temp_dir = Path(temp_dir_name)
        raw_output_path = temp_dir / "ssh-audit.json"
        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
        )

        stdout_text = process.stdout or ""
        raw_output_path.write_text(stdout_text, encoding="utf-8")
        try:
            payload = json.loads(stdout_text) if stdout_text.strip() else {}
            if not isinstance(payload, dict):
                payload = {}
        except json.JSONDecodeError:
            payload = {}

        result_payload = {
            "host": host,
            "port": port,
            "status": "ok" if process.returncode == 0 else "failed",
            "banner": payload.get("banner"),
            "raw_payload": payload,
            "analysis_findings": _extract_findings(payload, host=host, port=port),
        }
        artifact_name = f"{SSH_AUDIT_ARTIFACT_PREFIX}-{_safe_slug(host)}-{port}.json"
        artifact = EvidenceArtifact(
            name=artifact_name,
            content_type="application/json",
            data=(json.dumps(result_payload, sort_keys=True) + "\n").encode("utf-8"),
            kind="ssh-audit-results",
        )
        return RunnerExecution(
            tool="ssh-audit",
            exit_code=process.returncode,
            stdout=process.stdout,
            stderr=process.stderr,
            metadata={
                "status": "ok" if process.returncode == 0 else "failed",
                "host": host,
                "port": port,
                "finding_count": len(result_payload["analysis_findings"]),
                "runner_digest": "workers.ssh_audit.runner:v1",
                "tool_version": "ssh-audit",
            },
            artifacts=[artifact],
        )
