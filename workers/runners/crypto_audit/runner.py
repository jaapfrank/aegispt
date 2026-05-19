from __future__ import annotations

import base64
import json
import re
import subprocess
import tempfile
from hashlib import sha256
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse

import httpx as httpx_client

from api.app.services.runs import (
    target_value_is_allowed,
    web_target_value_is_allowed_with_path,
)
from workers.runners.base.contracts import EvidenceArtifact, RunnerExecution
from workers.runners.ssh_audit.runner import execute_ssh_audit

CRYPTO_AUDIT_RESULTS_ARTIFACT_NAME = "crypto-audit-results.json"
DEFAULT_TIMEOUT_SECONDS = 30.0
WEAK_JWS_PKCS1_ALGORITHMS = {"RS256", "RS384", "RS512"}
WEAK_JWE_ALGORITHMS = {"RSA1_5"}
WEAK_HMAC_ALGORITHMS = {"HS256", "HS384", "HS512"}
HEX_MD5_RE = re.compile(r"^[a-fA-F0-9]{32}$")
HEX_SHA1_RE = re.compile(r"^[a-fA-F0-9]{40}$")
CERT_KEY_RE = re.compile(
    r"\b(?:rsa|dsa|ecdsa|key|cert(?:ificate)?)\D{0,30}(\d{3,5})\s*(?:bit|bits)?\b", re.I
)
DH_SIZE_RE = re.compile(r"\b(?:dh|diffie|hellman|group)\D{0,30}(\d{3,5})\s*(?:bit|bits)?\b", re.I)


def _json_artifact(payload: dict[str, Any]) -> EvidenceArtifact:
    return EvidenceArtifact(
        name=CRYPTO_AUDIT_RESULTS_ARTIFACT_NAME,
        content_type="application/json",
        data=(json.dumps(payload, sort_keys=True) + "\n").encode("utf-8"),
        kind="runner-results",
    )


def _dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        value = str(item or "").strip()
        if not value or value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


def _safe_slug(value: str) -> str:
    return (
        "".join(
            character if character.isalnum() or character in {"-", "_", "."} else "-"
            for character in value
        ).strip("-")
        or "target"
    )


def _positive_signal(text: str) -> bool:
    normalized = str(text or "").lower()
    negative_markers = (
        "not vulnerable",
        "not offered",
        "not supported",
        "not available",
        "not detected",
        "not found",
        "not ok",
        "not enabled",
        "no vulnerability",
    )
    if any(marker in normalized for marker in negative_markers):
        return False
    if normalized.strip() in {"ok", "true", "false", "n/a"}:
        return False
    return bool(normalized.strip())


def _walk_json(node: Any) -> list[Any]:
    items: list[Any] = []

    def walk(value: Any) -> None:
        items.append(value)
        if isinstance(value, dict):
            for child in value.values():
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    walk(node)
    return items


def _flatten_testssl_records(payload: Any) -> list[Any]:
    if isinstance(payload, dict):
        for key in ("scanResult", "scan_results", "findings", "results"):
            value = payload.get(key)
            if isinstance(value, list):
                return value
        return list(payload.values())
    if isinstance(payload, list):
        return payload
    if isinstance(payload, str):
        return [{"id": "testssl-text", "finding": payload}]
    return []


def _record_text(record: Any) -> str:
    if isinstance(record, dict):
        return json.dumps(record, sort_keys=True, default=str)
    return str(record or "")


def _host_port_from_target(value: str, *, default_port: int) -> tuple[str, int, str]:
    candidate = str(value or "").strip()
    parsed = urlparse(candidate if "://" in candidate else f"//{candidate}")
    host = str(parsed.hostname or "").strip()
    port = int(parsed.port or default_port)
    if not host:
        host = candidate.split("/", 1)[0].split(":", 1)[0].strip()
    if not host:
        raise ValueError("crypto-audit target host must not be blank")
    return host, port, f"{host}:{port}"


def _is_url(value: str) -> bool:
    parsed = urlparse(str(value or "").strip())
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def _assert_target_allowed(scope_allowlist: dict[str, Any] | None, target: str) -> None:
    scope = scope_allowlist or {}
    if _is_url(target):
        if not web_target_value_is_allowed_with_path(scope, target):
            raise ValueError(f"target outside approved crypto audit web scope: {target}")
        return
    if not target_value_is_allowed(scope, target):
        raise ValueError(f"target outside approved crypto audit scope: {target}")


def _normalize_tls_targets(
    targets: list[str],
    *,
    configured_tls_targets: list[str] | None,
    scope_allowlist: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    raw_targets = [*targets, *(configured_tls_targets or [])]
    normalized: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw_target in raw_targets:
        candidate = str(raw_target or "").strip()
        if not candidate:
            continue
        _assert_target_allowed(scope_allowlist, candidate)
        host, port, target_id = _host_port_from_target(candidate, default_port=443)
        if target_id in seen:
            continue
        seen.add(target_id)
        normalized.append(
            {
                "input": candidate,
                "host": host,
                "port": port,
                "target_id": target_id,
                "testssl_target": target_id,
                "https_url": f"https://{target_id}" if port != 443 else f"https://{host}",
            }
        )
    return normalized


def _normalize_ssh_target_item(raw_item: Any) -> tuple[str, int] | None:
    if isinstance(raw_item, dict):
        host = str(
            raw_item.get("host") or raw_item.get("target") or raw_item.get("value") or ""
        ).strip()
        port = raw_item.get("port")
        return (
            (host, int(port))
            if host and isinstance(port, int) and 1 <= port <= 65535
            else ((host, 22) if host else None)
        )
    value = str(raw_item or "").strip()
    if not value:
        return None
    parsed = urlparse(value if "://" in value else f"//{value}")
    if parsed.scheme in {"http", "https"}:
        return None
    host = str(parsed.hostname or value.split(":", 1)[0]).strip()
    port = int(parsed.port or 22)
    return (host, port) if host else None


def _normalize_ssh_targets(
    targets: list[str],
    *,
    configured_ssh_targets: list[Any] | None,
    scope_allowlist: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    if configured_ssh_targets is None:
        raw_targets = [target for target in targets if not _is_url(str(target or "").strip())]
    else:
        raw_targets = list(configured_ssh_targets)
    normalized: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw_target in raw_targets:
        parsed = _normalize_ssh_target_item(raw_target)
        if parsed is None:
            continue
        host, port = parsed
        _assert_target_allowed(scope_allowlist, host)
        target_id = f"{host}:{port}"
        if target_id in seen:
            continue
        seen.add(target_id)
        normalized.append({"host": host, "port": port, "target_id": target_id})
    return normalized


def build_testssl_command(
    *,
    binary: str,
    target: str,
    json_output_path: str,
    mode: str = "passive",
) -> list[str]:
    normalized_binary = str(binary or "").strip()
    normalized_target = str(target or "").strip()
    if not normalized_binary:
        raise ValueError("testssl binary must not be blank")
    if not normalized_target:
        raise ValueError("testssl target must not be blank")
    command = [
        normalized_binary,
        "--warnings",
        "batch",
        "--jsonfile",
        str(json_output_path),
    ]
    if str(mode or "").strip().lower() == "passive":
        command.append("--fast")
    else:
        command.extend(["--parallel", "1"])
    command.append(normalized_target)
    return command


def _run_testssl(
    *,
    binary: str,
    target: str,
    mode: str,
    timeout_seconds: float,
) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="aegispt-crypto-audit-testssl-") as temp_dir_name:
        output_path = Path(temp_dir_name) / "testssl.json"
        command = build_testssl_command(
            binary=binary,
            target=target,
            json_output_path=str(output_path),
            mode=mode,
        )
        try:
            process = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=max(float(timeout_seconds), 1.0),
                check=False,
            )
            stdout_text = process.stdout or ""
            stderr_text = process.stderr or ""
            if output_path.exists():
                raw_output = output_path.read_text(encoding="utf-8", errors="replace")
            else:
                raw_output = stdout_text
            try:
                parsed: Any = json.loads(raw_output) if raw_output.strip() else {}
            except json.JSONDecodeError:
                parsed = raw_output
            return {
                "status": "ok" if process.returncode == 0 else "failed",
                "exit_code": process.returncode,
                "command": command,
                "stdout": stdout_text,
                "stderr": stderr_text,
                "payload": parsed,
            }
        except subprocess.TimeoutExpired as exc:
            return {
                "status": "timeout",
                "exit_code": 124,
                "command": command,
                "stdout": str(exc.stdout or ""),
                "stderr": str(exc.stderr or "testssl.sh timed out"),
                "payload": {},
            }
        except FileNotFoundError as exc:
            return {
                "status": "tool_unavailable",
                "exit_code": 127,
                "command": command,
                "stdout": "",
                "stderr": str(exc),
                "payload": {},
            }


def _fixture_for_target(fixtures: Any, target_id: str) -> Any | None:
    if not fixtures:
        return None
    if isinstance(fixtures, dict):
        if target_id in fixtures:
            return fixtures[target_id]
        host = target_id.split(":", 1)[0]
        if host in fixtures:
            return fixtures[host]
        if "default" in fixtures:
            return fixtures["default"]
    return fixtures


def _finding(
    *,
    finding_type: str,
    title: str,
    severity: str,
    target: str,
    summary: str,
    evidence: dict[str, Any],
    why_weak: str,
    fix_recommendation: str,
    better_alternative: str,
    family: str,
) -> dict[str, Any]:
    return {
        "type": finding_type,
        "title": title,
        "severity": severity,
        "target": target,
        "summary": summary,
        "confirmed": True,
        "methodology_tags": [
            "owasp-wstg",
            "WSTG-CRYP",
            "cryptography",
            "crypto-audit-validation",
            family,
        ],
        "control_family": "cryptography",
        "evidence": evidence,
        "why_weak": why_weak,
        "fix_recommendation": fix_recommendation,
        "better_alternative": better_alternative,
        "replay_recipe": {
            "tool": "crypto-audit",
            "target": target,
            "scope": "approved-targets-only",
            "bruteforce_attempted": False,
            "decryption_attempted": False,
            "custom_cipher_analysis": False,
        },
    }


def _append_once(
    findings: list[dict[str, Any]], seen: set[tuple[str, str]], finding: dict[str, Any]
) -> None:
    key = (str(finding.get("type") or ""), str(finding.get("target") or ""))
    if key in seen:
        return
    seen.add(key)
    findings.append(finding)


def _record_matches(records: list[Any], *needles: str) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    lowered_needles = [needle.lower() for needle in needles]
    for record in records:
        text = _record_text(record)
        lowered = text.lower()
        if all(needle in lowered for needle in lowered_needles) and _positive_signal(lowered):
            matches.append({"record": record if isinstance(record, dict) else str(record)[:500]})
    return matches


def _smallest_size_from_records(records: list[Any], pattern: re.Pattern[str]) -> int | None:
    sizes: list[int] = []
    for record in records:
        for match in pattern.finditer(_record_text(record)):
            try:
                sizes.append(int(match.group(1)))
            except ValueError:
                continue
    return min(sizes) if sizes else None


def _analyze_testssl_payload(
    *,
    target: dict[str, Any],
    payload: Any,
    http_headers: dict[str, str] | None,
) -> list[dict[str, Any]]:
    target_id = str(target["target_id"])
    records = _flatten_testssl_records(payload)
    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    if (
        _record_matches(records, "export")
        or _record_matches(records, "freak")
        or _record_matches(records, "drown")
    ):
        _append_once(
            findings,
            seen,
            _finding(
                finding_type="tls_export_grade_cipher",
                title=f"Export-grade TLS cipher accepted on {target_id}",
                severity="high",
                target=target_id,
                summary=f"testssl.sh evidence indicates export-grade or legacy RSA cipher support on {target_id}.",
                evidence={"testssl_matches": _record_matches(records, "export")[:3]},
                why_weak="Export-grade cipher suites were intentionally weakened and enable attacks such as FREAK-style downgrade scenarios.",
                fix_recommendation="Disable all EXPORT, LOW, NULL, DES, and legacy RSA key-exchange cipher suites.",
                better_alternative="TLS 1.2 or TLS 1.3 with AEAD suites such as AES-GCM or ChaCha20-Poly1305.",
                family="tls",
            ),
        )

    if _record_matches(records, "ssl", "3") or _record_matches(records, "poodle"):
        _append_once(
            findings,
            seen,
            _finding(
                finding_type="tls_sslv3_poodle",
                title=f"SSLv3/POODLE-compatible protocol support on {target_id}",
                severity="high",
                target=target_id,
                summary=f"testssl.sh evidence indicates SSLv3 or POODLE-compatible behavior on {target_id}.",
                evidence={
                    "testssl_matches": (
                        _record_matches(records, "ssl", "3") + _record_matches(records, "poodle")
                    )[:3]
                },
                why_weak="SSLv3 is obsolete and vulnerable to POODLE-style padding oracle attacks.",
                fix_recommendation="Disable SSLv2/SSLv3 completely and reject downgrade fallback to SSLv3.",
                better_alternative="TLS 1.2 or TLS 1.3 only, with modern AEAD cipher suites.",
                family="tls",
            ),
        )

    if (
        _record_matches(records, "tls1")
        or _record_matches(records, "tls 1.0")
        or _record_matches(records, "tls 1.1")
    ):
        _append_once(
            findings,
            seen,
            _finding(
                finding_type="tls_legacy_protocol_enabled",
                title=f"Legacy TLS 1.0/1.1 enabled on {target_id}",
                severity="medium",
                target=target_id,
                summary=f"testssl.sh evidence indicates TLS 1.0 or TLS 1.1 remains enabled on {target_id}.",
                evidence={
                    "testssl_matches": (
                        _record_matches(records, "tls1")
                        + _record_matches(records, "tls 1.0")
                        + _record_matches(records, "tls 1.1")
                    )[:3]
                },
                why_weak="TLS 1.0 and TLS 1.1 lack modern protocol protections and are deprecated by current security baselines.",
                fix_recommendation="Disable TLS 1.0 and TLS 1.1 on the server and downstream load balancers.",
                better_alternative="TLS 1.2 and TLS 1.3 with secure cipher policy.",
                family="tls",
            ),
        )

    if _record_matches(records, "beast") or (
        _record_matches(records, "cbc")
        and (_record_matches(records, "tls1") or _record_matches(records, "tls 1.0"))
    ):
        _append_once(
            findings,
            seen,
            _finding(
                finding_type="tls_beast_cbc_tls10",
                title=f"BEAST-risk TLS 1.0 CBC cipher support on {target_id}",
                severity="medium",
                target=target_id,
                summary=f"testssl.sh evidence indicates TLS 1.0 CBC cipher support on {target_id}.",
                evidence={
                    "testssl_matches": (
                        _record_matches(records, "beast") + _record_matches(records, "cbc")
                    )[:3]
                },
                why_weak="CBC mode in TLS 1.0 is historically vulnerable to BEAST-class attacks and should not remain enabled.",
                fix_recommendation="Disable TLS 1.0 and CBC-mode suites where possible.",
                better_alternative="TLS 1.2+ AEAD suites such as AES-GCM or ChaCha20-Poly1305.",
                family="tls",
            ),
        )

    if _record_matches(records, "lucky13"):
        _append_once(
            findings,
            seen,
            _finding(
                finding_type="tls_lucky13_cbc",
                title=f"LUCKY13 CBC timing-risk signal on {target_id}",
                severity="medium",
                target=target_id,
                summary=f"testssl.sh evidence indicates CBC timing-risk exposure on {target_id}.",
                evidence={"testssl_matches": _record_matches(records, "lucky13")[:3]},
                why_weak="LUCKY13 targets timing differences in CBC-mode TLS implementations.",
                fix_recommendation="Remove CBC-mode TLS suites and patch TLS libraries.",
                better_alternative="AEAD-only cipher policy with current TLS libraries.",
                family="tls",
            ),
        )

    if _record_matches(records, "rc4"):
        _append_once(
            findings,
            seen,
            _finding(
                finding_type="tls_rc4_enabled",
                title=f"RC4 cipher support on {target_id}",
                severity="high",
                target=target_id,
                summary=f"testssl.sh evidence indicates RC4 support on {target_id}.",
                evidence={"testssl_matches": _record_matches(records, "rc4")[:3]},
                why_weak="RC4 has known biases and is prohibited for TLS use.",
                fix_recommendation="Disable RC4 suites across TLS terminators.",
                better_alternative="TLS 1.2 or TLS 1.3 AEAD suites.",
                family="tls",
            ),
        )

    dh_size = _smallest_size_from_records(records, DH_SIZE_RE)
    if dh_size is not None and dh_size < 2048:
        _append_once(
            findings,
            seen,
            _finding(
                finding_type="tls_weak_dh_parameters",
                title=f"Weak Diffie-Hellman parameters on {target_id}",
                severity="high",
                target=target_id,
                summary=f"testssl.sh evidence indicates Diffie-Hellman parameters below 2048 bits on {target_id}.",
                evidence={"smallest_dh_bits": dh_size},
                why_weak="Small finite-field Diffie-Hellman groups are susceptible to precomputation and downgrade risk.",
                fix_recommendation="Disable weak DHE suites or deploy at least 2048-bit custom DH parameters.",
                better_alternative="ECDHE with modern curves or TLS 1.3 key exchange groups.",
                family="tls",
            ),
        )

    cert_key_size = _smallest_size_from_records(records, CERT_KEY_RE)
    if cert_key_size is not None and cert_key_size < 2048:
        _append_once(
            findings,
            seen,
            _finding(
                finding_type="tls_short_certificate_key",
                title=f"Certificate key length below 2048 bits on {target_id}",
                severity="medium",
                target=target_id,
                summary=f"Certificate evidence indicates a key length of {cert_key_size} bits on {target_id}.",
                evidence={"certificate_key_bits": cert_key_size},
                why_weak="RSA or DSA keys below 2048 bits no longer meet common enterprise cryptographic baselines.",
                fix_recommendation="Replace the certificate with a key of at least RSA 2048 bits or an approved ECDSA curve.",
                better_alternative="RSA 2048/3072+ or ECDSA P-256/P-384 certificates.",
                family="tls",
            ),
        )

    if _record_matches(records, "heartbleed") and not _record_matches(
        records, "not vulnerable", "heartbleed"
    ):
        _append_once(
            findings,
            seen,
            _finding(
                finding_type="tls_heartbleed_signal",
                title=f"Heartbleed/OpenSSL CVE-2014-0160 signal on {target_id}",
                severity="critical",
                target=target_id,
                summary=f"testssl.sh evidence indicates a Heartbleed-style OpenSSL exposure on {target_id}.",
                evidence={"testssl_matches": _record_matches(records, "heartbleed")[:3]},
                why_weak="Heartbleed can expose process memory from vulnerable OpenSSL versions.",
                fix_recommendation="Patch OpenSSL, restart dependent services, and rotate affected keys/certificates if exposure is confirmed.",
                better_alternative="A current OpenSSL or platform TLS library with heartbeat vulnerability patches applied.",
                family="tls",
            ),
        )

    hsts_value = ""
    if isinstance(http_headers, dict):
        hsts_value = str(
            http_headers.get("strict-transport-security")
            or http_headers.get("Strict-Transport-Security")
            or ""
        ).strip()
    if http_headers is not None and "preload" not in hsts_value.lower():
        _append_once(
            findings,
            seen,
            _finding(
                finding_type="tls_hsts_preload_missing",
                title=f"HSTS preload not enabled on {target_id}",
                severity="low" if hsts_value else "medium",
                target=target_id,
                summary=f"HTTPS header evidence for {target_id} does not include an HSTS preload directive.",
                evidence={"strict_transport_security": hsts_value or None},
                why_weak="Without HSTS preload, first-visit downgrade protection depends on the browser already having seen the site over HTTPS.",
                fix_recommendation="Deploy HSTS with an appropriate max-age, includeSubDomains where safe, and preload only after confirming subdomain readiness.",
                better_alternative="Strict-Transport-Security: max-age=31536000; includeSubDomains; preload, after operational readiness review.",
                family="tls",
            ),
        )

    return findings


def _collect_algorithm_names(payload: Any) -> set[str]:
    names: set[str] = set()
    for node in _walk_json(payload):
        if isinstance(node, str) and node.strip():
            names.add(node.strip().lower())
    return names


def _analyze_ssh_payload(*, target_id: str, payload: Any) -> list[dict[str, Any]]:
    raw_payload = payload.get("raw_payload") if isinstance(payload, dict) else None
    effective_payload = raw_payload if raw_payload else payload
    algorithm_names = _collect_algorithm_names(effective_payload)
    findings: list[dict[str, Any]] = []

    weak_kex = sorted(
        name
        for name in algorithm_names
        if name
        in {
            "diffie-hellman-group1-sha1",
            "diffie-hellman-group14-sha1",
            "diffie-hellman-group-exchange-sha1",
        }
    )
    weak_macs = sorted(
        name for name in algorithm_names if name in {"hmac-md5", "hmac-md5-96", "hmac-sha1-96"}
    )
    weak_keys = sorted(name for name in algorithm_names if name in {"ssh-dss", "dsa"})
    weak_ciphers = sorted(
        name
        for name in algorithm_names
        if name
        in {
            "3des-cbc",
            "aes128-cbc",
            "aes192-cbc",
            "aes256-cbc",
            "arcfour",
            "arcfour128",
            "arcfour256",
        }
    )

    if weak_kex:
        findings.append(
            _finding(
                finding_type="ssh_weak_kex",
                title=f"Deprecated SSH key exchange on {target_id}",
                severity="high",
                target=target_id,
                summary=f"ssh-audit evidence lists deprecated key exchange algorithms: {', '.join(weak_kex)}.",
                evidence={"algorithms": weak_kex},
                why_weak="SHA1-based and group1/group14 finite-field exchanges are legacy choices with downgrade and precomputation concerns.",
                fix_recommendation="Disable deprecated Diffie-Hellman SHA1 groups in the SSH server configuration.",
                better_alternative="curve25519-sha256, sntrup761x25519-sha512, or diffie-hellman-group16/18-sha512 where appropriate.",
                family="ssh",
            )
        )
    if weak_macs:
        findings.append(
            _finding(
                finding_type="ssh_weak_mac",
                title=f"Weak SSH MAC algorithm on {target_id}",
                severity="medium",
                target=target_id,
                summary=f"ssh-audit evidence lists weak MAC algorithms: {', '.join(weak_macs)}.",
                evidence={"algorithms": weak_macs},
                why_weak="MD5 and truncated SHA1 MACs no longer meet modern SSH integrity baselines.",
                fix_recommendation="Remove MD5 and truncated SHA1 MACs from the SSH server allowlist.",
                better_alternative="hmac-sha2-256-etm@openssh.com or hmac-sha2-512-etm@openssh.com.",
                family="ssh",
            )
        )
    if weak_keys:
        findings.append(
            _finding(
                finding_type="ssh_deprecated_host_key",
                title=f"Deprecated SSH DSA host key on {target_id}",
                severity="medium",
                target=target_id,
                summary=f"ssh-audit evidence lists deprecated host key algorithms: {', '.join(weak_keys)}.",
                evidence={"algorithms": weak_keys},
                why_weak="DSA/ssh-dss host keys are deprecated and limited by obsolete security assumptions.",
                fix_recommendation="Remove DSA host keys and disable ssh-dss.",
                better_alternative="Ed25519 or RSA SHA-2 host keys with modern OpenSSH defaults.",
                family="ssh",
            )
        )
    if weak_ciphers:
        findings.append(
            _finding(
                finding_type="ssh_weak_cipher",
                title=f"Weak SSH cipher support on {target_id}",
                severity="medium",
                target=target_id,
                summary=f"ssh-audit evidence lists weak SSH ciphers: {', '.join(weak_ciphers)}.",
                evidence={"algorithms": weak_ciphers},
                why_weak="CBC, 3DES, and RC4-style SSH ciphers are legacy modes with known security weaknesses.",
                fix_recommendation="Disable CBC, 3DES, and arcfour ciphers in SSH server configuration.",
                better_alternative="chacha20-poly1305@openssh.com or AES-GCM/CTR with encrypt-then-MAC.",
                family="ssh",
            )
        )

    return findings


def _base64url_json(segment: str) -> dict[str, Any]:
    padding = "=" * (-len(segment) % 4)
    decoded = base64.urlsafe_b64decode((segment + padding).encode("ascii"))
    payload = json.loads(decoded.decode("utf-8"))
    return payload if isinstance(payload, dict) else {}


def _token_label_and_value(item: Any, index: int) -> tuple[str, str, dict[str, Any]]:
    if isinstance(item, dict):
        label = str(item.get("label") or item.get("source") or f"token-evidence-{index}").strip()
        value = str(item.get("token") or item.get("value") or item.get("sample") or "").strip()
        return label or f"token-evidence-{index}", value, item
    return f"token-evidence-{index}", str(item or "").strip(), {}


def _analyze_token_evidence(
    token_evidence: list[Any] | None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    findings: list[dict[str, Any]] = []
    observations: list[dict[str, Any]] = []
    for index, item in enumerate(token_evidence or [], start=1):
        label, token_value, metadata = _token_label_and_value(item, index)
        token_hash = sha256(token_value.encode("utf-8")).hexdigest() if token_value else None
        observation = {"label": label, "token_sha256": token_hash, "token_length": len(token_value)}
        header: dict[str, Any] = {}
        alg = str(metadata.get("algorithm") or metadata.get("alg") or "").strip()
        if token_value.count(".") >= 2:
            try:
                header = _base64url_json(token_value.split(".", 1)[0])
                alg = str(header.get("alg") or alg).strip()
                observation["jwt_header"] = {
                    key: value for key, value in header.items() if key in {"alg", "typ", "enc"}
                }
            except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
                observation["jwt_header_parse_error"] = True
        observations.append(observation)
        target = str(metadata.get("source_url") or metadata.get("target") or label)

        if HEX_MD5_RE.fullmatch(token_value):
            findings.append(
                _finding(
                    finding_type="token_md5_length_signal",
                    title=f"MD5-length token observed in {label}",
                    severity="medium",
                    target=target,
                    summary=f"Token evidence from {label} is 32 hexadecimal characters, consistent with an MD5-length value.",
                    evidence=observation,
                    why_weak="32-character hexadecimal tokens often indicate MD5-sized material and may have insufficient entropy or weak hashing.",
                    fix_recommendation="Use high-entropy random tokens or password-reset/session token formats backed by modern keyed storage.",
                    better_alternative="At least 128 bits of CSPRNG entropy encoded opaquely, with server-side hashing using SHA-256/HMAC or stronger.",
                    family="token",
                )
            )
        if HEX_SHA1_RE.fullmatch(token_value):
            findings.append(
                _finding(
                    finding_type="token_sha1_length_signal",
                    title=f"SHA1-length token observed in {label}",
                    severity="low",
                    target=target,
                    summary=f"Token evidence from {label} is 40 hexadecimal characters, consistent with a SHA1-length value.",
                    evidence=observation,
                    why_weak="SHA1-sized token material is a weak design signal when used for reset or session tokens.",
                    fix_recommendation="Use opaque, CSPRNG-generated tokens and modern server-side storage.",
                    better_alternative="High-entropy opaque tokens with SHA-256/HMAC-backed verification.",
                    family="token",
                )
            )

        normalized_alg = alg.upper()
        if normalized_alg in WEAK_JWS_PKCS1_ALGORITHMS:
            findings.append(
                _finding(
                    finding_type="jws_rsa_pkcs1_v15",
                    title=f"JWS uses RSA PKCS#1 v1.5 algorithm {normalized_alg}",
                    severity="low",
                    target=target,
                    summary=f"JWT/JWS evidence declares {normalized_alg}, an RSA PKCS#1 v1.5 signature algorithm.",
                    evidence={**observation, "algorithm": normalized_alg},
                    why_weak="RSA PKCS#1 v1.5 signatures are older than RSA-PSS and are commonly retired in hardened token policies.",
                    fix_recommendation="Prefer RSA-PSS algorithms for new JWT deployments where library and IdP support allow it.",
                    better_alternative="PS256, PS384, or EdDSA with strict issuer/audience validation.",
                    family="jwt",
                )
            )
        if normalized_alg in WEAK_JWE_ALGORITHMS:
            findings.append(
                _finding(
                    finding_type="jwe_rsa1_5",
                    title=f"JWE uses deprecated RSA1_5 key management in {label}",
                    severity="high",
                    target=target,
                    summary="JWE evidence declares RSA1_5 key management.",
                    evidence={**observation, "algorithm": normalized_alg},
                    why_weak="RSA1_5 key management is vulnerable to adaptive chosen-ciphertext attack classes.",
                    fix_recommendation="Disable RSA1_5 for JWE key management.",
                    better_alternative="RSA-OAEP-256 or ECDH-ES with authenticated encryption.",
                    family="jwt",
                )
            )
        if normalized_alg in WEAK_HMAC_ALGORITHMS:
            key_bits = metadata.get("hmac_key_bits") or metadata.get("key_length_bits")
            if isinstance(key_bits, int) and key_bits < 256:
                findings.append(
                    _finding(
                        finding_type="jwt_hs_short_key",
                        title=f"{normalized_alg} configured with short HMAC key in {label}",
                        severity="high",
                        target=target,
                        summary=f"Configured token evidence reports a {key_bits}-bit HMAC key for {normalized_alg}.",
                        evidence={
                            **observation,
                            "algorithm": normalized_alg,
                            "key_length_bits": key_bits,
                        },
                        why_weak="Short HMAC keys reduce brute-force resistance for symmetric JWT signatures.",
                        fix_recommendation="Rotate to a high-entropy HMAC secret of at least 256 bits or use asymmetric signing.",
                        better_alternative="A CSPRNG-generated 256-bit or stronger HMAC secret, or EdDSA/RSASSA-PSS.",
                        family="jwt",
                    )
                )

    return findings, observations


def _fetch_https_headers(
    url: str, *, timeout_seconds: float
) -> tuple[dict[str, str] | None, str | None]:
    try:
        with httpx_client.Client(
            timeout=min(max(timeout_seconds, 1.0), 10.0), follow_redirects=False
        ) as client:
            response = client.head(url, headers={"User-Agent": "AegisPT/crypto-audit header check"})
            if response.status_code == 405:
                response = client.get(
                    url, headers={"User-Agent": "AegisPT/crypto-audit header check"}
                )
            return {str(key).lower(): str(value) for key, value in response.headers.items()}, None
    except Exception as exc:  # pragma: no cover - defensive around local tool/runtime differences
        return None, str(exc)


def execute_crypto_audit(
    targets: list[str],
    *,
    scope_allowlist: dict[str, Any] | None = None,
    mode: str = "passive",
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    testssl_binary: str = "testssl.sh",
    ssh_audit_binary: str = "ssh-audit",
    tls_targets: list[str] | None = None,
    ssh_targets: list[Any] | None = None,
    token_evidence: list[Any] | None = None,
    testssl_results: Any | None = None,
    ssh_audit_results: Any | None = None,
    http_headers_by_target: dict[str, dict[str, str]] | None = None,
    execute_ssh: Callable[..., RunnerExecution] = execute_ssh_audit,
) -> RunnerExecution:
    normalized_mode = "active" if str(mode or "").strip().lower() == "active" else "passive"
    target_values = _dedupe([str(target or "").strip() for target in targets])
    tls_target_entries = _normalize_tls_targets(
        target_values,
        configured_tls_targets=tls_targets,
        scope_allowlist=scope_allowlist,
    )
    ssh_target_entries = _normalize_ssh_targets(
        target_values,
        configured_ssh_targets=ssh_targets,
        scope_allowlist=scope_allowlist,
    )
    if not tls_target_entries and not ssh_target_entries and not token_evidence:
        raise ValueError("crypto-audit requires at least one TLS, SSH, or token evidence target")

    warnings: list[str] = []
    findings: list[dict[str, Any]] = []
    artifacts: list[EvidenceArtifact] = []
    tls_results: list[dict[str, Any]] = []
    ssh_results: list[dict[str, Any]] = []

    header_fixtures = http_headers_by_target if isinstance(http_headers_by_target, dict) else {}
    for target in tls_target_entries:
        target_id = str(target["target_id"])
        fixture_payload = _fixture_for_target(testssl_results, target_id)
        if fixture_payload is None:
            testssl_result = _run_testssl(
                binary=testssl_binary,
                target=str(target["testssl_target"]),
                mode=normalized_mode,
                timeout_seconds=timeout_seconds,
            )
        else:
            testssl_result = {
                "status": "fixture",
                "exit_code": 0,
                "command": build_testssl_command(
                    binary=testssl_binary,
                    target=str(target["testssl_target"]),
                    json_output_path="<fixture>/testssl.json",
                    mode=normalized_mode,
                ),
                "stdout": "",
                "stderr": "",
                "payload": fixture_payload,
            }
        if testssl_result.get("stderr"):
            warnings.append(str(testssl_result["stderr"]).strip())

        if target_id in header_fixtures:
            headers = header_fixtures[target_id]
        elif str(target["host"]) in header_fixtures:
            headers = header_fixtures[str(target["host"])]
        else:
            headers = None
        header_error = None
        if headers is None:
            headers, header_error = _fetch_https_headers(
                str(target["https_url"]),
                timeout_seconds=min(timeout_seconds, 5.0),
            )
            if header_error:
                warnings.append(f"HTTPS header check failed for {target_id}: {header_error}")

        target_findings = _analyze_testssl_payload(
            target=target,
            payload=testssl_result.get("payload"),
            http_headers=headers,
        )
        findings.extend(target_findings)
        tls_results.append(
            {
                "target_id": target_id,
                "input": target["input"],
                "host": target["host"],
                "port": target["port"],
                "status": testssl_result.get("status"),
                "exit_code": testssl_result.get("exit_code"),
                "command_family": "testssl.sh",
                "command_preview": " ".join(
                    str(part) for part in testssl_result.get("command", [])
                ),
                "finding_count": len(target_findings),
                "hsts_header_present": bool(headers and headers.get("strict-transport-security")),
            }
        )

    for target in ssh_target_entries:
        target_id = str(target["target_id"])
        fixture_payload = _fixture_for_target(ssh_audit_results, target_id)
        if fixture_payload is None:
            ssh_execution = execute_ssh(
                host=str(target["host"]),
                port=int(target["port"]),
                binary=ssh_audit_binary,
                timeout_seconds=min(timeout_seconds, 15.0),
            )
            artifacts.extend(ssh_execution.artifacts)
            if ssh_execution.stderr:
                warnings.append(ssh_execution.stderr.strip())
            payload: Any = {}
            for artifact in ssh_execution.artifacts:
                if artifact.name.startswith("ssh-audit-") and artifact.data:
                    try:
                        payload = json.loads(artifact.data.decode("utf-8", errors="replace"))
                    except json.JSONDecodeError:
                        payload = {}
                    break
            status = str(ssh_execution.metadata.get("status") or "unknown")
            exit_code = ssh_execution.exit_code
        else:
            payload = fixture_payload
            status = "fixture"
            exit_code = 0
        target_findings = _analyze_ssh_payload(target_id=target_id, payload=payload)
        findings.extend(target_findings)
        ssh_results.append(
            {
                "target_id": target_id,
                "host": target["host"],
                "port": target["port"],
                "status": status,
                "exit_code": exit_code,
                "command_family": "ssh-audit",
                "command_preview": f"{ssh_audit_binary} -j -p {int(target['port'])} {target['host']}",
                "finding_count": len(target_findings),
            }
        )

    token_findings, token_observations = _analyze_token_evidence(token_evidence)
    findings.extend(token_findings)

    status = "completed_with_errors" if warnings else "ok"
    payload = {
        "tool": "crypto-audit",
        "mode": normalized_mode,
        "status": status,
        "targets": target_values,
        "tls_results": tls_results,
        "ssh_results": ssh_results,
        "token_observations": token_observations,
        "findings": findings,
        "analysis_findings": findings,
        "safety": {
            "configuration_and_algorithm_detection_only": True,
            "testssl_used": bool(tls_results),
            "ssh_audit_used": bool(ssh_results),
            "bruteforce_attempted": False,
            "decryption_attempted": False,
            "custom_cipher_analysis": False,
            "known_plaintext_attack_attempted": False,
            "dh_bruteforce_attempted": False,
            "runtime_self_modification": False,
            "raw_tokens_stored": False,
            "scope_enforced": True,
        },
        "warnings": [warning for warning in warnings if warning],
    }
    artifacts.append(_json_artifact(payload))
    return RunnerExecution(
        tool="crypto-audit",
        exit_code=0,
        stdout=json.dumps(
            {
                "status": status,
                "tls_target_count": len(tls_results),
                "ssh_target_count": len(ssh_results),
                "finding_count": len(findings),
            },
            sort_keys=True,
        ),
        stderr="\n".join(payload["warnings"]),
        metadata={
            "status": status,
            "mode": normalized_mode,
            "tls_target_count": len(tls_results),
            "ssh_target_count": len(ssh_results),
            "finding_count": len(findings),
            "runner_digest": "workers.crypto_audit.runner:v1",
            "tool_version": "crypto-audit:testssl+ssh-audit",
        },
        artifacts=artifacts,
    )
