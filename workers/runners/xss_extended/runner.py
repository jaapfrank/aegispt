from __future__ import annotations

import json
import re
from hashlib import sha256
from typing import Any
from urllib.parse import parse_qsl, quote, urlencode, urljoin, urlparse, urlunparse

import httpx as httpx_client

from api.app.services.runs import web_target_value_is_allowed_with_path
from workers.runners.base.contracts import EvidenceArtifact, RunnerExecution
from workers.runners.httpx.runner import normalize_http_target

XSS_EXTENDED_RESULTS_ARTIFACT_NAME = "xss-extended-results.json"
DEFAULT_XSS_PAYLOAD = "<html><script>alert('aegispt-xss')</script></html>"
DEFAULT_AJAX_PAYLOAD = "<script>alert('aegispt-json-xss')</script>"
SENSITIVE_JSON_KEYS = (
    "email",
    "user",
    "username",
    "token",
    "session",
    "account",
    "profile",
    "private_snippet",
)
JSONP_CALLBACK_RE = re.compile(r"^\s*[A-Za-z_$][\w$]*\s*\((?P<body>.*)\)\s*;?\s*$", flags=re.S)


def _json_artifact(name: str, payload: dict[str, Any], *, kind: str = "runner-results") -> EvidenceArtifact:
    return EvidenceArtifact(
        name=name,
        content_type="application/json",
        data=(json.dumps(payload, sort_keys=True) + "\n").encode("utf-8"),
        kind=kind,
    )


def _normalize_string_list(value: object, *, limit: int = 100) -> list[str]:
    if not isinstance(value, list):
        return []
    normalized: list[str] = []
    seen: set[str] = set()
    for item in value:
        candidate = str(item or "").strip()
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)
        normalized.append(candidate)
        if len(normalized) >= limit:
            break
    return normalized


def _render_url(base_target: str, value: str) -> str:
    candidate = str(value or "").strip()
    if not candidate:
        return base_target
    if "://" in candidate:
        return normalize_http_target(candidate)
    return urljoin(base_target.rstrip("/") + "/", candidate.lstrip("/"))


def _allowed(scope_allowlist: dict[str, Any] | None, url: str) -> bool:
    return web_target_value_is_allowed_with_path(scope_allowlist or {}, url)


def _assert_allowed(scope_allowlist: dict[str, Any] | None, url: str) -> None:
    if not _allowed(scope_allowlist, url):
        raise ValueError(f"target outside approved web scope: {url}")


def _same_origin(left: str, right: str) -> bool:
    left_parsed = urlparse(left)
    right_parsed = urlparse(right)
    return (
        left_parsed.scheme.lower(),
        left_parsed.hostname,
        left_parsed.port,
    ) == (
        right_parsed.scheme.lower(),
        right_parsed.hostname,
        right_parsed.port,
    )


def _response_hash(response: httpx_client.Response) -> str:
    return sha256(response.content).hexdigest()


def _body_excerpt(response: httpx_client.Response) -> str:
    return response.text[:500].replace("\n", " ").strip()


def _success_status(status_code: int) -> bool:
    return 200 <= status_code < 300


def _append_finding(
    findings: list[dict[str, Any]],
    seen: set[tuple[str, str]],
    *,
    finding_type: str,
    title: str,
    severity: str,
    target: str,
    summary: str,
    evidence: dict[str, Any],
) -> None:
    key = (title.lower(), target.lower())
    if key in seen:
        return
    seen.add(key)
    findings.append(
        {
            "type": finding_type,
            "title": title,
            "severity": severity,
            "target": target,
            "summary": summary,
            "methodology_tags": ["xss", "input_validation", "xss-extended"],
            "evidence": evidence,
            "replay_recipe": {
                "tool": "xss-extended",
                "target": target,
                "scope": "approved-web-root-only",
            },
        }
    )


def _candidate_records(
    base_target: str,
    *,
    configured: object,
    evidence_records: object,
    candidate_paths: object,
    record_type: str,
    scope_allowlist: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    if isinstance(configured, list):
        records.extend(item for item in configured if isinstance(item, dict))
    if isinstance(evidence_records, list):
        for item in evidence_records:
            if not isinstance(item, dict):
                continue
            raw_type = str(item.get("type") or item.get("kind") or "").strip().lower()
            if raw_type and record_type not in raw_type:
                continue
            records.append(item)
    if not records:
        for path in _normalize_string_list(candidate_paths, limit=50):
            if record_type in path.lower():
                records.append({"url": path})

    normalized: list[dict[str, Any]] = []
    seen_urls: set[str] = set()
    for record in records:
        raw_url = record.get("url") or record.get("target") or record.get("endpoint") or record.get("upload_url")
        if not raw_url:
            continue
        url = _render_url(base_target, str(raw_url))
        if url in seen_urls or not _allowed(scope_allowlist, url):
            continue
        seen_urls.add(url)
        normalized.append({**record, "url": url})
    return normalized


def _extract_returned_url(base_url: str, response: httpx_client.Response) -> str | None:
    location = response.headers.get("Location")
    if location:
        return urljoin(str(response.url), location)
    try:
        payload = response.json()
    except ValueError:
        payload = None
    if isinstance(payload, dict):
        for key in ("url", "path", "location", "file_url", "download_url", "href"):
            value = payload.get(key)
            if isinstance(value, str) and value.strip():
                return urljoin(base_url, value.strip())
    match = re.search(r"""https?://[^\s<>"']+""", response.text, flags=re.I)
    if match:
        return match.group(0)
    match = re.search(r"""(?:href|src)\s*=\s*["']([^"']+)["']""", response.text, flags=re.I)
    if match:
        return urljoin(str(response.url), match.group(1))
    return None


def _is_executable_html(response: httpx_client.Response, payload: str) -> bool:
    content_type = response.headers.get("Content-Type", "").lower()
    disposition = response.headers.get("Content-Disposition", "").lower()
    body = response.text.lower()
    return (
        payload.lower() in body
        and "<script" in body
        and "text/plain" not in content_type
        and "attachment" not in disposition
    )


def _inject_query(url: str, payload: str, parameters: list[str]) -> str:
    parsed = urlparse(url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    names = parameters or [name for name, _ in pairs] or ["q"]
    existing = dict(pairs)
    for name in names:
        existing[name] = payload
    return urlunparse(parsed._replace(query=urlencode(existing)))


def _json_or_jsonp_payload(text: str) -> str | None:
    stripped = text.strip()
    if stripped.startswith(("{", "[")):
        return stripped
    match = JSONP_CALLBACK_RE.match(stripped)
    if not match:
        return None
    inner = match.group("body").strip()
    while len(inner) >= 2 and inner.startswith("(") and inner.endswith(")"):
        inner = inner[1:-1].strip()
    if inner.startswith(("{", "[")):
        return inner
    return None


def _looks_like_sensitive_json(response: httpx_client.Response) -> bool:
    content_type = response.headers.get("Content-Type", "").lower()
    text = response.text.strip()
    json_payload = _json_or_jsonp_payload(text)
    if not ("json" in content_type or "javascript" in content_type or json_payload is not None):
        return False
    lower = (json_payload or text).lower()
    return any(f'"{key}"' in lower or f"{key}:" in lower for key in SENSITIVE_JSON_KEYS)


def _xssi_missing_protections(response: httpx_client.Response) -> list[str]:
    missing: list[str] = []
    if response.headers.get("X-Content-Type-Options", "").lower() != "nosniff":
        missing.append("x-content-type-options:nosniff")
    if "origin" not in response.headers.get("Vary", "").lower():
        missing.append("vary:origin")
    if not (
        response.headers.get("X-CSRF-Token")
        or response.headers.get("CSRF-Token")
        or response.headers.get("Content-Security-Policy")
    ):
        missing.append("csrf-or-csp-signal")
    return missing


def _urls_with_query_params(candidate_paths: object, base_target: str, scope_allowlist: dict[str, Any] | None) -> list[tuple[str, list[str]]]:
    """Return (url, [param_names]) for every candidate path that has a query string."""
    result: list[tuple[str, list[str]]] = []
    seen: set[str] = set()
    for raw in _normalize_string_list(candidate_paths, limit=100):
        url = _render_url(base_target, raw)
        if url in seen or not _allowed(scope_allowlist, url):
            continue
        parsed = urlparse(url)
        pairs = parse_qsl(parsed.query, keep_blank_values=True)
        if not pairs:
            continue
        seen.add(url)
        result.append((url, [name for name, _ in pairs]))
    return result


def execute_xss_extended_scan(
    targets: list[str],
    *,
    scope_allowlist: dict[str, Any] | None = None,
    upload_contexts: list[dict[str, Any]] | object = None,
    ajax_contexts: list[dict[str, Any]] | object = None,
    xssi_contexts: list[dict[str, Any]] | object = None,
    evidence_records: list[dict[str, Any]] | object = None,
    candidate_paths: list[str] | object = None,
    xss_payload: str = DEFAULT_XSS_PAYLOAD,
    ajax_payload: str = DEFAULT_AJAX_PAYLOAD,
    timeout_seconds: float = 10.0,
    client_factory: Any = httpx_client.Client,
) -> RunnerExecution:
    if not targets:
        raise ValueError("at least one target is required")
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be greater than zero")

    normalized_targets = [normalize_http_target(target) for target in targets]
    for target in normalized_targets:
        _assert_allowed(scope_allowlist, target)

    checks: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    seen_findings: set[tuple[str, str]] = set()
    stderr_lines: list[str] = []
    exit_code = 0

    with client_factory(follow_redirects=True, timeout=timeout_seconds) as client:
        for base_target in normalized_targets:
            upload_records = _candidate_records(
                base_target,
                configured=upload_contexts,
                evidence_records=evidence_records,
                candidate_paths=candidate_paths,
                record_type="upload",
                scope_allowlist=scope_allowlist,
            )
            for record in upload_records:
                upload_url = str(record["url"])
                field_name = str(record.get("file_field") or "file").strip() or "file"
                filename = str(record.get("filename") or "aegispt-xss.html").strip() or "aegispt-xss.html"
                try:
                    response = client.post(
                        upload_url,
                        files={field_name: (filename, xss_payload.encode("utf-8"), "text/html")},
                    )
                except httpx_client.HTTPError as exc:
                    exit_code = 1
                    stderr_lines.append(f"file upload XSS check failed for {upload_url}: {exc}")
                    continue
                uploaded_url = str(record.get("uploaded_url") or "").strip() or _extract_returned_url(base_target, response)
                check = {
                    "check_type": "file_upload_xss",
                    "target": upload_url,
                    "status_code": response.status_code,
                    "returned_url": uploaded_url,
                    "response_hash": _response_hash(response),
                }
                checks.append(check)
                if not uploaded_url:
                    continue
                served_url = _render_url(base_target, uploaded_url)
                if not _same_origin(base_target, served_url) or not _allowed(scope_allowlist, served_url):
                    continue
                try:
                    served = client.get(served_url)
                except httpx_client.HTTPError as exc:
                    exit_code = 1
                    stderr_lines.append(f"uploaded file retrieval failed for {served_url}: {exc}")
                    continue
                checks.append(
                    {
                        "check_type": "uploaded_file_retrieval",
                        "target": served_url,
                        "status_code": served.status_code,
                        "content_type": served.headers.get("Content-Type", ""),
                        "content_disposition": served.headers.get("Content-Disposition", ""),
                        "response_hash": _response_hash(served),
                    }
                )
                if _success_status(served.status_code) and _is_executable_html(served, xss_payload):
                    _append_finding(
                        findings,
                        seen_findings,
                        finding_type="stored_xss_unrestricted_html_upload",
                        title="Stored XSS via Unrestricted HTML Upload",
                        severity="high",
                        target=served_url,
                        summary="An uploaded HTML file was served from the same origin without text/plain or attachment protections.",
                        evidence={
                            **check,
                            "served_status_code": served.status_code,
                            "served_content_type": served.headers.get("Content-Type", ""),
                            "served_content_disposition": served.headers.get("Content-Disposition", ""),
                            "response_excerpt": _body_excerpt(served),
                        },
                    )

            ajax_records = _candidate_records(
                base_target,
                configured=ajax_contexts,
                evidence_records=evidence_records,
                candidate_paths=candidate_paths,
                record_type="ajax",
                scope_allowlist=scope_allowlist,
            )
            for record in ajax_records:
                ajax_url = str(record["url"])
                method = str(record.get("method") or "GET").strip().upper() or "GET"
                parameters = _normalize_string_list(record.get("parameters"), limit=20)
                try:
                    if method == "POST" and isinstance(record.get("json"), dict):
                        body = {
                            str(key): ajax_payload
                            for key in (parameters or list(record["json"].keys()) or ["q"])
                        }
                        response = client.post(ajax_url, json={**record["json"], **body})
                        requested_url = ajax_url
                    else:
                        requested_url = _inject_query(ajax_url, ajax_payload, parameters)
                        response = client.get(requested_url)
                except httpx_client.HTTPError as exc:
                    exit_code = 1
                    stderr_lines.append(f"AJAX/JSON XSS check failed for {ajax_url}: {exc}")
                    continue
                content_type = response.headers.get("Content-Type", "").lower()
                payload_reflected = ajax_payload in response.text
                dangerous_context = "text/html" in content_type or "javascript" in content_type or "json" not in content_type
                check = {
                    "check_type": "ajax_json_xss",
                    "target": requested_url,
                    "method": method,
                    "status_code": response.status_code,
                    "content_type": response.headers.get("Content-Type", ""),
                    "payload_reflected": payload_reflected,
                    "dangerous_context": dangerous_context,
                    "response_hash": _response_hash(response),
                }
                checks.append(check)
                if _success_status(response.status_code) and payload_reflected and dangerous_context:
                    _append_finding(
                        findings,
                        seen_findings,
                        finding_type="ajax_json_xss_response_context",
                        title="AJAX/JSON XSS in Response Context",
                        severity="high",
                        target=requested_url,
                        summary="An AJAX/JSON-style endpoint reflected an XSS payload in a browser-executable response context.",
                        evidence={**check, "response_excerpt": _body_excerpt(response)},
                    )

            xssi_records = _candidate_records(
                base_target,
                configured=xssi_contexts,
                evidence_records=evidence_records,
                candidate_paths=candidate_paths,
                record_type="json",
                scope_allowlist=scope_allowlist,
            )
            for record in xssi_records:
                xssi_url = str(record["url"])
                try:
                    response = client.get(
                        xssi_url,
                        headers={"User-Agent": "AegisPT/xss-extended xssi check"},
                    )
                except httpx_client.HTTPError as exc:
                    exit_code = 1
                    stderr_lines.append(f"XSSI check failed for {xssi_url}: {exc}")
                    continue
                missing = _xssi_missing_protections(response)
                sensitive = _looks_like_sensitive_json(response)
                check = {
                    "check_type": "xssi",
                    "target": xssi_url,
                    "status_code": response.status_code,
                    "content_type": response.headers.get("Content-Type", ""),
                    "sensitive_json": sensitive,
                    "missing_protections": missing,
                    "response_hash": _response_hash(response),
                }
                checks.append(check)
                if _success_status(response.status_code) and sensitive and missing:
                    _append_finding(
                        findings,
                        seen_findings,
                        finding_type="xssi_json_data_leakage",
                        title="Cross-Site Script Inclusion - Data Leakage via JSONP or JSON without protection",
                        severity="high",
                        target=xssi_url,
                        summary="A sensitive JSON response is accessible without the expected anti-XSSI response protections.",
                        evidence={**check, "response_excerpt": _body_excerpt(response)},
                    )

            # Path-component XSS: append raw XSS payloads as URL path segments.
            # Covers error pages that reflect the path verbatim (e.g. Gruyere /id/INVALID_PATH).
            _PATH_XSS_PAYLOADS = [
                "<script>alert('aegispt-xss')</script>",
                "<img src=x onerror=alert(1)>",
                "\"><script>alert(1)</script>",
            ]
            # Also probe generic invalid paths to detect reflection surfaces first.
            _PROBE_PATHS = [
                "aegispt-404-probe",
                "undefined-path-xss-probe",
                "error-test-aegispt",
            ]
            base_stripped = base_target.rstrip("/")
            reflection_detected = False

            for probe in _PROBE_PATHS:
                probe_url = f"{base_stripped}/{probe}"
                if not _allowed(scope_allowlist, probe_url):
                    continue
                try:
                    resp = client.get(probe_url)
                except httpx_client.HTTPError:
                    continue
                ct = resp.headers.get("Content-Type", "").lower()
                if "text/html" not in ct and ct:
                    continue
                if probe in resp.text:
                    reflection_detected = True
                    break

            path_payloads_to_test = _PATH_XSS_PAYLOADS if not reflection_detected else _PATH_XSS_PAYLOADS[:1]
            for payload_str in path_payloads_to_test:
                # Encode only characters that would break HTTP path parsing, keeping < > " ' intact
                encoded_path = quote(payload_str, safe="/<>\"'!()-_.")
                path_url = f"{base_stripped}/{encoded_path}"
                if not _allowed(scope_allowlist, path_url):
                    continue
                try:
                    resp = client.get(path_url)
                except httpx_client.HTTPError as exc:
                    stderr_lines.append(f"path XSS check failed for {path_url}: {exc}")
                    continue
                ct = resp.headers.get("Content-Type", "").lower()
                html_ctx = "text/html" in ct or not ct
                # Detection: raw payload or its html-decoded form appears unencoded in response body
                raw_reflected = payload_str in resp.text
                # Also check for partial match: just the <script> or onerror= token unencoded
                script_token = "<script>" in resp.text.lower() or "onerror=" in resp.text.lower()
                unencoded_angle = "<" in resp.text and ">" in resp.text and not all(
                    enc in resp.text for enc in ["&lt;", "&gt;"]
                )
                reflected = raw_reflected or (script_token and unencoded_angle)
                check = {
                    "check_type": "reflected_xss_path_component",
                    "target": path_url,
                    "base_target": base_target,
                    "payload": payload_str,
                    "status_code": resp.status_code,
                    "content_type": resp.headers.get("Content-Type", ""),
                    "payload_reflected": reflected,
                    "html_context": html_ctx,
                    "response_hash": _response_hash(resp),
                }
                checks.append(check)
                if html_ctx and reflected:
                    _append_finding(
                        findings,
                        seen_findings,
                        finding_type="reflected_xss_path_component",
                        title="Reflected XSS via URL Path Component",
                        severity="high",
                        target=path_url,
                        summary=(
                            f"An XSS payload injected as a URL path segment was reflected "
                            f"unencoded in the HTML response from {base_target}."
                        ),
                        evidence={
                            **check,
                            "response_excerpt": _body_excerpt(resp),
                            "reflection_detected_on_probe": reflection_detected,
                        },
                    )
                    break  # One confirmed path XSS per target is enough

            # Reflected XSS via URL parameters: inject into every query-string param in discovered paths.
            for param_url, param_names in _urls_with_query_params(candidate_paths, base_target, scope_allowlist):
                injected_url = _inject_query(param_url, ajax_payload, param_names)
                try:
                    response = client.get(injected_url)
                except httpx_client.HTTPError as exc:
                    stderr_lines.append(f"reflected XSS param check failed for {injected_url}: {exc}")
                    continue
                content_type = response.headers.get("Content-Type", "").lower()
                payload_in_body = ajax_payload in response.text
                html_context = "text/html" in content_type or not content_type
                check = {
                    "check_type": "reflected_xss_url_param",
                    "target": injected_url,
                    "original_url": param_url,
                    "tested_params": param_names,
                    "status_code": response.status_code,
                    "content_type": response.headers.get("Content-Type", ""),
                    "payload_reflected": payload_in_body,
                    "html_context": html_context,
                    "response_hash": _response_hash(response),
                }
                checks.append(check)
                if _success_status(response.status_code) and payload_in_body and html_context:
                    _append_finding(
                        findings,
                        seen_findings,
                        finding_type="reflected_xss_url_parameter",
                        title=f"Reflected XSS via URL Parameter ({', '.join(param_names)})",
                        severity="high",
                        target=param_url,
                        summary=f"XSS payload injected into URL parameter(s) {param_names} was reflected unencoded in an HTML response.",
                        evidence={**check, "response_excerpt": _body_excerpt(response)},
                    )

    payload = {
        "tool": "xss-extended",
        "targets": normalized_targets,
        "checks": checks,
        "findings": findings,
        "summary": {
            "target_count": len(normalized_targets),
            "check_count": len(checks),
            "finding_count": len(findings),
            "file_upload_findings": sum(1 for finding in findings if finding.get("type") == "stored_xss_unrestricted_html_upload"),
            "ajax_json_findings": sum(1 for finding in findings if finding.get("type") == "ajax_json_xss_response_context"),
            "xssi_findings": sum(1 for finding in findings if finding.get("type") == "xssi_json_data_leakage"),
            "reflected_url_param_findings": sum(1 for finding in findings if finding.get("type") == "reflected_xss_url_parameter"),
            "reflected_path_findings": sum(1 for finding in findings if finding.get("type") == "reflected_xss_path_component"),
        },
        "safety": {
            "scope_enforced": True,
            "approved_web_root_only": True,
            "variants": ["file-upload-xss", "ajax-json-xss", "xssi", "reflected-url-param", "reflected-path-component"],
            "zap_configuration_changed": False,
            "runtime_mutation": False,
            "requires_active_approval": True,
        },
    }
    return RunnerExecution(
        tool="xss-extended",
        exit_code=exit_code,
        stdout=json.dumps(payload["summary"], sort_keys=True),
        stderr="\n".join(line for line in stderr_lines if line),
        metadata={
            "status": "ok" if exit_code == 0 else "completed_with_errors",
            "runner_digest": "workers.xss_extended.runner:v1",
            "tool_version": "custom-python-bounded",
            "finding_count": len(findings),
            "check_count": len(checks),
        },
        artifacts=[_json_artifact(XSS_EXTENDED_RESULTS_ARTIFACT_NAME, payload)],
    )
