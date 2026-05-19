from __future__ import annotations

import json
import re
from hashlib import sha256
from typing import Any, Callable
from urllib.parse import urljoin, urlparse

import httpx as httpx_client

from api.app.services.runs import web_target_value_is_allowed_with_path
from workers.runners.base.contracts import EvidenceArtifact, RunnerExecution
from workers.runners.httpx.runner import normalize_http_target

HEADERS_SECURITY_RESULTS_ARTIFACT_NAME = "headers-security-results.json"
DEFAULT_ATTACKER_ORIGIN = "https://evil.example.com"
SENSITIVE_PATH_HINTS = (
    "account",
    "admin",
    "checkout",
    "login",
    "password",
    "profile",
    "reset",
    "settings",
    "signin",
)
VERSION_HEADER_PATTERN = re.compile(r"\b[A-Za-z][A-Za-z0-9_.+-]*/\d+(?:\.\d+){0,4}\b")


def _json_artifact(name: str, payload: dict[str, Any], *, kind: str = "runner-results") -> EvidenceArtifact:
    return EvidenceArtifact(
        name=name,
        content_type="application/json",
        data=(json.dumps(payload, sort_keys=True) + "\n").encode("utf-8"),
        kind=kind,
    )


def _allowed(scope_allowlist: dict[str, Any] | None, url: str) -> bool:
    return web_target_value_is_allowed_with_path(scope_allowlist or {}, url)


def _assert_allowed(scope_allowlist: dict[str, Any] | None, url: str) -> None:
    if not _allowed(scope_allowlist, url):
        raise ValueError(f"target outside approved web scope: {url}")


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


def _response_hash(response: httpx_client.Response) -> str:
    return sha256(response.content).hexdigest()


def _body_excerpt(response: httpx_client.Response) -> str:
    return re.sub(r"\s+", " ", response.text or "").strip()[:500]


def _header_value(headers: httpx_client.Headers | dict[str, str], name: str) -> str:
    try:
        return str(headers.get(name) or "").strip()
    except AttributeError:
        lowered = {str(key).lower(): str(value) for key, value in dict(headers).items()}
        return lowered.get(name.lower(), "").strip()


def _has_credentials_enabled(headers: httpx_client.Headers) -> bool:
    return _header_value(headers, "Access-Control-Allow-Credentials").lower() == "true"


def _acao(headers: httpx_client.Headers) -> str:
    return _header_value(headers, "Access-Control-Allow-Origin")


def _csp_directives(csp: str) -> dict[str, list[str]]:
    directives: dict[str, list[str]] = {}
    for raw_directive in csp.split(";"):
        parts = [part.strip() for part in raw_directive.split() if part.strip()]
        if not parts:
            continue
        directives[parts[0].lower()] = parts[1:]
    return directives


def _source_values(directives: dict[str, list[str]], directive: str) -> list[str]:
    return directives.get(directive, directives.get("default-src", []))


def _has_frame_protection(headers: httpx_client.Headers) -> bool:
    xfo = _header_value(headers, "X-Frame-Options").lower()
    if xfo in {"deny", "sameorigin"}:
        return True
    frame_ancestors = _csp_directives(_header_value(headers, "Content-Security-Policy")).get(
        "frame-ancestors",
        [],
    )
    return bool(frame_ancestors and any(value in {"'none'", "'self'"} for value in frame_ancestors))


def _is_sensitive_page(url: str, response: httpx_client.Response) -> bool:
    path = (urlparse(url).path or "/").lower()
    if any(hint in path for hint in SENSITIVE_PATH_HINTS):
        return True
    body = (response.text or "").lower()
    return "<form" in body and (
        'type="password"' in body
        or "name=\"csrf" in body
        or "name='csrf" in body
        or "password" in body
    )


def _hsts_state(value: str) -> dict[str, Any]:
    state: dict[str, Any] = {
        "present": bool(value),
        "min_age": None,
        "include_subdomains": False,
        "preload": False,
    }
    if not value:
        return state
    for part in value.split(";"):
        item = part.strip()
        lower = item.lower()
        if lower.startswith("max-age="):
            try:
                state["min_age"] = int(item.split("=", 1)[1])
            except ValueError:
                state["min_age"] = None
        elif lower == "includesubdomains":
            state["include_subdomains"] = True
        elif lower == "preload":
            state["preload"] = True
    return state


def _append_finding(
    findings: list[dict[str, Any]],
    seen: set[tuple[str, str, str]],
    *,
    finding_type: str,
    title: str,
    severity: str,
    target: str,
    summary: str,
    evidence: dict[str, Any],
) -> None:
    key = (finding_type, target, str(evidence.get("header") or evidence.get("origin") or evidence.get("directive") or ""))
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
            "confirmed": True,
            "methodology_tags": [
                "security_misconfiguration",
                "http_security_headers",
                "headers-security-validation",
            ],
            "control_family": "configuration",
            "evidence": evidence,
            "replay_recipe": {
                "tool": "headers-security",
                "target": target,
                "scope": "approved-web-root-only",
                "cors_data_extraction_performed": False,
                "clickjacking_poc_created": False,
            },
        }
    )


def _analyze_cors_response(
    *,
    findings: list[dict[str, Any]],
    seen: set[tuple[str, str, str]],
    target: str,
    origin: str,
    response: httpx_client.Response,
    probe_type: str,
) -> dict[str, Any]:
    allow_origin = _acao(response.headers)
    credentials = _has_credentials_enabled(response.headers)
    redirect = 300 <= response.status_code < 400
    check = {
        "check_type": "cors_origin_probe",
        "probe_type": probe_type,
        "target": target,
        "origin": origin,
        "status_code": response.status_code,
        "access_control_allow_origin": allow_origin,
        "access_control_allow_credentials": credentials,
        "redirect_response": redirect,
        "location_present": bool(_header_value(response.headers, "Location")),
        "response_hash": _response_hash(response),
        "actual_cross_origin_data_extracted": False,
    }

    if allow_origin == origin and credentials:
        severity = "critical" if probe_type == "attacker-origin" else "high"
        _append_finding(
            findings,
            seen,
            finding_type=f"cors_{probe_type.replace('-', '_')}_credential_reflection",
            title="CORS Credential Reflection Allows Cross-Origin Authenticated Reads",
            severity=severity,
            target=target,
            summary=(
                "The response reflected an untrusted Origin and allowed credentials. "
                "AegisPT did not extract cross-origin data."
            ),
            evidence={**check, "header": "Access-Control-Allow-Origin"},
        )
    elif allow_origin == "*" and credentials:
        _append_finding(
            findings,
            seen,
            finding_type="cors_wildcard_with_credentials",
            title="CORS Wildcard Origin Combined with Credentials",
            severity="high",
            target=target,
            summary="The response combines Access-Control-Allow-Origin: * with credential support.",
            evidence={**check, "header": "Access-Control-Allow-Origin"},
        )
    elif origin == "null" and allow_origin.lower() == "null" and credentials:
        _append_finding(
            findings,
            seen,
            finding_type="cors_null_origin_credentials",
            title="CORS Null Origin Accepted with Credentials",
            severity="high",
            target=target,
            summary="The response accepts the null Origin while allowing credentials.",
            evidence={**check, "header": "Access-Control-Allow-Origin"},
        )

    if redirect and allow_origin and credentials:
        _append_finding(
            findings,
            seen,
            finding_type="cors_headers_preserved_on_redirect",
            title="Credentialed CORS Headers Preserved on Redirect",
            severity="medium",
            target=target,
            summary=(
                "A redirect response preserved credentialed CORS headers. "
                "The runner records the header behavior only and does not follow it to extract data."
            ),
            evidence={**check, "header": "Access-Control-Allow-Origin"},
        )
    return check


def _jsonp_allowlist_sources(sources: list[str]) -> list[str]:
    risky: list[str] = []
    for source in sources:
        lower = source.lower()
        if "jsonp" in lower or "callback=" in lower or "ajax.googleapis.com" in lower:
            risky.append(source)
    return risky


def _analyze_passive_headers(
    *,
    findings: list[dict[str, Any]],
    seen: set[tuple[str, str, str]],
    target: str,
    response: httpx_client.Response,
) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    csp = _header_value(response.headers, "Content-Security-Policy")
    directives = _csp_directives(csp)
    script_sources = _source_values(directives, "script-src")
    csp_check = {
        "check_type": "csp_policy_analysis",
        "target": target,
        "csp_present": bool(csp),
        "directives": sorted(directives.keys()),
        "script_src": script_sources,
    }
    checks.append(csp_check)
    if csp:
        if "'unsafe-inline'" in script_sources:
            _append_finding(
                findings,
                seen,
                finding_type="csp_unsafe_inline",
                title="CSP Allows unsafe-inline Scripts",
                severity="medium",
                target=target,
                summary="The Content-Security-Policy script sources allow unsafe-inline.",
                evidence={**csp_check, "directive": "script-src", "header": "Content-Security-Policy"},
            )
        if "'unsafe-eval'" in script_sources:
            _append_finding(
                findings,
                seen,
                finding_type="csp_unsafe_eval",
                title="CSP Allows unsafe-eval Scripts",
                severity="medium",
                target=target,
                summary="The Content-Security-Policy script sources allow unsafe-eval.",
                evidence={**csp_check, "directive": "script-src", "header": "Content-Security-Policy"},
            )
        if "*" in script_sources:
            _append_finding(
                findings,
                seen,
                finding_type="csp_wildcard_script_source",
                title="CSP Uses Wildcard Script Source",
                severity="medium",
                target=target,
                summary="The Content-Security-Policy allows wildcard script sources.",
                evidence={**csp_check, "directive": "script-src", "header": "Content-Security-Policy"},
            )
        if "default-src" not in directives:
            _append_finding(
                findings,
                seen,
                finding_type="csp_missing_default_src",
                title="CSP Missing default-src Directive",
                severity="low",
                target=target,
                summary="The Content-Security-Policy does not define a default-src fallback.",
                evidence={**csp_check, "directive": "default-src", "header": "Content-Security-Policy"},
            )
        if any(source.lower() == "data:" for source in script_sources):
            _append_finding(
                findings,
                seen,
                finding_type="csp_data_script_source",
                title="CSP Allows data: Script Source",
                severity="medium",
                target=target,
                summary="The Content-Security-Policy permits data: in script sources.",
                evidence={**csp_check, "directive": "script-src", "header": "Content-Security-Policy"},
            )
        jsonp_sources = _jsonp_allowlist_sources(script_sources)
        if jsonp_sources:
            _append_finding(
                findings,
                seen,
                finding_type="csp_jsonp_allowlist_risk",
                title="CSP Script Allowlist Includes JSONP-Capable Source",
                severity="low",
                target=target,
                summary="The script allowlist includes sources commonly associated with JSONP/callback execution risk.",
                evidence={
                    **csp_check,
                    "directive": "script-src",
                    "jsonp_like_sources": jsonp_sources,
                    "header": "Content-Security-Policy",
                },
            )

    frame_protected = _has_frame_protection(response.headers)
    clickjacking_check = {
        "check_type": "clickjacking_header_analysis",
        "target": target,
        "sensitive_page": _is_sensitive_page(target, response),
        "x_frame_options": _header_value(response.headers, "X-Frame-Options"),
        "frame_ancestors": directives.get("frame-ancestors", []),
        "frame_protection_present": frame_protected,
    }
    checks.append(clickjacking_check)
    if clickjacking_check["sensitive_page"] and not frame_protected:
        _append_finding(
            findings,
            seen,
            finding_type="clickjacking_sensitive_page_missing_frame_protection",
            title="Sensitive Page Missing Clickjacking Frame Protection",
            severity="medium",
            target=target,
            summary="A login, form, or sensitive page is missing X-Frame-Options and CSP frame-ancestors protection.",
            evidence={**clickjacking_check, "response_excerpt": _body_excerpt(response)},
        )

    if urlparse(target).scheme.lower() == "https":
        hsts = _header_value(response.headers, "Strict-Transport-Security")
        hsts_details = _hsts_state(hsts)
        hsts_check = {
            "check_type": "hsts_analysis",
            "target": target,
            "strict_transport_security": hsts,
            **hsts_details,
        }
        checks.append(hsts_check)
        if not hsts:
            _append_finding(
                findings,
                seen,
                finding_type="hsts_missing",
                title="HSTS Missing on HTTPS Target",
                severity="medium",
                target=target,
                summary="The HTTPS target does not send Strict-Transport-Security.",
                evidence={**hsts_check, "header": "Strict-Transport-Security"},
            )
        elif (hsts_details["min_age"] or 0) < 31536000 or not hsts_details["include_subdomains"]:
            _append_finding(
                findings,
                seen,
                finding_type="hsts_incomplete",
                title="HSTS Policy Is Incomplete",
                severity="low",
                target=target,
                summary="Strict-Transport-Security is present but lacks a one-year min-age or includeSubDomains.",
                evidence={**hsts_check, "header": "Strict-Transport-Security"},
            )

    disclosure_headers = {
        "Server": _header_value(response.headers, "Server"),
        "X-Powered-By": _header_value(response.headers, "X-Powered-By"),
        "X-AspNet-Version": _header_value(response.headers, "X-AspNet-Version"),
        "X-AspNetMvc-Version": _header_value(response.headers, "X-AspNetMvc-Version"),
    }
    disclosure_check = {
        "check_type": "information_disclosure_header_analysis",
        "target": target,
        "headers_present": [name for name, value in disclosure_headers.items() if value],
    }
    checks.append(disclosure_check)
    for header_name, header_value in disclosure_headers.items():
        if not header_value:
            continue
        has_version = bool(VERSION_HEADER_PATTERN.search(header_value)) or header_name.lower().startswith("x-aspnet")
        if header_name.lower() == "x-powered-by" or has_version:
            _append_finding(
                findings,
                seen,
                finding_type="information_disclosure_header",
                title="Information Disclosure Header Exposes Platform Detail",
                severity="info" if header_name.lower() == "server" and not has_version else "low",
                target=target,
                summary=f"The {header_name} response header exposes implementation or version detail.",
                evidence={
                    "check_type": "information_disclosure_header",
                    "target": target,
                    "header": header_name,
                    "value_class": "versioned" if has_version else "platform",
                    "raw_header_value_recorded": False,
                },
            )
    return checks


def _regex_bypass_origin_for_target(target: str) -> str:
    host = urlparse(target).hostname or "target.example"
    return f"https://{host}.evil.example.com"


def execute_headers_security_analysis(
    targets: list[str],
    *,
    scope_allowlist: dict[str, Any] | None = None,
    attacker_origin: str = DEFAULT_ATTACKER_ORIGIN,
    additional_origins: list[str] | object = None,
    redirect_paths: list[str] | object = None,
    timeout_seconds: float = 10.0,
    client_factory: Callable[..., Any] = httpx_client.Client,
) -> RunnerExecution:
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be greater than zero")
    normalized_targets = _normalize_targets(targets, scope_allowlist)
    origins = [attacker_origin, "null"]
    for origin in additional_origins if isinstance(additional_origins, list) else []:
        candidate = str(origin or "").strip()
        if candidate and candidate not in origins:
            origins.append(candidate)

    checks: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    seen_findings: set[tuple[str, str, str]] = set()
    stderr_lines: list[str] = []
    exit_code = 0

    with client_factory(follow_redirects=False, timeout=timeout_seconds) as client:
        for target in normalized_targets:
            try:
                response = client.get(
                    target,
                    headers={"User-Agent": "AegisPT/headers-security bounded validation"},
                )
                checks.append(
                    {
                        "check_type": "baseline_header_fetch",
                        "target": target,
                        "status_code": response.status_code,
                        "response_hash": _response_hash(response),
                    }
                )
                checks.extend(
                    _analyze_passive_headers(
                        findings=findings,
                        seen=seen_findings,
                        target=target,
                        response=response,
                    )
                )
            except httpx_client.HTTPError as exc:
                exit_code = 1
                stderr_lines.append(f"header analysis failed for {target}: {exc}")
                continue

            probe_origins = list(origins)
            bypass_origin = _regex_bypass_origin_for_target(target)
            if bypass_origin not in probe_origins:
                probe_origins.append(bypass_origin)
            for origin in probe_origins:
                probe_type = (
                    "null-origin"
                    if origin == "null"
                    else "regex-bypass-origin"
                    if origin == bypass_origin
                    else "attacker-origin"
                )
                try:
                    probe_response = client.get(
                        target,
                        headers={
                            "User-Agent": "AegisPT/headers-security bounded CORS validation",
                            "Origin": origin,
                        },
                    )
                    checks.append(
                        _analyze_cors_response(
                            findings=findings,
                            seen=seen_findings,
                            target=target,
                            origin=origin,
                            response=probe_response,
                            probe_type=probe_type,
                        )
                    )
                except httpx_client.HTTPError as exc:
                    exit_code = 1
                    stderr_lines.append(f"CORS origin probe failed for {target} with {origin}: {exc}")

            for raw_path in redirect_paths if isinstance(redirect_paths, list) else []:
                redirect_url = urljoin(target.rstrip("/") + "/", str(raw_path or "").lstrip("/"))
                if not _allowed(scope_allowlist, redirect_url):
                    continue
                try:
                    redirect_response = client.get(
                        redirect_url,
                        headers={
                            "User-Agent": "AegisPT/headers-security bounded CORS redirect validation",
                            "Origin": attacker_origin,
                        },
                    )
                    checks.append(
                        _analyze_cors_response(
                            findings=findings,
                            seen=seen_findings,
                            target=redirect_url,
                            origin=attacker_origin,
                            response=redirect_response,
                            probe_type="redirect-cors-preservation",
                        )
                    )
                except httpx_client.HTTPError as exc:
                    exit_code = 1
                    stderr_lines.append(f"CORS redirect probe failed for {redirect_url}: {exc}")

    payload = {
        "tool": "headers-security",
        "targets": normalized_targets,
        "checks": checks,
        "findings": findings,
        "summary": {
            "target_count": len(normalized_targets),
            "check_count": len(checks),
            "finding_count": len(findings),
            "cors_findings": sum(1 for item in findings if str(item.get("type", "")).startswith("cors_")),
            "csp_findings": sum(1 for item in findings if str(item.get("type", "")).startswith("csp_")),
            "clickjacking_findings": sum(1 for item in findings if str(item.get("type", "")).startswith("clickjacking")),
            "hsts_findings": sum(1 for item in findings if str(item.get("type", "")).startswith("hsts_")),
            "information_disclosure_findings": sum(1 for item in findings if item.get("type") == "information_disclosure_header"),
        },
        "safety": {
            "scope_enforced": True,
            "approved_web_root_only": True,
            "passive_header_analysis": True,
            "active_origin_reflection_probes": True,
            "actual_cors_data_extraction": False,
            "csp_nonce_bypass_attempted": False,
            "clickjacking_poc_created": False,
            "zap_configuration_changed": False,
            "ssl_tls_runner_changed": False,
            "runtime_mutation": False,
        },
    }
    return RunnerExecution(
        tool="headers-security",
        exit_code=exit_code,
        stdout=json.dumps(payload["summary"], sort_keys=True),
        stderr="\n".join(line for line in stderr_lines if line),
        metadata={
            "status": "ok" if exit_code == 0 else "completed_with_errors",
            "runner_digest": "workers.headers_security.runner:v1",
            "tool_version": "custom-python-bounded",
            "finding_count": len(findings),
            "check_count": len(checks),
        },
        artifacts=[_json_artifact(HEADERS_SECURITY_RESULTS_ARTIFACT_NAME, payload)],
    )

