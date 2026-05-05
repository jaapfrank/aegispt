from __future__ import annotations

import json
import re
from hashlib import sha256
from typing import Any, Callable
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

import httpx as httpx_client

from api.app.services.runs import web_target_value_is_allowed_with_path
from workers.runners.base.contracts import EvidenceArtifact, RunnerExecution
from workers.runners.httpx.runner import normalize_http_target

OAUTH_PROBE_RESULTS_ARTIFACT_NAME = "oauth-probe-results.json"
DEFAULT_TIMEOUT_SECONDS = 5.0
MAX_FETCHED_SCRIPT_COUNT = 5
DEFAULT_WELL_KNOWN_PATHS = ("/.well-known/openid-configuration",)
DEFAULT_LOGIN_PATHS = ("/login", "/signin", "/oauth/authorize", "/authorize")
URL_TOKEN_PATTERN = re.compile(
    r"""(?P<url>https?://[^\s"'<>\\)]+|/[A-Za-z0-9._~!$&'()*+,;=:@%/?#-]+)"""
)
HTML_ATTR_PATTERN = re.compile(
    r"""(?:href|src|action)\s*=\s*["'](?P<url>[^"']+)["']""",
    re.IGNORECASE,
)
TOKEN_PARAMETER_NAMES = {"access_token", "id_token", "refresh_token", "token"}
SENSITIVE_SCOPE_NAMES = {
    "admin",
    "write",
    "delete",
    "offline_access",
    "openid",
    "profile",
    "email",
}


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
        raise ValueError(f"target outside approved OAuth/OIDC web scope: {url}")


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


def _dedupe_dicts(items: list[dict[str, Any]], *, key_fields: tuple[str, ...]) -> list[dict[str, Any]]:
    deduped: list[dict[str, Any]] = []
    seen: set[tuple[str, ...]] = set()
    for item in items:
        key = tuple(str(item.get(field) or "") for field in key_fields)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return deduped


def _origin(url: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def _absolute_url(base_url: str, raw_url: object) -> str | None:
    value = str(raw_url or "").strip()
    if not value or value.startswith(("mailto:", "tel:", "javascript:", "data:")):
        return None
    try:
        return normalize_http_target(urljoin(base_url, value))
    except ValueError:
        return None


def _redacted_url_with_sensitive_params(url: str) -> tuple[str, list[dict[str, Any]]]:
    parsed = urlparse(url)
    leaked: list[dict[str, Any]] = []
    query = parse_qs(parsed.query, keep_blank_values=True)
    fragment = parse_qs(parsed.fragment, keep_blank_values=True)

    def redact(values: dict[str, list[str]], placement: str) -> dict[str, list[str]]:
        redacted: dict[str, list[str]] = {}
        for name, raw_values in values.items():
            if name.lower() in TOKEN_PARAMETER_NAMES:
                for raw_value in raw_values:
                    leaked.append(
                        {
                            "parameter": name,
                            "placement": placement,
                            "value_sha256": sha256(str(raw_value).encode("utf-8")).hexdigest(),
                            "value_length": len(str(raw_value)),
                        }
                    )
                redacted[name] = ["<redacted>"]
            else:
                redacted[name] = raw_values
        return redacted

    redacted_query = urlencode(redact(query, "query"), doseq=True)
    redacted_fragment = urlencode(redact(fragment, "fragment"), doseq=True)
    redacted_url = urlunparse(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            redacted_query,
            redacted_fragment,
        )
    )
    return redacted_url, leaked


def _authorization_params(url: str) -> dict[str, str]:
    parsed = urlparse(url)
    raw = parse_qs(parsed.query, keep_blank_values=True)
    return {name: values[-1] for name, values in raw.items() if values}


def _looks_like_authorization_request(url: str) -> bool:
    parsed = urlparse(url)
    params = _authorization_params(url)
    path = parsed.path.lower()
    return (
        "response_type" in params
        or "client_id" in params
        or "redirect_uri" in params
        or path.endswith("/authorize")
        or "/oauth/authorize" in path
        or "/oidc/authorize" in path
    )


def _extract_urls(base_url: str, text: str) -> list[str]:
    urls: list[str] = []
    for match in HTML_ATTR_PATTERN.finditer(text or ""):
        absolute = _absolute_url(base_url, match.group("url"))
        if absolute:
            urls.append(absolute)
    for match in URL_TOKEN_PATTERN.finditer(text or ""):
        absolute = _absolute_url(base_url, match.group("url"))
        if absolute:
            urls.append(absolute)
    return list(dict.fromkeys(urls))


def _script_urls(base_url: str, text: str) -> list[str]:
    scripts: list[str] = []
    for match in re.finditer(r"""<script[^>]+src=["'](?P<src>[^"']+)["']""", text or "", re.I):
        absolute = _absolute_url(base_url, match.group("src"))
        if absolute:
            scripts.append(absolute)
    return list(dict.fromkeys(scripts))


def _has_spa_indicators(text_blocks: list[str], urls: list[str]) -> bool:
    combined = "\n".join(text_blocks + urls).lower()
    indicators = (
        "react",
        "vue",
        "angular",
        "webpack",
        "single page",
        "spa",
        "app.js",
        "main.js",
        "bundle.js",
        "sessionstorage",
        "localstorage",
    )
    return any(indicator in combined for indicator in indicators)


def _same_host(left: str, right: str) -> bool:
    left_parsed = urlparse(left)
    right_parsed = urlparse(right)
    return left_parsed.scheme in {"http", "https"} and left_parsed.netloc == right_parsed.netloc


def _safe_get(
    client: httpx_client.Client,
    url: str,
    *,
    headers: dict[str, str] | None = None,
) -> tuple[httpx_client.Response | None, dict[str, Any]]:
    check: dict[str, Any] = {
        "url": url,
        "method": "GET",
        "follow_redirects": False,
    }
    try:
        response = client.get(url, headers=headers or {})
    except httpx_client.HTTPError as exc:
        check["status"] = "error"
        check["error"] = str(exc)[:240]
        return None, check
    check["status"] = "ok"
    check["status_code"] = response.status_code
    if response.headers.get("location"):
        check["location"] = _redacted_url_with_sensitive_params(response.headers["location"])[0][:300]
    return response, check


def _make_finding(
    *,
    title: str,
    severity: str,
    target: str,
    summary: str,
    evidence: dict[str, Any],
    tags: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "title": title,
        "severity": severity,
        "target": target,
        "summary": summary,
        "evidence": evidence,
        "methodology_tags": list(
            dict.fromkeys(
                [
                    "oauth-oidc-validation",
                    "authentication",
                    "owasp-wstg",
                    *(tags or []),
                ]
            )
        ),
        "ptes_phase": "Exploitation",
        "nist_phase": "Attack",
        "wstg_id": "WSTG-ATHN-10",
        "wstg_version": "v4.2",
        "control_family": "authentication",
    }


def _redirect_bypass_candidates(target: str) -> list[str]:
    parsed = urlparse(target)
    host = parsed.hostname or "target.local"
    origin = _origin(target)
    return [
        f"https://evil.{host}/oauth/callback",
        f"{origin}/../evil/oauth/callback",
        f"{origin}/redirect?next=https://evil.example.invalid/oauth/callback",
    ]


def _with_query(url: str, params: dict[str, str]) -> str:
    parsed = urlparse(url)
    existing = _authorization_params(url)
    merged = {**existing, **params}
    return urlunparse(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path or "/",
            parsed.params,
            urlencode(merged),
            parsed.fragment,
        )
    )


def _client_id_from_requests(auth_requests: list[str], configured_client_id: str | None) -> str:
    if configured_client_id and configured_client_id.strip():
        return configured_client_id.strip()
    for url in auth_requests:
        client_id = _authorization_params(url).get("client_id")
        if client_id:
            return client_id
    return "aegispt-probe"


def _scope_items(value: object) -> set[str]:
    if isinstance(value, list):
        return {str(item).strip() for item in value if str(item).strip()}
    return {item for item in str(value or "").replace(",", " ").split() if item}


def _token_scope_findings(
    *,
    target: str,
    token_evidence: list[dict[str, Any]] | None,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for item in token_evidence or []:
        if not isinstance(item, dict):
            continue
        requested = _scope_items(item.get("requested_scope") or item.get("requested_scopes"))
        granted = _scope_items(item.get("granted_scope") or item.get("granted_scopes"))
        if not requested or not granted:
            continue
        extra = sorted(granted - requested)
        risky_extra = [scope for scope in extra if scope.lower() in SENSITIVE_SCOPE_NAMES]
        if not extra:
            continue
        findings.append(
            _make_finding(
                title="OAuth2 Token Scope Over-Provisioning",
                severity="medium" if not risky_extra else "high",
                target=str(item.get("source_url") or item.get("target") or target),
                summary=(
                    "Token evidence grants scopes that were not present in the requested OAuth scope."
                ),
                evidence={
                    "requested_scope_count": len(requested),
                    "granted_scope_count": len(granted),
                    "extra_scopes": extra[:20],
                    "risky_extra_scopes": risky_extra[:20],
                    "raw_token_stored": False,
                    "source": item.get("source") or "configured-token-evidence",
                },
                tags=["oauth-scope-review"],
            )
        )
    return findings


def _metadata_auth_urls(metadata: dict[str, Any]) -> list[str]:
    urls: list[str] = []
    for field_name in ("authorization_endpoint", "token_endpoint", "userinfo_endpoint"):
        value = metadata.get(field_name)
        if isinstance(value, str) and value.strip():
            urls.append(value.strip())
    return urls


def execute_oauth_probe(
    targets: list[str],
    *,
    scope_allowlist: dict[str, Any] | None = None,
    authorization_urls: list[str] | None = None,
    login_paths: list[str] | None = None,
    well_known_paths: list[str] | None = None,
    script_paths: list[str] | None = None,
    token_evidence: list[dict[str, Any]] | None = None,
    client_id: str | None = None,
    timeout_seconds: float | int | None = DEFAULT_TIMEOUT_SECONDS,
    client_factory: Callable[..., httpx_client.Client] = httpx_client.Client,
) -> RunnerExecution:
    normalized_targets = _normalize_targets(targets, scope_allowlist)
    timeout = _bounded_timeout(timeout_seconds)
    findings: list[dict[str, Any]] = []
    checks: list[dict[str, Any]] = []
    discovered: list[dict[str, Any]] = []
    fetched_url_count = 0
    skipped_third_party_count = 0

    with client_factory(timeout=timeout, follow_redirects=False) as client:
        for target in normalized_targets:
            target_origin = _origin(target)
            observed_text: list[str] = []
            observed_urls: list[str] = []
            auth_requests: list[str] = []
            metadata_documents: list[dict[str, Any]] = []

            target_response, target_check = _safe_get(
                client,
                target,
                headers={"User-Agent": "AegisPT/oauth-probe discovery"},
            )
            checks.append({**target_check, "source": "target"})
            if target_response is not None:
                fetched_url_count += 1
                body = target_response.text[:250_000]
                observed_text.append(body)
                if target_response.headers.get("location"):
                    observed_urls.append(urljoin(target, target_response.headers["location"]))
                observed_urls.extend(_extract_urls(target, body))

            for raw_path in (*DEFAULT_WELL_KNOWN_PATHS, *(well_known_paths or [])):
                well_known_url = _absolute_url(target_origin + "/", raw_path)
                if not well_known_url:
                    continue
                if not _allowed(scope_allowlist, well_known_url):
                    checks.append(
                        {
                            "url": well_known_url,
                            "source": "oidc-metadata",
                            "status": "skipped",
                            "skip_reason": "well-known endpoint outside approved scope",
                        }
                    )
                    continue
                response, check = _safe_get(
                    client,
                    well_known_url,
                    headers={"User-Agent": "AegisPT/oauth-probe metadata-discovery"},
                )
                checks.append({**check, "source": "oidc-metadata"})
                if response is None:
                    continue
                fetched_url_count += 1
                if "application/json" not in response.headers.get("content-type", "") and not response.text.strip().startswith("{"):
                    continue
                try:
                    metadata = response.json()
                except json.JSONDecodeError:
                    continue
                if isinstance(metadata, dict):
                    metadata_documents.append(metadata)
                    for metadata_url in _metadata_auth_urls(metadata):
                        absolute = _absolute_url(well_known_url, metadata_url)
                        if absolute:
                            observed_urls.append(absolute)
                    response_types = [
                        str(item)
                        for item in metadata.get("response_types_supported", [])
                        if isinstance(item, str)
                    ]
                    if any("token" in item.split() or "id_token" in item.split() for item in response_types):
                        findings.append(
                            _make_finding(
                                title="OAuth2 Implicit Flow Still Supported",
                                severity="medium",
                                target=well_known_url,
                                summary=(
                                    "OIDC metadata advertises token or id_token response types, indicating implicit-flow support."
                                ),
                                evidence={
                                    "source": "openid-configuration",
                                    "response_types_supported": response_types,
                                },
                                tags=["oauth-implicit-flow"],
                            )
                        )

            for raw_path in (*DEFAULT_LOGIN_PATHS, *(login_paths or [])):
                candidate = _absolute_url(target_origin + "/", raw_path)
                if not candidate or not _allowed(scope_allowlist, candidate):
                    continue
                response, check = _safe_get(
                    client,
                    candidate,
                    headers={"User-Agent": "AegisPT/oauth-probe endpoint-discovery"},
                )
                checks.append({**check, "source": "login-or-authorize-path"})
                if response is None:
                    continue
                fetched_url_count += 1
                observed_text.append(response.text[:120_000])
                if response.headers.get("location"):
                    observed_urls.append(urljoin(candidate, response.headers["location"]))
                observed_urls.extend(_extract_urls(candidate, response.text[:120_000]))

            configured_script_urls = [
                url for item in script_paths or [] if (url := _absolute_url(target, item))
            ]
            script_candidates = list(
                dict.fromkeys(
                    [
                        *_script_urls(target, "\n".join(observed_text)),
                        *configured_script_urls,
                    ]
                )
            )[:MAX_FETCHED_SCRIPT_COUNT]
            for script_url in script_candidates:
                if not _allowed(scope_allowlist, script_url):
                    checks.append(
                        {
                            "url": script_url,
                            "source": "script-discovery",
                            "status": "skipped",
                            "skip_reason": "script outside approved scope",
                        }
                    )
                    continue
                response, check = _safe_get(
                    client,
                    script_url,
                    headers={"User-Agent": "AegisPT/oauth-probe script-discovery"},
                )
                checks.append({**check, "source": "script-discovery"})
                if response is None:
                    continue
                fetched_url_count += 1
                script_body = response.text[:250_000]
                observed_text.append(script_body)
                observed_urls.extend(_extract_urls(script_url, script_body))

            for configured_url in authorization_urls or []:
                absolute = _absolute_url(target, configured_url)
                if absolute:
                    observed_urls.append(absolute)

            observed_urls = list(dict.fromkeys(observed_urls))
            for observed_url in observed_urls:
                redacted_url, leaks = _redacted_url_with_sensitive_params(observed_url)
                if leaks:
                    findings.append(
                        _make_finding(
                            title="OAuth2/OIDC Token Leaked in URL",
                            severity="high",
                            target=target,
                            summary=(
                                "OAuth token material was observed in a URL query string or fragment; raw token values were hashed and redacted."
                            ),
                            evidence={
                                "source_url": redacted_url,
                                "leaked_parameters": leaks,
                                "raw_token_stored": False,
                            },
                            tags=["oauth-token-leakage"],
                        )
                    )
                if _looks_like_authorization_request(observed_url):
                    auth_requests.append(observed_url)
                    discovered.append(
                        {
                            "type": "authorization_request",
                            "url": redacted_url,
                            "in_scope": _allowed(scope_allowlist, observed_url),
                        }
                    )

            auth_requests = list(dict.fromkeys(auth_requests))
            spa_indicators = _has_spa_indicators(observed_text, observed_urls)
            for auth_url in auth_requests:
                params = _authorization_params(auth_url)
                response_type = params.get("response_type", "")
                if response_type and "state" not in params:
                    findings.append(
                        _make_finding(
                            title="OAuth2 State Parameter Missing",
                            severity="medium",
                            target=auth_url,
                            summary=(
                                "An OAuth authorization request was discovered without a state parameter, leaving the flow exposed to OAuth CSRF."
                            ),
                            evidence={
                                "response_type": response_type,
                                "client_id_present": bool(params.get("client_id")),
                                "redirect_uri_present": bool(params.get("redirect_uri")),
                            },
                            tags=["oauth-csrf"],
                        )
                    )
                if "token" in response_type.split() or "id_token" in response_type.split():
                    findings.append(
                        _make_finding(
                            title="OAuth2 Implicit Flow Still Supported",
                            severity="medium",
                            target=auth_url,
                            summary="An OAuth authorization request uses token or id_token response_type.",
                            evidence={"response_type": response_type},
                            tags=["oauth-implicit-flow"],
                        )
                    )
                if "code" in response_type.split() and "code_challenge" not in params and spa_indicators:
                    findings.append(
                        _make_finding(
                            title="OAuth2 Authorization Code Flow Without PKCE",
                            severity="high",
                            target=auth_url,
                            summary=(
                                "A browser/SPAs-style authorization-code flow was discovered without a PKCE code_challenge."
                            ),
                            evidence={
                                "response_type": response_type,
                                "spa_indicators_present": True,
                                "code_challenge_present": False,
                            },
                            tags=["oauth-pkce"],
                        )
                    )

            active_authorize_urls = [
                url for url in auth_requests if _allowed(scope_allowlist, url) and _same_host(url, target)
            ]
            for metadata in metadata_documents:
                metadata_auth_url = _absolute_url(target, metadata.get("authorization_endpoint"))
                if metadata_auth_url:
                    if _allowed(scope_allowlist, metadata_auth_url) and _same_host(metadata_auth_url, target):
                        active_authorize_urls.append(metadata_auth_url)
                    else:
                        skipped_third_party_count += 1
                        checks.append(
                            {
                                "url": metadata_auth_url,
                                "source": "authorization-endpoint",
                                "status": "skipped",
                                "skip_reason": "authorization endpoint outside approved scope or third-party IdP",
                            }
                        )

            active_authorize_urls = list(dict.fromkeys(active_authorize_urls))
            effective_client_id = _client_id_from_requests(auth_requests, client_id)
            for authorize_url in active_authorize_urls:
                for redirect_uri in _redirect_bypass_candidates(target):
                    probe_url = _with_query(
                        authorize_url,
                        {
                            "response_type": "code",
                            "client_id": effective_client_id,
                            "redirect_uri": redirect_uri,
                            "state": "aegispt-state",
                        },
                    )
                    response, check = _safe_get(
                        client,
                        probe_url,
                        headers={"User-Agent": "AegisPT/oauth-probe redirect-validation"},
                    )
                    checks.append(
                        {
                            **check,
                            "source": "redirect-uri-validation",
                            "redirect_uri_variant": redirect_uri,
                        }
                    )
                    if response is None:
                        continue
                    fetched_url_count += 1
                    location = response.headers.get("location", "")
                    redacted_location, leaks = _redacted_url_with_sensitive_params(
                        urljoin(authorize_url, location)
                    )
                    if leaks:
                        findings.append(
                            _make_finding(
                                title="OAuth2/OIDC Token Leaked in URL",
                                severity="high",
                                target=authorize_url,
                                summary=(
                                    "OAuth token material appeared in an authorization redirect Location header; raw token values were hashed and redacted."
                                ),
                                evidence={
                                    "redirect_location": redacted_location,
                                    "leaked_parameters": leaks,
                                    "raw_token_stored": False,
                                },
                                tags=["oauth-token-leakage"],
                            )
                        )
                    if response.status_code in {301, 302, 303, 307, 308} and location:
                        if redirect_uri in location or redirect_uri in urljoin(authorize_url, location):
                            findings.append(
                                _make_finding(
                                    title="OAuth2 Redirect URI Bypass - Account Takeover Possible",
                                    severity="critical",
                                    target=authorize_url,
                                    summary=(
                                        "The authorization endpoint accepted a malicious redirect_uri variant and reflected it into a redirect response."
                                    ),
                                    evidence={
                                        "redirect_uri_variant": redirect_uri,
                                        "status_code": response.status_code,
                                        "location": redacted_location,
                                        "follow_redirects": False,
                                    },
                                    tags=["oauth-redirect-uri"],
                                )
                            )

                implicit_url = _with_query(
                    authorize_url,
                    {
                        "response_type": "token",
                        "client_id": effective_client_id,
                        "redirect_uri": target,
                        "state": "aegispt-state",
                    },
                )
                response, check = _safe_get(
                    client,
                    implicit_url,
                    headers={"User-Agent": "AegisPT/oauth-probe implicit-flow-validation"},
                )
                checks.append({**check, "source": "implicit-flow-validation"})
                if response is None:
                    continue
                fetched_url_count += 1
                location = response.headers.get("location", "")
                redacted_location, leaks = _redacted_url_with_sensitive_params(
                    urljoin(authorize_url, location)
                )
                if leaks:
                    findings.append(
                        _make_finding(
                            title="OAuth2/OIDC Token Leaked in URL",
                            severity="high",
                            target=authorize_url,
                            summary=(
                                "Implicit-flow validation observed token material in the redirect URL; raw token values were hashed and redacted."
                            ),
                            evidence={
                                "redirect_location": redacted_location,
                                "leaked_parameters": leaks,
                                "raw_token_stored": False,
                            },
                            tags=["oauth-token-leakage"],
                        )
                    )
                    findings.append(
                        _make_finding(
                            title="OAuth2 Implicit Flow Still Supported",
                            severity="medium",
                            target=authorize_url,
                            summary="The authorization endpoint returned a token-bearing implicit-flow redirect.",
                            evidence={
                                "response_type": "token",
                                "status_code": response.status_code,
                                "location": redacted_location,
                            },
                            tags=["oauth-implicit-flow"],
                        )
                    )

            findings.extend(_token_scope_findings(target=target, token_evidence=token_evidence))

    findings = _dedupe_dicts(findings, key_fields=("title", "target", "summary"))
    payload = {
        "tool": "oauth-probe",
        "summary": {
            "target_count": len(normalized_targets),
            "fetched_url_count": fetched_url_count,
            "discovered_authorization_request_count": len(discovered),
            "finding_count": len(findings),
            "skipped_third_party_idp_count": skipped_third_party_count,
        },
        "targets": normalized_targets,
        "discovered": discovered,
        "checks": checks,
        "findings": findings,
        "safety": {
            "approval_gated": True,
            "follow_redirects": False,
            "third_party_idp_requests_attempted": False,
            "direct_third_party_idp_interaction": False,
            "token_exchange_performed": False,
            "browser_automation_performed": False,
            "runtime_self_modification": False,
            "raw_tokens_stored": False,
            "max_timeout_seconds": DEFAULT_TIMEOUT_SECONDS,
        },
    }
    return RunnerExecution(
        tool="oauth-probe",
        exit_code=0,
        stdout=json.dumps(
            {
                "target_count": len(normalized_targets),
                "finding_count": len(findings),
                "skipped_third_party_idp_count": skipped_third_party_count,
            },
            sort_keys=True,
        ),
        stderr="",
        metadata={
            "target_count": len(normalized_targets),
            "finding_count": len(findings),
            "safety": payload["safety"],
        },
        artifacts=[_json_artifact(OAUTH_PROBE_RESULTS_ARTIFACT_NAME, payload)],
    )
