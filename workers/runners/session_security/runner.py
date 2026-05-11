from __future__ import annotations

import json
import math
from hashlib import sha256
from http.cookies import SimpleCookie
from typing import Any, Callable
from urllib.parse import parse_qsl, urljoin, urlparse

import httpx as httpx_client

from api.app.services.runs import web_target_value_is_allowed_with_path
from workers.runners.base.contracts import EvidenceArtifact, RunnerExecution
from workers.runners.httpx.runner import normalize_http_target

SESSION_SECURITY_RESULTS_ARTIFACT_NAME = "session-security-results.json"
DEFAULT_SESSION_TOKEN_PARAMETERS = (
    "sid",
    "session",
    "sessionid",
    "jsessionid",
    "phpsessid",
    "aspsessionid",
    "auth_token",
    "token",
)
SESSION_COOKIE_NAME_MARKERS = ("session", "sid", "jsessionid", "phpsessid", "aspsessionid")
AUTH_ACCEPTED_STATUS_CODES = {200, 201, 202, 204}


def _json_artifact(name: str, payload: dict[str, Any], *, kind: str = "runner-results") -> EvidenceArtifact:
    return EvidenceArtifact(
        name=name,
        content_type="application/json",
        data=(json.dumps(payload, sort_keys=True) + "\n").encode("utf-8"),
        kind=kind,
    )


def _response_hash(response: httpx_client.Response) -> str:
    return sha256(response.content).hexdigest()


def _body_excerpt(response: httpx_client.Response) -> str:
    return (response.text or "")[:800].replace("\n", " ").strip()


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


def _render_url(base_target: str, value: object | None) -> str:
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


def _normalize_auth_contexts(auth_contexts: object) -> list[dict[str, Any]]:
    if not isinstance(auth_contexts, list):
        raise ValueError("session-security requires at least one configured credential context")

    normalized: list[dict[str, Any]] = []
    for index, raw_context in enumerate(auth_contexts):
        if not isinstance(raw_context, dict):
            continue
        headers = raw_context.get("headers")
        normalized_headers = {
            str(key).strip(): str(value).strip()
            for key, value in (headers.items() if isinstance(headers, dict) else [])
            if str(key).strip() and str(value).strip()
        }
        username = str(raw_context.get("username") or "").strip()
        password = str(raw_context.get("password") or "").strip()
        if not username or not password:
            continue
        normalized.append(
            {
                "label": str(raw_context.get("label") or username or f"Account {index + 1}").strip()
                or f"Account {index + 1}",
                "username": username,
                "password": password,
                "role": str(raw_context.get("role") or "User").strip() or "User",
                "headers": normalized_headers,
            }
        )

    if not normalized:
        raise ValueError("session-security requires a configured username/password credential context")
    return normalized


def _cookie_headers(response: httpx_client.Response) -> list[str]:
    try:
        return list(response.headers.get_list("set-cookie"))
    except AttributeError:
        raw_value = response.headers.get("set-cookie")
        return [raw_value] if raw_value else []


def _parse_set_cookie(header: str) -> list[dict[str, Any]]:
    cookie = SimpleCookie()
    try:
        cookie.load(header)
    except Exception:
        return []

    parsed: list[dict[str, Any]] = []
    for name, morsel in cookie.items():
        parsed.append(
            {
                "name": name,
                "value": morsel.value,
                "secure": bool(morsel["secure"]),
                "httponly": bool(morsel["httponly"]),
                "samesite": str(morsel["samesite"] or "").strip(),
                "path": str(morsel["path"] or "").strip() or None,
                "domain": str(morsel["domain"] or "").strip() or None,
            }
        )
    return parsed


def _set_cookie_records(response: httpx_client.Response, *, url: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for header in _cookie_headers(response):
        for parsed in _parse_set_cookie(header):
            records.append({**parsed, "url": url, "http_scheme": urlparse(url).scheme})
    return records


def _session_like_cookie(records: list[dict[str, Any]]) -> dict[str, Any] | None:
    for record in records:
        name = str(record.get("name") or "").lower()
        if any(marker in name for marker in SESSION_COOKIE_NAME_MARKERS):
            return record
    return records[0] if records else None


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
    wstg_id: str,
) -> None:
    key = (finding_type, target)
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
            "methodology_tags": [
                "session_security",
                "session-management",
                "authentication",
                "session-security",
            ],
            "wstg_id": wstg_id,
            "control_family": "session_management",
            "evidence": evidence,
            "replay_recipe": {
                "tool": "session-security",
                "target": target,
                "scope": "approved-web-root-only",
                "credential_source": "configured-credential-context",
            },
        }
    )


def _cookie_flag_findings(
    *,
    findings: list[dict[str, Any]],
    seen: set[tuple[str, str]],
    checks: list[dict[str, Any]],
    response: httpx_client.Response,
    url: str,
) -> None:
    records = _set_cookie_records(response, url=url)
    for record in records:
        check = {
            "check_type": "cookie_flags",
            "target": url,
            "cookie_name": record["name"],
            "secure": record["secure"],
            "httponly": record["httponly"],
            "samesite": record["samesite"],
            "http_scheme": record["http_scheme"],
            "response_hash": _response_hash(response),
        }
        checks.append(check)
        if not record["secure"]:
            _append_finding(
                findings,
                seen,
                finding_type=f"missing_secure_cookie_flag:{record['name']}",
                title="Session Cookie Missing Secure Flag",
                severity="medium",
                target=url,
                summary=f"Cookie {record['name']} was issued without the Secure flag.",
                evidence=check,
                wstg_id="WSTG-SESS-02",
            )
        if not record["httponly"]:
            _append_finding(
                findings,
                seen,
                finding_type=f"missing_httponly_cookie_flag:{record['name']}",
                title="Session Cookie Missing HttpOnly Flag",
                severity="medium",
                target=url,
                summary=f"Cookie {record['name']} was issued without the HttpOnly flag.",
                evidence=check,
                wstg_id="WSTG-SESS-02",
            )
        if str(record["samesite"]).lower() not in {"lax", "strict"}:
            _append_finding(
                findings,
                seen,
                finding_type=f"missing_samesite_cookie_flag:{record['name']}",
                title="Session Cookie Missing SameSite Lax/Strict",
                severity="medium",
                target=url,
                summary=f"Cookie {record['name']} was issued without SameSite=Lax or SameSite=Strict.",
                evidence=check,
                wstg_id="WSTG-SESS-02",
            )
        if record["http_scheme"] == "http":
            _append_finding(
                findings,
                seen,
                finding_type=f"session_cookie_exposed_over_http:{record['name']}",
                title="Session Cookie Exposed Over HTTP",
                severity="medium",
                target=url,
                summary=f"Cookie {record['name']} was observed on an HTTP URL, exposing it to cleartext transport risk.",
                evidence=check,
                wstg_id="WSTG-SESS-02",
            )


def _looks_sequential(values: list[str]) -> bool:
    numeric_values: list[int] = []
    for value in values:
        if not value.isdigit():
            return False
        numeric_values.append(int(value))
    if len(numeric_values) < 3:
        return False
    deltas = [right - left for left, right in zip(numeric_values, numeric_values[1:], strict=False)]
    return bool(deltas) and len(set(deltas)) == 1 and abs(deltas[0]) <= 10


def _entropy_bits(value: str) -> float:
    unique = len(set(value))
    if not value or unique <= 1:
        return 0.0
    return len(value) * math.log2(unique)


def _entropy_reason(values: list[str]) -> tuple[bool, dict[str, Any]]:
    if not values:
        return False, {"reason": "no_session_tokens_observed"}
    min_bits = min(_entropy_bits(value) for value in values)
    min_length = min(len(value) for value in values)
    unique_count = len(set(values))
    sequential = _looks_sequential(values)
    repeated = unique_count < len(values)
    weak = min_bits < 128 or min_length < 16 or sequential or repeated
    return weak, {
        "sample_count": len(values),
        "unique_count": unique_count,
        "minimum_estimated_bits": round(min_bits, 2),
        "minimum_length": min_length,
        "sequential_pattern": sequential,
        "repeated_tokens": repeated,
        "token_hashes": [sha256(value.encode("utf-8")).hexdigest() for value in values],
    }


def _login_form_payload(
    auth_context: dict[str, Any],
    *,
    username_field: str,
    password_field: str,
    extra_form_fields: dict[str, Any] | None,
) -> dict[str, str]:
    payload = {
        username_field: str(auth_context["username"]),
        password_field: str(auth_context["password"]),
    }
    if isinstance(extra_form_fields, dict):
        for key, value in extra_form_fields.items():
            normalized_key = str(key).strip()
            if normalized_key:
                payload[normalized_key] = str(value)
    return payload


def _protected_session_accepted(
    response: httpx_client.Response,
    *,
    success_markers: list[str],
    login_markers: list[str],
) -> bool:
    if response.status_code in {401, 403}:
        return False
    if response.status_code in {301, 302, 303, 307, 308}:
        location = str(response.headers.get("location") or "").lower()
        if "login" in location or "signin" in location:
            return False
    body = (response.text or "").lower()
    if success_markers and any(marker.lower() in body for marker in success_markers):
        return True
    if login_markers and any(marker.lower() in body for marker in login_markers):
        return False
    return response.status_code in AUTH_ACCEPTED_STATUS_CODES


def _token_url_findings(
    *,
    targets: list[str],
    request_contexts: object,
    token_parameter_names: list[str],
    findings: list[dict[str, Any]],
    seen: set[tuple[str, str]],
    checks: list[dict[str, Any]],
    scope_allowlist: dict[str, Any] | None,
) -> None:
    candidates = list(targets)
    if isinstance(request_contexts, list):
        for item in request_contexts:
            if isinstance(item, str):
                candidates.append(item)
            elif isinstance(item, dict):
                value = item.get("url") or item.get("target") or item.get("endpoint")
                if value:
                    candidates.append(str(value))

    lowered_names = {name.lower() for name in token_parameter_names}
    for candidate in candidates:
        url = normalize_http_target(candidate) if "://" in candidate else candidate
        if "://" in url and not _allowed(scope_allowlist, url):
            continue
        parsed = urlparse(url)
        leaked = [
            name
            for name, value in parse_qsl(parsed.query, keep_blank_values=True)
            if name.lower() in lowered_names and value
        ]
        if not leaked:
            continue
        check = {
            "check_type": "session_token_in_url",
            "target": url,
            "parameter_names": sorted(set(leaked)),
        }
        checks.append(check)
        _append_finding(
            findings,
            seen,
            finding_type=f"session_token_in_url:{url}",
            title="Session Token in URL",
            severity="high",
            target=url,
            summary="A session-like token parameter was observed in a URL, exposing it through logs, browser history, and referrer headers.",
            evidence=check,
            wstg_id="WSTG-SESS-03",
        )


def execute_session_security_analysis(
    targets: list[str],
    *,
    auth_contexts: list[dict[str, Any]] | object,
    scope_allowlist: dict[str, Any] | None = None,
    request_contexts: list[dict[str, Any]] | object = None,
    candidate_paths: list[str] | object = None,
    login_url: str | None = None,
    logout_url: str | None = None,
    protected_url: str | None = None,
    pre_login_url: str | None = None,
    token_sample_url: str | None = None,
    username_field: str = "username",
    password_field: str = "password",
    extra_form_fields: dict[str, Any] | None = None,
    success_markers: list[str] | object = None,
    login_markers: list[str] | object = None,
    token_parameter_names: list[str] | object = None,
    sample_count: int = 10,
    timeout_seconds: float = 10.0,
    client_factory: Callable[..., Any] = httpx_client.Client,
) -> RunnerExecution:
    if not targets:
        raise ValueError("at least one target is required")
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be greater than zero")

    normalized_targets = [normalize_http_target(target) for target in targets]
    for target in normalized_targets:
        _assert_allowed(scope_allowlist, target)

    safe_auth_contexts = _normalize_auth_contexts(auth_contexts)
    auth_context = safe_auth_contexts[0]
    target = normalized_targets[0]
    rendered_login_url = _render_url(target, login_url or "login")
    rendered_logout_url = _render_url(target, logout_url or "logout")
    rendered_protected_url = _render_url(target, protected_url or "")
    rendered_pre_login_url = _render_url(target, pre_login_url or "")
    rendered_token_sample_url = _render_url(target, token_sample_url or login_url or "")

    for url in (
        rendered_login_url,
        rendered_logout_url,
        rendered_protected_url,
        rendered_pre_login_url,
        rendered_token_sample_url,
    ):
        _assert_allowed(scope_allowlist, url)
    for raw_path in _normalize_string_list(candidate_paths, limit=50):
        _assert_allowed(scope_allowlist, _render_url(target, raw_path))

    success_marker_values = _normalize_string_list(success_markers, limit=10)
    login_marker_values = _normalize_string_list(login_markers, limit=10) or [
        "login",
        "sign in",
        "username",
        "password",
    ]
    parameter_names = _normalize_string_list(token_parameter_names, limit=20) or list(
        DEFAULT_SESSION_TOKEN_PARAMETERS
    )
    bounded_sample_count = min(max(int(sample_count or 10), 2), 10)

    checks: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    seen_findings: set[tuple[str, str]] = set()
    stderr_lines: list[str] = []
    exit_code = 0

    _token_url_findings(
        targets=normalized_targets,
        request_contexts=request_contexts,
        token_parameter_names=parameter_names,
        findings=findings,
        seen=seen_findings,
        checks=checks,
        scope_allowlist=scope_allowlist,
    )

    sample_tokens: list[str] = []
    with client_factory(follow_redirects=False, timeout=timeout_seconds) as client:
        try:
            pre_response = client.get(
                rendered_pre_login_url,
                headers={
                    "User-Agent": "AegisPT/session-security pre-login",
                    **dict(auth_context.get("headers") or {}),
                },
            )
            _cookie_flag_findings(
                findings=findings,
                seen=seen_findings,
                checks=checks,
                response=pre_response,
                url=rendered_pre_login_url,
            )
            pre_cookie = _session_like_cookie(
                _set_cookie_records(pre_response, url=rendered_pre_login_url)
            )
        except httpx_client.HTTPError as exc:
            exit_code = 1
            stderr_lines.append(f"pre-login session check failed for {rendered_pre_login_url}: {exc}")
            pre_cookie = None

        try:
            login_payload = _login_form_payload(
                auth_context,
                username_field=username_field,
                password_field=password_field,
                extra_form_fields=extra_form_fields,
            )
            login_response = client.post(
                rendered_login_url,
                data=login_payload,
                headers={
                    "User-Agent": "AegisPT/session-security configured-login",
                    **dict(auth_context.get("headers") or {}),
                },
            )
            _cookie_flag_findings(
                findings=findings,
                seen=seen_findings,
                checks=checks,
                response=login_response,
                url=rendered_login_url,
            )
            post_cookie = _session_like_cookie(_set_cookie_records(login_response, url=rendered_login_url))
            protected_response = client.get(
                rendered_protected_url,
                headers={"User-Agent": "AegisPT/session-security protected-resource"},
            )
            protected_accepted = _protected_session_accepted(
                protected_response,
                success_markers=success_marker_values,
                login_markers=login_marker_values,
            )
            checks.append(
                {
                    "check_type": "session_fixation",
                    "target": rendered_login_url,
                    "pre_login_cookie_name": pre_cookie.get("name") if pre_cookie else None,
                    "post_login_cookie_name": post_cookie.get("name") if post_cookie else None,
                    "protected_status_code": protected_response.status_code,
                    "protected_accepted": protected_accepted,
                    "pre_login_cookie_hash": (
                        sha256(str(pre_cookie.get("value")).encode("utf-8")).hexdigest()
                        if pre_cookie
                        else None
                    ),
                    "post_login_cookie_hash": (
                        sha256(str(post_cookie.get("value")).encode("utf-8")).hexdigest()
                        if post_cookie
                        else None
                    ),
                }
            )
            if (
                pre_cookie
                and post_cookie
                and pre_cookie.get("name") == post_cookie.get("name")
                and pre_cookie.get("value") == post_cookie.get("value")
                and protected_accepted
            ):
                _append_finding(
                    findings,
                    seen_findings,
                    finding_type="session_fixation",
                    title="Session Fixation - Token Not Rotated After Login",
                    severity="high",
                    target=rendered_login_url,
                    summary="The same session token observed before login remained in use after authenticated login and protected resource access.",
                    evidence=checks[-1],
                    wstg_id="WSTG-SESS-03",
                )

            captured_cookie = post_cookie
            if captured_cookie:
                logout_response = client.get(
                    rendered_logout_url,
                    headers={"User-Agent": "AegisPT/session-security logout"},
                )
                replay_client = client_factory(follow_redirects=False, timeout=timeout_seconds)
                with replay_client as fresh_client:
                    fresh_client.cookies.set(
                        str(captured_cookie["name"]),
                        str(captured_cookie["value"]),
                        domain=urlparse(rendered_protected_url).hostname,
                    )
                    replay_response = fresh_client.get(
                        rendered_protected_url,
                        headers={"User-Agent": "AegisPT/session-security post-logout-replay"},
                    )
                replay_accepted = _protected_session_accepted(
                    replay_response,
                    success_markers=success_marker_values,
                    login_markers=login_marker_values,
                )
                replay_check = {
                    "check_type": "post_logout_replay",
                    "target": rendered_protected_url,
                    "logout_status_code": logout_response.status_code,
                    "replay_status_code": replay_response.status_code,
                    "replay_accepted": replay_accepted,
                    "cookie_name": captured_cookie["name"],
                    "cookie_hash": sha256(str(captured_cookie["value"]).encode("utf-8")).hexdigest(),
                    "response_hash": _response_hash(replay_response),
                }
                checks.append(replay_check)
                if replay_accepted:
                    _append_finding(
                        findings,
                        seen_findings,
                        finding_type="session_not_invalidated_on_logout",
                        title="Session Not Invalidated on Logout - Allows Session Replay Attacks",
                        severity="high",
                        target=rendered_protected_url,
                        summary="A captured session cookie remained accepted by the protected resource after the logout flow completed.",
                        evidence={**replay_check, "response_excerpt": _body_excerpt(replay_response)},
                        wstg_id="WSTG-SESS-06",
                    )
        except httpx_client.HTTPError as exc:
            exit_code = 1
            stderr_lines.append(f"authenticated session lifecycle check failed for {target}: {exc}")

    for _ in range(bounded_sample_count):
        with client_factory(follow_redirects=False, timeout=timeout_seconds) as sample_client:
            try:
                response = sample_client.get(
                    rendered_token_sample_url,
                    headers={"User-Agent": "AegisPT/session-security entropy-sample"},
                )
            except httpx_client.HTTPError as exc:
                exit_code = 1
                stderr_lines.append(
                    f"session entropy sampling failed for {rendered_token_sample_url}: {exc}"
                )
                continue
            _cookie_flag_findings(
                findings=findings,
                seen=seen_findings,
                checks=checks,
                response=response,
                url=rendered_token_sample_url,
            )
            sample_cookie = _session_like_cookie(_set_cookie_records(response, url=rendered_token_sample_url))
            if sample_cookie:
                sample_tokens.append(str(sample_cookie.get("value") or ""))

    weak_entropy, entropy_details = _entropy_reason(sample_tokens)
    entropy_check = {
        "check_type": "session_token_entropy",
        "target": rendered_token_sample_url,
        **entropy_details,
    }
    checks.append(entropy_check)
    if weak_entropy and sample_tokens:
        _append_finding(
            findings,
            seen_findings,
            finding_type="low_entropy_session_token",
            title="Session Token Entropy Weakness",
            severity="high",
            target=rendered_token_sample_url,
            summary="Consecutive issued session tokens appear predictable, too short, repeated, or below the 128-bit entropy target.",
            evidence=entropy_check,
            wstg_id="WSTG-SESS-01",
        )

    payload = {
        "tool": "session-security",
        "targets": normalized_targets,
        "checks": checks,
        "findings": findings,
        "summary": {
            "target_count": len(normalized_targets),
            "auth_context_count": len(safe_auth_contexts),
            "check_count": len(checks),
            "finding_count": len(findings),
            "cookie_flag_findings": sum(1 for finding in findings if "cookie" in str(finding.get("type", ""))),
            "session_fixation_findings": sum(1 for finding in findings if finding.get("type") == "session_fixation"),
            "logout_replay_findings": sum(
                1 for finding in findings if finding.get("type") == "session_not_invalidated_on_logout"
            ),
            "entropy_findings": sum(1 for finding in findings if finding.get("type") == "low_entropy_session_token"),
            "token_url_findings": sum(1 for finding in findings if str(finding.get("type", "")).startswith("session_token_in_url")),
        },
        "safety": {
            "scope_enforced": True,
            "approved_web_root_only": True,
            "requires_active_approval": True,
            "configured_credentials_only": True,
            "other_user_session_hijacking": False,
            "credential_values_stored_in_artifacts": False,
            "sample_count_limit": 10,
        },
    }
    return RunnerExecution(
        tool="session-security",
        exit_code=exit_code,
        stdout=json.dumps(payload["summary"], sort_keys=True),
        stderr="\n".join(line for line in stderr_lines if line),
        metadata={
            "status": "ok" if exit_code == 0 else "completed_with_errors",
            "runner_digest": "workers.session_security.runner:v1",
            "tool_version": "custom-python-bounded",
            "finding_count": len(findings),
            "check_count": len(checks),
        },
        artifacts=[_json_artifact(SESSION_SECURITY_RESULTS_ARTIFACT_NAME, payload)],
    )
