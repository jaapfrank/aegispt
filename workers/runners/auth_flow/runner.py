from __future__ import annotations

import json
import math
import re
import secrets
import time
from hashlib import sha256
from typing import Any, Callable
from urllib.parse import parse_qsl, urljoin, urlparse

import httpx as httpx_client

from api.app.services.runs import web_target_value_is_allowed_with_path
from workers.runners.base.contracts import EvidenceArtifact, RunnerExecution
from workers.runners.httpx.runner import normalize_http_target

AUTH_FLOW_RESULTS_ARTIFACT_NAME = "auth-flow-results.json"
DEFAULT_INVALID_USERNAMES = ("aegispt-invalid-user@example.invalid",)
DEFAULT_LOCKOUT_MARKERS = (
    "locked",
    "lockout",
    "too many",
    "rate limit",
    "try again later",
    "captcha",
)
RESET_TOKEN_PATTERN = re.compile(
    r"(?:reset[_-]?token|token|code)=([A-Za-z0-9._~+/=-]{4,256})", re.IGNORECASE
)
URL_PATTERN = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)


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
        normalized.append(candidate)
        seen.add(candidate)
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


def _try_auto_register(
    client: httpx_client.Client,
    *,
    registration_url: str,
    scope_allowlist: dict[str, Any] | None,
    reg_username_field: str = "username",
    reg_password_field: str = "password",
    extra_reg_fields: dict[str, Any] | None = None,
) -> tuple[str, str] | None:
    """Attempt to register a disposable test account.

    Returns (username, password) on success, None on failure.
    The username/password are random AegisPT test credentials — never real.
    """
    if not _allowed(scope_allowlist, registration_url):
        return None
    test_user = f"aegispt-test-{secrets.token_hex(6)}"
    test_pass = f"AegisPT_T{secrets.token_hex(8)}!9"
    try:
        payload = {
            reg_username_field: test_user,
            reg_password_field: test_pass,
            **(extra_reg_fields or {}),
        }
        response = client.post(registration_url, data=payload, follow_redirects=True, timeout=12.0)
        # Gruyere and similar apps return 200/302 on success, no "error" in body
        error_markers = ("error", "invalid", "already taken", "already exists", "failed", "captcha")
        body_lower = response.text.lower()
        if response.status_code in (200, 201, 301, 302, 303) and not any(m in body_lower for m in error_markers):
            return test_user, test_pass
    except Exception:  # noqa: BLE001
        pass
    return None


def _normalize_auth_contexts(auth_contexts: object) -> list[dict[str, Any]]:
    if not isinstance(auth_contexts, list):
        raise ValueError("auth-flow requires at least one configured credential context")

    normalized: list[dict[str, Any]] = []
    for index, raw_context in enumerate(auth_contexts):
        if not isinstance(raw_context, dict):
            continue
        username = str(raw_context.get("username") or "").strip()
        password = str(raw_context.get("password") or "").strip()
        if not username or not password:
            continue
        headers = raw_context.get("headers")
        normalized_headers = {
            str(key).strip(): str(value).strip()
            for key, value in (headers.items() if isinstance(headers, dict) else [])
            if str(key).strip() and str(value).strip()
        }
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
        raise ValueError("auth-flow requires a configured username/password credential context")
    return normalized


def _response_hash(response: httpx_client.Response) -> str:
    return sha256(response.content).hexdigest()


def _body_signature(response: httpx_client.Response) -> dict[str, Any]:
    body = response.text or ""
    normalized = re.sub(r"\s+", " ", body).strip().lower()
    return {
        "status_code": response.status_code,
        "body_hash": sha256(normalized.encode("utf-8")).hexdigest(),
        "body_length": len(body),
    }


def _token_hash(value: str) -> str:
    return sha256(value.encode("utf-8")).hexdigest()


def _entropy_bits(value: str) -> float:
    unique = len(set(value))
    if not value or unique <= 1:
        return 0.0
    return len(value) * math.log2(unique)


def _looks_sequential(values: list[str]) -> bool:
    numeric_values: list[int] = []
    for value in values:
        if not value.isdigit():
            return False
        numeric_values.append(int(value))
    if len(numeric_values) < 3:
        return False
    deltas = [right - left for left, right in zip(numeric_values, numeric_values[1:], strict=False)]
    return bool(deltas) and len(set(deltas)) == 1 and abs(deltas[0]) <= 1000


def _looks_timestamp_based(values: list[str]) -> bool:
    if len(values) < 3:
        return False
    numeric_values = [int(value) for value in values if value.isdigit()]
    if len(numeric_values) != len(values):
        return False
    return any(946684800 <= value <= 4102444800 for value in numeric_values)


def _extract_reset_tokens(response: httpx_client.Response) -> list[str]:
    candidates: list[str] = []
    for value in (response.headers.get("location"), response.headers.get("x-reset-link")):
        if value:
            candidates.extend(match.group(1) for match in RESET_TOKEN_PATTERN.finditer(value))
    candidates.extend(match.group(1) for match in RESET_TOKEN_PATTERN.finditer(response.text or ""))
    seen: set[str] = set()
    normalized: list[str] = []
    for token in candidates:
        value = token.strip()
        if value and value not in seen:
            normalized.append(value)
            seen.add(value)
    return normalized


def _extract_reset_links(response: httpx_client.Response) -> list[str]:
    links: list[str] = []
    for value in (response.headers.get("location"), response.headers.get("x-reset-link")):
        if value:
            links.append(value.strip())
    links.extend(match.group(0).strip() for match in URL_PATTERN.finditer(response.text or ""))
    return [link for link in dict.fromkeys(links) if link]


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
                "authentication",
                "password_reset",
                "auth_flow",
                "auth-flow",
            ],
            "wstg_id": wstg_id,
            "control_family": "authentication",
            "evidence": evidence,
            "replay_recipe": {
                "tool": "auth-flow",
                "target": target,
                "scope": "approved-web-root-only",
                "credential_source": "configured-test-account",
            },
        }
    )


def _submit_form(
    client: httpx_client.Client,
    url: str,
    *,
    method: str,
    data: dict[str, str],
    headers: dict[str, str] | None = None,
) -> httpx_client.Response:
    normalized_method = method.strip().upper()
    if normalized_method == "GET":
        return client.get(url, params=data, headers=headers)
    return client.post(url, data=data, headers=headers)


def _safe_elapsed_call(call: Callable[[], httpx_client.Response]) -> tuple[httpx_client.Response, float]:
    started = time.perf_counter()
    response = call()
    return response, time.perf_counter() - started


def execute_auth_flow_analysis(
    targets: list[str],
    *,
    auth_contexts: list[dict[str, Any]] | object,
    scope_allowlist: dict[str, Any] | None = None,
    login_url: str | None = None,
    registration_url: str | None = None,
    reg_username_field: str = "username",
    reg_password_field: str = "password",
    extra_reg_fields: dict[str, Any] | None = None,
    password_reset_url: str | None = None,
    reset_consume_url: str | None = None,
    login_method: str = "POST",
    reset_method: str = "POST",
    username_field: str = "username",
    password_field: str = "password",
    reset_username_field: str = "username",
    reset_token_field: str = "token",
    new_password_field: str = "new_password",
    extra_login_fields: dict[str, Any] | None = None,
    extra_reset_fields: dict[str, Any] | None = None,
    invalid_usernames: list[str] | object = None,
    reset_token_samples: int = 5,
    failed_login_attempts: int = 10,
    invalid_password: str = "AegisPT-invalid-password-000!",
    reset_poison_host: str | None = None,
    lockout_markers: list[str] | object = None,
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

    # Auto-register: if no credentials are configured but a registration URL is provided,
    # create a disposable test account and proceed with those credentials.
    effective_auth_contexts = auth_contexts
    auto_registered: tuple[str, str] | None = None
    if registration_url and (not isinstance(auth_contexts, list) or not auth_contexts):
        rendered_reg_url = _render_url(normalized_targets[0], registration_url)
        with client_factory(follow_redirects=True, timeout=timeout_seconds) as reg_client:
            auto_registered = _try_auto_register(
                reg_client,
                registration_url=rendered_reg_url,
                scope_allowlist=scope_allowlist,
                reg_username_field=reg_username_field,
                reg_password_field=reg_password_field,
                extra_reg_fields=extra_reg_fields,
            )
        if auto_registered:
            effective_auth_contexts = [{"username": auto_registered[0], "password": auto_registered[1]}]

    # Graceful skip when no credentials are available (and auto-register was not possible)
    try:
        safe_auth_contexts = _normalize_auth_contexts(effective_auth_contexts)
    except ValueError as exc:
        return RunnerExecution(
            tool="auth-flow",
            exit_code=0,
            stdout=f"auth-flow skipped: {exc}. Configure credentials via the credential vault or set registration_url for auto-register.",
            stderr="",
            artifacts=[],
            metadata={"skipped": True, "skip_reason": str(exc)},
        )
    auth_context = safe_auth_contexts[0]
    target = normalized_targets[0]
    rendered_login_url = _render_url(target, login_url or "login")
    rendered_reset_url = _render_url(target, password_reset_url or "password-reset")
    rendered_consume_url = _render_url(target, reset_consume_url or password_reset_url or "password-reset")
    for url in (rendered_login_url, rendered_reset_url, rendered_consume_url):
        _assert_allowed(scope_allowlist, url)

    invalid_users = _normalize_string_list(invalid_usernames, limit=5) or list(DEFAULT_INVALID_USERNAMES)
    lockout_marker_values = _normalize_string_list(lockout_markers, limit=10) or list(DEFAULT_LOCKOUT_MARKERS)
    sample_bound = min(max(int(reset_token_samples or 5), 2), 5)
    failed_attempt_bound = min(max(int(failed_login_attempts or 10), 1), 10)
    login_method = login_method.strip().upper() or "POST"
    reset_method = reset_method.strip().upper() or "POST"

    checks: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    seen_findings: set[tuple[str, str]] = set()
    stderr_lines: list[str] = []
    exit_code = 0
    headers = {"User-Agent": "AegisPT/auth-flow bounded validation", **auth_context["headers"]}

    if urlparse(rendered_login_url).scheme == "http":
        evidence = {
            "check_type": "credentials_over_http",
            "target": rendered_login_url,
            "scheme": "http",
            "password_value_recorded": False,
        }
        checks.append(evidence)
        _append_finding(
            findings,
            seen_findings,
            finding_type="credentials_over_http",
            title="Credentials Submitted Over HTTP",
            severity="high",
            target=rendered_login_url,
            summary="The configured login endpoint uses cleartext HTTP for credential submission.",
            evidence=evidence,
            wstg_id="WSTG-ATHN-01",
        )
    if login_method == "GET":
        parsed_login = urlparse(rendered_login_url)
        parameter_names = {name.lower() for name, value in parse_qsl(parsed_login.query, keep_blank_values=True) if value}
        evidence = {
            "check_type": "credentials_in_get",
            "target": rendered_login_url,
            "login_method": "GET",
            "credential_parameters_present": sorted(
                name for name in {username_field.lower(), password_field.lower()} if name in parameter_names
            ),
            "password_value_recorded": False,
        }
        checks.append(evidence)
        _append_finding(
            findings,
            seen_findings,
            finding_type="credentials_in_get",
            title="Credentials Submitted via GET Parameters",
            severity="high",
            target=rendered_login_url,
            summary="The configured login flow submits credentials with GET semantics, exposing them to logs, browser history, and referrer headers.",
            evidence=evidence,
            wstg_id="WSTG-ATHN-01",
        )

    reset_tokens: list[str] = []
    with client_factory(follow_redirects=False, timeout=timeout_seconds) as client:
        try:
            for _ in range(sample_bound):
                payload = {
                    reset_username_field: str(auth_context["username"]),
                    **{
                        str(key).strip(): str(value)
                        for key, value in (extra_reset_fields or {}).items()
                        if str(key).strip()
                    },
                }
                response = _submit_form(
                    client,
                    rendered_reset_url,
                    method=reset_method,
                    data=payload,
                    headers=headers,
                )
                tokens = _extract_reset_tokens(response)
                if tokens:
                    reset_tokens.append(tokens[0])
                checks.append(
                    {
                        "check_type": "password_reset_token_sample",
                        "target": rendered_reset_url,
                        "status_code": response.status_code,
                        "response_hash": _response_hash(response),
                        "token_hashes": [_token_hash(token) for token in tokens],
                        "token_count": len(tokens),
                    }
                )
        except httpx_client.HTTPError as exc:
            exit_code = 1
            stderr_lines.append(f"password reset token sampling failed for {rendered_reset_url}: {exc}")

        if reset_poison_host:
            try:
                poison_payload = {
                    reset_username_field: str(auth_context["username"]),
                    **{
                        str(key).strip(): str(value)
                        for key, value in (extra_reset_fields or {}).items()
                        if str(key).strip()
                    },
                }
                poison_response = _submit_form(
                    client,
                    rendered_reset_url,
                    method=reset_method,
                    data=poison_payload,
                    headers={**headers, "Host": reset_poison_host},
                )
                links = _extract_reset_links(poison_response)
                poison_seen = any(urlparse(link).hostname == reset_poison_host for link in links)
                check = {
                    "check_type": "password_reset_host_header_poisoning",
                    "target": rendered_reset_url,
                    "forged_host_hash": _token_hash(reset_poison_host),
                    "reset_link_uses_forged_host": poison_seen,
                    "link_hostnames": sorted({urlparse(link).hostname for link in links if urlparse(link).hostname}),
                    "response_hash": _response_hash(poison_response),
                }
                checks.append(check)
                if poison_seen:
                    _append_finding(
                        findings,
                        seen_findings,
                        finding_type="password_reset_host_header_poisoning",
                        title="Password Reset Host Header Injection",
                        severity="high",
                        target=rendered_reset_url,
                        summary="A password reset response produced a reset link using the forged Host header value.",
                        evidence=check,
                        wstg_id="WSTG-ATHN-09",
                    )
            except httpx_client.HTTPError as exc:
                exit_code = 1
                stderr_lines.append(f"password reset host-header check failed for {rendered_reset_url}: {exc}")

        if reset_tokens:
            unique_count = len(set(reset_tokens))
            minimum_bits = min(_entropy_bits(token) for token in reset_tokens)
            minimum_length = min(len(token) for token in reset_tokens)
            sequential = _looks_sequential(reset_tokens)
            timestamp_based = _looks_timestamp_based(reset_tokens)
            weak = (
                unique_count < len(reset_tokens)
                or minimum_bits < 128
                or minimum_length < 16
                or sequential
                or timestamp_based
            )
            check = {
                "check_type": "password_reset_token_predictability",
                "target": rendered_reset_url,
                "sample_count": len(reset_tokens),
                "unique_count": unique_count,
                "minimum_estimated_bits": round(minimum_bits, 2),
                "minimum_length": minimum_length,
                "sequential_pattern": sequential,
                "timestamp_based_pattern": timestamp_based,
                "token_hashes": [_token_hash(token) for token in reset_tokens],
            }
            checks.append(check)
            if weak:
                _append_finding(
                    findings,
                    seen_findings,
                    finding_type="predictable_password_reset_token",
                    title="Predictable Password Reset Token",
                    severity="high",
                    target=rendered_reset_url,
                    summary="Bounded reset samples appear predictable, repeated, timestamp-like, too short, or below the 128-bit entropy target.",
                    evidence=check,
                    wstg_id="WSTG-ATHN-09",
                )

        if reset_tokens:
            try:
                token = reset_tokens[0]
                consume_payload = {
                    reset_token_field: token,
                    new_password_field: str(auth_context["password"]),
                }
                first = _submit_form(
                    client,
                    rendered_consume_url,
                    method="POST",
                    data=consume_payload,
                    headers=headers,
                )
                second = _submit_form(
                    client,
                    rendered_consume_url,
                    method="POST",
                    data=consume_payload,
                    headers=headers,
                )
                first_success = first.status_code in {200, 201, 202, 204, 302, 303}
                second_success = second.status_code in {200, 201, 202, 204, 302, 303}
                second_body = (second.text or "").lower()
                reuse_rejected = (
                    second.status_code in {400, 401, 403, 404, 409, 410, 422}
                    or any(marker in second_body for marker in ("used", "expired", "invalid", "already"))
                )
                check = {
                    "check_type": "password_reset_token_reuse",
                    "target": rendered_consume_url,
                    "first_status_code": first.status_code,
                    "second_status_code": second.status_code,
                    "first_success_like": first_success,
                    "second_success_like": second_success,
                    "reuse_rejected": reuse_rejected,
                    "token_hash": _token_hash(token),
                    "password_value_recorded": False,
                }
                checks.append(check)
                if first_success and second_success and not reuse_rejected:
                    _append_finding(
                        findings,
                        seen_findings,
                        finding_type="password_reset_token_reuse",
                        title="Password Reset Token Reuse Accepted",
                        severity="high",
                        target=rendered_consume_url,
                        summary="A password reset token remained accepted after an earlier reset-token consumption request.",
                        evidence=check,
                        wstg_id="WSTG-ATHN-09",
                    )
            except httpx_client.HTTPError as exc:
                exit_code = 1
                stderr_lines.append(f"password reset token reuse check failed for {rendered_consume_url}: {exc}")

        try:
            valid_login_payload = {
                username_field: str(auth_context["username"]),
                password_field: invalid_password,
                **{
                    str(key).strip(): str(value)
                    for key, value in (extra_login_fields or {}).items()
                    if str(key).strip()
                },
            }
            invalid_login_payload = {
                username_field: invalid_users[0],
                password_field: invalid_password,
                **{
                    str(key).strip(): str(value)
                    for key, value in (extra_login_fields or {}).items()
                    if str(key).strip()
                },
            }
            valid_response, valid_elapsed = _safe_elapsed_call(
                lambda: _submit_form(
                    client,
                    rendered_login_url,
                    method=login_method,
                    data=valid_login_payload,
                    headers=headers,
                )
            )
            invalid_response, invalid_elapsed = _safe_elapsed_call(
                lambda: _submit_form(
                    client,
                    rendered_login_url,
                    method=login_method,
                    data=invalid_login_payload,
                    headers=headers,
                )
            )
            valid_signature = _body_signature(valid_response)
            invalid_signature = _body_signature(invalid_response)
            timing_delta_ms = abs(valid_elapsed - invalid_elapsed) * 1000
            content_differs = valid_signature != invalid_signature
            enumeration_signal = content_differs or timing_delta_ms >= 500
            check = {
                "check_type": "username_enumeration",
                "target": rendered_login_url,
                "valid_user_status_code": valid_response.status_code,
                "invalid_user_status_code": invalid_response.status_code,
                "valid_user_body_hash": valid_signature["body_hash"],
                "invalid_user_body_hash": invalid_signature["body_hash"],
                "valid_user_body_length": valid_signature["body_length"],
                "invalid_user_body_length": invalid_signature["body_length"],
                "timing_delta_ms": round(timing_delta_ms, 2),
                "enumeration_signal": enumeration_signal,
            }
            checks.append(check)
            if enumeration_signal:
                _append_finding(
                    findings,
                    seen_findings,
                    finding_type="username_enumeration",
                    title="Username Enumeration in Authentication Flow",
                    severity="medium",
                    target=rendered_login_url,
                    summary="Valid and invalid usernames produced different response status, body signature, body length, or timing behavior.",
                    evidence=check,
                    wstg_id="WSTG-ATHN-04",
                )
        except httpx_client.HTTPError as exc:
            exit_code = 1
            stderr_lines.append(f"username enumeration check failed for {rendered_login_url}: {exc}")

        protection_triggered = False
        attempt_records: list[dict[str, Any]] = []
        try:
            for attempt in range(1, failed_attempt_bound + 1):
                payload = {
                    username_field: str(auth_context["username"]),
                    password_field: invalid_password,
                    **{
                        str(key).strip(): str(value)
                        for key, value in (extra_login_fields or {}).items()
                        if str(key).strip()
                    },
                }
                response = _submit_form(
                    client,
                    rendered_login_url,
                    method=login_method,
                    data=payload,
                    headers=headers,
                )
                body = (response.text or "").lower()
                protected = response.status_code in {403, 423, 429} or any(
                    marker in body for marker in lockout_marker_values
                )
                attempt_records.append(
                    {
                        "attempt": attempt,
                        "status_code": response.status_code,
                        "response_hash": _response_hash(response),
                        "protection_triggered": protected,
                    }
                )
                if protected:
                    protection_triggered = True
                    break
            check = {
                "check_type": "brute_force_protection",
                "target": rendered_login_url,
                "attempt_count": len(attempt_records),
                "max_attempts": 10,
                "stopped_immediately_on_protection": protection_triggered,
                "protection_triggered": protection_triggered,
                "attempts": attempt_records,
                "password_value_recorded": False,
            }
            checks.append(check)
            if len(attempt_records) >= failed_attempt_bound and not protection_triggered:
                _append_finding(
                    findings,
                    seen_findings,
                    finding_type="missing_brute_force_protection",
                    title="Missing Brute Force Protection on Login",
                    severity="medium",
                    target=rendered_login_url,
                    summary="Ten bounded failed login attempts completed without lockout, throttling, rate limiting, or equivalent protection signal.",
                    evidence=check,
                    wstg_id="WSTG-ATHN-03",
                )
        except httpx_client.HTTPError as exc:
            exit_code = 1
            stderr_lines.append(f"brute-force protection check failed for {rendered_login_url}: {exc}")

    payload = {
        "tool": "auth-flow",
        "targets": normalized_targets,
        "checks": checks,
        "findings": findings,
        "summary": {
            "target_count": len(normalized_targets),
            "auth_context_count": len(safe_auth_contexts),
            "check_count": len(checks),
            "finding_count": len(findings),
            "predictable_reset_token_findings": sum(
                1 for finding in findings if finding.get("type") == "predictable_password_reset_token"
            ),
            "reset_token_reuse_findings": sum(
                1 for finding in findings if finding.get("type") == "password_reset_token_reuse"
            ),
            "reset_poisoning_findings": sum(
                1 for finding in findings if finding.get("type") == "password_reset_host_header_poisoning"
            ),
            "username_enumeration_findings": sum(
                1 for finding in findings if finding.get("type") == "username_enumeration"
            ),
            "brute_force_findings": sum(
                1 for finding in findings if finding.get("type") == "missing_brute_force_protection"
            ),
            "insecure_credential_submission_findings": sum(
                1
                for finding in findings
                if finding.get("type") in {"credentials_over_http", "credentials_in_get"}
            ),
        },
        "safety": {
            "scope_enforced": True,
            "approved_web_root_only": True,
            "requires_active_approval": True,
            "configured_test_accounts_only": True,
            "brute_force_attempt_limit": 10,
            "actual_account_takeover": False,
            "credential_values_stored_in_artifacts": False,
            "reset_token_values_stored_in_artifacts": False,
        },
    }
    return RunnerExecution(
        tool="auth-flow",
        exit_code=exit_code,
        stdout=json.dumps(payload["summary"], sort_keys=True),
        stderr="\n".join(line for line in stderr_lines if line),
        metadata={
            "status": "ok" if exit_code == 0 else "completed_with_errors",
            "runner_digest": "workers.auth_flow.runner:v1",
            "tool_version": "custom-python-bounded",
            "finding_count": len(findings),
            "check_count": len(checks),
        },
        artifacts=[_json_artifact(AUTH_FLOW_RESULTS_ARTIFACT_NAME, payload)],
    )
