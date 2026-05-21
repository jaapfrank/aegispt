from __future__ import annotations

import json
import re
from hashlib import sha256
from typing import Any, Callable
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

import httpx as httpx_client

from api.app.services.runs import web_target_value_is_allowed_with_path
from workers.runners.base.contracts import EvidenceArtifact, RunnerExecution
from workers.runners.httpx.runner import normalize_http_target

CLIENT_STATE_RESULTS_ARTIFACT_NAME = "client-state-results.json"
PRIVILEGE_FIELD_MUTATIONS: dict[str, Any] = {
    "role": "admin",
    "userrole": "admin",
    "user_type": "admin",
    "usertype": "admin",
    "account_type": "admin",
    "accounttype": "admin",
    "access_level": "admin",
    "accesslevel": "admin",
    "privilege": "admin",
    "is_admin": "true",
    "isadmin": "true",
    "admin": "true",
    "administrator": "true",
}
PRICE_FIELD_MUTATIONS: dict[str, str] = {
    "price": "0.01",
    "amount": "0.01",
    "total": "0.01",
    "subtotal": "0.01",
    "cost": "0.01",
    "quantity": "999",
    "qty": "999",
}
SUCCESS_MARKERS = (
    "admin",
    "accepted",
    "updated",
    "saved",
    "created",
    "checkout complete",
    "order confirmed",
    "newsnippet",
)
DENIAL_MARKERS = (
    "forbidden",
    "unauthorized",
    "access denied",
    "not allowed",
    "permission denied",
    "login",
    "sign in",
)
INPUT_PATTERN = re.compile(r"<input\b[^>]*>", re.IGNORECASE)
FORM_PATTERN = re.compile(r"<form\b(?P<attrs>[^>]*)>(?P<body>.*?)</form>", re.IGNORECASE | re.DOTALL)
ATTR_PATTERN = re.compile(r"""(?P<name>[A-Za-z_:][-A-Za-z0-9_:.]*)\s*=\s*["'](?P<value>[^"']*)["']""")


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


def _normalize_auth_contexts(auth_contexts: object) -> list[dict[str, Any]]:
    if not isinstance(auth_contexts, list):
        raise ValueError("client-state requires at least one authenticated access account")

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

        basic_auth = raw_context.get("basic_auth")
        normalized_basic_auth = None
        if isinstance(basic_auth, dict):
            username = str(basic_auth.get("username") or "").strip()
            password = str(basic_auth.get("password") or "").strip()
            if username and password:
                normalized_basic_auth = (username, password)
        elif isinstance(basic_auth, tuple) and len(basic_auth) == 2:
            username, password = str(basic_auth[0] or "").strip(), str(basic_auth[1] or "").strip()
            if username and password:
                normalized_basic_auth = (username, password)

        if not normalized_headers and normalized_basic_auth is None:
            continue

        label = str(raw_context.get("label") or raw_context.get("username") or f"Account {index + 1}").strip()
        normalized.append(
            {
                "label": label or f"Account {index + 1}",
                "username": str(raw_context.get("username") or "").strip(),
                "role": str(raw_context.get("role") or "User").strip() or "User",
                "headers": normalized_headers,
                "basic_auth": normalized_basic_auth,
            }
        )

    if not normalized:
        raise ValueError("client-state requires at least one authenticated access account")
    return normalized


def _allowed(scope_allowlist: dict[str, Any] | None, url: str) -> bool:
    return web_target_value_is_allowed_with_path(scope_allowlist or {}, url)


def _assert_allowed(scope_allowlist: dict[str, Any] | None, url: str) -> None:
    if not _allowed(scope_allowlist, url):
        raise ValueError(f"target outside approved web scope: {url}")


def _render_url(base_target: str, value: object | None) -> str:
    candidate = str(value or "").strip()
    if not candidate:
        return base_target
    if "://" in candidate:
        return normalize_http_target(candidate)
    return urljoin(base_target.rstrip("/") + "/", candidate.lstrip("/"))


def _request_headers(auth_context: dict[str, Any], *, extra: dict[str, str] | None = None) -> dict[str, str]:
    headers = {
        "User-Agent": "AegisPT/client-state bounded authorization validation",
        **dict(auth_context.get("headers") or {}),
    }
    if extra:
        headers.update(extra)
    return headers


def _response_hash(response: httpx_client.Response) -> str:
    return sha256(response.content).hexdigest()


def _body_excerpt(response: httpx_client.Response) -> str:
    return re.sub(r"\s+", " ", response.text or "").strip()[:500]


def _success_status(status_code: int) -> bool:
    return 200 <= status_code < 300


def _attrs(raw: str) -> dict[str, str]:
    return {match.group("name").lower(): match.group("value") for match in ATTR_PATTERN.finditer(raw or "")}


def _field_key(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", name.lower())


def _mutation_for_field(name: str, value: object, *, price: bool = False) -> Any | None:
    key = _field_key(name)
    if price:
        return PRICE_FIELD_MUTATIONS.get(key)
    if isinstance(value, bool) and key in {"admin", "isadmin", "administrator"}:
        return True
    if key in PRIVILEGE_FIELD_MUTATIONS:
        return PRIVILEGE_FIELD_MUTATIONS[key]
    raw_value = str(value or "").strip().lower()
    if raw_value in {"false", "0", "no", "user", "standard", "viewer", "customer"}:
        return "true" if raw_value in {"false", "0", "no"} else "admin"
    return None


def _hidden_forms(base_url: str, html: str) -> list[dict[str, Any]]:
    forms: list[dict[str, Any]] = []
    for form_match in FORM_PATTERN.finditer(html or ""):
        form_attrs = _attrs(form_match.group("attrs"))
        fields: dict[str, str] = {}
        hidden_names: list[str] = []
        for input_match in INPUT_PATTERN.finditer(form_match.group("body")):
            input_attrs = _attrs(input_match.group(0))
            name = input_attrs.get("name", "").strip()
            if not name:
                continue
            fields[name] = input_attrs.get("value", "")
            if input_attrs.get("type", "").lower() == "hidden":
                hidden_names.append(name)
        if hidden_names:
            forms.append(
                {
                    "action": urljoin(base_url, form_attrs.get("action") or base_url),
                    "method": (form_attrs.get("method") or "POST").upper(),
                    "fields": fields,
                    "hidden_names": hidden_names,
                }
            )
    return forms


def _marker_matched(response: httpx_client.Response, markers: list[str]) -> bool:
    text = (response.text or "").lower()
    marker_values = [marker.lower() for marker in markers if marker.strip()] or list(SUCCESS_MARKERS)
    if any(marker in text for marker in marker_values):
        return True
    if any(marker in text for marker in DENIAL_MARKERS):
        return False
    return _success_status(response.status_code)


def _submit(
    client: httpx_client.Client,
    method: str,
    url: str,
    *,
    auth_context: dict[str, Any],
    data: dict[str, Any] | None = None,
    json_body: dict[str, Any] | None = None,
    extra_headers: dict[str, str] | None = None,
) -> httpx_client.Response:
    normalized_method = method.strip().upper() or "POST"
    headers = _request_headers(auth_context, extra=extra_headers)
    if normalized_method == "GET":
        return client.get(url, params=data or {}, headers=headers, auth=auth_context.get("basic_auth"))
    return client.request(
        normalized_method,
        url,
        data=data if json_body is None else None,
        json=json_body,
        headers=headers,
        auth=auth_context.get("basic_auth"),
    )


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
    confirmed: bool = True,
) -> None:
    key = (finding_type, target, str(evidence.get("parameter") or evidence.get("cookie_name") or ""))
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
            "confirmed": confirmed,
            "methodology_tags": [
                "broken_access_control",
                "authorization",
                "client_state",
                "client-state-validation",
            ],
            "control_family": "business_logic",
            "evidence": evidence,
            "replay_recipe": {
                "tool": "client-state",
                "target": target,
                "scope": "approved-web-root-only",
                "credential_source": "configured-access-context",
                "raw_credentials_included": False,
            },
        }
    )


def _mutated_query_url(url: str, parameter: str, replacement: str) -> str:
    parsed = urlparse(url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    mutated = [(name, replacement if name == parameter else value) for name, value in pairs]
    return urlunparse(parsed._replace(query=urlencode(mutated)))


def _cookie_header(base_header: str, cookie_name: str, value: str) -> str:
    parts = [part.strip() for part in base_header.split(";") if part.strip()]
    filtered = [part for part in parts if part.split("=", 1)[0].strip() != cookie_name]
    filtered.append(f"{cookie_name}={value}")
    return "; ".join(filtered)


def _classified_value(value: object) -> str:
    raw = str(value or "").strip().lower()
    if raw in {"", "none", "null"}:
        return "empty"
    if raw in {"false", "0", "no", "user", "standard", "viewer", "customer"}:
        return "low-privilege-like"
    if raw in {"true", "1", "yes", "admin", "administrator", "root"}:
        return "privileged-like"
    return "custom"


def execute_client_state_analysis(
    targets: list[str],
    *,
    auth_contexts: list[dict[str, Any]] | object,
    scope_allowlist: dict[str, Any] | None = None,
    form_contexts: list[dict[str, Any]] | object = None,
    cookie_contexts: list[dict[str, Any]] | object = None,
    request_contexts: list[dict[str, Any]] | object = None,
    price_contexts: list[dict[str, Any]] | object = None,
    workflow_contexts: list[dict[str, Any]] | object = None,
    gruyere_contexts: list[dict[str, Any]] | object = None,
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
    try:
        safe_auth_contexts = _normalize_auth_contexts(auth_contexts)
    except ValueError as exc:
        return RunnerExecution(
            tool="client-state",
            exit_code=78,  # EX_CONFIG — runner unavailable in this deployment
            stdout=f"client-state skipped: {exc}. Configure authenticated access accounts via the credential vault.",
            stderr="",
            artifacts=[],
            metadata={"skipped": True, "skip_reason": str(exc)},
        )
    auth_context = safe_auth_contexts[0]

    checks: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    seen_findings: set[tuple[str, str, str]] = set()
    stderr_lines: list[str] = []
    exit_code = 0

    with client_factory(follow_redirects=True, timeout=timeout_seconds) as client:
        for base_target in normalized_targets:
            for raw_context in form_contexts if isinstance(form_contexts, list) else []:
                if not isinstance(raw_context, dict):
                    continue
                form_url = _render_url(base_target, raw_context.get("url") or raw_context.get("target") or "")
                if not _allowed(scope_allowlist, form_url):
                    continue
                markers = _normalize_string_list(raw_context.get("success_markers"), limit=10)
                try:
                    html = str(raw_context.get("html") or "")
                    if not html:
                        response = client.get(
                            form_url,
                            headers=_request_headers(auth_context),
                            auth=auth_context.get("basic_auth"),
                        )
                        html = response.text
                        checks.append(
                            {
                                "check_type": "hidden_field_form_discovery",
                                "target": form_url,
                                "status_code": response.status_code,
                                "response_hash": _response_hash(response),
                            }
                        )
                    for form in _hidden_forms(form_url, html):
                        action = str(raw_context.get("action") or form["action"])
                        if not _allowed(scope_allowlist, action):
                            continue
                        for field_name in form["hidden_names"]:
                            original = form["fields"].get(field_name, "")
                            replacement = _mutation_for_field(field_name, original)
                            if replacement is None or str(replacement) == str(original):
                                continue
                            data = dict(form["fields"])
                            data[field_name] = str(replacement)
                            response = _submit(
                                client,
                                str(raw_context.get("method") or form["method"]),
                                action,
                                auth_context=auth_context,
                                data=data,
                            )
                            marker_hit = _marker_matched(response, markers)
                            check = {
                                "check_type": "hidden_field_privilege_manipulation",
                                "target": action,
                                "auth_label": auth_context["label"],
                                "parameter": field_name,
                                "original_value_class": _classified_value(original),
                                "mutated_value_class": _classified_value(replacement),
                                "status_code": response.status_code,
                                "success_marker_matched": marker_hit,
                                "response_hash": _response_hash(response),
                                "raw_values_recorded": False,
                            }
                            checks.append(check)
                            if _success_status(response.status_code) and marker_hit:
                                _append_finding(
                                    findings,
                                    seen_findings,
                                    finding_type="hidden_field_privilege_escalation",
                                    title="Client-State Manipulation - Hidden Field Privilege Escalation",
                                    severity="high",
                                    target=action,
                                    summary=(
                                        "The server accepted a privilege-like hidden form-field mutation from "
                                        "a configured authenticated context."
                                    ),
                                    evidence={**check, "response_excerpt": _body_excerpt(response)},
                                )
                except httpx_client.HTTPError as exc:
                    exit_code = 1
                    stderr_lines.append(f"hidden field manipulation failed for {form_url}: {exc}")

            all_cookie_contexts = list(cookie_contexts if isinstance(cookie_contexts, list) else [])
            all_cookie_contexts.extend(gruyere_contexts if isinstance(gruyere_contexts, list) else [])
            for raw_context in all_cookie_contexts:
                if not isinstance(raw_context, dict):
                    continue
                target_url = _render_url(base_target, raw_context.get("url") or raw_context.get("target") or "")
                if not _allowed(scope_allowlist, target_url):
                    continue
                cookie_name = str(raw_context.get("cookie_name") or raw_context.get("name") or "").strip()
                if not cookie_name:
                    continue
                original = str(raw_context.get("original_value") or raw_context.get("value") or "false").strip()
                replacement = str(raw_context.get("mutated_value") or _mutation_for_field(cookie_name, original) or "true")
                markers = _normalize_string_list(raw_context.get("success_markers"), limit=10)
                headers = {
                    "Cookie": _cookie_header(
                        str(auth_context.get("headers", {}).get("Cookie") or ""),
                        cookie_name,
                        replacement,
                    )
                }
                try:
                    response = client.get(
                        target_url,
                        headers=_request_headers(auth_context, extra=headers),
                        auth=auth_context.get("basic_auth"),
                    )
                    marker_hit = _marker_matched(response, markers)
                    check = {
                        "check_type": "cookie_privilege_manipulation",
                        "target": target_url,
                        "auth_label": auth_context["label"],
                        "cookie_name": cookie_name,
                        "original_value_class": _classified_value(original),
                        "mutated_value_class": _classified_value(replacement),
                        "status_code": response.status_code,
                        "success_marker_matched": marker_hit,
                        "response_hash": _response_hash(response),
                        "cookie_values_recorded": False,
                    }
                    checks.append(check)
                    if _success_status(response.status_code) and marker_hit:
                        _append_finding(
                            findings,
                            seen_findings,
                            finding_type="cookie_based_privilege_escalation",
                            title="Cookie-Based Privilege Escalation",
                            severity="high",
                            target=target_url,
                            summary=(
                                "A privilege-like cookie mutation unlocked server-side behavior for a "
                                "configured authenticated context."
                            ),
                            evidence={**check, "response_excerpt": _body_excerpt(response)},
                        )
                except httpx_client.HTTPError as exc:
                    exit_code = 1
                    stderr_lines.append(f"cookie manipulation failed for {target_url}: {exc}")

            for raw_context in request_contexts if isinstance(request_contexts, list) else []:
                if not isinstance(raw_context, dict):
                    continue
                target_url = _render_url(base_target, raw_context.get("url") or raw_context.get("target") or "")
                if not _allowed(scope_allowlist, target_url):
                    continue
                markers = _normalize_string_list(raw_context.get("success_markers"), limit=10)
                method = str(raw_context.get("method") or "POST").upper()
                raw_body = raw_context.get("json") or raw_context.get("json_body") or raw_context.get("form") or raw_context.get("body")
                candidate_fields = raw_body if isinstance(raw_body, dict) else dict(parse_qsl(urlparse(target_url).query, keep_blank_values=True))
                for field_name, original in list(candidate_fields.items()):
                    replacement = _mutation_for_field(field_name, original)
                    if replacement is None or str(replacement) == str(original):
                        continue
                    try:
                        if isinstance(raw_body, dict):
                            body = dict(raw_body)
                            body[field_name] = replacement
                            response = _submit(
                                client,
                                method,
                                target_url,
                                auth_context=auth_context,
                                json_body=body if raw_context.get("json") or raw_context.get("json_body") else None,
                                data=body if not (raw_context.get("json") or raw_context.get("json_body")) else None,
                            )
                        else:
                            response = client.get(
                                _mutated_query_url(target_url, field_name, str(replacement)),
                                headers=_request_headers(auth_context),
                                auth=auth_context.get("basic_auth"),
                            )
                        marker_hit = _marker_matched(response, markers)
                        check = {
                            "check_type": "request_parameter_privilege_manipulation",
                            "target": target_url,
                            "auth_label": auth_context["label"],
                            "parameter": field_name,
                            "method": method,
                            "original_value_class": _classified_value(original),
                            "mutated_value_class": _classified_value(replacement),
                            "status_code": response.status_code,
                            "success_marker_matched": marker_hit,
                            "response_hash": _response_hash(response),
                            "raw_values_recorded": False,
                        }
                        checks.append(check)
                        if _success_status(response.status_code) and marker_hit:
                            _append_finding(
                                findings,
                                seen_findings,
                                finding_type="request_parameter_privilege_escalation",
                                title="Server-Side Authorization Bypass via Request Parameter",
                                severity="high",
                                target=target_url,
                                summary="A role/admin-style request parameter mutation was accepted by the server.",
                                evidence={**check, "response_excerpt": _body_excerpt(response)},
                            )
                    except httpx_client.HTTPError as exc:
                        exit_code = 1
                        stderr_lines.append(f"request parameter manipulation failed for {target_url}: {exc}")

            for raw_context in price_contexts if isinstance(price_contexts, list) else []:
                if not isinstance(raw_context, dict):
                    continue
                target_url = _render_url(base_target, raw_context.get("url") or raw_context.get("target") or "")
                if not _allowed(scope_allowlist, target_url):
                    continue
                markers = _normalize_string_list(raw_context.get("success_markers"), limit=10)
                method = str(raw_context.get("method") or "POST").upper()
                raw_body = raw_context.get("json") or raw_context.get("json_body") or raw_context.get("form") or raw_context.get("body")
                if not isinstance(raw_body, dict):
                    continue
                for field_name, original in list(raw_body.items()):
                    replacement = _mutation_for_field(field_name, original, price=True)
                    if replacement is None or str(replacement) == str(original):
                        continue
                    body = dict(raw_body)
                    body[field_name] = replacement
                    try:
                        response = _submit(
                            client,
                            method,
                            target_url,
                            auth_context=auth_context,
                            json_body=body if raw_context.get("json") or raw_context.get("json_body") else None,
                            data=body if not (raw_context.get("json") or raw_context.get("json_body")) else None,
                        )
                        marker_hit = _marker_matched(response, markers)
                        check = {
                            "check_type": "price_amount_manipulation",
                            "target": target_url,
                            "auth_label": auth_context["label"],
                            "parameter": field_name,
                            "method": method,
                            "original_value_class": "business-amount",
                            "mutated_value_class": "tampered-business-amount",
                            "status_code": response.status_code,
                            "success_marker_matched": marker_hit,
                            "response_hash": _response_hash(response),
                            "raw_values_recorded": False,
                        }
                        checks.append(check)
                        if _success_status(response.status_code) and marker_hit:
                            _append_finding(
                                findings,
                                seen_findings,
                                finding_type="price_amount_manipulation",
                                title="Business Logic - Price or Amount Manipulation",
                                severity="high",
                                target=target_url,
                                summary="The server accepted a client-controlled price, amount, total, or quantity mutation.",
                                evidence={**check, "response_excerpt": _body_excerpt(response)},
                            )
                    except httpx_client.HTTPError as exc:
                        exit_code = 1
                        stderr_lines.append(f"price manipulation failed for {target_url}: {exc}")

            for raw_context in workflow_contexts if isinstance(workflow_contexts, list) else []:
                if not isinstance(raw_context, dict):
                    continue
                final_url = _render_url(
                    base_target,
                    raw_context.get("final_url") or raw_context.get("url") or raw_context.get("target") or "",
                )
                if not _allowed(scope_allowlist, final_url):
                    continue
                markers = _normalize_string_list(raw_context.get("success_markers"), limit=10)
                try:
                    response = client.get(
                        final_url,
                        headers=_request_headers(auth_context),
                        auth=auth_context.get("basic_auth"),
                    )
                    marker_hit = _marker_matched(response, markers)
                    check = {
                        "check_type": "workflow_step_skipping",
                        "target": final_url,
                        "auth_label": auth_context["label"],
                        "status_code": response.status_code,
                        "success_marker_matched": marker_hit,
                        "response_hash": _response_hash(response),
                    }
                    checks.append(check)
                    if _success_status(response.status_code) and marker_hit:
                        _append_finding(
                            findings,
                            seen_findings,
                            finding_type="workflow_step_skipping",
                            title="Business Logic - Workflow Step Skipping Accepted",
                            severity="medium",
                            target=final_url,
                            summary="A later workflow step was accepted directly from a configured authenticated context.",
                            evidence={**check, "response_excerpt": _body_excerpt(response)},
                        )
                except httpx_client.HTTPError as exc:
                    exit_code = 1
                    stderr_lines.append(f"workflow step-skipping failed for {final_url}: {exc}")

    payload = {
        "tool": "client-state",
        "targets": normalized_targets,
        "checks": checks,
        "findings": findings,
        "summary": {
            "target_count": len(normalized_targets),
            "auth_context_count": len(safe_auth_contexts),
            "check_count": len(checks),
            "finding_count": len(findings),
            "hidden_field_findings": sum(1 for item in findings if item.get("type") == "hidden_field_privilege_escalation"),
            "cookie_privilege_findings": sum(1 for item in findings if item.get("type") == "cookie_based_privilege_escalation"),
            "request_parameter_findings": sum(1 for item in findings if item.get("type") == "request_parameter_privilege_escalation"),
            "price_manipulation_findings": sum(1 for item in findings if item.get("type") == "price_amount_manipulation"),
            "workflow_step_skipping_findings": sum(1 for item in findings if item.get("type") == "workflow_step_skipping"),
        },
        "safety": {
            "scope_enforced": True,
            "approved_web_root_only": True,
            "requires_active_approval": True,
            "configured_credentials_only": True,
            "parameter_and_cookie_manipulation_only": True,
            "post_exploitation_chaining": False,
            "raw_credentials_stored_in_artifacts": False,
            "raw_cookie_values_stored_in_artifacts": False,
            "runtime_mutation": False,
        },
    }
    return RunnerExecution(
        tool="client-state",
        exit_code=exit_code,
        stdout=json.dumps(payload["summary"], sort_keys=True),
        stderr="\n".join(line for line in stderr_lines if line),
        metadata={
            "status": "ok" if exit_code == 0 else "completed_with_errors",
            "runner_digest": "workers.client_state.runner:v1",
            "tool_version": "custom-python-bounded",
            "finding_count": len(findings),
            "check_count": len(checks),
        },
        artifacts=[_json_artifact(CLIENT_STATE_RESULTS_ARTIFACT_NAME, payload)],
    )
