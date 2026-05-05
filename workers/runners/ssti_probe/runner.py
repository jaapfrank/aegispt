from __future__ import annotations

import html
import json
import re
from dataclasses import dataclass
from hashlib import sha256
from typing import Any, Callable
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

import httpx as httpx_client

from api.app.services.runs import web_target_value_is_allowed_with_path
from workers.runners.base.contracts import EvidenceArtifact, RunnerExecution
from workers.runners.httpx.runner import normalize_http_target

SSTI_RESULTS_ARTIFACT_NAME = "ssti-probe-results.json"
DEFAULT_PARAMETER_NAMES = (
    "q",
    "query",
    "search",
    "name",
    "message",
    "title",
    "content",
    "comment",
    "template",
    "snippet",
)
DEFAULT_STORED_FIELD_NAMES = ("snippet", "template", "content", "message", "comment", "title")
MARKER_PREFIX = "aegispt"
MARKER_SUFFIX = "ssti"


@dataclass(frozen=True, slots=True)
class PayloadSpec:
    payload_id: str
    engine: str
    payload: str
    expected_result: str
    expression: str


PAYLOAD_SPECS: tuple[PayloadSpec, ...] = (
    PayloadSpec(
        payload_id="double-curly-math",
        engine="Jinja2/Twig/GTL-style",
        payload=f"{MARKER_PREFIX}{{{{7*7}}}}{MARKER_SUFFIX}",
        expected_result="49",
        expression="7*7",
    ),
    PayloadSpec(
        payload_id="double-curly-string-multiply",
        engine="Jinja2",
        payload=f"{MARKER_PREFIX}{{{{7*'7'}}}}{MARKER_SUFFIX}",
        expected_result="7777777",
        expression="7*'7'",
    ),
    PayloadSpec(
        payload_id="dollar-expression-math",
        engine="Freemarker/Spring EL",
        payload=f"{MARKER_PREFIX}${{7*7}}{MARKER_SUFFIX}",
        expected_result="49",
        expression="7*7",
    ),
    PayloadSpec(
        payload_id="freemarker-assign-math",
        engine="Freemarker",
        payload=f"<#assign x=7*7>{MARKER_PREFIX}${{x}}{MARKER_SUFFIX}",
        expected_result="49",
        expression="7*7",
    ),
    PayloadSpec(
        payload_id="velocity-set-math",
        engine="Velocity",
        payload=f"#set($x=7*7){MARKER_PREFIX}${{x}}{MARKER_SUFFIX}",
        expected_result="49",
        expression="7*7",
    ),
    PayloadSpec(
        payload_id="hash-expression-math",
        engine="Pug/Jade/Spring EL",
        payload=f"{MARKER_PREFIX}#{{7*7}}{MARKER_SUFFIX}",
        expected_result="49",
        expression="7*7",
    ),
    PayloadSpec(
        payload_id="smarty-custom-math",
        engine="Smarty/custom template",
        payload=f"{MARKER_PREFIX}{{7*7}}{MARKER_SUFFIX}",
        expected_result="49",
        expression="7*7",
    ),
    PayloadSpec(
        payload_id="erb-expression-math",
        engine="ERB/EEx",
        payload=f"{MARKER_PREFIX}<%= 7*7 %>{MARKER_SUFFIX}",
        expected_result="49",
        expression="7*7",
    ),
)


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
    return re.sub(r"\s+", " ", response.text or "").strip()[:700]


def _allowed(scope_allowlist: dict[str, Any] | None, url: str) -> bool:
    return web_target_value_is_allowed_with_path(scope_allowlist or {}, url)


def _assert_allowed(scope_allowlist: dict[str, Any] | None, url: str) -> None:
    if not _allowed(scope_allowlist, url):
        raise ValueError(f"target outside approved SSTI/web scope: {url}")


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


def _configured_string_list(values: list[Any] | None, *, default: tuple[str, ...], limit: int) -> list[str]:
    raw_values = values if isinstance(values, list) else list(default)
    normalized: list[str] = []
    seen: set[str] = set()
    for value in raw_values:
        candidate = str(value or "").strip()
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)
        normalized.append(candidate)
        if len(normalized) >= limit:
            break
    return normalized


def _join_candidate_path(target: str, raw_path: Any) -> str | None:
    path = str(raw_path or "").strip()
    if not path:
        return None
    if "://" in path:
        return normalize_http_target(path)
    parsed = urlparse(target)
    if path.startswith("/"):
        return urljoin(f"{parsed.scheme}://{parsed.netloc}/", path.lstrip("/"))
    base = target if target.endswith("/") else f"{target}/"
    return urljoin(base, path)


def _candidate_urls(
    targets: list[str],
    scope_allowlist: dict[str, Any] | None,
    candidate_paths: list[Any] | None,
) -> list[str]:
    candidates: list[str] = []
    seen: set[str] = set()
    for target in targets:
        for candidate in [target] + [
            item
            for item in (
                _join_candidate_path(target, raw_path)
                for raw_path in (candidate_paths if isinstance(candidate_paths, list) else [])
            )
            if item
        ]:
            _assert_allowed(scope_allowlist, candidate)
            if candidate in seen:
                continue
            seen.add(candidate)
            candidates.append(candidate)
    return candidates


def _parameters_for_url(url: str, configured_names: list[str], max_parameters: int) -> list[str]:
    parsed = urlparse(url)
    query_names = [
        key
        for key, _ in parse_qsl(parsed.query, keep_blank_values=True)
        if key and key not in configured_names
    ]
    return (query_names + configured_names)[:max_parameters]


def _url_with_payload(url: str, parameter: str, payload: str) -> str:
    parsed = urlparse(url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    replaced = False
    updated: list[tuple[str, str]] = []
    for key, value in pairs:
        if key == parameter:
            updated.append((key, payload))
            replaced = True
        else:
            updated.append((key, value))
    if not replaced:
        updated.append((parameter, payload))
    return urlunparse(parsed._replace(query=urlencode(updated, doseq=True)))


def _expected_marker_pattern(expected_result: str) -> re.Pattern[str]:
    result_pattern = re.escape(expected_result)
    if expected_result == "49":
        result_pattern = r"49(?:\.0)?"
    return re.compile(
        rf"{re.escape(MARKER_PREFIX)}\s*{result_pattern}\s*{re.escape(MARKER_SUFFIX)}",
        flags=re.IGNORECASE,
    )


def _marker_confirmed(response: httpx_client.Response, spec: PayloadSpec) -> bool:
    pattern = _expected_marker_pattern(spec.expected_result)
    body = response.text or ""
    return bool(pattern.search(body) or pattern.search(html.unescape(body)))


def _literal_payload_reflected(response: httpx_client.Response, spec: PayloadSpec) -> bool:
    body = html.unescape(response.text or "")
    return spec.payload in body


def _context_url(context: dict[str, Any]) -> str:
    return str(
        context.get("url")
        or context.get("action")
        or context.get("target")
        or context.get("endpoint")
        or ""
    ).strip()


def _context_render_url(context: dict[str, Any]) -> str:
    return str(context.get("render_url") or context.get("final_url") or context.get("view_url") or "").strip()


def _context_field(context: dict[str, Any]) -> str:
    for key in ("field", "parameter", "template_field", "name"):
        value = str(context.get(key) or "").strip()
        if value:
            return value
    fields = context.get("fields")
    if isinstance(fields, dict):
        for key in fields:
            if str(key).strip():
                return str(key).strip()
    return DEFAULT_STORED_FIELD_NAMES[0]


def _safe_headers(context: dict[str, Any]) -> dict[str, str]:
    headers = context.get("headers")
    if not isinstance(headers, dict):
        return {}
    return {
        str(key): str(value)
        for key, value in headers.items()
        if str(key).strip() and str(value).strip()
    }


def _safe_cookies(context: dict[str, Any]) -> dict[str, str]:
    cookies = context.get("cookies")
    if not isinstance(cookies, dict):
        return {}
    return {
        str(key): str(value)
        for key, value in cookies.items()
        if str(key).strip() and str(value).strip()
    }


def _send_stored_context(
    client: httpx_client.Client,
    *,
    context: dict[str, Any],
    payload: str,
    scope_allowlist: dict[str, Any] | None,
) -> tuple[httpx_client.Response, httpx_client.Response | None, str]:
    action_url = normalize_http_target(_context_url(context))
    _assert_allowed(scope_allowlist, action_url)
    render_url = _context_render_url(context)
    if render_url:
        render_url = normalize_http_target(render_url)
        _assert_allowed(scope_allowlist, render_url)

    fields = dict(context.get("fields") if isinstance(context.get("fields"), dict) else {})
    field_name = _context_field(context)
    fields[field_name] = payload
    method = str(context.get("method") or "POST").strip().upper()
    headers = {
        "User-Agent": "AegisPT/ssti-probe math-only stored validation",
        **_safe_headers(context),
    }
    cookies = _safe_cookies(context)
    request_kwargs: dict[str, Any] = {"headers": headers}
    render_kwargs: dict[str, Any] = {
        "headers": {
            "User-Agent": "AegisPT/ssti-probe math-only render validation",
            **_safe_headers(context),
        }
    }
    if cookies:
        request_kwargs["cookies"] = cookies
        render_kwargs["cookies"] = cookies
    if method == "GET":
        submit_response = client.get(action_url, params=fields, **request_kwargs)
    else:
        submit_response = client.post(action_url, data=fields, **request_kwargs)
    render_response = None
    if render_url:
        render_response = client.get(render_url, **render_kwargs)
    return submit_response, render_response, field_name


def _append_finding(
    findings: list[dict[str, Any]],
    seen: set[tuple[str, str, str, str]],
    *,
    finding_type: str,
    target: str,
    context_kind: str,
    parameter: str,
    engine: str,
    spec: PayloadSpec,
    response: httpx_client.Response,
) -> None:
    key = (finding_type, target, parameter, engine)
    if key in seen:
        return
    seen.add(key)
    findings.append(
        {
            "type": finding_type,
            "title": f"SSTI Confirmed (Engine: {engine}) - Remote Code Execution Possible",
            "severity": "critical",
            "target": target,
            "summary": (
                "A math-only server-side template expression probe was evaluated by the "
                "application template engine inside approved scope."
            ),
            "confirmed": True,
            "methodology_tags": [
                "input_validation",
                "server_side_template_injection",
                "owasp-a03-2021",
                "ssti-probe-validation",
            ],
            "control_family": "input_validation",
            "evidence": {
                "probe": "math-expression-marker",
                "context": context_kind,
                "parameter": parameter,
                "engine": engine,
                "payload_id": spec.payload_id,
                "expression": spec.expression,
                "expected_result": spec.expected_result,
                "status_code": response.status_code,
                "response_hash": _response_hash(response),
                "body_excerpt": _body_excerpt(response),
                "literal_payload_reflected": _literal_payload_reflected(response, spec),
                "math_expression_payload_only": True,
                "command_payload_sent": False,
                "config_dump_payload_sent": False,
            },
            "replay_recipe": {
                "tool": "ssti-probe",
                "target": target,
                "scope": "approved-web-root-only",
                "context": context_kind,
                "payload_policy": "math-expression-only",
                "command_payloads_sent": False,
                "config_dump_payloads_sent": False,
                "stored_context_requires_explicit_configuration": context_kind != "reflected-parameter",
            },
        }
    )


def _stored_contexts(value: list[Any] | None) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    contexts: list[dict[str, Any]] = []
    for item in value:
        if isinstance(item, dict) and _context_url(item):
            contexts.append(dict(item))
    return contexts


def execute_ssti_probe(
    targets: list[str],
    *,
    scope_allowlist: dict[str, Any] | None = None,
    parameter_names: list[Any] | None = None,
    candidate_paths: list[Any] | None = None,
    stored_form_contexts: list[Any] | None = None,
    gruyere_contexts: list[Any] | None = None,
    max_parameters: int = 12,
    timeout_seconds: float = 10.0,
    client_factory: Callable[..., httpx_client.Client] | None = None,
) -> RunnerExecution:
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be greater than zero")
    max_parameters = min(max(int(max_parameters or 12), 1), 20)

    normalized_targets = _normalize_targets(targets, scope_allowlist)
    configured_parameters = _configured_string_list(
        parameter_names,
        default=DEFAULT_PARAMETER_NAMES,
        limit=20,
    )
    candidate_urls = _candidate_urls(normalized_targets, scope_allowlist, candidate_paths)
    stored_context_entries = _stored_contexts(stored_form_contexts)
    gruyere_context_entries = _stored_contexts(gruyere_contexts)

    checks: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    seen_findings: set[tuple[str, str, str, str]] = set()
    stderr_lines: list[str] = []
    exit_code = 0

    factory = client_factory or httpx_client.Client
    with factory(timeout=timeout_seconds, follow_redirects=False) as client:
        for candidate_url in candidate_urls:
            for parameter in _parameters_for_url(candidate_url, configured_parameters, max_parameters):
                for spec in PAYLOAD_SPECS:
                    probe_url = _url_with_payload(candidate_url, parameter, spec.payload)
                    try:
                        response = client.get(
                            probe_url,
                            headers={"User-Agent": "AegisPT/ssti-probe math-only reflected validation"},
                        )
                    except httpx_client.HTTPError as exc:
                        exit_code = 1
                        stderr_lines.append(f"SSTI reflected probe failed for {probe_url}: {exc}")
                        continue
                    confirmed = _marker_confirmed(response, spec)
                    checks.append(
                        {
                            "check_type": "reflected_parameter_ssti",
                            "target": candidate_url,
                            "parameter": parameter,
                            "payload_id": spec.payload_id,
                            "engine_candidate": spec.engine,
                            "expression": spec.expression,
                            "status_code": response.status_code,
                            "expression_result_detected": confirmed,
                            "literal_payload_reflected": _literal_payload_reflected(response, spec),
                            "response_hash": _response_hash(response),
                        }
                    )
                    if confirmed:
                        _append_finding(
                            findings,
                            seen_findings,
                            finding_type="ssti_confirmed",
                            target=candidate_url,
                            context_kind="reflected-parameter",
                            parameter=parameter,
                            engine=spec.engine,
                            spec=spec,
                            response=response,
                        )
                        break

        for context_kind, contexts in (
            ("stored-form", stored_context_entries),
            ("gruyere-gtl-stored-form", gruyere_context_entries),
        ):
            for index, context in enumerate(contexts):
                action_url = normalize_http_target(_context_url(context))
                parameter = _context_field(context)
                for spec in PAYLOAD_SPECS:
                    try:
                        submit_response, render_response, submitted_field = _send_stored_context(
                            client,
                            context=context,
                            payload=spec.payload,
                            scope_allowlist=scope_allowlist,
                        )
                    except httpx_client.HTTPError as exc:
                        exit_code = 1
                        stderr_lines.append(f"SSTI stored probe failed for {action_url}: {exc}")
                        continue
                    response_to_check = render_response or submit_response
                    confirmed = _marker_confirmed(response_to_check, spec)
                    engine = (
                        "Gruyere GTL/custom template language"
                        if context_kind == "gruyere-gtl-stored-form" and confirmed
                        else spec.engine
                    )
                    checks.append(
                        {
                            "check_type": context_kind.replace("-", "_"),
                            "target": action_url,
                            "context_index": index,
                            "field": submitted_field,
                            "payload_id": spec.payload_id,
                            "engine_candidate": engine,
                            "expression": spec.expression,
                            "submit_status_code": submit_response.status_code,
                            "render_status_code": getattr(render_response, "status_code", None),
                            "expression_result_detected": confirmed,
                            "literal_payload_reflected": _literal_payload_reflected(response_to_check, spec),
                            "response_hash": _response_hash(response_to_check),
                        }
                    )
                    if confirmed:
                        _append_finding(
                            findings,
                            seen_findings,
                            finding_type="ssti_confirmed",
                            target=action_url,
                            context_kind=context_kind,
                            parameter=parameter,
                            engine=engine,
                            spec=spec,
                            response=response_to_check,
                        )
                        break

    payload = {
        "tool": "ssti-probe",
        "targets": normalized_targets,
        "candidate_urls": candidate_urls,
        "checks": checks,
        "findings": findings,
        "summary": {
            "target_count": len(normalized_targets),
            "candidate_url_count": len(candidate_urls),
            "stored_context_count": len(stored_context_entries),
            "gruyere_context_count": len(gruyere_context_entries),
            "check_count": len(checks),
            "finding_count": len(findings),
            "confirmed_ssti_count": sum(1 for item in findings if item.get("type") == "ssti_confirmed"),
            "engine_candidates": sorted(
                {
                    str(item.get("evidence", {}).get("engine"))
                    for item in findings
                    if isinstance(item.get("evidence"), dict) and item.get("evidence", {}).get("engine")
                }
            ),
        },
        "safety": {
            "scope_enforced": True,
            "approved_web_roots_only": True,
            "active_tier_requires_approval": True,
            "math_expression_payloads_only": True,
            "command_payloads_sent": False,
            "config_dump_payloads_sent": False,
            "runtime_mutation": False,
            "stored_contexts_require_explicit_configuration": True,
            "max_parameters": max_parameters,
        },
    }
    return RunnerExecution(
        tool="ssti-probe",
        exit_code=exit_code,
        stdout=json.dumps(payload["summary"], sort_keys=True),
        stderr="\n".join(line for line in stderr_lines if line),
        metadata={
            "status": "ok" if exit_code == 0 else "completed_with_errors",
            "runner_digest": "workers.ssti_probe.runner:v1",
            "tool_version": "custom-python-math-only",
            "finding_count": len(findings),
            "check_count": len(checks),
        },
        artifacts=[_json_artifact(SSTI_RESULTS_ARTIFACT_NAME, payload)],
    )
