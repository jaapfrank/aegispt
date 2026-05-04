from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from ipaddress import ip_address, ip_network
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from workers.runners.base.contracts import EvidenceArtifact, RunnerExecution
from workers.runners.httpx.runner import normalize_http_target

PLAYWRIGHT_WEB_RESULTS_ARTIFACT_NAME = "playwright-web-results.json"
PLAYWRIGHT_WEB_NETWORK_ARTIFACT_NAME = "playwright-web-network.jsonl"
PLAYWRIGHT_WEB_CONSOLE_ARTIFACT_NAME = "playwright-web-console.jsonl"
PLAYWRIGHT_WEB_DOM_ARTIFACT_NAME = "playwright-web-dom.html"
PLAYWRIGHT_WEB_SCREENSHOT_ARTIFACT_NAME = "playwright-web-screenshot.png"
RUNNER_DIGEST = "workers.playwright_web.runner:v1"
SENSITIVE_STORAGE_PATTERNS = (
    "api_key",
    "apikey",
    "authorization",
    "bearer",
    "id_token",
    "jwt",
    "refresh_token",
    "secret",
    "session",
    "token",
)
SAFE_METHODS = {"", "get", "dialog"}


@dataclass(slots=True, frozen=True)
class BrowserObservation:
    url: str
    status: str = "ok"
    final_url: str | None = None
    title: str | None = None
    dom: str = ""
    screenshot: bytes | None = None
    console: list[dict[str, Any]] | None = None
    network: list[dict[str, Any]] | None = None
    storage: dict[str, dict[str, str]] | None = None
    forms: list[dict[str, Any]] | None = None
    hidden_inputs: list[dict[str, str]] | None = None
    errors: list[str] | None = None


BrowserCollector = Callable[..., BrowserObservation | dict[str, Any]]


def _target_host(value: str) -> str:
    parsed = urlparse(value if "://" in value else f"//{value}")
    return (parsed.hostname or value.split("/", 1)[0].split(":", 1)[0]).strip().lower()


def _allowed_values(scope_allowlist: dict[str, Any] | list[str] | None) -> list[str]:
    if isinstance(scope_allowlist, list):
        return [str(item).strip() for item in scope_allowlist if str(item).strip()]
    if not isinstance(scope_allowlist, dict):
        return []

    values: list[str] = []
    for key in (
        "urls",
        "api_base_urls",
        "domains",
        "hosts",
        "ip_addresses",
        "targets",
        "cidrs",
        "cidr_ranges",
    ):
        raw_items = scope_allowlist.get(key)
        if isinstance(raw_items, list):
            values.extend(str(item).strip() for item in raw_items if str(item).strip())
    return values


def _target_is_in_scope(target: str, scope_allowlist: dict[str, Any] | list[str] | None) -> bool:
    allowed_values = _allowed_values(scope_allowlist)
    if not allowed_values:
        return False
    if target in allowed_values:
        return True

    target_host = _target_host(target)
    try:
        target_ip = ip_address(target_host)
    except ValueError:
        target_ip = None

    for allowed in allowed_values:
        if target == allowed:
            return True
        allowed_host = _target_host(allowed)
        if target_host == allowed_host or target_host.endswith(f".{allowed_host}"):
            return True
        try:
            network = ip_network(allowed, strict=False)
        except ValueError:
            continue
        if target_ip is not None and target_ip in network:
            return True
    return False


def _redact(value: object) -> str:
    text = str(value or "")
    if not text:
        return ""
    lowered = text.lower()
    if any(marker in lowered for marker in SENSITIVE_STORAGE_PATTERNS):
        return "[redacted]"
    if "=" in text and (";" in text or "session" in lowered or "cookie" in lowered):
        return "[redacted]"
    return text[:500]


def _safe_headers(headers: dict[str, Any] | None) -> dict[str, str]:
    safe: dict[str, str] = {}
    for key, value in (headers or {}).items():
        normalized = str(key).strip()
        lowered = normalized.lower()
        if lowered in {"authorization", "cookie", "set-cookie", "x-api-key"}:
            safe[normalized] = "[redacted]"
        else:
            safe[normalized] = _redact(value)
    return safe


def _with_proof_marker(target: str, proof_marker: str | None) -> str:
    normalized = normalize_http_target(target)
    marker = str(proof_marker or "").strip()
    if not marker:
        return normalized
    parsed = urlparse(normalized)
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    query["aegispt_probe"] = marker
    return urlunparse(parsed._replace(query=urlencode(query)))


def _cookie_records(*, cookie_header: str, target_url: str) -> list[dict[str, Any]]:
    parsed = urlparse(target_url)
    host = parsed.hostname
    if not host:
        return []
    cookies: list[dict[str, Any]] = []
    for item in cookie_header.split(";"):
        if "=" not in item:
            continue
        name, value = item.split("=", 1)
        name = name.strip()
        if not name:
            continue
        cookies.append(
            {
                "name": name,
                "value": value.strip(),
                "domain": host,
                "path": "/",
                "httpOnly": True,
                "secure": parsed.scheme == "https",
            }
        )
    return cookies


def _auth_material(auth_contexts: list[dict[str, Any]]) -> tuple[dict[str, str], list[dict[str, str]]]:
    headers: dict[str, str] = {}
    cookies: list[dict[str, str]] = []
    for context in auth_contexts:
        if not isinstance(context, dict):
            continue
        context_headers = context.get("headers")
        if isinstance(context_headers, dict):
            for key, value in context_headers.items():
                normalized_key = str(key).strip()
                if normalized_key:
                    headers[normalized_key] = str(value)
        cookie_value = str((context_headers or {}).get("Cookie") or "").strip() if isinstance(context_headers, dict) else ""
        if cookie_value:
            cookies.append({"cookie_header": cookie_value})
    return headers, cookies


def _default_collect_with_playwright(
    *,
    target: str,
    auth_contexts: list[dict[str, Any]],
    proof_marker: str | None,
    timeout_seconds: float,
) -> BrowserObservation:
    from playwright.sync_api import Error as PlaywrightError
    from playwright.sync_api import sync_playwright

    navigation_url = _with_proof_marker(target, proof_marker)
    console_events: list[dict[str, Any]] = []
    network_events: list[dict[str, Any]] = []
    headers, cookie_sources = _auth_material(auth_contexts)

    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            context = browser.new_context(
                ignore_https_errors=True,
                extra_http_headers=headers or None,
            )
            cookie_records: list[dict[str, Any]] = []
            for source in cookie_sources:
                cookie_records.extend(
                    _cookie_records(
                        cookie_header=source["cookie_header"],
                        target_url=navigation_url,
                    )
                )
            if cookie_records:
                context.add_cookies(cookie_records)

            page = context.new_page()
            page.on(
                "console",
                lambda message: console_events.append(
                    {"type": message.type, "text": _redact(message.text)}
                ),
            )
            page.on(
                "request",
                lambda request: network_events.append(
                    {
                        "event": "request",
                        "method": request.method,
                        "url": request.url,
                        "headers": _safe_headers(request.headers),
                    }
                ),
            )
            page.on(
                "response",
                lambda response: network_events.append(
                    {
                        "event": "response",
                        "status": response.status,
                        "url": response.url,
                        "headers": _safe_headers(response.headers),
                    }
                ),
            )
            response = page.goto(
                navigation_url,
                wait_until="domcontentloaded",
                timeout=max(int(timeout_seconds * 1000), 1000),
            )
            page.wait_for_timeout(250)
            dom = page.content()
            storage = page.evaluate(
                """() => ({
                    localStorage: Object.fromEntries(Object.entries(window.localStorage || {})),
                    sessionStorage: Object.fromEntries(Object.entries(window.sessionStorage || {}))
                })"""
            )
            forms = page.evaluate(
                """() => Array.from(document.forms).map((form) => ({
                    method: String(form.method || '').toLowerCase(),
                    action: form.action || window.location.href,
                    inputNames: Array.from(form.querySelectorAll('input, textarea, select'))
                        .map((input) => input.name || input.id || '')
                        .filter(Boolean),
                    hiddenInputs: Array.from(form.querySelectorAll('input[type="hidden"]'))
                        .map((input) => ({name: input.name || input.id || '', value: input.value || ''}))
                }))"""
            )
            hidden_inputs = page.evaluate(
                """() => Array.from(document.querySelectorAll('input[type="hidden"]'))
                    .map((input) => ({name: input.name || input.id || '', value: input.value || ''}))"""
            )
            screenshot = page.screenshot(full_page=True)
            title = page.title()
            final_url = page.url
            status = "ok" if response is None or response.status < 500 else "partial"
            browser.close()
    except PlaywrightError as exc:
        return BrowserObservation(
            url=target,
            status="failed",
            errors=[str(exc)],
            console=console_events,
            network=network_events,
        )

    return BrowserObservation(
        url=target,
        status=status,
        final_url=final_url,
        title=title,
        dom=dom,
        screenshot=screenshot,
        console=console_events,
        network=network_events,
        storage=storage if isinstance(storage, dict) else {},
        forms=forms if isinstance(forms, list) else [],
        hidden_inputs=hidden_inputs if isinstance(hidden_inputs, list) else [],
    )


def _normalize_observation(value: BrowserObservation | dict[str, Any], *, target: str) -> dict[str, Any]:
    if isinstance(value, BrowserObservation):
        return {
            "url": value.url,
            "status": value.status,
            "final_url": value.final_url,
            "title": value.title,
            "dom": value.dom,
            "console": list(value.console or []),
            "network": list(value.network or []),
            "storage": dict(value.storage or {}),
            "forms": list(value.forms or []),
            "hidden_inputs": list(value.hidden_inputs or []),
            "errors": list(value.errors or []),
            "screenshot": value.screenshot,
        }
    payload = dict(value)
    payload.setdefault("url", target)
    payload.setdefault("status", "ok")
    payload.setdefault("console", [])
    payload.setdefault("network", [])
    payload.setdefault("storage", {})
    payload.setdefault("forms", [])
    payload.setdefault("hidden_inputs", [])
    payload.setdefault("errors", [])
    return payload


def _storage_findings(*, target: str, storage: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for storage_name in ("localStorage", "sessionStorage"):
        entries = storage.get(storage_name)
        if not isinstance(entries, dict):
            continue
        exposed_keys = []
        for key, value in entries.items():
            candidate = f"{key} {value}".lower()
            if any(marker in candidate for marker in SENSITIVE_STORAGE_PATTERNS):
                exposed_keys.append(str(key))
        if exposed_keys:
            findings.append(
                {
                    "title": "Browser storage exposes sensitive token-like state",
                    "severity": "medium",
                    "target": target,
                    "summary": (
                        f"{storage_name} contains token-like keys visible to browser-side JavaScript: "
                        f"{', '.join(sorted(set(exposed_keys)))}."
                    ),
                    "methodology_tags": ["OWASP-WSTG-CLNT", "client-side-state"],
                }
            )
    return findings


def _csrf_findings(*, target: str, forms: list[Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for form in forms:
        if not isinstance(form, dict):
            continue
        method = str(form.get("method") or "").strip().lower()
        if method in SAFE_METHODS:
            continue
        names = [str(name).strip().lower() for name in list(form.get("inputNames") or [])]
        has_signal = any("csrf" in name or "xsrf" in name or "requestverification" in name for name in names)
        if has_signal:
            continue
        findings.append(
            {
                "title": "State-changing browser form lacks visible anti-CSRF signal",
                "severity": "medium",
                "target": str(form.get("action") or target).strip() or target,
                "summary": (
                    "A state-changing form was observed without a visible CSRF/request-origin token. "
                    "AegisPT inspected the DOM only and did not submit the form."
                ),
                "methodology_tags": ["OWASP-WSTG-SESS", "csrf-review"],
            }
        )
    return findings


def _proof_marker_findings(*, target: str, dom: str, proof_marker: str | None) -> list[dict[str, Any]]:
    marker = str(proof_marker or "").strip()
    if not marker or marker not in dom:
        return []
    return [
        {
            "title": "Reflected browser proof marker observed",
            "severity": "info",
            "target": target,
            "summary": (
                "A harmless AegisPT proof marker was reflected in the rendered DOM. "
                "This proves browser-executed workflow reachability without using an exploit payload."
            ),
            "methodology_tags": ["OWASP-WSTG-CLNT", "proof-of-execution"],
        }
    ]


def _derive_findings(
    *,
    target: str,
    observation: dict[str, Any],
    mode: str,
    proof_marker: str | None,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    findings.extend(
        _proof_marker_findings(
            target=target,
            dom=str(observation.get("dom") or ""),
            proof_marker=proof_marker,
        )
    )
    storage = observation.get("storage")
    if isinstance(storage, dict):
        findings.extend(_storage_findings(target=target, storage=storage))
    if mode == "active":
        forms = observation.get("forms")
        if isinstance(forms, list):
            findings.extend(_csrf_findings(target=target, forms=forms))
    return findings


def execute_playwright_web_validation(
    targets: list[str],
    *,
    auth_contexts: list[dict[str, Any]] | None = None,
    scope_allowlist: dict[str, Any] | list[str] | None = None,
    mode: str = "passive",
    requires_auth_context: bool = False,
    proof_marker: str | None = None,
    timeout_seconds: float = 10.0,
    collector: BrowserCollector | None = None,
) -> RunnerExecution:
    normalized_targets = [normalize_http_target(target) for target in targets if str(target).strip()]
    if not normalized_targets:
        raise ValueError("playwright-web requires at least one target")

    for target in normalized_targets:
        if not _target_is_in_scope(target, scope_allowlist):
            raise ValueError(f"playwright-web target outside scope: {target}")

    materialized_auth_contexts = [dict(item) for item in list(auth_contexts or []) if isinstance(item, dict)]
    normalized_mode = "active" if str(mode).strip().lower() == "active" else "passive"

    if requires_auth_context and not materialized_auth_contexts:
        payload = {
            "status": "skipped",
            "reason": "missing_auth_context",
            "targets": [
                {
                    "url": target,
                    "status": "skipped",
                    "findings": [],
                    "evidence": [],
                }
                for target in normalized_targets
            ],
            "safety": {
                "destructive_actions": False,
                "forms_submitted": False,
                "autonomous_chaining": False,
            },
        }
        return RunnerExecution(
            tool="playwright-web",
            exit_code=0,
            stdout="playwright-web skipped: stored auth/session context is required but missing",
            stderr="",
            metadata={
                "status": "skipped",
                "reason": "missing_auth_context",
                "runner_digest": RUNNER_DIGEST,
                "tool_version": "playwright",
                "finding_count": 0,
                "auth_context_count": 0,
            },
            artifacts=[
                EvidenceArtifact(
                    name=PLAYWRIGHT_WEB_RESULTS_ARTIFACT_NAME,
                    content_type="application/json",
                    data=json.dumps(payload, indent=2, sort_keys=True).encode("utf-8"),
                    kind="browser-validation-results",
                )
            ],
        )

    collect = collector or _default_collect_with_playwright
    target_results: list[dict[str, Any]] = []
    network_rows: list[dict[str, Any]] = []
    console_rows: list[dict[str, Any]] = []
    first_dom = ""
    first_screenshot: bytes | None = None
    finding_count = 0
    failed_targets = 0

    for target in normalized_targets:
        observation = _normalize_observation(
            collect(
                target=target,
                auth_contexts=materialized_auth_contexts,
                proof_marker=proof_marker,
                timeout_seconds=timeout_seconds,
            ),
            target=target,
        )
        screenshot = observation.pop("screenshot", None)
        dom = str(observation.get("dom") or "")
        if not first_dom and dom:
            first_dom = dom
        if first_screenshot is None and isinstance(screenshot, bytes):
            first_screenshot = screenshot

        safe_network = []
        for event in list(observation.get("network") or []):
            if not isinstance(event, dict):
                continue
            safe_event = {
                **event,
                "headers": _safe_headers(event.get("headers") if isinstance(event.get("headers"), dict) else {}),
            }
            safe_network.append(safe_event)
            network_rows.append({"target": target, **safe_event})

        safe_console = []
        for event in list(observation.get("console") or []):
            if not isinstance(event, dict):
                continue
            safe_event = {**event, "text": _redact(event.get("text"))}
            safe_console.append(safe_event)
            console_rows.append({"target": target, **safe_event})

        observation["network"] = safe_network
        observation["console"] = safe_console
        observation["auth_contexts_applied"] = len(materialized_auth_contexts)
        observation["findings"] = _derive_findings(
            target=target,
            observation=observation,
            mode=normalized_mode,
            proof_marker=proof_marker,
        )
        finding_count += len(observation["findings"])
        if observation.get("status") == "failed":
            failed_targets += 1

        target_results.append(observation)

    status = "failed" if failed_targets == len(target_results) else "completed"
    payload = {
        "status": status,
        "mode": normalized_mode,
        "targets": target_results,
        "auth_context_count": len(materialized_auth_contexts),
        "finding_count": finding_count,
        "safety": {
            "destructive_actions": False,
            "forms_submitted": False,
            "autonomous_chaining": False,
            "proof_marker_only": bool(proof_marker),
        },
    }
    artifacts = [
        EvidenceArtifact(
            name=PLAYWRIGHT_WEB_RESULTS_ARTIFACT_NAME,
            content_type="application/json",
            data=json.dumps(payload, indent=2, sort_keys=True).encode("utf-8"),
            kind="browser-validation-results",
        ),
        EvidenceArtifact(
            name=PLAYWRIGHT_WEB_NETWORK_ARTIFACT_NAME,
            content_type="application/x-ndjson",
            data="\n".join(json.dumps(row, sort_keys=True) for row in network_rows).encode("utf-8"),
            kind="browser-network-log",
        ),
        EvidenceArtifact(
            name=PLAYWRIGHT_WEB_CONSOLE_ARTIFACT_NAME,
            content_type="application/x-ndjson",
            data="\n".join(json.dumps(row, sort_keys=True) for row in console_rows).encode("utf-8"),
            kind="browser-console-log",
        ),
    ]
    if first_dom:
        artifacts.append(
            EvidenceArtifact(
                name=PLAYWRIGHT_WEB_DOM_ARTIFACT_NAME,
                content_type="text/html",
                data=first_dom.encode("utf-8", errors="replace"),
                kind="browser-dom-snapshot",
            )
        )
    if first_screenshot is not None:
        artifacts.append(
            EvidenceArtifact(
                name=PLAYWRIGHT_WEB_SCREENSHOT_ARTIFACT_NAME,
                content_type="image/png",
                data=first_screenshot,
                kind="browser-screenshot",
            )
        )

    return RunnerExecution(
        tool="playwright-web",
        exit_code=0 if status != "failed" else 1,
        stdout=f"playwright-web {normalized_mode} validation completed for {len(target_results)} target(s); {finding_count} finding(s)",
        stderr="",
        metadata={
            "status": status,
            "mode": normalized_mode,
            "runner_digest": RUNNER_DIGEST,
            "tool_version": "playwright",
            "finding_count": finding_count,
            "auth_context_count": len(materialized_auth_contexts),
            "destructive_actions": False,
            "forms_submitted": False,
        },
        artifacts=artifacts,
    )
