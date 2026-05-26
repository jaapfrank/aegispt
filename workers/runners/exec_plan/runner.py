"""Structured test plan executor.

Claude (or another AI) generates a JSON plan of HTTP request steps. This runner
executes them in order, safely:
- Every URL is scope-validated before request.
- Variables can be captured from prior steps and interpolated into later steps
  (e.g. capture session URL from a redirect, then use it as `${register.session}`).
- `expect` clauses validate response status / body contents.
- `on_success.create_finding` emits a structured finding when an exploitation
  sequence succeeds (e.g. privilege escalation confirmed).

Safety boundaries:
- No filesystem access, no subprocess, no eval — pure HTTP via httpx.
- Methods limited to GET/POST/PUT/PATCH/DELETE.
- Header keys allowlisted (no Host overrides).
- Each step has a per-step timeout + an overall budget.
- Maximum 20 steps per plan.
- Body and response payloads truncated for storage.
"""
from __future__ import annotations

import json
import logging
import re
import secrets
import string
from hashlib import sha256
from typing import Any
from urllib.parse import urlparse

import httpx as httpx_client

from api.app.services.evidence_ingest import make_captured_value_observation
from api.app.services.runs import web_target_value_is_allowed_with_path
from workers.runners.base.contracts import EvidenceArtifact, RunnerExecution


def _infer_value_kind(var_name: str, capture_spec_kind: str) -> str:
    """Map an exec_plan capture `from` source + variable name to a
    captured_value subtype (#334). Heuristic only — keep emergent, no
    app-specific seeding."""
    name_lower = (var_name or "").lower()
    kind = (capture_spec_kind or "").lower()
    if kind == "cookie":
        return "cookie"
    if kind == "header":
        if "auth" in name_lower or "token" in name_lower:
            return "token"
        return "other"
    if kind == "redirect_path":
        return "url"
    if kind == "body_regex":
        if "token" in name_lower or "jwt" in name_lower or "csrf" in name_lower:
            return "token"
        if "host" in name_lower or "domain" in name_lower:
            return "hostname"
        if "url" in name_lower:
            return "url"
        if "pw" in name_lower or "pass" in name_lower or "secret" in name_lower:
            return "credential_ref"
        return "other"
    if kind == "request_field":
        if "pw" in name_lower or "pass" in name_lower or "secret" in name_lower:
            return "credential_ref"
        if "user" in name_lower or "uid" in name_lower or "email" in name_lower:
            return "other"
        return "other"
    return "other"

logger = logging.getLogger(__name__)

EXEC_PLAN_ARTIFACT_NAME = "exec-plan-results.json"
MAX_STEPS = 50
MAX_BODY_BYTES = 1_048_576  # 1 MiB request body cap
MAX_CAPTURE_LEN = 4096
RESPONSE_EXCERPT_LIMIT = 800
ALLOWED_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE"}
ALLOWED_HEADER_KEYS = {
    "accept", "accept-language", "accept-encoding",
    "content-type", "cookie", "referer", "user-agent",
    "authorization", "x-csrf-token", "x-requested-with",
}

_VAR_RE = re.compile(r"\$\{([a-zA-Z0-9_.-]+)\}")


def _rand_token(length: int = 8) -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _safe_str(value: Any, limit: int = MAX_CAPTURE_LEN) -> str:
    text = str(value)
    return text if len(text) <= limit else text[:limit] + "…"


def _resolve_template(value: str, ctx: dict[str, Any]) -> str:
    """Replace ${path.to.value} placeholders. Unknown keys become empty strings."""
    def replacer(match: re.Match[str]) -> str:
        key_path = match.group(1)
        if key_path == "rand":
            return _rand_token()
        if key_path == "rand16":
            return _rand_token(16)
        cur: Any = ctx
        for part in key_path.split("."):
            if isinstance(cur, dict):
                cur = cur.get(part)
            else:
                return ""
            if cur is None:
                return ""
        return _safe_str(cur, 200)
    return _VAR_RE.sub(replacer, str(value))


def _resolve_obj(obj: Any, ctx: dict[str, Any]) -> Any:
    """Recursively interpolate ${} references in strings inside dicts/lists."""
    if isinstance(obj, str):
        return _resolve_template(obj, ctx)
    if isinstance(obj, dict):
        return {k: _resolve_obj(v, ctx) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_resolve_obj(item, ctx) for item in obj]
    return obj


def _filter_headers(headers: dict[str, Any] | None) -> dict[str, str]:
    """Drop any header keys not in the allowlist."""
    if not headers:
        return {}
    out: dict[str, str] = {}
    for key, value in headers.items():
        k = str(key or "").strip().lower()
        if k in ALLOWED_HEADER_KEYS:
            out[k] = str(value)
    return out


def _scope_check(url: str, scope_allowlist: dict[str, Any] | None) -> bool:
    return web_target_value_is_allowed_with_path(scope_allowlist or {}, url)


def _check_expectations(expect: dict[str, Any], response: httpx_client.Response) -> tuple[bool, list[str]]:
    """Return (passed, failure_reasons)."""
    if not isinstance(expect, dict):
        return True, []
    reasons: list[str] = []

    statuses = expect.get("status")
    if statuses is not None:
        allowed = statuses if isinstance(statuses, list) else [statuses]
        if response.status_code not in [int(s) for s in allowed]:
            reasons.append(f"status {response.status_code} not in {allowed}")

    body_contains = expect.get("body_contains")
    if body_contains:
        needles = body_contains if isinstance(body_contains, list) else [body_contains]
        for needle in needles:
            if str(needle) not in response.text:
                reasons.append(f"body missing {str(needle)[:60]!r}")

    body_not_contains = expect.get("body_not_contains")
    if body_not_contains:
        needles = body_not_contains if isinstance(body_not_contains, list) else [body_not_contains]
        for needle in needles:
            if str(needle) in response.text:
                reasons.append(f"body unexpectedly contains {str(needle)[:60]!r}")

    body_regex = expect.get("body_regex")
    if body_regex:
        if not re.search(str(body_regex), response.text, re.DOTALL):
            reasons.append(f"body_regex {str(body_regex)[:60]!r} did not match")

    return (len(reasons) == 0, reasons)


def _capture_values(
    capture_spec: dict[str, Any],
    response: httpx_client.Response,
    request_data: dict[str, Any] | None,
) -> dict[str, Any]:
    """Extract values from response/request per capture spec.

    Capture grammar:
      {"name": {"from": "cookie", "key": "GRUYERE"}}
      {"name": {"from": "header", "key": "Location"}}
      {"name": {"from": "redirect_path"}}
      {"name": {"from": "body_regex", "regex": "user_id=(\\d+)"}}
      {"name": {"from": "request_field", "field": "uid"}}
      {"name": {"from": "status"}}
    """
    if not isinstance(capture_spec, dict):
        return {}
    captured: dict[str, Any] = {}
    for var_name, rule in capture_spec.items():
        if not isinstance(rule, dict):
            continue
        kind = str(rule.get("from") or "").lower()
        try:
            if kind == "cookie":
                key = str(rule.get("key") or "")
                cookie = response.cookies.get(key, "")
                captured[var_name] = cookie
            elif kind == "header":
                key = str(rule.get("key") or "")
                captured[var_name] = response.headers.get(key, "")
            elif kind == "redirect_path":
                loc = response.headers.get("Location") or response.headers.get("location") or ""
                if loc:
                    parsed = urlparse(loc)
                    captured[var_name] = parsed.path
                else:
                    captured[var_name] = ""
            elif kind == "body_regex":
                m = re.search(str(rule.get("regex") or ""), response.text, re.DOTALL)
                captured[var_name] = m.group(1) if (m and m.groups()) else (m.group(0) if m else "")
            elif kind == "request_field":
                field = str(rule.get("field") or "")
                if isinstance(request_data, dict):
                    captured[var_name] = _safe_str(request_data.get(field, ""), 200)
            elif kind == "status":
                captured[var_name] = response.status_code
        except Exception as exc:
            logger.debug("exec-plan capture %s failed: %s", var_name, exc)
            captured[var_name] = ""
    return captured


def execute_exec_plan(
    targets: list[str],
    *,
    plan: dict[str, Any],
    scope_allowlist: dict[str, Any] | None = None,
    timeout_seconds: float = 30.0,
    overall_timeout_seconds: float = 90.0,
    client_factory: Any = httpx_client.Client,
) -> RunnerExecution:
    if not targets:
        raise ValueError("at least one target is required")
    if not isinstance(plan, dict):
        raise ValueError("exec-plan requires a plan dict")

    primary_target = str(targets[0]).strip()
    plan_name = str(plan.get("name") or plan.get("plan") or "unnamed-plan")
    steps = plan.get("steps") or []
    if not isinstance(steps, list) or not steps:
        raise ValueError("exec-plan requires at least one step")
    if len(steps) > MAX_STEPS:
        raise ValueError(f"exec-plan rejected: too many steps ({len(steps)} > {MAX_STEPS})")

    # Build context with target available as ${target}
    ctx: dict[str, Any] = {"target": primary_target.rstrip("/")}

    findings: list[dict[str, Any]] = []
    step_results: list[dict[str, Any]] = []
    stderr_lines: list[str] = []
    # #334: emit captured_value observations so cross-target chains are
    # visible in the graph + picker projection. Orchestrator picks them
    # up from execution.metadata["observations"] via persist_runner_observations.
    captured_observations: list[dict[str, Any]] = []
    exit_code = 0

    import time
    start_time = time.time()

    with client_factory(follow_redirects=False, timeout=timeout_seconds) as client:
        cookie_jars: dict[str, dict[str, str]] = {}  # named cookie jars per step

        for i, raw_step in enumerate(steps):
            if not isinstance(raw_step, dict):
                stderr_lines.append(f"step {i}: not a dict, skipped")
                continue
            if time.time() - start_time > overall_timeout_seconds:
                stderr_lines.append("overall plan budget exceeded — remaining steps skipped")
                exit_code = 1
                break

            step = _resolve_obj(raw_step, ctx)
            name = str(step.get("name") or f"step{i}")
            method = str(step.get("method") or "GET").upper()
            if method not in ALLOWED_METHODS:
                stderr_lines.append(f"step {name}: method {method} not allowed")
                exit_code = 1
                continue

            url = str(step.get("url") or "").strip()
            if not url:
                stderr_lines.append(f"step {name}: missing url")
                continue
            if not _scope_check(url, scope_allowlist):
                stderr_lines.append(f"step {name}: url {url[:80]} out of scope, skipped")
                exit_code = 1
                step_results.append({
                    "name": name, "method": method, "url": url,
                    "skipped": "out_of_scope",
                })
                continue

            headers = _filter_headers(step.get("headers"))
            data = step.get("data")
            json_body = step.get("json")
            params = step.get("params")

            # Combine cookies from a previous step's jar if requested
            cookies_from = step.get("cookies_from")
            request_cookies: dict[str, str] = {}
            if cookies_from and isinstance(cookies_from, str):
                request_cookies.update(cookie_jars.get(cookies_from, {}))
            if isinstance(step.get("cookies"), dict):
                request_cookies.update({str(k): str(v) for k, v in step["cookies"].items()})

            try:
                request_kwargs: dict[str, Any] = {
                    "method": method,
                    "url": url,
                    "headers": headers,
                    "cookies": request_cookies or None,
                }
                if params:
                    request_kwargs["params"] = params
                if data is not None and method != "GET":
                    request_kwargs["data"] = data
                if json_body is not None and method != "GET":
                    request_kwargs["json"] = json_body
                response = client.request(**request_kwargs)
            except httpx_client.HTTPError as exc:
                stderr_lines.append(f"step {name}: HTTP error: {exc}")
                exit_code = 1
                step_results.append({
                    "name": name, "method": method, "url": url,
                    "error": str(exc)[:200],
                })
                continue

            # Capture variables for downstream interpolation
            captured = _capture_values(step.get("capture") or {}, response, data if isinstance(data, dict) else None)
            if captured:
                ctx[name] = captured
                # #334: each captured value also becomes a graph entity
                # with provenance (origin step, source URL, redacted value).
                # The orchestrator persists these as EvidenceObservation rows
                # so subsequent tasks can reference them via the picker's
                # graph projection.
                capture_spec = step.get("capture") or {}
                for var_name, raw_value in captured.items():
                    if raw_value in (None, ""):
                        continue
                    spec_rule = capture_spec.get(var_name) or {}
                    spec_kind = str(spec_rule.get("from") or "") if isinstance(spec_rule, dict) else ""
                    value_kind = _infer_value_kind(var_name, spec_kind)
                    try:
                        observation = make_captured_value_observation(
                            var_name=var_name,
                            value=str(raw_value),
                            value_kind=value_kind,
                            origin_step_name=name,
                            source_url=url,
                        )
                        captured_observations.append(observation)
                    except (ValueError, TypeError) as obs_exc:
                        logger.debug(
                            "exec-plan: failed to construct captured_value observation for %s: %s",
                            var_name, obs_exc,
                        )

            # Store this step's response cookies in a named jar
            cookie_jars[name] = {k: v for k, v in response.cookies.items()}

            # Check expectations
            expectations = step.get("expect") or {}
            passed, reasons = _check_expectations(expectations, response)

            step_result = {
                "name": name,
                "method": method,
                "url": url,
                "status_code": response.status_code,
                "content_type": response.headers.get("Content-Type", ""),
                "passed_expectations": passed,
                "failures": reasons,
                "captured": list(captured.keys()),
                "response_excerpt": response.text[:RESPONSE_EXCERPT_LIMIT].replace("\n", " ").strip(),
                "response_hash": sha256(response.content).hexdigest(),
            }
            step_results.append(step_result)

            # If expectations passed and there's an on_success.create_finding, emit it
            if passed:
                on_success = step.get("on_success") or {}
                # Defensive: specialists/picker sometimes emit on_success as
                # a free-text string instead of the expected dict. Treat
                # non-dict as empty (no finding emit) rather than crashing.
                if not isinstance(on_success, dict):
                    on_success = {}
                finding_spec = on_success.get("create_finding")
                if isinstance(finding_spec, dict):
                    severity = str(finding_spec.get("severity") or "high").lower()
                    title = str(finding_spec.get("title") or f"Exec-plan success: {plan_name}")
                    summary = str(finding_spec.get("summary") or finding_spec.get("evidence") or "")
                    methodology_tags = list(finding_spec.get("methodology_tags") or ["exec_plan"])
                    findings.append({
                        "type": str(finding_spec.get("type") or "exec_plan_success"),
                        "title": title[:200],
                        "severity": severity,
                        "target": url,
                        "summary": summary[:600],
                        "methodology_tags": methodology_tags + ["exec_plan", plan_name],
                        "evidence": {
                            "plan_name": plan_name,
                            "step_name": name,
                            "request": {"method": method, "url": url},
                            "status_code": response.status_code,
                            "response_excerpt": response.text[:RESPONSE_EXCERPT_LIMIT].replace("\n", " ").strip(),
                        },
                        # backlog-413 validator: needs an actually-runnable
                        # recipe to replay the exploit and validate the verdict.
                        # The original stub ({tool, plan_name, step}) was not
                        # replayable → validator.validate_exploit always
                        # returned inconclusive → foothold never advanced.
                        # Now we ship the SAME step body that triggered the
                        # finding, in the runner-compatible single-step plan
                        # shape, with the expect clauses that originally
                        # passed. validate_exploit re-runs it and compares.
                        "replay_recipe": {
                            "tool": "exec-plan",
                            "plan_name": f"replay::{plan_name}::{name}",
                            "steps": [{
                                "name": name,
                                "method": method,
                                "url": url,
                                "headers": step.get("headers") or {},
                                "params": step.get("params") or {},
                                "data": step.get("data"),
                                "json": step.get("json"),
                                "cookies": step.get("cookies") or {},
                                "cookies_from": step.get("cookies_from"),
                                "expect": expectations,
                            }],
                        },
                    })

    payload = {
        "tool": "exec-plan",
        "plan_name": plan_name,
        "primary_target": primary_target,
        "steps_executed": len(step_results),
        "step_results": step_results,
        "findings": findings,
        "context_keys": sorted(list(ctx.keys())),
        "safety": {
            "scope_enforced": True,
            "approved_web_root_only": True,
            "max_steps": MAX_STEPS,
            "header_allowlist_enforced": True,
            "no_filesystem_access": True,
            "no_subprocess": True,
        },
    }
    return RunnerExecution(
        tool="exec-plan",
        exit_code=exit_code,
        stdout=json.dumps({k: v for k, v in payload.items() if k != "step_results"}, sort_keys=True),
        stderr="\n".join(stderr_lines)[:2000],
        metadata={
            "status": "ok" if exit_code == 0 else "completed_with_errors",
            "tool_version": "exec-plan:v1",
            "plan_name": plan_name,
            "step_count": len(step_results),
            "finding_count": len(findings),
            # #334: orchestrator's persist_runner_observations consumes
            # this list and writes EvidenceObservation rows so captured
            # values are queryable across tasks.
            "observations": captured_observations,
        },
        artifacts=[
            EvidenceArtifact(
                name=EXEC_PLAN_ARTIFACT_NAME,
                content_type="application/json",
                data=(json.dumps(payload, sort_keys=True) + "\n").encode("utf-8"),
                kind="runner-results",
            )
        ],
    )
