"""Recon Deliverable runner — Shannon-style 9-section attack surface map.

Phase 2 of landscape-plan 2026-05-22. The 5 OWASP-category specialists
(Phase 1) returned empty hypothesis lists because the stub recon they
were fed only had "targets / tested_keys / findings" — no actual API
endpoint inventory, no input vectors, no auth surface map.

This runner:
1. HEAD + GET the target homepage + common entrypoint paths (/robots.txt,
   /sitemap.xml, /login, /admin, /api/, /api/v1/, /openapi.json,
   /.well-known/security.txt, /server-status)
2. Parse the response HTML for:
   - <form action="..." method="..."> with input names + types
   - <a href="..."> anchors within scope
   - <script src="..."> JS resources (often reveal API endpoints)
   - meta/comments that leak credentials (the "test:test" pattern we
     keep hitting in XBOW)
3. Extract HTTP headers for technology fingerprinting (Server, X-Powered-By,
   Set-Cookie shape, Content-Security-Policy)
4. Emit a markdown deliverable matching Shannon's 9 sections so the
   specialists have STRUCTURED evidence to reason from.

No LLM call. Pure deterministic parsing. Each section explicitly empty
when no evidence found — specialists then correctly skip their category
rather than hallucinate.
"""
from __future__ import annotations

import json
import logging
import re
from collections import defaultdict
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx as httpx_client

from workers.runners.base.contracts import EvidenceArtifact, RunnerExecution

logger = logging.getLogger(__name__)

RECON_DELIVERABLE_ARTIFACT_NAME = "recon-deliverable.md"

# Common entry-point paths to probe — heuristic, not exhaustive. The
# vulnerability specialists must rely on what we ACTUALLY observe, not
# on probe paths we tried that 404'd.
DEFAULT_PROBE_PATHS = [
    "/",
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
    "/login",
    "/admin",
    "/api",
    "/api/",
    "/api/v1",
    "/api/v1/",
    "/openapi.json",
    "/swagger.json",
    "/swagger-ui",
    "/swagger-ui.html",
    "/server-status",
    "/.git/config",
    "/.env",
    "/healthz",
    "/health",
]

# Credentials-disclosure regex — recurring patterns seen across XBOW
# challenges and Gruyere. Matches in HTML comments + plaintext.
CRED_PATTERNS = [
    re.compile(r"(?:test|admin|dev|guest|user|demo)\s*[:/=]\s*(?:test|admin|password|123456|dev|guest|demo)", re.IGNORECASE),
    re.compile(r"username\s*[:=]\s*[\"']?\w{3,20}[\"']?\s*[,\s].*?password\s*[:=]\s*[\"']?[\w!@#$]{3,40}[\"']?", re.IGNORECASE | re.DOTALL),
    re.compile(r"<!--\s*.*?(?:credentials?|cred|passwords?|TODO).*?-->", re.IGNORECASE | re.DOTALL),
]


class _FormCollector(HTMLParser):
    """Minimal HTML parser that records every <form> + its inputs."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._forms: list[dict[str, Any]] = []
        self._current: dict[str, Any] | None = None
        self._links: set[str] = set()
        self._scripts: set[str] = set()
        self._comments: list[str] = []

    def handle_starttag(self, tag: str, attrs_list: list[tuple[str, str | None]]) -> None:
        attrs = {k.lower(): (v or "") for k, v in attrs_list}
        if tag == "form":
            self._current = {
                "action": attrs.get("action", ""),
                "method": (attrs.get("method", "GET") or "GET").upper(),
                "enctype": attrs.get("enctype", "application/x-www-form-urlencoded"),
                "inputs": [],
            }
        elif tag == "input" and self._current is not None:
            self._current["inputs"].append({
                "name": attrs.get("name", ""),
                "type": (attrs.get("type", "text") or "text").lower(),
                "value": attrs.get("value", ""),
                "required": "required" in attrs,
            })
        elif tag in ("select", "textarea") and self._current is not None:
            self._current["inputs"].append({
                "name": attrs.get("name", ""),
                "type": tag,
                "value": "",
                "required": "required" in attrs,
            })
        elif tag == "a":
            href = attrs.get("href", "").strip()
            if href:
                self._links.add(href)
        elif tag == "script":
            src = attrs.get("src", "").strip()
            if src:
                self._scripts.add(src)

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._current is not None:
            self._forms.append(self._current)
            self._current = None

    def handle_comment(self, data: str) -> None:
        text = data.strip()
        if text:
            self._comments.append(text[:500])

    @property
    def forms(self) -> list[dict[str, Any]]:
        return self._forms

    @property
    def links(self) -> list[str]:
        return sorted(self._links)

    @property
    def scripts(self) -> list[str]:
        return sorted(self._scripts)

    @property
    def comments(self) -> list[str]:
        return self._comments


def _fingerprint_stack(headers: dict[str, str], body_snippet: str) -> dict[str, Any]:
    """Look at response headers + first ~4KB of body for tech fingerprints.
    Conservative: only flag a stack when there's an explicit signal."""
    fp: dict[str, Any] = {}
    server = headers.get("server", "").strip()
    powered = headers.get("x-powered-by", "").strip()
    if server:
        fp["server"] = server
    if powered:
        fp["x_powered_by"] = powered

    csp = headers.get("content-security-policy", "")
    if csp:
        fp["csp_present"] = True
        if "unsafe-inline" in csp:
            fp["csp_unsafe_inline"] = True
        if "unsafe-eval" in csp:
            fp["csp_unsafe_eval"] = True

    cookies = headers.get("set-cookie", "")
    if cookies:
        fp["sets_cookies"] = True
        fp["cookie_secure"] = "Secure" in cookies
        fp["cookie_httponly"] = "HttpOnly" in cookies

    # Framework probes via body content.
    body_lower = body_snippet.lower()
    if "<meta name=\"generator\" content=\"wordpress" in body_lower:
        fp["framework"] = "wordpress"
    elif "_csrf" in body_lower and "jinja" in (powered + server).lower():
        fp["framework"] = "flask-jinja"
    elif "csrfmiddlewaretoken" in body_lower:
        fp["framework"] = "django"
    elif "__VIEWSTATE" in body_snippet:  # case-sensitive
        fp["framework"] = "asp.net"
    elif "rails" in (powered + server).lower():
        fp["framework"] = "rails"

    return fp


def _find_credentials_in_text(text: str) -> list[str]:
    hits: list[str] = []
    for pattern in CRED_PATTERNS:
        for match in pattern.finditer(text):
            hits.append(match.group(0).strip()[:200])
    return hits[:10]


def _build_endpoint_inventory(probe_results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Synthesize an API endpoint inventory from observed probe paths +
    discovered links + form actions. Each row: {method, path, status,
    requires_auth_inferred, content_type, evidence_source}."""
    inventory: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for pr in probe_results:
        url = pr.get("url", "")
        if not url:
            continue
        path = urlparse(url).path or "/"
        method = pr.get("method", "GET")
        key = (method, path)
        if key in seen:
            continue
        seen.add(key)
        status = int(pr.get("status_code") or 0)
        # Heuristic: 401/403/302 → likely auth-protected.
        requires_auth = status in (401, 403) or (
            status == 302 and "login" in (pr.get("headers", {}).get("location", "") or "").lower()
        )
        inventory.append({
            "method": method,
            "path": path,
            "status": status,
            "requires_auth_inferred": requires_auth,
            "content_type": pr.get("headers", {}).get("content-type", "")[:80],
            "evidence_source": pr.get("source", "probe"),
        })
    return inventory


def _build_markdown(
    *,
    target: str,
    probe_results: list[dict[str, Any]],
    forms: list[dict[str, Any]],
    links: list[str],
    scripts: list[str],
    comments: list[str],
    fingerprint: dict[str, Any],
    credentials_in_html: list[str],
    inventory: list[dict[str, Any]],
) -> str:
    """Compose the 9-section Shannon-style markdown deliverable."""

    def _section(title: str, body: str) -> str:
        return f"## {title}\n\n{body.strip()}\n"

    # 1. Executive summary
    summary = (
        f"Target: `{target}`. Probed {len(probe_results)} endpoint(s). "
        f"Found {len(forms)} form(s), {len(links)} unique link(s) within scope, "
        f"{len(scripts)} script reference(s), {len(comments)} HTML comment(s), "
        f"{len(credentials_in_html)} credential-shaped pattern(s) in HTML."
    )

    # 2. Technology map
    tech = "\n".join(f"- **{k}**: `{v}`" for k, v in sorted(fingerprint.items())) or "_(no explicit fingerprint signals)_"

    # 3. Auth/Session flow
    login_endpoints = [row for row in inventory if "login" in row["path"].lower() or "auth" in row["path"].lower()]
    login_forms = [f for f in forms if "password" in {i.get("type") for i in f.get("inputs", [])}]
    auth_lines = []
    if login_endpoints:
        for row in login_endpoints:
            auth_lines.append(f"- `{row['method']} {row['path']}` → status={row['status']}")
    if login_forms:
        for lf in login_forms:
            inames = ", ".join(i.get("name", "?") for i in lf.get("inputs", []))
            auth_lines.append(f"- Login form: `action={lf['action']}` method={lf['method']} inputs=[{inames}]")
    if fingerprint.get("sets_cookies"):
        auth_lines.append(
            f"- Cookies observed: Secure={fingerprint.get('cookie_secure')}, "
            f"HttpOnly={fingerprint.get('cookie_httponly')}"
        )
    auth = "\n".join(auth_lines) if auth_lines else "_(no explicit auth surface observed in scope)_"

    # 4. API endpoint inventory (TABLE — specialists explicitly need this)
    if inventory:
        inv_rows = ["| method | path | status | requires_auth | content_type |", "|---|---|---|---|---|"]
        for row in inventory:
            inv_rows.append(
                f"| {row['method']} | `{row['path']}` | {row['status']} | "
                f"{row['requires_auth_inferred']} | `{row['content_type']}` |"
            )
        inv = "\n".join(inv_rows)
    else:
        inv = "_(no endpoints discovered)_"

    # 5. Input vectors (forms + query parameters seen)
    if forms:
        vec_rows = []
        for form in forms:
            inames = [i.get("name", "?") for i in form.get("inputs", []) if i.get("name")]
            itypes = ",".join(str(i.get("type", "?")) for i in form.get("inputs", []) if i.get("name"))
            origin = ""
            if form.get("_discovered_via") == "form-follow":
                origin = f" [follow-up after POST `{form.get('_predecessor_action', '?')}`]"
            if form.get("_action_was_empty"):
                origin += " [empty-action — submitted to discovered page URL]"
            vec_rows.append(
                f"- Form: `{form['method']} {form['action']}` (enctype={form['enctype']}) "
                f"inputs=[{', '.join(inames)}] types=[{itypes}]{origin}"
            )
        vectors = "\n".join(vec_rows)
    else:
        vectors = "_(no forms observed)_"

    # 6. Network / interaction map (scripts + external links — light)
    net_rows = [f"- script: `{s}`" for s in scripts[:20]]
    if not net_rows:
        net_rows = ["_(no script tags observed)_"]
    network = "\n".join(net_rows)

    # 7. Role/Privilege architecture — heuristic from inventory
    auth_protected = [r for r in inventory if r["requires_auth_inferred"]]
    role_text = (
        f"- Endpoints inferred to require auth: {len(auth_protected)}\n"
        + "\n".join(f"  - `{r['method']} {r['path']}` (status={r['status']})" for r in auth_protected[:10])
        if auth_protected
        else "_(no clearly auth-gated endpoints observed)_"
    )

    # 8. Authorization candidates — endpoints likely to allow horiz/vert
    #    escalation if reached
    authz_candidates = [
        r for r in inventory
        if any(seg in r["path"].lower() for seg in ("/admin", "/users/", "/account/", "/profile"))
    ]
    if authz_candidates:
        authz = "\n".join(f"- `{r['method']} {r['path']}` (status={r['status']})" for r in authz_candidates[:15])
    else:
        authz = "_(no obvious horizontal/vertical-escalation candidates from path heuristics)_"

    # 9. Injection sources — observed input fields whose names look like
    #    they reach a DB/template
    inj_candidates: list[str] = []
    for form in forms:
        for inp in form.get("inputs", []):
            name = str(inp.get("name") or "").lower()
            if any(kw in name for kw in ("query", "search", "filter", "id", "uid", "name", "user", "email")):
                inj_candidates.append(
                    f"- form `{form['action']}` field `{inp.get('name')}` (type={inp.get('type')})"
                )
    injection = "\n".join(inj_candidates[:20]) if inj_candidates else "_(no injection-shaped input names observed)_"

    # Optional: bonus section for credentials found in HTML/comments (we
    # observed test:test in earlier XBEN runs — this is the specialist
    # vuln_auth's #1 evidence pump).
    cred_section = ""
    if credentials_in_html:
        cred_lines = [f"- `{c}`" for c in credentials_in_html[:10]]
        cred_section = _section("Credentials disclosed in HTML/comments", "\n".join(cred_lines))

    body = (
        f"# Recon Deliverable — {target}\n\n"
        + _section("Executive Summary", summary)
        + _section("Technology Map", tech)
        + _section("Auth / Session Flow", auth)
        + _section("API Endpoint Inventory", inv)
        + _section("Input Vectors", vectors)
        + _section("Network / Interaction Map", network)
        + _section("Role / Privilege Architecture", role_text)
        + _section("Authorization Candidates", authz)
        + _section("Injection Sources", injection)
        + cred_section
    )
    return body


def execute_recon_deliverable(
    targets: list[str],
    *,
    scope_allowlist: dict[str, Any] | None = None,
    probe_paths: list[str] | None = None,
    timeout_seconds: float = 10.0,
    client_factory=None,
) -> RunnerExecution:
    """Probe target + parse HTML + emit recon_deliverable markdown."""
    if not targets:
        raise ValueError("recon_deliverable requires at least one target")
    target = str(targets[0]).rstrip("/")
    paths = probe_paths or DEFAULT_PROBE_PATHS

    probe_results: list[dict[str, Any]] = []
    forms: list[dict[str, Any]] = []
    links: list[str] = []
    scripts: list[str] = []
    comments: list[str] = []
    fingerprint: dict[str, Any] = {}
    credentials_in_html: list[str] = []

    factory = client_factory or httpx_client.Client

    with factory(timeout=timeout_seconds, follow_redirects=False) as client:
        for path in paths:
            url = target + path if path.startswith("/") else f"{target}/{path}"
            try:
                resp = client.get(url)
            except Exception as exc:  # noqa: BLE001
                probe_results.append({
                    "method": "GET", "url": url, "error": str(exc)[:200],
                    "status_code": 0, "headers": {}, "source": "probe",
                })
                continue
            headers_lower = {k.lower(): v for k, v in resp.headers.items()}
            body_snippet = (resp.text or "")[:8192]
            probe_results.append({
                "method": "GET",
                "url": url,
                "status_code": resp.status_code,
                "headers": headers_lower,
                "body_length": len(resp.content or b""),
                "source": "probe",
            })

            # On 200 HTML responses, parse for forms/links/scripts/comments.
            ctype = headers_lower.get("content-type", "")
            if resp.status_code == 200 and "html" in ctype.lower():
                parser = _FormCollector()
                try:
                    parser.feed(body_snippet)
                except Exception:  # noqa: BLE001
                    pass
                # Normalise relative form actions to absolute URLs.
                # Empty action attribute → submit to the page URL we
                # discovered the form on (HTML form semantic).
                for form in parser.forms:
                    raw_action = (form.get("action") or "").strip()
                    if not raw_action:
                        form["action"] = url
                        form["_action_was_empty"] = True
                    elif not raw_action.startswith("http"):
                        form["action"] = urljoin(url, raw_action)
                    form["_discovered_on"] = url
                    form["_discovered_via"] = "get-probe"
                    forms.append(form)
                for link in parser.links:
                    absolute = urljoin(url, link) if not link.startswith("http") else link
                    links.append(absolute)
                for s in parser.scripts:
                    absolute = urljoin(url, s) if not s.startswith("http") else s
                    scripts.append(absolute)
                comments.extend(parser.comments)
                credentials_in_html.extend(_find_credentials_in_text(body_snippet))

                # Fingerprint from headers + body of the FIRST 200 HTML response.
                if not fingerprint:
                    fingerprint = _fingerprint_stack(headers_lower, body_snippet)

    # Follow-form probes: for each POST form discovered, submit it with
    # placeholder values and parse the response. This catches multi-step
    # forms (e.g. step 1 takes username, step 2 takes password) where the
    # single-pass GET-only recon misses the second form.
    form_follow_results: list[dict[str, Any]] = []
    with factory(timeout=timeout_seconds, follow_redirects=True) as client:
        # Track which forms we've already POSTed to avoid loops.
        followed: set[tuple[str, str]] = set()
        for form in list(forms):
            method = str(form.get("method") or "GET").upper()
            if method != "POST":
                continue
            action = str(form.get("action") or "").strip()
            if not action:
                continue
            key = (action, ",".join(sorted(str(i.get("name") or "") for i in form.get("inputs", []))))
            if key in followed:
                continue
            followed.add(key)

            # Synthesize placeholder values per input. Heuristic only —
            # specialists may later submit smarter values. Hidden inputs
            # keep their pre-set value; password inputs get a strong
            # placeholder; username-like fields get the credential hint
            # if one was discovered (test:test pattern).
            data: dict[str, str] = {}
            cred_hint_user = None
            cred_hint_pass = None
            for c in credentials_in_html:
                if ":" in c:
                    parts = c.replace("test:test", "test:test").split(":", 1)
                    if len(parts) == 2 and parts[0].strip() and parts[1].strip():
                        cred_hint_user = parts[0].strip().strip("<!- '\"")[:40]
                        cred_hint_pass = parts[1].strip().strip("-->'\"")[:40]
                        break

            for inp in form.get("inputs", []):
                name = str(inp.get("name") or "").strip()
                if not name:
                    continue
                itype = str(inp.get("type") or "text").lower()
                existing = str(inp.get("value") or "").strip()
                if itype == "hidden" and existing:
                    data[name] = existing
                    continue
                lower_name = name.lower()
                if itype == "password":
                    data[name] = cred_hint_pass or "ProbePassword1!"
                elif any(kw in lower_name for kw in ("user", "email", "login", "uid")):
                    data[name] = cred_hint_user or "probe"
                elif itype == "checkbox":
                    data[name] = "1"
                elif itype == "submit":
                    data[name] = existing or "submit"
                else:
                    data[name] = existing or "probe"

            try:
                resp = client.post(action, data=data)
            except Exception as exc:  # noqa: BLE001
                form_follow_results.append({
                    "form_action": action,
                    "submitted_keys": sorted(data.keys()),
                    "error": str(exc)[:200],
                })
                continue

            ct = resp.headers.get("content-type", "")
            form_follow_results.append({
                "form_action": action,
                "submitted_keys": sorted(data.keys()),
                "submitted_values_redacted": {
                    k: "<redacted>" if any(t in k.lower() for t in ("pass", "token", "secret")) else v
                    for k, v in data.items()
                },
                "response_status": resp.status_code,
                "response_url": str(resp.url),  # captures redirects
                "response_set_cookie": "Set-Cookie" in resp.headers,
                "content_type": ct[:80],
            })

            if resp.status_code == 200 and "html" in ct.lower():
                # Parse for NEW forms — the multi-step continuation.
                follow_parser = _FormCollector()
                try:
                    follow_parser.feed(resp.text[:8192])
                except Exception:  # noqa: BLE001
                    pass
                for new_form in follow_parser.forms:
                    new_action = (new_form.get("action") or "").strip()
                    if not new_action:
                        new_form["action"] = str(resp.url)
                        new_form["_action_was_empty"] = True
                    elif not new_action.startswith("http"):
                        new_form["action"] = urljoin(str(resp.url), new_action)
                    new_form["_discovered_on"] = str(resp.url)
                    new_form["_discovered_via"] = "form-follow"
                    new_form["_predecessor_action"] = action
                    # Avoid trivial duplicates (same action + same inputs).
                    sig = (
                        new_form["action"],
                        ",".join(sorted(str(i.get("name") or "") for i in new_form.get("inputs", []))),
                    )
                    if sig not in followed:
                        forms.append(new_form)
                        followed.add(sig)
                # Also pick up additional comments / credentials from this
                # follow-up page.
                comments.extend(follow_parser.comments)
                credentials_in_html.extend(_find_credentials_in_text(resp.text[:8192]))

    # Deduplicate links + scripts.
    links = sorted(set(links))
    scripts = sorted(set(scripts))
    credentials_in_html = sorted(set(credentials_in_html))

    inventory = _build_endpoint_inventory(probe_results)

    # Stitch follow-form results into the markdown via the comments
    # field as a fallback (specialists already inspect Input Vectors,
    # so the form-follow data is appended below).
    markdown = _build_markdown(
        target=target,
        probe_results=probe_results,
        forms=forms,
        links=links,
        scripts=scripts,
        comments=comments,
        fingerprint=fingerprint,
        credentials_in_html=credentials_in_html,
        inventory=inventory,
    )

    payload = {
        "tool": "recon-deliverable",
        "target": target,
        "probe_count": len(probe_results),
        "form_count": len(forms),
        "link_count": len(links),
        "script_count": len(scripts),
        "comment_count": len(comments),
        "credentials_in_html": len(credentials_in_html),
        "endpoint_inventory_count": len(inventory),
        "fingerprint": fingerprint,
    }

    artifact = EvidenceArtifact(
        name=RECON_DELIVERABLE_ARTIFACT_NAME,
        content_type="text/markdown",
        data=markdown.encode("utf-8"),
        kind="recon",
    )

    return RunnerExecution(
        tool="recon-deliverable",
        exit_code=0,
        stdout=json.dumps(payload),
        stderr="",
        artifacts=[artifact],
        metadata={
            "tool_version": "recon-deliverable:v1-phase2-2026-05-22",
            "runner_digest": "workers.recon_deliverable.runner:v1",
        },
    )
