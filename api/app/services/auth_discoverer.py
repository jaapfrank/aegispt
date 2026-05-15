"""Auth discovery service — Mythos task #325 (backlog-375).

Generic HTML-form auth flow discovery. Two pure functions:

- :func:`fetch_auth_pages` probes a base URL for common register/login
  paths and returns observed pages whose response is 200. All HTTP
  respects the passed scope_allowlist.

- :func:`fingerprint_application` parses HTML form documents and emits a
  normalized fingerprint dict suitable as a cache key (#327) and as
  input to the AI recipe builder (#326).

Constraints honored:
- No AI calls in this task (those are #326).
- No cache logic (that is #327).
- No probe migration (that is #328).
- No imports from workers/runners or assessment_loop.
- Pure parsing + heuristic stack detection.

Reference implementation studied: ``workers/runners/xss_proof/runner.py``
(``_try_register_with_ai``, ``_discover_candidate_pages``,
``_discover_auth_forms``). That module is **NOT** imported here — its
regex patterns are reproduced and generalized so this service has no
runner-side dependency.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx as httpx_client

from api.app.services.runs import web_target_value_is_allowed_with_path

# Common register / login paths. Intentionally NOT Gruyere-specific —
# only widely-used patterns across the OWASP ecosystem and common
# enterprise stacks. Order matters: most common paths first so the probe
# short-circuits quickly when the target answers.
REGISTER_PATHS: tuple[str, ...] = (
    "/register",
    "/signup",
    "/sign-up",
    "/join",
    "/create-account",
    "/new-account",
    "/account/create",
    "/users/new",
    "/api/users",
    "/api/register",
    "/auth/register",
    "/register.aspx",
    "/Register.asp",
    "/bank/register.aspx",
)

LOGIN_PATHS: tuple[str, ...] = (
    "/login",
    "/signin",
    "/sign-in",
    "/log-in",
    "/users/sign_in",
    "/auth/login",
    "/api/login",
    "/api/auth/login",
    "/login.jsp",
    "/login.aspx",
    "/Login.asp",
    "/bank/login.jsp",
    "/account/login",
)

# Keywords used when scanning the index page for links pointing at
# register/login flows. Generic enough to cover localized strings too.
REGISTER_LINK_KEYWORDS = re.compile(
    r"register|signup|sign[\s\-]?up|create[\s\-]?account|new[\s\-]?account|join|aanmeld",
    re.IGNORECASE,
)
LOGIN_LINK_KEYWORDS = re.compile(
    r"login|signin|sign[\s\-]?in|log[\s\-]?in|aanmelden|inloggen|auth",
    re.IGNORECASE,
)

# Session cookie names that hint at the underlying stack.
SESSION_COOKIE_STACK_HINTS: tuple[tuple[str, str], ...] = (
    ("JSESSIONID", "java_servlet"),
    ("ASP.NET_SessionId", "aspnet"),
    ("ASPNET_SessionId", "aspnet"),
    ("ASPSESSIONID", "asp_classic"),
    ("PHPSESSID", "php"),
    ("connect.sid", "node_express"),
    ("laravel_session", "php_laravel"),
    ("django_session", "python_django"),
    ("django_csrf_token", "python_django"),
    ("rack.session", "ruby_rack"),
    ("_rails_session", "ruby_rails"),
    ("GRUYERE", "python_gruyere"),
    ("AIOHTTP_SESSION", "python_aiohttp"),
)

# Hidden form field signatures keyed to framework.
HIDDEN_FIELD_STACK_HINTS: tuple[tuple[str, str], ...] = (
    ("__VIEWSTATE", "aspnet"),
    ("__EVENTVALIDATION", "aspnet"),
    ("__RequestVerificationToken", "aspnet_mvc"),
    ("csrfmiddlewaretoken", "python_django"),
    ("authenticity_token", "ruby_rails"),
    ("_csrf", "node_express"),
    ("_token", "php_laravel"),
)

# File extension hints in form action URLs.
ACTION_EXTENSION_STACK_HINTS: tuple[tuple[str, str], ...] = (
    (".aspx", "aspnet"),
    (".asp", "asp_classic"),
    (".jsp", "java_jsp"),
    (".do", "java_struts"),
    (".php", "php"),
    (".gtl", "python_gruyere"),
    (".cgi", "cgi"),
)

# Limit on probe attempts to avoid hammering targets.
DEFAULT_PROBE_LIMIT = 12
DEFAULT_TIMEOUT = 8.0
MAX_PAGE_HTML_BYTES = 200_000  # truncate large bodies
MAX_FIELDS_PER_FORM = 30
FINGERPRINT_MAX_BYTES = 1900  # acceptance criterion: <2 KB

_FORM_RE = re.compile(r"<form([^>]*)>(.*?)</form>", re.DOTALL | re.IGNORECASE)
_INPUT_RE = re.compile(r"<input([^>]*?)/?>", re.IGNORECASE)
_META_GENERATOR_RE = re.compile(
    r'<meta\s+name=["\']generator["\']\s+content=["\']([^"\']+)["\']',
    re.IGNORECASE,
)
_HREF_RE = re.compile(r'href=["\']([^"\'#][^"\']*)["\']', re.IGNORECASE)


def fetch_auth_pages(
    base_url: str,
    *,
    scope_allowlist: dict[str, Any] | None = None,
    timeout_seconds: float = DEFAULT_TIMEOUT,
    probe_limit: int = DEFAULT_PROBE_LIMIT,
    client: httpx_client.Client | None = None,
) -> list[dict[str, Any]]:
    """Probe common register / login paths under ``base_url`` and return
    observed pages.

    Each returned dict has shape::

        {
            "url": str,
            "kind": "register" | "login" | "index",
            "status_code": int,
            "html": str,                  # truncated to MAX_PAGE_HTML_BYTES
            "response_headers": dict[str, str],   # selected hint headers only
            "set_cookie_names": list[str],
        }

    Pages outside ``scope_allowlist`` are silently skipped. HTTP errors
    on a candidate page are skipped (no exception bubbles up). The
    ``index`` page is always probed first.

    A caller-supplied ``client`` keeps cookies/session state when
    needed; otherwise a fresh ephemeral client is created.

    No AI calls are made — see #326 for that.
    """
    pages: list[dict[str, Any]] = []
    if not base_url:
        return pages

    parsed = urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    instance_prefix = ""
    path_parts = [p for p in parsed.path.strip("/").split("/") if p]
    if path_parts:
        instance_prefix = "/" + path_parts[0]

    candidates: list[tuple[str, str]] = [(base_url, "index")]
    for path in REGISTER_PATHS:
        candidates.append((origin + instance_prefix + path, "register"))
        if instance_prefix:
            candidates.append((origin + path, "register"))
    for path in LOGIN_PATHS:
        candidates.append((origin + instance_prefix + path, "login"))
        if instance_prefix:
            candidates.append((origin + path, "login"))

    seen_urls: set[str] = set()
    deduped: list[tuple[str, str]] = []
    for url, kind in candidates:
        if url in seen_urls:
            continue
        seen_urls.add(url)
        deduped.append((url, kind))
    deduped = deduped[:probe_limit]

    owned_client = False
    if client is None:
        client = httpx_client.Client(
            timeout=timeout_seconds, follow_redirects=False, verify=True
        )
        owned_client = True

    try:
        for url, kind in deduped:
            if scope_allowlist and not web_target_value_is_allowed_with_path(
                scope_allowlist, url
            ):
                continue
            try:
                resp = client.get(url)
            except httpx_client.HTTPError:
                continue

            if resp.status_code != 200:
                # Also probe the index even on non-200 for link scanning.
                if kind == "index" and resp.status_code in (301, 302):
                    # Try the redirect target if it's still in scope.
                    location = resp.headers.get("location")
                    if location:
                        redirect_url = urljoin(url, location)
                        if scope_allowlist and not web_target_value_is_allowed_with_path(
                            scope_allowlist, redirect_url
                        ):
                            continue
                        try:
                            resp = client.get(redirect_url)
                            url = redirect_url
                        except httpx_client.HTTPError:
                            continue
                if resp.status_code != 200:
                    continue

            body = (resp.text or "")[:MAX_PAGE_HTML_BYTES]
            response_headers: dict[str, str] = {}
            for header in ("server", "x-powered-by", "x-aspnet-version", "x-generator"):
                value = resp.headers.get(header)
                if value:
                    response_headers[header] = str(value)[:200]

            # Capture set-cookie names without exposing values (scope: fingerprint hints only).
            set_cookie_names: list[str] = []
            try:
                for cookie in resp.cookies.jar:
                    if cookie.name:
                        set_cookie_names.append(cookie.name)
            except AttributeError:
                # Fallback: parse raw Set-Cookie headers
                for raw in resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else []:
                    name = raw.split("=", 1)[0].strip()
                    if name:
                        set_cookie_names.append(name)

            pages.append(
                {
                    "url": url,
                    "kind": kind,
                    "status_code": resp.status_code,
                    "html": body,
                    "response_headers": response_headers,
                    "set_cookie_names": sorted(set(set_cookie_names))[:10],
                }
            )

            # Once we have the index page, scan it for additional same-origin
            # register/login links not yet in our candidate list.
            if kind == "index":
                for href_match in _HREF_RE.finditer(body):
                    href = href_match.group(1).strip()
                    if not href or href.startswith(("mailto:", "javascript:")):
                        continue
                    if not (
                        REGISTER_LINK_KEYWORDS.search(href)
                        or LOGIN_LINK_KEYWORDS.search(href)
                    ):
                        continue
                    if href.startswith("http"):
                        absolute = href
                    else:
                        absolute = urljoin(url, href)
                    parsed_link = urlparse(absolute)
                    if parsed_link.netloc and parsed_link.netloc != parsed.netloc:
                        continue
                    inferred_kind = (
                        "register"
                        if REGISTER_LINK_KEYWORDS.search(href)
                        else "login"
                    )
                    if absolute not in seen_urls and len(seen_urls) < probe_limit + 5:
                        seen_urls.add(absolute)
                        if scope_allowlist and not web_target_value_is_allowed_with_path(
                            scope_allowlist, absolute
                        ):
                            continue
                        try:
                            r2 = client.get(absolute)
                        except httpx_client.HTTPError:
                            continue
                        if r2.status_code == 200:
                            pages.append(
                                {
                                    "url": absolute,
                                    "kind": inferred_kind,
                                    "status_code": r2.status_code,
                                    "html": (r2.text or "")[:MAX_PAGE_HTML_BYTES],
                                    "response_headers": {
                                        k: r2.headers.get(k, "")[:200]
                                        for k in (
                                            "server",
                                            "x-powered-by",
                                            "x-aspnet-version",
                                            "x-generator",
                                        )
                                        if r2.headers.get(k)
                                    },
                                    "set_cookie_names": sorted(
                                        {c.name for c in r2.cookies.jar if c.name}
                                    )[:10],
                                }
                            )
    finally:
        if owned_client:
            client.close()

    return pages


def _parse_forms(html: str, *, page_url: str) -> list[dict[str, Any]]:
    """Extract HTML forms (action, method, fields) from ``html``.

    Field list shape::

        [{"name": str, "type": str, "value": str, "required": bool}, ...]

    Returns deterministic order: forms in document order.
    """
    if not html:
        return []
    parsed_url = urlparse(page_url)
    origin = f"{parsed_url.scheme}://{parsed_url.netloc}"

    forms: list[dict[str, Any]] = []
    for form_match in _FORM_RE.finditer(html):
        attrs_raw = form_match.group(1) or ""
        body = form_match.group(2) or ""

        action_match = re.search(r'action=["\']([^"\']*)["\']', attrs_raw, re.IGNORECASE)
        method_match = re.search(r'method=["\']([^"\']*)["\']', attrs_raw, re.IGNORECASE)
        id_match = re.search(r'\bid=["\']([^"\']*)["\']', attrs_raw, re.IGNORECASE)
        name_match = re.search(r'\bname=["\']([^"\']*)["\']', attrs_raw, re.IGNORECASE)

        action = action_match.group(1).strip() if action_match else page_url
        method = (method_match.group(1).strip().upper() if method_match else "POST")
        if not action:
            action = page_url
        if action.startswith("http"):
            full_action = action
        else:
            full_action = urljoin(page_url, action) if action.startswith("/") else urljoin(origin, action)

        fields: list[dict[str, Any]] = []
        seen_names: set[str] = set()
        for input_match in _INPUT_RE.finditer(body):
            attrs = input_match.group(1) or ""
            n_match = re.search(r'\bname=["\']([^"\']*)["\']', attrs, re.IGNORECASE)
            t_match = re.search(r'\btype=["\']([^"\']*)["\']', attrs, re.IGNORECASE)
            v_match = re.search(r'\bvalue=["\']([^"\']*)["\']', attrs, re.IGNORECASE)
            req_match = re.search(r"\brequired\b", attrs, re.IGNORECASE)
            if not n_match:
                continue
            field_name = n_match.group(1).strip()
            if not field_name or field_name in seen_names:
                continue
            seen_names.add(field_name)
            fields.append(
                {
                    "name": field_name,
                    "type": (t_match.group(1).strip().lower() if t_match else "text"),
                    "value": (v_match.group(1) if v_match else "")[:200],
                    "required": bool(req_match),
                }
            )
            if len(fields) >= MAX_FIELDS_PER_FORM:
                break

        form_record: dict[str, Any] = {
            "action": full_action,
            "method": method if method in {"GET", "POST", "PUT", "PATCH", "DELETE"} else "POST",
            "fields": fields,
            "source_page": page_url,
        }
        form_id = id_match.group(1) if id_match else (name_match.group(1) if name_match else None)
        if form_id:
            form_record["form_id"] = form_id
        forms.append(form_record)

    return forms


def _form_resembles(form: dict[str, Any], kind: str) -> int:
    """Score a form as register/login candidate. Higher = more likely.

    Heuristic only — no AI. Combines URL hints, field name hints, and
    type hints (password + email/username = login; password + confirm =
    register; etc.).
    """
    score = 0
    action = (form.get("action") or "").lower()
    field_names = [str(f.get("name") or "").lower() for f in form.get("fields") or []]
    field_types = [str(f.get("type") or "").lower() for f in form.get("fields") or []]
    field_set = set(field_names)
    page_kind = str(form.get("page_kind") or "").lower()

    # Page context is a strong hint when fetch_auth_pages classified the
    # URL as register/login before form parsing.
    if page_kind == kind:
        score += 3

    if kind == "register":
        if REGISTER_LINK_KEYWORDS.search(action):
            score += 4
        if any("confirm" in n for n in field_names):
            score += 5  # confirm password is a strong register signal
        if "email" in field_set and "password" in field_set and any(
            "user" in n or "name" in n for n in field_names
        ):
            score += 3
        if any(n in {"is_admin", "is_author", "role"} for n in field_names):
            score += 1  # register flows that expose role flags (Gruyere, etc.)
    elif kind == "login":
        if LOGIN_LINK_KEYWORDS.search(action):
            score += 4
        if field_types.count("password") == 1 and "password" in field_set:
            score += 3
        if "remember" in " ".join(field_names) or "rememberme" in field_set:
            score += 2
        if {"username", "password"}.issubset(field_set) or {"email", "password"}.issubset(field_set) or {"uid", "pw"}.issubset(field_set):
            score += 4
        if any("confirm" in n for n in field_names):
            score -= 3  # confirm-pw is a register signal, downscore for login

    # Both: password presence is required for either flow.
    if "password" in field_set or any(t == "password" for t in field_types) or "pw" in field_set:
        score += 1
    else:
        # No password-class field at all → unlikely auth form.
        score -= 4
    return score


def _detect_stack_hints(pages: list[dict[str, Any]]) -> list[str]:
    """Heuristic stack detection from pages + response headers + cookies + forms.

    Order of returned hints is deterministic (sorted). No external API
    calls. Hints are strings like "aspnet", "python_gruyere", "java_jsp".
    """
    hints: set[str] = set()
    for page in pages:
        # Response headers
        headers = page.get("response_headers") or {}
        server = str(headers.get("server") or "").lower()
        x_powered_by = str(headers.get("x-powered-by") or "").lower()
        x_aspnet = str(headers.get("x-aspnet-version") or "").lower()
        if "iis" in server or x_aspnet or "asp.net" in x_powered_by:
            hints.add("aspnet")
        if "apache" in server:
            hints.add("apache")
        if "nginx" in server:
            hints.add("nginx")
        if "express" in x_powered_by or "node" in x_powered_by:
            hints.add("node_express")
        if "php" in x_powered_by:
            hints.add("php")
        if "django" in x_powered_by:
            hints.add("python_django")
        if "tomcat" in server or "tomcat" in x_powered_by or "jetty" in server:
            hints.add("java_servlet")

        # Cookie hints
        for cookie_name in page.get("set_cookie_names") or []:
            for needle, hint in SESSION_COOKIE_STACK_HINTS:
                if cookie_name == needle or cookie_name.startswith(needle):
                    hints.add(hint)

        # HTML body hints
        html = page.get("html") or ""
        meta_match = _META_GENERATOR_RE.search(html)
        if meta_match:
            generator = meta_match.group(1).lower()
            if "wordpress" in generator:
                hints.add("wordpress")
            if "drupal" in generator:
                hints.add("drupal")
            if "django" in generator:
                hints.add("python_django")
            if "jekyll" in generator:
                hints.add("jekyll_static")
        if "ng-app" in html or "ng-controller" in html or 'data-ng-' in html:
            hints.add("angular")
        if "react" in html.lower() and ("data-reactroot" in html or "react-dom" in html):
            hints.add("react")
        if "_next/static" in html or "__NEXT_DATA__" in html:
            hints.add("nextjs")
        if "__VIEWSTATE" in html or "__EVENTVALIDATION" in html:
            hints.add("aspnet")

        # Form hints (action extensions, hidden fields)
        forms = _parse_forms(html, page_url=page.get("url") or "")
        for form in forms:
            action = (form.get("action") or "").lower()
            for ext, hint in ACTION_EXTENSION_STACK_HINTS:
                if ext in action:
                    hints.add(hint)
            for field in form.get("fields") or []:
                fname = str(field.get("name") or "")
                for needle, hint in HIDDEN_FIELD_STACK_HINTS:
                    if fname == needle:
                        hints.add(hint)

    return sorted(hints)


def _pick_session_cookie_hint(pages: list[dict[str, Any]]) -> str | None:
    """Pick the most informative session cookie name observed across pages."""
    candidates: list[str] = []
    for page in pages:
        for name in page.get("set_cookie_names") or []:
            candidates.append(name)
    if not candidates:
        return None
    # Prefer known framework cookies first.
    known_priority = [needle for needle, _ in SESSION_COOKIE_STACK_HINTS]
    for needle in known_priority:
        for name in candidates:
            if name == needle or name.startswith(needle):
                return name
    # Otherwise return the first one alphabetically (deterministic).
    return sorted(candidates)[0]


def fingerprint_application(
    html_documents: list[dict[str, Any]],
) -> dict[str, Any]:
    """Parse HTML form documents and emit a normalized fingerprint dict.

    Input: list of page dicts as returned by :func:`fetch_auth_pages`.

    Output::

        {
          "stack_hints": [...sorted strings...],
          "register_form": {"action", "method", "fields", "score"} | None,
          "login_form": {"action", "method", "fields", "score"} | None,
          "session_cookie_hint": str | None,
          "fingerprint_hash": str,       # sha256 of canonical normalized form
          "fingerprint_version": "auth-discoverer-v1",
        }

    The output is deterministic for identical inputs and JSON-serializable.
    Field-name lists are alphabetized for canonical comparison. The
    fingerprint_hash is computed over `(stack_hints, register_field_names,
    login_field_names, session_cookie_hint, register_action_path,
    login_action_path)`.

    Pages with no parseable forms still emit a fingerprint (stack hints
    only) — useful for SPAs where forms load via JS.
    """
    if not isinstance(html_documents, list):
        html_documents = []

    # Collect all forms across pages, scored.
    all_forms: list[dict[str, Any]] = []
    for page in html_documents:
        if not isinstance(page, dict):
            continue
        html = page.get("html") or ""
        page_url = page.get("url") or ""
        forms = _parse_forms(html, page_url=page_url)
        for form in forms:
            form["page_kind"] = page.get("kind") or ""
            form["register_score"] = _form_resembles(form, "register")
            form["login_score"] = _form_resembles(form, "login")
            all_forms.append(form)

    register_form: dict[str, Any] | None = None
    login_form: dict[str, Any] | None = None
    if all_forms:
        best_register = max(all_forms, key=lambda f: f["register_score"])
        best_login = max(all_forms, key=lambda f: f["login_score"])
        if best_register["register_score"] >= 3:
            register_form = {
                "action": best_register["action"],
                "method": best_register["method"],
                "fields": [
                    {"name": f["name"], "type": f["type"], "required": f["required"]}
                    for f in best_register["fields"]
                ],
                "score": best_register["register_score"],
            }
        if best_login["login_score"] >= 3:
            login_form = {
                "action": best_login["action"],
                "method": best_login["method"],
                "fields": [
                    {"name": f["name"], "type": f["type"], "required": f["required"]}
                    for f in best_login["fields"]
                ],
                "score": best_login["login_score"],
            }

    stack_hints = _detect_stack_hints(html_documents)
    session_cookie_hint = _pick_session_cookie_hint(html_documents)

    def _action_path(form: dict[str, Any] | None) -> str:
        if not form:
            return ""
        return urlparse(form.get("action") or "").path or ""

    def _field_names(form: dict[str, Any] | None) -> list[str]:
        if not form:
            return []
        return sorted(str(f.get("name") or "") for f in form.get("fields") or [])

    canonical = {
        "stack_hints": stack_hints,
        "register_field_names": _field_names(register_form),
        "register_action_path": _action_path(register_form),
        "login_field_names": _field_names(login_form),
        "login_action_path": _action_path(login_form),
        "session_cookie_hint": session_cookie_hint or "",
    }
    canonical_blob = json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
    fingerprint_hash = hashlib.sha256(canonical_blob).hexdigest()

    payload: dict[str, Any] = {
        "stack_hints": stack_hints,
        "register_form": register_form,
        "login_form": login_form,
        "session_cookie_hint": session_cookie_hint,
        "fingerprint_hash": fingerprint_hash,
        "fingerprint_version": "auth-discoverer-v1",
    }

    # Enforce the < 2 KB acceptance criterion by truncating field lists
    # if the serialized payload would exceed the bound. Fields are dropped
    # from the tail (alphabetical end) to preserve high-priority anchors.
    serialized = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    while len(serialized) > FINGERPRINT_MAX_BYTES:
        trimmed = False
        for form_key in ("register_form", "login_form"):
            form = payload.get(form_key)
            if isinstance(form, dict) and len(form.get("fields") or []) > 3:
                form["fields"] = form["fields"][:-1]
                trimmed = True
                break
        if not trimmed:
            # Last resort: truncate stack hints from the tail.
            if len(payload.get("stack_hints") or []) > 0:
                payload["stack_hints"] = payload["stack_hints"][:-1]
            else:
                break
        serialized = json.dumps(payload, separators=(",", ":")).encode("utf-8")

    return payload
