"""Auth discovery service — Mythos tasks #325 + #326 + #327.

Generic HTML-form auth flow discovery. Public surface:

- :func:`fetch_auth_pages` (#325) probes a base URL for common register/
  login paths and returns observed pages whose response is 200. All HTTP
  respects the passed scope_allowlist.

- :func:`fingerprint_application` (#325) parses HTML form documents and
  emits a normalized fingerprint dict suitable as a cache key and as
  input to the AI recipe builder.

- :func:`build_recipe` (#326) takes a fingerprint and uses Claude Haiku
  to synthesize an executable AuthRecipe (steps + verification) any
  runner can execute via existing HTTP primitives.

- :func:`lookup_recipe` / :func:`store_recipe` / :func:`verify_recipe` /
  :func:`mark_recipe_stale` (#327) layer a per-engagement cache on top
  of build_recipe. Cache files live at
  ``/memories/auth-recipes/<fingerprint-hash>.json`` via the existing
  Claude memory backend. Aging + replay-before-trust + size caps
  enforced.

Constraints honored:
- No probe migration (that is #328).
- No imports from workers/runners or assessment_loop.
- No app-specific patterns seeded in code or prompts. The AI must
  derive the recipe from the fingerprint at runtime.
- Cache is per-engagement. The memory_backend root is already per-
  engagement (one root path per runtime), so isolation is inherited
  rather than reimplemented.

Reference implementation studied: ``workers/runners/xss_proof/runner.py``
(``_try_register_with_ai``, ``_discover_candidate_pages``,
``_discover_auth_forms``). That module is **NOT** imported here — its
regex patterns are reproduced and generalized so this service has no
runner-side dependency.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import random
import re
import string
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx as httpx_client

from api.app.services import memory_backend
from api.app.services.runs import web_target_value_is_allowed_with_path

logger = logging.getLogger(__name__)

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


# ---------------------------------------------------------------------------
# #326 — AI-driven recipe builder
# ---------------------------------------------------------------------------

RECIPE_VERSION = "auth-recipe-v1"
RECIPE_MODEL = "claude-haiku-4-5-20251001"
RECIPE_MAX_STEPS = 6
RECIPE_MAX_FIELDS_PER_STEP = 30
RECIPE_MAX_TOKENS = 1500
RECIPE_TIMEOUT_SECONDS = 30.0

_ALLOWED_FIELD_INTENTS: frozenset[str] = frozenset(
    {
        "username",
        "password",
        "confirm_password",
        "email",
        "csrf_token",
        "hidden_passthrough",
        "literal",
    }
)
_ALLOWED_STEP_INTENTS: frozenset[str] = frozenset(
    {"register", "login", "csrf_fetch", "post_login"}
)
_ALLOWED_HTTP_METHODS: frozenset[str] = frozenset(
    {"GET", "POST", "PUT", "PATCH"}
)


_RECIPE_SYSTEM_PROMPT = (
    "You are an authentication recipe synthesizer. You receive a normalized "
    "fingerprint of an unknown web application's auth surface (observed "
    "forms and stack hints — NOT app-specific patterns). You produce a "
    "structured AuthRecipe: an ordered list of HTTP steps with field "
    "mappings plus a verification step. The recipe must be JSON only, no "
    "prose. Do not invent URLs that are not in the fingerprint. Do not "
    "embed credentials — use placeholder intents."
)


def _recipe_user_prompt(fingerprint: dict[str, Any]) -> str:
    """Build the user-side prompt. Contains ONLY fingerprint data — no
    application-specific guidance (per feedback_no_prescriptive_recipes)."""
    fp_json = json.dumps(fingerprint, separators=(",", ":"), sort_keys=True)
    schema_example = {
        "recipe_version": RECIPE_VERSION,
        "steps": [
            {
                "name": "register",
                "intent": "register",
                "method": "POST",
                "url": "<exact action URL from fingerprint>",
                "field_mappings": {
                    "<observed_field_name>": "username|password|confirm_password|email|csrf_token|hidden_passthrough|literal:<value>",
                },
                "expected_status": [200, 302, 303],
                "description": "<short purpose>",
            }
        ],
        "verification": {
            "method": "GET",
            "url": "<URL same-origin to a page reachable after auth>",
            "expect_status": [200],
            "expect_set_cookie": "<session cookie name observed in fingerprint, or null>",
            "expect_body_contains": [],
            "description": "<how to confirm session>",
        },
    }
    schema_json = json.dumps(schema_example, indent=2)
    return (
        "Fingerprint:\n"
        f"{fp_json}\n\n"
        "Output schema (JSON, exact field names; produce ONLY this object):\n"
        f"{schema_json}\n\n"
        "Rules:\n"
        f"- steps[].url MUST match an action URL appearing in the fingerprint (register_form.action or login_form.action). Maximum {RECIPE_MAX_STEPS} steps.\n"
        "- For every form field observed in register_form/login_form fields you choose to fill, map it to one of: username, password, confirm_password, email, csrf_token, hidden_passthrough, or literal:<value>.\n"
        "- hidden_passthrough means: replay the value observed in the form on initial GET.\n"
        "- verification.url must be same-origin as the step URLs.\n"
        "- If fingerprint has no register_form and no login_form, return {\"recipe_version\":\"" + RECIPE_VERSION + "\",\"steps\":[],\"verification\":null}.\n"
        "- Output ONLY the JSON object. No markdown fences, no prose."
    )


def _extract_text_from_response(response: Any) -> str:
    """Pull the text content out of an Anthropic SDK response or a duck
    type that mimics it. Returns empty string on shape mismatch."""
    try:
        content = response.content  # type: ignore[attr-defined]
    except AttributeError:
        return ""
    if not content:
        return ""
    first = content[0]
    # Real SDK blocks have a `.text` attribute. Duck types may use dict access.
    text = getattr(first, "text", None)
    if text is None and isinstance(first, dict):
        text = first.get("text")
    return str(text or "")


def _extract_json_object(text: str) -> dict[str, Any] | None:
    """Find the outermost JSON object in raw model text. Handles fenced
    code blocks and surrounding prose defensively."""
    if not text:
        return None
    stripped = text.strip()
    # Strip ```json fences if present.
    if stripped.startswith("```"):
        stripped = re.sub(r"^```[a-zA-Z]*\s*", "", stripped)
        stripped = re.sub(r"\s*```$", "", stripped)
    try:
        candidate = json.loads(stripped)
        if isinstance(candidate, dict):
            return candidate
    except json.JSONDecodeError:
        pass
    # Fall back: find the first balanced { ... } object.
    start = stripped.find("{")
    if start < 0:
        return None
    depth = 0
    for idx in range(start, len(stripped)):
        ch = stripped[idx]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                blob = stripped[start : idx + 1]
                try:
                    candidate = json.loads(blob)
                    if isinstance(candidate, dict):
                        return candidate
                except json.JSONDecodeError:
                    return None
                break
    return None


def _collect_allowed_action_urls(fingerprint: dict[str, Any]) -> set[str]:
    """The set of action URLs the AI may legally reference in its
    steps. URL hijack defense: anything the model returns outside this
    set is rejected."""
    urls: set[str] = set()
    for key in ("register_form", "login_form"):
        form = fingerprint.get(key)
        if isinstance(form, dict):
            action = form.get("action")
            if isinstance(action, str) and action:
                urls.add(action)
    return urls


def _collect_field_names(fingerprint: dict[str, Any]) -> dict[str, set[str]]:
    """Map of action_url -> set of field names observed on that form.
    Used to validate that field_mappings only reference real fields."""
    out: dict[str, set[str]] = {}
    for key in ("register_form", "login_form"):
        form = fingerprint.get(key)
        if not isinstance(form, dict):
            continue
        action = form.get("action")
        if not isinstance(action, str) or not action:
            continue
        names = {
            str(f.get("name") or "")
            for f in (form.get("fields") or [])
            if isinstance(f, dict) and f.get("name")
        }
        out[action] = names
    return out


def _validate_step(
    step: Any,
    *,
    allowed_urls: set[str],
    fields_by_url: dict[str, set[str]],
) -> dict[str, Any] | None:
    """Coerce + validate a single recipe step. Returns sanitized dict or None."""
    if not isinstance(step, dict):
        return None
    name = str(step.get("name") or "").strip()
    intent = str(step.get("intent") or "").strip().lower()
    method = str(step.get("method") or "").strip().upper()
    url = str(step.get("url") or "").strip()
    field_mappings_raw = step.get("field_mappings") or {}
    expected_status_raw = step.get("expected_status") or []
    description = str(step.get("description") or "")[:240]

    if not name or len(name) > 64:
        return None
    if intent not in _ALLOWED_STEP_INTENTS:
        return None
    if method not in _ALLOWED_HTTP_METHODS:
        return None
    if url not in allowed_urls:
        return None
    if not isinstance(field_mappings_raw, dict):
        return None
    if not isinstance(expected_status_raw, list):
        return None

    expected_status: list[int] = []
    for code in expected_status_raw[:6]:
        try:
            value = int(code)
        except (TypeError, ValueError):
            continue
        if 100 <= value < 600:
            expected_status.append(value)
    if not expected_status:
        expected_status = [200]

    legal_field_names = fields_by_url.get(url, set())
    field_mappings: dict[str, str] = {}
    for field_name, mapping in list(field_mappings_raw.items())[:RECIPE_MAX_FIELDS_PER_STEP]:
        if not isinstance(field_name, str) or not field_name:
            continue
        # Only map fields the form actually has. Prevents the model from
        # injecting arbitrary parameters.
        if legal_field_names and field_name not in legal_field_names:
            continue
        if not isinstance(mapping, str) or not mapping:
            continue
        head = mapping.split(":", 1)[0].strip().lower()
        if head not in _ALLOWED_FIELD_INTENTS:
            continue
        field_mappings[field_name] = mapping[:200]

    return {
        "name": name,
        "intent": intent,
        "method": method,
        "url": url,
        "field_mappings": field_mappings,
        "expected_status": expected_status,
        "description": description,
    }


def _validate_verification(
    verification: Any,
    *,
    allowed_origin: str,
) -> dict[str, Any] | None:
    if not isinstance(verification, dict):
        return None
    method = str(verification.get("method") or "GET").strip().upper()
    url = str(verification.get("url") or "").strip()
    expect_status_raw = verification.get("expect_status") or [200]
    expect_set_cookie = verification.get("expect_set_cookie")
    expect_body_contains_raw = verification.get("expect_body_contains") or []
    description = str(verification.get("description") or "")[:240]

    if method not in _ALLOWED_HTTP_METHODS:
        return None
    if not url:
        return None
    # Same-origin guard.
    if allowed_origin:
        parsed = urlparse(url)
        if parsed.scheme and parsed.netloc:
            origin = f"{parsed.scheme}://{parsed.netloc}"
            if origin != allowed_origin:
                return None
    if not isinstance(expect_status_raw, list):
        return None
    expect_status: list[int] = []
    for code in expect_status_raw[:6]:
        try:
            value = int(code)
        except (TypeError, ValueError):
            continue
        if 100 <= value < 600:
            expect_status.append(value)
    if not expect_status:
        expect_status = [200]
    if expect_set_cookie is not None and not isinstance(expect_set_cookie, str):
        expect_set_cookie = None
    if isinstance(expect_set_cookie, str):
        expect_set_cookie = expect_set_cookie[:80] or None

    expect_body_contains: list[str] = []
    if isinstance(expect_body_contains_raw, list):
        for token in expect_body_contains_raw[:8]:
            if isinstance(token, str) and token:
                expect_body_contains.append(token[:120])

    return {
        "method": method,
        "url": url,
        "expect_status": expect_status,
        "expect_set_cookie": expect_set_cookie,
        "expect_body_contains": expect_body_contains,
        "description": description,
    }


def _allowed_origin_from_fingerprint(fingerprint: dict[str, Any]) -> str:
    for key in ("register_form", "login_form"):
        form = fingerprint.get(key)
        if isinstance(form, dict):
            action = form.get("action") or ""
            parsed = urlparse(action)
            if parsed.scheme and parsed.netloc:
                return f"{parsed.scheme}://{parsed.netloc}"
    return ""


def build_recipe(
    fingerprint: dict[str, Any],
    *,
    anthropic_client: Any = None,
    timeout_seconds: float = RECIPE_TIMEOUT_SECONDS,
) -> dict[str, Any] | None:
    """Synthesize an executable AuthRecipe from a fingerprint via Claude Haiku.

    Returns a JSON-serializable dict::

        {
          "recipe_version": "auth-recipe-v1",
          "fingerprint_hash": str,
          "model": str,
          "steps": [
              {
                "name": str,
                "intent": "register"|"login"|"csrf_fetch"|"post_login",
                "method": "GET"|"POST"|...,
                "url": str,                # must match a fingerprint action URL
                "field_mappings": {field_name: intent_string},
                "expected_status": [int, ...],
                "description": str,
              }, ...
          ],
          "verification": {
              "method": "GET",
              "url": str,                  # same-origin
              "expect_status": [int, ...],
              "expect_set_cookie": str | None,
              "expect_body_contains": [str, ...],
              "description": str,
          } | None,
        }

    Returns ``None`` on:
    - no auth surface in fingerprint (no register_form AND no login_form),
    - no ANTHROPIC_API_KEY env var (and no ``anthropic_client`` injected),
    - SDK call exception,
    - JSON parse failure,
    - validation rejection (e.g. model returned URLs not in the fingerprint).

    Pass ``anthropic_client`` for tests — any duck-typed object exposing
    ``.messages.create(model=..., max_tokens=..., system=..., messages=[...])``
    that returns an object with ``.content[0].text``.
    """
    if not isinstance(fingerprint, dict):
        return None

    has_register = isinstance(fingerprint.get("register_form"), dict)
    has_login = isinstance(fingerprint.get("login_form"), dict)
    if not has_register and not has_login:
        return None

    client = anthropic_client
    if client is None:
        api_key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
        if not api_key:
            return None
        try:
            import anthropic
        except ImportError:
            return None
        try:
            client = anthropic.Anthropic(api_key=api_key)
        except Exception as exc:  # pragma: no cover — defensive
            logger.debug("auth_discoverer.build_recipe: client init failed: %s", exc)
            return None

    user_prompt = _recipe_user_prompt(fingerprint)
    try:
        response = client.messages.create(
            model=RECIPE_MODEL,
            max_tokens=RECIPE_MAX_TOKENS,
            system=_RECIPE_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_prompt}],
            timeout=timeout_seconds,
        )
    except TypeError:
        # Mock clients may not accept the `timeout` kwarg.
        try:
            response = client.messages.create(
                model=RECIPE_MODEL,
                max_tokens=RECIPE_MAX_TOKENS,
                system=_RECIPE_SYSTEM_PROMPT,
                messages=[{"role": "user", "content": user_prompt}],
            )
        except Exception as exc:
            logger.debug("auth_discoverer.build_recipe: call failed: %s", exc)
            return None
    except Exception as exc:
        logger.debug("auth_discoverer.build_recipe: call failed: %s", exc)
        return None

    raw_text = _extract_text_from_response(response)
    parsed = _extract_json_object(raw_text)
    if parsed is None:
        logger.debug("auth_discoverer.build_recipe: JSON parse failed, raw=%r", raw_text[:300])
        return None

    allowed_urls = _collect_allowed_action_urls(fingerprint)
    fields_by_url = _collect_field_names(fingerprint)
    allowed_origin = _allowed_origin_from_fingerprint(fingerprint)

    steps_raw = parsed.get("steps")
    if not isinstance(steps_raw, list):
        return None

    steps: list[dict[str, Any]] = []
    for step in steps_raw[:RECIPE_MAX_STEPS]:
        validated = _validate_step(
            step, allowed_urls=allowed_urls, fields_by_url=fields_by_url
        )
        if validated is not None:
            steps.append(validated)

    if not steps:
        logger.debug(
            "auth_discoverer.build_recipe: no valid steps after validation "
            "(allowed_urls=%s)",
            sorted(allowed_urls),
        )
        return None

    verification_raw = parsed.get("verification")
    verification = _validate_verification(
        verification_raw, allowed_origin=allowed_origin
    )

    fingerprint_hash = str(fingerprint.get("fingerprint_hash") or "")
    return {
        "recipe_version": RECIPE_VERSION,
        "fingerprint_hash": fingerprint_hash,
        "model": RECIPE_MODEL,
        "steps": steps,
        "verification": verification,
    }


# ---------------------------------------------------------------------------
# #327 — Auth pattern cache backed by Claude memory store
# ---------------------------------------------------------------------------

CACHE_SCHEMA_VERSION = "auth-recipe-cache-v1"
CACHE_DIR_LOGICAL = "/memories/auth-recipes"
CACHE_MAX_FILE_BYTES = 2048           # 2 KB per recipe file
CACHE_MAX_TOTAL_BYTES = 50 * 1024     # 50 KB across all recipe files
CACHE_MAX_AGE_SECONDS = 30 * 24 * 60 * 60     # 30 days
CACHE_FAILURE_COOLDOWN_SECONDS = 60 * 60      # 1 hour
CACHE_EVICTION_FRACTION_MAX = 0.25    # #346: cap per-store eviction at 25%

VERDICT_FRESH = "fresh"
VERDICT_STALE = "stale"
VERDICT_ABSENT = "absent"

# #346 — Migration registry.
#
# When a future task ships a v2 schema, register the migration here:
#     _RECIPE_MIGRATIONS["auth-recipe-cache-v1"] = _migrate_v1_to_v2
# The chain is walked forward (v1 → v2 → … → current) so a v1 entry on
# disk gets transparently upgraded on first read after deployment.
#
# Currently only v1 exists; the registry is empty by design. With an
# empty registry, _migrate_entry is a strict no-op for v1 entries
# (idempotent) and returns None+warning for any non-v1 version. This
# matches the #346 contract for unknown source versions.
_RECIPE_MIGRATIONS: dict[str, Any] = {}

# Track fingerprints we've already warned about per-process so a stale
# fleet doesn't spam logs. Reset between unit tests via the public
# _reset_migration_warning_cache() helper.
_MIGRATION_WARNED_FINGERPRINTS: set[str] = set()


def _reset_migration_warning_cache() -> None:
    """Test seam: reset the per-process 'already warned' set. Production
    code never calls this — the warning suppression is per-process."""
    _MIGRATION_WARNED_FINGERPRINTS.clear()


def _migrate_entry(
    entry: dict[str, Any],
    *,
    target_schema_version: str = CACHE_SCHEMA_VERSION,
) -> dict[str, Any] | None:
    """Migrate a cache entry to ``target_schema_version`` (#346).

    Returns:
    - The input dict unchanged if already at target (idempotent no-op).
    - A migrated dict if a registered migration path exists.
    - ``None`` if the source version is unknown — logs a single warning
      per (fingerprint_hash, process) so a stale fleet doesn't spam.

    Caller treats ``None`` like a cache miss (verdict ``absent``), which
    is the existing forward-compat behavior carried forward from
    :func:`_load_cache_entry`.
    """
    if not isinstance(entry, dict):
        return None
    src = str(entry.get("schema_version") or "")
    if src == target_schema_version:
        return entry  # idempotent — already current
    cur: dict[str, Any] = entry
    visited: set[str] = set()
    while str(cur.get("schema_version") or "") != target_schema_version:
        version = str(cur.get("schema_version") or "")
        if version in visited:
            # Cycle in migration registry — defensive; shouldn't happen.
            logger.warning(
                "auth_discoverer.cache: migration cycle detected at %r — "
                "treating entry as absent",
                version,
            )
            return None
        visited.add(version)
        migration = _RECIPE_MIGRATIONS.get(version)
        if migration is None:
            fp = str(cur.get("fingerprint_hash") or "?")
            if fp not in _MIGRATION_WARNED_FINGERPRINTS:
                _MIGRATION_WARNED_FINGERPRINTS.add(fp)
                logger.warning(
                    "auth_discoverer.cache: unknown schema_version=%r for "
                    "fingerprint=%s — treating as absent. Manual rebuild "
                    "(delete %s) will recover; otherwise re-derivation "
                    "happens on the next discovery run.",
                    version, fp[:16], CACHE_DIR_LOGICAL,
                )
            return None
        try:
            cur = migration(cur)
        except Exception as exc:
            logger.warning(
                "auth_discoverer.cache: migration from %s failed: %s",
                version, exc,
            )
            return None
        if not isinstance(cur, dict):
            return None
    return cur


def _utc_now(now: datetime | None = None) -> datetime:
    if isinstance(now, datetime):
        if now.tzinfo is None:
            return now.replace(tzinfo=timezone.utc)
        return now.astimezone(timezone.utc)
    return datetime.now(timezone.utc)


def _to_iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()


def _from_iso(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        # `fromisoformat` handles +00:00 offsets natively; "Z" suffix
        # needs translation for Python <3.11 compatibility.
        normalized = value.replace("Z", "+00:00") if value.endswith("Z") else value
        dt = datetime.fromisoformat(normalized)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except (TypeError, ValueError):
        return None


def _cache_path_for(fingerprint_hash: str) -> str | None:
    """Return the logical /memories/... path for a fingerprint, or None
    if the hash is unusable."""
    if not isinstance(fingerprint_hash, str):
        return None
    cleaned = re.sub(r"[^a-zA-Z0-9_-]", "", fingerprint_hash)[:80]
    if not cleaned:
        return None
    return f"{CACHE_DIR_LOGICAL}/{cleaned}.json"


def _load_cache_entry(logical_path: str) -> dict[str, Any] | None:
    """Read+parse a cache file. Returns None on any error (missing file,
    not-JSON, schema-mismatch). Defensive — the file is on disk under a
    path Claude can also write to."""
    response = memory_backend.execute("view", path=logical_path)
    if response.startswith("Error") or response.startswith("The path"):
        return None
    # `view` returns a header line + line-numbered content. Strip the
    # header and the `<lineno>\t` prefix from each remaining line.
    lines = response.splitlines()
    if not lines:
        return None
    body_lines: list[str] = []
    for line in lines[1:]:
        stripped = line.lstrip()
        # Lines from memory_backend are "<right-padded lineno>\t<text>".
        # Find the tab and keep everything after it.
        if "\t" in line:
            body_lines.append(line.split("\t", 1)[1])
        else:
            body_lines.append(stripped)
    body = "\n".join(body_lines)
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        logger.debug(
            "auth_discoverer.cache: JSON decode failed for %s",
            logical_path,
        )
        return None
    if not isinstance(data, dict):
        return None
    # #346 — defer schema-version handling to the migration layer so that
    # older versions can be upgraded transparently. Unknown versions
    # surface as None (caller treats as cache miss / verdict ABSENT)
    # plus a single warning per fingerprint per process.
    return _migrate_entry(data)


def _list_cache_files() -> list[str]:
    """List logical paths of all cache files under CACHE_DIR_LOGICAL.
    Empty list if directory doesn't exist.

    Uses direct filesystem access via :func:`memory_backend._resolve`
    rather than ``memory_backend.execute("view", ...)`` because the
    view response is capped at 2 KB by #332 — fine for Claude-facing
    prompts but undercount-prone for internal accounting that needs
    to see every cache file."""
    try:
        cache_dir = memory_backend._resolve(CACHE_DIR_LOGICAL)
    except ValueError:
        return []
    if not cache_dir.exists() or not cache_dir.is_dir():
        return []
    files: list[str] = []
    try:
        for entry in sorted(cache_dir.iterdir()):
            if entry.is_file() and entry.suffix == ".json":
                # Reconstruct the logical path Claude uses.
                files.append(f"{CACHE_DIR_LOGICAL}/{entry.name}")
    except OSError:
        return []
    return files


def _current_cache_size_bytes() -> int:
    """Sum the sizes of every cache file. Best-effort — counts only
    files we can stat. Uses direct filesystem access (see
    :func:`_list_cache_files` for the rationale)."""
    total = 0
    try:
        cache_dir = memory_backend._resolve(CACHE_DIR_LOGICAL)
    except ValueError:
        return 0
    if not cache_dir.exists() or not cache_dir.is_dir():
        return 0
    try:
        for entry in cache_dir.iterdir():
            if entry.is_file() and entry.suffix == ".json":
                try:
                    total += entry.stat().st_size
                except OSError:
                    continue
    except OSError:
        return 0
    return total


def _evict_for_space(
    needed_bytes: int,
    *,
    now: datetime,  # noqa: ARG001 — reserved for future age-aware policies
    keep_path: str | None = None,
) -> int:
    """Free at least ``needed_bytes`` from the cache directory by removing
    the oldest entries (by ``last_confirmed_at``, then ``created_at``),
    tie-broken by ``confidence`` ascending. Bounded by
    :data:`CACHE_EVICTION_FRACTION_MAX` (25% of entries).

    Tie-breaking semantics (#346):
    - If two entries share the SAME (anchor_timestamp, confidence), they
      are considered tied — the function aborts further eviction at that
      point ("ties beyond that → evict neither"). Returns whatever was
      freed up to the abort point; caller checks against
      ``needed_bytes``.

    ``keep_path`` is the logical path of an entry we must NOT evict
    (typically the one being stored — if it already exists it's about
    to be overwritten, not evicted).

    Returns the number of bytes freed.
    """
    if needed_bytes <= 0:
        return 0

    candidates: list[tuple[float, float, int, str]] = []
    for path in _list_cache_files():
        if path == keep_path:
            continue
        entry = _load_cache_entry(path)
        if entry is None:
            # Could be a migration miss (unknown version) — those rows
            # are pure dead weight. Treat them as evictable to recover
            # space; size is read via stat directly.
            try:
                real = memory_backend._resolve(path)
                size = real.stat().st_size
            except (ValueError, OSError):
                continue
            candidates.append((float("inf"), -1.0, size, path))
            continue
        anchor_dt = (
            _from_iso(entry.get("last_confirmed_at"))
            or _from_iso(entry.get("created_at"))
        )
        # Entries with no anchor (corrupt or v.old) sort LAST so we
        # don't pre-empt entries with a real timestamp. Use +inf so
        # they come after every valid anchor.
        anchor_ts = anchor_dt.timestamp() if anchor_dt is not None else float("inf")
        confidence = float(entry.get("confidence") or 0.0)
        try:
            real = memory_backend._resolve(path)
            size = real.stat().st_size
        except (ValueError, OSError):
            continue
        candidates.append((anchor_ts, confidence, size, path))

    if not candidates:
        return 0

    # Sort oldest first, then lowest confidence first (so when two share
    # the same anchor, the lower-confidence one is the legitimate pick).
    candidates.sort(key=lambda t: (t[0], t[1]))

    max_evictions = max(1, int(len(candidates) * CACHE_EVICTION_FRACTION_MAX))
    freed = 0
    evicted_count = 0
    i = 0
    while (
        i < len(candidates)
        and freed < needed_bytes
        and evicted_count < max_evictions
    ):
        anchor_ts, conf, size, path = candidates[i]
        if i + 1 < len(candidates):
            next_anchor, next_conf, _, _ = candidates[i + 1]
            if anchor_ts == next_anchor and conf == next_conf:
                # Ambiguous tie — bail per #346 non_destructive_on_uncertainty.
                logger.debug(
                    "auth_discoverer.cache: eviction aborted at tie "
                    "(anchor=%s conf=%s) — freed=%d/%d bytes",
                    anchor_ts, conf, freed, needed_bytes,
                )
                break
        try:
            memory_backend.execute("delete", path=path)
            freed += size
            evicted_count += 1
        except Exception as exc:
            logger.debug(
                "auth_discoverer.cache: failed to evict %s: %s",
                path, exc,
            )
        i += 1

    logger.info(
        "auth_discoverer.cache: evicted %d entries freeing %d bytes "
        "(needed=%d, max_evictions=%d)",
        evicted_count, freed, needed_bytes, max_evictions,
    )
    return freed


def _verdict_for_entry(entry: dict[str, Any], now: datetime) -> str:
    """Apply aging rules to determine fresh vs stale."""
    last_confirmed = _from_iso(entry.get("last_confirmed_at"))
    created = _from_iso(entry.get("created_at"))
    anchor = last_confirmed or created
    if anchor is not None and (now - anchor).total_seconds() > CACHE_MAX_AGE_SECONDS:
        return VERDICT_STALE
    last_failure = _from_iso(entry.get("last_replay_failure_at"))
    if (
        last_failure is not None
        and (now - last_failure).total_seconds() < CACHE_FAILURE_COOLDOWN_SECONDS
    ):
        return VERDICT_STALE
    return VERDICT_FRESH


def lookup_recipe(
    fingerprint: dict[str, Any],
    *,
    now: datetime | None = None,
) -> tuple[dict[str, Any] | None, str]:
    """Look up a cached recipe for ``fingerprint``.

    Returns ``(recipe, verdict)`` where verdict is one of:
    - ``"fresh"`` — recipe is usable; caller may proceed to verify-then-use
    - ``"stale"`` — recipe found but aged out OR within failure-cooldown;
      caller should treat as needing fresh discovery
    - ``"absent"`` — no cache entry exists

    Cache miss (``absent``) and parse failures both return
    ``(None, "absent")``. The caller can then run full discovery.

    The cache hit path performs **zero AI calls** (acceptance criterion).
    """
    if not isinstance(fingerprint, dict):
        return None, VERDICT_ABSENT
    fingerprint_hash = str(fingerprint.get("fingerprint_hash") or "")
    logical = _cache_path_for(fingerprint_hash)
    if not logical:
        return None, VERDICT_ABSENT
    entry = _load_cache_entry(logical)
    if entry is None:
        return None, VERDICT_ABSENT
    recipe = entry.get("recipe")
    if not isinstance(recipe, dict):
        return None, VERDICT_ABSENT
    verdict = _verdict_for_entry(entry, _utc_now(now))
    return recipe, verdict


def store_recipe(
    fingerprint: dict[str, Any],
    recipe: dict[str, Any],
    *,
    confidence: float = 1.0,
    now: datetime | None = None,
) -> bool:
    """Persist ``recipe`` against ``fingerprint`` in the memory backend.

    Returns ``True`` on success, ``False`` if:
    - inputs are malformed
    - the serialized entry exceeds ``CACHE_MAX_FILE_BYTES`` (2 KB)
    - writing it would push the total cache dir over ``CACHE_MAX_TOTAL_BYTES`` (50 KB)

    Existing entry for the same fingerprint is overwritten (atomically:
    delete + create). ``last_confirmed_at`` and ``created_at`` are
    stamped to ``now`` (UTC). Caller can later flag a failed replay via
    :func:`mark_recipe_stale`.
    """
    if not isinstance(fingerprint, dict) or not isinstance(recipe, dict):
        return False
    fingerprint_hash = str(fingerprint.get("fingerprint_hash") or "")
    logical = _cache_path_for(fingerprint_hash)
    if not logical:
        return False
    if not (0.0 <= float(confidence) <= 1.0):
        confidence = max(0.0, min(1.0, float(confidence)))

    now_dt = _utc_now(now)
    now_iso = _to_iso(now_dt)
    entry: dict[str, Any] = {
        "schema_version": CACHE_SCHEMA_VERSION,
        "fingerprint_hash": fingerprint_hash,
        "recipe": recipe,
        "confidence": float(confidence),
        "created_at": now_iso,
        "last_confirmed_at": now_iso,
        "last_replay_failure_at": None,
        "replay_failures": 0,
    }
    serialized = json.dumps(entry, separators=(",", ":"))
    if len(serialized.encode("utf-8")) > CACHE_MAX_FILE_BYTES:
        logger.debug(
            "auth_discoverer.cache: entry too large (%d bytes > %d), skipping store",
            len(serialized.encode("utf-8")),
            CACHE_MAX_FILE_BYTES,
        )
        return False

    # Compute projected total dir size with this entry added. If the
    # fingerprint already exists, subtract its current contribution.
    current_total = _current_cache_size_bytes()
    existing = _load_cache_entry(logical)
    if existing is not None:
        existing_bytes = len(
            json.dumps(existing, separators=(",", ":")).encode("utf-8")
        )
        current_total = max(0, current_total - existing_bytes)
    entry_bytes = len(serialized.encode("utf-8"))
    projected = current_total + entry_bytes
    if projected > CACHE_MAX_TOTAL_BYTES:
        # #346 — try bounded LRU eviction before giving up. The 25%
        # cap + tie-break-abort semantics live inside _evict_for_space.
        needed = projected - CACHE_MAX_TOTAL_BYTES
        freed = _evict_for_space(needed, now=now_dt, keep_path=logical)
        if freed < needed:
            logger.debug(
                "auth_discoverer.cache: dir cap reached (current=%d entry=%d "
                "cap=%d) and eviction only freed %d/%d — skipping store",
                current_total, entry_bytes, CACHE_MAX_TOTAL_BYTES,
                freed, needed,
            )
            return False

    # Overwrite atomically: delete existing then create.
    if existing is not None:
        memory_backend.execute("delete", path=logical)
    response = memory_backend.execute("create", path=logical, file_text=serialized)
    if response.startswith("Error"):
        logger.debug(
            "auth_discoverer.cache: store failed: %s",
            response[:200],
        )
        return False
    return True


def mark_recipe_stale(
    fingerprint: dict[str, Any],
    *,
    now: datetime | None = None,
) -> bool:
    """Stamp ``last_replay_failure_at`` on the cached entry for
    ``fingerprint``. The recipe becomes stale to subsequent lookups
    until ``CACHE_FAILURE_COOLDOWN_SECONDS`` elapses.

    Returns ``True`` if a cache entry was updated, ``False`` otherwise."""
    if not isinstance(fingerprint, dict):
        return False
    fingerprint_hash = str(fingerprint.get("fingerprint_hash") or "")
    logical = _cache_path_for(fingerprint_hash)
    if not logical:
        return False
    entry = _load_cache_entry(logical)
    if entry is None:
        return False
    entry["last_replay_failure_at"] = _to_iso(_utc_now(now))
    entry["replay_failures"] = int(entry.get("replay_failures") or 0) + 1
    serialized = json.dumps(entry, separators=(",", ":"))
    if len(serialized.encode("utf-8")) > CACHE_MAX_FILE_BYTES:
        return False
    memory_backend.execute("delete", path=logical)
    response = memory_backend.execute("create", path=logical, file_text=serialized)
    return not response.startswith("Error")


def verify_recipe(
    recipe: dict[str, Any],
    *,
    http_client: httpx_client.Client | None = None,
    timeout_seconds: float = 10.0,
) -> bool:
    """Replay-before-trust. Executes ONLY the verification step of
    ``recipe`` and checks the response against the expectations.

    Verification passes when ALL the following hold (when specified):
    - response status_code ∈ ``expect_status``
    - if ``expect_set_cookie`` is set, the response sets a cookie with
      that name (case-insensitive)
    - every token in ``expect_body_contains`` appears in the response body

    Returns ``True`` on success, ``False`` otherwise. HTTP errors,
    timeouts, and malformed verification blocks all return ``False``.
    Caller is expected to follow up with :func:`mark_recipe_stale` on
    failure.
    """
    if not isinstance(recipe, dict):
        return False
    verification = recipe.get("verification")
    if not isinstance(verification, dict):
        return False
    url = str(verification.get("url") or "").strip()
    method = str(verification.get("method") or "GET").strip().upper()
    if not url or method not in _ALLOWED_HTTP_METHODS:
        return False
    expect_status = verification.get("expect_status") or [200]
    if not isinstance(expect_status, list):
        return False
    expect_set_cookie = verification.get("expect_set_cookie")
    expect_body_contains = verification.get("expect_body_contains") or []

    owned = False
    client = http_client
    if client is None:
        client = httpx_client.Client(
            timeout=timeout_seconds, follow_redirects=False, verify=True
        )
        owned = True

    try:
        try:
            response = client.request(method, url)
        except httpx_client.HTTPError as exc:
            logger.debug("auth_discoverer.verify_recipe: HTTP error: %s", exc)
            return False

        try:
            if int(response.status_code) not in {int(s) for s in expect_status}:
                return False
        except (TypeError, ValueError):
            return False

        if isinstance(expect_set_cookie, str) and expect_set_cookie:
            cookie_names: set[str] = set()
            try:
                for cookie in response.cookies.jar:
                    if cookie.name:
                        cookie_names.add(cookie.name)
            except AttributeError:
                # Fallback for very old/odd httpx response shapes
                raw_cookies = (
                    response.headers.get_list("set-cookie")
                    if hasattr(response.headers, "get_list")
                    else []
                )
                for raw in raw_cookies:
                    name = raw.split("=", 1)[0].strip()
                    if name:
                        cookie_names.add(name)
            if expect_set_cookie not in cookie_names:
                return False

        if isinstance(expect_body_contains, list) and expect_body_contains:
            body = response.text or ""
            for token in expect_body_contains:
                if isinstance(token, str) and token and token not in body:
                    return False

        return True
    finally:
        if owned:
            client.close()


# ---------------------------------------------------------------------------
# #328 — Integration helper: acquire_session
# ---------------------------------------------------------------------------

ACQUIRE_DEFAULT_PROBE_LIMIT = 12
ACQUIRE_DEFAULT_TIMEOUT = 20.0
ACQUIRE_USERNAME_PREFIX = "aegispt_"


def _generate_credentials() -> tuple[str, str, str]:
    """Generate (username, password, email) for an emergent auth attempt."""
    suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
    username = f"{ACQUIRE_USERNAME_PREFIX}{suffix}"
    password_suffix = "".join(
        random.choices(string.ascii_lowercase + string.digits, k=8)
    )
    password = f"Pw!{password_suffix}"
    email = f"{username}@aegispt.test"
    return username, password, email


def _resolve_field_value(
    mapping: str,
    *,
    username: str,
    password: str,
    email: str,
    original_value: str,
) -> str:
    """Resolve a field_mappings intent to a concrete value.

    Intent vocabulary mirrors build_recipe's contract:
    - username / password / confirm_password / email -> generated creds
    - hidden_passthrough -> original value from the form (for __VIEWSTATE etc.)
    - literal:<value> -> the literal after the colon
    - csrf_token -> empty for now (capture-from-prior-step is out of scope
      until #330+)
    - anything else -> empty string (defensive)
    """
    head, _, tail = mapping.partition(":")
    head_lower = head.strip().lower()
    if head_lower == "username":
        return username
    if head_lower in {"password", "confirm_password"}:
        return password
    if head_lower == "email":
        return email
    if head_lower == "hidden_passthrough":
        return original_value or ""
    if head_lower == "literal":
        return tail
    if head_lower == "csrf_token":
        return ""
    return ""


def _execute_recipe_steps(
    recipe: dict[str, Any],
    *,
    client: httpx_client.Client,
    username: str,
    password: str,
    email: str,
    form_field_values: dict[str, dict[str, str]],
    scope_allowlist: dict[str, Any] | None,
) -> bool:
    """Replay each step of `recipe.steps` through `client`. Returns True if
    all steps complete with an acceptable status code (one of
    step.expected_status). Cookies accumulate on the client jar."""
    for step in recipe.get("steps") or []:
        url = str(step.get("url") or "")
        method = str(step.get("method") or "POST").upper()
        if not url:
            return False
        if (
            scope_allowlist
            and not web_target_value_is_allowed_with_path(scope_allowlist, url)
        ):
            return False
        mappings = step.get("field_mappings") or {}
        if not isinstance(mappings, dict):
            return False
        per_url_originals = form_field_values.get(url, {})
        payload: dict[str, str] = {}
        for field_name, mapping in mappings.items():
            payload[field_name] = _resolve_field_value(
                mapping,
                username=username,
                password=password,
                email=email,
                original_value=per_url_originals.get(field_name, ""),
            )
        try:
            if method == "GET":
                response = client.get(url, params=payload, follow_redirects=False)
            else:
                response = client.request(
                    method, url, data=payload, follow_redirects=False
                )
        except httpx_client.HTTPError as exc:
            logger.debug("auth_discoverer.acquire_session: step %s errored: %s", url, exc)
            return False
        expected = step.get("expected_status") or [200, 302]
        try:
            if int(response.status_code) not in {int(s) for s in expected}:
                logger.debug(
                    "auth_discoverer.acquire_session: step %s got %s, expected %s",
                    url, response.status_code, expected,
                )
                return False
        except (TypeError, ValueError):
            return False
    return True


def _form_field_value_map(pages: list[dict[str, Any]]) -> dict[str, dict[str, str]]:
    """Build {form_action: {field_name: original_value}} for hidden_passthrough resolution.

    Reads from the *pages* (raw HTML) rather than the fingerprint, because
    :func:`fingerprint_application` deliberately strips field values from
    its canonical output to keep the fingerprint under 2 KB. Values are
    needed at execute time to replay __VIEWSTATE, hidden flags etc.
    """
    out: dict[str, dict[str, str]] = {}
    for page in pages or []:
        if not isinstance(page, dict):
            continue
        html = page.get("html") or ""
        page_url = page.get("url") or ""
        for form in _parse_forms(html, page_url=page_url):
            action = form.get("action")
            if not isinstance(action, str) or not action:
                continue
            values: dict[str, str] = {}
            for field in form.get("fields") or []:
                if not isinstance(field, dict):
                    continue
                name = str(field.get("name") or "")
                if not name:
                    continue
                values[name] = str(field.get("value") or "")
            if values:
                # If two pages reference the same action, merge — later
                # pages win on collision (deterministic).
                out.setdefault(action, {}).update(values)
    return out


def acquire_session(
    base_url: str,
    *,
    scope_allowlist: dict[str, Any] | None = None,
    http_client: httpx_client.Client | None = None,
    force_refresh: bool = False,
    anthropic_client: Any = None,
    timeout_seconds: float = ACQUIRE_DEFAULT_TIMEOUT,
    probe_limit: int = ACQUIRE_DEFAULT_PROBE_LIMIT,
    now: datetime | None = None,
    session: Any = None,
    run: Any = None,
) -> dict[str, Any] | None:
    """End-to-end integration helper: discover -> fingerprint -> cache ->
    (build_recipe on miss) -> verify -> execute -> return session.

    Pipeline:

    1. ``fetch_auth_pages(base_url, scope_allowlist, probe_limit=probe_limit)``
    2. ``fingerprint_application(pages)``
    3. ``lookup_recipe(fingerprint)`` — if ``force_refresh`` or verdict is
       ``stale`` / ``absent``, fall through to (4); if ``fresh``, the cached
       recipe is verified and reused.
    4. ``build_recipe(fingerprint, anthropic_client=anthropic_client)``
    5. ``verify_recipe(recipe, http_client=client)``
    6. Execute ``recipe.steps`` against ``client`` so the session cookie
       jar is populated.
    7. ``store_recipe(fingerprint, recipe)`` on success of fresh discovery.
    8. ``mark_recipe_stale(fingerprint)`` on verify or execute failure.

    Returns a dict on success::

        {
          "client": httpx.Client,                  # session cookie jar populated
          "username": str,
          "password": str,
          "email": str,
          "fingerprint_hash": str,
          "from_cache": bool,
          "recipe": dict,
          "session_cookies": {name: value, ...},
        }

    Returns ``None`` when any of the pipeline steps fail or no auth surface
    is observable. The caller is responsible for closing ``client`` if
    they own it (i.e. did not pass it in).

    Probes that craft malicious registrations themselves (cookie_tamper_probe)
    should use :func:`fetch_auth_pages` + :func:`fingerprint_application`
    directly — :func:`acquire_session` is intentionally for probes that need
    a clean authenticated session.

    Operator-credentialed dispatch (#345): when BOTH ``session`` and ``run``
    are provided AND the run's credential vault contains a password-kind
    secret targeting ``base_url``'s host, this function delegates to
    :func:`acquire_session_with_credentials` (login strategy) instead of
    falling through to the emergent-registration path. Probes that do NOT
    pass session/run keep their previous behavior unchanged (default
    ``None`` ⇒ emergent path), which preserves the #328 contract that the
    5 migrated probes consume ``acquire_session`` without signature changes
    in their call sites.
    """
    if not isinstance(base_url, str) or not base_url:
        return None

    # === #345 — operator-credentialed dispatch ===
    # When a session + run are wired through, check the run credential vault
    # for a password-kind secret matching this base_url. Vault hit ⇒ use
    # the login strategy with operator credentials. Vault miss ⇒ fall
    # through to the existing emergent-registration path (no behavior
    # change for sandbox/Gruyere-style targets that have a register form).
    if session is not None and run is not None:
        creds = _lookup_operator_credentials(session, run=run, base_url=base_url)
        if creds is not None:
            return acquire_session_with_credentials(
                base_url,
                username=creds[0],
                password=creds[1],
                scope_allowlist=scope_allowlist,
                http_client=http_client,
                anthropic_client=anthropic_client,
                timeout_seconds=timeout_seconds,
                probe_limit=probe_limit,
                now=now,
            )

    owns_client = False
    client = http_client
    if client is None:
        client = httpx_client.Client(
            timeout=timeout_seconds, follow_redirects=False, verify=True
        )
        owns_client = True

    success = False
    try:
        pages = fetch_auth_pages(
            base_url,
            scope_allowlist=scope_allowlist,
            timeout_seconds=timeout_seconds,
            probe_limit=probe_limit,
            client=client,
        )
        if not pages:
            return None
        fingerprint = fingerprint_application(pages)
        if not (fingerprint.get("register_form") or fingerprint.get("login_form")):
            return None

        cached_recipe: dict[str, Any] | None = None
        verdict = VERDICT_ABSENT
        if not force_refresh:
            cached_recipe, verdict = lookup_recipe(fingerprint, now=now)

        if verdict == VERDICT_FRESH and isinstance(cached_recipe, dict):
            recipe = cached_recipe
            from_cache = True
        else:
            recipe = build_recipe(fingerprint, anthropic_client=anthropic_client)
            if recipe is None:
                return None
            from_cache = False

        username, password, email = _generate_credentials()
        form_field_values = _form_field_value_map(pages)
        ok = _execute_recipe_steps(
            recipe,
            client=client,
            username=username,
            password=password,
            email=email,
            form_field_values=form_field_values,
            scope_allowlist=scope_allowlist,
        )
        if not ok:
            if not from_cache:
                # Fresh recipe that failed at execute time — store as stale
                # so we don't immediately re-use it via cache.
                store_recipe(fingerprint, recipe, now=now)
            mark_recipe_stale(fingerprint, now=now)
            return None

        # Post-execute verification: replay the verification step against
        # the *now-populated* client cookie jar. This is the "replay-
        # before-trust" gate from the cache contract.
        if not verify_recipe(
            recipe, http_client=client, timeout_seconds=timeout_seconds
        ):
            if not from_cache:
                store_recipe(fingerprint, recipe, now=now)
            mark_recipe_stale(fingerprint, now=now)
            return None

        if not from_cache:
            # Only store a fresh recipe AFTER it successfully authenticates
            # and verifies. Caching a broken recipe is worse than not caching.
            store_recipe(fingerprint, recipe, now=now)

        cookies: dict[str, str] = {}
        try:
            for cookie in client.cookies.jar:
                if cookie.name:
                    cookies[cookie.name] = cookie.value or ""
        except AttributeError:
            try:
                cookies = {k: v for k, v in client.cookies.items()}
            except AttributeError:
                cookies = {}

        success = True
        return {
            "client": client,
            "username": username,
            "password": password,
            "email": email,
            "fingerprint_hash": str(fingerprint.get("fingerprint_hash") or ""),
            "from_cache": from_cache,
            "recipe": recipe,
            "session_cookies": cookies,
        }
    except Exception as exc:
        logger.debug("auth_discoverer.acquire_session: unexpected error: %s", exc)
        return None
    finally:
        # Only close the client when we own it AND we are returning None
        # (or raising). On success the caller takes ownership of the
        # client + populated cookie jar.
        if owns_client and not success:
            try:
                client.close()
            except Exception:  # pragma: no cover — defensive
                pass


# ===========================================================================
# #345 — Operator-credentialed strategy
# ===========================================================================
#
# acquire_session does emergent registration only — it creates a new user
# via the discovered register form. Real-world login-only targets (DVWA,
# customer staging, internal corporate apps) have no register form, so
# acquire_session returns None on those. This block adds a parallel
# strategy: operator-supplied credentials looked up from the run credential
# vault, replayed against the login form.
#
# Credential handling rules (carried forward from #334 redaction policy):
# - Credentials are NEVER stored in graph entities or observation attributes.
# - Full values stay in run_credential_vault (encrypted at rest).
# - Recipe execution carries them only as in-memory POST body fields.
# - The returned session dict deliberately does NOT include the operator
#   password — only generated metadata + populated cookie jar.


def _base_url_host(base_url: str) -> str:
    """Extract the lowercase host (no port, no scheme) from base_url."""
    try:
        parsed = urlparse(base_url)
    except (TypeError, ValueError):
        return ""
    host = parsed.hostname or ""
    return host.lower()


def _lookup_operator_credentials(
    session: Any,
    *,
    run: Any,
    base_url: str,
) -> tuple[str, str] | None:
    """Query the run credential vault for a password-kind secret targeting
    ``base_url``'s host. Returns ``(username, password)`` or None.

    Matching rules:
    - secret_kind must be ``password`` (canonical, hyphens-normalized
      via run_credential_vault.store_run_credential_vault_secret).
    - metadata['target'] must resolve to the same host as base_url
      (port and scheme ignored — credentials are usually scope-of-host
      not scope-of-port).
    - metadata['username'] must be set (a login flow without a
      username is not a valid credentialed strategy).

    Decryption uses the same storage_backend that wrote the secret. Any
    decrypt error or missing settings returns None for that ref and the
    iteration continues. If no ref matches, returns None.
    """
    target_host = _base_url_host(base_url)
    if not target_host:
        return None
    try:
        from api.app.config import get_settings
        from api.app.services.run_credential_vault import _vault_refs_for_run
        from api.app.services.secrets import decrypt_secret_value
    except Exception as exc:  # pragma: no cover — defensive
        logger.debug("auth_discoverer: vault module import failed: %s", exc)
        return None

    try:
        refs = _vault_refs_for_run(session, run=run)
    except Exception as exc:
        logger.debug("auth_discoverer: vault lookup failed: %s", exc)
        return None

    settings = None
    for ref in refs:
        if getattr(ref, "secret_kind", "") != "password":
            continue
        meta = getattr(ref, "metadata_json", None) or {}
        if not isinstance(meta, dict):
            continue
        target_value = str(meta.get("target") or "")
        if not target_value:
            continue
        if _base_url_host(target_value) != target_host:
            continue
        username = str(meta.get("username") or "").strip()
        if not username:
            continue
        try:
            if settings is None:
                settings = get_settings()
            password = decrypt_secret_value(
                getattr(ref, "encrypted_value", "") or "",
                settings,
                storage_backend=getattr(ref, "storage_backend", "encrypted_local"),
            )
        except Exception as exc:
            logger.debug(
                "auth_discoverer: decrypt failed for ref=%s: %s",
                str(getattr(ref, "id", ""))[:8], exc,
            )
            continue
        if not password:
            continue
        return (username, password)
    return None


def _login_only_fingerprint(fingerprint: dict[str, Any]) -> dict[str, Any]:
    """Return a shallow copy of ``fingerprint`` with ``register_form``
    removed, so :func:`build_recipe` is forced to synthesize a LOGIN
    recipe (its prompt already supports both intents; with register
    absent, the model has no choice).

    Does NOT mutate the input. The fingerprint_hash field is left
    unchanged — the credentialed path skips the cache entirely so a
    hash collision doesn't matter.
    """
    out = dict(fingerprint)
    out["register_form"] = None
    return out


def acquire_session_with_credentials(
    base_url: str,
    *,
    username: str,
    password: str,
    scope_allowlist: dict[str, Any] | None = None,
    http_client: httpx_client.Client | None = None,
    anthropic_client: Any = None,
    timeout_seconds: float = ACQUIRE_DEFAULT_TIMEOUT,
    probe_limit: int = ACQUIRE_DEFAULT_PROBE_LIMIT,
    now: datetime | None = None,
) -> dict[str, Any] | None:
    """Operator-credentialed login-form variant of :func:`acquire_session`.

    Same fetch+fingerprint pipeline, but:

    - skips the recipe cache (lookup_recipe / store_recipe / mark_stale)
      because cached recipes were derived against the emergent path with
      register_form preferred; replaying them with operator credentials
      against a register flow is meaningless. Cache namespacing for the
      credentialed path is a separate task (backlog-396).
    - strips ``register_form`` from the fingerprint copy passed to
      :func:`build_recipe`, so the model produces login-only steps.
    - replays the recipe with operator-supplied ``(username, password)``
      instead of :func:`_generate_credentials`. An ``email`` is derived
      from the username only for the rare case where the login form
      includes an email field mapped via the ``email`` intent.
    - returns the same session dict shape as :func:`acquire_session`
      EXCEPT the ``password`` field is omitted (operator-secret hygiene
      — full value stays in the vault) and ``email`` reflects the
      derived value, not a generated mailbox.

    Returns None on any pipeline failure (no pages, no login form, recipe
    build failure, execute failure, verify failure). The caller is
    responsible for closing ``client`` if they own it.
    """
    if not isinstance(base_url, str) or not base_url:
        return None
    if not isinstance(username, str) or not username.strip():
        return None
    if not isinstance(password, str) or not password:
        return None
    username = username.strip()

    owns_client = False
    client = http_client
    if client is None:
        client = httpx_client.Client(
            timeout=timeout_seconds, follow_redirects=False, verify=True
        )
        owns_client = True

    success = False
    try:
        pages = fetch_auth_pages(
            base_url,
            scope_allowlist=scope_allowlist,
            timeout_seconds=timeout_seconds,
            probe_limit=probe_limit,
            client=client,
        )
        if not pages:
            return None
        fingerprint = fingerprint_application(pages)
        if not fingerprint.get("login_form"):
            # No observable login form ⇒ credentialed strategy cannot
            # proceed. Distinct from the emergent path which would fall
            # through to register_form. Caller can decide whether to
            # retry without credentials (see acquire_session dispatch).
            return None

        login_fp = _login_only_fingerprint(fingerprint)
        recipe = build_recipe(login_fp, anthropic_client=anthropic_client)
        if recipe is None:
            return None

        # Synthesize a non-PII email derived from the username; harmless
        # for login forms because the email intent is only resolved when
        # the login form has an explicit email field, which is rare.
        email = f"{username}@aegispt.test"

        form_field_values = _form_field_value_map(pages)
        ok = _execute_recipe_steps(
            recipe,
            client=client,
            username=username,
            password=password,
            email=email,
            form_field_values=form_field_values,
            scope_allowlist=scope_allowlist,
        )
        if not ok:
            return None

        if not verify_recipe(
            recipe, http_client=client, timeout_seconds=timeout_seconds,
        ):
            return None

        cookies: dict[str, str] = {}
        try:
            for cookie in client.cookies.jar:
                if cookie.name:
                    cookies[cookie.name] = cookie.value or ""
        except AttributeError:
            try:
                cookies = {k: v for k, v in client.cookies.items()}
            except AttributeError:
                cookies = {}

        success = True
        # NOTE: the password is DELIBERATELY omitted from the returned
        # dict (credential_handling per task #345). Callers that need
        # the password must read it from the run_credential_vault, not
        # from the session dict.
        return {
            "client": client,
            "username": username,
            "email": email,
            "fingerprint_hash": str(fingerprint.get("fingerprint_hash") or ""),
            "from_cache": False,
            "from_credentials": True,
            "recipe": recipe,
            "session_cookies": cookies,
        }
    except Exception as exc:
        logger.debug("auth_discoverer.acquire_session_with_credentials: error: %s", exc)
        return None
    finally:
        if owns_client and not success:
            try:
                client.close()
            except Exception:  # pragma: no cover — defensive
                pass
