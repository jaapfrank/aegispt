"""Stack-aware path augmentation for the 5 #328-migrated probes.

#338 / backlog-400 — the hardcoded ``PROBE_PATHS`` catalogs that
``info_disclosure_probe`` and friends ship with are stack-agnostic
generics (``/dump``, ``/.env``, ``/backup.sql``, ...). On live Gruyere
2026-05-18 those covered 0% of the actual leak surface because
Gruyere's debug endpoint is ``/dump.gtl`` — stripped from the catalog
in #328 "for generality" and not replaced.

This module is the "look here too" layer the probes consult AT
RUNTIME, keyed on stack-family hints derived from prior ``target_intel``
observations:

    base_catalog = (...)  # the existing PROBE_PATHS
    extra = paths_for_stack(stack_hints, "debug-dump")
    full_catalog = base_catalog + extra

Per ``feedback_no_prescriptive_recipes``: the registry only carries
discovery PATH strings, never payloads or exploit recipes. The probes
still apply their existing detection heuristics to whatever response
each path returns. No app-instance-specific identifiers — only
stack-family-level paths.

Source of stack hints: ``target_intel`` runner emits
``EvidenceObservation`` rows with ``attributes_json['technology_stack']``
containing AI-generated stack-description strings (e.g. "Google App
Engine — Gruyere training app", "ASP.NET MVC", "Tomcat Servlet
Container"). The :func:`stack_hints_from_observations` normalizer
maps those raw strings onto the registry's key vocabulary
(``python_gruyere``, ``aspnet``, ``ruby_rails``, ...).
"""
from __future__ import annotations

from typing import Any

# --------------------------------------------------------------------------
# Categories the probes consume.
#
# Each of the 5 #328-migrated probes maps to one or two categories:
#   - info_disclosure_probe   →  "debug-dump"
#   - file_upload_probe       →  "file-upload-target"
#   - param_pollution_probe   →  "register-action"
#   - cookie_tamper_probe     →  "register-action"
#   - stored_xss_probe        →  "stored-xss-page"  (where stored XSS
#                                                    typically renders)
# --------------------------------------------------------------------------

_CAT_DEBUG_DUMP = "debug-dump"
_CAT_FILE_UPLOAD = "file-upload-target"
_CAT_REGISTER_ACTION = "register-action"
_CAT_STORED_XSS = "stored-xss-page"

KNOWN_CATEGORIES: frozenset[str] = frozenset({
    _CAT_DEBUG_DUMP,
    _CAT_FILE_UPLOAD,
    _CAT_REGISTER_ACTION,
    _CAT_STORED_XSS,
})

# --------------------------------------------------------------------------
# Registry: stack-hint → category → list of (path, label) tuples.
#
# Label is what the consuming probe stores in its result row to indicate
# WHY that path was tried. It mirrors the per-path label conventions in
# the existing PROBE_PATHS tuples (e.g. "debug-dump", "phpinfo",
# "config-leak"). Probes feed it back as the `category` field on
# findings so operators can group leaks by detection bucket.
# --------------------------------------------------------------------------

_STACK_PATH_REGISTRY: dict[str, dict[str, tuple[tuple[str, str], ...]]] = {
    # Google Gruyere — purpose-built training app, .gtl debug endpoints.
    "python_gruyere": {
        _CAT_DEBUG_DUMP: (
            ("/dump.gtl", "debug-dump"),
            ("/debug.gtl", "debug-dump"),
        ),
        _CAT_REGISTER_ACTION: (
            # signup form lives at /signup.gtl; the form action is
            # discovered via fingerprint, not seeded here.
            ("/signup.gtl", "register-form"),
        ),
        _CAT_STORED_XSS: (
            # Snippet store renders user-supplied HTML.
            ("/snippets.gtl", "snippet-store"),
        ),
    },
    # ASP.NET (WebForms + classic) — Elmah error log + Trace handler are
    # the canonical post-config leaks. /elmah.axd documented at
    # https://github.com/elmah/Elmah; /trace.axd at
    # https://learn.microsoft.com/en-us/previous-versions/aspnet/wwh16c6c.
    "aspnet": {
        _CAT_DEBUG_DUMP: (
            ("/elmah.axd", "elmah-leak"),
            ("/trace.axd", "asp-trace"),
            ("/Web.config", "config-leak"),
        ),
    },
    # ASP.NET MVC — same elmah surface plus the conventional debug
    # endpoint.
    "aspnet_mvc": {
        _CAT_DEBUG_DUMP: (
            ("/elmah.axd", "elmah-leak"),
            ("/trace.axd", "asp-trace"),
        ),
    },
    # PHP — phpinfo is the textbook info-disclosure path. /phpmyadmin/
    # is a frequently-exposed admin UI on misconfigured LAMP stacks.
    "php": {
        _CAT_DEBUG_DUMP: (
            ("/info.php", "phpinfo"),
            ("/phpinfo.php", "phpinfo"),
            ("/phpmyadmin/", "admin-ui"),
            ("/phpmyadmin/index.php", "admin-ui"),
        ),
    },
    "php_laravel": {
        _CAT_DEBUG_DUMP: (
            # Laravel's telescope debug UI when env=local was left on.
            ("/telescope", "laravel-telescope"),
            ("/_ignition/health-check", "laravel-ignition"),
        ),
    },
    # Java JSP / Servlet — Tomcat manager console is the canonical
    # post-default-creds leak vector.
    "java_jsp": {
        _CAT_DEBUG_DUMP: (
            ("/admin/console.jsp", "admin-console"),
            ("/manager/html", "tomcat-manager"),
            ("/manager/status", "tomcat-manager"),
            ("/host-manager/html", "tomcat-manager"),
        ),
    },
    "java_servlet": {
        _CAT_DEBUG_DUMP: (
            ("/manager/html", "tomcat-manager"),
            ("/manager/status", "tomcat-manager"),
            ("/jmx-console/", "jmx-console"),
        ),
    },
    # Node / Express — the .well-known/express-status convention
    # (express-status-monitor) plus the common health endpoint.
    "node_express": {
        _CAT_DEBUG_DUMP: (
            ("/.well-known/express-status", "express-status"),
            ("/status", "node-status"),
        ),
    },
    # Django — accounts/login often exposes the admin redirect; the
    # `/admin/` URL itself is the convention when DEBUG=False isn't set.
    "python_django": {
        _CAT_DEBUG_DUMP: (
            ("/admin/", "django-admin"),
            ("/admin/login/", "django-admin"),
        ),
    },
    "ruby_rails": {
        _CAT_DEBUG_DUMP: (
            ("/rails/info", "rails-info"),
            ("/rails/info/properties", "rails-info"),
            ("/rails/info/routes", "rails-info"),
        ),
    },
}

# --------------------------------------------------------------------------
# Normalizer: turn raw target_intel "technology_stack" strings into
# registry keys. The mapping is keyword-based — if a phrase contains a
# known token, we add the corresponding hint. Multi-hint outputs are
# possible (e.g. "Apache Tomcat with JSP" → both java_servlet AND
# java_jsp) and the probes use that natively (union of paths).
# --------------------------------------------------------------------------

_STACK_KEYWORD_HINTS: tuple[tuple[str, str], ...] = (
    ("gruyere", "python_gruyere"),
    ("asp.net mvc", "aspnet_mvc"),
    ("aspnet mvc", "aspnet_mvc"),
    ("asp.net", "aspnet"),
    ("aspnet", "aspnet"),
    ("rails", "ruby_rails"),
    ("django", "python_django"),
    ("laravel", "php_laravel"),
    ("symfony", "php"),
    ("express", "node_express"),
    ("node.js", "node_express"),
    ("nodejs", "node_express"),
    (".jsp", "java_jsp"),
    ("jsp ", "java_jsp"),
    ("jsp/", "java_jsp"),
    ("tomcat", "java_servlet"),
    ("servlet", "java_servlet"),
    ("jboss", "java_servlet"),
    ("wildfly", "java_servlet"),
    (".php", "php"),
    ("php ", "php"),
    ("php/", "php"),
    ("php-fpm", "php"),
)


def paths_for_stack(
    stack_hints: list[str] | None,
    category: str,
) -> list[tuple[str, str]]:
    """Return (path, label) tuples for ``category`` from the stack
    registry.

    Empty list when ``stack_hints`` is None / empty / unknown — caller's
    base catalog continues to drive discovery.

    Result is order-preserving (registry order per hint, then hint
    order) and deduplicated on path-string. Category is matched
    case-insensitive.
    """
    if not stack_hints:
        return []
    cat_normalized = (category or "").strip().lower()
    if cat_normalized not in KNOWN_CATEGORIES:
        return []
    out: list[tuple[str, str]] = []
    seen_paths: set[str] = set()
    for hint in stack_hints:
        normalized_hint = str(hint or "").strip().lower()
        if not normalized_hint:
            continue
        cat_map = _STACK_PATH_REGISTRY.get(normalized_hint)
        if not cat_map:
            continue
        for path, label in cat_map.get(cat_normalized, ()):
            if path in seen_paths:
                continue
            seen_paths.add(path)
            out.append((path, label))
    return out


def stack_hints_from_observations(
    observations: list[dict[str, Any]] | None,
) -> list[str]:
    """Normalize raw ``target_intel`` observation rows into the
    registry's stack-key vocabulary.

    Reads ``attributes_json['technology_stack']`` (list of free-text
    strings) and matches them keyword-by-keyword against
    :data:`_STACK_KEYWORD_HINTS`. Output is deduplicated and sorted for
    deterministic ordering across runs.

    Empty list when ``observations`` is None, empty, or contains no
    matchable strings.

    The probes consume this via the orchestrator wiring at
    ``workers/orchestration/tasks.py``; tests construct synthetic
    observation dicts to exercise the normalization without a DB.
    """
    if not observations:
        return []
    hits: set[str] = set()
    for obs in observations:
        if not isinstance(obs, dict):
            continue
        attrs = obs.get("attributes") or obs.get("attributes_json") or {}
        if not isinstance(attrs, dict):
            continue
        tech = attrs.get("technology_stack") or attrs.get("stack_hints") or []
        if isinstance(tech, str):
            tech = [tech]
        if not isinstance(tech, list):
            continue
        joined = " ".join(str(t).lower() for t in tech if t)
        if not joined:
            continue
        for needle, hint in _STACK_KEYWORD_HINTS:
            if needle in joined:
                hits.add(hint)
    return sorted(hits)


__all__ = [
    "KNOWN_CATEGORIES",
    "paths_for_stack",
    "stack_hints_from_observations",
]
