"""Discovered attack-surface backlog — Track 0 (recon→action loop closure).

Operator diagnosis 2026-06-03 (Gruyere run 15357dd6): the loop DISCOVERS endpoints
(20 found, incl. /admin, /upload.gtl, /saveprofile) but does NOT act on them — they are
emitted as passive "Hidden Endpoint Discovered" findings and dropped. The picker never
pursues them, so multi-step "cause→follow-up" never happens.

This module turns those discoveries into an explicit BACKLOG the picker is directed to
work through — every discovered endpoint becomes a target to actively test (access-control,
injection, IDOR, upload→RCE, traversal/files-behind), not a deliverable.

Pure functions over finding-like dicts so they are unit-testable without a live run.
"""
from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

# Endpoint-discovery findings emitted by content-discovery / recon.
_ENDPOINT_TITLE_RE = re.compile(r"endpoint discovered|hidden endpoint|discovered (?:path|route|endpoint)", re.I)

# Endpoints whose path hints at a high-value primitive — surfaced first so the picker
# pursues the impactful ones (admin panel, file upload, profile/stored-XSS sink, …).
_HIGH_VALUE_HINTS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"/admin|/manage|/dashboard|/console|/wp-admin", re.I), "access-control / direct-admin"),
    (re.compile(r"upload|/file|/import|/avatar|/attach", re.I), "unrestricted-upload → RCE"),
    (re.compile(r"profile|account|saveacct|saveprofile|settings", re.I), "stored-XSS / account-takeover chain"),
    (re.compile(r"/api|/graphql|/rest|/v[0-9]", re.I), "API enumeration / IDOR / authz"),
    (re.compile(r"redirect|return|next|url=|callback", re.I), "open-redirect / SSRF"),
    (re.compile(r"\.\.|traversal|download|/static|/files?/", re.I), "path-traversal / files-behind"),
    (re.compile(r"backup|\.bak|\.old|\.zip|\.sql|\.git|\.env", re.I), "sensitive-file disclosure"),
]


def _endpoint_of(finding: dict[str, Any]) -> str | None:
    """Best-effort extraction of the endpoint URL/path from an endpoint finding."""
    title = str(finding.get("title") or "")
    if not _ENDPOINT_TITLE_RE.search(title):
        return None
    ep = str(finding.get("target_id") or "").strip()
    if not ep:
        # fall back to the first URL in the summary
        m = re.search(r"https?://[^\s'\"]+", str(finding.get("summary") or ""))
        ep = m.group(0) if m else ""
    return ep or None


def _classify(endpoint: str) -> str:
    path = (urlparse(endpoint).path or endpoint) + "?" + (urlparse(endpoint).query or "")
    for rx, label in _HIGH_VALUE_HINTS:
        if rx.search(path):
            return label
    return "probe: params / auth / injection / IDOR"


def discovered_attack_surface(findings: list[dict[str, Any]]) -> list[dict[str, str]]:
    """Distinct discovered endpoints + a suggested probe focus, high-value first.

    `findings` is a list of dicts with at least `title` and `target_id` (and optionally
    `summary`). Returns [{"endpoint": url, "focus": label}], deduped, ordered so the
    high-value endpoints (admin/upload/profile/api/...) come first.
    """
    seen: dict[str, str] = {}
    for f in findings:
        ep = _endpoint_of(f)
        if not ep or ep in seen:
            continue
        seen[ep] = _classify(ep)
    # high-value (non-generic focus) first, then generic, stable within group
    items = [{"endpoint": ep, "focus": focus} for ep, focus in seen.items()]
    items.sort(key=lambda it: it["focus"].startswith("probe:"))
    return items


def render_attack_surface_block(findings: list[dict[str, Any]], *, cap: int = 30) -> str:
    """Render the PENDING ATTACK SURFACE block for the picker's decision context.

    Empty string when nothing discovered yet (so it adds no noise on a fresh run).
    """
    surface = discovered_attack_surface(findings)
    if not surface:
        return ""
    lines = [
        "=== PENDING ATTACK SURFACE — actively test EACH (do NOT stop while any remain) ===",
        "These endpoints were DISCOVERED but not yet exploited. A discovered endpoint is a",
        "TODO, not a deliverable. For each, pursue to IMPACT (admin/takeover/flag), then move on:",
    ]
    for it in surface[:cap]:
        lines.append(f"  - {it['endpoint']}  →  {it['focus']}")
    if len(surface) > cap:
        lines.append(f"  - … {len(surface) - cap} more discovered endpoints (test these too)")
    lines.append("")
    return "\n".join(lines)


def attack_surface_block_for_run(run: Any) -> str:
    """Adapter: render the backlog block from a Run ORM object's findings.

    Best-effort + exception-safe (recon/picker context assembly must never crash on a
    missing relationship). Returns "" when there is nothing discovered yet.
    """
    try:
        findings = []
        for f in (getattr(run, "findings", None) or []):
            findings.append({
                "title": str(getattr(f, "title", "") or ""),
                "target_id": str(getattr(f, "target_id", "") or ""),
                "summary": str(getattr(f, "summary", "") or ""),
            })
        return render_attack_surface_block(findings)
    except Exception:  # noqa: BLE001
        return ""
