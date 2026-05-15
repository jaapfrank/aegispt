"""Client-side HTTP fetch tool for the AI loop.

Lets Claude read the actual content of the target site (HTML, headers, JSON)
before deciding which tools to pick or what exec_plan to write.

Restrictions:
- URL must pass the run's scope allowlist (host AND path level).
- GET only. No POST/PUT/etc. — that's what exec-plan is for.
- Body capped to ~4 KB, headers compacted to safe whitelist.
- Per-call timeout, no redirect following beyond same-host.
"""
from __future__ import annotations

import logging
from typing import Any

import httpx

from api.app.services.runs import web_target_value_is_allowed_with_path

logger = logging.getLogger(__name__)

# Headers we expose to Claude. Anything else is noise or PII-risk.
_HEADER_ALLOWLIST = {
    "server",
    "x-powered-by",
    "content-type",
    "content-length",
    "set-cookie",
    "x-frame-options",
    "content-security-policy",
    "strict-transport-security",
    "x-content-type-options",
    "x-runtime",
    "x-aspnet-version",
    "via",
    "location",
}

_MAX_BODY_BYTES = 4096
_FETCH_TIMEOUT = 15.0


def execute(url: str, scope_allowlist: dict[str, Any] | None) -> str:
    """Fetch a URL after scope validation. Returns a human-readable string
    for Claude (status + headers + body excerpt). Errors are returned as
    strings rather than raised so the tool_result completes.
    """
    if not isinstance(url, str) or not url.strip():
        return "Error: url must be a non-empty string"
    target = url.strip()
    if not target.lower().startswith(("http://", "https://")):
        return f"Error: url must start with http:// or https:// (got {target[:60]!r})"

    allowed = web_target_value_is_allowed_with_path(scope_allowlist or {}, target)
    if not allowed:
        return (
            f"Error: url out of scope: {target}\n"
            "The scope allowlist restricts which paths under the target host are allowed. "
            "Use a URL that falls under the approved instance path."
        )

    try:
        with httpx.Client(timeout=_FETCH_TIMEOUT, follow_redirects=False) as client:
            response = client.get(target)
    except httpx.TimeoutException:
        return f"Error: timeout fetching {target} (>{_FETCH_TIMEOUT}s)"
    except httpx.RequestError as exc:
        return f"Error: request failed for {target}: {exc}"

    header_lines: list[str] = []
    for key, value in response.headers.items():
        if key.lower() in _HEADER_ALLOWLIST:
            header_lines.append(f"{key}: {str(value)[:200]}")

    body = response.text or ""
    truncated = False
    if len(body.encode("utf-8", errors="replace")) > _MAX_BODY_BYTES:
        body = body.encode("utf-8", errors="replace")[:_MAX_BODY_BYTES].decode(
            "utf-8", errors="replace"
        )
        truncated = True

    parts = [
        f"GET {target}",
        f"HTTP/{response.http_version} {response.status_code} {response.reason_phrase}",
        "",
        "--- headers ---",
        "\n".join(header_lines) if header_lines else "(no whitelisted headers)",
        "",
        "--- body" + (" (truncated to 4KB)" if truncated else "") + " ---",
        body,
    ]
    return "\n".join(parts)
