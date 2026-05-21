"""WebSearchTool + WebFetchTool — read-only external information access."""
from __future__ import annotations

from typing import Any

import httpx

from api.app.agents.agent_tools.registry import (
    ToolResult,
    _layer0_dispatch_check,
    _rebuild_schemas,
    _register,
)


class WebSearchTool:
    """Picker-facing wrapper around backlog-416 external_knowledge lookups.

    The picker can ask for CVE/exploit hints by CVE id or product/version.
    Returns the marker-wrapped envelopes so the picker cannot mistake a
    KB result for proof of impact.
    """

    name = "web_search"

    def schema(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": (
                "Search ExploitDB / NVD / CISA KEV for hints. Returns "
                "marker-wrapped envelopes ([KB HINT, VERIFY BEFORE USE — "
                "NEVER CLAIM IMPACT]). Read-only."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "cve_id": {"type": "string", "description": "CVE id like CVE-2024-12345."},
                    "product": {"type": "string", "description": "Product name (e.g. apache, wordpress)."},
                    "version": {"type": "string", "description": "Optional version string."},
                },
            },
        }

    def execute(self, arguments: dict[str, Any], *, run: Any, session: Any | None = None) -> ToolResult:  # noqa: ARG002
        try:
            from api.app.services.external_knowledge import lookup_exploits  # noqa: E402
        except ImportError as exc:
            return ToolResult.error(f"external_knowledge unavailable: {exc}")
        cve_id = arguments.get("cve_id") or None
        product = arguments.get("product") or None
        version = arguments.get("version") or None
        try:
            hits = lookup_exploits(cve_id=cve_id, product=product, version=version)
        except Exception as exc:  # noqa: BLE001
            return ToolResult.error(f"lookup failed: {exc}")
        envelopes = [h.to_picker_envelope() for h in hits[:5]]
        body = "\n".join(
            f"- {env['source']}: {env['title']} (score={env['applicability_score']}) {env['source_url']}"
            for env in envelopes
        ) or "(no hits)"
        return ToolResult.success(body, metadata={"hit_count": len(envelopes)})


class WebFetchTool:
    """HTTP GET an in-scope URL (read-only). Routes through Layer 0 so the
    picker cannot fetch outside the engagement scope.
    """

    name = "web_fetch"

    def schema(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": (
                "GET a URL within the approved engagement scope and return the "
                "response body (truncated to 8 KB). Use this BEFORE picking a "
                "runner to read a specific endpoint's actual content."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Absolute URL within scope."},
                    "method": {"type": "string", "enum": ["GET", "HEAD"], "default": "GET"},
                },
                "required": ["url"],
            },
        }

    def execute(self, arguments: dict[str, Any], *, run: Any, session: Any | None = None) -> ToolResult:
        url = str(arguments.get("url") or "").strip()
        method = str(arguments.get("method") or "GET").upper()
        if not url:
            return ToolResult.error("empty url")
        if method not in {"GET", "HEAD"}:
            return ToolResult.denied(f"method {method!r} not allowed (GET/HEAD only)")
        ok, deny_reason = _layer0_dispatch_check(
            run=run, session=session, runner_name="agent_tool.web_fetch",
            target=url, tier="passive",
        )
        if not ok:
            return ToolResult.denied(deny_reason or "web_fetch denied by Layer 0")
        try:
            with httpx.Client(timeout=10.0, follow_redirects=False, verify=False) as client:
                resp = client.request(method, url)
            body = (resp.text or "")[:8192]
            return ToolResult.success(
                body,
                metadata={
                    "status_code": resp.status_code,
                    "content_type": resp.headers.get("content-type", ""),
                    "bytes": len(body),
                },
            )
        except httpx.HTTPError as exc:
            return ToolResult.error(f"http error: {exc}")


_register(WebSearchTool())
_register(WebFetchTool())
_rebuild_schemas()

__all__ = ["WebFetchTool", "WebSearchTool"]
