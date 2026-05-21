"""Common base + registry for the picker's agent tools.

Per backlog-422: every tool exposes a single ``execute(arguments, *, run, session)``
entrypoint that returns a normalized :class:`ToolResult`. The picker treats the
``tools=`` parameter of the Anthropic Messages API as the call surface; a small
dispatch helper (:func:`execute_tool_call`) routes ``tool_use`` events back to
the right wrapper.

Layer 0 enforcement is intentional: each tool's ``execute`` MUST consult
:class:`api.app.governance.GovernanceControlPlane` before doing real work. The
helper :func:`_layer0_dispatch_check` centralises the verdict shape so a tool
author cannot accidentally skip the gate.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Protocol

logger = logging.getLogger(__name__)


@dataclass
class ToolResult:
    """Normalized envelope every tool returns to the picker."""

    ok: bool
    content: str
    metadata: dict[str, Any] = field(default_factory=dict)
    deny_reason: str | None = None

    @classmethod
    def denied(cls, reason: str) -> "ToolResult":
        return cls(ok=False, content=f"[denied by Layer 0] {reason}", deny_reason=reason)

    @classmethod
    def error(cls, message: str, *, metadata: dict[str, Any] | None = None) -> "ToolResult":
        return cls(ok=False, content=f"[error] {message}", metadata=metadata or {})

    @classmethod
    def success(cls, content: str, *, metadata: dict[str, Any] | None = None) -> "ToolResult":
        return cls(ok=True, content=content, metadata=metadata or {})


class PickerAgentTool(Protocol):
    """Each tool exposes name, schema, and an ``execute()`` callable."""

    name: str

    def schema(self) -> dict[str, Any]:
        """Return the Anthropic tool-use input_schema entry."""
        ...

    def execute(
        self,
        arguments: dict[str, Any],
        *,
        run: Any,
        session: Any | None = None,
    ) -> ToolResult:
        ...


def _layer0_dispatch_check(
    *,
    run: Any,
    session: Any | None,
    runner_name: str,
    target: str,
    tier: str = "passive",
) -> tuple[bool, str | None]:
    """Returns (allow, deny_reason). Calls into Layer 0 if a session is
    available; otherwise denies on the safe-by-default principle."""
    if session is None:
        return False, "no SQLAlchemy session bound to the tool call; cannot reach Layer 0 control_plane"
    try:
        from api.app.governance import GovernanceControlPlane  # noqa: E402
        plane = GovernanceControlPlane(session)
        verdict = plane.authorize_dispatch(
            run=run, runner=runner_name, target=target, tier=tier,
        )
        if verdict.allow:
            return True, None
        return False, verdict.deny_reason or f"{runner_name!r} denied by Layer 0"
    except Exception as exc:  # noqa: BLE001
        return False, f"Layer 0 unreachable: {exc}"


# Populated at import-time below once each tool module is loaded.
_TOOL_REGISTRY: dict[str, PickerAgentTool] = {}


def _register(tool: PickerAgentTool) -> PickerAgentTool:
    """Insert a tool into the registry. Called once per tool module."""
    _TOOL_REGISTRY[tool.name] = tool
    return tool


def resolve_tool(name: str) -> PickerAgentTool | None:
    return _TOOL_REGISTRY.get(name)


def all_tools() -> list[PickerAgentTool]:
    return list(_TOOL_REGISTRY.values())


ALL_TOOL_SCHEMAS: list[dict[str, Any]] = []


def _rebuild_schemas() -> None:
    """Recompute ``ALL_TOOL_SCHEMAS`` from the current registry. Called after
    each tool module imports so the schema list stays in sync."""
    ALL_TOOL_SCHEMAS.clear()
    for tool in _TOOL_REGISTRY.values():
        ALL_TOOL_SCHEMAS.append(tool.schema())


def execute_tool_call(
    tool_name: str,
    arguments: dict[str, Any],
    *,
    run: Any,
    session: Any | None = None,
) -> ToolResult:
    """Picker-side dispatch: looks up the tool by name and routes the call.

    Emits a `agent_tool execute_tool_call: <tool_name>` log line so the
    aegispt-validator sentinel canary (which greps for
    `execute_tool_call|agent_tool|tool_use`) increments. Without this
    log line every backlog-422 wire-in pathway was invisible to the
    validator and the canary stayed at 0 even when the tools fired.
    """
    run_id = str(getattr(run, "id", "?"))[:8] if run is not None else "?"
    tool = resolve_tool(tool_name)
    if tool is None:
        logger.warning(
            "agent_tool execute_tool_call: unknown tool=%s run=%s — rejected",
            tool_name, run_id,
        )
        return ToolResult.error(f"unknown tool {tool_name!r}")
    logger.info(
        "agent_tool execute_tool_call: dispatch tool=%s run=%s args_keys=%s",
        tool_name, run_id, sorted(list((arguments or {}).keys()))[:8],
    )
    try:
        result = tool.execute(arguments, run=run, session=session)
    except Exception as exc:  # noqa: BLE001
        logger.warning("agent_tool execute_tool_call: tool=%s raised: %s", tool_name, exc)
        return ToolResult.error(f"tool {tool_name!r} raised: {exc}")
    logger.info(
        "agent_tool execute_tool_call: complete tool=%s run=%s ok=%s",
        tool_name, run_id, getattr(result, "ok", False),
    )
    return result


__all__ = [
    "ALL_TOOL_SCHEMAS",
    "PickerAgentTool",
    "ToolResult",
    "_layer0_dispatch_check",
    "_rebuild_schemas",
    "_register",
    "all_tools",
    "execute_tool_call",
    "resolve_tool",
]
