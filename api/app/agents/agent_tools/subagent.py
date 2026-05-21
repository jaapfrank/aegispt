"""SubagentSpawnTool — delegates to backlog-415 MetaCoordinator."""
from __future__ import annotations

from typing import Any

from api.app.agents.agent_tools.registry import (
    ToolResult,
    _rebuild_schemas,
    _register,
)


class SubagentSpawnTool:
    """Allows the picker to delegate a step to a specialist instead of
    picking a runner directly. Routes through
    :class:`api.app.agents.coordinator.MetaCoordinator` — the per-agent
    ACL governs which runners the spawned specialist may dispatch.

    Per ``no_runtime_self_modification`` (backlog-415): this tool does NOT
    let the picker rewrite a specialist's prompt — it only invokes the
    delegation flow with the currently-published prompts. Prompt updates
    still require ``approve_prompt_change``.
    """

    name = "subagent_spawn"

    def schema(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": (
                "Delegate to one of the 6 specialists (recon, hypothesis, "
                "exploit_dev, validator, memorist, reporter, reflector). "
                "Pass intent + confidence; coordinator decides actual routing."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "intent": {
                        "type": "string",
                        "enum": [
                            "need_recon",
                            "need_hypothesis_test",
                            "need_multi_step_exploit",
                            "need_validation",
                            "need_memory_lookup",
                            "need_report",
                            "need_reflection",
                        ],
                    },
                    "coordinator_confidence": {
                        "type": "number",
                        "description": "Picker's own confidence in handling the step (0-1). Below 0.70 triggers delegation.",
                    },
                    "context_hint": {
                        "type": "string",
                        "description": "Short context for the specialist (≤200 chars).",
                    },
                },
                "required": ["intent", "coordinator_confidence"],
            },
        }

    def execute(self, arguments: dict[str, Any], *, run: Any, session: Any | None = None) -> ToolResult:  # noqa: ARG002
        intent = str(arguments.get("intent") or "").strip()
        confidence = float(arguments.get("coordinator_confidence") or 0.5)
        context_hint = str(arguments.get("context_hint") or "")[:200]
        try:
            from api.app.agents.coordinator import MetaCoordinator  # noqa: E402
        except ImportError as exc:
            return ToolResult.error(f"coordinator unavailable: {exc}")
        coord = MetaCoordinator(run_id=str(getattr(run, "id", "")))
        decision = coord.decide(intent=intent, coordinator_confidence=confidence)
        if decision.delegate_to is None:
            return ToolResult.success(
                f"coordinator handles directly: {decision.reasoning}",
                metadata={
                    "delegated": False,
                    "confidence": confidence,
                    "intent": intent,
                    "context_hint": context_hint,
                },
            )
        return ToolResult.success(
            f"delegated to specialist {decision.delegate_to.value} (intent={intent}, confidence={confidence:.2f})\n"
            f"reasoning: {decision.reasoning}\n"
            f"context_hint: {context_hint or '(none)'}",
            metadata={
                "delegated": True,
                "specialist": decision.delegate_to.value,
                "confidence": confidence,
                "intent": intent,
            },
        )


_register(SubagentSpawnTool())
_rebuild_schemas()

__all__ = ["SubagentSpawnTool"]
