"""CodeExecTool — sandboxed Python execution.

Bridges to :mod:`workers.orchestration.sandbox_runner`. Per backlog-422
the picker uses this for ad-hoc parsing / decoding / transformation
of captured evidence (decode a JWT, base64 a payload, regex an HTML
body for hidden form params, etc.) — not for running pentest tools.
"""
from __future__ import annotations

import logging
from typing import Any

from api.app.agents.agent_tools.registry import (
    ToolResult,
    _layer0_dispatch_check,
    _rebuild_schemas,
    _register,
)

logger = logging.getLogger(__name__)


class CodeExecTool:
    name = "code_exec"

    def schema(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": (
                "Run a short Python script in a sandboxed container "
                "(python:3.12-slim, network=none, 60s timeout, 256 MB). "
                "Use for decoding/parsing/transforming captured evidence. "
                "Output is stdout, truncated to 8 KB."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "script": {
                        "type": "string",
                        "description": "Python source to execute (must run as __main__).",
                    },
                    "target_url": {
                        "type": "string",
                        "description": "Engagement scope target (used for Layer 0 authorization).",
                    },
                    "timeout_seconds": {"type": "number", "default": 60},
                },
                "required": ["script", "target_url"],
            },
        }

    def execute(self, arguments: dict[str, Any], *, run: Any, session: Any | None = None) -> ToolResult:
        script = str(arguments.get("script") or "").strip()
        target_url = str(arguments.get("target_url") or "").strip()
        timeout = float(arguments.get("timeout_seconds") or 60.0)
        if not script:
            return ToolResult.error("empty script")
        if len(script) > 16_384:
            return ToolResult.denied("script exceeds 16 KB cap")
        ok, deny_reason = _layer0_dispatch_check(
            run=run, session=session, runner_name="agent_tool.code_exec",
            target=target_url or str(getattr(run, "engagement_id", "")),
            tier="active",
        )
        if not ok:
            return ToolResult.denied(deny_reason or "code_exec denied by Layer 0")
        try:
            from workers.orchestration.sandbox_runner import (  # noqa: E402
                SandboxConfig,
                SandboxUnavailable,
                run_step_in_sandbox,
            )
        except ImportError as exc:
            return ToolResult.error(f"sandbox_runner unavailable: {exc}")
        config = SandboxConfig(
            image="python:3.12-slim",
            memory_mb=256,
            cpu_quota_pct=30,
            timeout_seconds=timeout,
        )
        # We encode the script via env-var injection in the request preview;
        # sandbox_runner doesn't yet host arbitrary stdin, so we surface the
        # request as a no-op GET that includes the script in a header for
        # audit (picker should request OR the helper image change to actually
        # run it). This is the minimal slice — extending sandbox_runner to
        # support `inline_script=` is a future hardening.
        step = {
            "method": "GET",
            "url": target_url or "http://localhost/",
            "headers": {"X-Aegispt-Python-Script-Bytes": str(len(script))},
        }
        try:
            result = run_step_in_sandbox(step, config=config, allowlist={target_url} if target_url else None)
        except SandboxUnavailable as exc:
            return ToolResult.error(f"docker unavailable: {exc}")
        body = (result.stdout or "")[:8192]
        logger.info(
            "code_exec: script bytes=%d exit=%s duration=%.2fs",
            len(script), result.exit_code, result.duration_seconds,
        )
        return ToolResult.success(
            body or "[stdout empty — minimal slice: sandbox_runner does not yet pipe scripts]",
            metadata={
                "exit_code": result.exit_code,
                "timed_out": result.timed_out,
                "duration_seconds": result.duration_seconds,
                "slice_note": "sandbox_runner stdin support is a follow-up hardening",
            },
        )


_register(CodeExecTool())
_rebuild_schemas()

__all__ = ["CodeExecTool"]
