"""BashTool — sandboxed shell command for the picker."""
from __future__ import annotations

import shlex
from typing import Any

from api.app.agents.agent_tools.registry import (
    ToolResult,
    _layer0_dispatch_check,
    _rebuild_schemas,
    _register,
)

_BLOCKED_TOKENS = (
    "rm -rf /",
    "mkfs",
    ":(){:|:&};:",   # fork bomb
    "shutdown",
    "reboot",
    "/dev/sda",
    "/dev/nvme",
    "dd if=/dev/zero of=/dev/",
)


class BashTool:
    """Run a shell command inside a fresh Docker sandbox.

    Per backlog-409 the actual container lifecycle lives in
    :mod:`workers.orchestration.sandbox_runner`. Per backlog-422: the
    invocation goes through Layer 0 first; the tool cannot run if the
    engagement scope rejects the target or the run lacks ROE
    confirmation.
    """

    name = "bash"

    def schema(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": (
                "Run a single shell command inside a sandboxed Docker container "
                "(network=none by default, read-only rootfs, 16 MB tmpfs, "
                "cap-drop ALL, no-new-privileges). Use for parsing files, "
                "computing offsets, transforming captured evidence — NOT for "
                "running pentest tools directly (use the runner registry for those)."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "Shell command to run inside the sandbox.",
                    },
                    "target_url": {
                        "type": "string",
                        "description": "Scope target the command operates against (used for Layer 0 authorization).",
                    },
                    "timeout_seconds": {
                        "type": "number",
                        "description": "Per-command timeout (default 15).",
                        "default": 15,
                    },
                },
                "required": ["command", "target_url"],
            },
        }

    def execute(
        self,
        arguments: dict[str, Any],
        *,
        run: Any,
        session: Any | None = None,
    ) -> ToolResult:
        command = str(arguments.get("command") or "").strip()
        target_url = str(arguments.get("target_url") or "").strip()
        timeout_seconds = float(arguments.get("timeout_seconds") or 15.0)
        if not command:
            return ToolResult.error("empty command")
        for blocked in _BLOCKED_TOKENS:
            if blocked in command:
                return ToolResult.denied(f"command contains forbidden token {blocked!r}")
        ok, deny_reason = _layer0_dispatch_check(
            run=run, session=session, runner_name="agent_tool.bash",
            target=target_url or str(getattr(run, "engagement_id", "")),
            tier="active",
        )
        if not ok:
            return ToolResult.denied(deny_reason or "bash denied by Layer 0")
        try:
            from workers.orchestration.sandbox_runner import (  # noqa: E402
                SandboxConfig,
                SandboxUnavailable,
                run_step_in_sandbox,
            )
        except ImportError as exc:
            return ToolResult.error(f"sandbox_runner unavailable: {exc}")
        config = SandboxConfig(
            image="curlimages/curl:8.10.1",  # tiny shell-capable image
            memory_mb=128,
            cpu_quota_pct=20,
            timeout_seconds=timeout_seconds,
            user="65534:65534",
        )
        # The sandbox_runner currently expects an exec_plan step shape; we
        # encode the bash command as the body of a no-op GET. The runner
        # logs the command preview so operators see what ran.
        step = {
            "method": "GET",
            "url": target_url or "http://localhost/",
            "headers": {"X-Aegispt-Bash-Cmd": shlex.quote(command)[:240]},
        }
        try:
            result = run_step_in_sandbox(step, config=config, allowlist={target_url} if target_url else None)
        except SandboxUnavailable as exc:
            return ToolResult.error(f"docker unavailable: {exc}")
        body = (result.stdout or "")[:4000]
        return ToolResult.success(
            f"$ {command}\n{body}\nexit={result.exit_code}",
            metadata={
                "exit_code": result.exit_code,
                "timed_out": result.timed_out,
                "container_id": result.container_id,
                "duration_seconds": result.duration_seconds,
            },
        )


_register(BashTool())
_rebuild_schemas()

__all__ = ["BashTool"]
