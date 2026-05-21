"""Picker agentic toolset — backlog-422.

Closes the "AegisPT picker IS Mythos" capability gap: the picker now has
the same agentic affordances Claude has in interactive sessions, wrapped
behind the Anthropic Messages API ``tools=`` schema and gated by Layer 0
(:mod:`api.app.governance`).

Tools exported:

- ``BashTool`` — sandboxed shell command via :func:`workers.orchestration.sandbox_runner.run_step_in_sandbox`.
- ``FileReadTool`` — scope-bounded read under ``AEGISPT_MEMORY_ROOT``.
- ``FileWriteTool`` — scope-bounded write under ``AEGISPT_MEMORY_ROOT``.
- ``WebSearchTool`` — wraps :func:`api.app.services.external_knowledge.lookup_exploits`.
- ``WebFetchTool`` — http GET inside the engagement scope.
- ``CodeExecTool`` — sandboxed Python script via :func:`run_step_in_sandbox` with ``python:3.12-slim``.
- ``SubagentSpawnTool`` — delegates to :class:`api.app.agents.coordinator.MetaCoordinator`.

Every tool's ``execute`` invocation routes through Layer 0
(:func:`api.app.governance.GovernanceControlPlane.authorize_dispatch`) so
the picker cannot escape engagement scope by picking an agentic tool.
"""
from api.app.agents.agent_tools.bash import BashTool
from api.app.agents.agent_tools.code_exec import CodeExecTool
from api.app.agents.agent_tools.file_io import FileReadTool, FileWriteTool
from api.app.agents.agent_tools.registry import (
    ALL_TOOL_SCHEMAS,
    PickerAgentTool,
    ToolResult,
    execute_tool_call,
    resolve_tool,
)
from api.app.agents.agent_tools.subagent import SubagentSpawnTool
from api.app.agents.agent_tools.web import WebFetchTool, WebSearchTool

__all__ = [
    "ALL_TOOL_SCHEMAS",
    "BashTool",
    "CodeExecTool",
    "FileReadTool",
    "FileWriteTool",
    "PickerAgentTool",
    "SubagentSpawnTool",
    "ToolResult",
    "WebFetchTool",
    "WebSearchTool",
    "execute_tool_call",
    "resolve_tool",
]
