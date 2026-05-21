"""FileReadTool + FileWriteTool — scope-bounded under AEGISPT_MEMORY_ROOT."""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

from api.app.agents.agent_tools.registry import (
    ToolResult,
    _rebuild_schemas,
    _register,
)


def _memory_root() -> Path:
    root = os.environ.get("AEGISPT_MEMORY_ROOT", "").strip()
    if not root:
        root = "/home/administrator/.aegispt/memories"
    return Path(root).expanduser().resolve()


_TRAVERSAL_RE = re.compile(r"(?:^|/)\.\.(?:/|$)|%2e%2e", re.IGNORECASE)


def _resolve_under_root(logical_path: str) -> Path:
    """Translate the LLM-supplied logical path to a real path under the
    memory root. Refuses path traversal and absolute paths that escape
    the root.
    """
    if not isinstance(logical_path, str) or not logical_path:
        raise ValueError("path must be a non-empty string")
    if _TRAVERSAL_RE.search(logical_path):
        raise ValueError(f"path contains traversal sequence: {logical_path!r}")
    cleaned = logical_path.strip().lstrip("/")
    root = _memory_root()
    root.mkdir(parents=True, exist_ok=True)
    resolved = (root / cleaned).resolve() if cleaned else root
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"path escapes memory root: {logical_path!r}") from exc
    return resolved


class FileReadTool:
    name = "file_read"

    def schema(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": (
                "Read a file under AEGISPT_MEMORY_ROOT (the picker's scratchpad). "
                "Path is relative; traversal sequences (../) are rejected. "
                "Returns up to 8 KB of UTF-8 text."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Path relative to memory root."},
                },
                "required": ["path"],
            },
        }

    def execute(self, arguments: dict[str, Any], *, run: Any, session: Any | None = None) -> ToolResult:  # noqa: ARG002
        try:
            real = _resolve_under_root(str(arguments.get("path") or ""))
        except ValueError as exc:
            return ToolResult.denied(str(exc))
        if not real.exists():
            return ToolResult.error(f"path does not exist: {real}")
        if real.is_dir():
            entries = sorted(p.name for p in real.iterdir())[:50]
            return ToolResult.success(
                "directory:\n" + "\n".join(entries),
                metadata={"kind": "directory", "entry_count": len(entries)},
            )
        try:
            text = real.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            return ToolResult.error(f"read failed: {exc}")
        return ToolResult.success(text[:8192], metadata={"kind": "file", "bytes": len(text)})


class FileWriteTool:
    name = "file_write"

    def schema(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": (
                "Write a file under AEGISPT_MEMORY_ROOT. Overwrites; pass a "
                "different path to keep history. Total file size capped at 64 KB."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Path relative to memory root."},
                    "content": {"type": "string", "description": "UTF-8 text to write."},
                },
                "required": ["path", "content"],
            },
        }

    def execute(self, arguments: dict[str, Any], *, run: Any, session: Any | None = None) -> ToolResult:  # noqa: ARG002
        try:
            real = _resolve_under_root(str(arguments.get("path") or ""))
        except ValueError as exc:
            return ToolResult.denied(str(exc))
        content = str(arguments.get("content") or "")
        if len(content.encode("utf-8")) > 65_536:
            return ToolResult.denied("content exceeds 64 KB cap")
        try:
            real.parent.mkdir(parents=True, exist_ok=True)
            real.write_text(content, encoding="utf-8")
        except OSError as exc:
            return ToolResult.error(f"write failed: {exc}")
        return ToolResult.success(
            f"wrote {len(content)} chars to {real.name}",
            metadata={"kind": "file", "bytes": len(content)},
        )


_register(FileReadTool())
_register(FileWriteTool())
_rebuild_schemas()

__all__ = ["FileReadTool", "FileWriteTool"]
