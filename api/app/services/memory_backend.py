"""Filesystem backend for the Anthropic Memory tool (`memory_20250818`).

Claude uses this to persist scratch notes across runs/phases. The backend is
intentionally minimal and unopinionated — Claude decides what to store.

Security:
- All paths must resolve under the memories root.
- No symlinks followed outside the root.
- Path traversal sequences (``..``, URL-encoded variants) rejected.

The handler returns string payloads matching the Anthropic spec so Claude
parses them consistently.
"""
from __future__ import annotations

import os
import re
import shutil
from pathlib import Path
from typing import Any


def _root() -> Path:
    root = os.environ.get("AEGISPT_MEMORY_ROOT", "").strip()
    if not root:
        root = "/home/administrator/.aegispt/memories"
    p = Path(root)
    p.mkdir(parents=True, exist_ok=True)
    return p.resolve()


_TRAVERSAL_RE = re.compile(r"(?:^|/)\.\.(?:/|$)|%2e%2e", re.IGNORECASE)


def _resolve(path: str) -> Path:
    """Translate ``/memories/...`` (Claude's logical path) into a real path.

    Reject anything that escapes the root after resolution.
    """
    if not isinstance(path, str) or not path:
        raise ValueError("path must be a non-empty string")
    if _TRAVERSAL_RE.search(path):
        raise ValueError(f"path contains traversal sequence: {path!r}")
    cleaned = path.strip()
    if cleaned.startswith("/memories"):
        cleaned = cleaned[len("/memories"):]
    cleaned = cleaned.lstrip("/")
    root = _root()
    resolved = (root / cleaned).resolve() if cleaned else root
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"path escapes memories root: {path!r}") from exc
    return resolved


def _human_size(n: int) -> str:
    for unit in ("", "K", "M", "G"):
        if n < 1024:
            return f"{n}{unit}" if unit == "" else f"{n:.1f}{unit}"
        n = n / 1024
    return f"{n:.1f}T"


def _list_dir(path: Path, logical_path: str, max_depth: int = 2) -> str:
    lines = [
        f"Here're the files and directories up to 2 levels deep in {logical_path}, "
        "excluding hidden items and node_modules:"
    ]
    root = path
    if not root.exists():
        return f"The path {logical_path} does not exist. Please provide a valid path."
    for entry in sorted(root.rglob("*")):
        rel = entry.relative_to(root)
        if any(part.startswith(".") or part == "node_modules" for part in rel.parts):
            continue
        depth = len(rel.parts)
        if depth > max_depth:
            continue
        size = entry.stat().st_size if entry.is_file() else _dir_size(entry)
        logical = f"{logical_path.rstrip('/')}/{rel.as_posix()}"
        lines.append(f"{_human_size(size)}\t{logical}")
    # Always include root entry first too
    root_size = _dir_size(root)
    lines.insert(1, f"{_human_size(root_size)}\t{logical_path}")
    return "\n".join(lines)


def _dir_size(path: Path) -> int:
    total = 0
    for p in path.rglob("*"):
        if p.is_file():
            try:
                total += p.stat().st_size
            except OSError:
                pass
    return total


def _read_with_line_numbers(path: Path, logical: str, view_range: list[int] | None) -> str:
    text = path.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()
    if len(lines) > 999_999:
        return f"File {logical} exceeds maximum line limit of 999,999 lines."
    start, end = 1, len(lines)
    if isinstance(view_range, list) and len(view_range) == 2:
        try:
            start = max(1, int(view_range[0]))
            end = min(len(lines), int(view_range[1]))
        except (TypeError, ValueError):
            pass
    header = f"Here's the content of {logical} with line numbers:"
    body_lines = [
        f"{i:>6}\t{lines[i - 1]}" for i in range(start, end + 1)
    ]
    return header + "\n" + "\n".join(body_lines)


def execute(command: str, **kwargs: Any) -> str:
    """Run a single memory operation. Returns the response string Claude expects.

    Unknown commands return a clear error string instead of raising, so the
    tool_result still completes and Claude can react.
    """
    try:
        if command == "view":
            logical = str(kwargs.get("path") or "/memories")
            real = _resolve(logical)
            if not real.exists():
                return f"The path {logical} does not exist. Please provide a valid path."
            if real.is_dir():
                return _list_dir(real, logical)
            return _read_with_line_numbers(real, logical, kwargs.get("view_range"))

        if command == "create":
            logical = str(kwargs.get("path") or "")
            real = _resolve(logical)
            if real.exists():
                return f"Error: File {logical} already exists"
            real.parent.mkdir(parents=True, exist_ok=True)
            real.write_text(str(kwargs.get("file_text") or ""), encoding="utf-8")
            return f"File created successfully at: {logical}"

        if command == "str_replace":
            logical = str(kwargs.get("path") or "")
            real = _resolve(logical)
            if not real.exists() or real.is_dir():
                return f"Error: The path {logical} does not exist. Please provide a valid path."
            text = real.read_text(encoding="utf-8", errors="replace")
            old = str(kwargs.get("old_str") or "")
            new = str(kwargs.get("new_str") or "")
            occurrences = text.count(old)
            if occurrences == 0:
                return f"No replacement was performed, old_str `{old}` did not appear verbatim in {logical}."
            if occurrences > 1:
                lines_with = [
                    str(i + 1) for i, line in enumerate(text.splitlines()) if old in line
                ]
                return (
                    f"No replacement was performed. Multiple occurrences of old_str `{old}` "
                    f"in lines: {','.join(lines_with)}. Please ensure it is unique"
                )
            real.write_text(text.replace(old, new, 1), encoding="utf-8")
            snippet_lines = real.read_text(encoding="utf-8").splitlines()[:20]
            preview = "\n".join(
                f"{i + 1:>6}\t{line}" for i, line in enumerate(snippet_lines)
            )
            return f"The memory file has been edited.\n{preview}"

        if command == "insert":
            logical = str(kwargs.get("path") or "")
            real = _resolve(logical)
            if not real.exists() or real.is_dir():
                return f"Error: The path {logical} does not exist"
            text = real.read_text(encoding="utf-8", errors="replace")
            lines = text.splitlines()
            try:
                line_no = int(kwargs.get("insert_line"))
            except (TypeError, ValueError):
                return (
                    f"Error: Invalid `insert_line` parameter: {kwargs.get('insert_line')!r}. "
                    f"It should be within the range of lines of the file: [0, {len(lines)}]"
                )
            if line_no < 0 or line_no > len(lines):
                return (
                    f"Error: Invalid `insert_line` parameter: {line_no}. "
                    f"It should be within the range of lines of the file: [0, {len(lines)}]"
                )
            insert_text = str(kwargs.get("insert_text") or "")
            new_lines = lines[:line_no] + insert_text.splitlines() + lines[line_no:]
            real.write_text("\n".join(new_lines) + ("\n" if text.endswith("\n") else ""), encoding="utf-8")
            return f"The file {logical} has been edited."

        if command == "delete":
            logical = str(kwargs.get("path") or "")
            real = _resolve(logical)
            if not real.exists():
                return f"Error: The path {logical} does not exist"
            if real == _root():
                return "Error: refusing to delete the memories root"
            if real.is_dir():
                shutil.rmtree(real)
            else:
                real.unlink()
            return f"Successfully deleted {logical}"

        if command == "rename":
            old_logical = str(kwargs.get("old_path") or "")
            new_logical = str(kwargs.get("new_path") or "")
            old_real = _resolve(old_logical)
            new_real = _resolve(new_logical)
            if not old_real.exists():
                return f"Error: The path {old_logical} does not exist"
            if new_real.exists():
                return f"Error: The destination {new_logical} already exists"
            new_real.parent.mkdir(parents=True, exist_ok=True)
            old_real.rename(new_real)
            return f"Successfully renamed {old_logical} to {new_logical}"

        return f"Error: unknown memory command {command!r}"
    except ValueError as exc:
        return f"Error: {exc}"
    except OSError as exc:
        return f"Error: filesystem error: {exc}"
