"""Pure utility helpers used across the assessment-loop code paths.

These were inlined in assessment_loop.py at the top of the helper section.
Moving them into a separate module is the first step of the O4 split — no
state, no side effects, no other dependencies inside this package.
"""
from __future__ import annotations

import re as _re
from datetime import UTC, datetime
from typing import Any


def as_dict(value: object) -> dict[str, Any]:
    """Coerce an arbitrary value into a dict; non-dicts become {}."""
    return dict(value) if isinstance(value, dict) else {}


def as_list(value: object) -> list[Any]:
    """Coerce an arbitrary value into a list. None -> [], scalar -> [scalar]."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return [value]


def tolerant_json_fix(text: str) -> str:
    """Best-effort fixes for common Claude JSON mistakes.

    - Strip trailing commas before ``}`` or ``]``.
    - Escape stray raw newlines/tabs inside string literals.
    Conservative: if it still can't parse, the caller logs and returns None.
    """
    out = _re.sub(r",(\s*[}\]])", r"\1", text)
    result: list[str] = []
    in_string = False
    escape = False
    for ch in out:
        if escape:
            result.append(ch)
            escape = False
            continue
        if ch == "\\":
            result.append(ch)
            escape = True
            continue
        if ch == '"':
            in_string = not in_string
            result.append(ch)
            continue
        if in_string and ch == "\n":
            result.append("\\n")
        elif in_string and ch == "\t":
            result.append("\\t")
        elif in_string and ch == "\r":
            result.append("\\r")
        else:
            result.append(ch)
    return "".join(result)


def now_iso() -> str:
    """Return the current UTC time as an ISO-8601 string."""
    return datetime.now(UTC).isoformat()
