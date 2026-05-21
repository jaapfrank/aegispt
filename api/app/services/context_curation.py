"""Context-window curation for the picker — Claude Code autoCompact pattern.

Per backlog-411 (sprint mythos-exploitation-foundation, task 5/15): the
picker's message list grows linearly per advance (raw tool stdouts, finding
records, recent failures, target intel JSON). At ~10 advances the cache
budget exhausts and picker quality degrades. This module shrinks the list
deterministically at 60% / 80% budget triggers while PRESERVING the
evidence the picker needs to make a good next decision.

Preserve rules (NEVER drop):
- Anthropic system / first-turn messages — those carry the assignment.
- Structured finding records (any message whose JSON content contains a
  ``finding`` field with a non-empty title/severity).
- captured_value entities (any payload containing a ``captured_value``
  key — credentials, tokens, IDs flagged by exec_plan).
- The last 6 conversational turns — recent context drives the next pick.

Drop / summarize:
- Raw tool stdout payloads larger than ``LARGE_STDOUT_BYTES`` get replaced
  with a one-line envelope:
  ``[curated: tool=X status=Y bytes_dropped=N preview="..."]``.
- Older conversational turns (older than the last 6) get folded into a
  single deterministic summary message of the form:
  ``[curated summary of N prior turns: tools=[...] findings=N]``.

Token estimation uses a rough ~4 chars/token heuristic — good enough to
decide whether to trigger curation; Anthropic returns the exact count
post-call.

OTEL: each invocation emits a ``picker.context_curation`` span (via
`api.app.observability.traced`) with attributes for before/after tokens
and dropped count so operators can see the savings per advance.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any

from api.app.observability import traced

logger = logging.getLogger(__name__)


# Budgets (input-token caps; Anthropic Opus 4.x has 200k context).
DEFAULT_MAX_TOKENS = 120_000
CURATE_TRIGGER_FRACTION = 0.60  # at 60% of max, start curating older turns
HARD_TRIGGER_FRACTION = 0.80    # at 80%, also drop large raw stdouts aggressively
LARGE_STDOUT_BYTES = 2048
RECENT_TURN_FLOOR = 6           # always keep the last N turns intact
ROUGH_CHARS_PER_TOKEN = 4       # heuristic


@dataclass
class CurationEvent:
    """Telemetry envelope returned next to the curated message list."""

    triggered: bool = False
    before_tokens: int = 0
    after_tokens: int = 0
    dropped_count: int = 0
    summarized_count: int = 0
    preserved_finding_count: int = 0
    preserved_captured_value_count: int = 0
    notes: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------
# Token estimation
# --------------------------------------------------------------------------


def _message_text(message: Any) -> str:
    """Best-effort textification of an Anthropic message dict for sizing."""
    if isinstance(message, str):
        return message
    if not isinstance(message, dict):
        return ""
    content = message.get("content")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if isinstance(item, dict):
                if "text" in item:
                    parts.append(str(item.get("text") or ""))
                elif "content" in item:
                    parts.append(str(item.get("content") or ""))
                elif item.get("type") == "tool_result":
                    inner = item.get("content")
                    if isinstance(inner, list):
                        for sub in inner:
                            if isinstance(sub, dict):
                                parts.append(str(sub.get("text") or ""))
                    elif isinstance(inner, str):
                        parts.append(inner)
                else:
                    parts.append(json.dumps(item, default=str))
            elif isinstance(item, str):
                parts.append(item)
        return "\n".join(parts)
    return json.dumps(content, default=str)


def estimate_tokens(messages: list[Any]) -> int:
    """Heuristic token count — ~4 chars per token. Good enough to TRIGGER
    curation; the real count is what Anthropic returns post-call.
    """
    total_chars = 0
    for msg in messages:
        total_chars += len(_message_text(msg))
    return total_chars // ROUGH_CHARS_PER_TOKEN


# --------------------------------------------------------------------------
# Preserve detectors
# --------------------------------------------------------------------------


def _carries_finding(message: Any) -> bool:
    text = _message_text(message)
    if not text:
        return False
    # JSON-shaped probe is cheap and catches the structured finding emit
    # contract used elsewhere in AegisPT (finding=, severity=, title=).
    if '"finding"' in text or '"severity"' in text:
        return True
    if '"captured_value"' in text:
        return True
    return False


def _carries_captured_value(message: Any) -> bool:
    text = _message_text(message)
    return '"captured_value"' in text or '"credential"' in text


# --------------------------------------------------------------------------
# Summarization (deterministic — no LLM call needed)
# --------------------------------------------------------------------------


def _summarize_older_turns(older: list[Any]) -> dict[str, Any]:
    """Collapse N older turns into one synthetic message describing what
    happened, without an LLM round-trip. The summary keeps tool names +
    rough byte count so the picker still has a sense of what came before.
    """
    tools_seen: list[str] = []
    total_bytes = 0
    finding_count = 0
    for msg in older:
        text = _message_text(msg)
        total_bytes += len(text)
        if '"finding"' in text:
            finding_count += 1
        # Pull tool=X hints out of curl-style command previews.
        for marker in ("$ ", "tool=", "runner="):
            idx = text.find(marker)
            if idx >= 0:
                tail = text[idx + len(marker): idx + len(marker) + 40].split()
                if tail:
                    tools_seen.append(tail[0].rstrip(",\""))
    uniq_tools = sorted(set(t for t in tools_seen if t))[:10]
    return {
        "role": "user",
        "content": (
            f"[curated summary of {len(older)} prior turns: "
            f"tools={uniq_tools} findings={finding_count} bytes_dropped={total_bytes}]"
        ),
    }


def _shrink_large_stdout(message: Any) -> tuple[Any, int]:
    """Replace large raw stdout payloads with a one-line envelope. Returns
    (curated_message, bytes_dropped). Leaves the message untouched if it
    carries a finding / captured_value or is below the threshold.
    """
    if _carries_finding(message) or _carries_captured_value(message):
        return message, 0
    if not isinstance(message, dict):
        return message, 0
    text = _message_text(message)
    text_len = len(text)
    if text_len < LARGE_STDOUT_BYTES:
        return message, 0
    preview = text[:160].replace("\n", " ")
    envelope = {
        "role": message.get("role", "user"),
        "content": (
            f"[curated: bytes_dropped={text_len} preview={preview!r}]"
        ),
    }
    return envelope, text_len


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------


@traced("picker.context_curation")
def curate_for_picker(
    messages: list[Any],
    *,
    max_tokens: int = DEFAULT_MAX_TOKENS,
) -> tuple[list[Any], CurationEvent]:
    """Return (curated_messages, CurationEvent).

    No-op fast-path when total estimated tokens are below the 60% trigger.
    At 60% trigger, summarize older turns (keep RECENT_TURN_FLOOR most-
    recent). At 80% trigger, ALSO shrink large stdouts in the kept turns.

    Finding / captured_value carrier messages are NEVER dropped or shrunk —
    they are the proof the picker reasons over.
    """
    event = CurationEvent(before_tokens=estimate_tokens(messages))
    trigger_at = int(max_tokens * CURATE_TRIGGER_FRACTION)
    hard_trigger_at = int(max_tokens * HARD_TRIGGER_FRACTION)
    if event.before_tokens < trigger_at:
        event.after_tokens = event.before_tokens
        return list(messages), event

    event.triggered = True

    # Step 1: preserve recent + finding/captured_value carriers.
    n = len(messages)
    keep_indices: set[int] = set(range(max(0, n - RECENT_TURN_FLOOR), n))
    for i, msg in enumerate(messages):
        if _carries_finding(msg):
            keep_indices.add(i)
            event.preserved_finding_count += 1
        if _carries_captured_value(msg):
            keep_indices.add(i)
            event.preserved_captured_value_count += 1

    preserved: list[Any] = []
    older: list[Any] = []
    for i, msg in enumerate(messages):
        if i in keep_indices:
            preserved.append(msg)
        else:
            older.append(msg)
    if older:
        summary = _summarize_older_turns(older)
        preserved.insert(0, summary)
        event.summarized_count = len(older)

    # Step 2: at hard trigger, also shrink large stdouts in kept turns.
    if event.before_tokens >= hard_trigger_at:
        shrunk: list[Any] = []
        for msg in preserved:
            new_msg, bytes_dropped = _shrink_large_stdout(msg)
            shrunk.append(new_msg)
            if bytes_dropped > 0:
                event.dropped_count += 1
        preserved = shrunk

    event.after_tokens = estimate_tokens(preserved)
    event.notes.append(
        f"trigger=60%@{trigger_at} hard=80%@{hard_trigger_at} "
        f"recent_floor={RECENT_TURN_FLOOR}"
    )
    logger.info(
        "context_curation: %d → %d tokens (summarized=%d shrunk=%d findings=%d)",
        event.before_tokens, event.after_tokens, event.summarized_count,
        event.dropped_count, event.preserved_finding_count,
    )
    return preserved, event


__all__ = [
    "CURATE_TRIGGER_FRACTION",
    "CurationEvent",
    "DEFAULT_MAX_TOKENS",
    "HARD_TRIGGER_FRACTION",
    "LARGE_STDOUT_BYTES",
    "RECENT_TURN_FLOOR",
    "curate_for_picker",
    "estimate_tokens",
]
