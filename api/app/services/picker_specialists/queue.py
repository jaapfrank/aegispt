"""Persistent hypothesis queue for the specialist orchestrator
(refinement #1 of landscape-plan + gap-analysis-2026-05-22).

Today the orchestrator fans out to 5 specialists on EVERY picker iter
(60-150s each). That's wasteful — the recon evidence is largely the
same between iters; we re-pay the latency to re-derive almost the same
hypotheses. Naptime's "multiple trajectories" idea + Shannon's
hypothesis-then-validate split point at: produce hypotheses ONCE per
phase, store them in a queue, and let the executor consume top-rank
items one at a time. Re-run the orchestrator only when (a) the queue
is empty, (b) a high-confidence new finding shifts the evidence base.

State per hypothesis:
- ``open``: not yet attempted
- ``running``: dispatched, awaiting runner result
- ``verified``: runner produced a finding matching success_condition
  AND the validator confirmed replay
- ``failed``: runner ran but success_condition not met
- ``pruned``: invalidated by later evidence (e.g. credential changed)
- ``unreproducible``: validator could not replay → finding downgraded

Storage: `run.configuration_json["ai_assessment_loop"]["hypothesis_queue"]`.
"""
from __future__ import annotations

import time
import uuid
from typing import Any

QUEUE_STATE_OPEN = "open"
QUEUE_STATE_RUNNING = "running"
QUEUE_STATE_VERIFIED = "verified"
QUEUE_STATE_FAILED = "failed"
QUEUE_STATE_PRUNED = "pruned"
QUEUE_STATE_UNREPRODUCIBLE = "unreproducible"

QUEUE_TERMINAL_STATES = {
    QUEUE_STATE_VERIFIED,
    QUEUE_STATE_FAILED,
    QUEUE_STATE_PRUNED,
    QUEUE_STATE_UNREPRODUCIBLE,
}


def _now_iso() -> str:
    from datetime import UTC, datetime
    return datetime.now(UTC).isoformat()


def assign_ids_to_hypotheses(hypotheses: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Stamp each hypothesis with a stable id + initial state.
    Caller is responsible for storing the returned list."""
    out: list[dict[str, Any]] = []
    for h in hypotheses:
        item = dict(h)
        item.setdefault("hypothesis_id", uuid.uuid4().hex)
        item.setdefault("state", QUEUE_STATE_OPEN)
        item.setdefault("attempts", 0)
        item.setdefault("created_at", _now_iso())
        item.setdefault("last_state_change", _now_iso())
        out.append(item)
    return out


def pick_next_open(
    queue: list[dict[str, Any]],
    *,
    max_attempts_per_hypothesis: int = 2,
) -> dict[str, Any] | None:
    """Return the lowest-rank ``open`` hypothesis with attempts <
    max_attempts. None when no candidate remains."""
    candidates = [
        h for h in queue
        if h.get("state") == QUEUE_STATE_OPEN
        and int(h.get("attempts", 0)) < max_attempts_per_hypothesis
    ]
    if not candidates:
        return None
    candidates.sort(key=lambda h: int(h.get("rank", 99)))
    return candidates[0]


def transition_state(
    item: dict[str, Any],
    *,
    new_state: str,
    reason: str = "",
) -> dict[str, Any]:
    """Mutate the hypothesis dict in place + return it."""
    item["state"] = new_state
    item["last_state_change"] = _now_iso()
    if reason:
        history = item.setdefault("state_history", [])
        history.append({"at": item["last_state_change"], "state": new_state, "reason": reason[:200]})
    if new_state == QUEUE_STATE_RUNNING:
        item["attempts"] = int(item.get("attempts", 0)) + 1
    return item


def queue_summary(queue: list[dict[str, Any]]) -> dict[str, Any]:
    """Compact summary for logging + run.configuration_json visibility."""
    counts: dict[str, int] = {}
    for h in queue:
        st = str(h.get("state") or "open")
        counts[st] = counts.get(st, 0) + 1
    return {
        "total": len(queue),
        "by_state": counts,
        "next_open": (pick_next_open(queue) or {}).get("title"),
    }


def has_open_work(queue: list[dict[str, Any]]) -> bool:
    """True iff there is at least one open hypothesis still within
    its attempt budget."""
    return pick_next_open(queue) is not None
