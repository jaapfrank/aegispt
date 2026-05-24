"""M5 cross-run recall — shared block builder for both picker paths.

Before this extraction the SAME recall logic existed twice in
assessment_loop.py: once in `_specialists_select_next_action` (primary
PICKER_MODE=specialists path) and once in `_claude_select_next_action`
(legacy fallback). Both built the "PRIOR EPISODES" block by calling
``recall_similar`` with k=6, filtering on success_marker + run_id, and
formatting top-3 results.

This module exposes one function the two callers share. Bug-fixes to the
recall query / formatting now apply to both paths in one edit.

Contract:
- Returns ``("", 0)`` when session is None, recall fails, or no actionable
  episodes are found (caller renders nothing).
- Returns ``(block_text, n)`` with block_text starting with the section
  header and ending WITHOUT trailing newlines. Callers add whatever
  padding their consumer expects.
"""
from __future__ import annotations

import json
import logging
from typing import Any

from sqlalchemy.orm import Session

from api.app.models import Run

logger = logging.getLogger("api.app.services.assessment_loop")


def build_prior_episodes_block(
    *,
    session: Session | None,
    run: Run,
    primary_target: str,
    prior_findings_summary: str,
    phase_label: str | None = None,
    findings_for_query: list[Any] | None = None,
    k: int = 6,
    keep_top: int = 3,
) -> tuple[str, int]:
    """Return the "PRIOR EPISODES" hint block plus the count of episodes
    surfaced. Empty string + 0 when nothing actionable was found.

    ``phase_label`` and ``findings_for_query`` are optional extras the
    Claude fallback caller passes (its query is slightly richer than the
    specialists caller's). The specialists caller passes only
    ``prior_findings_summary`` and target — both forms are honoured.
    """
    if session is None:
        return ("", 0)
    try:
        from api.app.services.episodic_memory import recall_similar  # noqa: E402
        eng_name = str(
            getattr(getattr(run, "engagement", None), "name", "") or ""
        ).lower()
        is_bench = eng_name.startswith("xbow-bench") or "benchmark" in eng_name

        if findings_for_query is not None:
            findings_part = f"findings={json.dumps(findings_for_query, default=str)[:600]}"
        else:
            findings_part = f"findings={prior_findings_summary[:400]}"
        phase_part = f"phase={phase_label} " if phase_label else ""
        query = f"{phase_part}target={primary_target} {findings_part}"

        episodes = recall_similar(
            session,
            query=query,
            k=k,
            include_benchmark=is_bench,
        )
        actionable = [
            e for e in episodes
            if e.success_marker and str(e.run_id) != str(run.id)
        ][:keep_top]
        if not actionable:
            return ("", 0)

        lines: list[str] = []
        for ep in actionable:
            marker = ep.success_marker or ""
            outcome = "SOLVED" if marker == "flag_extracted" else marker.upper()
            tool = ep.action_type.split(":", 1)[1] if ":" in ep.action_type else ep.action_type
            ctx = ep.action_context if isinstance(ep.action_context, dict) else {}
            tgt = str(ctx.get("target") or "?")
            rsn = str(ctx.get("reasoning") or "")[:120].replace("\n", " ")
            sim = ep.similarity or 0.0
            lines.append(f"  [{outcome}, sim={sim:.2f}] {tool} -> {tgt} | {rsn}")

        block = (
            "=== PRIOR EPISODES (cross-run memory — HINTS, verify before reuse) ===\n"
            "Past picks on similar evidence + their outcome marker. SOLVED = the pick\n"
            "preceded a flag-extraction in that run. Use as a hint, not authoritative —\n"
            "the prior target may differ in details that matter here.\n"
            + "\n".join(lines)
        )
        return (block, len(actionable))
    except Exception as exc:  # noqa: BLE001
        logger.debug("prior episodes recall skipped: %s", exc)
        return ("", 0)
