"""M2 verdict-based finding gate (Shannon "no exploit, no report").

Classifies findings into 4 verdicts after the existing finding_verifier
runs, and (when the gate is enabled via env flag) drops the obvious
false positives BEFORE the Finding row is persisted.

Verdicts:
- EXPLOITED — verifier confirmed AND a replay recipe exists.
- BLOCKED_BY_SECURITY — verifier failed but a replay recipe exists
  (the exploit was attempted, the control or WAF stopped it). Kept.
- OUT_OF_SCOPE_INTERNAL — reserved for scope-aware suppression. The
  scope allowlist is already enforced upstream; nothing classifies
  here for now, but the verdict slot exists so the same gate can
  evolve.
- FALSE_POSITIVE — verifier failed AND no replay recipe. There is no
  evidence the exploit was attempted; the original "find" cannot be
  reproduced. Dropped when the gate is on.
- UNCLASSIFIED — verifier did not run (severity below high) or returned
  inconclusive. Kept for operator review.

Per docs/plans/beat-shannon-pro-roadmap-2026-05-23.md M2.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


M2_GATE_ENV_VAR = "AEGISPT_M2_VERDICT_GATE_ENABLED"
PROOF_EXEC_MARKER = "PROOF_EXEC_M2_VERDICT_GATE_2026052313"

VERDICT_EXPLOITED = "EXPLOITED"
VERDICT_BLOCKED_BY_SECURITY = "BLOCKED_BY_SECURITY"
VERDICT_OUT_OF_SCOPE_INTERNAL = "OUT_OF_SCOPE_INTERNAL"
VERDICT_FALSE_POSITIVE = "FALSE_POSITIVE"
VERDICT_UNCLASSIFIED = "UNCLASSIFIED"


@dataclass(frozen=True)
class GateDecision:
    verdict: str
    drop: bool
    reason: str


def gate_enabled() -> bool:
    return os.environ.get(M2_GATE_ENV_VAR, "").strip().lower() in {
        "1", "true", "yes", "on",
    }


def _has_replay_recipe(finding: Any) -> bool:
    recipe = getattr(finding, "replay_recipe_json", None)
    if not isinstance(recipe, dict):
        return False
    steps = recipe.get("steps")
    return isinstance(steps, list) and len(steps) > 0


def classify(*, finding: Any, verifier_verdict: Any) -> GateDecision:
    """Map verifier signal + replay-recipe presence to one of the 4 verdicts."""
    if verifier_verdict is None:
        return GateDecision(
            verdict=VERDICT_UNCLASSIFIED,
            drop=False,
            reason="verifier did not run (severity below high)",
        )

    vdict = str(getattr(verifier_verdict, "verdict", "") or "")
    has_replay = _has_replay_recipe(finding)

    if vdict == "confirmed":
        return GateDecision(
            verdict=VERDICT_EXPLOITED,
            drop=False,
            reason="verifier confirmed",
        )
    if vdict == "failed":
        if has_replay:
            return GateDecision(
                verdict=VERDICT_BLOCKED_BY_SECURITY,
                drop=False,
                reason="verifier failed but replay recipe exists — likely blocked by control",
            )
        return GateDecision(
            verdict=VERDICT_FALSE_POSITIVE,
            drop=True,
            reason="verifier failed AND no replay recipe — cannot reproduce",
        )
    return GateDecision(
        verdict=VERDICT_UNCLASSIFIED,
        drop=False,
        reason=f"verifier verdict={vdict!r} — keep for review",
    )


def evaluate_for_persistence(
    *,
    finding: Any,
    verifier_verdict: Any,
) -> GateDecision:
    """Classify + emit PROOF marker. Caller decides whether to honor `drop`
    based on the gate_enabled() flag."""
    decision = classify(finding=finding, verifier_verdict=verifier_verdict)
    logger.info(
        "%s finding=%s severity=%s verdict=%s drop=%s gate_on=%s reason=%s",
        PROOF_EXEC_MARKER,
        str(getattr(finding, "title", "") or getattr(finding, "id", ""))[:60],
        str(getattr(finding, "severity", "") or ""),
        decision.verdict,
        decision.drop,
        gate_enabled(),
        decision.reason,
    )
    return decision
