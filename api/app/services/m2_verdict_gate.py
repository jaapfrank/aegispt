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
import re
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


M2_GATE_ENV_VAR = "AEGISPT_M2_VERDICT_GATE_ENABLED"
PROOF_EXEC_MARKER = "PROOF_EXEC_M2_VERDICT_GATE_2026052313"

VERDICT_EXPLOITED = "EXPLOITED"
VERDICT_DETERMINISTIC_PROOF = "DETERMINISTIC_PROOF"
VERDICT_BLOCKED_BY_SECURITY = "BLOCKED_BY_SECURITY"
VERDICT_OUT_OF_SCOPE_INTERNAL = "OUT_OF_SCOPE_INTERNAL"
VERDICT_FALSE_POSITIVE = "FALSE_POSITIVE"
VERDICT_UNCLASSIFIED = "UNCLASSIFIED"

# Bounded deterministic-proof class: a captured flag literal is itself the
# proof — it either byte-matches the grader or it does not, with no model or
# re-prober judgment. Such a finding must NOT be dropped just because the
# HTTP-oriented re-prober cannot reproduce it (e.g. raw-TCP line protocols).
# This is the canonical flag shape only; nothing else is exempted, so the gate
# is NOT generically bypassed.
_FLAG_PROOF_RE = re.compile(r"(?:aegispt|flag|FLAG)\{[^}]{1,200}\}|xbow-[0-9a-fA-F]{6,}")
_DETERMINISTIC_PROOF_METHODOLOGIES = {"interactive_exploit", "code_exec_attack"}


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


def is_deterministic_flag_proof(finding: Any) -> bool:
    """True for the bounded deterministic-proof class: a finding whose evidence
    carries a canonical flag literal AND has the provenance that makes it a
    real solve (an evidence artifact ref, an in-scope target, and an exploit
    methodology tag). Grader-matchable proof — exempt from the re-prober verdict,
    but only when fully provenanced (mirrors the canonical-solve definition)."""
    text = " ".join(
        str(getattr(finding, attr, "") or "")
        for attr in ("title", "summary", "evidence_excerpt")
    )
    if not _FLAG_PROOF_RE.search(text):
        return False
    if not str(getattr(finding, "evidence_ref", "") or "").strip():
        return False  # transcript/evidence artifact provenance required
    if not str(getattr(finding, "target_id", "") or "").strip():
        return False  # scope provenance required
    tags = getattr(finding, "methodology_tags", None) or []
    return any(str(t) in _DETERMINISTIC_PROOF_METHODOLOGIES for t in tags)


def classify(*, finding: Any, verifier_verdict: Any) -> GateDecision:
    """Map verifier signal + replay-recipe presence to one of the verdicts."""
    # Bounded exemption FIRST: a provenanced flag-literal capture is
    # deterministic proof and is never a re-prober false positive.
    if is_deterministic_flag_proof(finding):
        return GateDecision(
            verdict=VERDICT_DETERMINISTIC_PROOF,
            drop=False,
            reason="deterministic flag-literal proof (grader-matchable, provenanced) — exempt from re-prober verdict",
        )
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
