"""Trace -> Review Committee -> Evidence Arbiter -> Training Candidate Factory.

AI-trains-AI for the pentest agent, with ONE rule: evidence is the boss, never a
single model. The small model acts and logs a frozen trace; a committee of reviewers
(gpt-5.5 / deepseek / gemini / local judge) each return a STRUCTURED verdict; the
arbiter decides — runner-evidence first, then jury consensus, human only on conflict
or safety risk — and the decision becomes training data (SFT / DPO pair / contrastive
/ process-reward). Reviewers are advisors that can hallucinate or share blind spots,
so a held-out eval set is NEVER touched by this loop and real evidence is the final
judge. (Design converged independently by Claude + Codex, 2026-06-06.)

This module is the decision CORE (schema + arbiter + aggregation + factory). Wiring
real providers reuses the interactive-exploit adapter layer; a Reviewer is any
callable trace -> verdict-dict.
"""
from __future__ import annotations

import statistics
from typing import Any, Callable, Optional

# ---- frozen trace schema (one dict per step) -------------------------------
TRACE_FIELDS = ("state", "action", "tool_result", "evidence", "safety_status",
                "objective_progress", "failure_reason", "final_outcome")
# ---- reviewer verdict schema ----------------------------------------------
VERDICT_FIELDS = ("verdict", "confidence", "first_wrong_step", "reason",
                  "better_action_type", "safety_ok", "training_value")

Reviewer = Callable[[list[dict]], dict]  # trace(list of step dicts) -> verdict dict


def evidence_verdict(trace: list[dict]) -> Optional[dict]:
    """The BOSS. Objective verdict from runner-evidence on the LAST step. Returns
    None only when there is no objective signal (then the jury is consulted)."""
    if not trace:
        return None
    last = trace[-1]
    outcome = (last.get("final_outcome") or "").lower()
    safe = bool(last.get("safety_status", "ok") not in ("violation", "out_of_scope", "destructive"))
    if not safe:
        return {"source": "evidence", "verdict": "unsafe", "decisive": True, "safety_ok": False}
    if outcome in ("solved", "flag_captured", "goal_satisfied", "objective_met"):
        return {"source": "evidence", "verdict": "good", "decisive": True, "safety_ok": True}
    if outcome in ("failed", "no_flag", "aborted"):
        # objective failure is decisive that the run did NOT succeed, but WHERE it
        # went wrong is a process question -> still gather the jury for the step label
        return {"source": "evidence", "verdict": "bad", "decisive": False, "safety_ok": True}
    return None


# ---- the "found nothing" arbiter ------------------------------------------
# A no-finding on a LIVE target is COVERAGE evidence, never hard negative truth. The
# question is not "is the model right?" but "did it do enough to responsibly say
# no-confirmed-finding?". 5 labels (Codex + Claude, 2026-06-06).
NO_FINDING_LABELS = ("true_negative", "missed_finding", "inconclusive", "blocked", "correct_restraint")
NO_FINDING_ARTIFACT = ("outcome", "confidence", "coverage", "negative_evidence_refs",
                       "untested_boundaries", "blockers", "lab_truth", "conscious_restraint")


def coverage_verdict(trace: list[dict], *, min_coverage: int = 3) -> dict:
    """Classify a no-confirmed-finding trace. lab_truth in {known_clean,
    known_vulnerable, live_no_oracle}. The hard rule: a LIVE no-finding is NEVER a
    'safe'/true-negative label — only process/coverage training."""
    last = trace[-1] if trace else {}
    art = last.get("no_finding") or {}
    lab = (art.get("lab_truth") or "live_no_oracle").lower()
    blockers = art.get("blockers") or []
    coverage = art.get("coverage") or []
    untested = art.get("untested_boundaries") or []
    restraint = bool(art.get("conscious_restraint"))

    if blockers:                       # external block (no creds / target down / tool / policy)
        return {"label": "blocked", "training_use": "exclude", "human_review": False, "lab_truth": lab}
    if lab == "known_vulnerable":      # an oracle existed and was MISSED -> gold for DPO/contrastive
        return {"label": "missed_finding", "training_use": "dpo_negative", "human_review": False, "lab_truth": lab}
    if restraint:                      # suspicion, no proof/authz, deliberately did NOT report
        return {"label": "correct_restraint", "training_use": "safety_positive", "human_review": False, "lab_truth": lab}
    if lab == "known_clean" and len(coverage) >= min_coverage and not untested:
        return {"label": "true_negative", "training_use": "sft_positive", "human_review": False, "lab_truth": lab}
    # live target OR thin coverage OR reachable-but-untested -> NEVER 'safe', process only
    return {"label": "inconclusive", "training_use": "do_not_reward",
            "human_review": bool(untested), "lab_truth": lab}


def aggregate(reviews: list[dict]) -> dict:
    """Median/consensus over the committee — robust to one model's bias. No single
    reviewer leads; disagreement is surfaced, not hidden."""
    reviews = [r for r in reviews if r]
    if not reviews:
        return {"verdict": "unknown", "confidence": 0.0, "agreement": 0.0, "first_wrong_step": None}
    verdicts = [str(r.get("verdict", "unknown")) for r in reviews]
    top = max(set(verdicts), key=verdicts.count)
    agreement = verdicts.count(top) / len(verdicts)
    confs = [float(r.get("confidence", 0.0)) for r in reviews if r.get("verdict") == top]
    wrong = [r.get("first_wrong_step") for r in reviews
             if r.get("verdict") in ("bad", "bad_step") and isinstance(r.get("first_wrong_step"), (int, float))]
    return {
        "verdict": top,
        "confidence": round(statistics.median(confs), 3) if confs else 0.0,
        "agreement": round(agreement, 3),
        "first_wrong_step": int(statistics.median(wrong)) if wrong else None,
        "safety_ok": all(r.get("safety_ok", True) for r in reviews),
        "n_reviewers": len(reviews),
    }


def arbitrate(trace: list[dict], reviews: list[dict], *, conflict_threshold: float = 0.67) -> dict:
    """Evidence first; else jury consensus; flag for HUMAN on conflict / safety /
    novelty. Returns the final decision + why."""
    last = trace[-1] if trace else {}
    # 0. "found nothing" routes to the coverage arbiter (responsible no-finding vs
    # should-have-continued), NOT the good/bad jury.
    if (last.get("final_outcome") or "").lower() in ("no_confirmed_finding", "no_finding"):
        cov = coverage_verdict(trace)
        return {"decision": cov["label"], "by": "coverage_arbiter", "human_review": cov["human_review"],
                "jury": aggregate(reviews), "coverage": cov, "evidence": evidence_verdict(trace)}

    ev = evidence_verdict(trace)
    jury = aggregate(reviews)
    jbad = jury["verdict"] in ("bad", "bad_step")

    # 1. safety overrides everything (evidence OR jury flag)
    if (ev and not ev["safety_ok"]) or not jury["safety_ok"]:
        return {"decision": "reject_unsafe", "by": "evidence" if (ev and not ev["safety_ok"]) else "jury",
                "human_review": True, "jury": jury, "evidence": ev}
    # 2. decisive evidence (solved) wins outright
    if ev and ev.get("decisive"):
        return {"decision": "good" if ev["verdict"] == "good" else "bad", "by": "evidence",
                "human_review": False, "jury": jury, "evidence": ev}
    # 3. objective failure: the run IS bad; the jury only pinpoints WHERE, so a
    # step-split is NOT a reason for human review of the good/bad call.
    if ev and ev["verdict"] == "bad":
        return {"decision": "bad", "by": "evidence+jury", "human_review": False, "jury": jury, "evidence": ev}
    # 4. no objective signal -> jury leads; human on a genuine good/bad split
    decision = "bad" if jbad else ("good" if jury["verdict"] == "good" else "uncertain")
    human = jury["agreement"] < conflict_threshold or decision == "uncertain"
    return {"decision": decision, "by": "jury", "human_review": human, "jury": jury, "evidence": ev}


def to_training(trace: list[dict], decision: dict, bad_trace: Optional[list[dict]] = None) -> dict:
    """Turn an arbitrated trace into training data. Evidence-anchored: only
    human_review==False decisions become auto-training data."""
    # no-finding coverage labels carry their own training_use (do_not_reward /
    # exclude are kept for audit but NOT used as positive training signal)
    cov = decision.get("coverage")
    if cov:
        tv = cov["training_use"]
        use = tv not in ("do_not_reward", "exclude") and not decision["human_review"]
        return {"training_value": tv, "use": use, "label": decision["decision"], "trace": trace}
    if decision["human_review"]:
        return {"training_value": "needs_human_review", "use": False}
    d = decision["decision"]
    if d == "good":
        return {"training_value": "sft_positive", "use": True, "trace": trace}
    if d in ("bad", "bad_step"):
        fws = decision["jury"].get("first_wrong_step")
        out = {"training_value": "dpo_negative" if bad_trace is None else "dpo_pair",
               "use": True, "first_wrong_step": fws, "rejected": trace}
        if bad_trace is None and fws is not None:
            out["training_value"] = "contrastive"  # wrong step known -> needs a corrected alternative
        return out
    return {"training_value": "discard", "use": False}


def review_trace(trace: list[dict], committee: list[Reviewer]) -> dict:
    """Full pipeline for one trace: committee -> arbiter -> training candidate."""
    reviews = []
    for r in committee:
        try:
            reviews.append(r(trace))
        except Exception as e:  # a flaky reviewer must not sink the run
            reviews.append({"verdict": "unknown", "confidence": 0.0, "reason": f"reviewer_error:{e}"})
    decision = arbitrate(trace, reviews)
    decision["training"] = to_training(trace, decision)
    return decision
