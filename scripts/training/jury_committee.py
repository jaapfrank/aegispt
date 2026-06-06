"""The committee entry point — makes the operator's idea usable end-to-end: several
frontier models (DeepSeek-V4-Pro / Grok / a local judge) each review a trace, and
EVIDENCE + CALIBRATION decide. No single model leads. On evidence-decisive cases the
ledger learns whom to trust (the self-correcting loop).

  committee = build_committee([{"id":"v4pro","endpoint":..,"model":"deepseek-v4-pro",
                                "api_key":KEY,"angle":"reasoning/safety"}, ...])
  decision = review(trace, committee, ledger)   # ledger optional (weighted if given)
"""
from __future__ import annotations

import jury_calibration as C
import jury_review as J
import jury_reviewers as JR


def build_committee(configs: list[dict]) -> list[tuple]:
    return [(c["id"], JR.make_reviewer(endpoint=c["endpoint"], model=c["model"],
                                       api_key=c.get("api_key", ""), angle=c.get("angle", "")))
            for c in configs]


def review(trace: list[dict], committee: list[tuple],
           ledger: C.CalibrationLedger | None = None) -> dict:
    reviews: list[tuple[str, dict]] = []
    for rid, rev in committee:
        try:
            reviews.append((rid, rev(trace)))
        except Exception as exc:  # a flaky reviewer must not sink the run
            reviews.append((rid, {"verdict": "unknown", "confidence": 0.0, "reason": f"error:{exc}"}))

    decision = J.arbitrate(trace, [v for _rid, v in reviews])
    if ledger is not None:
        decision["jury"] = C.weighted_aggregate(reviews, ledger)
        # learn whom to trust: on evidence-decisive cases, score each reviewer vs evidence
        ev = decision.get("evidence")
        if ev and ev.get("decisive"):
            for rid, v in reviews:
                ledger.record(rid, v.get("verdict", "unknown"), ev.get("verdict", ""))
    decision["reviews"] = {rid: v for rid, v in reviews}
    decision["training"] = J.to_training(trace, decision)
    return decision
