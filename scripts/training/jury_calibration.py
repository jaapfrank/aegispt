"""Calibration ledger (#4) — 'who should lead' answered EMPIRICALLY.

On evidence-decisive cases (ground truth known: solved/failed/unsafe) record whether
each reviewer's verdict matched the evidence. Derive a smoothed weight per reviewer.
On ambiguous cases (no decisive evidence) aggregate the committee WEIGHTED by those
weights -> a reviewer with a blind spot is down-weighted instead of averaging its
error in. Evidence is still the boss; calibration just decides whom to trust when
evidence is silent.
"""
from __future__ import annotations

import json
import statistics
from pathlib import Path


def _bucket(v: str) -> str:
    """Collapse verdict variants into comparable buckets."""
    v = str(v or "").lower()
    if v in ("bad", "bad_step", "missed_finding"):
        return "bad"
    if v in ("good", "true_negative", "correct_restraint", "solved"):
        return "good"
    if v in ("unsafe", "reject_unsafe"):
        return "unsafe"
    return v


class CalibrationLedger:
    def __init__(self, path: str | None = None) -> None:
        self.path = path
        self.stats: dict[str, dict] = {}
        if path and Path(path).exists():
            try:
                self.stats = json.loads(Path(path).read_text())
            except Exception:
                self.stats = {}

    def record(self, reviewer_id: str, reviewer_verdict: str, evidence_verdict: str) -> None:
        """Only meaningful when evidence is decisive (caller passes such cases)."""
        s = self.stats.setdefault(reviewer_id, {"hits": 0, "total": 0})
        s["total"] += 1
        if _bucket(reviewer_verdict) == _bucket(evidence_verdict):
            s["hits"] += 1

    def weight(self, reviewer_id: str, *, prior: float = 0.5, k: int = 4) -> float:
        """Smoothed agreement rate (k pseudo-cases at `prior` so a new reviewer starts
        neutral and earns/loses trust with evidence)."""
        s = self.stats.get(reviewer_id, {"hits": 0, "total": 0})
        return round((s["hits"] + prior * k) / (s["total"] + k), 4)

    def save(self) -> None:
        if self.path:
            Path(self.path).write_text(json.dumps(self.stats, indent=2, sort_keys=True))


def weighted_aggregate(reviews: list[tuple[str, dict]], ledger: CalibrationLedger) -> dict:
    """reviews: list of (reviewer_id, verdict_dict). Weighted consensus by calibration
    weight (down-weights unreliable reviewers). No single reviewer leads."""
    reviews = [(rid, v) for rid, v in reviews if v]
    if not reviews:
        return {"verdict": "unknown", "confidence": 0.0, "weight_sum": 0.0,
                "first_wrong_step": None, "safety_ok": True, "n_reviewers": 0}
    tally: dict[str, float] = {}
    for rid, v in reviews:
        b = _bucket(v.get("verdict", "unknown"))
        tally[b] = tally.get(b, 0.0) + ledger.weight(rid)
    top = max(tally, key=tally.get)
    wsum = sum(tally.values()) or 1.0
    confs = [float(v.get("confidence", 0.0)) for rid, v in reviews if _bucket(v.get("verdict")) == top]
    wrong = [v.get("first_wrong_step") for rid, v in reviews
             if _bucket(v.get("verdict")) in ("bad",) and isinstance(v.get("first_wrong_step"), (int, float))]
    return {
        "verdict": top,
        "confidence": round(statistics.median(confs), 3) if confs else 0.0,
        "weighted_agreement": round(tally[top] / wsum, 3),
        "first_wrong_step": int(statistics.median(wrong)) if wrong else None,
        "safety_ok": all(v.get("safety_ok", True) for _rid, v in reviews),
        "n_reviewers": len(reviews),
    }
