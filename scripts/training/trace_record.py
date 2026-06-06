"""Trace recorder — Phase 1 of the jury direction (no reviewer models, no GPU).

Turns an agent run into the frozen run_trace.jsonl that jury_review.py consumes, so
the evidence + coverage arbiter can mint training data from the trajectories we
ALREADY generate. Standalone on purpose: it does NOT modify deep_chain_eval (which
the live gate is using); the runner/deep-chain just CALL this.

Key correctness point baked in: the deep-chain (and any CTF/lab with a known flag)
is `lab_truth=known_vulnerable`, so a no-flag run is a MISSED finding (gold for
dpo_negative), never a true negative. See [[ai-trains-ai-jury-direction]].
"""
from __future__ import annotations

import json
from pathlib import Path


class TraceRecorder:
    """Append one frozen-schema step per agent turn, then finalize with the outcome."""

    def __init__(self) -> None:
        self.steps: list[dict] = []

    def step(self, *, state: str = "", action: str = "", tool_result: str = "",
             evidence=None, safety_status: str = "ok",
             objective_progress: float = 0.0, failure_reason: str = "") -> "TraceRecorder":
        self.steps.append({
            "state": state, "action": action, "tool_result": tool_result,
            "evidence": list(evidence or []), "safety_status": safety_status,
            "objective_progress": objective_progress, "failure_reason": failure_reason,
            "final_outcome": "", "no_finding": {},
        })
        return self

    def finalize(self, outcome: str, *, no_finding: dict | None = None) -> list[dict]:
        if self.steps:
            self.steps[-1]["final_outcome"] = outcome
            if no_finding:
                self.steps[-1]["no_finding"] = no_finding
        return self.steps

    def write(self, path: str) -> list[dict]:
        Path(path).write_text("\n".join(json.dumps(s) for s in self.steps) + "\n")
        return self.steps


def from_deep_chain(result: dict, step_sigs: list[str], *,
                    lab_truth: str = "known_vulnerable") -> list[dict]:
    """Build a trace from a deep_chain run: its {flag,steps,idor,logged_in,unique}
    result + the per-step action signatures. Because the lab HAS a flag, a no-flag
    run is a missed_finding, never a true negative."""
    rec = TraceRecorder()
    n = max(len(step_sigs), 1)
    for i, sig in enumerate(step_sigs):
        rec.step(state=f"step{i + 1}", action=sig, tool_result="observed",
                 evidence=[f"deep_chain-step-{i + 1}"],
                 objective_progress=round((i + 1) / n, 3))
    if result.get("flag"):
        return rec.finalize("solved")
    coverage = [f"routes_seen:{result.get('unique', 0)}"]
    if result.get("logged_in"):
        coverage.append("auth_checked")
    if result.get("idor"):
        coverage.append("idor_probed")
    untested = [] if result.get("idor") else ["admin/token path not reached"]
    return rec.finalize("no_confirmed_finding", no_finding={
        "lab_truth": lab_truth, "coverage": coverage, "blockers": [],
        "untested_boundaries": untested, "conscious_restraint": False,
    })
