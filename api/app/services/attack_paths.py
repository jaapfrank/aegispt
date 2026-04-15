from __future__ import annotations

from typing import Any
from uuid import UUID


def build_attack_graph(run_id: UUID | str) -> dict[str, Any]:
    return {
        "status": "placeholder",
        "run_id": str(run_id),
        "nodes": [],
        "edges": [],
        "sources": ["inventory", "findings", "capability-packs"],
        "notes": "Future attack path engine will compose attack chains from existing evidence and adaptive pack context.",
    }


def evaluate_paths(run_id: UUID | str) -> dict[str, Any]:
    return {
        "status": "placeholder",
        "run_id": str(run_id),
        "candidate_paths": [],
        "evaluation_model": "future-risk-scoring-engine",
        "notes": "Future path evaluation will remain evidence-first and read-only against completed run state.",
    }
