"""Build prioritized triage rows from iter-5 near-duplicate flags.

The near-duplicate flagger intentionally writes review-only findings. This
script turns those flags into an operator-facing cleanup queue so training can
prioritize train/eval leakage before lower-risk template diversity cleanup.

It never rewrites source datasets.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any

DEFAULT_TRAINING_DIR = Path.home() / ".aegispt-tools" / "training"
DEFAULT_FLAGS_PATH = DEFAULT_TRAINING_DIR / "aegispt_near_duplicate_flags_iter5.jsonl"
DEFAULT_OUT_DIR = DEFAULT_TRAINING_DIR
DEFAULT_PREFIX = "aegispt_duplicate_triage_iter5"


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        raise FileNotFoundError(f"duplicate flag file not found: {path}")
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def priority(flag: dict[str, Any]) -> str:
    recommendation = flag["recommendation"]
    family_pair = set(flag["family_pair"])
    if recommendation == "drop_or_rewrite_train_row_before_eval_to_prevent_leakage":
        return "p0_train_eval_or_test_leakage"
    if "aegispt_combined_all" in family_pair:
        return "p1_combined_dataset_overlap"
    if recommendation == "manual_review_keep_only_if_curriculum_overlap_is_intentional":
        return "p1_cross_family_overlap"
    if flag["split_pair"] == ["train"]:
        return "p2_train_template_diversity"
    return "p3_manual_review"


def action_for(priority_value: str) -> str:
    return {
        "p0_train_eval_or_test_leakage": "rewrite_or_drop_train_row_before_final_eval",
        "p1_combined_dataset_overlap": "rebuild_combined_family_after_source_cleanup",
        "p1_cross_family_overlap": "manual_review_curriculum_overlap",
        "p2_train_template_diversity": "deduplicate_or_diversify_train_templates",
        "p3_manual_review": "manual_review",
    }[priority_value]


def training_impact(priority_value: str) -> str:
    return {
        "p0_train_eval_or_test_leakage": "eval_or_test_score_may_be_inflated_if_left_unfixed",
        "p1_combined_dataset_overlap": "combined_training_mix_may_repeat_rows_from_source_families",
        "p1_cross_family_overlap": "curriculum_overlap_may_be_intentional_but_should_be_documented",
        "p2_train_template_diversity": "model_may_overfit_template_shape_or_marker_language",
        "p3_manual_review": "requires_operator_judgment",
    }[priority_value]


def rewrite_recipe(flag: dict[str, Any], priority_value: str) -> dict[str, Any]:
    primary = flag["primary"]
    duplicate = flag["duplicate"]
    train_ref = primary if primary["split"] == "train" else duplicate if duplicate["split"] == "train" else None
    if priority_value == "p0_train_eval_or_test_leakage":
        return {
            "candidate_row": train_ref,
            "preferred_action": "drop_or_rewrite_train_candidate",
            "rewrite_requirements": [
                "change scenario structure, not only marker or host",
                "change evidence expectation shape",
                "preserve safety tags and approval gates",
                "rerun near-duplicate flagger before final eval",
            ],
        }
    if priority_value == "p1_combined_dataset_overlap":
        return {
            "candidate_row": None,
            "preferred_action": "regenerate_combined_mix_after_source_families_are_clean",
            "rewrite_requirements": [
                "do not score combined family against source eval/test rows",
                "document whether combined rows are derived or canonical",
            ],
        }
    if priority_value == "p1_cross_family_overlap":
        return {
            "candidate_row": train_ref,
            "preferred_action": "keep_only_if_learning_objective_differs",
            "rewrite_requirements": [
                "confirm family-specific objective differs",
                "add provenance note if overlap is intentional",
            ],
        }
    return {
        "candidate_row": duplicate,
        "preferred_action": "diversify_template_or_cap_duplicate_frequency",
        "rewrite_requirements": [
            "vary task framing and evidence fields",
            "avoid cosmetic-only target or marker changes",
        ],
    }


def triage_row(index: int, flag: dict[str, Any]) -> dict[str, Any]:
    priority_value = priority(flag)
    return {
        "action": action_for(priority_value),
        "duplicate": flag["duplicate"],
        "family_pair": flag["family_pair"],
        "reason": flag["reason"],
        "recommendation": flag["recommendation"],
        "review_required": True,
        "rewrite_recipe": rewrite_recipe(flag, priority_value),
        "safe_to_auto_apply": False,
        "similarity": flag["similarity"],
        "source_flag_id": flag["flag_id"],
        "split_pair": flag["split_pair"],
        "training_impact": training_impact(priority_value),
        "triage_id": f"duplicate-triage-{index:05d}",
        "triage_priority": priority_value,
    }


def build_triage(flags: list[dict[str, Any]], *, limit: int | None = None) -> list[dict[str, Any]]:
    rows = [triage_row(index + 1, flag) for index, flag in enumerate(flags)]
    rows.sort(
        key=lambda row: (
            row["triage_priority"],
            row["family_pair"],
            row["split_pair"],
            row["source_flag_id"],
        )
    )
    if limit is not None:
        return rows[:limit]
    return rows


def summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    priorities = Counter(row["triage_priority"] for row in rows)
    actions = Counter(row["action"] for row in rows)
    family_pairs = Counter(" + ".join(row["family_pair"]) for row in rows)
    split_pairs = Counter(" + ".join(row["split_pair"]) for row in rows)
    return {
        "actions": dict(sorted(actions.items())),
        "family_pairs": dict(sorted(family_pairs.items())),
        "priorities": dict(sorted(priorities.items())),
        "split_pairs": dict(sorted(split_pairs.items())),
        "total_rows": len(rows),
    }


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")


def build_dataset(
    *,
    flags_path: Path = DEFAULT_FLAGS_PATH,
    out_dir: Path = DEFAULT_OUT_DIR,
    prefix: str = DEFAULT_PREFIX,
    limit: int | None = None,
) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    flags = load_jsonl(flags_path)
    rows = build_triage(flags, limit=limit)
    path = out_dir / f"{prefix}.jsonl"
    write_jsonl(path, rows)
    manifest = {
        "dataset": prefix,
        "format": "jsonl duplicate-triage queue",
        "path": str(path),
        "policy": {
            "non_destructive": True,
            "review_required": True,
            "rewrites_source_data": False,
            "safe_to_auto_apply": False,
        },
        "source_flags": str(flags_path),
        "source_flag_count": len(flags),
        "stats": summarize(rows),
    }
    manifest_path = out_dir / f"{prefix}_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--flags", type=Path, default=DEFAULT_FLAGS_PATH)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    parser.add_argument("--prefix", default=DEFAULT_PREFIX)
    parser.add_argument("--limit", type=int, default=None)
    args = parser.parse_args()
    manifest = build_dataset(
        flags_path=args.flags,
        out_dir=args.out_dir,
        prefix=args.prefix,
        limit=args.limit,
    )
    print(json.dumps(manifest["stats"], indent=2, sort_keys=True))
    print(f"manifest: {args.out_dir / (args.prefix + '_manifest.json')}")


if __name__ == "__main__":
    main()
