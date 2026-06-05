"""Create non-destructive training exclusions from iter-5 duplicate triage.

This turns duplicate triage into a hard exclusion list that a training mix can
consume without editing source datasets. Only high-confidence exclusions are
emitted:

- P0 train-vs-eval/test leakage: exclude the train-side row
- P1 combined dataset overlap: exclude the combined-all row and rebuild the mix

Template diversity rows remain review-only in the triage queue.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any

DEFAULT_TRAINING_DIR = Path.home() / ".aegispt-tools" / "training"
DEFAULT_TRIAGE_PATH = DEFAULT_TRAINING_DIR / "aegispt_duplicate_triage_iter5.jsonl"
DEFAULT_OUT_DIR = DEFAULT_TRAINING_DIR
DEFAULT_PREFIX = "aegispt_training_exclusions_iter5"


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        raise FileNotFoundError(f"triage file not found: {path}")
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def exclusion_key(ref: dict[str, Any]) -> tuple[str, int, str]:
    return (str(ref["path"]), int(ref["line"]), str(ref["case_id"]))


def refs_from_triage(row: dict[str, Any]) -> list[dict[str, Any]]:
    refs: list[dict[str, Any]] = []
    for key in ("primary", "duplicate"):
        value = row.get(key)
        if isinstance(value, dict):
            refs.append(value)
    candidate = row.get("rewrite_recipe", {}).get("candidate_row")
    if isinstance(candidate, dict):
        refs.insert(0, candidate)
    return refs


def select_exclusion_ref(row: dict[str, Any]) -> tuple[dict[str, Any] | None, str]:
    priority = row["triage_priority"]
    refs = refs_from_triage(row)
    if priority == "p0_train_eval_or_test_leakage":
        for ref in refs:
            if ref.get("split") == "train":
                return ref, "hard_exclude_train_leakage"
    if priority == "p1_combined_dataset_overlap":
        for ref in refs:
            if ref.get("dataset_family") == "aegispt_combined_all":
                return ref, "hard_exclude_combined_overlap"
    return None, "review_only"


def make_exclusion(row: dict[str, Any], ref: dict[str, Any], reason: str) -> dict[str, Any]:
    return {
        "case_id": ref["case_id"],
        "dataset_family": ref["dataset_family"],
        "exclusion_reason": reason,
        "line": ref["line"],
        "path": ref["path"],
        "review_required_before_reinclude": True,
        "safe_to_auto_delete_source": False,
        "source_triage_id": row["triage_id"],
        "split": ref["split"],
        "training_impact": row["training_impact"],
        "triage_priority": row["triage_priority"],
    }


def build_exclusions(triage_rows: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    exclusions: list[dict[str, Any]] = []
    review_only: list[dict[str, Any]] = []
    seen: set[tuple[str, int, str]] = set()
    for row in triage_rows:
        ref, reason = select_exclusion_ref(row)
        if ref is None:
            review_only.append(
                {
                    "source_triage_id": row["triage_id"],
                    "triage_priority": row["triage_priority"],
                    "reason": reason,
                    "action": row["action"],
                }
            )
            continue
        key = exclusion_key(ref)
        if key in seen:
            continue
        seen.add(key)
        exclusions.append(make_exclusion(row, ref, reason))
    exclusions.sort(key=lambda item: (item["triage_priority"], item["dataset_family"], item["path"], item["line"]))
    return exclusions, review_only


def summarize(exclusions: list[dict[str, Any]], review_only: list[dict[str, Any]]) -> dict[str, Any]:
    reasons = Counter(item["exclusion_reason"] for item in exclusions)
    families = Counter(item["dataset_family"] for item in exclusions)
    priorities = Counter(item["triage_priority"] for item in exclusions)
    review_priorities = Counter(item["triage_priority"] for item in review_only)
    return {
        "exclusion_reasons": dict(sorted(reasons.items())),
        "excluded_families": dict(sorted(families.items())),
        "excluded_priorities": dict(sorted(priorities.items())),
        "hard_exclusion_rows": len(exclusions),
        "review_only_priorities": dict(sorted(review_priorities.items())),
        "review_only_rows": len(review_only),
    }


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")


def build_dataset(
    *,
    triage_path: Path = DEFAULT_TRIAGE_PATH,
    out_dir: Path = DEFAULT_OUT_DIR,
    prefix: str = DEFAULT_PREFIX,
) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    triage_rows = load_jsonl(triage_path)
    exclusions, review_only = build_exclusions(triage_rows)
    path = out_dir / f"{prefix}.jsonl"
    write_jsonl(path, exclusions)
    manifest = {
        "dataset": prefix,
        "format": "jsonl hard training exclusions",
        "path": str(path),
        "policy": {
            "non_destructive": True,
            "review_required_before_reinclude": True,
            "rewrites_source_data": False,
            "safe_to_auto_delete_source": False,
        },
        "source_triage": str(triage_path),
        "source_triage_rows": len(triage_rows),
        "stats": summarize(exclusions, review_only),
    }
    manifest_path = out_dir / f"{prefix}_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--triage", type=Path, default=DEFAULT_TRIAGE_PATH)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    parser.add_argument("--prefix", default=DEFAULT_PREFIX)
    args = parser.parse_args()
    manifest = build_dataset(triage_path=args.triage, out_dir=args.out_dir, prefix=args.prefix)
    print(json.dumps(manifest["stats"], indent=2, sort_keys=True))
    print(f"manifest: {args.out_dir / (args.prefix + '_manifest.json')}")


if __name__ == "__main__":
    main()
