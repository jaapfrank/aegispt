"""Build an evidence-first XBEN triage backlog from the solve-gap matrix.

This script deliberately does not infer vulnerability labels for unknown rows.
It turns the current matrix into a worklist: which rows need source triage,
which known classes still lack env/demo coverage, and which covered rows should
move to rollout/eval. That keeps the data lane honest while the XBEN matrix is
still incomplete.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MATRIX_PATH = (
    REPO_ROOT
    / "codex"
    / "results"
    / "training"
    / "xben-gap-matrix-20260607"
    / "aegispt_xben_gap_matrix_iter10.jsonl"
)
DEFAULT_OUT_DIR = REPO_ROOT / "codex" / "results" / "training" / "xben-triage-backlog-20260607"
DEFAULT_PREFIX = "aegispt_xben_triage_backlog_iter10"


def load_matrix(path: Path = DEFAULT_MATRIX_PATH) -> list[dict[str, Any]]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _xben_number(row: dict[str, Any]) -> int:
    return int(str(row.get("xben_id", "XBEN-000")).rsplit("-", 1)[-1])


def neighbor_context(row: dict[str, Any], rows_by_number: dict[int, dict[str, Any]]) -> list[dict[str, Any]]:
    number = _xben_number(row)
    context: list[dict[str, Any]] = []
    for neighbor_number in range(number - 2, number + 3):
        if neighbor_number == number:
            continue
        neighbor = rows_by_number.get(neighbor_number)
        if not neighbor:
            continue
        vuln_class = str(neighbor.get("vuln_class", ""))
        if vuln_class == "unknown_untriaged":
            continue
        context.append(
            {
                "coverage_bucket": neighbor.get("coverage_bucket"),
                "distance": abs(neighbor_number - number),
                "solve_status": neighbor.get("solve_status"),
                "vuln_class": vuln_class,
                "xben_id": neighbor.get("xben_id"),
            }
        )
    return sorted(context, key=lambda item: (item["distance"], str(item["xben_id"])))


def lane_for_row(row: dict[str, Any]) -> str:
    if row.get("has_solve"):
        return "solved_reference_only"
    if row.get("vuln_class") == "unknown_untriaged":
        return "source_triage_required"
    if not row.get("has_env") or not row.get("has_teacher_demo"):
        return "known_gap_needs_data"
    return "covered_needs_rollout_eval"


def priority_for_row(row: dict[str, Any], lane: str) -> int:
    evidence_bonus = 2 if row.get("evidence_paths") else 0
    attempted_bonus = 2 if row.get("solve_status") == "attempted_no_solve" else 0
    if lane == "source_triage_required":
        return 80 + evidence_bonus + attempted_bonus
    if lane == "known_gap_needs_data":
        return 60 + evidence_bonus + attempted_bonus
    if lane == "covered_needs_rollout_eval":
        return 40 + evidence_bonus + attempted_bonus
    return 0


def recommended_next_step(row: dict[str, Any], lane: str) -> str:
    if lane == "source_triage_required":
        if row.get("evidence_paths"):
            return "read_committed_evidence_and_challenge_source; assign vuln_class only with direct evidence"
        return "collect_source_or_run_summary_before_labeling; keep unknown out of training data"
    if lane == "known_gap_needs_data":
        return "build_or_map_env_and_teacher_demo_for_existing_evidence_class"
    if lane == "covered_needs_rollout_eval":
        return "run_rollout_or_live_eval_against_existing_env_demo_coverage"
    return "keep_as_solve_evidence_not_training_gap"


def build_backlog(rows: list[dict[str, Any]]) -> dict[str, Any]:
    rows_by_number = {_xben_number(row): row for row in rows}
    items: list[dict[str, Any]] = []
    for row in rows:
        lane = lane_for_row(row)
        if lane == "solved_reference_only":
            continue
        item = {
            "coverage_bucket": row.get("coverage_bucket"),
            "current_vuln_class": row.get("vuln_class"),
            "evidence_paths": row.get("evidence_paths", []),
            "has_env": bool(row.get("has_env")),
            "has_solve": bool(row.get("has_solve")),
            "has_teacher_demo": bool(row.get("has_teacher_demo")),
            "label_policy": "do_not_infer_labels_from_neighbors",
            "lane": lane,
            "neighbor_context_not_label": neighbor_context(row, rows_by_number),
            "priority": priority_for_row(row, lane),
            "recommended_next_step": recommended_next_step(row, lane),
            "solve_status": row.get("solve_status"),
            "xben_id": row.get("xben_id"),
        }
        items.append(item)
    items.sort(
        key=lambda item: (
            -int(item["priority"]),
            str(item["lane"]),
            str(item["coverage_bucket"]),
            str(item["xben_id"]),
        )
    )
    by_lane = Counter(str(item["lane"]) for item in items)
    by_bucket = Counter(str(item["coverage_bucket"]) for item in items)
    unknown_items = [item for item in items if item["lane"] == "source_triage_required"]
    return {
        "dataset": DEFAULT_PREFIX,
        "items": items,
        "matrix_source": str(DEFAULT_MATRIX_PATH),
        "policy": {
            "data_lane_only": True,
            "no_training_rows_generated": True,
            "unknown_rows_are_not_labeled": True,
            "neighbor_context_is_not_a_label": True,
        },
        "stats": {
            "by_bucket": dict(sorted(by_bucket.items())),
            "by_lane": dict(sorted(by_lane.items())),
            "item_count": len(items),
            "source_triage_required_count": len(unknown_items),
            "source_triage_with_existing_evidence_count": sum(
                1 for item in unknown_items if item["evidence_paths"]
            ),
            "top_unknown_xben_ids": [str(item["xben_id"]) for item in unknown_items[:24]],
        },
    }


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")


def write_outputs(backlog: dict[str, Any], out_dir: Path, prefix: str = DEFAULT_PREFIX) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / f"{prefix}.json"
    jsonl_path = out_dir / f"{prefix}.jsonl"
    markdown_path = out_dir / f"{prefix}_summary.md"
    json_path.write_text(json.dumps(backlog, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    write_jsonl(jsonl_path, list(backlog["items"]))
    lines = [
        "# XBEN triage backlog iter10",
        "",
        f"- items: {backlog['stats']['item_count']}",
        f"- source triage required: {backlog['stats']['source_triage_required_count']}",
        "- policy: unknown rows are not labeled from neighbor context",
        "",
        "## Lanes",
        "",
    ]
    for lane, count in backlog["stats"]["by_lane"].items():
        lines.append(f"- `{lane}`: {count}")
    lines.extend(["", "## Top Unknown Rows", ""])
    for item in [
        row for row in backlog["items"] if row["lane"] == "source_triage_required"
    ][:16]:
        evidence = "yes" if item["evidence_paths"] else "no"
        lines.append(
            f"- `{item['xben_id']}`: evidence={evidence}; "
            f"next={item['recommended_next_step']}"
        )
    markdown_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return {
        "files": {
            "backlog": str(json_path),
            "backlog_jsonl": str(jsonl_path),
            "summary_markdown": str(markdown_path),
        },
        **backlog["stats"],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--matrix", type=Path, default=DEFAULT_MATRIX_PATH)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    parser.add_argument("--prefix", default=DEFAULT_PREFIX)
    args = parser.parse_args()
    rows = load_matrix(args.matrix)
    backlog = build_backlog(rows)
    backlog["matrix_source"] = str(args.matrix)
    summary = write_outputs(backlog, args.out_dir, prefix=args.prefix)
    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
