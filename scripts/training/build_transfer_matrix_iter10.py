"""Build a class x model transfer matrix from rollout result artifacts.

The generalized rollout driver writes ``res_*.json`` files per rollout. This
aggregator joins those results with one or more env manifests so transfer can
be read per chain class instead of as one aggregate "any flag" number.

It is eval/reporting only: it does not create SFT rows and should be safe to
run over held-out D2 eval rollouts.
"""

from __future__ import annotations

import argparse
import json
import shlex
from collections import Counter, defaultdict
from pathlib import Path
from statistics import mean
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_D2_DIR = REPO_ROOT / "codex" / "results" / "training" / "multichain-heldout-eval-envs-20260607"
DEFAULT_D2_MANIFEST = DEFAULT_D2_DIR / "aegispt_multichain_heldout_eval_envs_iter10_manifest.json"
DEFAULT_OUT_DIR = REPO_ROOT / "codex" / "results" / "training" / "transfer-matrix-20260607"
DEFAULT_PREFIX = "aegispt_transfer_matrix_iter10"


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def load_scenario_index(manifest_paths: list[Path]) -> dict[str, dict[str, Any]]:
    index: dict[str, dict[str, Any]] = {}
    for path in manifest_paths:
        data = read_json(path)
        manifest = data.get("manifest") if isinstance(data.get("manifest"), dict) else data
        for item in manifest.get("scenarios", []):
            scenario_id = str(item.get("scenario_id", ""))
            if not scenario_id:
                continue
            index[scenario_id] = {
                "chain_class": item.get("chain_class", "unknown"),
                "dataset_family": item.get("dataset_family", manifest.get("dataset", "")),
                "domain": item.get("domain", ""),
                "lab_truth": item.get("lab_truth", ""),
                "scenario_hash": item.get("scenario_hash", ""),
            }
    return index


def parse_run_arg(value: str) -> tuple[str, Path]:
    if "=" in value:
        label, raw_path = value.split("=", 1)
        label = label.strip()
        if not label:
            raise ValueError(f"empty run label in {value!r}")
        return label, Path(raw_path)
    path = Path(value)
    return path.name or "run", path


def command_path(path: Path) -> str:
    try:
        path = path.resolve().relative_to(REPO_ROOT)
    except ValueError:
        path = path.resolve()
    return shlex.quote(path.as_posix())


def ledger_ingest_command(matrix_path: Path, *, write: bool = False) -> str:
    parts = [
        "python3",
        "scripts/validation/build_evidence_ledger.py",
        "--transfer-matrix",
        command_path(matrix_path),
    ]
    parts.append("--write" if write else "--summary-json")
    return " ".join(parts)


def load_results(run_label: str, rollout_dir: Path, scenario_index: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in sorted(rollout_dir.glob("res_*.json")):
        result = read_json(path)
        scenario_id = str(result.get("scenario_id", ""))
        scenario = scenario_index.get(scenario_id, {})
        rows.append(
            {
                "blocked_goal": bool(result.get("blocked_goal")),
                "chain_class": str(scenario.get("chain_class") or result.get("chain_class") or "unknown"),
                "dataset_family": str(scenario.get("dataset_family") or ""),
                "domain": str(scenario.get("domain") or ""),
                "flag": bool(result.get("flag")),
                "lab_truth": str(result.get("lab_truth") or scenario.get("lab_truth") or ""),
                "pivot": bool(result.get("pivot") or result.get("idor")),
                "recovered_after_block": bool(result.get("recovered_after_block")),
                "result_path": str(path),
                "reward": int(result.get("reward") or 0),
                "run_label": run_label,
                "scenario_hash": str(result.get("scenario_hash") or scenario.get("scenario_hash") or ""),
                "scenario_id": scenario_id,
                "steps": int(result.get("steps") or 0),
                "used_revealed_value": bool(result.get("used_revealed_value")),
            }
        )
    return rows


def summarize_group(rows: list[dict[str, Any]]) -> dict[str, Any]:
    attempts = len(rows)
    rewards = [int(row["reward"]) for row in rows]
    steps = [int(row["steps"]) for row in rows if int(row["steps"]) > 0]
    solved = sum(1 for row in rows if row["flag"])
    recovered = sum(1 for row in rows if row["recovered_after_block"])
    revealed = sum(1 for row in rows if row["used_revealed_value"])
    pivot = sum(1 for row in rows if row["pivot"])
    return {
        "attempts": attempts,
        "avg_reward": round(mean(rewards), 3) if rewards else 0.0,
        "avg_steps": round(mean(steps), 3) if steps else 0.0,
        "blocked_goal_rate": round(sum(1 for row in rows if row["blocked_goal"]) / attempts, 3) if attempts else 0.0,
        "failed_scenario_ids": sorted({row["scenario_id"] for row in rows if not row["flag"]}),
        "max_reward": max(rewards) if rewards else 0,
        "pivot_rate": round(pivot / attempts, 3) if attempts else 0.0,
        "recovered_after_block_rate": round(recovered / attempts, 3) if attempts else 0.0,
        "scenario_count": len({row["scenario_id"] for row in rows}),
        "solved": solved,
        "solve_rate": round(solved / attempts, 3) if attempts else 0.0,
        "used_revealed_value_rate": round(revealed / attempts, 3) if attempts else 0.0,
    }


def build_matrix(
    *,
    runs: list[tuple[str, Path]],
    manifest_paths: list[Path],
) -> dict[str, Any]:
    scenario_index = load_scenario_index(manifest_paths)
    rows: list[dict[str, Any]] = []
    for label, path in runs:
        rows.extend(load_results(label, path, scenario_index))
    by_run_class: dict[str, dict[str, Any]] = {}
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[(row["run_label"], row["chain_class"])].append(row)
    for (run_label, chain_class), group in sorted(grouped.items()):
        by_run_class[f"{run_label}::{chain_class}"] = {
            "chain_class": chain_class,
            "run_label": run_label,
            **summarize_group(group),
        }
    by_run = {
        run_label: summarize_group([row for row in rows if row["run_label"] == run_label])
        for run_label in sorted({row["run_label"] for row in rows})
    }
    by_class = {
        chain_class: summarize_group([row for row in rows if row["chain_class"] == chain_class])
        for chain_class in sorted({row["chain_class"] for row in rows})
    }
    expected_scenario_ids = set(scenario_index)
    missing_by_run: dict[str, list[str]] = {}
    unknown_by_run: dict[str, list[str]] = {}
    duplicate_by_run: dict[str, list[str]] = {}
    for run_label, _path in runs:
        run_rows = [row for row in rows if row["run_label"] == run_label]
        present = {row["scenario_id"] for row in run_rows if row["scenario_id"]}
        missing = sorted(expected_scenario_ids - present)
        if missing:
            missing_by_run[run_label] = missing
        unknown = sorted(
            {
                row["scenario_id"]
                for row in run_rows
                if not row["scenario_id"] or row["scenario_id"] not in expected_scenario_ids
            }
        )
        if unknown:
            unknown_by_run[run_label] = unknown
        counts = Counter(row["scenario_id"] for row in run_rows if row["scenario_id"])
        duplicates = sorted(scenario_id for scenario_id, count in counts.items() if count > 1)
        if duplicates:
            duplicate_by_run[run_label] = duplicates
    return {
        "dataset": DEFAULT_PREFIX,
        "matrix": by_run_class,
        "policy": {
            "data_lane_only": True,
            "held_out_eval_safe": True,
            "no_training_rows_generated": True,
            "runtime_execution": False,
        },
        "rows": rows,
        "scenario_index_count": len(scenario_index),
        "stats": {
            "by_class": by_class,
            "by_run": by_run,
            "chain_class_count": len({row["chain_class"] for row in rows}),
            "result_count": len(rows),
            "run_count": len({row["run_label"] for row in rows}),
            "run_labels": sorted({row["run_label"] for row in rows}),
            "scenario_count": len({row["scenario_id"] for row in rows}),
            "expected_scenario_count": len(expected_scenario_ids),
            "missing_scenario_ids_by_run": missing_by_run,
            "unknown_scenario_ids_by_run": unknown_by_run,
            "duplicate_scenario_ids_by_run": duplicate_by_run,
            "complete_run_count": sum(
                1
                for run_label, _path in runs
                if run_label not in missing_by_run and run_label not in unknown_by_run
            ),
            "unknown_chain_class_count": sum(1 for row in rows if row["chain_class"] == "unknown"),
        },
    }


def validate_complete_scenarios(matrix: dict[str, Any]) -> None:
    stats = matrix.get("stats", {})
    missing = stats.get("missing_scenario_ids_by_run") or {}
    unknown = stats.get("unknown_scenario_ids_by_run") or {}
    if missing or unknown:
        raise ValueError(
            "transfer matrix is incomplete: "
            f"missing_scenario_ids_by_run={missing}; "
            f"unknown_scenario_ids_by_run={unknown}"
        )


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")


def write_outputs(matrix: dict[str, Any], out_dir: Path, prefix: str = DEFAULT_PREFIX) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    matrix_path = out_dir / f"{prefix}.json"
    rows_path = out_dir / f"{prefix}_rows.jsonl"
    summary_path = out_dir / f"{prefix}_summary.md"
    matrix_path.write_text(json.dumps(matrix, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    write_jsonl(rows_path, matrix["rows"])
    lines = [
        "# Transfer matrix iter10",
        "",
        f"- runs: {matrix['stats']['run_count']}",
        f"- scenarios: {matrix['stats']['scenario_count']}",
        f"- expected scenarios: {matrix['stats']['expected_scenario_count']}",
        f"- results: {matrix['stats']['result_count']}",
        f"- complete runs: {matrix['stats']['complete_run_count']}",
        "- policy: eval/reporting only; no training rows generated",
        "",
        "## Ledger ingestion",
        "",
        "Summary check:",
        "",
        f"`{ledger_ingest_command(matrix_path)}`",
        "",
        "Materialize canonical ledger with this transfer matrix:",
        "",
        f"`{ledger_ingest_command(matrix_path, write=True)}`",
        "",
        "## Run x Class",
        "",
    ]
    for item in matrix["matrix"].values():
        lines.append(
            f"- `{item['run_label']}` / `{item['chain_class']}`: "
            f"solve_rate={item['solve_rate']}; "
            f"recover_rate={item['recovered_after_block_rate']}; "
            f"revealed_rate={item['used_revealed_value_rate']}; "
            f"avg_reward={item['avg_reward']}; attempts={item['attempts']}"
        )
    summary_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return {
        "files": {
            "matrix": str(matrix_path),
            "rows": str(rows_path),
            "summary_markdown": str(summary_path),
        },
        "commands": {
            "ledger_summary": ledger_ingest_command(matrix_path),
            "ledger_write": ledger_ingest_command(matrix_path, write=True),
        },
        **matrix["stats"],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--run",
        action="append",
        help="Run as LABEL=rollout_dir. Defaults to oracle D2 held-out artifacts.",
    )
    parser.add_argument(
        "--manifest",
        action="append",
        type=Path,
        help="Env manifest path. Defaults to D2 held-out manifest.",
    )
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    parser.add_argument("--prefix", default=DEFAULT_PREFIX)
    parser.add_argument(
        "--require-complete-scenarios",
        action="store_true",
        help=(
            "Fail if any run misses a manifest scenario or emits an unknown "
            "scenario_id. Multiple samples per scenario are allowed."
        ),
    )
    args = parser.parse_args()
    runs = [parse_run_arg(item) for item in (args.run or [f"d2_oracle={DEFAULT_D2_DIR}"])]
    manifest_paths = list(args.manifest or [DEFAULT_D2_MANIFEST])
    matrix = build_matrix(runs=runs, manifest_paths=manifest_paths)
    if args.require_complete_scenarios:
        validate_complete_scenarios(matrix)
    summary = write_outputs(matrix, args.out_dir, prefix=args.prefix)
    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
