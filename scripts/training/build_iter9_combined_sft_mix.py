"""Build the iter9 combined SFT mix for the next training candidate.

The mix is deliberately narrow:

* iter5 curated SFT mix as the stable base
* iter6 auth/authz follow-through rows
* V4-Pro demonstrated rows that pass the blocked-goal recovery arc guard

It does not synthesize new rows, execute labs, or mutate runtime state.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.training.generate_v4pro_demonstrated_chains_iter9 import (
    _has_blocked_goal_recovery_arc,
)
from scripts.training.jury_factory import load_held_out, scenario_hash
from scripts.training.make_curated_sft_mix_iter5 import content_hash

DEFAULT_TRAINING_DIR = Path.home() / ".aegispt-tools" / "training"
DEFAULT_OUT_DIR = Path("codex/results/training/iter9-combined-sft-mix-20260607")
DEFAULT_PREFIX = "aegispt_iter9_combined_sft_mix"
DEFAULT_CURATED_PATH = DEFAULT_TRAINING_DIR / "aegispt_curated_sft_mix_iter5.jsonl"
DEFAULT_ITER6_PATH = DEFAULT_TRAINING_DIR / "aegispt_multiturn_agentic_chain_iter6_train.jsonl"
DEFAULT_V4PRO_PATHS = (
    Path("codex/results/training/v4pro-demonstrated-chains-20260607-scale/aegispt_v4pro_demonstrated_chains_iter9_train.jsonl"),
    Path("codex/results/training/v4pro-demonstrated-chains-20260607-accepted/aegispt_v4pro_demonstrated_chains_iter9_train.jsonl"),
)
DEFAULT_HELD_OUT_REGISTRY = Path(
    "codex/results/training/iter8-multiservice-diversity-20260607/aegispt_lab_truth_heldout_registry_iter6.json"
)
DEFAULT_ITER6_CHAIN_CLASSES = (
    "api_object_authorization_chain",
    "web_auth_followthrough",
)
FORBIDDEN_HELD_OUT_STRINGS = (
    "flag{deep-eval-5b7c2}",
    "ADM-7741-KQ",
    "X-Admin-Token",
    "shop.lab",
    "/notes/",
    "/admin/config",
    "/reset_password",
)


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines()
        if line.strip()
    ]


def row_hash(row: dict[str, Any]) -> str:
    return content_hash(json.dumps(row, sort_keys=True))


def row_case_id(row: dict[str, Any], fallback: str) -> str:
    metadata = row.get("metadata")
    if isinstance(metadata, dict):
        return str(metadata.get("case_id") or metadata.get("scenario_id") or fallback)
    return fallback


def row_scenario_hash(row: dict[str, Any]) -> str:
    metadata = row.get("metadata")
    if not isinstance(metadata, dict):
        return ""
    return str(metadata.get("scenario_hash") or "")


def has_forbidden_held_out_string(row: dict[str, Any]) -> bool:
    serialized = json.dumps(row, sort_keys=True)
    return any(marker in serialized for marker in FORBIDDEN_HELD_OUT_STRINGS)


def load_held_out_hashes(paths: list[Path]) -> set[str]:
    existing = [str(path) for path in paths if path.exists()]
    if not existing:
        return set()
    return set(load_held_out(existing))


def held_out_collision(row: dict[str, Any], held_out: set[str]) -> bool:
    if not held_out:
        return False
    case_id = row_case_id(row, "")
    candidates = {case_id, scenario_hash(case_id)}
    scenario = row_scenario_hash(row)
    if scenario:
        candidates.add(scenario)
    return any(candidate in held_out for candidate in candidates if candidate)


def source_record(row: dict[str, Any], *, family: str, source_path: Path, line_number: int) -> dict[str, Any]:
    return {
        "case_id": row_case_id(row, f"{source_path.name}:{line_number}"),
        "content_hash": row_hash(row),
        "family": family,
        "line_number": line_number,
        "path": str(source_path),
        "row": row,
        "scenario_hash": row_scenario_hash(row),
    }


def iter6_records(path: Path, chain_classes: set[str]) -> list[dict[str, Any]]:
    rows = []
    for line_number, row in enumerate(read_jsonl(path), start=1):
        metadata = row.get("metadata", {})
        if not isinstance(metadata, dict):
            continue
        if str(metadata.get("chain_class")) not in chain_classes:
            continue
        rows.append(source_record(row, family="iter6_auth", source_path=path, line_number=line_number))
    return rows


def curated_records(path: Path) -> list[dict[str, Any]]:
    return [
        source_record(row, family="curated_iter5", source_path=path, line_number=line_number)
        for line_number, row in enumerate(read_jsonl(path), start=1)
    ]


def v4pro_records(paths: list[Path], held_out: set[str]) -> tuple[list[dict[str, Any]], dict[str, int]]:
    accepted: list[dict[str, Any]] = []
    skipped = Counter()
    for path in paths:
        for line_number, row in enumerate(read_jsonl(path), start=1):
            if held_out_collision(row, held_out):
                skipped["held_out_collision"] += 1
                continue
            if has_forbidden_held_out_string(row):
                skipped["held_out_string"] += 1
                continue
            if not _has_blocked_goal_recovery_arc(row):
                skipped["missing_blocked_goal_recovery_arc"] += 1
                continue
            accepted.append(source_record(row, family="v4pro_demonstrated_iter9", source_path=path, line_number=line_number))
    return accepted, dict(sorted(skipped.items()))


def select_records(records: list[dict[str, Any]], *, held_out: set[str], seen: set[str]) -> tuple[list[dict[str, Any]], dict[str, int]]:
    selected: list[dict[str, Any]] = []
    skipped = Counter()
    for record in records:
        row = record["row"]
        if record["content_hash"] in seen:
            skipped["duplicate_content"] += 1
            continue
        if held_out_collision(row, held_out):
            skipped["held_out_collision"] += 1
            continue
        if has_forbidden_held_out_string(row):
            skipped["held_out_string"] += 1
            continue
        selected.append(record)
        seen.add(record["content_hash"])
    return selected, dict(sorted(skipped.items()))


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_gzip_jsonl(path: Path, rows: list[dict[str, Any]]) -> dict[str, Any]:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as handle:
            for row in rows:
                handle.write((json.dumps(row, sort_keys=True) + "\n").encode("utf-8"))
    return {
        "bytes": path.stat().st_size,
        "path": str(path),
        "row_count": len(rows),
        "sha256": _sha256(path),
    }


def build_mix(
    *,
    curated_path: Path = DEFAULT_CURATED_PATH,
    iter6_path: Path = DEFAULT_ITER6_PATH,
    v4pro_paths: list[Path] | None = None,
    held_out_registry_paths: list[Path] | None = None,
    out_dir: Path = DEFAULT_OUT_DIR,
    prefix: str = DEFAULT_PREFIX,
    iter6_chain_classes: tuple[str, ...] = DEFAULT_ITER6_CHAIN_CLASSES,
) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    v4_paths = list(v4pro_paths or DEFAULT_V4PRO_PATHS)
    held_out_paths = list(held_out_registry_paths or [DEFAULT_HELD_OUT_REGISTRY])
    held_out = load_held_out_hashes(held_out_paths)
    seen: set[str] = set()

    curated_selected, curated_skipped = select_records(
        curated_records(curated_path),
        held_out=held_out,
        seen=seen,
    )
    iter6_selected, iter6_skipped = select_records(
        iter6_records(iter6_path, set(iter6_chain_classes)),
        held_out=held_out,
        seen=seen,
    )
    v4_selected_raw, v4_guard_skipped = v4pro_records(v4_paths, held_out)
    v4_selected, v4_dedupe_skipped = select_records(v4_selected_raw, held_out=held_out, seen=seen)
    selected = curated_selected + iter6_selected + v4_selected

    train_rows = [record["row"] for record in selected]
    source_rows = [
        {
            "case_id": record["case_id"],
            "content_hash": record["content_hash"],
            "family": record["family"],
            "line_number": record["line_number"],
            "mix_index": idx,
            "path": record["path"],
            "scenario_hash": record["scenario_hash"],
        }
        for idx, record in enumerate(selected, start=1)
    ]
    train_info = write_gzip_jsonl(out_dir / f"{prefix}_train.jsonl.gz", train_rows)
    source_info = write_gzip_jsonl(out_dir / f"{prefix}_source_map.jsonl.gz", source_rows)
    per_family = Counter(record["family"] for record in selected)
    manifest = {
        "dataset": prefix,
        "files": {
            "source_map": source_info,
            "train": train_info,
        },
        "format": "gzip-compressed chat SFT jsonl plus gzip source map",
        "policy": {
            "blocked_goal_recovery_required_for_v4pro": True,
            "data_lane_only": True,
            "held_out_guard": True,
            "iter6_chain_classes": list(iter6_chain_classes),
            "runtime_execution": False,
            "v4pro_happy_path_rows_rejected": True,
        },
        "sources": {
            "curated_iter5": str(curated_path),
            "held_out_registries": [str(path) for path in held_out_paths],
            "iter6": str(iter6_path),
            "v4pro": [str(path) for path in v4_paths],
        },
        "stats": {
            "held_out_hashes": len(held_out),
            "per_family": dict(sorted(per_family.items())),
            "selected_total": len(selected),
            "skipped": {
                "curated_iter5": curated_skipped,
                "iter6_auth": iter6_skipped,
                "v4pro_dedupe": v4_dedupe_skipped,
                "v4pro_guard": v4_guard_skipped,
            },
        },
    }
    manifest_path = out_dir / f"{prefix}_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--curated", type=Path, default=DEFAULT_CURATED_PATH)
    parser.add_argument("--iter6", type=Path, default=DEFAULT_ITER6_PATH)
    parser.add_argument("--v4pro", type=Path, action="append")
    parser.add_argument("--held-out", type=Path, action="append")
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    parser.add_argument("--prefix", default=DEFAULT_PREFIX)
    parser.add_argument("--iter6-chain-class", action="append", help="Can be supplied more than once.")
    args = parser.parse_args()
    manifest = build_mix(
        curated_path=args.curated,
        iter6_path=args.iter6,
        v4pro_paths=args.v4pro,
        held_out_registry_paths=args.held_out,
        out_dir=args.out_dir,
        prefix=args.prefix,
        iter6_chain_classes=tuple(args.iter6_chain_class or DEFAULT_ITER6_CHAIN_CLASSES),
    )
    print(json.dumps(manifest["stats"], indent=2, sort_keys=True))
    print(f"manifest: {args.out_dir / (args.prefix + '_manifest.json')}")


if __name__ == "__main__":
    main()
