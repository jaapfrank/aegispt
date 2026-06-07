"""Generate focused V4-Pro teacher top-up rows for under-quota D1 classes.

This is a companion to ``generate_v4pro_demonstrated_chains_iter9.py``. The
main D1 job is intentionally left untouched while it runs; this script reads
its manifest, identifies chain classes below the target quota, and generates
additional rows into a separate output directory using the same prompt,
held-out registry, blocked-goal recovery guard, and ingest guard.
"""

from __future__ import annotations

import argparse
import json
import random
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.training import generate_v4pro_demonstrated_chains_iter9 as d1
from scripts.training.ingest_v4pro_demonstrated_chains_iter8 import ingest_rows, write_jsonl
from scripts.training.make_lab_truth_heldout_registry_iter6 import build_registry, load_registry

DEFAULT_BASE_MANIFEST = (
    REPO_ROOT
    / "codex"
    / "results"
    / "training"
    / "v4pro-teacher-corpus-d1-20260607"
    / "aegispt_v4pro_demonstrated_chains_iter9_manifest.json"
)
DEFAULT_OUT_DIR = (
    REPO_ROOT
    / "codex"
    / "results"
    / "training"
    / "v4pro-teacher-corpus-d1-topup-20260607"
)
DEFAULT_PREFIX = "aegispt_v4pro_teacher_topup_iter10"
DEFAULT_SEED = 2026060710


def load_base_counts(path: Path = DEFAULT_BASE_MANIFEST) -> dict[str, int]:
    data = json.loads(path.read_text(encoding="utf-8"))
    stats = data.get("stats") if isinstance(data.get("stats"), dict) else {}
    counts = stats.get("accepted_by_chain_class")
    if not isinstance(counts, dict):
        counts = data.get("quality_report", {}).get("accepted_by_chain_class", {})
    return {name: int(counts.get(name, 0)) for name in d1.TEACHER_CHAIN_CLASS_NAMES}


def deficits_from_counts(
    counts: dict[str, int],
    *,
    target_min: int,
    only_classes: list[str] | None = None,
) -> dict[str, int]:
    allowed = set(only_classes or d1.TEACHER_CHAIN_CLASS_NAMES)
    unknown = sorted(allowed - set(d1.TEACHER_CHAIN_CLASS_NAMES))
    if unknown:
        raise ValueError(f"unknown chain classes: {unknown}")
    return {
        name: max(0, target_min - int(counts.get(name, 0)))
        for name in d1.TEACHER_CHAIN_CLASS_NAMES
        if name in allowed and max(0, target_min - int(counts.get(name, 0))) > 0
    }


def _class_spec(chain_class: str) -> d1.TeacherChainClass:
    for item in d1.TEACHER_CHAIN_CLASSES:
        if item.chain_class == chain_class:
            return item
    raise ValueError(f"unknown chain_class: {chain_class}")


def make_scenario(chain_class: str, *, index: int, seed: int) -> d1.TeacherScenario:
    class_spec = _class_spec(chain_class)
    rng = random.Random(f"{seed}:{chain_class}:{index}")
    suffix = f"topup-{index:04d}-{rng.randint(1000, 9999)}"
    host = f"https://{chain_class.replace('_', '-')}-{suffix}.fictional-lab.example"
    lab_id = f"v4pro-teacher-topup-{chain_class}-{suffix}"
    marker = f"AEGISPT_V4PRO_TOPUP_{index:04d}_{rng.randint(100000, 999999)}"
    return d1.TeacherScenario(
        chain_class=class_spec.chain_class,
        domain=class_spec.domain,
        host=host,
        lab_id=lab_id,
        marker=marker,
        objective=class_spec.objective,
    )


def _scenario_registry_rows(rows: list[dict[str, Any]], prefix: str) -> list[dict[str, Any]]:
    return [
        {
            "case_id": row["metadata"]["case_id"],
            "dataset_family": prefix,
            "holdout_reason": "teacher_demonstrated_reserved_train",
            "original_case_id": row["metadata"]["original_case_id"],
            "scenario_hash": row["metadata"]["scenario_hash"],
            "scenario_id": row["metadata"]["case_id"],
            "source": "scripts/training/generate_v4pro_teacher_topup_iter10.py",
            "split": "train",
            "teacher_model": row["metadata"]["teacher_model"],
        }
        for row in rows
    ]


def _assistant_turn_count(row: dict[str, Any]) -> int:
    return sum(1 for item in row.get("messages", []) if item.get("role") == "assistant")


def _row_chain_class(row: dict[str, Any]) -> str:
    metadata = row.get("metadata")
    if isinstance(metadata, dict):
        return str(metadata.get("chain_class") or "unknown")
    return "unknown"


def _write_manifest(
    *,
    accepted: list[dict[str, Any]],
    attempts: int,
    base_manifest: Path,
    base_counts: dict[str, int],
    deficits_initial: dict[str, int],
    endpoint: str,
    manifest_path: Path,
    model: str,
    prefix: str,
    raw_path: Path,
    raw_rows: list[dict[str, Any]],
    rejected: list[dict[str, Any]],
    rejected_path: Path,
    scenario_registry_path: Path,
    stopped_reason: str,
    target_min: int,
    topup_classes: list[str],
    train_path: Path,
) -> dict[str, Any]:
    accepted_by_chain = dict(sorted(Counter(_row_chain_class(row) for row in accepted).items()))
    combined_counts = {
        name: int(base_counts.get(name, 0)) + int(accepted_by_chain.get(name, 0))
        for name in d1.TEACHER_CHAIN_CLASS_NAMES
    }
    deficits_remaining = deficits_from_counts(
        combined_counts,
        target_min=target_min,
        only_classes=topup_classes,
    )
    write_jsonl(raw_path, raw_rows)
    write_jsonl(train_path, accepted)
    write_jsonl(rejected_path, rejected)
    write_jsonl(scenario_registry_path, _scenario_registry_rows(accepted, prefix))
    manifest = {
        "base_manifest": str(base_manifest),
        "dataset": prefix,
        "endpoint": endpoint,
        "files": {
            "raw_teacher": str(raw_path),
            "rejected": str(rejected_path),
            "scenario_registry": str(scenario_registry_path),
            "train": str(train_path),
        },
        "model": model,
        "policy": {
            "blocked_goal_recovery_required": True,
            "data_lane_only": True,
            "held_out_guard": True,
            "runtime_execution": False,
            "secret_committed": False,
            "topup_only": True,
            "train_only": True,
        },
        "stats": {
            "accepted_by_chain_class": accepted_by_chain,
            "accepted_count": len(accepted),
            "attempts": attempts,
            "base_accepted_by_chain_class": base_counts,
            "combined_accepted_by_chain_class": combined_counts,
            "deficits_initial": deficits_initial,
            "deficits_remaining": deficits_remaining,
            "rejected_by_reason": dict(sorted(Counter(row["reason"] for row in rejected).items())),
            "rejected_count": len(rejected),
            "stopped_reason": stopped_reason,
            "target_min_per_chain_class": target_min,
            "topup_chain_classes": topup_classes,
            "turn_distribution": dict(
                sorted(Counter(str(_assistant_turn_count(row)) for row in accepted).items())
            ),
        },
    }
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest


def build_topup(
    *,
    base_manifest: Path = DEFAULT_BASE_MANIFEST,
    out_dir: Path = DEFAULT_OUT_DIR,
    prefix: str = DEFAULT_PREFIX,
    endpoint: str = d1.DEFAULT_ENDPOINT,
    model: str = d1.DEFAULT_MODEL,
    max_tokens: int = d1.DEFAULT_MAX_TOKENS,
    temperature: float = 0.35,
    timeout: int = 300,
    max_attempts: int = 160,
    seed: int = DEFAULT_SEED,
    registry_path: Path | None = None,
    secret_file: Path | None = None,
    sleep_seconds: float = 0.5,
    wall_seconds: float | None = None,
    target_min: int = 8,
    only_classes: list[str] | None = None,
) -> dict[str, Any]:
    api_key = d1.read_secret_key(secret_file)
    if not api_key:
        raise RuntimeError("DEEPSEEK_API_KEY not found in environment or ~/.aegispt-secrets")
    out_dir.mkdir(parents=True, exist_ok=True)
    registry = load_registry(registry_path) if registry_path else build_registry()
    base_counts = load_base_counts(base_manifest)
    deficits_initial = deficits_from_counts(
        base_counts,
        target_min=target_min,
        only_classes=only_classes,
    )
    raw_path = out_dir / f"{prefix}_raw_teacher.jsonl"
    train_path = out_dir / f"{prefix}_train.jsonl"
    rejected_path = out_dir / f"{prefix}_rejected.jsonl"
    scenario_registry_path = out_dir / f"{prefix}_scenario_registry.jsonl"
    manifest_path = out_dir / f"{prefix}_manifest.json"
    accepted: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    raw_rows: list[dict[str, Any]] = []
    attempts = 0
    start_time = time.monotonic()
    stopped_reason = "completed"
    topup_classes = list(deficits_initial or only_classes or [])
    if not deficits_initial:
        return _write_manifest(
            accepted=accepted,
            attempts=attempts,
            base_manifest=base_manifest,
            base_counts=base_counts,
            deficits_initial=deficits_initial,
            endpoint=endpoint,
            manifest_path=manifest_path,
            model=model,
            prefix=prefix,
            raw_path=raw_path,
            raw_rows=raw_rows,
            rejected=rejected,
            rejected_path=rejected_path,
            scenario_registry_path=scenario_registry_path,
            stopped_reason="already_satisfied",
            target_min=target_min,
            topup_classes=topup_classes,
            train_path=train_path,
        )
    class_order = list(deficits_initial)
    accepted_counter = Counter()
    for index in range(max_attempts):
        combined_counts = {
            name: base_counts.get(name, 0) + accepted_counter.get(name, 0)
            for name in d1.TEACHER_CHAIN_CLASS_NAMES
        }
        remaining = deficits_from_counts(
            combined_counts,
            target_min=target_min,
            only_classes=class_order,
        )
        if not remaining:
            break
        chain_class = max(remaining, key=lambda name: (remaining[name], name))
        spec = make_scenario(chain_class, index=index, seed=seed)
        attempts += 1
        try:
            candidate = d1.call_deepseek(
                endpoint=endpoint,
                model=model,
                messages=d1.teacher_messages(spec),
                api_key=api_key,
                max_tokens=max_tokens,
                temperature=temperature,
                timeout=timeout,
                json_mode=True,
            )
            metadata = candidate.get("metadata") if isinstance(candidate.get("metadata"), dict) else {}
            metadata.setdefault("case_id", spec.lab_id)
            metadata.setdefault("chain_class", spec.chain_class)
            metadata.setdefault("dataset_family", "external_v4pro_teacher_raw")
            metadata.setdefault("domain", spec.domain)
            metadata.setdefault("lab_only", True)
            metadata.setdefault("runtime_execution", False)
            metadata.setdefault("scenario_hash", spec.scenario_hash)
            metadata.setdefault("split", "train")
            metadata.setdefault("teacher_model", model)
            candidate["metadata"] = metadata
            raw_rows.append(candidate)
            if not d1._has_blocked_goal_recovery_arc(candidate):
                raise ValueError("missing_blocked_goal_recovery_arc")
            ingested = ingest_rows(
                [candidate],
                registry=registry,
                prefix=prefix,
                teacher_model=model,
                fail_on_rejected=False,
            )
            if ingested["accepted"]:
                accepted.extend(ingested["accepted"])
                accepted_counter[chain_class] += len(ingested["accepted"])
            else:
                rejected.extend(
                    {
                        **row,
                        "source_chain_class": chain_class,
                        "source_lab_id": spec.lab_id,
                    }
                    for row in ingested["rejected"]
                )
        except Exception as exc:  # noqa: BLE001
            detail = str(exc)[:240]
            reason = (
                "missing_blocked_goal_recovery_arc"
                if detail == "missing_blocked_goal_recovery_arc"
                else f"teacher_error:{type(exc).__name__}"
            )
            rejected.append(
                {
                    "candidate_ids": [spec.lab_id, spec.scenario_hash],
                    "detail": detail,
                    "index": attempts - 1,
                    "reason": reason,
                    "source_chain_class": chain_class,
                    "source_lab_id": spec.lab_id,
                }
            )
        _write_manifest(
            accepted=accepted,
            attempts=attempts,
            base_manifest=base_manifest,
            base_counts=base_counts,
            deficits_initial=deficits_initial,
            endpoint=endpoint,
            manifest_path=manifest_path,
            model=model,
            prefix=prefix,
            raw_path=raw_path,
            raw_rows=raw_rows,
            rejected=rejected,
            rejected_path=rejected_path,
            scenario_registry_path=scenario_registry_path,
            stopped_reason="running",
            target_min=target_min,
            topup_classes=topup_classes,
            train_path=train_path,
        )
        if sleep_seconds:
            time.sleep(sleep_seconds)
        if wall_seconds is not None and time.monotonic() - start_time >= wall_seconds:
            stopped_reason = "wall_seconds"
            break
    else:
        stopped_reason = "attempt_limit"
    return _write_manifest(
        accepted=accepted,
        attempts=attempts,
        base_manifest=base_manifest,
        base_counts=base_counts,
        deficits_initial=deficits_initial,
        endpoint=endpoint,
        manifest_path=manifest_path,
        model=model,
        prefix=prefix,
        raw_path=raw_path,
        raw_rows=raw_rows,
        rejected=rejected,
        rejected_path=rejected_path,
        scenario_registry_path=scenario_registry_path,
        stopped_reason=stopped_reason,
        target_min=target_min,
        topup_classes=topup_classes,
        train_path=train_path,
    )


def parse_classes(values: list[str] | None) -> list[str] | None:
    if not values:
        return None
    classes: list[str] = []
    for value in values:
        classes.extend(item.strip() for item in value.split(",") if item.strip())
    return classes or None


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-manifest", type=Path, default=DEFAULT_BASE_MANIFEST)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    parser.add_argument("--prefix", default=DEFAULT_PREFIX)
    parser.add_argument("--endpoint", default=d1.DEFAULT_ENDPOINT)
    parser.add_argument("--model", default=d1.DEFAULT_MODEL)
    parser.add_argument("--max-tokens", type=int, default=d1.DEFAULT_MAX_TOKENS)
    parser.add_argument("--temperature", type=float, default=0.35)
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--max-attempts", type=int, default=160)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--registry", type=Path)
    parser.add_argument("--secret-file", type=Path)
    parser.add_argument("--sleep-seconds", type=float, default=0.5)
    parser.add_argument("--wall-seconds", type=float)
    parser.add_argument("--target-min", type=int, default=8)
    parser.add_argument("--only-chain-class", action="append")
    args = parser.parse_args()
    manifest = build_topup(
        base_manifest=args.base_manifest,
        out_dir=args.out_dir,
        prefix=args.prefix,
        endpoint=args.endpoint,
        model=args.model,
        max_tokens=args.max_tokens,
        temperature=args.temperature,
        timeout=args.timeout,
        max_attempts=args.max_attempts,
        seed=args.seed,
        registry_path=args.registry,
        secret_file=args.secret_file,
        sleep_seconds=args.sleep_seconds,
        wall_seconds=args.wall_seconds,
        target_min=args.target_min,
        only_classes=parse_classes(args.only_chain_class),
    )
    print(json.dumps(manifest, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
