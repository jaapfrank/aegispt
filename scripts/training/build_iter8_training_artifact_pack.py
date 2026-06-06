"""Build committed iter8 multi-service training artifacts for handoff.

This pack mirrors the iter7 artifact contract, but carries the longer iter8
multi-service chain family plus a refreshed lab-truth/held-out registry. The
registry protects iter8 eval/test case ids from re-entering SFT, DPO,
contrastive, or process-reward data.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.training.make_lab_truth_heldout_registry_iter6 import (
    DEFAULT_PREFIX as REGISTRY_PREFIX,
)
from scripts.training.make_lab_truth_heldout_registry_iter6 import build_registry
from scripts.training.make_llmsvs_adversarial_eval_data import (
    DEFAULT_COUNT as LLMSVS_COUNT,
)
from scripts.training.make_llmsvs_adversarial_eval_data import (
    DEFAULT_PREFIX as LLMSVS_PREFIX,
)
from scripts.training.make_llmsvs_adversarial_eval_data import generate_rows as generate_llmsvs_rows
from scripts.training.make_llmsvs_adversarial_eval_data import validate_rows as validate_llmsvs_rows
from scripts.training.make_multiservice_chaintype_diversity_iter8 import (
    DEFAULT_COUNTS as MULTISERVICE_COUNTS,
)
from scripts.training.make_multiservice_chaintype_diversity_iter8 import (
    DEFAULT_PREFIX as MULTISERVICE_PREFIX,
)
from scripts.training.make_multiservice_chaintype_diversity_iter8 import (
    generate_rows as generate_multiservice_rows,
)
from scripts.training.make_multiservice_chaintype_diversity_iter8 import (
    validate_rows as validate_multiservice_rows,
)
from scripts.training.make_multiturn_agentic_chain_iter6 import (
    DEFAULT_COUNTS as MULTITURN_COUNTS,
)
from scripts.training.make_multiturn_chaintype_diversity_iter7 import (
    DEFAULT_COUNTS as CHAINTYPE_COUNTS,
)

DEFAULT_OUT_DIR = Path("codex/results/training/iter8-multiservice-diversity-20260607")
DEFAULT_PREFIX = "aegispt_iter8_multiservice_training_artifact_pack"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_gzip_jsonl(path: Path, rows: list[dict[str, Any]]) -> dict[str, Any]:
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


def _write_json(path: Path, payload: dict[str, Any]) -> dict[str, Any]:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return {
        "bytes": path.stat().st_size,
        "path": str(path),
        "sha256": _sha256(path),
    }


def parse_counts(values: list[str] | None, defaults: dict[str, int]) -> dict[str, int]:
    counts = dict(defaults)
    for value in values or []:
        split, raw_count = value.split("=", 1)
        if split not in counts:
            raise ValueError(f"unknown split {split!r}")
        counts[split] = int(raw_count)
    return counts


def build_pack(
    *,
    out_dir: Path = DEFAULT_OUT_DIR,
    prefix: str = DEFAULT_PREFIX,
    multiservice_counts: dict[str, int] | None = None,
    llmsvs_count: int = LLMSVS_COUNT,
    multiturn_counts: dict[str, int] | None = None,
    chaintype_counts: dict[str, int] | None = None,
) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    ms_counts = dict(MULTISERVICE_COUNTS)
    ms_counts.update(multiservice_counts or {})
    mt_counts = {
        "eval": MULTITURN_COUNTS["eval"],
        "test": MULTITURN_COUNTS["test"],
    }
    mt_counts.update(multiturn_counts or {})
    ct_counts = {
        "eval": CHAINTYPE_COUNTS["eval"],
        "test": CHAINTYPE_COUNTS["test"],
    }
    ct_counts.update(chaintype_counts or {})

    files: dict[str, Any] = {}
    multiservice_stats: dict[str, Any] = {}
    for split, count in ms_counts.items():
        rows = generate_multiservice_rows(count, split=split)
        multiservice_stats[split] = validate_multiservice_rows(rows)
        files[f"multiservice_{split}"] = _write_gzip_jsonl(
            out_dir / f"{MULTISERVICE_PREFIX}_{split}.jsonl.gz",
            rows,
        )

    llmsvs_rows = generate_llmsvs_rows(count=llmsvs_count)
    llmsvs_stats = validate_llmsvs_rows(llmsvs_rows)
    files["llmsvs_eval"] = _write_gzip_jsonl(
        out_dir / f"{LLMSVS_PREFIX}.jsonl.gz",
        llmsvs_rows,
    )

    registry = build_registry(
        llmsvs_count=llmsvs_count,
        multiturn_counts=mt_counts,
        chaintype_counts=ct_counts,
        multiservice_counts={
            "eval": ms_counts["eval"],
            "test": ms_counts["test"],
        },
    )
    files["held_out_registry"] = _write_json(out_dir / f"{REGISTRY_PREFIX}.json", registry)
    files["held_out_jsonl"] = _write_gzip_jsonl(
        out_dir / f"{REGISTRY_PREFIX}_held_out.jsonl.gz",
        registry["held_out_scenarios"],
    )
    files["lab_truth_jsonl"] = _write_gzip_jsonl(
        out_dir / f"{REGISTRY_PREFIX}_lab_truth.jsonl.gz",
        registry["lab_truth_scenarios"],
    )

    manifest = {
        "dataset": prefix,
        "files": files,
        "format": "deterministic gzip-compressed jsonl plus registry json",
        "policy": {
            "committed_artifact_pack": True,
            "data_lane_only": True,
            "held_out_deep_chain_solution_not_copied": True,
            "iter8_eval_test_registered_as_held_out": True,
            "llmsvs_eval_only": True,
            "multi_service_chain_type_diversity": True,
            "runtime_execution": False,
        },
        "stats": {
            "held_out_registry": registry["stats"],
            "llmsvs": llmsvs_stats,
            "multiservice": multiservice_stats,
        },
    }
    manifest_path = out_dir / f"{prefix}_manifest.json"
    manifest["manifest"] = _write_json(manifest_path, manifest)
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    parser.add_argument("--prefix", default=DEFAULT_PREFIX)
    parser.add_argument("--multiservice-count", action="append", help="Override iter8 split size, e.g. train=100")
    parser.add_argument("--llmsvs-count", type=int, default=LLMSVS_COUNT)
    parser.add_argument("--multiturn-count", action="append", help="Override iter6 held-out split size, e.g. eval=40")
    parser.add_argument("--chaintype-count", action="append", help="Override iter7 held-out split size, e.g. eval=40")
    args = parser.parse_args()
    manifest = build_pack(
        out_dir=args.out_dir,
        prefix=args.prefix,
        multiservice_counts=parse_counts(args.multiservice_count, MULTISERVICE_COUNTS),
        llmsvs_count=args.llmsvs_count,
        multiturn_counts=parse_counts(
            args.multiturn_count,
            {"eval": MULTITURN_COUNTS["eval"], "test": MULTITURN_COUNTS["test"]},
        ),
        chaintype_counts=parse_counts(
            args.chaintype_count,
            {"eval": CHAINTYPE_COUNTS["eval"], "test": CHAINTYPE_COUNTS["test"]},
        ),
    )
    print(json.dumps({"manifest": manifest["manifest"], "stats": manifest["stats"]}, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
