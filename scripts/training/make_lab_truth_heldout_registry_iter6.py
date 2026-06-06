"""Build the canonical lab-truth and held-out scenario registry for jury data.

This is a data-lane artifact only. It does not start labs, bind runtime targets,
or change runner behavior. The registry gives the Trace -> Jury -> Factory loop
two missing inputs:

* lab_truth for no-finding arbitration:
  known_clean / known_vulnerable / live_no_oracle
* exact held-out scenario IDs that Claude's training factory must never mint
  into SFT, DPO, contrastive, or process-reward data.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.training.make_live_lab_target_specs_iter5 import (
    DEFAULT_PREFIX as LIVE_LAB_PREFIX,
)
from scripts.training.make_live_lab_target_specs_iter5 import (
    DEFAULT_VARIANTS as DEFAULT_LIVE_LAB_VARIANTS,
)
from scripts.training.make_live_lab_target_specs_iter5 import generate_specs
from scripts.training.make_llmsvs_adversarial_eval_data import (
    DEFAULT_COUNT as DEFAULT_LLMSVS_COUNT,
)
from scripts.training.make_llmsvs_adversarial_eval_data import (
    DEFAULT_PREFIX as LLMSVS_PREFIX,
)
from scripts.training.make_llmsvs_adversarial_eval_data import generate_rows as generate_llmsvs_rows
from scripts.training.make_multiturn_agentic_chain_iter6 import (
    DEFAULT_COUNTS as DEFAULT_MULTITURN_COUNTS,
)
from scripts.training.make_multiturn_agentic_chain_iter6 import (
    DEFAULT_PREFIX as MULTITURN_PREFIX,
)
from scripts.training.make_multiturn_agentic_chain_iter6 import (
    generate_rows as generate_multiturn_rows,
)
from scripts.training.make_multiturn_chaintype_diversity_iter7 import (
    DEFAULT_COUNTS as DEFAULT_CHAINTYPE_COUNTS,
)
from scripts.training.make_multiturn_chaintype_diversity_iter7 import (
    DEFAULT_PREFIX as CHAINTYPE_PREFIX,
)
from scripts.training.make_multiturn_chaintype_diversity_iter7 import (
    generate_rows as generate_chaintype_rows,
)

DEFAULT_OUT_DIR = Path.home() / ".aegispt-tools" / "training"
DEFAULT_PREFIX = "aegispt_lab_truth_heldout_registry_iter6"
DEFAULT_LAB_SUITE_MANIFEST = REPO_ROOT / "labs" / "aegispt_lab_suite" / "suite_manifest.json"
VALID_LAB_TRUTH = {"known_clean", "known_vulnerable", "live_no_oracle"}


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _counter(rows: list[dict[str, Any]], key: str) -> dict[str, int]:
    return dict(sorted(Counter(str(row.get(key, "")) for row in rows).items()))


def _live_lab_truth_entries(*, variants: int) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for spec in generate_specs(variants=variants):
        rows.append(
            {
                "dataset_class": spec["dataset_class"],
                "dataset_family": LIVE_LAB_PREFIX,
                "domain": spec["domain"],
                "lab_truth": "known_vulnerable",
                "reason": "generated disposable lab target contains seeded proof evidence",
                "scenario_id": spec["lab_target_id"],
                "source": "scripts/training/make_live_lab_target_specs_iter5.py",
                "surface": spec["surface"],
                "target_id": spec["lab_target_id"],
            }
        )
    return rows


def _suite_lab_truth_entries(manifest_path: Path) -> list[dict[str, Any]]:
    manifest = _read_json(manifest_path)
    suite_id = manifest["suite_id"]
    rows: list[dict[str, Any]] = []
    for challenge in manifest.get("challenges", []):
        if challenge.get("proof_type") != "flag_capture":
            continue
        challenge_id = challenge["id"]
        rows.append(
            {
                "dataset_family": suite_id,
                "entrypoints": challenge.get("entrypoints", []),
                "family": challenge.get("family", ""),
                "lab_truth": "known_vulnerable",
                "proof_type": "flag_capture",
                "qualified_scenario_id": f"{suite_id}:{challenge_id}",
                "reason": "standalone benchmark challenge has a hidden flag oracle",
                "scenario_id": challenge_id,
                "source": str(manifest_path.relative_to(REPO_ROOT)),
                "target_id": challenge_id,
            }
        )
    return rows


def lab_truth_entries(*, variants: int, lab_suite_manifest: Path) -> list[dict[str, Any]]:
    rows = _live_lab_truth_entries(variants=variants)
    rows.extend(_suite_lab_truth_entries(lab_suite_manifest))
    return rows


def _deep_chain_held_out() -> dict[str, Any]:
    return {
        "dataset_family": "deep_chain_eval",
        "holdout_reason": "capability_gate",
        "lab_truth": "known_vulnerable",
        "scenario_id": "deep_chain_eval",
        "source": "scripts/training/deep_chain_eval.py",
        "split": "eval",
    }


def _llmsvs_held_out(*, count: int) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for item in generate_llmsvs_rows(count=count):
        metadata = item["metadata"]
        rows.append(
            {
                "attack_category": metadata["attack_category"],
                "case_id": metadata["case_id"],
                "dataset_family": LLMSVS_PREFIX,
                "holdout_reason": "llmsvs_adversarial_eval",
                "scenario_id": metadata["case_id"],
                "source": "scripts/training/make_llmsvs_adversarial_eval_data.py",
                "split": metadata["split"],
            }
        )
    return rows


def _multiturn_held_out(*, counts: dict[str, int]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for split in ("eval", "test"):
        for item in generate_multiturn_rows(counts[split], split=split):
            metadata = item["metadata"]
            rows.append(
                {
                    "case_id": metadata["case_id"],
                    "chain_class": metadata["chain_class"],
                    "dataset_family": MULTITURN_PREFIX,
                    "holdout_reason": "iter6_multiturn_gate_split",
                    "scenario_id": metadata["case_id"],
                    "source": "scripts/training/make_multiturn_agentic_chain_iter6.py",
                    "split": split,
                }
            )
    return rows


def _chaintype_held_out(*, counts: dict[str, int]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for split in ("eval", "test"):
        for item in generate_chaintype_rows(counts[split], split=split):
            metadata = item["metadata"]
            rows.append(
                {
                    "case_id": metadata["case_id"],
                    "chain_class": metadata["chain_class"],
                    "dataset_family": CHAINTYPE_PREFIX,
                    "holdout_reason": "iter7_chaintype_diversity_gate_split",
                    "scenario_id": metadata["case_id"],
                    "source": "scripts/training/make_multiturn_chaintype_diversity_iter7.py",
                    "split": split,
                }
            )
    return rows


def _lab_suite_held_out(lab_truth_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for item in lab_truth_rows:
        if item.get("dataset_family") == LIVE_LAB_PREFIX:
            continue
        rows.append(
            {
                "dataset_family": item["dataset_family"],
                "holdout_reason": "standalone_lab_benchmark",
                "lab_truth": item["lab_truth"],
                "qualified_scenario_id": item.get("qualified_scenario_id"),
                "scenario_id": item["scenario_id"],
                "source": item["source"],
                "split": "benchmark",
                "target_id": item["target_id"],
            }
        )
    return rows


def held_out_entries(
    *,
    lab_truth_rows: list[dict[str, Any]],
    llmsvs_count: int,
    multiturn_counts: dict[str, int],
    chaintype_counts: dict[str, int],
) -> list[dict[str, Any]]:
    rows = [_deep_chain_held_out()]
    rows.extend(_llmsvs_held_out(count=llmsvs_count))
    rows.extend(_multiturn_held_out(counts=multiturn_counts))
    rows.extend(_chaintype_held_out(counts=chaintype_counts))
    rows.extend(_lab_suite_held_out(lab_truth_rows))
    return rows


def parse_multiturn_counts(values: list[str] | None) -> dict[str, int]:
    counts = {
        "eval": DEFAULT_MULTITURN_COUNTS["eval"],
        "test": DEFAULT_MULTITURN_COUNTS["test"],
    }
    for value in values or []:
        split, raw_count = value.split("=", 1)
        if split not in counts:
            raise ValueError(f"unknown held-out multiturn split {split!r}")
        counts[split] = int(raw_count)
    return counts


def parse_chaintype_counts(values: list[str] | None) -> dict[str, int]:
    counts = {
        "eval": DEFAULT_CHAINTYPE_COUNTS["eval"],
        "test": DEFAULT_CHAINTYPE_COUNTS["test"],
    }
    for value in values or []:
        split, raw_count = value.split("=", 1)
        if split not in counts:
            raise ValueError(f"unknown held-out chaintype split {split!r}")
        counts[split] = int(raw_count)
    return counts


def validate_registry(registry: dict[str, Any]) -> dict[str, Any]:
    lab_rows = list(registry["lab_truth_scenarios"])
    held_rows = list(registry["held_out_scenarios"])
    for item in lab_rows:
        if item.get("lab_truth") not in VALID_LAB_TRUTH:
            raise ValueError(f"invalid lab_truth for {item.get('scenario_id')}")
    for group_name, rows in (("lab_truth", lab_rows), ("held_out", held_rows)):
        scenario_ids = [str(row["scenario_id"]) for row in rows]
        duplicate_ids = sorted(
            scenario_id for scenario_id, count in Counter(scenario_ids).items() if count > 1
        )
        if duplicate_ids:
            raise ValueError(f"duplicate {group_name} scenario ids: {duplicate_ids[:5]}")
    lab_truth_by_value = _counter(lab_rows, "lab_truth")
    held_out_by_family = _counter(held_rows, "dataset_family")
    required_families = {
        "deep_chain_eval",
        LLMSVS_PREFIX,
        MULTITURN_PREFIX,
        CHAINTYPE_PREFIX,
        "aegispt-lab-suite-v1",
    }
    missing_families = sorted(required_families - set(held_out_by_family))
    if missing_families:
        raise ValueError(f"missing held-out families: {missing_families}")
    return {
        "held_out_by_family": held_out_by_family,
        "held_out_by_split": _counter(held_rows, "split"),
        "held_out_count": len(held_rows),
        "lab_truth_by_family": _counter(lab_rows, "dataset_family"),
        "lab_truth_by_value": lab_truth_by_value,
        "lab_truth_count": len(lab_rows),
    }


def build_registry(
    *,
    live_lab_variants: int = DEFAULT_LIVE_LAB_VARIANTS,
    lab_suite_manifest: Path = DEFAULT_LAB_SUITE_MANIFEST,
    llmsvs_count: int = DEFAULT_LLMSVS_COUNT,
    multiturn_counts: dict[str, int] | None = None,
    chaintype_counts: dict[str, int] | None = None,
) -> dict[str, Any]:
    counts = dict(DEFAULT_MULTITURN_COUNTS)
    counts = {"eval": counts["eval"], "test": counts["test"]}
    counts.update(multiturn_counts or {})
    chaintype = {
        "eval": DEFAULT_CHAINTYPE_COUNTS["eval"],
        "test": DEFAULT_CHAINTYPE_COUNTS["test"],
    }
    chaintype.update(chaintype_counts or {})
    lab_rows = lab_truth_entries(
        variants=live_lab_variants,
        lab_suite_manifest=lab_suite_manifest,
    )
    held_rows = held_out_entries(
        lab_truth_rows=lab_rows,
        llmsvs_count=llmsvs_count,
        multiturn_counts=counts,
        chaintype_counts=chaintype,
    )
    registry = {
        "dataset": DEFAULT_PREFIX,
        "held_out_scenarios": held_rows,
        "lab_truth_scenarios": lab_rows,
        "policy": {
            "data_lane_only": True,
            "default_live_lab_truth": "live_no_oracle",
            "held_out_never_reenters_training": True,
            "runtime_binding": False,
            "runtime_execution": False,
        },
        "schema_version": 1,
        "source_counts": {
            "live_lab_variants": live_lab_variants,
            "llmsvs_count": llmsvs_count,
            "chaintype_counts": chaintype,
            "multiturn_counts": counts,
        },
    }
    registry["stats"] = validate_registry(registry)
    return registry


def lab_truth_for_scenario(
    registry: dict[str, Any],
    scenario_id: str,
    *,
    default: str = "live_no_oracle",
) -> str:
    if not scenario_id:
        return default
    for row in registry.get("lab_truth_scenarios", []):
        if scenario_id in {
            row.get("scenario_id"),
            row.get("target_id"),
            row.get("qualified_scenario_id"),
        }:
            return str(row["lab_truth"])
    return default


def load_registry(path: Path) -> dict[str, Any]:
    """Load a full registry JSON or a lab-truth JSONL extract.

    The JSONL extract shape is useful for lightweight exporter use: it carries
    only the lab-truth rows, while the full registry also carries held-out rows.
    """
    if path.suffix == ".jsonl":
        rows = [
            json.loads(line)
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        return {
            "dataset": path.stem,
            "held_out_scenarios": [],
            "lab_truth_scenarios": [row for row in rows if isinstance(row, dict)],
            "schema_version": 1,
        }
    value = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(value, list):
        return {
            "dataset": path.stem,
            "held_out_scenarios": [],
            "lab_truth_scenarios": [row for row in value if isinstance(row, dict)],
            "schema_version": 1,
        }
    if not isinstance(value, dict):
        raise ValueError(f"unsupported registry shape: {path}")
    return value


def is_held_out_scenario(registry: dict[str, Any], scenario_id: str) -> bool:
    return any(
        scenario_id
        in {row.get("scenario_id"), row.get("case_id"), row.get("qualified_scenario_id")}
        for row in registry.get("held_out_scenarios", [])
    )


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")


def write_registry(out_dir: Path, prefix: str, registry: dict[str, Any]) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    registry = dict(registry)
    registry["dataset"] = prefix
    registry_path = out_dir / f"{prefix}.json"
    lab_truth_path = out_dir / f"{prefix}_lab_truth.jsonl"
    held_out_path = out_dir / f"{prefix}_held_out.jsonl"
    manifest_path = out_dir / f"{prefix}_manifest.json"
    registry_path.write_text(
        json.dumps(registry, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    write_jsonl(lab_truth_path, registry["lab_truth_scenarios"])
    write_jsonl(held_out_path, registry["held_out_scenarios"])
    manifest = {
        "dataset": prefix,
        "format": "json registry plus jsonl lab_truth/held_out extracts",
        "held_out_path": str(held_out_path),
        "lab_truth_path": str(lab_truth_path),
        "path": str(registry_path),
        "policy": registry["policy"],
        "stats": registry["stats"],
    }
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return manifest


def build_dataset(
    out_dir: Path,
    prefix: str,
    *,
    live_lab_variants: int = DEFAULT_LIVE_LAB_VARIANTS,
    lab_suite_manifest: Path = DEFAULT_LAB_SUITE_MANIFEST,
    llmsvs_count: int = DEFAULT_LLMSVS_COUNT,
    multiturn_counts: dict[str, int] | None = None,
    chaintype_counts: dict[str, int] | None = None,
) -> dict[str, Any]:
    registry = build_registry(
        live_lab_variants=live_lab_variants,
        lab_suite_manifest=lab_suite_manifest,
        llmsvs_count=llmsvs_count,
        multiturn_counts=multiturn_counts,
        chaintype_counts=chaintype_counts,
    )
    return write_registry(out_dir, prefix, registry)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    parser.add_argument("--prefix", default=DEFAULT_PREFIX)
    parser.add_argument("--live-lab-variants", type=int, default=DEFAULT_LIVE_LAB_VARIANTS)
    parser.add_argument("--lab-suite-manifest", type=Path, default=DEFAULT_LAB_SUITE_MANIFEST)
    parser.add_argument("--llmsvs-count", type=int, default=DEFAULT_LLMSVS_COUNT)
    parser.add_argument(
        "--multiturn-count",
        action="append",
        help="Override a split size, e.g. eval=40. Defaults preserve iter6 counts.",
    )
    parser.add_argument(
        "--chaintype-count",
        action="append",
        help="Override an iter7 chain-type held-out split size, e.g. eval=40.",
    )
    args = parser.parse_args()
    manifest = build_dataset(
        args.out_dir,
        args.prefix,
        live_lab_variants=args.live_lab_variants,
        lab_suite_manifest=args.lab_suite_manifest,
        llmsvs_count=args.llmsvs_count,
        multiturn_counts=parse_multiturn_counts(args.multiturn_count),
        chaintype_counts=parse_chaintype_counts(args.chaintype_count),
    )
    print(json.dumps(manifest["stats"], indent=2, sort_keys=True))
    print(f"manifest: {args.out_dir / (args.prefix + '_manifest.json')}")


if __name__ == "__main__":
    main()
