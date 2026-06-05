"""Build an iter-5 curated SFT mix using hard exclusions and heldout guards.

This mix is for chat/SFT-style JSONL rows only. DPO prompt/chosen/rejected data
remains a separate training lane and is intentionally not mixed here.

The script is non-destructive: it reads source datasets, applies an exclusion
manifest, deduplicates selected rows, and writes a new mix plus a source map.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import re
from collections import Counter
from pathlib import Path
from typing import Any

DEFAULT_TRAINING_DIR = Path.home() / ".aegispt-tools" / "training"
DEFAULT_PREFIX = "aegispt_curated_sft_mix_iter5"
DEFAULT_TOTAL = 16000
DEFAULT_SEED = 20260605
DEFAULT_MAX_PER_TEMPLATE = 240

DEFAULT_FAMILIES = {
    "full_coverage": {
        "file": "aegispt_full_coverage_dora_loraplus_unsloth_train.jsonl",
        "weight": 0.32,
    },
    "open_corpus": {
        "file": "aegispt_open_corpus_iter3_train.jsonl",
        "weight": 0.22,
    },
    "payload_capability": {
        "file": "aegispt_payload_capability_iter4_train.jsonl",
        "weight": 0.20,
    },
    "payload_negative": {
        "file": "aegispt_payload_negative_contrastive_iter4_train.jsonl",
        "weight": 0.14,
    },
    "payload_domain_extension": {
        "file": "aegispt_payload_domain_extension_iter4_train.jsonl",
        "weight": 0.12,
    },
}

VOLATILE_PATTERNS = (
    (re.compile(r"FAKE_AEGISPT_CANARY_[A-Z0-9]+", re.I), "AEGISPT_MARKER"),
    (re.compile(r"AEGISPT_[A-Z0-9_]+", re.I), "AEGISPT_MARKER"),
    (re.compile(r"https?://[a-z0-9.-]+", re.I), "URL_PLACEHOLDER"),
    (re.compile(r"\b(?:192\.0\.2|198\.51\.100|203\.0\.113)\.\d+\b"), "IP_PLACEHOLDER"),
    (re.compile(r"\b\d{2,}\b"), "NUMBER_PLACEHOLDER"),
)


def load_jsonl_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    return [line for line in path.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip()]


def row_text(row: dict[str, Any]) -> str:
    pieces: list[str] = []
    for message in row.get("messages", []):
        if isinstance(message, dict):
            pieces.append(f"{message.get('role', '')}:{message.get('content', '')}")
    for key in ("prompt", "chosen", "rejected"):
        value = row.get(key)
        if isinstance(value, dict):
            pieces.append(f"{value.get('role', key)}:{value.get('content', '')}")
        elif value:
            pieces.append(str(value))
    return "\n".join(pieces) if pieces else json.dumps(row, sort_keys=True)


def canonicalize(text: str) -> str:
    lowered = text.lower()
    for pattern, replacement in VOLATILE_PATTERNS:
        lowered = pattern.sub(replacement.lower(), lowered)
    return re.sub(r"\s+", " ", lowered).strip()


def content_hash(line: str) -> str:
    try:
        text = row_text(json.loads(line))
    except json.JSONDecodeError:
        text = line
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


def template_hash(line: str) -> str:
    try:
        text = canonicalize(row_text(json.loads(line)))
    except json.JSONDecodeError:
        text = canonicalize(line)
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


def case_id_from_line(line: str, fallback: str) -> str:
    try:
        row = json.loads(line)
    except json.JSONDecodeError:
        return fallback
    metadata = row.get("metadata", {})
    return str(metadata.get("case_id") or fallback)


def load_exclusions(path: Path | None) -> set[tuple[str, int, str]]:
    if path is None or not path.exists():
        return set()
    exclusions: set[tuple[str, int, str]] = set()
    for line in load_jsonl_lines(path):
        row = json.loads(line)
        exclusions.add((str(row["path"]), int(row["line"]), str(row["case_id"])))
    return exclusions


def heldout_hashes(training_dir: Path) -> set[str]:
    hashes: set[str] = set()
    for pattern in ("aegispt_*_eval.jsonl", "aegispt_*_test.jsonl"):
        for path in training_dir.glob(pattern):
            for line in load_jsonl_lines(path):
                hashes.add(content_hash(line))
    return hashes


def source_records(training_dir: Path, exclusions: set[tuple[str, int, str]]) -> dict[str, list[dict[str, Any]]]:
    records: dict[str, list[dict[str, Any]]] = {}
    for family, config in DEFAULT_FAMILIES.items():
        path = training_dir / config["file"]
        family_records: list[dict[str, Any]] = []
        for line_number, line in enumerate(load_jsonl_lines(path), start=1):
            case_id = case_id_from_line(line, f"{path.name}:{line_number}")
            if (str(path), line_number, case_id) in exclusions:
                continue
            family_records.append(
                {
                    "case_id": case_id,
                    "content_hash": content_hash(line),
                    "family": family,
                    "line": line,
                    "line_number": line_number,
                    "path": str(path),
                    "template_hash": template_hash(line),
                }
            )
        records[family] = family_records
    return records


def select_family_rows(
    *,
    family: str,
    records: list[dict[str, Any]],
    rng: random.Random,
    target: int,
    heldout: set[str],
    seen_content: set[str],
    template_counts: Counter,
    max_per_template: int,
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    rng.shuffle(records)
    selected: list[dict[str, Any]] = []
    skipped = Counter()
    for record in records:
        if len(selected) >= target:
            break
        if record["content_hash"] in heldout:
            skipped["heldout_hash"] += 1
            continue
        if record["content_hash"] in seen_content:
            skipped["mix_duplicate"] += 1
            continue
        template_key = (family, record["template_hash"])
        if template_counts[template_key] >= max_per_template:
            skipped["template_cap"] += 1
            continue
        selected.append(record)
        seen_content.add(record["content_hash"])
        template_counts[template_key] += 1
    return selected, dict(skipped)


def backfill_rows(
    *,
    records_by_family: dict[str, list[dict[str, Any]]],
    rng: random.Random,
    target_total: int,
    heldout: set[str],
    seen_content: set[str],
    template_counts: Counter,
    max_per_template: int,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    pool = [record for records in records_by_family.values() for record in records]
    rng.shuffle(pool)
    selected: list[dict[str, Any]] = []
    skipped = Counter()
    per_family = Counter()
    for record in pool:
        if len(selected) >= target_total:
            break
        if record["content_hash"] in heldout:
            skipped["heldout_hash"] += 1
            continue
        if record["content_hash"] in seen_content:
            skipped["already_selected"] += 1
            continue
        template_key = (record["family"], record["template_hash"])
        if template_counts[template_key] >= max_per_template:
            skipped["template_cap"] += 1
            continue
        selected.append(record)
        seen_content.add(record["content_hash"])
        template_counts[template_key] += 1
        per_family[record["family"]] += 1
    return selected, {
        "per_family": dict(sorted(per_family.items())),
        "skipped": dict(sorted(skipped.items())),
    }


def write_mix(path: Path, selected: list[dict[str, Any]]) -> None:
    path.write_text("\n".join(record["line"] for record in selected) + "\n", encoding="utf-8")


def write_source_map(path: Path, selected: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for index, record in enumerate(selected, start=1):
            handle.write(
                json.dumps(
                    {
                        "case_id": record["case_id"],
                        "content_hash": record["content_hash"],
                        "family": record["family"],
                        "line": record["line_number"],
                        "mix_index": index,
                        "path": record["path"],
                        "template_hash": record["template_hash"],
                    },
                    sort_keys=True,
                )
                + "\n"
            )


def build_mix(
    *,
    training_dir: Path = DEFAULT_TRAINING_DIR,
    out_dir: Path = DEFAULT_TRAINING_DIR,
    exclusions_path: Path | None = DEFAULT_TRAINING_DIR / "aegispt_training_exclusions_iter5.jsonl",
    prefix: str = DEFAULT_PREFIX,
    total: int = DEFAULT_TOTAL,
    seed: int = DEFAULT_SEED,
    max_per_template: int = DEFAULT_MAX_PER_TEMPLATE,
) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    rng = random.Random(seed)
    exclusions = load_exclusions(exclusions_path)
    heldout = heldout_hashes(training_dir)
    records_by_family = source_records(training_dir, exclusions)
    selected: list[dict[str, Any]] = []
    seen_content: set[str] = set()
    template_counts: Counter = Counter()
    family_stats: dict[str, Any] = {}

    for family, config in DEFAULT_FAMILIES.items():
        target = round(total * float(config["weight"]))
        records = records_by_family.get(family, [])
        family_selected, skipped = select_family_rows(
            family=family,
            records=records,
            rng=rng,
            target=target,
            heldout=heldout,
            seen_content=seen_content,
            template_counts=template_counts,
            max_per_template=max_per_template,
        )
        selected.extend(family_selected)
        family_stats[family] = {
            "available_after_exclusions": len(records),
            "selected": len(family_selected),
            "skipped": skipped,
            "target": target,
            "weight": config["weight"],
        }

    backfill_stats: dict[str, Any] = {"per_family": {}, "skipped": {}}
    if len(selected) < total:
        backfilled, backfill_stats = backfill_rows(
            records_by_family=records_by_family,
            rng=rng,
            target_total=total - len(selected),
            heldout=heldout,
            seen_content=seen_content,
            template_counts=template_counts,
            max_per_template=max_per_template,
        )
        selected.extend(backfilled)
        for family, count in backfill_stats["per_family"].items():
            family_stats[family]["backfill_selected"] = count

    rng.shuffle(selected)
    mix_path = out_dir / f"{prefix}.jsonl"
    source_map_path = out_dir / f"{prefix}_source_map.jsonl"
    write_mix(mix_path, selected)
    write_source_map(source_map_path, selected)
    manifest = {
        "dataset": prefix,
        "format": "jsonl chat SFT mix plus source-map jsonl",
        "paths": {
            "mix": str(mix_path),
            "source_map": str(source_map_path),
        },
        "policy": {
            "dpo_data_excluded": True,
            "hard_exclusions_applied": True,
            "heldout_hash_guard": True,
            "non_destructive": True,
            "rewrites_source_data": False,
        },
        "seed": seed,
        "settings": {
            "max_per_template": max_per_template,
            "requested_total": total,
        },
        "stats": {
            "backfill": backfill_stats,
            "exclusion_rows_loaded": len(exclusions),
            "heldout_hashes": len(heldout),
            "per_family": family_stats,
            "selected_total": len(selected),
        },
    }
    manifest_path = out_dir / f"{prefix}_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--training-dir", type=Path, default=DEFAULT_TRAINING_DIR)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_TRAINING_DIR)
    parser.add_argument("--exclusions", type=Path, default=DEFAULT_TRAINING_DIR / "aegispt_training_exclusions_iter5.jsonl")
    parser.add_argument("--prefix", default=DEFAULT_PREFIX)
    parser.add_argument("--total", type=int, default=DEFAULT_TOTAL)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--max-per-template", type=int, default=DEFAULT_MAX_PER_TEMPLATE)
    args = parser.parse_args()
    manifest = build_mix(
        training_dir=args.training_dir,
        out_dir=args.out_dir,
        exclusions_path=args.exclusions,
        prefix=args.prefix,
        total=args.total,
        seed=args.seed,
        max_per_template=args.max_per_template,
    )
    print(json.dumps(manifest["stats"], indent=2, sort_keys=True))
    print(f"manifest: {args.out_dir / (args.prefix + '_manifest.json')}")


if __name__ == "__main__":
    main()
