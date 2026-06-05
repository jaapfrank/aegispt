"""Flag exact and near-duplicate rows across local AegisPT training datasets.

The script reads generated JSONL datasets from ``~/.aegispt-tools/training`` by
default, normalizes volatile markers/targets/ids, and writes reviewable flags.
It never rewrites source datasets; de-duplication remains an explicit operator
or training-pipeline decision.
"""

from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import re
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

DEFAULT_INPUT_DIR = Path.home() / ".aegispt-tools" / "training"
DEFAULT_OUT_DIR = Path.home() / ".aegispt-tools" / "training"
DEFAULT_PREFIX = "aegispt_near_duplicate_flags_iter5"
DEFAULT_THRESHOLD = 0.92
DEFAULT_MAX_FLAGS = 5000
TRAINING_SPLITS = {"train", "eval", "test"}

VOLATILE_PATTERNS = (
    (re.compile(r"FAKE_AEGISPT_CANARY_[A-Z0-9]+", re.I), "AEGISPT_MARKER"),
    (re.compile(r"AEGISPT_[A-Z0-9_]+", re.I), "AEGISPT_MARKER"),
    (re.compile(r"https?://[a-z0-9.-]+", re.I), "URL_PLACEHOLDER"),
    (re.compile(r"\b(?:192\.0\.2|198\.51\.100|203\.0\.113)\.\d+\b"), "IP_PLACEHOLDER"),
    (re.compile(r"\b\d{2,}\b"), "NUMBER_PLACEHOLDER"),
)

TOKEN_RE = re.compile(r"[a-z0-9_./:-]+")


@dataclass(frozen=True)
class Record:
    case_id: str
    canonical_text: str
    dataset_family: str
    exact_hash: str
    line: int
    path: str
    split: str
    token_set: frozenset[str]


def split_from_path(path: Path) -> str | None:
    suffix = path.stem.rsplit("_", 1)[-1]
    if suffix in TRAINING_SPLITS:
        return suffix
    return None


def iter_dataset_paths(input_dir: Path) -> list[Path]:
    paths: list[Path] = []
    for path in sorted(input_dir.glob("aegispt_*.jsonl")):
        if path.name.startswith(DEFAULT_PREFIX):
            continue
        if split_from_path(path) in TRAINING_SPLITS:
            paths.append(path)
    return paths


def text_from_message(message: dict[str, Any]) -> str:
    return f"{message.get('role', '')}: {message.get('content', '')}"


def text_from_row(row: dict[str, Any]) -> str:
    pieces: list[str] = []
    if "messages" in row:
        pieces.extend(text_from_message(message) for message in row["messages"])
    if "prompt" in row:
        prompt = row["prompt"]
        if isinstance(prompt, dict):
            pieces.append(text_from_message(prompt))
        else:
            pieces.append(str(prompt))
    for key in ("chosen", "rejected"):
        value = row.get(key)
        if isinstance(value, dict):
            pieces.append(text_from_message(value))
        elif value:
            pieces.append(str(value))
    if not pieces:
        pieces.append(json.dumps(row, sort_keys=True))
    return "\n".join(pieces)


def canonicalize(text: str) -> str:
    lowered = text.lower()
    for pattern, replacement in VOLATILE_PATTERNS:
        lowered = pattern.sub(replacement.lower(), lowered)
    lowered = re.sub(r"\s+", " ", lowered)
    return lowered.strip()


def tokens(text: str) -> frozenset[str]:
    return frozenset(TOKEN_RE.findall(text))


def load_records(paths: Iterable[Path]) -> list[Record]:
    records: list[Record] = []
    for path in paths:
        split = split_from_path(path)
        if split is None:
            continue
        with path.open(encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                row = json.loads(line)
                metadata = row.get("metadata", {})
                dataset_family = metadata.get("dataset_family") or path.stem.removesuffix(f"_{split}")
                case_id = metadata.get("case_id") or f"{path.name}:{line_number}"
                canonical_text = canonicalize(text_from_row(row))
                exact_hash = hashlib.sha256(canonical_text.encode()).hexdigest()
                records.append(
                    Record(
                        case_id=case_id,
                        canonical_text=canonical_text,
                        dataset_family=dataset_family,
                        exact_hash=exact_hash,
                        line=line_number,
                        path=str(path),
                        split=split,
                        token_set=tokens(canonical_text),
                    )
                )
    return records


def shingle_keys(text: str, *, width: int = 5, key_count: int = 8) -> list[str]:
    words = text.split()
    if len(words) < width:
        return [hashlib.sha1(text.encode()).hexdigest()[:12]]
    shingles = (" ".join(words[index : index + width]) for index in range(len(words) - width + 1))
    hashes = sorted(hashlib.sha1(shingle.encode()).hexdigest()[:12] for shingle in shingles)
    return hashes[:key_count]


def similarity(left: Record, right: Record) -> float:
    if not left.token_set or not right.token_set:
        return difflib.SequenceMatcher(None, left.canonical_text, right.canonical_text).ratio()
    intersection = len(left.token_set & right.token_set)
    union = len(left.token_set | right.token_set)
    jaccard = intersection / union if union else 0.0
    sequence = difflib.SequenceMatcher(None, left.canonical_text, right.canonical_text).ratio()
    return max(jaccard, sequence)


def record_ref(record: Record) -> dict[str, Any]:
    return {
        "case_id": record.case_id,
        "dataset_family": record.dataset_family,
        "exact_hash": record.exact_hash,
        "line": record.line,
        "path": record.path,
        "split": record.split,
    }


def recommendation(left: Record, right: Record, reason: str) -> str:
    splits = {left.split, right.split}
    if "train" in splits and ("eval" in splits or "test" in splits):
        return "drop_or_rewrite_train_row_before_eval_to_prevent_leakage"
    if left.dataset_family != right.dataset_family:
        return "manual_review_keep_only_if_curriculum_overlap_is_intentional"
    if reason == "exact_canonical_duplicate":
        return "drop_duplicate_or_template_diversify"
    return "manual_review_near_duplicate"


def make_flag(flag_index: int, left: Record, right: Record, reason: str, score: float) -> dict[str, Any]:
    return {
        "duplicate": record_ref(right),
        "family_pair": sorted({left.dataset_family, right.dataset_family}),
        "flag_id": f"near-duplicate-{flag_index:05d}",
        "primary": record_ref(left),
        "reason": reason,
        "recommendation": recommendation(left, right, reason),
        "similarity": round(score, 4),
        "split_pair": sorted({left.split, right.split}),
    }


def exact_duplicate_flags(records: list[Record], *, max_flags: int) -> list[dict[str, Any]]:
    buckets: dict[str, list[Record]] = defaultdict(list)
    for record in records:
        buckets[record.exact_hash].append(record)
    flags: list[dict[str, Any]] = []
    for group in buckets.values():
        if len(group) < 2:
            continue
        primary = group[0]
        for duplicate in group[1:]:
            flags.append(make_flag(len(flags) + 1, primary, duplicate, "exact_canonical_duplicate", 1.0))
            if len(flags) >= max_flags:
                return flags
    return flags


def near_duplicate_flags(
    records: list[Record],
    *,
    existing_flags: list[dict[str, Any]],
    max_flags: int,
    threshold: float,
) -> list[dict[str, Any]]:
    buckets: dict[str, list[int]] = defaultdict(list)
    for index, record in enumerate(records):
        for key in shingle_keys(record.canonical_text):
            buckets[key].append(index)

    seen_pairs = {
        tuple(sorted((flag["primary"]["case_id"], flag["duplicate"]["case_id"])))
        for flag in existing_flags
    }
    flags: list[dict[str, Any]] = []
    for candidate_indexes in buckets.values():
        if len(candidate_indexes) < 2:
            continue
        capped = candidate_indexes[:80]
        for left_offset, left_index in enumerate(capped):
            left = records[left_index]
            for right_index in capped[left_offset + 1 :]:
                right = records[right_index]
                pair_key = tuple(sorted((left.case_id, right.case_id)))
                if pair_key in seen_pairs or left.exact_hash == right.exact_hash:
                    continue
                score = similarity(left, right)
                if score >= threshold:
                    flags.append(
                        make_flag(
                            len(existing_flags) + len(flags) + 1,
                            left,
                            right,
                            "near_duplicate_similarity",
                            score,
                        )
                    )
                    seen_pairs.add(pair_key)
                    if len(existing_flags) + len(flags) >= max_flags:
                        return flags
    return flags


def find_duplicate_flags(
    records: list[Record],
    *,
    max_flags: int = DEFAULT_MAX_FLAGS,
    threshold: float = DEFAULT_THRESHOLD,
) -> list[dict[str, Any]]:
    exact_flags = exact_duplicate_flags(records, max_flags=max_flags)
    if len(exact_flags) >= max_flags:
        return exact_flags
    near_flags = near_duplicate_flags(
        records,
        existing_flags=exact_flags,
        max_flags=max_flags,
        threshold=threshold,
    )
    return exact_flags + near_flags


def summarize_flags(flags: list[dict[str, Any]]) -> dict[str, Any]:
    reasons = defaultdict(int)
    recommendations = defaultdict(int)
    split_pairs = defaultdict(int)
    family_pairs = defaultdict(int)
    for flag in flags:
        reasons[flag["reason"]] += 1
        recommendations[flag["recommendation"]] += 1
        split_pairs[" + ".join(flag["split_pair"])] += 1
        family_pairs[" + ".join(flag["family_pair"])] += 1
    return {
        "family_pairs": dict(sorted(family_pairs.items())),
        "reasons": dict(sorted(reasons.items())),
        "recommendations": dict(sorted(recommendations.items())),
        "split_pairs": dict(sorted(split_pairs.items())),
        "total_flags": len(flags),
    }


def extra_family_recommendations() -> list[dict[str, str]]:
    return [
        {
            "family": "aegispt_live_lab_target_specs_iter5",
            "reason": "text-only payload classes need matching disposable runner-lane targets",
            "status": "created_by_data_lane",
        },
        {
            "family": "aegispt_llmsvs_adversarial_eval_iter5",
            "reason": "agentic pentest models need prompt-injection and tool-misuse eval gates",
            "status": "created_by_data_lane",
        },
        {
            "family": "aegispt_near_duplicate_flags_iter5",
            "reason": "large synthetic curricula need train/eval leakage and template-repeat review",
            "status": "created_by_data_lane",
        },
    ]


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")


def build_dataset(
    *,
    input_dir: Path,
    out_dir: Path,
    prefix: str = DEFAULT_PREFIX,
    max_flags: int = DEFAULT_MAX_FLAGS,
    threshold: float = DEFAULT_THRESHOLD,
) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    paths = iter_dataset_paths(input_dir)
    records = load_records(paths)
    flags = find_duplicate_flags(records, max_flags=max_flags, threshold=threshold)
    path = out_dir / f"{prefix}.jsonl"
    write_jsonl(path, flags)
    manifest = {
        "dataset": prefix,
        "format": "jsonl duplicate-review flags",
        "input_dir": str(input_dir),
        "input_files": [str(path) for path in paths],
        "path": str(path),
        "policy": {
            "non_destructive": True,
            "rewrites_source_data": False,
            "review_required": True,
        },
        "record_count": len(records),
        "similarity_threshold": threshold,
        "stats": summarize_flags(flags),
        "suggested_extra_families": extra_family_recommendations(),
    }
    manifest_path = out_dir / f"{prefix}_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-dir", type=Path, default=DEFAULT_INPUT_DIR)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    parser.add_argument("--prefix", default=DEFAULT_PREFIX)
    parser.add_argument("--max-flags", type=int, default=DEFAULT_MAX_FLAGS)
    parser.add_argument("--threshold", type=float, default=DEFAULT_THRESHOLD)
    args = parser.parse_args()
    manifest = build_dataset(
        input_dir=args.input_dir,
        out_dir=args.out_dir,
        prefix=args.prefix,
        max_flags=args.max_flags,
        threshold=args.threshold,
    )
    print(json.dumps(manifest["stats"], indent=2, sort_keys=True))
    print(f"manifest: {args.out_dir / (args.prefix + '_manifest.json')}")


if __name__ == "__main__":
    main()
