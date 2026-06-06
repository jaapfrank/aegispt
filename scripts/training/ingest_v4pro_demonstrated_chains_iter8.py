"""Ingest externally demonstrated V4-Pro chain trajectories.

Codex cannot create genuine V4-Pro-demonstrated rows without a configured
teacher endpoint. This script is the data-lane guard for the moment Claude or
another teacher lane exports real non-held-out trajectories: it validates the
multi-turn SFT shape, rejects held-out/eval leakage, normalizes metadata, and
emits a train-only JSONL family.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.training.make_lab_truth_heldout_registry_iter6 import (
    build_registry,
    load_registry,
)
from scripts.training.make_multiservice_chaintype_diversity_iter8 import (
    FORBIDDEN_HELD_OUT_MARKERS as ITER8_HELD_OUT_MARKERS,
)

DEFAULT_OUT_DIR = Path.home() / ".aegispt-tools" / "training"
DEFAULT_PREFIX = "aegispt_v4pro_demonstrated_chains_iter8"
DEFAULT_TEACHER_MODEL = "external-v4pro"

REQUIRED_ASSISTANT_KEYS = {"done", "evidence", "next_action", "reasoning", "safety", "state"}
FORBIDDEN = re.compile(
    r"\b(rm\s+-rf|mimikatz|hashcat|ransom|wipe|destroy|drop\s+table|"
    r"credential\s+dump|password\s+spray|brute[\s_-]?force)\b|BEGIN RSA PRIVATE KEY|sk-",
    re.I,
)
FORBIDDEN_HELD_OUT_MARKERS = tuple(
    sorted(
        {
            *ITER8_HELD_OUT_MARKERS,
            "ADM-7741-KQ",
            "X-Admin-Token",
            "shop.lab",
            "/notes/",
            "/admin/config",
            "flag{deep-eval-5b7c2}",
        }
    )
)


class IngestRejected(ValueError):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def _json_dump(value: Any) -> str:
    return json.dumps(value, sort_keys=True)


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError(f"{path}:{line_no} is not a JSON object")
        rows.append(value)
    return rows


def read_input_rows(paths: list[Path]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in paths:
        if path.is_dir():
            for child in sorted(path.glob("*.jsonl")):
                rows.extend(_read_jsonl(child))
            continue
        rows.extend(_read_jsonl(path))
    return rows


def held_out_ids(registry: dict[str, Any]) -> set[str]:
    ids: set[str] = set()
    for row in registry.get("held_out_scenarios", []):
        for key in ("scenario_id", "case_id", "qualified_scenario_id", "target_id"):
            value = row.get(key)
            if value:
                ids.add(str(value))
    return ids


def candidate_ids(row: dict[str, Any]) -> set[str]:
    metadata = row.get("metadata") if isinstance(row.get("metadata"), dict) else {}
    ids: set[str] = set()
    for source in (row, metadata):
        for key in (
            "case_id",
            "scenario_id",
            "target_id",
            "lab_target_id",
            "challenge_id",
            "qualified_scenario_id",
            "original_case_id",
        ):
            value = source.get(key)
            if value:
                ids.add(str(value))
    return ids


def _assistant_payloads(row: dict[str, Any]) -> list[dict[str, Any]]:
    messages = row.get("messages")
    if not isinstance(messages, list) or len(messages) < 3:
        raise IngestRejected("missing_or_short_messages")
    assistants: list[dict[str, Any]] = []
    for message in messages:
        if not isinstance(message, dict):
            raise IngestRejected("message_not_object")
        if message.get("role") != "assistant":
            continue
        try:
            payload = json.loads(str(message.get("content", "")))
        except json.JSONDecodeError as exc:
            raise IngestRejected("assistant_content_not_json") from exc
        if set(payload) != REQUIRED_ASSISTANT_KEYS:
            raise IngestRejected("assistant_schema_mismatch")
        assistants.append(payload)
    if len(assistants) < 2:
        raise IngestRejected("too_few_assistant_turns")
    return assistants


def validate_candidate(row: dict[str, Any], held_out: set[str]) -> dict[str, Any]:
    serialized = _json_dump(row)
    if FORBIDDEN.search(serialized):
        raise IngestRejected("unsafe_marker")
    for marker in FORBIDDEN_HELD_OUT_MARKERS:
        if marker in serialized:
            raise IngestRejected("held_out_marker_leak")
    matched_held_out = sorted(candidate_ids(row) & held_out)
    if matched_held_out:
        raise IngestRejected(f"held_out_scenario:{matched_held_out[0]}")
    assistants = _assistant_payloads(row)
    for idx, payload in enumerate(assistants):
        next_action = payload.get("next_action")
        if not isinstance(next_action, dict) or "args" not in next_action:
            raise IngestRejected("missing_next_action_args")
        safety = payload.get("safety")
        if not isinstance(safety, dict):
            raise IngestRejected("missing_safety_object")
        if safety.get("runtime_execution") is True:
            raise IngestRejected("runtime_execution_true")
        if idx < len(assistants) - 1 and payload.get("done") is True:
            raise IngestRejected("premature_done")
        if idx == len(assistants) - 1:
            if payload.get("done") is not True:
                raise IngestRejected("final_not_done")
            evidence = payload.get("evidence")
            if not isinstance(evidence, dict) or evidence.get("goal_satisfied") is not True:
                raise IngestRejected("final_goal_not_satisfied")
    return {
        "assistant_turns": len(assistants),
        "message_count": len(row["messages"]),
    }


def normalize_candidate(
    row: dict[str, Any],
    *,
    prefix: str,
    teacher_model: str,
    held_out: set[str],
) -> dict[str, Any]:
    validation = validate_candidate(row, held_out)
    original_metadata = row.get("metadata") if isinstance(row.get("metadata"), dict) else {}
    original_case_id = str(
        original_metadata.get("case_id")
        or original_metadata.get("scenario_id")
        or row.get("case_id")
        or row.get("scenario_id")
        or "external"
    )
    normalized_messages: list[dict[str, str]] = []
    for message in row["messages"]:
        if message.get("role") != "assistant":
            normalized_messages.append(
                {"content": str(message.get("content", "")), "role": str(message.get("role", ""))}
            )
            continue
        payload = json.loads(str(message.get("content", "")))
        safety = dict(payload["safety"])
        safety["dataset_family"] = prefix
        safety["lab_only"] = True
        safety["runtime_execution"] = False
        payload["safety"] = safety
        normalized_messages.append({"content": _json_dump(payload), "role": "assistant"})

    digest = _sha256_text(_json_dump(normalized_messages))
    metadata = dict(original_metadata)
    source_family = metadata.get("dataset_family", "external_teacher_export")
    metadata.update(
        {
            "assistant_turns": validation["assistant_turns"],
            "case_id": f"v4pro-demo-{digest[:16]}",
            "dataset_family": prefix,
            "generation_mode": "frontier_model_demonstrated_non_held_out",
            "global_held_out_registry": "excluded",
            "lab_only": True,
            "original_case_id": original_case_id,
            "runtime_execution": False,
            "source_dataset_family": source_family,
            "split": "train",
            "teacher_model": str(metadata.get("teacher_model") or teacher_model),
        }
    )
    safety_tags = list(metadata.get("safety_tags") or [])
    for tag in ("teacher_demonstrated", "non_held_out_scenario", "runtime_disabled"):
        if tag not in safety_tags:
            safety_tags.append(tag)
    metadata["safety_tags"] = safety_tags
    return {
        "messages": normalized_messages,
        "metadata": metadata,
    }


def ingest_rows(
    rows: list[dict[str, Any]],
    *,
    registry: dict[str, Any] | None = None,
    prefix: str = DEFAULT_PREFIX,
    teacher_model: str = DEFAULT_TEACHER_MODEL,
    fail_on_rejected: bool = True,
) -> dict[str, Any]:
    held_out = held_out_ids(registry or build_registry())
    accepted: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    seen_digests: set[str] = set()
    for index, row in enumerate(rows):
        try:
            normalized = normalize_candidate(
                row,
                prefix=prefix,
                teacher_model=teacher_model,
                held_out=held_out,
            )
            digest = _sha256_text(_json_dump(normalized["messages"]))
            if digest in seen_digests:
                raise IngestRejected("duplicate_messages")
            seen_digests.add(digest)
            accepted.append(normalized)
        except IngestRejected as exc:
            rejected.append(
                {
                    "candidate_ids": sorted(candidate_ids(row)),
                    "index": index,
                    "reason": exc.reason,
                }
            )
    if rejected and fail_on_rejected:
        reasons = ", ".join(row["reason"] for row in rejected[:5])
        raise ValueError(f"rejected {len(rejected)} demonstrated rows: {reasons}")
    return {
        "accepted": accepted,
        "rejected": rejected,
        "stats": {
            "accepted_count": len(accepted),
            "assistant_turns": dict(Counter(str(row["metadata"]["assistant_turns"]) for row in accepted)),
            "rejected_by_reason": dict(Counter(row["reason"] for row in rejected)),
            "rejected_count": len(rejected),
            "source_count": len(rows),
        },
    }


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(_json_dump(row) + "\n")


def build_dataset(
    *,
    input_paths: list[Path],
    out_dir: Path = DEFAULT_OUT_DIR,
    prefix: str = DEFAULT_PREFIX,
    registry_path: Path | None = None,
    teacher_model: str = DEFAULT_TEACHER_MODEL,
    allow_rejected: bool = False,
) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    registry = load_registry(registry_path) if registry_path else build_registry()
    rows = read_input_rows(input_paths)
    result = ingest_rows(
        rows,
        registry=registry,
        prefix=prefix,
        teacher_model=teacher_model,
        fail_on_rejected=not allow_rejected,
    )
    train_path = out_dir / f"{prefix}_train.jsonl"
    manifest_path = out_dir / f"{prefix}_manifest.json"
    rejected_path = out_dir / f"{prefix}_rejected.jsonl"
    write_jsonl(train_path, result["accepted"])
    write_jsonl(rejected_path, result["rejected"])
    manifest = {
        "dataset": prefix,
        "files": {
            "rejected": str(rejected_path),
            "train": str(train_path),
        },
        "format": "jsonl chat sft rows",
        "policy": {
            "data_lane_only": True,
            "held_out_guard": True,
            "runtime_execution": False,
            "train_only": True,
            "v4pro_rows_must_be_external_demonstrations": True,
        },
        "stats": result["stats"],
        "teacher_model": teacher_model,
    }
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inputs", nargs="+", type=Path, help="JSONL files or directories containing teacher rows.")
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    parser.add_argument("--prefix", default=DEFAULT_PREFIX)
    parser.add_argument("--registry", type=Path, help="Optional held-out registry JSON or JSONL.")
    parser.add_argument("--teacher-model", default=DEFAULT_TEACHER_MODEL)
    parser.add_argument(
        "--allow-rejected",
        action="store_true",
        help="Write rejected rows to the manifest instead of failing the ingest.",
    )
    args = parser.parse_args()
    manifest = build_dataset(
        input_paths=args.inputs,
        out_dir=args.out_dir,
        prefix=args.prefix,
        registry_path=args.registry,
        teacher_model=args.teacher_model,
        allow_rejected=args.allow_rejected,
    )
    print(json.dumps(manifest, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
