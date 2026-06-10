#!/usr/bin/env python3
"""Build discovery-prefixed completion arcs for the next 14B training pass.

This data-lane builder consumes the free 3.3d completion-arc corpus and
rewrites each row so it starts from a terse goal, then infers and hits the
likely goal path before continuing through the existing blocked-goal recovery
arc. It does not call a model, run a target, or create runtime capability.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.training.build_free_completion_arc_dataset_iter10 import (
    DEFAULT_HELDOUT_MANIFEST,
    has_forbidden_string,
    json_payload,
    load_heldout_hashes,
    read_jsonl,
    repo_rel,
    row_has_completion_arc,
    row_hashes,
    stable_hash,
    write_jsonl,
)

DEFAULT_PREFIX = "aegispt_discovery_prefixed_completion_arcs_iter10"
DEFAULT_SOURCE_TRAIN = (
    REPO_ROOT
    / "codex"
    / "results"
    / "training"
    / "free-completion-arcs-20260609"
    / "aegispt_free_completion_arcs_iter10_train.jsonl"
)
DEFAULT_OUT_DIR = REPO_ROOT / "codex" / "results" / "training" / "discovery-prefixed-arcs-20260610"
DISCOVERY_VARIANTS = (
    (
        "semantic_direct",
        "infer the likely goal path directly from the terse objective before recovery",
    ),
    (
        "scout_then_semantic",
        "make one safe orientation probe, then infer the likely goal path from the terse objective",
    ),
)


def split_words(value: str) -> list[str]:
    return [word for word in re.split(r"[^A-Za-z0-9]+", value.lower()) if word]


def goal_phrase_from_path(path: str, metadata: dict[str, Any]) -> str:
    words = split_words(path)
    if not words:
        words = split_words(str(metadata.get("chain_class") or "blocked goal marker"))
    if words and words[0] in {"api", "v1", "v2"}:
        words = words[1:]
    if "marker" not in words:
        words.append("marker")
    words = words[-4:]
    phrase = " ".join(words).strip()
    return phrase or "blocked goal marker"


def first_goal_action(messages: list[dict[str, Any]]) -> tuple[int, dict[str, Any], str, str, str] | None:
    for index, message in enumerate(messages):
        if not isinstance(message, dict) or message.get("role") != "assistant":
            continue
        payload = json_payload(message)
        if not payload:
            continue
        action = payload.get("next_action") if isinstance(payload.get("next_action"), dict) else {}
        args = action.get("args") if isinstance(action.get("args"), dict) else {}
        url = str(args.get("url") or "")
        if not url:
            continue
        parsed = urlparse(url)
        host = f"{parsed.scheme}://{parsed.netloc}" if parsed.scheme and parsed.netloc else ""
        method = str(args.get("method") or "GET").upper()
        return index, payload, url, parsed.path or "/", method
    return None


def terse_goal_message(*, host: str, phrase: str, variant_name: str, metadata: dict[str, Any]) -> dict[str, str]:
    payload = {
        "goal": f"Find the blocked {phrase} and finish only after final proof evidence.",
        "host": host,
        "known_path": None,
        "available_context": [
            "authorized fictional lab",
            "no route map is given",
            "infer the likely endpoint from the goal words before using recovery hints",
        ],
        "required_arc": (
            "terse goal -> infer likely goal path -> hit blocked goal -> "
            "recover hinted resource/value -> retry -> final proof"
        ),
        "source_case_id": metadata.get("case_id", ""),
        "training_focus": variant_name,
    }
    return {"role": "user", "content": json.dumps(payload, sort_keys=True)}


def discovery_system_message(original: dict[str, Any], *, phrase: str, variant_name: str) -> dict[str, str]:
    original_content = str(original.get("content", "")) if isinstance(original, dict) else ""
    suffix = (
        " Discovery-prefixed training: begin from the terse goal, infer the likely lab route "
        f"for '{phrase}', then continue through the blocked-goal recovery arc. "
        f"Discovery variant: {variant_name}."
    )
    return {"role": "system", "content": f"{original_content}{suffix}".strip()}


def adapt_goal_action(
    payload: dict[str, Any],
    *,
    phrase: str,
    path: str,
    variant_name: str,
) -> dict[str, Any]:
    cloned = json.loads(json.dumps(payload, sort_keys=True))
    cloned["reasoning"] = (
        f"The terse objective names '{phrase}'. Infer the likely lab route from those "
        f"route tokens and test that path before using recovery hints."
    )
    action = cloned.setdefault("next_action", {})
    if isinstance(action, dict):
        action["purpose"] = "infer and test the likely goal path from the terse objective"
    evidence = cloned.setdefault("evidence", {})
    if isinstance(evidence, dict):
        refs = list(evidence.get("refs") or [])
        if "obs-discovery-inference" not in refs:
            refs.append("obs-discovery-inference")
        evidence["refs"] = refs
    state = cloned.setdefault("state", {})
    if isinstance(state, dict):
        state.update(
            {
                "discovery_inferred_goal_path": True,
                "discovery_variant": variant_name,
                "inferred_goal_path": path,
                "inferred_goal_phrase": phrase,
            }
        )
    safety = cloned.setdefault("safety", {})
    if isinstance(safety, dict):
        safety["dataset_family"] = DEFAULT_PREFIX
        safety["lab_only"] = True
        safety["runtime_execution"] = False
    return cloned


def scout_pair(*, host: str, phrase: str, goal_path: str) -> list[dict[str, str]]:
    scout_path = "/" if goal_path != "/" else "/status"
    scout_url = f"{host}{scout_path}" if host else scout_path
    assistant = {
        "done": False,
        "evidence": {"goal_satisfied": False, "refs": ["obs-discovery-scout"]},
        "next_action": {
            "args": {"headers": {}, "method": "GET", "url": scout_url},
            "purpose": "safe orientation probe before inferring the goal path",
            "tool": "lab_http_request",
        },
        "reasoning": (
            f"Start with a bounded orientation probe. If no route map appears, use the terse "
            f"goal words '{phrase}' to infer the likely goal path."
        ),
        "safety": {"dataset_family": DEFAULT_PREFIX, "lab_only": True, "runtime_execution": False},
        "state": {"discovery_probe": True, "goal_path_not_known_yet": True},
    }
    observation = (
        "TOOL OBSERVATION: orientation probe returned sparse lab metadata and no route map; "
        f"continue by inferring the likely goal endpoint from phrase '{phrase}'."
    )
    return [
        {"role": "assistant", "content": json.dumps(assistant, sort_keys=True)},
        {"role": "user", "content": observation},
    ]


def make_discovery_prefixed_row(
    row: dict[str, Any],
    *,
    variant_name: str,
    focus: str,
    index: int,
) -> dict[str, Any] | None:
    messages = row.get("messages")
    if not isinstance(messages, list) or len(messages) < 3:
        return None
    action_info = first_goal_action(messages)
    if not action_info:
        return None
    first_index, first_payload, goal_url, goal_path, goal_method = action_info
    metadata = row.get("metadata") if isinstance(row.get("metadata"), dict) else {}
    phrase = goal_phrase_from_path(goal_path, metadata)
    parsed = urlparse(goal_url)
    host = f"{parsed.scheme}://{parsed.netloc}" if parsed.scheme and parsed.netloc else ""
    adapted_first = adapt_goal_action(
        first_payload,
        phrase=phrase,
        path=goal_path,
        variant_name=variant_name,
    )
    new_messages: list[dict[str, str]] = [
        discovery_system_message(messages[0], phrase=phrase, variant_name=variant_name),
        terse_goal_message(host=host, phrase=phrase, variant_name=variant_name, metadata=metadata),
    ]
    if variant_name == "scout_then_semantic":
        new_messages.extend(scout_pair(host=host, phrase=phrase, goal_path=goal_path))
    new_messages.append({"role": "assistant", "content": json.dumps(adapted_first, sort_keys=True)})
    new_messages.extend(json.loads(json.dumps(messages[first_index + 1 :], sort_keys=True)))

    source_hash = str(metadata.get("scenario_hash") or stable_hash(json.dumps(row, sort_keys=True)))
    source_env_hash = str(
        metadata.get("source_env_scenario_hash")
        or metadata.get("source_scenario_hash")
        or source_hash
    )
    base_case = str(metadata.get("case_id") or f"discovery-source-{index:04d}")
    new_metadata = json.loads(json.dumps(metadata, sort_keys=True))
    new_metadata.update(
        {
            "case_id": f"{base_case}::discovery::{variant_name}",
            "dataset_family": DEFAULT_PREFIX,
            "discovery_focus": focus,
            "discovery_prefixed_completion_arc": True,
            "discovery_variant": variant_name,
            "first_goal_method": goal_method,
            "first_goal_path": goal_path,
            "free_oracle_completion_arc": True,
            "inferred_goal_phrase": phrase,
            "lab_only": True,
            "runtime_execution": False,
            "scenario_hash": stable_hash(f"{DEFAULT_PREFIX}|{source_hash}|{variant_name}|{goal_path}|{index}"),
            "source_completion_case_id": base_case,
            "source_completion_scenario_hash": source_hash,
            "source_env_scenario_hash": source_env_hash,
            "source_scenario_hash": source_hash,
            "split": "train",
        }
    )
    safety_tags = set(new_metadata.get("safety_tags") or [])
    safety_tags.update(
        {
            "completion_arc",
            "discovery_prefixed",
            "free_oracle",
            "non_held_out_scenario",
        }
    )
    new_metadata["safety_tags"] = sorted(safety_tags)
    return {"messages": new_messages, "metadata": new_metadata}


def row_has_discovery_prefix(row: dict[str, Any]) -> bool:
    if not row_has_completion_arc(row):
        return False
    metadata = row.get("metadata") if isinstance(row.get("metadata"), dict) else {}
    first_goal_path = str(metadata.get("first_goal_path") or "")
    messages = row.get("messages") if isinstance(row.get("messages"), list) else []
    if len(messages) < 4 or not first_goal_path:
        return False
    first_user = next((message for message in messages if message.get("role") == "user"), {})
    if first_goal_path != "/" and first_goal_path in str(first_user.get("content", "")):
        return False
    assistant_payloads = [
        payload
        for message in messages
        if message.get("role") == "assistant"
        for payload in [json_payload(message)]
        if payload is not None
    ]
    return any(
        isinstance(payload.get("state"), dict)
        and payload["state"].get("discovery_inferred_goal_path") is True
        for payload in assistant_payloads[:3]
    )


def build_dataset(
    *,
    source_train: Path,
    heldout_manifest: Path,
    variants: tuple[tuple[str, str], ...] = DISCOVERY_VARIANTS,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    heldout_hashes = load_heldout_hashes(heldout_manifest)
    source_rows = read_jsonl(source_train)
    selected: list[dict[str, Any]] = []
    skipped = Counter()
    seen_messages: set[str] = set()
    for source_index, row in enumerate(source_rows):
        if has_forbidden_string(row):
            skipped["forbidden_heldout_string"] += 1
            continue
        if row_hashes(row) & heldout_hashes:
            skipped["source_heldout_hash_collision"] += 1
            continue
        if not row_has_completion_arc(row):
            skipped["source_missing_completion_arc"] += 1
            continue
        for variant_name, focus in variants:
            new_row = make_discovery_prefixed_row(
                row,
                variant_name=variant_name,
                focus=focus,
                index=source_index,
            )
            if not new_row:
                skipped["missing_goal_action"] += 1
                continue
            if has_forbidden_string(new_row):
                skipped["augmented_forbidden_heldout_string"] += 1
                continue
            if row_hashes(new_row) & heldout_hashes:
                skipped["augmented_heldout_hash_collision"] += 1
                continue
            if not row_has_discovery_prefix(new_row):
                skipped["missing_discovery_prefix"] += 1
                continue
            message_hash = stable_hash(json.dumps(new_row["messages"], sort_keys=True))
            if message_hash in seen_messages:
                skipped["duplicate_messages"] += 1
                continue
            selected.append(new_row)
            seen_messages.add(message_hash)

    by_class = Counter(str(row["metadata"].get("chain_class") or "unknown") for row in selected)
    by_variant = Counter(str(row["metadata"].get("discovery_variant") or "unknown") for row in selected)
    by_source_kind = Counter(str(row["metadata"].get("source_kind") or "unknown") for row in selected)
    audit = {
        "forbidden_string_hits": skipped.get("forbidden_heldout_string", 0)
        + skipped.get("augmented_forbidden_heldout_string", 0),
        "heldout_collision_count": skipped.get("source_heldout_hash_collision", 0)
        + skipped.get("augmented_heldout_hash_collision", 0),
        "heldout_hash_count": len(heldout_hashes),
        "skipped": dict(sorted(skipped.items())),
    }
    manifest = {
        "dataset": DEFAULT_PREFIX,
        "policy": {
            "data_lane_only": True,
            "discovery_prefixed_required": True,
            "free_oracle_or_scripted_sources_only": True,
            "held_out_eval_not_used_for_training": True,
            "lab_only": True,
            "no_cloud_teacher_batch": True,
            "no_runtime_execution": True,
            "terse_goal_hides_exact_path": True,
        },
        "stats": {
            "accepted_count": len(selected),
            "by_chain_class": dict(sorted(by_class.items())),
            "by_discovery_variant": dict(sorted(by_variant.items())),
            "by_source_kind": dict(sorted(by_source_kind.items())),
            "source_row_count": len(source_rows),
            "variant_count": len(variants),
        },
        "leakage_audit": audit,
        "sources": {
            "heldout_manifest": repo_rel(heldout_manifest),
            "source_train": repo_rel(source_train),
        },
    }
    return selected, manifest


def write_outputs(rows: list[dict[str, Any]], manifest: dict[str, Any], out_dir: Path, prefix: str) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    train_path = out_dir / f"{prefix}_train.jsonl"
    manifest_path = out_dir / f"{prefix}_manifest.json"
    registry_path = out_dir / f"{prefix}_scenario_registry.jsonl"
    summary_path = out_dir / f"{prefix}_summary.md"
    write_jsonl(train_path, rows)
    registry_rows = [
        {
            "case_id": row["metadata"].get("case_id", ""),
            "chain_class": row["metadata"].get("chain_class", ""),
            "dataset_family": row["metadata"].get("dataset_family", ""),
            "discovery_variant": row["metadata"].get("discovery_variant", ""),
            "first_goal_path": row["metadata"].get("first_goal_path", ""),
            "scenario_hash": row["metadata"].get("scenario_hash", ""),
            "source_completion_scenario_hash": row["metadata"].get("source_completion_scenario_hash", ""),
            "source_env_scenario_hash": row["metadata"].get("source_env_scenario_hash", ""),
            "split": "train",
        }
        for row in rows
    ]
    write_jsonl(registry_path, registry_rows)
    manifest = {
        **manifest,
        "files": {
            "manifest": repo_rel(manifest_path),
            "scenario_registry": repo_rel(registry_path),
            "summary": repo_rel(summary_path),
            "train": repo_rel(train_path),
        },
    }
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    lines = [
        "# Discovery-prefixed completion arcs iter10",
        "",
        f"- accepted rows: {manifest['stats']['accepted_count']}",
        f"- source rows: {manifest['stats']['source_row_count']}",
        f"- variant count: {manifest['stats']['variant_count']}",
        f"- held-out collision count: {manifest['leakage_audit']['heldout_collision_count']}",
        f"- forbidden string hits: {manifest['leakage_audit']['forbidden_string_hits']}",
        "- policy: data-lane only; no model calls; no runtime execution; no held-out eval rows used for training",
        "- arc shape: terse goal -> infer/hit goal path -> blocked recovery -> retry -> final proof",
        "",
        "## Discovery Variants",
        "",
    ]
    for variant, count in manifest["stats"]["by_discovery_variant"].items():
        lines.append(f"- `{variant}`: {count}")
    lines.extend(["", "## Chain Classes", ""])
    for chain_class, count in manifest["stats"]["by_chain_class"].items():
        lines.append(f"- `{chain_class}`: {count}")
    summary_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return manifest


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-train", type=Path, default=DEFAULT_SOURCE_TRAIN)
    parser.add_argument("--heldout-manifest", type=Path, default=DEFAULT_HELDOUT_MANIFEST)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    parser.add_argument("--prefix", default=DEFAULT_PREFIX)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    rows, manifest = build_dataset(
        source_train=args.source_train,
        heldout_manifest=args.heldout_manifest,
    )
    written = write_outputs(rows, manifest, args.out_dir, args.prefix)
    print(json.dumps(written, indent=2, sort_keys=True))
    if written["leakage_audit"]["heldout_collision_count"] != 0:
        return 2
    if written["leakage_audit"]["forbidden_string_hits"] != 0:
        return 3
    if written["stats"]["accepted_count"] < 1000:
        return 4
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
