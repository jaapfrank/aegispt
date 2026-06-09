#!/usr/bin/env python3
"""Build the free completion-arc dataset for the next 14B training pass.

This is a data-lane-only builder. It consumes existing scripted/oracle
training artifacts, filters for completed blocked-goal recovery arcs, checks
scenario-hash leakage against the D2 held-out eval set, and emits one
messages-format JSONL. It does not call a model, run a target, or generate any
runtime capability.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUT_DIR = REPO_ROOT / "codex" / "results" / "training" / "free-completion-arcs-20260609"
DEFAULT_PREFIX = "aegispt_free_completion_arcs_iter10"
DEFAULT_HELDOUT_MANIFEST = (
    REPO_ROOT
    / "codex"
    / "results"
    / "training"
    / "multichain-heldout-eval-envs-20260607"
    / "aegispt_multichain_heldout_eval_envs_iter10_manifest.json"
)
DEFAULT_DEMO_PATHS = (
    REPO_ROOT
    / "codex"
    / "results"
    / "training"
    / "headless-oob-chain-envs-20260607"
    / "aegispt_headless_oob_teacher_demos_iter10_train.jsonl",
    REPO_ROOT
    / "codex"
    / "results"
    / "training"
    / "blind-oob-command-envs-20260607"
    / "aegispt_blind_oob_command_teacher_demos_iter10_train.jsonl",
    REPO_ROOT
    / "codex"
    / "results"
    / "training"
    / "other-stack-recovery-envs-20260607"
    / "aegispt_other_stack_recovery_teacher_demos_iter10_train.jsonl",
    REPO_ROOT
    / "codex"
    / "results"
    / "training"
    / "web-source-gap-recovery-envs-20260607"
    / "aegispt_web_source_gap_recovery_teacher_demos_iter10_train.jsonl",
)
DEFAULT_ROLLOUT_DIRS = (
    REPO_ROOT / "codex" / "results" / "training" / "multichain-rl-envs-20260607",
    REPO_ROOT / "codex" / "results" / "training" / "headless-oob-chain-envs-20260607",
    REPO_ROOT / "codex" / "results" / "training" / "blind-oob-command-envs-20260607",
    REPO_ROOT / "codex" / "results" / "training" / "other-stack-recovery-envs-20260607",
    REPO_ROOT / "codex" / "results" / "training" / "web-source-gap-recovery-envs-20260607",
)
DEFAULT_VARIANTS = (
    ("recovery_arc", "prioritize blocked-goal backtracking before retrying the goal"),
    ("evidence_reuse", "name the observed token or proof before reusing it"),
    ("final_proof", "finish only after final marker/proof evidence is observed"),
    ("state_carry", "carry session, proof, and blocker state across every step"),
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


def repo_rel(path: Path) -> str:
    try:
        return path.resolve().relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def stable_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not path.exists():
        return rows
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def load_heldout_hashes(manifest_path: Path) -> set[str]:
    data = load_json(manifest_path)
    manifest = data.get("manifest") if isinstance(data.get("manifest"), dict) else data
    hashes = set()
    for scenario in manifest.get("scenarios", []):
        scenario_hash = str(scenario.get("scenario_hash") or "")
        if scenario_hash:
            hashes.add(scenario_hash)
    return hashes


def scenario_index_from_manifest(path: Path) -> dict[str, dict[str, Any]]:
    if not path.exists():
        return {}
    data = load_json(path)
    manifest = data.get("manifest") if isinstance(data.get("manifest"), dict) else data
    return {
        str(item.get("scenario_id")): item
        for item in manifest.get("scenarios", [])
        if item.get("scenario_id")
    }


def json_payload(message: dict[str, Any]) -> dict[str, Any] | None:
    try:
        payload = json.loads(str(message.get("content", "")))
    except json.JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) else None


def row_has_completion_arc(row: dict[str, Any]) -> bool:
    messages = row.get("messages")
    if not isinstance(messages, list):
        return False
    assistant_payloads = [
        payload
        for message in messages
        if isinstance(message, dict) and message.get("role") == "assistant"
        for payload in [json_payload(message)]
        if payload is not None
    ]
    if len(assistant_payloads) < 5:
        return False
    final_payload = assistant_payloads[-1]
    final_evidence = final_payload.get("evidence")
    final_serialized = json.dumps(final_payload, sort_keys=True).lower()
    serialized = json.dumps(row, sort_keys=True).lower()
    blocked = any(token in serialized for token in ("blocked", "403", "forbidden"))
    recovered = any(
        token in serialized
        for token in (
            "recovered_after_block",
            "callback proof",
            "evidence token",
            "proof token",
            "recovery proof",
            "retry",
            "reusing",
            "reused",
        )
    )
    final_complete = (
        final_payload.get("done") is True
        and isinstance(final_evidence, dict)
        and final_evidence.get("goal_satisfied") is True
    )
    final_proof = any(token in final_serialized for token in ("marker", "proof", "flag"))
    return blocked and recovered and final_complete and final_proof


def row_hashes(row: dict[str, Any]) -> set[str]:
    metadata = row.get("metadata") if isinstance(row.get("metadata"), dict) else {}
    return {
        str(value)
        for key in ("scenario_hash", "source_env_scenario_hash")
        for value in [metadata.get(key)]
        if value
    }


def has_forbidden_string(row: dict[str, Any]) -> bool:
    serialized = json.dumps(row, sort_keys=True)
    return any(marker in serialized for marker in FORBIDDEN_HELD_OUT_STRINGS)


def append_focus_to_message(content: str, focus: str) -> str:
    try:
        payload = json.loads(content)
    except json.JSONDecodeError:
        return f"{content}\nTraining focus: {focus}"
    if isinstance(payload, dict):
        payload["training_focus"] = focus
        return json.dumps(payload, sort_keys=True)
    return f"{content}\nTraining focus: {focus}"


def augment_row(row: dict[str, Any], *, variant_name: str, focus: str, index: int) -> dict[str, Any]:
    cloned = json.loads(json.dumps(row, sort_keys=True))
    messages = cloned["messages"]
    original_metadata = row.get("metadata") if isinstance(row.get("metadata"), dict) else {}
    base_hash = str(original_metadata.get("scenario_hash") or stable_hash(json.dumps(row, sort_keys=True)))
    base_case = str(original_metadata.get("case_id") or original_metadata.get("scenario_id") or f"free-arc-{index:04d}")
    case_anchor = {
        "case_id": base_case,
        "chain_class": original_metadata.get("chain_class", "unknown"),
        "source_kind": original_metadata.get("source_kind", "unknown"),
        "source_scenario_hash": original_metadata.get("source_env_scenario_hash", base_hash),
        "variant": variant_name,
    }
    if messages and messages[0].get("role") == "system":
        messages[0]["content"] = (
            f"{messages[0]['content']} Training focus: {focus}. "
            f"Lab case anchor: {json.dumps(case_anchor, sort_keys=True)}."
        )
    for message in messages:
        if message.get("role") == "user":
            message["content"] = append_focus_to_message(
                str(message.get("content", "")),
                f"{focus}; lab_case_anchor={json.dumps(case_anchor, sort_keys=True)}",
            )
            break
    metadata = cloned.setdefault("metadata", {})
    metadata.update(
        {
            "augmentation_variant": variant_name,
            "case_id": f"{base_case}::{variant_name}",
            "dataset_family": DEFAULT_PREFIX,
            "free_oracle_completion_arc": True,
            "lab_only": True,
            "runtime_execution": False,
            "scenario_hash": stable_hash(f"{base_hash}|{variant_name}|{index}"),
            "source_scenario_hash": base_hash,
            "split": "train",
        }
    )
    safety_tags = set(metadata.get("safety_tags") or [])
    safety_tags.update({"free_oracle", "completion_arc", "non_held_out_scenario"})
    metadata["safety_tags"] = sorted(safety_tags)
    return cloned


def load_demo_rows(paths: list[Path]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in paths:
        for row in read_jsonl(path):
            metadata = row.setdefault("metadata", {})
            metadata.setdefault("source_path", repo_rel(path))
            metadata.setdefault("source_kind", "scripted_teacher_demo")
            rows.append(row)
    return rows


def rollout_row(
    *,
    roll_path: Path,
    result_path: Path,
    result: dict[str, Any],
    scenario: dict[str, Any],
) -> dict[str, Any] | None:
    trace = read_jsonl(roll_path)
    if not trace:
        return None
    messages: list[dict[str, str]] = [
        {
            "role": "system",
            "content": (
                "Authorized fictional lab training row. Follow the observed "
                "blocked-goal recovery arc, use only lab-scoped proof values, "
                "and stop after final marker evidence."
            ),
        },
        {
            "role": "user",
            "content": json.dumps(
                {
                    "goal": scenario.get("goal")
                    or "Recover from the blocked goal and retrieve the lab proof marker.",
                    "host": scenario.get("host", ""),
                    "required_arc": "blocked goal -> recover hinted proof/token -> retry goal",
                    "scenario_id": result.get("scenario_id", ""),
                },
                sort_keys=True,
            ),
        },
    ]
    for item in trace:
        action_text = str(item.get("action") or "{}")
        try:
            action_payload = json.loads(action_text)
        except json.JSONDecodeError:
            action_payload = {"done": False, "next_action": {"args": {}, "tool": "unknown"}}
        if "next_action" not in action_payload:
            request = action_payload.get("request", {})
            action_payload = {
                "done": False,
                "evidence": {"goal_satisfied": False, "refs": item.get("evidence", [])},
                "next_action": {"args": request, "tool": "lab_http_request"},
                "reasoning": action_payload.get(
                    "reasoning",
                    "Continue the scripted recovery arc using the next lab request.",
                ),
                "safety": {"lab_only": True, "runtime_execution": False},
                "state": {"scenario_id": result.get("scenario_id", ""), "step": item.get("state", "")},
            }
        messages.append({"role": "assistant", "content": json.dumps(action_payload, sort_keys=True)})
        messages.append(
            {
                "role": "user",
                "content": f"TOOL OBSERVATION: {item.get('tool_result', '{}')}",
            }
        )
    messages.append(
        {
            "role": "assistant",
            "content": json.dumps(
                {
                    "done": True,
                    "evidence": {
                        "goal_satisfied": True,
                        "refs": ["obs-final"],
                        "reward": result.get("reward", 0),
                        "scenario_id": result.get("scenario_id", ""),
                    },
                    "next_action": {"args": {}, "purpose": "goal complete", "tool": "none"},
                    "reasoning": (
                        "The completion arc reached final evidence after backtracking from "
                        "the blocked goal and reusing the observed bounded value."
                    ),
                    "safety": {"lab_only": True, "runtime_execution": False},
                    "state": {
                        "done": True,
                        "flag": bool(result.get("flag")),
                        "recovered_after_block": bool(result.get("recovered_after_block")),
                        "used_revealed_value": bool(result.get("used_revealed_value")),
                    },
                },
                sort_keys=True,
            ),
        }
    )
    scenario_id = str(result.get("scenario_id") or roll_path.stem)
    source_hash = str(result.get("scenario_hash") or scenario.get("scenario_hash") or "")
    return {
        "messages": messages,
        "metadata": {
            "case_id": f"free-rollout-{scenario_id}",
            "chain_class": scenario.get("chain_class", "unknown"),
            "dataset_family": "aegispt_free_oracle_rollout_completion_arcs_iter10",
            "domain": scenario.get("domain", ""),
            "lab_only": True,
            "runtime_execution": False,
            "scenario_hash": stable_hash(f"free-rollout|{scenario_id}|{source_hash}"),
            "source_env_scenario_hash": source_hash,
            "source_kind": "scripted_oracle_rollout",
            "source_res_path": repo_rel(result_path),
            "source_roll_path": repo_rel(roll_path),
            "split": "train",
        },
    }


def load_rollout_rows(rollout_dirs: list[Path]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for rollout_dir in rollout_dirs:
        manifest_paths = sorted(rollout_dir.glob("*manifest.json"))
        scenario_index: dict[str, dict[str, Any]] = {}
        for manifest_path in manifest_paths:
            scenario_index.update(scenario_index_from_manifest(manifest_path))
        for result_path in sorted(rollout_dir.glob("res_*.json")):
            result = load_json(result_path)
            if not (
                result.get("flag")
                and result.get("blocked_goal")
                and result.get("recovered_after_block")
                and result.get("used_revealed_value")
            ):
                continue
            idx = result_path.stem.split("_", 1)[-1]
            roll_path = rollout_dir / f"roll_{idx}.jsonl"
            scenario = scenario_index.get(str(result.get("scenario_id") or ""), {})
            row = rollout_row(
                roll_path=roll_path,
                result_path=result_path,
                result=result,
                scenario=scenario,
            )
            if row:
                rows.append(row)
    return rows


def build_dataset(
    *,
    demo_paths: list[Path],
    rollout_dirs: list[Path],
    heldout_manifest: Path,
    variants: tuple[tuple[str, str], ...] = DEFAULT_VARIANTS,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    heldout_hashes = load_heldout_hashes(heldout_manifest)
    source_rows = load_demo_rows(demo_paths) + load_rollout_rows(rollout_dirs)
    selected: list[dict[str, Any]] = []
    skipped = Counter()
    seen_messages: set[str] = set()
    for source_index, row in enumerate(source_rows):
        if has_forbidden_string(row):
            skipped["forbidden_heldout_string"] += 1
            continue
        if row_hashes(row) & heldout_hashes:
            skipped["heldout_hash_collision"] += 1
            continue
        if not row_has_completion_arc(row):
            skipped["missing_completion_arc"] += 1
            continue
        for variant_name, focus in variants:
            augmented = augment_row(row, variant_name=variant_name, focus=focus, index=source_index)
            if row_hashes(augmented) & heldout_hashes:
                skipped["augmented_heldout_hash_collision"] += 1
                continue
            message_hash = stable_hash(json.dumps(augmented["messages"], sort_keys=True))
            if message_hash in seen_messages:
                skipped["duplicate_messages"] += 1
                continue
            selected.append(augmented)
            seen_messages.add(message_hash)
    by_family = Counter(str(row["metadata"].get("source_kind") or "unknown") for row in selected)
    by_class = Counter(str(row["metadata"].get("chain_class") or "unknown") for row in selected)
    audit = {
        "forbidden_string_hits": skipped.get("forbidden_heldout_string", 0),
        "heldout_collision_count": skipped.get("heldout_hash_collision", 0)
        + skipped.get("augmented_heldout_hash_collision", 0),
        "heldout_hash_count": len(heldout_hashes),
        "skipped": dict(sorted(skipped.items())),
    }
    manifest = {
        "dataset": DEFAULT_PREFIX,
        "policy": {
            "data_lane_only": True,
            "free_oracle_or_scripted_sources_only": True,
            "held_out_eval_not_used_for_training": True,
            "lab_only": True,
            "no_cloud_teacher_batch": True,
            "no_runtime_execution": True,
        },
        "stats": {
            "accepted_count": len(selected),
            "by_chain_class": dict(sorted(by_class.items())),
            "by_source_kind": dict(sorted(by_family.items())),
            "source_row_count": len(source_rows),
            "variant_count": len(variants),
        },
        "leakage_audit": audit,
        "sources": {
            "demo_paths": [repo_rel(path) for path in demo_paths],
            "heldout_manifest": repo_rel(heldout_manifest),
            "rollout_dirs": [repo_rel(path) for path in rollout_dirs],
        },
    }
    return selected, manifest


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")


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
            "scenario_hash": row["metadata"].get("scenario_hash", ""),
            "source_scenario_hash": row["metadata"].get("source_scenario_hash", ""),
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
        "# Free completion arcs iter10",
        "",
        f"- accepted rows: {manifest['stats']['accepted_count']}",
        f"- source rows: {manifest['stats']['source_row_count']}",
        f"- variant count: {manifest['stats']['variant_count']}",
        f"- held-out collision count: {manifest['leakage_audit']['heldout_collision_count']}",
        f"- forbidden string hits: {manifest['leakage_audit']['forbidden_string_hits']}",
        "- policy: data-lane only; no model calls; no runtime execution; no held-out eval rows used for training",
        "",
        "## Chain Classes",
        "",
    ]
    for chain_class, count in manifest["stats"]["by_chain_class"].items():
        lines.append(f"- `{chain_class}`: {count}")
    summary_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return manifest


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--demo-path", action="append", type=Path)
    parser.add_argument("--rollout-dir", action="append", type=Path)
    parser.add_argument("--heldout-manifest", type=Path, default=DEFAULT_HELDOUT_MANIFEST)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    parser.add_argument("--prefix", default=DEFAULT_PREFIX)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    rows, manifest = build_dataset(
        demo_paths=list(args.demo_path or DEFAULT_DEMO_PATHS),
        rollout_dirs=list(args.rollout_dir or DEFAULT_ROLLOUT_DIRS),
        heldout_manifest=args.heldout_manifest,
    )
    written = write_outputs(rows, manifest, args.out_dir, args.prefix)
    print(json.dumps(written, indent=2, sort_keys=True))
    if written["leakage_audit"]["heldout_collision_count"] != 0:
        return 2
    if written["stats"]["accepted_count"] < 500:
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
