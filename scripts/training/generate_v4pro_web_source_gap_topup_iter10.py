"""Generate V4-Pro demonstrated rows for E2 web source-gap recovery classes.

This is the model-demonstrated companion to
``web_source_gap_recovery_envs_iter10.py``. It targets the four source-proven
web buckets that E1 exposed after the main D1 teacher corpus:

* sqli_filter_bypass
* file_upload_webroot
* path_traversal_file_read
* static_file_or_server_misconfig

The generated rows are lab-only and payload-free. They teach the specific
recovery behavior Claude observed missing in cold starts: attempt the goal,
hit a block, backtrack to a hinted evidence resource, reuse the bounded value,
then retry successfully.
"""

from __future__ import annotations

import argparse
import json
import random
import sys
import time
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.training import generate_v4pro_demonstrated_chains_iter9 as d1
from scripts.training.generate_v4pro_other_stack_topup_iter10 import (
    _assistant_turn_count,
    _has_observed_recovery_arc,
    _teacher_action_guard,
)
from scripts.training.ingest_v4pro_demonstrated_chains_iter8 import ingest_rows, write_jsonl
from scripts.training.make_lab_truth_heldout_registry_iter6 import build_registry, load_registry
from scripts.training.web_source_gap_recovery_envs_iter10 import WebGapSpec, scenario_specs

DEFAULT_OUT_DIR = REPO_ROOT / "codex" / "results" / "training" / "v4pro-web-source-gap-topup-20260607"
DEFAULT_PREFIX = "aegispt_v4pro_web_source_gap_topup_iter10"
DEFAULT_SEED = 2026060717
DEFAULT_TARGET_MIN_PER_CLASS = 4
WEB_SOURCE_GAP_CHAIN_CLASSES = tuple(spec.chain_class for spec in scenario_specs())


@dataclass(frozen=True)
class WebSourceGapTeacherScenario:
    blocked_goal_path: str
    chain_class: str
    domain: str
    evidence_path: str
    goal: str
    host: str
    lab_id: str
    marker: str
    proof_path: str
    proof_value: str
    recovery_header: str
    recovery_path: str
    recovery_token: str
    source_variant: str

    @property
    def scenario_hash(self) -> str:
        return d1.scenario_hash(self.lab_id)


def _spec_by_class() -> dict[str, WebGapSpec]:
    return {spec.chain_class: spec for spec in scenario_specs()}


def parse_classes(values: list[str] | None) -> list[str] | None:
    if not values:
        return None
    parsed: list[str] = []
    for value in values:
        parsed.extend(item.strip() for item in value.split(",") if item.strip())
    unknown = sorted(set(parsed) - set(WEB_SOURCE_GAP_CHAIN_CLASSES))
    if unknown:
        raise ValueError(f"unknown web source-gap chain classes: {unknown}")
    return parsed or None


def make_scenario(spec: WebGapSpec, *, index: int, seed: int) -> WebSourceGapTeacherScenario:
    rng = random.Random(f"{seed}:{spec.chain_class}:{index}")
    suffix = f"e2-web-{index:04d}-{rng.randint(1000, 9999)}"
    class_slug = spec.chain_class.replace("_", "-")
    return WebSourceGapTeacherScenario(
        blocked_goal_path=spec.blocked_goal_path,
        chain_class=spec.chain_class,
        domain="web_source_gap",
        evidence_path=spec.evidence_path,
        goal=spec.goal,
        host=f"https://{class_slug}-{suffix}.fictional-lab.example",
        lab_id=f"v4pro-web-source-gap-{spec.chain_class}-{suffix}",
        marker=f"{spec.marker}_V4_{index:04d}_{rng.randint(1000, 9999)}",
        proof_path=spec.proof_path,
        proof_value=f"{spec.proof_value}-V4-{index:04d}-{rng.randint(1000, 9999)}",
        recovery_header=spec.recovery_header,
        recovery_path=spec.recovery_path,
        recovery_token=f"{spec.recovery_token}-V4-{index:04d}-{rng.randint(1000, 9999)}",
        source_variant=spec.variant,
    )


def teacher_messages(spec: WebSourceGapTeacherScenario) -> list[dict[str, str]]:
    system = (
        "You generate training data for an authorized, fictional AegisPT lab. "
        "Return ONLY one JSON object, with no markdown or surrounding prose. "
        "The JSON object must be {\"messages\":[...],\"metadata\":{...}}. "
        "Every assistant message content must be a JSON string with EXACTLY keys "
        "done, evidence, next_action, reasoning, safety, state. Use alternating "
        "assistant actions and user TOOL OBSERVATION messages. The final assistant "
        "turn must set done=true and evidence.goal_satisfied=true. Every "
        "next_action must be {\"tool\":...,\"purpose\":...,\"args\":{...}}; "
        "method, url, headers, and body must live inside args, never at "
        "next_action top level. Keep runtime_execution=false, lab_only=true, "
        "and payload_free=true. Do not use real public targets, real secrets, "
        "malware, destructive actions, brute force, credential dumping, real "
        "exploit payloads, executable code, base64 blobs, templating expressions, "
        "XML DOCTYPEs, SQL snippets, shell commands, serialized objects, or "
        "eval/code strings. Request bodies must be empty or bounded JSON "
        "containing only lab evidence keys such as evidence_token, proof, "
        "proof_value, decision, requested_decision, and lab_only. The row must "
        "show this recovery arc in observations, not just prose: premature goal "
        "attempt, blocked/403 observation, backtrack to the hinted evidence "
        "resource, use the bounded evidence token/proof, then retry/complete "
        "the goal."
    )
    user = {
        "allowed_route_contract": {
            "blocked_goal_path": spec.blocked_goal_path,
            "evidence_path": spec.evidence_path,
            "proof_path": spec.proof_path,
            "proof_value": spec.proof_value,
            "recovery_header": spec.recovery_header,
            "recovery_path": spec.recovery_path,
            "recovery_token": spec.recovery_token,
        },
        "blocked_goal_recovery_required": {
            "arc": "premature_goal_attempt -> blocked_observation -> hinted_resource_exploration -> revealed_value_used -> successful_goal_retry",
            "minimum_blocked_observations": 1,
            "must_use_revealed_value_after_block": True,
        },
        "chain_class": spec.chain_class,
        "domain": spec.domain,
        "forbidden_strings": list(d1.HELD_OUT_STRINGS),
        "host": spec.host,
        "marker": spec.marker,
        "minimum_assistant_turns": 4,
        "objective": spec.goal,
        "required_metadata": {
            "case_id": spec.lab_id,
            "chain_class": spec.chain_class,
            "dataset_family": "external_v4pro_teacher_raw",
            "domain": spec.domain,
            "lab_only": True,
            "runtime_execution": False,
            "scenario_hash": spec.scenario_hash,
            "split": "train",
            "teacher_model": d1.DEFAULT_MODEL,
            "variant": spec.source_variant,
        },
        "tool_schema": {
            "next_action": {
                "args": {
                    "body": "empty string or JSON with only bounded lab evidence keys",
                    "headers": {},
                    "method": "GET|POST",
                    "url": "fictional lab URL",
                },
                "purpose": "bounded lab proof step",
                "tool": "lab_http_request|lab_api_request|none",
            }
        },
    }
    return [
        {"role": "system", "content": system},
        {"role": "user", "content": json.dumps(user, sort_keys=True)},
    ]


def _row_chain_class(row: dict[str, Any]) -> str:
    metadata = row.get("metadata")
    if isinstance(metadata, dict):
        return str(metadata.get("chain_class") or "unknown")
    return "unknown"


def _accepted_by_chain_class(rows: list[dict[str, Any]]) -> dict[str, int]:
    counts = Counter(_row_chain_class(row) for row in rows)
    return {name: counts.get(name, 0) for name in WEB_SOURCE_GAP_CHAIN_CLASSES}


def _class_quota_satisfied(rows: list[dict[str, Any]], *, target_min_per_class: int) -> dict[str, bool]:
    counts = _accepted_by_chain_class(rows)
    return {name: counts.get(name, 0) >= target_min_per_class for name in WEB_SOURCE_GAP_CHAIN_CLASSES}


def _deficits(
    rows: list[dict[str, Any]],
    *,
    target_min_per_class: int,
    only_classes: list[str],
) -> dict[str, int]:
    counts = _accepted_by_chain_class(rows)
    return {
        name: max(0, target_min_per_class - int(counts.get(name, 0)))
        for name in only_classes
        if max(0, target_min_per_class - int(counts.get(name, 0))) > 0
    }


def _scenario_registry_rows(rows: list[dict[str, Any]], prefix: str) -> list[dict[str, Any]]:
    return [
        {
            "case_id": row["metadata"]["case_id"],
            "chain_class": row["metadata"].get("chain_class", ""),
            "dataset_family": prefix,
            "holdout_reason": "teacher_demonstrated_reserved_train",
            "original_case_id": row["metadata"]["original_case_id"],
            "scenario_hash": row["metadata"]["scenario_hash"],
            "scenario_id": row["metadata"]["case_id"],
            "source": "scripts/training/generate_v4pro_web_source_gap_topup_iter10.py",
            "split": "train",
            "teacher_model": row["metadata"]["teacher_model"],
        }
        for row in rows
    ]


def _write_manifest(
    *,
    accepted: list[dict[str, Any]],
    attempts: int,
    endpoint: str,
    manifest_path: Path,
    model: str,
    only_classes: list[str],
    prefix: str,
    raw_path: Path,
    raw_rows: list[dict[str, Any]],
    rejected: list[dict[str, Any]],
    rejected_path: Path,
    scenario_registry_path: Path,
    stopped_reason: str,
    target_min_per_class: int,
    train_path: Path,
) -> dict[str, Any]:
    write_jsonl(raw_path, raw_rows)
    write_jsonl(train_path, accepted)
    write_jsonl(rejected_path, rejected)
    write_jsonl(scenario_registry_path, _scenario_registry_rows(accepted, prefix))
    accepted_by_chain_class = _accepted_by_chain_class(accepted)
    manifest = {
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
            "no_real_payloads": True,
            "payload_free": True,
            "runtime_execution": False,
            "secret_committed": False,
            "train_only": True,
            "v4pro_demonstrated_rows": True,
        },
        "quality_report": {
            "accepted_by_chain_class": accepted_by_chain_class,
            "assistant_turn_distribution": dict(
                sorted(Counter(str(_assistant_turn_count(row)) for row in accepted).items())
            ),
            "class_quota_satisfied": _class_quota_satisfied(
                accepted,
                target_min_per_class=target_min_per_class,
            ),
            "deficits_remaining": _deficits(
                accepted,
                target_min_per_class=target_min_per_class,
                only_classes=only_classes,
            ),
            "rejected_by_reason": dict(sorted(Counter(row["reason"] for row in rejected).items())),
        },
        "stats": {
            "accepted_count": len(accepted),
            "accepted_by_chain_class": accepted_by_chain_class,
            "attempts": attempts,
            "rejected_count": len(rejected),
            "stopped_reason": stopped_reason,
            "target_chain_classes": only_classes,
            "target_min_per_chain_class": target_min_per_class,
        },
    }
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest


def build_topup(
    *,
    out_dir: Path = DEFAULT_OUT_DIR,
    prefix: str = DEFAULT_PREFIX,
    endpoint: str = d1.DEFAULT_ENDPOINT,
    model: str = d1.DEFAULT_MODEL,
    max_tokens: int = d1.DEFAULT_MAX_TOKENS,
    temperature: float = 0.35,
    timeout: int = 300,
    max_attempts: int = 96,
    seed: int = DEFAULT_SEED,
    registry_path: Path | None = None,
    secret_file: Path | None = None,
    sleep_seconds: float = 0.5,
    wall_seconds: float | None = None,
    target_min_per_class: int = DEFAULT_TARGET_MIN_PER_CLASS,
    only_classes: list[str] | None = None,
) -> dict[str, Any]:
    api_key = d1.read_secret_key(secret_file)
    if not api_key:
        raise RuntimeError("DEEPSEEK_API_KEY not found in environment or ~/.aegispt-secrets")
    out_dir.mkdir(parents=True, exist_ok=True)
    registry = load_registry(registry_path) if registry_path else build_registry()
    allowed_classes = only_classes or list(WEB_SOURCE_GAP_CHAIN_CLASSES)
    spec_by_class = _spec_by_class()
    unknown = sorted(set(allowed_classes) - set(spec_by_class))
    if unknown:
        raise ValueError(f"unknown web source-gap chain classes: {unknown}")

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

    for index in range(max_attempts):
        remaining = _deficits(
            accepted,
            target_min_per_class=target_min_per_class,
            only_classes=allowed_classes,
        )
        if not remaining:
            break
        chain_class = max(remaining, key=lambda name: (remaining[name], name))
        spec = make_scenario(spec_by_class[chain_class], index=index, seed=seed)
        attempts += 1
        try:
            candidate = d1.call_deepseek(
                endpoint=endpoint,
                model=model,
                messages=teacher_messages(spec),
                api_key=api_key,
                max_tokens=max_tokens,
                temperature=temperature,
                timeout=timeout,
                json_mode=True,
            )
            metadata = candidate.get("metadata") if isinstance(candidate.get("metadata"), dict) else {}
            metadata.update(
                {
                    "case_id": spec.lab_id,
                    "chain_class": spec.chain_class,
                    "dataset_family": "external_v4pro_teacher_raw",
                    "domain": spec.domain,
                    "lab_only": True,
                    "runtime_execution": False,
                    "scenario_hash": spec.scenario_hash,
                    "split": "train",
                    "teacher_model": model,
                    "variant": spec.source_variant,
                }
            )
            candidate["metadata"] = metadata
            raw_rows.append(candidate)
            guard_reason = _teacher_action_guard(candidate)
            if guard_reason:
                raise ValueError(guard_reason)
            if not _has_observed_recovery_arc(candidate):
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
            reason = detail if detail in {
                "assistant_action_schema_mismatch",
                "missing_blocked_goal_recovery_arc",
                "unsafe_body_payload",
            } else f"teacher_error:{type(exc).__name__}"
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
            endpoint=endpoint,
            manifest_path=manifest_path,
            model=model,
            only_classes=allowed_classes,
            prefix=prefix,
            raw_path=raw_path,
            raw_rows=raw_rows,
            rejected=rejected,
            rejected_path=rejected_path,
            scenario_registry_path=scenario_registry_path,
            stopped_reason="running",
            target_min_per_class=target_min_per_class,
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
        endpoint=endpoint,
        manifest_path=manifest_path,
        model=model,
        only_classes=allowed_classes,
        prefix=prefix,
        raw_path=raw_path,
        raw_rows=raw_rows,
        rejected=rejected,
        rejected_path=rejected_path,
        scenario_registry_path=scenario_registry_path,
        stopped_reason=stopped_reason,
        target_min_per_class=target_min_per_class,
        train_path=train_path,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    parser.add_argument("--prefix", default=DEFAULT_PREFIX)
    parser.add_argument("--endpoint", default=d1.DEFAULT_ENDPOINT)
    parser.add_argument("--model", default=d1.DEFAULT_MODEL)
    parser.add_argument("--max-tokens", type=int, default=d1.DEFAULT_MAX_TOKENS)
    parser.add_argument("--temperature", type=float, default=0.35)
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--max-attempts", type=int, default=96)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--registry", type=Path)
    parser.add_argument("--secret-file", type=Path)
    parser.add_argument("--sleep-seconds", type=float, default=0.5)
    parser.add_argument("--wall-seconds", type=float)
    parser.add_argument("--target-min-per-class", type=int, default=DEFAULT_TARGET_MIN_PER_CLASS)
    parser.add_argument("--only-chain-class", action="append")
    args = parser.parse_args()
    manifest = build_topup(
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
        target_min_per_class=args.target_min_per_class,
        only_classes=parse_classes(args.only_chain_class),
    )
    print(json.dumps(manifest["stats"], indent=2, sort_keys=True))
    print(f"manifest: {args.out_dir / (args.prefix + '_manifest.json')}")


if __name__ == "__main__":
    main()
