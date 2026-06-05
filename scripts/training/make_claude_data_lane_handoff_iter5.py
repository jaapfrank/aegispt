"""Build a Claude-readable handoff for the iter-3/4/5 data lane.

The handoff consolidates local training artifact manifests into a repo-backed
JSON + Markdown summary under ``codex/results``. It is meant for the next Claude
or Codex operator to understand what was generated, what is safe to train, what
must remain separate, and which promotion gates are still blocking.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

DEFAULT_TRAINING_DIR = Path.home() / ".aegispt-tools" / "training"
DEFAULT_RESULTS_DIR = Path("codex/results")
DEFAULT_PREFIX = "aegispt-data-lane-iter5-claude-handoff-20260605"
DEFAULT_LATEST_PREFIX = "aegispt-data-lane-iter5-claude-handoff-latest"

MANIFESTS = {
    "full_coverage_sft": "aegispt_full_coverage_dora_loraplus_unsloth_manifest.json",
    "open_corpus_iter3": "aegispt_open_corpus_iter3_manifest.json",
    "payload_capability_iter4": "aegispt_payload_capability_iter4_manifest.json",
    "payload_negative_iter4": "aegispt_payload_negative_contrastive_iter4_manifest.json",
    "payload_dpo_iter4": "aegispt_payload_dpo_iter4_manifest.json",
    "payload_domain_extension_iter4": "aegispt_payload_domain_extension_iter4_manifest.json",
    "live_lab_specs_iter5": "aegispt_live_lab_target_specs_iter5_manifest.json",
    "llmsvs_eval_iter5": "aegispt_llmsvs_adversarial_eval_iter5_manifest.json",
    "near_duplicate_flags_iter5": "aegispt_near_duplicate_flags_iter5_manifest.json",
    "duplicate_triage_iter5": "aegispt_duplicate_triage_iter5_manifest.json",
    "training_exclusions_iter5": "aegispt_training_exclusions_iter5_manifest.json",
    "curated_sft_mix_iter5": "aegispt_curated_sft_mix_iter5_manifest.json",
    "multiturn_agentic_chain_iter6": "aegispt_multiturn_agentic_chain_iter6_manifest.json",
    "llmsvs_request_pack_iter5": "aegispt_llmsvs_prediction_requests_iter5_manifest.json",
    "adapter_readiness_iter5": "aegispt_adapter_promotion_readiness_iter5.json",
}

TRAINING_ORDER = [
    "Use the curated SFT mix for the next SFT run: aegispt_curated_sft_mix_iter5.jsonl.",
    "Keep DPO data separate: aegispt_payload_dpo_iter4_* remains prompt/chosen/rejected data.",
    "Keep the multi-turn chain family separate from the active iter5 SFT run unless a follow-up adapter/RL curriculum explicitly selects it.",
    "Use LLMSVS adversarial data as an eval gate, not ordinary SFT data.",
    "Generate real adapter predictions for aegispt_llmsvs_prediction_requests_iter5.jsonl.",
    "Score predictions with score_llmsvs_adversarial_eval_iter5.py.",
    "Run the SFT eval harness to produce eval_<label>.json.",
    "Run deep_chain_eval.py to produce deep_<label>.json.",
    "Rebuild adapter readiness with non-smoke LLMSVS scores and deep-chain scores before promotion.",
]

SAFETY_BOUNDARIES = [
    "No runtime assessment behavior was changed by this data lane.",
    "No capability pack registry, approval flow, deployment flow, NEXT_TASK.md, or TASK_QUEUE.md was changed.",
    "Live-lab specs are data-only contracts; they do not materialize or bind runtime targets.",
    "Duplicate exclusions are non-destructive and only apply to derived mixes.",
    "Multi-turn chain rows are lab/simulator/read-only training data and do not bind live runner targets.",
    "Smoke LLMSVS scores prove the scorer path only; they are not model-promotion evidence.",
]

CLAUDE_NEXT_ACTIONS = [
    {
        "action": "train_sft_candidate",
        "command_hint": "Use ~/.aegispt-tools/training/aegispt_curated_sft_mix_iter5.jsonl as the SFT training file.",
        "owner": "Claude or training operator",
        "status": "ready",
    },
    {
        "action": "run_sft_eval_harness",
        "command_hint": "python3 scripts/training/eval_harness.py --per-family 50 --out ~/.aegispt-tools/training/eval_scores.json",
        "owner": "Claude or training operator",
        "status": "blocked_until_candidate_adapter_exists",
    },
    {
        "action": "generate_llmsvs_predictions",
        "command_hint": "Run the candidate adapter against ~/.aegispt-tools/training/aegispt_llmsvs_prediction_requests_iter5.jsonl.",
        "owner": "Claude or training operator",
        "status": "blocked_until_candidate_adapter_exists",
    },
    {
        "action": "score_llmsvs_predictions",
        "command_hint": "python3 scripts/training/score_llmsvs_adversarial_eval_iter5.py --predictions <model_predictions.jsonl> --fail-on-gate",
        "owner": "Claude or training operator",
        "status": "ready_after_predictions",
    },
    {
        "action": "run_deep_chain_eval",
        "command_hint": "AEGISPT_DEEP_OUT=~/.aegispt-tools/training/deep_<label>.json python3 scripts/training/deep_chain_eval.py",
        "owner": "Claude or training operator",
        "status": "blocked_until_candidate_adapter_is_served",
    },
    {
        "action": "rebuild_promotion_readiness",
        "command_hint": "python3 scripts/training/make_adapter_promotion_readiness_iter5.py --sft-eval-scores <eval_label.json> --llmsvs-scores <non_smoke_scores.json> --deep-chain-scores <deep_label.json>",
        "owner": "Claude or training operator",
        "status": "ready_after_scores",
    },
    {
        "action": "use_multiturn_chain_family_for_frontier",
        "command_hint": "Use ~/.aegispt-tools/training/aegispt_multiturn_agentic_chain_iter6_train.jsonl as the multi-turn follow-through curriculum/rollout seed after the supervised iter5 gate.",
        "owner": "Claude or training operator",
        "status": "ready_after_iter5_gate",
    },
]


def read_json(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def artifact_record(key: str, training_dir: Path) -> dict[str, Any]:
    filename = MANIFESTS[key]
    path = training_dir / filename
    data = read_json(path)
    return {
        "dataset": data.get("dataset") if data else None,
        "key": key,
        "manifest_path": str(path),
        "paths": data.get("paths") if data else data.get("path") if data else None,
        "policy": data.get("policy") if data else None,
        "present": data is not None,
        "stats": data.get("stats") if data else None,
    }


def promotion_summary(artifacts: list[dict[str, Any]]) -> dict[str, Any]:
    readiness = next((item for item in artifacts if item["key"] == "adapter_readiness_iter5"), None)
    if not readiness or not readiness["present"]:
        return {
            "promotion_ready": False,
            "required_failures": ["adapter_readiness_missing"],
        }
    data = read_json(Path(readiness["manifest_path"])) or {}
    return {
        "promotion_ready": data.get("promotion_ready", False),
        "required_failures": data.get("required_failures", []),
    }


def build_handoff(
    *,
    training_dir: Path = DEFAULT_TRAINING_DIR,
    results_dir: Path = DEFAULT_RESULTS_DIR,
    prefix: str = DEFAULT_PREFIX,
    latest_prefix: str = DEFAULT_LATEST_PREFIX,
) -> dict[str, Any]:
    results_dir.mkdir(parents=True, exist_ok=True)
    artifacts = [artifact_record(key, training_dir) for key in MANIFESTS]
    handoff = {
        "artifact_count": len(artifacts),
        "artifacts": artifacts,
        "claude_next_actions": CLAUDE_NEXT_ACTIONS,
        "handoff": prefix,
        "missing_artifacts": [item["key"] for item in artifacts if not item["present"]],
        "promotion": promotion_summary(artifacts),
        "safety_boundaries": SAFETY_BOUNDARIES,
        "training_dir": str(training_dir),
        "training_order": TRAINING_ORDER,
    }
    json_path = results_dir / f"{prefix}.json"
    markdown_path = results_dir / f"{prefix}.md"
    json_text = json.dumps(handoff, indent=2, sort_keys=True) + "\n"
    markdown_text = render_markdown(handoff)
    json_path.write_text(json_text, encoding="utf-8")
    markdown_path.write_text(markdown_text, encoding="utf-8")
    latest_json_path = results_dir / f"{latest_prefix}.json"
    latest_markdown_path = results_dir / f"{latest_prefix}.md"
    latest_json_path.write_text(json_text, encoding="utf-8")
    latest_markdown_path.write_text(markdown_text, encoding="utf-8")
    return {
        **handoff,
        "output_paths": {
            "json": str(json_path),
            "latest_json": str(latest_json_path),
            "latest_markdown": str(latest_markdown_path),
            "markdown": str(markdown_path),
        },
    }


def render_markdown(handoff: dict[str, Any]) -> str:
    promotion = handoff["promotion"]
    lines = [
        "# AegisPT Data-Lane Iter-5 Claude Handoff",
        "",
        "This handoff summarizes the Codex data-lane work so Claude can continue without rediscovering artifact state.",
        "",
        "## Promotion State",
        "",
        f"- promotion_ready: `{str(promotion['promotion_ready']).lower()}`",
        f"- required_failures: `{', '.join(promotion['required_failures']) or 'none'}`",
        "",
        "## Safety Boundaries",
        "",
    ]
    lines.extend(f"- {item}" for item in handoff["safety_boundaries"])
    lines.extend(["", "## Training Order", ""])
    lines.extend(f"{index}. {item}" for index, item in enumerate(handoff["training_order"], start=1))
    lines.extend(["", "## Claude Next Actions", ""])
    for action in handoff["claude_next_actions"]:
        lines.append(f"- `{action['action']}` ({action['status']}): {action['command_hint']}")
    lines.extend(["", "## Artifact Summary", ""])
    for artifact in handoff["artifacts"]:
        status = "present" if artifact["present"] else "missing"
        lines.append(f"- `{artifact['key']}`: {status} - `{artifact['manifest_path']}`")
    lines.append("")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--training-dir", type=Path, default=DEFAULT_TRAINING_DIR)
    parser.add_argument("--results-dir", type=Path, default=DEFAULT_RESULTS_DIR)
    parser.add_argument("--prefix", default=DEFAULT_PREFIX)
    parser.add_argument("--latest-prefix", default=DEFAULT_LATEST_PREFIX)
    args = parser.parse_args()
    handoff = build_handoff(
        training_dir=args.training_dir,
        results_dir=args.results_dir,
        prefix=args.prefix,
        latest_prefix=args.latest_prefix,
    )
    print(
        json.dumps(
            {
                "missing_artifacts": handoff["missing_artifacts"],
                "output_paths": handoff["output_paths"],
                "promotion": handoff["promotion"],
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
