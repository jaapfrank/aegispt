import json

from scripts.training.make_claude_data_lane_handoff_iter5 import (
    DEFAULT_PREFIX,
    MANIFESTS,
    build_handoff,
)


def write_json(path, data):
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def minimal_manifest(dataset):
    return {
        "dataset": dataset,
        "path": f"/tmp/{dataset}.jsonl",
        "policy": {"runtime_execution": False},
        "stats": {"count": 1},
    }


def test_claude_handoff_summarizes_artifacts_and_blocks_promotion_until_scores(tmp_path):
    for key, filename in MANIFESTS.items():
        if key == "adapter_readiness_iter5":
            write_json(
                tmp_path / filename,
                {
                    "dataset": "aegispt_adapter_promotion_readiness_iter5",
                    "policy": {"runtime_execution": False},
                    "promotion_ready": False,
                    "required_failures": [
                        "sft_eval_score_present",
                        "deep_chain_eval_gate",
                        "llmsvs_adversarial_gate",
                    ],
                },
            )
        elif key != "near_duplicate_flags_iter5":
            write_json(tmp_path / filename, minimal_manifest(key))

    handoff = build_handoff(
        training_dir=tmp_path,
        results_dir=tmp_path,
        prefix=DEFAULT_PREFIX,
    )

    assert "near_duplicate_flags_iter5" in handoff["missing_artifacts"]
    assert handoff["promotion"]["promotion_ready"] is False
    assert handoff["promotion"]["required_failures"] == [
        "sft_eval_score_present",
        "deep_chain_eval_gate",
        "llmsvs_adversarial_gate",
    ]
    assert any(action["action"] == "generate_llmsvs_predictions" for action in handoff["claude_next_actions"])
    assert any(action["action"] == "run_deep_chain_eval" for action in handoff["claude_next_actions"])
    assert any(artifact["key"] == "multiturn_agentic_chain_iter6" for artifact in handoff["artifacts"])
    assert "No runtime assessment behavior was changed" in "\n".join(handoff["safety_boundaries"])

    markdown = (tmp_path / f"{DEFAULT_PREFIX}.md").read_text(encoding="utf-8")
    assert "Claude Next Actions" in markdown
    assert "promotion_ready: `false`" in markdown
    assert (tmp_path / f"{DEFAULT_PREFIX}.json").exists()
    assert (tmp_path / "aegispt-data-lane-iter5-claude-handoff-latest.json").exists()
    assert (tmp_path / "aegispt-data-lane-iter5-claude-handoff-latest.md").exists()
