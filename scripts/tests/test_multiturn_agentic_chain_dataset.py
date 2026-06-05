import json

from scripts.training.make_multiturn_agentic_chain_iter6 import (
    CHAIN_CLASSES,
    DEFAULT_PREFIX,
    MIN_ASSISTANT_TURNS,
    build_dataset,
    generate_rows,
    validate_rows,
)


def test_multiturn_agentic_chain_dataset_covers_domains_and_carries_state(tmp_path):
    rows = generate_rows(64, split="test", seed=2026)
    stats = validate_rows(rows)

    assert set(stats["chain_classes"]) == set(CHAIN_CLASSES)
    assert set(stats["domains"]) == {"active_directory", "api", "cloud", "iot", "lan", "web"}
    assert min(stats["assistant_turns"]) >= MIN_ASSISTANT_TURNS

    for row in rows:
        assert row["metadata"]["dataset_family"] == DEFAULT_PREFIX
        assert row["metadata"]["runtime_execution"] is False
        assistant_turns = [message for message in row["messages"] if message["role"] == "assistant"]
        assert len(assistant_turns) >= MIN_ASSISTANT_TURNS
        assert "TOOL OBSERVATION" in row["messages"][3]["content"]

        first = json.loads(assistant_turns[0]["content"])
        second = json.loads(assistant_turns[1]["content"])
        final = json.loads(assistant_turns[-1]["content"])
        assert first["done"] is False
        assert second["state"]["last_observation_ref"]
        assert final["done"] is True
        assert final["evidence"]["goal_satisfied"] is True
        assert final["next_action"]["tool"] == "none"
        assert final["safety"]["runtime_execution"] is False

    manifest = build_dataset(tmp_path, DEFAULT_PREFIX, {"train": 32, "eval": 16, "test": 16}, seed=1)
    assert manifest["policy"]["teaches_followthrough_not_fixed_recipes"] is True
    assert manifest["policy"]["held_out_deep_chain_solution_not_copied"] is True
    assert manifest["splits"]["train"]["count"] == 32
