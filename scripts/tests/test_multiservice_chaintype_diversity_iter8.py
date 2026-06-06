import json

from scripts.training.make_multiservice_chaintype_diversity_iter8 import (
    CHAIN_CLASSES,
    DEFAULT_PREFIX,
    FORBIDDEN_HELD_OUT_MARKERS,
    MIN_ASSISTANT_TURNS,
    build_dataset,
    generate_rows,
    validate_rows,
)


def test_multiservice_chaintype_diversity_has_long_safe_chains(tmp_path):
    rows = generate_rows(32, split="test", seed=20260607)
    stats = validate_rows(rows)

    assert set(stats["chain_classes"]) == set(CHAIN_CLASSES)
    assert min(stats["assistant_turns"]) >= MIN_ASSISTANT_TURNS
    assert stats["domains"] == {
        "api_worker": 8,
        "cloud_api": 8,
        "lan_web": 8,
        "web_api": 8,
    }
    assert {"lab_api_request", "lab_http_request", "none"} <= set(stats["tools"])

    serialized = "\n".join(json.dumps(row, sort_keys=True) for row in rows)
    for forbidden in FORBIDDEN_HELD_OUT_MARKERS:
        assert forbidden not in serialized

    for row in rows:
        assert row["metadata"]["dataset_family"] == DEFAULT_PREFIX
        assert row["metadata"]["global_held_out_registry"] == "excluded"
        assert row["metadata"]["runtime_execution"] is False
        assert "multi_service_pivot_followthrough" in row["metadata"]["safety_tags"]

        assistant_turns = [message for message in row["messages"] if message["role"] == "assistant"]
        assert len(assistant_turns) >= MIN_ASSISTANT_TURNS
        assert "TOOL OBSERVATION" in row["messages"][3]["content"]

        for turn_idx, message in enumerate(assistant_turns):
            parsed = json.loads(message["content"])
            assert set(parsed) == {"done", "evidence", "next_action", "reasoning", "safety", "state"}
            assert "args" in parsed["next_action"]
            assert parsed["safety"]["runtime_execution"] is False
            if turn_idx < len(assistant_turns) - 1:
                assert parsed["done"] is False
            else:
                assert parsed["done"] is True
                assert parsed["evidence"]["goal_satisfied"] is True
                assert parsed["next_action"]["tool"] == "none"

    manifest = build_dataset(tmp_path, DEFAULT_PREFIX, {"train": 8, "eval": 8, "test": 8}, seed=7)
    assert manifest["policy"]["multi_service_chain_type_diversity"] is True
    assert manifest["policy"]["iter8_eval_test_must_be_registered_held_out"] is True
    assert manifest["policy"]["held_out_deep_chain_solution_not_copied"] is True
    assert manifest["splits"]["train"]["count"] == 8
