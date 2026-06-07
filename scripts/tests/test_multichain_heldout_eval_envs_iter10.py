import json
from pathlib import Path

from scripts.training.multichain_heldout_eval_envs_iter10 import (
    DEFAULT_PREFIX,
    NO_FINDING_LABELS,
    manifest,
    registry_entries,
    run_oracle,
    scenario_specs,
    validate_manifest,
    write_oracle_rollouts,
)


def test_heldout_eval_manifest_is_eval_only_and_complete():
    data = manifest()
    stats = validate_manifest(data)

    assert data["dataset"] == DEFAULT_PREFIX
    assert data["policy"]["eval_only"] is True
    assert data["policy"]["not_training_data"] is True
    assert stats["scenario_count"] == 8
    assert len(stats["chain_classes"]) >= 7
    assert all(
        set(item["no_finding_labels"]) == set(NO_FINDING_LABELS)
        for item in data["scenarios"]
    )


def test_heldout_eval_oracles_solve_with_recovery_signals():
    for spec in scenario_specs():
        trace, result = run_oracle(spec)

        assert len(trace) == 4
        assert result["flag"] is True
        assert result["blocked_goal"] is True
        assert result["recovered_after_block"] is True
        assert result["used_revealed_value"] is True
        assert result["lab_truth"] == "known_vulnerable"


def test_heldout_eval_registry_entries_are_hash_guarded():
    entries = registry_entries()

    assert len(entries) == 8
    assert {entry["split"] for entry in entries} == {"eval"}
    assert {entry["dataset_family"] for entry in entries} == {DEFAULT_PREFIX}
    assert all(entry["scenario_hash"] for entry in entries)
    assert all(entry["lab_truth"] == "known_vulnerable" for entry in entries)
    assert all(set(entry["no_finding_labels"]) == set(NO_FINDING_LABELS) for entry in entries)


def test_write_oracle_rollouts(tmp_path):
    summary = write_oracle_rollouts(tmp_path)

    assert len(summary["rollouts"]) == 8
    assert (tmp_path / f"{DEFAULT_PREFIX}_manifest.json").exists()
    first_roll = summary["rollouts"][0]
    roll_rows = [
        json.loads(line)
        for line in Path(first_roll["roll_path"]).read_text(encoding="utf-8").splitlines()
    ]
    result = json.loads(Path(first_roll["res_path"]).read_text(encoding="utf-8"))
    assert roll_rows
    assert result["flag"] is True
