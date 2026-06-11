import json
from pathlib import Path

from scripts.training.multichain_heldout_eval_envs_iter11 import (
    DEFAULT_PREFIX,
    HeldoutEvalEnv,
    NO_FINDING_LABELS,
    action,
    manifest,
    registry_entries,
    run_oracle,
    scenario_specs,
    validate_manifest,
    write_oracle_rollouts,
)


def test_iter11_manifest_is_paired_eval_only_and_broader():
    data = manifest()
    stats = validate_manifest(data)

    assert data["dataset"] == DEFAULT_PREFIX
    assert data["policy"]["eval_only"] is True
    assert data["policy"]["not_training_data"] is True
    assert data["policy"]["paired_bare_and_recon_affordance"] is True
    assert stats["scenario_count"] == 24
    assert stats["base_scenario_count"] == 12
    assert stats["recon_affordance_count"] == 12
    assert stats["variants"] == ["bare", "recon_affordance"]
    assert len(stats["chain_classes"]) >= 10
    assert all(
        set(item["no_finding_labels"]) == set(NO_FINDING_LABELS)
        for item in data["scenarios"]
    )


def test_iter11_oracles_solve_and_recon_variants_start_with_route_affordance():
    for spec in scenario_specs():
        trace, result = run_oracle(spec)

        assert result["flag"] is True
        assert result["blocked_goal"] is True
        assert result["recovered_after_block"] is True
        assert result["used_revealed_value"] is True
        assert result["lab_truth"] == "known_vulnerable"
        if spec.recon_affordance:
            assert len(trace) == 5
            first_observation = json.loads(trace[0]["tool_result"])
            assert "recon_affordance" in first_observation["signals"]
            assert spec.blocked_goal_path in first_observation["body"]
        else:
            assert len(trace) == 4


def test_iter11_recon_route_is_only_available_on_recon_variant():
    bare_spec = next(spec for spec in scenario_specs() if spec.variant == "bare")
    recon_spec = next(
        spec
        for spec in scenario_specs()
        if spec.base_slug == bare_spec.base_slug and spec.variant == "recon_affordance"
    )

    bare_observation = HeldoutEvalEnv(bare_spec).step(action("GET", f"{bare_spec.host}{bare_spec.recon_path}"))
    recon_observation = HeldoutEvalEnv(recon_spec).step(action("GET", f"{recon_spec.host}{recon_spec.recon_path}"))

    assert bare_observation["status"] == 404
    assert recon_observation["status"] == 200
    assert recon_spec.blocked_goal_path in recon_observation["body"]
    assert recon_spec.hinted_resource_path in recon_observation["body"]
    assert recon_spec.exchange_path in recon_observation["body"]


def test_iter11_registry_entries_are_hash_guarded_and_eval_only():
    entries = registry_entries()

    assert len(entries) == 24
    assert {entry["split"] for entry in entries} == {"eval"}
    assert {entry["dataset_family"] for entry in entries} == {DEFAULT_PREFIX}
    assert {entry["variant"] for entry in entries} == {"bare", "recon_affordance"}
    assert all(entry["scenario_hash"] for entry in entries)
    assert all(entry["lab_truth"] == "known_vulnerable" for entry in entries)
    assert all(set(entry["no_finding_labels"]) == set(NO_FINDING_LABELS) for entry in entries)


def test_iter11_write_oracle_rollouts_with_zero_training_leakage_hits(tmp_path):
    summary = write_oracle_rollouts(tmp_path)

    assert len(summary["rollouts"]) == 24
    assert summary["stats"]["scenario_count"] == 24
    assert summary["leakage_audit"]["hit_count"] == 0
    assert (tmp_path / f"{DEFAULT_PREFIX}_manifest.json").exists()
    first_roll = summary["rollouts"][0]
    roll_rows = [
        json.loads(line)
        for line in Path(first_roll["roll_path"]).read_text(encoding="utf-8").splitlines()
    ]
    result = json.loads(Path(first_roll["res_path"]).read_text(encoding="utf-8"))
    assert roll_rows
    assert result["flag"] is True
