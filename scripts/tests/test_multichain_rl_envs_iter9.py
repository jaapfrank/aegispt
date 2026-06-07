import json

from scripts.training import jury_rollout
from scripts.training.multichain_rl_envs_iter9 import (
    DEFAULT_PREFIX,
    FORBIDDEN_HELD_OUT_MARKERS,
    TrainingEnv,
    manifest,
    registry_entries,
    run_oracle,
    scenario_specs,
    validate_manifest,
    write_oracle_rollouts,
)


def test_multichain_rl_env_manifest_is_non_held_out_and_diverse():
    data = manifest()
    stats = validate_manifest(data)

    assert data["dataset"] == DEFAULT_PREFIX
    assert stats["scenario_count"] == 6
    assert {item["chain_class"] for item in data["scenarios"]} == {
        "graphql_worker_queue_pivot",
        "idor_object_token_reuse",
        "info_disclosure_credential_reuse_lateral",
        "lowpriv_delegation_admin_marker",
        "oauth_callback_service_token_pivot",
        "ssrf_internal_recovery_ticket",
    }
    assert all(
        item.get("requires_blocked_goal_recovery") is True
        for item in data["scenarios"]
    )

    serialized = json.dumps(data, sort_keys=True)
    for forbidden in FORBIDDEN_HELD_OUT_MARKERS:
        assert forbidden not in serialized


def test_multichain_rl_oracles_solve_and_emit_shaped_reward():
    for spec in scenario_specs():
        trace, result = run_oracle(spec)
        assert trace
        assert result["blocked_goal"] is True
        assert result["flag"] is True
        assert result["pivot"] is True
        assert result["recovered_after_block"] is True
        assert result["used_revealed_value"] is True
        assert result["reward"] >= 22
        assert result["scenario_hash"] == spec.scenario_hash
        first_observation = json.loads(trace[0]["tool_result"])
        assert first_observation["status"] in {200, 302, 403}
        assert any(
            json.loads(row["tool_result"])["status"] == 403
            for row in trace
        )
        assert trace[-1]["objective_progress"] == 1.0


def test_multichain_rl_env_step_returns_observation():
    spec = scenario_specs()[0]
    env = TrainingEnv(spec)

    observation = env.step(spec.oracle_actions[0])

    assert observation["scenario_id"] == spec.scenario_id
    assert observation["scenario_hash"] == spec.scenario_hash
    assert observation["status"] in {200, 302}
    assert "reward" in observation


def test_multichain_rl_oracle_rollouts_are_rankable_by_jury_rollout(tmp_path):
    write_oracle_rollouts(tmp_path)

    result = jury_rollout.run(str(tmp_path), out=str(tmp_path / "best.jsonl"), min_reward=3)

    assert result["rollouts"] == 6
    assert result["any_flag"] is True
    assert result["kept"] >= 1
    assert (tmp_path / "best.jsonl").read_text(encoding="utf-8").strip()


def test_multichain_rl_registry_entries_have_hashes():
    rows = registry_entries()

    assert len(rows) == 6
    assert {row["dataset_family"] for row in rows} == {DEFAULT_PREFIX}
    assert all(row["scenario_hash"] for row in rows)
    assert {row["split"] for row in rows} == {"rl_train_env"}
