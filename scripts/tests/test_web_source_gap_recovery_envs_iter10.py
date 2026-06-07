import json
from pathlib import Path

from scripts.training.web_source_gap_recovery_envs_iter10 import (
    DEFAULT_PREFIX,
    DEMO_CHAIN_CLASSES,
    DEMO_PREFIX,
    demo_rows,
    manifest,
    registry_entries,
    run_oracle,
    scenario_specs,
    validate_manifest,
    write_artifacts,
)


def test_web_source_gap_manifest_is_lab_only_and_payload_free():
    data = manifest()
    stats = validate_manifest(data)

    assert data["dataset"] == DEFAULT_PREFIX
    assert data["policy"]["payload_free"] is True
    assert data["policy"]["no_runtime_execution"] is True
    assert stats["scenario_count"] == 4
    assert stats["chain_classes"] == sorted(DEMO_CHAIN_CLASSES)


def test_web_source_gap_oracles_solve_recovery_arc():
    for spec in scenario_specs():
        trace, result = run_oracle(spec)

        assert len(trace) == 4
        assert result["flag"] is True
        assert result["blocked_goal"] is True
        assert result["evidence_collected"] is True
        assert result["pivot"] is True
        assert result["recovered_after_block"] is True
        assert result["used_revealed_value"] is True


def test_web_source_gap_demo_rows_have_final_done_and_distribution():
    rows = demo_rows(12)

    assert len(rows) == 12
    assert {row["metadata"]["dataset_family"] for row in rows} == {DEMO_PREFIX}
    assert {row["metadata"]["chain_class"] for row in rows} == set(DEMO_CHAIN_CLASSES)
    final_payloads = [json.loads(row["messages"][-1]["content"]) for row in rows]
    assert all(payload["done"] is True for payload in final_payloads)
    assert all(payload["evidence"]["goal_satisfied"] is True for payload in final_payloads)
    serialized = "\n".join(json.dumps(row, sort_keys=True) for row in rows)
    assert "payload_free" in serialized
    assert "shop.lab" not in serialized
    assert "/admin/config" not in serialized


def test_web_source_gap_registry_entries_are_reserved():
    entries = registry_entries()

    assert len(entries) == 4
    assert {entry["dataset_family"] for entry in entries} == {DEFAULT_PREFIX}
    assert {entry["split"] for entry in entries} == {"rl_train_env"}
    assert all(entry["scenario_hash"] for entry in entries)


def test_web_source_gap_write_artifacts(tmp_path):
    summary = write_artifacts(tmp_path, demo_count=12)

    assert summary["stats"]["env_count"] == 4
    assert summary["demo_count"] == 12
    assert (tmp_path / f"{DEFAULT_PREFIX}_manifest.json").exists()
    assert (tmp_path / f"{DEMO_PREFIX}_train.jsonl").exists()
    first_roll = summary["rollouts"][0]
    result = json.loads(Path(first_roll["res_path"]).read_text(encoding="utf-8"))
    assert result["flag"] is True
