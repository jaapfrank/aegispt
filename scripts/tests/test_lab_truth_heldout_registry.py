import json

from scripts.training import jury_factory
from scripts.training.make_lab_truth_heldout_registry_iter6 import (
    DEFAULT_PREFIX,
    build_dataset,
    build_registry,
    is_held_out_scenario,
    lab_truth_for_scenario,
    load_registry,
)
from scripts.training.make_live_lab_target_specs_iter5 import ALL_CLASSES
from scripts.training.make_llmsvs_adversarial_eval_data import DEFAULT_PREFIX as LLMSVS_PREFIX
from scripts.training.make_multiservice_chaintype_diversity_iter8 import (
    DEFAULT_PREFIX as MULTISERVICE_PREFIX,
)
from scripts.training.make_multiturn_agentic_chain_iter6 import (
    DEFAULT_PREFIX as MULTITURN_PREFIX,
)
from scripts.training.make_multiturn_chaintype_diversity_iter7 import (
    DEFAULT_PREFIX as CHAINTYPE_PREFIX,
)
from scripts.training.multichain_rl_envs_iter9 import DEFAULT_PREFIX as RL_ENV_PREFIX


def small_registry():
    return build_registry(
        live_lab_variants=1,
        llmsvs_count=18,
        multiturn_counts={"eval": 16, "test": 16},
        chaintype_counts={"eval": 8, "test": 8},
        multiservice_counts={"eval": 8, "test": 8},
    )


def test_lab_truth_registry_tags_known_flag_labs_as_known_vulnerable():
    registry = small_registry()
    lab_rows = registry["lab_truth_scenarios"]
    live_lab_rows = [
        row
        for row in lab_rows
        if row["dataset_family"] == "aegispt_live_lab_target_specs_iter5"
    ]
    suite_rows = [
        row for row in lab_rows if row["dataset_family"] == "aegispt-lab-suite-v1"
    ]

    assert len(live_lab_rows) == len(ALL_CLASSES)
    assert suite_rows
    assert {row["lab_truth"] for row in lab_rows} == {"known_vulnerable"}
    assert (
        lab_truth_for_scenario(registry, "ssrf-loopback-metadata")
        == "known_vulnerable"
    )
    assert lab_truth_for_scenario(registry, "unknown-live-target") == "live_no_oracle"


def test_held_out_registry_contains_exact_eval_test_and_benchmark_ids():
    registry = small_registry()
    stats = registry["stats"]

    assert stats["held_out_by_family"]["deep_chain_eval"] == 1
    assert stats["held_out_by_family"][LLMSVS_PREFIX] == 18
    assert stats["held_out_by_family"][MULTITURN_PREFIX] == 32
    assert stats["held_out_by_family"][CHAINTYPE_PREFIX] == 16
    assert stats["held_out_by_family"][MULTISERVICE_PREFIX] == 16
    assert stats["held_out_by_family"][RL_ENV_PREFIX] == 4
    assert stats["held_out_by_family"]["aegispt-lab-suite-v1"] >= 1
    assert is_held_out_scenario(registry, "deep_chain_eval")
    assert is_held_out_scenario(registry, "ssrf-loopback-metadata")
    assert any(
        row["scenario_id"].startswith("llmsvs-")
        for row in registry["held_out_scenarios"]
    )
    assert any(
        "-eval-" in row["scenario_id"] for row in registry["held_out_scenarios"]
    )
    assert any(
        "-test-" in row["scenario_id"] for row in registry["held_out_scenarios"]
    )
    assert any(
        row["dataset_family"] == RL_ENV_PREFIX and row.get("scenario_hash")
        for row in registry["held_out_scenarios"]
    )


def test_registry_json_and_jsonl_are_consumed_by_jury_held_out_loader(tmp_path):
    manifest = build_dataset(
        tmp_path,
        DEFAULT_PREFIX,
        live_lab_variants=1,
        llmsvs_count=18,
        multiturn_counts={"eval": 16, "test": 16},
        chaintype_counts={"eval": 8, "test": 8},
        multiservice_counts={"eval": 8, "test": 8},
    )
    registry_path = tmp_path / f"{DEFAULT_PREFIX}.json"
    held_out_path = tmp_path / f"{DEFAULT_PREFIX}_held_out.jsonl"
    registry = json.loads(registry_path.read_text(encoding="utf-8"))
    held_from_registry = jury_factory.load_held_out([str(registry_path)])
    held_from_jsonl = jury_factory.load_held_out([str(held_out_path)])

    assert manifest["stats"]["held_out_count"] == len(registry["held_out_scenarios"])
    assert held_from_registry == held_from_jsonl
    assert jury_factory.scenario_hash("deep_chain_eval") in held_from_registry
    assert jury_factory.scenario_hash("ssrf-loopback-metadata") in held_from_registry


def test_lab_truth_registry_loader_accepts_json_and_lab_truth_jsonl(tmp_path):
    build_dataset(
        tmp_path,
        DEFAULT_PREFIX,
        live_lab_variants=1,
        llmsvs_count=18,
        multiturn_counts={"eval": 16, "test": 16},
        chaintype_counts={"eval": 8, "test": 8},
        multiservice_counts={"eval": 8, "test": 8},
    )
    registry_from_json = load_registry(tmp_path / f"{DEFAULT_PREFIX}.json")
    registry_from_jsonl = load_registry(tmp_path / f"{DEFAULT_PREFIX}_lab_truth.jsonl")

    assert (
        lab_truth_for_scenario(registry_from_json, "ssrf-loopback-metadata")
        == "known_vulnerable"
    )
    assert (
        lab_truth_for_scenario(registry_from_jsonl, "ssrf-loopback-metadata")
        == "known_vulnerable"
    )
    assert registry_from_jsonl["held_out_scenarios"] == []
