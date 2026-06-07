import json

from scripts.training.build_transfer_matrix_iter10 import (
    build_matrix,
    load_scenario_index,
    write_outputs,
)


def write_manifest(path):
    path.write_text(
        json.dumps(
            {
                "manifest": {
                    "scenarios": [
                        {
                            "chain_class": "auth_logic_session_forgery",
                            "dataset_family": "heldout",
                            "domain": "web_auth",
                            "lab_truth": "known_vulnerable",
                            "scenario_hash": "hash-a",
                            "scenario_id": "scenario-a",
                        },
                        {
                            "chain_class": "ssrf_internal_endpoint_recovery",
                            "dataset_family": "heldout",
                            "domain": "web_api",
                            "lab_truth": "known_vulnerable",
                            "scenario_hash": "hash-b",
                            "scenario_id": "scenario-b",
                        },
                    ]
                }
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )


def write_result(path, scenario_id, *, flag, recovered=True, revealed=True, reward=26):
    path.write_text(
        json.dumps(
            {
                "blocked_goal": True,
                "flag": flag,
                "pivot": flag,
                "recovered_after_block": recovered,
                "reward": reward,
                "scenario_id": scenario_id,
                "steps": 4,
                "used_revealed_value": revealed,
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )


def test_transfer_matrix_joins_results_to_manifest_classes(tmp_path):
    manifest = tmp_path / "manifest.json"
    write_manifest(manifest)
    run_a = tmp_path / "run-a"
    run_b = tmp_path / "run-b"
    run_a.mkdir()
    run_b.mkdir()
    write_result(run_a / "res_0.json", "scenario-a", flag=True)
    write_result(run_a / "res_1.json", "scenario-b", flag=False, recovered=False, revealed=False, reward=3)
    write_result(run_b / "res_0.json", "scenario-a", flag=True)

    matrix = build_matrix(
        runs=[("model_a", run_a), ("model_b", run_b)],
        manifest_paths=[manifest],
    )

    assert matrix["stats"]["run_count"] == 2
    assert matrix["stats"]["scenario_count"] == 2
    assert matrix["stats"]["unknown_chain_class_count"] == 0
    assert matrix["matrix"]["model_a::auth_logic_session_forgery"]["solve_rate"] == 1.0
    assert matrix["matrix"]["model_a::ssrf_internal_endpoint_recovery"]["solve_rate"] == 0.0
    assert matrix["stats"]["by_run"]["model_a"]["solve_rate"] == 0.5
    assert matrix["stats"]["by_run"]["model_b"]["solve_rate"] == 1.0


def test_transfer_matrix_writes_outputs(tmp_path):
    manifest = tmp_path / "manifest.json"
    write_manifest(manifest)
    run = tmp_path / "run"
    run.mkdir()
    write_result(run / "res_0.json", "scenario-a", flag=True)
    matrix = build_matrix(runs=[("oracle", run)], manifest_paths=[manifest])

    summary = write_outputs(matrix, tmp_path / "out")

    assert summary["result_count"] == 1
    assert summary["files"]["matrix"].endswith(".json")
    assert (tmp_path / "out" / "aegispt_transfer_matrix_iter10_rows.jsonl").exists()
    assert (tmp_path / "out" / "aegispt_transfer_matrix_iter10_summary.md").exists()


def test_transfer_matrix_loads_real_d2_manifest():
    index = load_scenario_index(
        [
            __import__(
                "scripts.training.build_transfer_matrix_iter10",
                fromlist=["DEFAULT_D2_MANIFEST"],
            ).DEFAULT_D2_MANIFEST
        ]
    )

    assert len(index) == 8
    assert "heldout-eval-authlogic-session-forgery" in index
