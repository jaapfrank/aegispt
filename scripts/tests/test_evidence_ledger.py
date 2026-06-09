import json

import pytest

from api.app.services.finding_evidence_gate import PROVEN, UNPROVEN
from scripts.validation.build_evidence_ledger import (
    build_ledger,
    summarize,
    validate_rows,
)


def write_gap_matrix(path, rows):
    path.write_text(
        "\n".join(json.dumps(row, sort_keys=True) for row in rows) + "\n",
        encoding="utf-8",
    )


def base_gap_row(xben_id, solve_status):
    return {
        "chain_depth": 1,
        "coverage_bucket": "test_bucket",
        "evidence_paths": [],
        "has_env": True,
        "has_solve": solve_status == "solved",
        "has_teacher_demo": False,
        "recommended_data_action": "test",
        "solve_evidence_path": "",
        "solve_status": solve_status,
        "vuln_class": "test_class",
        "xben_id": xben_id,
    }


def test_evidence_ledger_builds_canonical_status_rows(tmp_path):
    validation = tmp_path / "docs" / "validation"
    validation.mkdir(parents=True)
    gap_matrix = tmp_path / "gap.jsonl"
    write_gap_matrix(
        gap_matrix,
        [
            base_gap_row("XBEN-001", "attempted_no_solve"),
            base_gap_row("XBEN-002", "solved"),
            base_gap_row("XBEN-003", "infra_blocked_or_crashed"),
            base_gap_row("XBEN-004", "unknown_untriaged"),
        ],
    )
    solve_dir = validation / "xbow-xben002-test"
    solve_dir.mkdir()
    (solve_dir / "run-summary.json").write_text(
        json.dumps(
            {
                "challenge": "XBEN-002-24",
                "flag_found_in": ["findings", "task:abc:interactive-exploit"],
                "flag_injected": "xbow-0123456789abcdef0123456789abcdef",
                "provider": "chatgpt_oauth",
                "run_id": "11111111-1111-4111-8111-111111111111",
                "solved": True,
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    (solve_dir / "invariant.txt").write_text("[PASS] every captured flag persisted\n")

    rows = build_ledger(gap_matrix, validation)
    summary = summarize(rows)
    by_id = {row["xben_id"]: row for row in rows}

    assert summary["canonical_score"] == "1/4"
    assert summary["reportability_counts"][PROVEN] == 1
    assert summary["reportability_counts"][UNPROVEN] == 3
    assert by_id["XBEN-002"]["outcome"] == "solved"
    assert by_id["XBEN-002"]["evidence_level"] == "flag_capture_persisted_finding"
    assert by_id["XBEN-002"]["finding_persistence_invariant"] == "pass"
    assert by_id["XBEN-002"]["reportability_class"] == PROVEN
    assert by_id["XBEN-002"]["reportable_under_no_exploit_no_report"] is True
    assert by_id["XBEN-001"]["outcome"] == "attempted_no_solve"
    assert by_id["XBEN-001"]["reportability_class"] == UNPROVEN
    assert by_id["XBEN-001"]["reportable_under_no_exploit_no_report"] is False
    assert by_id["XBEN-003"]["outcome"] == "infra_blocked"
    assert by_id["XBEN-004"]["outcome"] == "unknown"


def test_evidence_ledger_uses_no_flag_outcome_for_attempted_target(tmp_path):
    validation = tmp_path / "docs" / "validation"
    validation.mkdir(parents=True)
    gap_matrix = tmp_path / "gap.jsonl"
    write_gap_matrix(gap_matrix, [base_gap_row("XBEN-024", "attempted_no_solve")])
    outcome_dir = validation / "xbow-xben024-test"
    outcome_dir.mkdir()
    (outcome_dir / "OUTCOME.md").write_text(
        "# XBEN-024-24 outcome\n\nResult: NO FLAG. The chain was not completed.\n",
        encoding="utf-8",
    )

    row = build_ledger(gap_matrix, validation)[0]

    assert row["outcome"] == "attempted_no_solve"
    assert row["evidence_level"] == "no_flag_outcome_note"
    assert row["proof_status"] == "attempted_no_solve"
    assert row["reportability_class"] == UNPROVEN
    assert row["reportable_under_no_exploit_no_report"] is False
    assert row["evidence_ref"].endswith("OUTCOME.md")


def test_evidence_ledger_labels_grader_solved_without_persisted_finding(tmp_path):
    validation = tmp_path / "docs" / "validation"
    validation.mkdir(parents=True)
    gap_matrix = tmp_path / "gap.jsonl"
    write_gap_matrix(gap_matrix, [base_gap_row("XBEN-020", "solved")])
    solve_dir = validation / "xbow-xben020-test"
    solve_dir.mkdir()
    (solve_dir / "README.md").write_text(
        "\n".join(
            [
                "# XBEN-020-24 GRADER SOLVE (canonical gap)",
                "",
                "Honest result: grader-solved, NOT canonical-finding-persisted.",
                "Byte-equal flag xbow-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa was captured by another tool.",
                "run_id `22222222-2222-4222-8222-222222222222`",
            ]
        ),
        encoding="utf-8",
    )

    row = build_ledger(gap_matrix, validation)[0]

    assert row["outcome"] == "solved"
    assert row["proof_status"] == "grader_solved_not_finding_persisted"
    assert row["evidence_level"] == "byte_equal_tool_capture_no_persisted_finding"
    assert row["reportability_class"] == PROVEN
    assert row["reportable_under_no_exploit_no_report"] is True


def test_evidence_ledger_can_include_heldout_transfer_rows_without_moving_xbow_score(tmp_path):
    validation = tmp_path / "docs" / "validation"
    validation.mkdir(parents=True)
    gap_matrix = tmp_path / "gap.jsonl"
    write_gap_matrix(
        gap_matrix,
        [
            base_gap_row("XBEN-001", "attempted_no_solve"),
            base_gap_row("XBEN-002", "solved"),
        ],
    )
    solve_dir = validation / "xbow-xben002-test"
    solve_dir.mkdir()
    (solve_dir / "run-summary.json").write_text(
        json.dumps(
            {
                "challenge": "XBEN-002-24",
                "flag_found_in": ["findings"],
                "flag_injected": "xbow-0123456789abcdef0123456789abcdef",
                "provider": "chatgpt_oauth",
                "run_id": "11111111-1111-4111-8111-111111111111",
                "solved": True,
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    transfer_matrix = tmp_path / "transfer.json"
    transfer_matrix.write_text(
        json.dumps(
            {
                "rows": [
                    {
                        "chain_class": "auth_logic_session_forgery",
                        "dataset_family": "heldout",
                        "domain": "web_auth",
                        "flag": False,
                        "lab_truth": "known_vulnerable",
                        "recovered_after_block": True,
                        "result_path": "codex/results/training/run/res_0.json",
                        "reward": 5,
                        "run_label": "qwen3_8b_iter7ct",
                        "scenario_hash": "hash-a",
                        "scenario_id": "heldout-a",
                        "steps": 6,
                        "used_revealed_value": True,
                    },
                    {
                        "chain_class": "ssrf_internal_endpoint_recovery",
                        "dataset_family": "heldout",
                        "domain": "web_api",
                        "flag": True,
                        "lab_truth": "known_vulnerable",
                        "recovered_after_block": True,
                        "result_path": "codex/results/training/run/res_1.json",
                        "reward": 26,
                        "run_label": "qwen3_8b_iter7ct",
                        "scenario_hash": "hash-b",
                        "scenario_id": "heldout-b",
                        "steps": 4,
                        "used_revealed_value": True,
                    },
                ]
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    rows = build_ledger(gap_matrix, validation, [transfer_matrix])
    summary = summarize(rows)
    transfer_rows = [row for row in rows if row["row_type"] == "heldout_transfer_eval"]

    assert summary["canonical_score"] == "1/2"
    assert summary["target_count"] == 2
    assert summary["row_count"] == 4
    assert summary["heldout_transfer"]["row_count"] == 2
    assert summary["heldout_transfer"]["by_run"]["qwen3_8b_iter7ct"]["solve_rate"] == 0.5
    assert transfer_rows[0]["benchmark"] == "AegisPT-D2-heldout"
    assert transfer_rows[0]["transfer_reward"] == 5
    assert transfer_rows[0]["transfer_recovered_after_block"] is True
    assert {row["outcome"] for row in transfer_rows} == {"attempted_no_solve", "solved"}


def test_evidence_ledger_rejects_solved_rows_without_validation_artifact():
    with pytest.raises(ValueError, match="solved row lacks validation artifact"):
        validate_rows(
            [
                {
                    "outcome": "solved",
                    "row_id": "abc",
                    "target": "XBEN-999-24",
                    "evidence_level": "matrix_status",
                    "evidence_ref": "gap.jsonl",
                }
            ]
        )
