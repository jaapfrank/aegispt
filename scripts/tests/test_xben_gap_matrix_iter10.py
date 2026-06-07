import json

from scripts.training.build_xben_gap_matrix_iter10 import (
    build_matrix,
    summarize,
    write_outputs,
)


def test_xben_gap_matrix_reads_solve_evidence_and_known_gap(tmp_path):
    validation = tmp_path / "validation"
    triage = tmp_path / "triage"
    strategy = tmp_path / "strategy"
    solve_dir = validation / "xbow-xben002-test"
    solve_dir.mkdir(parents=True)
    triage.mkdir()
    strategy.mkdir()
    (solve_dir / "run-summary.json").write_text(
        json.dumps({"challenge": "XBEN-002-24", "solved": True}),
        encoding="utf-8",
    )
    (triage / "xben003.md").write_text(
        "XBEN-003-24 auth-gated SSTI behind login.",
        encoding="utf-8",
    )

    rows = build_matrix(
        challenge_count=4,
        validation_root=validation,
        triage_root=triage,
        strategy_root=strategy,
    )
    by_id = {row["xben_id"]: row for row in rows}

    assert len(rows) == 4
    assert by_id["XBEN-002"]["solve_status"] == "solved"
    assert by_id["XBEN-002"]["has_solve"] is True
    assert by_id["XBEN-003"]["coverage_bucket"] == "auth_logic_session_forgery"
    assert by_id["XBEN-003"]["has_env"] is True
    assert by_id["XBEN-003"]["has_teacher_demo"] is True


def test_xben_gap_matrix_consumes_source_triage_for_unknown_rows(tmp_path):
    validation = tmp_path / "validation"
    triage = tmp_path / "triage"
    strategy = tmp_path / "strategy"
    validation.mkdir()
    triage.mkdir()
    strategy.mkdir()
    source_triage = tmp_path / "source-triage.jsonl"
    source_triage.write_text(
        json.dumps(
            {
                "chain_depth": 2,
                "coverage_bucket": "path_traversal_file_read",
                "triage_status": "source_classified",
                "vuln_class": "path_traversal_file_read",
                "winning_rule_id": "path_traversal_file_read",
                "xben_id": "XBEN-007",
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    rows = build_matrix(
        challenge_count=7,
        validation_root=validation,
        triage_root=triage,
        strategy_root=strategy,
        source_triage_path=source_triage,
    )
    by_id = {row["xben_id"]: row for row in rows}

    assert by_id["XBEN-007"]["vuln_class"] == "path_traversal_file_read"
    assert by_id["XBEN-007"]["class_evidence_source"] == (
        "E1 source triage rule:path_traversal_file_read"
    )
    assert by_id["XBEN-007"]["recommended_data_action"] == "monitor_after_top_gap_rollouts"


def test_xben_gap_matrix_keeps_manual_source_triage_unknown(tmp_path):
    validation = tmp_path / "validation"
    triage = tmp_path / "triage"
    strategy = tmp_path / "strategy"
    validation.mkdir()
    triage.mkdir()
    strategy.mkdir()
    (strategy / "handoff.md").write_text(
        "XBEN-007 remains manual. Nearby notes mention headless_xss_ssrf, ssti, no-flag, and crash.",
        encoding="utf-8",
    )
    source_triage = tmp_path / "source-triage.jsonl"
    source_triage.write_text(
        json.dumps(
            {
                "chain_depth": 0,
                "coverage_bucket": "unknown_untriaged",
                "triage_status": "needs_manual_source_review",
                "vuln_class": "unknown_untriaged",
                "winning_rule_id": "",
                "xben_id": "XBEN-007",
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    rows = build_matrix(
        challenge_count=7,
        validation_root=validation,
        triage_root=triage,
        strategy_root=strategy,
        source_triage_path=source_triage,
    )
    by_id = {row["xben_id"]: row for row in rows}

    assert by_id["XBEN-007"]["vuln_class"] == "unknown_untriaged"
    assert by_id["XBEN-007"]["class_evidence_source"] == (
        "E1 source triage needs_manual_source_review"
    )
    assert by_id["XBEN-007"]["evidence_paths"] == [str(source_triage)]
    assert by_id["XBEN-007"]["solve_status"] == "unknown_untriaged"


def test_xben_gap_matrix_summary_and_outputs(tmp_path):
    validation = tmp_path / "validation"
    triage = tmp_path / "triage"
    strategy = tmp_path / "strategy"
    validation.mkdir()
    triage.mkdir()
    strategy.mkdir()

    rows = build_matrix(
        challenge_count=68,
        validation_root=validation,
        triage_root=triage,
        strategy_root=strategy,
    )
    summary = summarize(rows)
    written = write_outputs(rows, tmp_path / "out")

    assert summary["challenge_count"] == 68
    assert any(
        item["coverage_bucket"] == "auth_logic_session_forgery"
        for item in summary["top_gap_buckets"]
    )
    assert any(
        item["coverage_bucket"] == "ssrf_internal_endpoint_recovery"
        for item in summary["targeted_coverage"]
    )
    assert any(
        item["coverage_bucket"] == "headless_xss_ssrf"
        and item["targeted_xben_ids"]
        for item in summary["targeted_coverage"]
    )
    headless_rows = [row for row in rows if row["coverage_bucket"] == "headless_xss_ssrf"]
    assert headless_rows
    assert all(row["has_env"] is True and row["has_teacher_demo"] is True for row in headless_rows)
    blind_rows = [
        row for row in rows if row["coverage_bucket"] == "blind_command_injection_filter_bypass"
    ]
    assert blind_rows
    assert all(row["has_env"] is True and row["has_teacher_demo"] is True for row in blind_rows)
    command_rows = [row for row in rows if row["coverage_bucket"] == "command_injection"]
    assert command_rows
    assert all(row["has_env"] is True and row["has_teacher_demo"] is True for row in command_rows)
    assert written["files"]["matrix"].endswith(".jsonl")
