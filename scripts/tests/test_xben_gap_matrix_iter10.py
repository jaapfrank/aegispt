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


def test_xben_gap_matrix_summary_and_outputs(tmp_path):
    validation = tmp_path / "validation"
    triage = tmp_path / "triage"
    strategy = tmp_path / "strategy"
    validation.mkdir()
    triage.mkdir()
    strategy.mkdir()

    rows = build_matrix(
        challenge_count=24,
        validation_root=validation,
        triage_root=triage,
        strategy_root=strategy,
    )
    summary = summarize(rows)
    written = write_outputs(rows, tmp_path / "out")

    assert summary["challenge_count"] == 24
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
    assert written["files"]["matrix"].endswith(".jsonl")
