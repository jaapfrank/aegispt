import json

from scripts.training.build_xben_triage_backlog_iter10 import (
    build_backlog,
    load_matrix,
    write_outputs,
)


def row(
    xben_id,
    vuln_class,
    *,
    evidence_paths=None,
    has_env=False,
    has_solve=False,
    has_teacher_demo=False,
    solve_status="attempted_no_solve",
):
    return {
        "coverage_bucket": vuln_class,
        "evidence_paths": evidence_paths or [],
        "has_env": has_env,
        "has_solve": has_solve,
        "has_teacher_demo": has_teacher_demo,
        "solve_status": solve_status,
        "vuln_class": vuln_class,
        "xben_id": xben_id,
    }


def test_xben_triage_backlog_keeps_unknown_rows_unlabeled():
    rows = [
        row("XBEN-001", "ssti", has_env=True, has_solve=True, has_teacher_demo=True, solve_status="solved"),
        row("XBEN-002", "unknown_untriaged", evidence_paths=["docs/triage/xben002.md"]),
        row("XBEN-003", "command_injection", has_env=True, has_teacher_demo=False),
        row("XBEN-004", "headless_xss_ssrf", has_env=True, has_teacher_demo=True),
    ]

    backlog = build_backlog(rows)
    by_id = {item["xben_id"]: item for item in backlog["items"]}

    assert "XBEN-001" not in by_id
    assert by_id["XBEN-002"]["lane"] == "source_triage_required"
    assert by_id["XBEN-002"]["current_vuln_class"] == "unknown_untriaged"
    assert by_id["XBEN-002"]["label_policy"] == "do_not_infer_labels_from_neighbors"
    assert by_id["XBEN-002"]["neighbor_context_not_label"]
    assert by_id["XBEN-003"]["lane"] == "known_gap_needs_data"
    assert by_id["XBEN-004"]["lane"] == "covered_needs_rollout_eval"


def test_xben_triage_backlog_writes_json_jsonl_and_summary(tmp_path):
    rows = [
        row("XBEN-001", "unknown_untriaged"),
        row("XBEN-002", "auth_logic_session_forgery", has_env=True, has_teacher_demo=True),
    ]
    backlog = build_backlog(rows)
    summary = write_outputs(backlog, tmp_path)
    reloaded = json.loads((tmp_path / "aegispt_xben_triage_backlog_iter10.json").read_text())

    assert summary["item_count"] == 2
    assert summary["source_triage_required_count"] == 1
    assert reloaded["policy"]["unknown_rows_are_not_labeled"] is True
    assert (tmp_path / "aegispt_xben_triage_backlog_iter10.jsonl").exists()
    assert (tmp_path / "aegispt_xben_triage_backlog_iter10_summary.md").exists()


def test_xben_triage_backlog_loads_real_matrix():
    rows = load_matrix()
    backlog = build_backlog(rows)

    assert backlog["stats"]["item_count"] >= 1
    assert all(
        item["current_vuln_class"] == "unknown_untriaged"
        for item in backlog["items"]
        if item["lane"] == "source_triage_required"
    )
