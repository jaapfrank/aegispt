from __future__ import annotations

from scripts.run_lab_benchmark_orchestrator import (
    build_orchestrator_report,
    lab_benchmarks,
    load_catalog,
    render_markdown,
)


def test_lab_catalog_contains_local_loopback_benchmarks_and_evidence_contract() -> None:
    catalog = load_catalog()
    benchmarks = {item["id"]: item for item in lab_benchmarks(catalog)}

    assert set(benchmarks) == {"gruyere-local", "webgoat-local", "dvwa-local", "dvga-local"}
    for benchmark in benchmarks.values():
        target = benchmark["target"]
        assert target["public_target_allowed"] is False
        assert target["fixture_setup_required"] is True
        assert set(target["allowed_hosts"]).issubset({"127.0.0.1", "localhost"})
        assert "127.0.0.1" in target["default_url"] or "localhost" in target["default_url"]
        assert "coverage_truth" in benchmark["required_evidence"]
        assert "runner_decision" in benchmark["required_evidence"]
        assert benchmark["safe_allowed_proof_types"]
        assert benchmark["unsupported_gaps"]
        for issue in benchmark["expected_issues"]:
            assert issue["safe_allowed_proof_type"]
            assert issue["required_evidence"]
            assert issue["unsupported_gaps"]


def test_dry_run_records_live_required_gaps_without_execution() -> None:
    report = build_orchestrator_report(
        catalog=load_catalog(),
        requested=["gruyere-local"],
        dry_run=True,
    )

    assert report["mode"] == "dry-run"
    assert report["status"] == "dry_run_ready"
    assert report["execution_contract"]["live_target_actions_performed"] is False
    assert report["execution_contract"]["launches_docker_containers"] is False
    assert report["execution_contract"]["dispatches_work"] is False

    benchmark = report["benchmarks"][0]
    assert benchmark["status"] == "dry_run_ready"
    assert benchmark["live_required_check"]["status"] == "not_executed_live_required"
    assert benchmark["counts"]["expected"] == 3
    assert benchmark["counts"]["not_evaluated"] == 3
    assert all(issue["status"] == "not_evaluated" for issue in benchmark["expected_vs_actual"])
    assert {gap["gap_type"] for gap in report["gap_records"]} == {"live_lab_not_executed"}
    assert all(gap["benchmark_id"] == "gruyere-local" for gap in report["gap_records"])


def test_collected_evidence_compares_expected_vs_actual_and_records_gaps() -> None:
    actual_results = {
        "benchmark_id": "dvga-local",
        "run_id": "run-dvga-1",
        "tasks": [{"id": "task-graphql-introspection"}],
        "coverage_truth": {"run_id": "run-dvga-1", "stop_condition": "complete-with-gaps"},
        "reports": [{"id": "report-technical-dvga", "variant": "technical"}],
        "runner_decisions": [{"id": "decision-graphql", "runner": "graphql-schema-probe"}],
        "findings": [
            {
                "id": "finding-graphql-introspection",
                "title": "GraphQL introspection schema exposure",
                "severity": "medium",
                "evidence_ref": "artifact-schema-summary",
            },
            {
                "id": "finding-graphql-injection",
                "title": "GraphQL injection canary observed",
                "severity": "high",
                "canary_evidence_ref": "artifact-canary",
            },
        ],
    }

    report = build_orchestrator_report(
        catalog=load_catalog(),
        requested=["dvga-local"],
        dry_run=False,
        actual_results=actual_results,
    )

    benchmark = report["benchmarks"][0]
    issues = {issue["issue_id"]: issue for issue in benchmark["expected_vs_actual"]}

    assert report["mode"] == "collected-evidence"
    assert report["execution_contract"]["live_target_actions_performed"] is False
    assert benchmark["counts"]["found"] == 2
    assert benchmark["counts"]["missed"] == 1
    assert benchmark["evidence_ids"]["run_id"] == ["run-dvga-1"]
    assert benchmark["evidence_ids"]["report_variant:technical"] == ["report-technical-dvga"]
    assert issues["dvga-graphql-introspection"]["status"] == "found"
    assert issues["dvga-graphql-injection-family"]["status"] == "found"
    assert issues["dvga-broken-access-control"]["status"] == "missed"
    assert issues["dvga-broken-access-control"]["unsupported_gaps"]
    assert any(gap["gap_type"] == "missed" for gap in report["gap_records"])


def test_markdown_output_lists_boundaries_evidence_and_unsupported_gaps() -> None:
    report = build_orchestrator_report(
        catalog=load_catalog(),
        requested=["webgoat-local"],
        dry_run=True,
    )
    markdown = render_markdown(report)

    assert "Dry-run is the default and performs no live target actions." in markdown
    assert "Docker containers are not launched by this orchestrator." in markdown
    assert "webgoat-sql-injection-family" in markdown
    assert "not_executed_live_required" in markdown
    assert "live_lab_not_executed" in markdown
    assert "database extraction is not accepted as benchmark proof" in markdown
