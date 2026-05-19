from __future__ import annotations

from scripts.run_benchmark_coverage import evaluate_benchmark, load_json


def test_benchmark_catalog_contains_expected_gruyere_and_webgoat_counts() -> None:
    catalog = load_json("scripts/validation/benchmark_coverage_expected.json")
    benchmarks = {item["id"]: item for item in catalog["benchmarks"]}

    assert set(benchmarks) == {"gruyere-local", "webgoat-local"}
    assert len(benchmarks["gruyere-local"]["expected_vulnerabilities"]) == 20
    assert len(benchmarks["webgoat-local"]["expected_vulnerabilities"]) == 32
    assert sum(len(item["expected_vulnerabilities"]) for item in benchmarks.values()) == 52
    assert benchmarks["gruyere-local"]["target"]["image"] == "karthequian/gruyere:latest"
    assert benchmarks["webgoat-local"]["target"]["image"] == "webgoat/webgoat:latest"


def test_benchmark_evaluation_records_detected_and_gap_rows() -> None:
    benchmark = {
        "id": "sample",
        "name": "Sample",
        "scan_profiles": ["active-web-zap-active"],
        "expected_vulnerabilities": [
            {
                "id": "sample-sqli",
                "family": "sql injection",
                "expected_severity": "high",
                "title_pattern": "(?i)sql.*injection",
                "gap_task_ref": "codex/tasks/backlog-211-pentest-depth-additional-tools.json",
            },
            {
                "id": "sample-xxe",
                "family": "xxe",
                "expected_severity": "high",
                "title_pattern": "(?i)xml external entity",
                "gap_task_ref": "codex/tasks/backlog-214-xxe-injection-runner.json",
            },
        ],
    }
    actual_findings = [
        {
            "title": "SQL Injection",
            "severity": "high",
            "tool": "zap",
            "target_id": "http://127.0.0.1:8008/",
        }
    ]

    result = evaluate_benchmark(
        benchmark,
        actual_findings,
        execution={"profiles": [{"profile": "active-web-zap-active", "run_status": "completed"}]},
    )

    assert result["coverage_pct"] == 50.0
    assert result["counts"]["detected"] == 1
    assert result["counts"]["missed"] == 1
    assert result["vulnerabilities"][0]["actual_detection"] is True
    assert result["vulnerabilities"][0]["tool_used"] == ["zap"]
    assert result["gaps"][0]["vulnerability_id"] == "sample-xxe"
