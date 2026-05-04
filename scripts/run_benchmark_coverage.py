#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.run_validation_matrix import (  # noqa: E402
    execute_aegispt_scenario,
    finding_matches,
    load_json,
    normalize_findings,
    write_json,
)

DEFAULT_CATALOG = REPO_ROOT / "scripts" / "validation" / "benchmark_coverage_expected.json"
DEFAULT_RESULTS_FILE = REPO_ROOT / "codex" / "results" / "benchmark-coverage-latest.json"
DEFAULT_COVERAGE_REPORT = REPO_ROOT / "codex" / "results" / "coverage_report.json"
PROFILE_TOOL_HINTS = {
    "passive-web-nuclei-audit": "nuclei",
    "active-web-safe": "zap",
    "active-web-zap-active": "zap",
}


def select_benchmarks(catalog: dict[str, Any], requested: list[str] | None) -> list[dict[str, Any]]:
    benchmarks = [deepcopy(item) for item in catalog.get("benchmarks", [])]
    if not requested:
        return benchmarks
    wanted = set(requested)
    selected = [item for item in benchmarks if item.get("id") in wanted]
    missing = wanted.difference({item.get("id") for item in selected})
    if missing:
        raise ValueError(f"Unknown benchmark id(s): {', '.join(sorted(missing))}")
    return selected


def _scenario_for_profile(benchmark: dict[str, Any], profile: str) -> dict[str, Any]:
    return {
        "id": f"{benchmark['id']}-{profile}",
        "name": f"{benchmark.get('name', benchmark['id'])} · {profile}",
        "target": deepcopy(benchmark["target"]),
        "assessment_type": benchmark.get("assessment_type") or "Website / Web App",
        "scan_profile": profile,
        "modules": list(benchmark.get("modules") or []),
        "minimum_coverage_pct": 0,
        "expected_findings": [],
        "forbidden_findings": [],
    }


def execute_benchmark(
    benchmark: dict[str, Any],
    *,
    base_url: str,
    actor: str,
    wait_seconds: int,
    poll_interval: float,
) -> dict[str, Any]:
    profile_results: list[dict[str, Any]] = []
    all_findings: list[dict[str, Any]] = []
    for profile in benchmark.get("scan_profiles") or []:
        scenario = _scenario_for_profile(benchmark, str(profile))
        execution = execute_aegispt_scenario(
            scenario,
            base_url=base_url,
            actor=actor,
            wait_seconds=wait_seconds,
            poll_interval=poll_interval,
        )
        findings = execution.get("findings") if isinstance(execution.get("findings"), list) else []
        for finding in findings:
            annotated = deepcopy(finding)
            annotated.setdefault("source_tool", PROFILE_TOOL_HINTS.get(str(profile), str(profile)))
            annotated.setdefault("benchmark_profile", profile)
            all_findings.append(annotated)
        profile_results.append(
            {
                "profile": profile,
                "run_id": execution.get("run_id"),
                "run_status": execution.get("run_status"),
                "task_count": execution.get("task_count"),
                "finding_count": len(findings),
                "terminal": bool(execution.get("terminal")),
            }
        )
    return {"profiles": profile_results, "findings": all_findings}


def evaluate_benchmark(
    benchmark: dict[str, Any],
    actual_findings_payload: Any,
    *,
    execution: dict[str, Any] | None = None,
) -> dict[str, Any]:
    findings = normalize_findings(actual_findings_payload)
    rows: list[dict[str, Any]] = []

    for expectation in benchmark.get("expected_vulnerabilities") or []:
        matcher = {
            "id": expectation.get("id"),
            "title_pattern": expectation.get("title_pattern"),
            "tool": expectation.get("tool"),
            "target_pattern": expectation.get("target_pattern"),
            "wstg": expectation.get("wstg"),
        }
        matched_indexes = [
            index
            for index, finding in enumerate(findings)
            if finding_matches(matcher, finding)
        ]
        matched_findings = [findings[index] for index in matched_indexes]
        rows.append(
            {
                "vulnerability_id": expectation.get("id"),
                "family": expectation.get("family"),
                "expected_detection": True,
                "actual_detection": bool(matched_indexes),
                "expected_severity": expectation.get("expected_severity"),
                "actual_severities": sorted({item.get("severity") for item in matched_findings if item.get("severity")}),
                "tool_used": sorted({item.get("tool") for item in matched_findings if item.get("tool")}),
                "matching_finding_titles": [item.get("title") for item in matched_findings],
                "gap_task_ref": expectation.get("gap_task_ref"),
                "notes": (
                    "Detected by existing AegisPT output."
                    if matched_indexes
                    else "No matching finding from existing passive/active benchmark runs."
                ),
            }
        )

    expected_count = len(rows)
    detected_count = sum(1 for row in rows if row["actual_detection"])
    coverage_pct = 100.0 if expected_count == 0 else round((detected_count / expected_count) * 100, 2)
    return {
        "benchmark_id": benchmark.get("id"),
        "benchmark_name": benchmark.get("name"),
        "target_image": benchmark.get("target", {}).get("image"),
        "scan_profiles": list(benchmark.get("scan_profiles") or []),
        "status": "completed" if execution is not None else "not_run",
        "coverage_pct": coverage_pct,
        "counts": {
            "expected": expected_count,
            "detected": detected_count,
            "missed": expected_count - detected_count,
            "actual_findings": len(findings),
        },
        "execution": execution or {},
        "vulnerabilities": rows,
        "gaps": [row for row in rows if not row["actual_detection"]],
    }


def build_report(args: argparse.Namespace) -> dict[str, Any]:
    catalog = load_json(args.catalog)
    benchmarks = select_benchmarks(catalog, args.benchmark)
    benchmark_results: list[dict[str, Any]] = []

    for benchmark in benchmarks:
        if args.execute:
            if not args.base_url:
                raise ValueError("--base-url is required with --execute")
            execution = execute_benchmark(
                benchmark,
                base_url=args.base_url,
                actor=args.actor,
                wait_seconds=args.wait_seconds,
                poll_interval=args.poll_interval,
            )
            benchmark_results.append(
                evaluate_benchmark(
                    benchmark,
                    execution["findings"],
                    execution={"profiles": execution["profiles"]},
                )
            )
        else:
            benchmark_results.append(evaluate_benchmark(benchmark, [], execution=None))

    expected_total = sum(item["counts"]["expected"] for item in benchmark_results)
    detected_total = sum(item["counts"]["detected"] for item in benchmark_results)
    missed_total = sum(item["counts"]["missed"] for item in benchmark_results)
    return {
        "schema_version": 1,
        "matrix_id": catalog.get("matrix_id"),
        "generated_at": datetime.now(tz=UTC).isoformat(),
        "mode": "execute" if args.execute else "catalog-only",
        "status": "completed" if args.execute else "not_run",
        "summary": {
            "benchmarks": len(benchmark_results),
            "expected": expected_total,
            "detected": detected_total,
            "missed": missed_total,
            "coverage_pct": 100.0 if expected_total == 0 else round((detected_total / expected_total) * 100, 2),
        },
        "benchmarks": benchmark_results,
        "gap_task_refs": sorted(
            {
                row["gap_task_ref"]
                for result in benchmark_results
                for row in result["gaps"]
                if row.get("gap_task_ref")
            }
        ),
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run Gruyere/WebGoat benchmark expected-vs-actual coverage.")
    parser.add_argument("--catalog", default=str(DEFAULT_CATALOG), help="Benchmark coverage catalog JSON.")
    parser.add_argument("--results-file", default=str(DEFAULT_RESULTS_FILE), help="Detailed result JSON path.")
    parser.add_argument("--coverage-report", default=str(DEFAULT_COVERAGE_REPORT), help="Compatibility coverage_report.json path.")
    parser.add_argument("--benchmark", action="append", help="Benchmark id to run. May be repeated.")
    parser.add_argument("--execute", action="store_true", help="Launch local Docker fixtures and run AegisPT via the API.")
    parser.add_argument("--base-url", help="AegisPT API base URL, required with --execute.")
    parser.add_argument("--actor", default="codex-benchmark-coverage", help="Actor id for AegisPT audit records.")
    parser.add_argument("--wait-seconds", type=int, default=600, help="Maximum wait for each AegisPT run.")
    parser.add_argument("--poll-interval", type=float, default=2.0, help="Polling interval while waiting for each run.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    payload = build_report(args)
    results_path = write_json(args.results_file, payload)
    coverage_path = write_json(args.coverage_report, payload)
    print(json.dumps({**payload, "results_file": str(results_path.resolve()), "coverage_report": str(coverage_path.resolve())}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
