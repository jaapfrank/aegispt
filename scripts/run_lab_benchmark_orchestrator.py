#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import sys
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.run_validation_matrix import normalize_findings, write_json  # noqa: E402

DEFAULT_CATALOG = REPO_ROOT / "scripts" / "validation" / "benchmark_coverage_expected.json"
DEFAULT_RESULTS_FILE = REPO_ROOT / "codex" / "results" / "lab-benchmark-orchestrator-latest.json"
DEFAULT_MARKDOWN_FILE = REPO_ROOT / "codex" / "results" / "lab-benchmark-orchestrator-latest.md"
ORCHESTRATOR_VERSION = "lab-benchmark-orchestrator-v1"
SAFE_HOSTS = {"127.0.0.1", "localhost"}


def load_catalog(path: str | Path = DEFAULT_CATALOG) -> dict[str, Any]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("benchmark catalog must be a JSON object")
    return payload


def lab_benchmarks(catalog: dict[str, Any]) -> list[dict[str, Any]]:
    orchestrator = catalog.get("lab_orchestrator")
    if isinstance(orchestrator, dict) and isinstance(orchestrator.get("benchmarks"), list):
        return [deepcopy(item) for item in orchestrator["benchmarks"] if isinstance(item, dict)]
    return [_legacy_benchmark_to_lab(item) for item in catalog.get("benchmarks", []) if isinstance(item, dict)]


def select_benchmarks(catalog: dict[str, Any], requested: list[str] | None = None) -> list[dict[str, Any]]:
    benchmarks = lab_benchmarks(catalog)
    if not requested:
        return benchmarks
    wanted = set(requested)
    selected = [item for item in benchmarks if item.get("id") in wanted]
    missing = wanted.difference({item.get("id") for item in selected})
    if missing:
        raise ValueError(f"Unknown lab benchmark id(s): {', '.join(sorted(missing))}")
    return selected


def load_actual_results(path: str | Path | None) -> dict[str, Any]:
    if path is None:
        return {"benchmarks": []}
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("actual results payload must be a JSON object")
    return payload


def build_orchestrator_report(
    *,
    catalog: dict[str, Any],
    requested: list[str] | None = None,
    dry_run: bool = True,
    actual_results: dict[str, Any] | None = None,
) -> dict[str, Any]:
    benchmarks = select_benchmarks(catalog, requested)
    actual_by_id = _actual_by_benchmark_id(actual_results or {})
    benchmark_results = [
        evaluate_benchmark(benchmark, actual_by_id.get(str(benchmark.get("id"))), dry_run=dry_run)
        for benchmark in benchmarks
    ]
    status_counts: dict[str, int] = {}
    for result in benchmark_results:
        status = str(result.get("status") or "unknown")
        status_counts[status] = status_counts.get(status, 0) + 1
    expected_count = sum(int(result["counts"]["expected"]) for result in benchmark_results)
    found_count = sum(int(result["counts"]["found"]) for result in benchmark_results)
    gap_count = sum(int(result["counts"]["gaps"]) for result in benchmark_results)
    return {
        "schema_version": 1,
        "orchestrator_version": ORCHESTRATOR_VERSION,
        "matrix_id": catalog.get("matrix_id"),
        "generated_at": datetime.now(tz=UTC).isoformat(),
        "mode": "dry-run" if dry_run else "collected-evidence",
        "status": "dry_run_ready" if dry_run else ("completed" if gap_count == 0 else "completed_with_gaps"),
        "execution_contract": {
            "live_target_actions_performed": False,
            "launches_docker_containers": False,
            "public_internet_targets_allowed": False,
            "adds_exploit_capability": False,
            "dispatches_work": False,
            "mutates_scope": False,
            "mutates_approvals": False,
            "runtime_self_modification": False,
        },
        "summary": {
            "benchmarks": len(benchmark_results),
            "status_counts": status_counts,
            "expected_issues": expected_count,
            "found_issues": found_count,
            "gap_records": gap_count,
            "coverage_pct": None if dry_run or expected_count == 0 else round((found_count / expected_count) * 100, 2),
        },
        "benchmarks": benchmark_results,
        "gap_records": [
            gap
            for result in benchmark_results
            for gap in result.get("gap_records", [])
            if isinstance(gap, dict)
        ],
    }


def evaluate_benchmark(benchmark: dict[str, Any], actual: dict[str, Any] | None, *, dry_run: bool) -> dict[str, Any]:
    target = _safe_dict(benchmark.get("target"))
    policy_gaps = _target_policy_gaps(target)
    expected_issues = [item for item in benchmark.get("expected_issues", []) if isinstance(item, dict)]
    actual = _safe_dict(actual)
    findings = normalize_findings(actual.get("findings") or [])
    evidence_ids = collect_evidence_ids(actual)
    issue_results = [
        evaluate_issue(issue, findings=findings, evidence_ids=evidence_ids, dry_run=dry_run)
        for issue in expected_issues
    ]
    found_count = sum(1 for issue in issue_results if issue["status"] == "found")
    gap_records = [
        {**gap, "benchmark_id": gap.get("benchmark_id") or benchmark.get("id")}
        for issue in issue_results
        for gap in issue.get("gap_records", [])
        if isinstance(gap, dict)
    ]
    if dry_run:
        live_status = "not_executed_live_required"
        status = "dry_run_ready" if not policy_gaps else "blocked"
    else:
        live_status = "collected_evidence_loaded"
        status = "completed" if not gap_records and not policy_gaps else "completed_with_gaps"
    return {
        "benchmark_id": benchmark.get("id"),
        "benchmark_name": benchmark.get("name"),
        "status": status,
        "target": target,
        "safe_allowed_proof_types": list(benchmark.get("safe_allowed_proof_types") or []),
        "required_evidence": list(benchmark.get("required_evidence") or []),
        "live_required_check": {
            "status": live_status,
            "reason": (
                "Dry-run mode validates catalog, evidence contract, and expected-vs-actual shape without live lab actions."
                if dry_run
                else "Actual results were loaded from a supplied evidence file; no live lab actions were launched by this script."
            ),
            "operator_next_step": (
                "Run the lab fixture separately on loopback, collect AegisPT run evidence, then rerun with --actual-results."
                if dry_run
                else "Review gap records before making any support claim."
            ),
        },
        "counts": {
            "expected": len(issue_results),
            "found": found_count,
            "missed": sum(1 for issue in issue_results if issue["status"] == "missed"),
            "not_evaluated": sum(1 for issue in issue_results if issue["status"] == "not_evaluated"),
            "gaps": len(gap_records) + len(policy_gaps),
            "actual_findings": len(findings),
        },
        "evidence_ids": evidence_ids,
        "coverage_truth": _actual_section_status(actual.get("coverage_truth"), "coverage_truth"),
        "report_evidence": _actual_section_status(actual.get("reports"), "reports"),
        "runner_decisions": _actual_section_status(actual.get("runner_decisions"), "runner_decisions"),
        "expected_vs_actual": issue_results,
        "unsupported_gaps": list(benchmark.get("unsupported_gaps") or []),
        "policy_gaps": policy_gaps,
        "gap_records": [
            *gap_records,
            *[
                {
                    "benchmark_id": benchmark.get("id"),
                    "issue_id": None,
                    "gap_type": "target_policy",
                    "reason": gap,
                    "safest_next_step": "Keep benchmark execution on loopback or explicitly authorized lab infrastructure.",
                }
                for gap in policy_gaps
            ],
        ],
    }


def evaluate_issue(
    issue: dict[str, Any],
    *,
    findings: list[dict[str, Any]],
    evidence_ids: dict[str, list[str]],
    dry_run: bool,
) -> dict[str, Any]:
    matches = [
        finding
        for finding in findings
        if _finding_matches_issue(issue, finding)
    ]
    missing_evidence = [
        evidence_key
        for evidence_key in list(issue.get("required_evidence") or [])
        if not evidence_ids.get(str(evidence_key))
    ]
    if dry_run:
        status = "not_evaluated"
    elif matches and not missing_evidence:
        status = "found"
    elif matches:
        status = "evidence_incomplete"
    else:
        status = "missed"
    gap_records: list[dict[str, Any]] = []
    if dry_run:
        gap_records.append(
            {
                "benchmark_id": None,
                "issue_id": issue.get("id"),
                "gap_type": "live_lab_not_executed",
                "reason": "Expected issue was not evaluated because dry-run mode performs no live target actions.",
                "safest_next_step": "Collect run, task, finding, coverage truth, report, and runner-decision evidence from an approved local lab.",
            }
        )
    elif status in {"missed", "evidence_incomplete"}:
        gap_records.append(
            {
                "benchmark_id": None,
                "issue_id": issue.get("id"),
                "gap_type": status,
                "reason": (
                    "No matching finding was present in collected evidence."
                    if status == "missed"
                    else f"Matching finding exists but required evidence is missing: {', '.join(missing_evidence)}"
                ),
                "safest_next_step": "Review runner coverage and evidence collection before claiming support.",
            }
        )
    return {
        "issue_id": issue.get("id"),
        "family": issue.get("family"),
        "expected_severity": issue.get("expected_severity"),
        "safe_allowed_proof_type": issue.get("safe_allowed_proof_type"),
        "required_evidence": list(issue.get("required_evidence") or []),
        "status": status,
        "actual_detection": bool(matches),
        "matching_finding_ids": [
            str(_safe_dict(finding.get("raw")).get("id") or _safe_dict(finding.get("raw")).get("finding_id") or "")
            for finding in matches
            if str(_safe_dict(finding.get("raw")).get("id") or _safe_dict(finding.get("raw")).get("finding_id") or "")
        ],
        "matching_finding_titles": [finding.get("title") for finding in matches],
        "missing_evidence": missing_evidence,
        "unsupported_gaps": list(issue.get("unsupported_gaps") or []),
        "gap_records": gap_records,
    }


def collect_evidence_ids(actual: dict[str, Any]) -> dict[str, list[str]]:
    evidence: dict[str, set[str]] = {}

    def add(key: str, value: Any) -> None:
        text = str(value or "").strip()
        if text:
            evidence.setdefault(key, set()).add(text)

    add("run_id", actual.get("run_id"))
    for task in _as_list(actual.get("tasks")):
        if isinstance(task, dict):
            add("task_output_id", task.get("id") or task.get("task_id"))
    for finding in _as_list(actual.get("findings")):
        if isinstance(finding, dict):
            add("finding_id", finding.get("id") or finding.get("finding_id"))
            add("finding_evidence_ref", finding.get("evidence_ref"))
            add("canary_evidence_ref", finding.get("canary_evidence_ref"))
            add("redacted_session_evidence", finding.get("redacted_session_evidence"))
            add("auth_context_ref", finding.get("auth_context_ref"))
            add("rationale_ledger_id", finding.get("rationale_ledger_id"))
    if isinstance(actual.get("coverage_truth"), dict):
        add("coverage_truth", actual["coverage_truth"].get("run_id") or "coverage_truth")
    for report in _as_list(actual.get("reports")):
        if isinstance(report, dict):
            variant = str(report.get("variant") or "").strip()
            add("report_variant:technical" if variant == "technical" else "report_variant", report.get("id") or variant)
    for decision in _as_list(actual.get("runner_decisions")):
        if isinstance(decision, dict):
            add("runner_decision", decision.get("id") or decision.get("runner") or decision.get("decision"))
            if decision.get("approval_gate"):
                add("approval_gate", decision.get("approval_gate"))
    return {key: sorted(values) for key, values in sorted(evidence.items())}


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Lab Benchmark Orchestrator",
        "",
        f"- Generated: {report.get('generated_at')}",
        f"- Mode: {report.get('mode')}",
        f"- Status: {report.get('status')}",
        f"- Benchmarks: {report['summary']['benchmarks']}",
        f"- Expected issues: {report['summary']['expected_issues']}",
        f"- Gap records: {report['summary']['gap_records']}",
        "",
        "## Boundaries",
        "",
        "- Dry-run is the default and performs no live target actions.",
        "- Docker containers are not launched by this orchestrator.",
        "- Public internet targets are not allowed by default.",
        "- Expected-vs-actual gaps remain gap records, not hidden success claims.",
        "",
        "## Benchmarks",
        "",
    ]
    for benchmark in report.get("benchmarks", []):
        lines.extend(
            [
                f"### {benchmark.get('benchmark_name')} (`{benchmark.get('benchmark_id')}`)",
                "",
                f"- Status: {benchmark.get('status')}",
                f"- Target: {benchmark.get('target', {}).get('default_url')}",
                f"- Live-required check: {benchmark.get('live_required_check', {}).get('status')}",
                f"- Expected: {benchmark.get('counts', {}).get('expected')}",
                f"- Found: {benchmark.get('counts', {}).get('found')}",
                f"- Gaps: {benchmark.get('counts', {}).get('gaps')}",
                f"- Unsupported benchmark gaps: {', '.join(benchmark.get('unsupported_gaps') or []) or 'none'}",
                "",
                "| Issue | Family | Status | Safe Proof | Missing Evidence | Unsupported Gaps |",
                "| --- | --- | --- | --- | --- | --- |",
            ]
        )
        for issue in benchmark.get("expected_vs_actual", []):
            missing = ", ".join(issue.get("missing_evidence") or []) or "none"
            unsupported = ", ".join(issue.get("unsupported_gaps") or []) or "none"
            lines.append(
                f"| `{issue.get('issue_id')}` | {issue.get('family')} | {issue.get('status')} | "
                f"{issue.get('safe_allowed_proof_type')} | {missing} | {unsupported} |"
            )
        lines.append("")
    if report.get("gap_records"):
        lines.extend(["## Gap Records", ""])
        for gap in report["gap_records"]:
            lines.append(
                f"- `{gap.get('issue_id') or gap.get('benchmark_id')}`: {gap.get('gap_type')} - {gap.get('reason')}"
            )
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def write_markdown(path: str | Path, report: dict[str, Any]) -> Path:
    result_path = Path(path)
    result_path.parent.mkdir(parents=True, exist_ok=True)
    result_path.write_text(render_markdown(report), encoding="utf-8")
    return result_path


def _legacy_benchmark_to_lab(item: dict[str, Any]) -> dict[str, Any]:
    target = _safe_dict(item.get("target"))
    return {
        "id": item.get("id"),
        "name": item.get("name"),
        "target": {
            "kind": "local_docker_lab",
            "image": target.get("image"),
            "default_url": f"http://127.0.0.1:{target.get('container_port')}{target.get('url_path') or '/'}",
            "allowed_hosts": ["127.0.0.1", "localhost"],
            "public_target_allowed": False,
            "fixture_setup_required": True,
        },
        "safe_allowed_proof_types": ["passive_observation", "controlled_canary_evidence"],
        "required_evidence": ["run_id", "task_output_id", "coverage_truth", "report_variant:technical", "runner_decision"],
        "expected_issues": [
            {
                "id": vulnerability.get("id"),
                "family": vulnerability.get("family"),
                "expected_severity": vulnerability.get("expected_severity"),
                "title_pattern": vulnerability.get("title_pattern"),
                "safe_allowed_proof_type": "controlled_canary_evidence",
                "required_evidence": ["finding_id", "finding_evidence_ref", "task_output_id"],
                "unsupported_gaps": [vulnerability.get("gap_task_ref")] if vulnerability.get("gap_task_ref") else [],
            }
            for vulnerability in item.get("expected_vulnerabilities", [])
            if isinstance(vulnerability, dict)
        ],
        "unsupported_gaps": ["legacy catalog entry adapted for orchestrator use"],
    }


def _actual_by_benchmark_id(payload: dict[str, Any]) -> dict[str, dict[str, Any]]:
    if isinstance(payload.get("benchmarks"), list):
        return {
            str(item.get("benchmark_id") or item.get("id")): item
            for item in payload["benchmarks"]
            if isinstance(item, dict) and (item.get("benchmark_id") or item.get("id"))
        }
    benchmark_id = payload.get("benchmark_id") or payload.get("id")
    return {str(benchmark_id): payload} if benchmark_id else {}


def _finding_matches_issue(issue: dict[str, Any], finding: dict[str, Any]) -> bool:
    title_pattern = str(issue.get("title_pattern") or "")
    severity = str(issue.get("expected_severity") or "")
    title_ok = not title_pattern or re.search(title_pattern, str(finding.get("title") or "")) is not None
    severity_ok = not severity or re.search(severity, str(finding.get("severity") or ""), flags=re.IGNORECASE) is not None
    return title_ok and severity_ok


def _target_policy_gaps(target: dict[str, Any]) -> list[str]:
    gaps: list[str] = []
    if target.get("public_target_allowed") is not False:
        gaps.append("target does not explicitly disable public internet execution")
    allowed_hosts = {str(host).strip().lower() for host in _as_list(target.get("allowed_hosts"))}
    if not allowed_hosts or not allowed_hosts.issubset(SAFE_HOSTS):
        gaps.append("target allowed_hosts must be limited to loopback hosts for default lab benchmarks")
    default_url = str(target.get("default_url") or "")
    if default_url and not any(host in default_url for host in ("127.0.0.1", "localhost")):
        gaps.append("target default_url must be loopback for default lab benchmarks")
    if target.get("fixture_setup_required") is not True:
        gaps.append("target must mark fixture_setup_required=true")
    return gaps


def _actual_section_status(value: Any, section_name: str) -> dict[str, Any]:
    if isinstance(value, dict):
        return {"present": True, "section": section_name, "summary": value}
    if isinstance(value, list):
        return {"present": bool(value), "section": section_name, "count": len(value)}
    return {"present": False, "section": section_name, "gap": f"{section_name} not supplied"}


def _safe_dict(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, dict) else {}


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return [value]


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build governed local-lab benchmark expected-vs-actual evidence.")
    parser.add_argument("--catalog", default=str(DEFAULT_CATALOG), help="Benchmark catalog JSON.")
    parser.add_argument("--benchmark", action="append", help="Benchmark id to include. May be repeated.")
    parser.add_argument("--dry-run", action="store_true", help="Validate catalog and produce non-executing gap records.")
    parser.add_argument("--actual-results", help="Optional collected AegisPT benchmark evidence JSON.")
    parser.add_argument("--results-file", default=str(DEFAULT_RESULTS_FILE), help="Machine-readable output JSON.")
    parser.add_argument("--markdown-file", default=str(DEFAULT_MARKDOWN_FILE), help="Human-readable Markdown output.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    dry_run = bool(args.dry_run or not args.actual_results)
    catalog = load_catalog(args.catalog)
    actual_results = load_actual_results(args.actual_results)
    report = build_orchestrator_report(
        catalog=catalog,
        requested=args.benchmark,
        dry_run=dry_run,
        actual_results=actual_results,
    )
    results_path = write_json(args.results_file, report)
    markdown_path = write_markdown(args.markdown_file, report)
    print(
        json.dumps(
            {
                "status": report["status"],
                "mode": report["mode"],
                "summary": report["summary"],
                "results_file": str(results_path.resolve()),
                "markdown_file": str(markdown_path.resolve()),
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
