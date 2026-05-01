#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import socket
import subprocess
import sys
import time
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

import httpx

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.acceptance_harness import (  # noqa: E402
    TERMINAL_RUN_STATUSES,
    build_allowlist_from_target,
    build_engagement_payload,
    build_inventory_seed_payload,
    build_run_configuration,
)
from scripts.run_acceptance_matrix import (  # noqa: E402
    api_headers,
    collect_task_details,
    grant_required_approvals,
    wait_for_terminal_run,
)

DEFAULT_CATALOG = REPO_ROOT / "scripts" / "validation" / "expected_findings.json"
DEFAULT_RESULTS_FILE = REPO_ROOT / "codex" / "results" / "validation-matrix-latest.json"
FALSE_POSITIVE_THRESHOLD_PCT = 10.0


@dataclass(frozen=True)
class MatchResult:
    expectation_id: str
    matched: bool
    finding_indexes: list[int]


def load_json(path: str | Path) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write_json(path: str | Path, payload: Any) -> Path:
    result_path = Path(path)
    result_path.parent.mkdir(parents=True, exist_ok=True)
    result_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result_path


def enabled_scenarios(catalog: dict[str, Any]) -> list[dict[str, Any]]:
    return [deepcopy(item) for item in catalog.get("scenarios", []) if item.get("enabled", True) is True]


def select_scenarios(catalog: dict[str, Any], requested: list[str] | None = None) -> list[dict[str, Any]]:
    scenarios = enabled_scenarios(catalog)
    if not requested:
        return scenarios
    wanted = set(requested)
    selected = [scenario for scenario in scenarios if scenario.get("id") in wanted]
    missing = wanted.difference({scenario.get("id") for scenario in selected})
    if missing:
        raise ValueError(f"Unknown or disabled validation scenarios: {', '.join(sorted(missing))}")
    return selected


def normalize_findings(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, dict):
        if isinstance(payload.get("findings"), list):
            raw_findings = payload["findings"]
        elif isinstance(payload.get("items"), list):
            raw_findings = payload["items"]
        elif isinstance(payload.get("data"), list):
            raw_findings = payload["data"]
        else:
            raw_findings = [payload]
    elif isinstance(payload, list):
        raw_findings = payload
    else:
        raw_findings = []

    normalized: list[dict[str, Any]] = []
    for item in raw_findings:
        if not isinstance(item, dict):
            continue
        target = (
            item.get("target_id")
            or item.get("target")
            or item.get("url")
            or item.get("asset")
            or item.get("host")
            or ""
        )
        tool = (
            item.get("tool")
            or item.get("tool_name")
            or item.get("source_tool")
            or item.get("scanner")
            or item.get("source")
            or ""
        )
        normalized.append(
            {
                "title": str(item.get("title") or item.get("name") or item.get("finding") or "").strip(),
                "severity": str(item.get("severity") or "").strip().lower(),
                "tool": str(tool).strip().lower(),
                "target": str(target).strip(),
                "wstg": str(item.get("wstg") or item.get("wstg_id") or "").strip(),
                "raw": item,
            }
        )
    return normalized


def _regex_matches(pattern: str | None, value: str) -> bool:
    if pattern is None or pattern == "":
        return True
    return re.search(pattern, value or "") is not None


def _severity_matches(expected: str | None, actual: str) -> bool:
    if not expected:
        return True
    return re.search(expected, actual or "", flags=re.IGNORECASE) is not None


def _tool_matches(expected: str | None, actual: str) -> bool:
    if not expected:
        return True
    return expected.lower() in (actual or "").lower()


def finding_matches(expectation: dict[str, Any], finding: dict[str, Any]) -> bool:
    return (
        _regex_matches(expectation.get("title_pattern"), finding.get("title", ""))
        and _severity_matches(expectation.get("severity"), finding.get("severity", ""))
        and _tool_matches(expectation.get("tool"), finding.get("tool", ""))
        and _regex_matches(expectation.get("target_pattern"), finding.get("target", ""))
        and _regex_matches(expectation.get("wstg"), finding.get("wstg", ""))
    )


def evaluate_scenario(
    scenario: dict[str, Any],
    actual_findings_payload: Any,
    *,
    false_positive_threshold_pct: float = FALSE_POSITIVE_THRESHOLD_PCT,
) -> dict[str, Any]:
    findings = normalize_findings(actual_findings_payload)
    expected = list(scenario.get("expected_findings") or [])
    forbidden = list(scenario.get("forbidden_findings") or [])

    expected_matches: list[MatchResult] = []
    matched_indexes: set[int] = set()
    for expectation in expected:
        indexes = [
            index
            for index, finding in enumerate(findings)
            if finding_matches(expectation, finding)
        ]
        matched_indexes.update(indexes)
        expected_matches.append(
            MatchResult(
                expectation_id=str(expectation.get("id") or expectation.get("title_pattern") or "expected"),
                matched=bool(indexes),
                finding_indexes=indexes,
            )
        )

    forbidden_matches: list[dict[str, Any]] = []
    for rule in forbidden:
        for index, finding in enumerate(findings):
            if finding_matches(rule, finding):
                forbidden_matches.append(
                    {
                        "rule_id": rule.get("id") or rule.get("title_pattern"),
                        "finding_index": index,
                        "finding_title": finding["title"],
                        "reason": rule.get("reason"),
                    }
                )

    expected_count = len(expected)
    found_count = sum(1 for item in expected_matches if item.matched)
    detection_rate = 100.0 if expected_count == 0 else round((found_count / expected_count) * 100, 2)
    unexpected_indexes = [
        index
        for index, finding in enumerate(findings)
        if index not in matched_indexes and not any(finding_matches(rule, finding) for rule in forbidden)
    ]
    false_positive_rate = 0.0 if not findings else round((len(unexpected_indexes) / len(findings)) * 100, 2)
    minimum_coverage = float(scenario.get("minimum_coverage_pct", 100))
    false_positive_threshold = float(scenario.get("false_positive_threshold_pct", false_positive_threshold_pct))
    passed = (
        detection_rate >= minimum_coverage
        and false_positive_rate <= false_positive_threshold
        and not forbidden_matches
    )

    return {
        "scenario_id": scenario.get("id"),
        "scenario_name": scenario.get("name"),
        "status": "passed" if passed else "failed",
        "detection_rate_pct": detection_rate,
        "false_positive_rate_pct": false_positive_rate,
        "minimum_coverage_pct": minimum_coverage,
        "false_positive_threshold_pct": false_positive_threshold,
        "counts": {
            "expected": expected_count,
            "expected_found": found_count,
            "actual_findings": len(findings),
            "unexpected_findings": len(unexpected_indexes),
            "forbidden_findings": len(forbidden_matches),
        },
        "missing_expected": [
            item.expectation_id for item in expected_matches if not item.matched
        ],
        "matched_expected": [
            {"id": item.expectation_id, "finding_indexes": item.finding_indexes}
            for item in expected_matches
            if item.matched
        ],
        "unexpected_findings": [
            {
                "finding_index": index,
                "title": findings[index]["title"],
                "severity": findings[index]["severity"],
                "target": findings[index]["target"],
            }
            for index in unexpected_indexes
        ],
        "forbidden_matches": forbidden_matches,
    }


def load_actual_findings(actual_findings_dir: str | Path, scenario_id: str) -> Any:
    directory = Path(actual_findings_dir)
    for suffix in (".json", ".findings.json"):
        candidate = directory / f"{scenario_id}{suffix}"
        if candidate.exists():
            return load_json(candidate)
    raise FileNotFoundError(f"No actual findings fixture found for scenario {scenario_id} in {directory}")


def _reserve_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _wait_for_http_ready(url: str, *, timeout_seconds: float) -> None:
    deadline = time.monotonic() + timeout_seconds
    last_error = "no response"
    with httpx.Client(timeout=5.0, follow_redirects=True) as client:
        while time.monotonic() < deadline:
            try:
                response = client.get(url)
                if response.status_code in {200, 201, 202, 204, 301, 302, 303, 307, 308, 401, 403}:
                    return
                last_error = f"HTTP {response.status_code}"
            except httpx.HTTPError as exc:
                last_error = str(exc)
            time.sleep(1.0)
    raise RuntimeError(f"Target {url} was not ready within {timeout_seconds:.0f}s ({last_error})")


@contextmanager
def docker_target(scenario: dict[str, Any]):
    target = scenario.get("target") or {}
    if target.get("type") != "docker":
        raise ValueError(f"Scenario {scenario.get('id')} does not define an executable Docker target")

    image = str(target["image"])
    container_port = int(target["container_port"])
    host = "127.0.0.1"
    host_port = _reserve_loopback_port()
    container_name = f"aegispt-validation-{uuid4().hex[:12]}"
    url_path = str(target.get("url_path") or "/")
    health_path = str(target.get("health_path") or url_path)
    base_url = f"http://{host}:{host_port}"
    target_url = f"{base_url}{url_path}"
    health_url = f"{base_url}{health_path}"

    subprocess.run(["docker", "rm", "-f", container_name], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        subprocess.run(
            [
                "docker",
                "run",
                "-d",
                "--rm",
                "--name",
                container_name,
                "-p",
                f"{host}:{host_port}:{container_port}",
                image,
            ],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        _wait_for_http_ready(
            health_url,
            timeout_seconds=float(target.get("startup_timeout_seconds") or 120),
        )
        yield {
            "id": scenario.get("id"),
            "label": scenario.get("name"),
            "classification": "training_lab",
            "enabled": True,
            "authorized": True,
            "owner": "Known Vulnerability Validation Matrix",
            "authorization_ref": "LOCAL-KNOWN-VULN-MATRIX",
            "assessment_type": scenario.get("assessment_type"),
            "recommended_run_profile": scenario.get("scan_profile"),
            "recommended_modules": list(scenario.get("modules") or []),
            "scope": {"urls": [target_url]},
            "runtime_fixture_context": {
                "container_name": container_name,
                "image": image,
                "target_url": target_url,
            },
        }
    finally:
        subprocess.run(["docker", "rm", "-f", container_name], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def execute_aegispt_scenario(
    scenario: dict[str, Any],
    *,
    base_url: str,
    actor: str,
    wait_seconds: int,
    poll_interval: float,
) -> dict[str, Any]:
    with docker_target(scenario) as target:
        harness_scenario = {
            "id": scenario.get("id"),
            "name": scenario.get("name"),
            "assessment_type": scenario.get("assessment_type"),
            "run_profile": scenario.get("scan_profile"),
            "modules": list(scenario.get("modules") or []),
            "profile": "Validation Matrix",
            "expected_outputs": ["findings_surface", "task_evidence"],
            "minimum_reports": 0,
            "minimum_findings": 0,
            "dispatch": True,
        }
        with httpx.Client(base_url=base_url.rstrip("/"), timeout=180.0) as client:
            engagement_payload = build_engagement_payload(scenario=harness_scenario, target=target)
            engagement_response = client.post("/api/v1/engagements", headers=api_headers(actor), json=engagement_payload)
            engagement_response.raise_for_status()
            engagement = engagement_response.json()

            scope_response = client.post(
                f"/api/v1/engagements/{engagement['id']}/scope",
                headers=api_headers(actor),
                json={"allowlist_json": build_allowlist_from_target(target), "denylist_json": {}},
            )
            scope_response.raise_for_status()

            inventory_response = client.post(
                "/api/v1/inventory/runs",
                headers=api_headers(actor),
                json=build_inventory_seed_payload(engagement["id"], scenario=harness_scenario, target=target),
            )
            inventory_response.raise_for_status()
            inventory_snapshot = inventory_response.json()

            run_response = client.post(
                f"/api/v1/engagements/{engagement['id']}/runs",
                headers=api_headers(actor),
                json={
                    "profile_name": scenario.get("scan_profile"),
                    "source_inventory_snapshot_id": inventory_snapshot["id"],
                    "configuration_json": build_run_configuration(scenario=harness_scenario, target=target),
                },
            )
            run_response.raise_for_status()
            run = grant_required_approvals(
                client,
                run=run_response.json(),
                scenario=harness_scenario,
                actor=actor,
            )
            dispatch_response = client.post(f"/api/v1/runs/{run['id']}/dispatch", headers=api_headers(actor))
            dispatch_response.raise_for_status()
            dispatch_payload = dispatch_response.json()
            run = wait_for_terminal_run(
                client,
                run_id=run["id"],
                actor=actor,
                dispatch_mode=str(dispatch_payload.get("dispatch_mode") or "manual"),
                wait_seconds=wait_seconds,
                poll_interval=poll_interval,
            )

            findings_response = client.get(f"/api/v1/runs/{run['id']}/findings", headers=api_headers(actor))
            findings_response.raise_for_status()
            findings = findings_response.json()
            task_details = collect_task_details(client, run, actor)

    return {
        "run_id": run.get("id"),
        "run_status": run.get("status"),
        "task_count": len(task_details),
        "findings": findings,
        "terminal": run.get("status") in TERMINAL_RUN_STATUSES,
    }


def build_not_run_result(scenario: dict[str, Any], reason: str) -> dict[str, Any]:
    return {
        "scenario_id": scenario.get("id"),
        "scenario_name": scenario.get("name"),
        "status": "not_run",
        "reason": reason,
        "detection_rate_pct": None,
        "false_positive_rate_pct": None,
        "minimum_coverage_pct": scenario.get("minimum_coverage_pct"),
        "counts": {
            "expected": len(scenario.get("expected_findings") or []),
            "expected_found": 0,
            "actual_findings": 0,
            "unexpected_findings": 0,
            "forbidden_findings": 0,
        },
        "missing_expected": [item.get("id") for item in scenario.get("expected_findings") or []],
    }


def run_matrix(args: argparse.Namespace) -> dict[str, Any]:
    catalog = load_json(args.catalog)
    false_positive_threshold = float(catalog.get("false_positive_threshold_pct", FALSE_POSITIVE_THRESHOLD_PCT))
    scenarios = select_scenarios(catalog, args.scenario)
    scenario_results: list[dict[str, Any]] = []

    for scenario in scenarios:
        if args.actual_findings_dir:
            actual = load_actual_findings(args.actual_findings_dir, str(scenario["id"]))
            scenario_results.append(
                evaluate_scenario(
                    scenario,
                    actual,
                    false_positive_threshold_pct=false_positive_threshold,
                )
            )
            continue

        if args.execute:
            if not args.base_url:
                raise ValueError("--base-url is required with --execute")
            execution = execute_aegispt_scenario(
                scenario,
                base_url=args.base_url,
                actor=args.actor,
                wait_seconds=args.wait_seconds,
                poll_interval=args.poll_interval,
            )
            result = evaluate_scenario(
                scenario,
                execution["findings"],
                false_positive_threshold_pct=false_positive_threshold,
            )
            result["execution"] = {
                "run_id": execution.get("run_id"),
                "run_status": execution.get("run_status"),
                "task_count": execution.get("task_count"),
            }
            scenario_results.append(result)
            continue

        scenario_results.append(
            build_not_run_result(
                scenario,
                "No --execute or --actual-findings-dir was supplied; catalog loaded and scenario marked not_run.",
            )
        )

    completed = [item for item in scenario_results if item["status"] != "not_run"]
    failed = [item for item in scenario_results if item["status"] == "failed"]
    passed = [item for item in scenario_results if item["status"] == "passed"]
    matrix_status = "not_run"
    if completed:
        matrix_status = "failed" if failed else "passed"

    payload = {
        "schema_version": 1,
        "matrix_id": catalog.get("matrix_id"),
        "status": matrix_status,
        "generated_at": datetime.now(tz=UTC).isoformat(),
        "catalog": str(Path(args.catalog).resolve()),
        "mode": "execute" if args.execute else "offline-fixtures" if args.actual_findings_dir else "catalog-only",
        "summary": {
            "scenarios": len(scenario_results),
            "passed": len(passed),
            "failed": len(failed),
            "not_run": len([item for item in scenario_results if item["status"] == "not_run"]),
        },
        "scenarios": scenario_results,
    }
    return payload


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the AegisPT known-vulnerability validation matrix.")
    parser.add_argument("--catalog", default=str(DEFAULT_CATALOG), help="Expected findings catalog JSON.")
    parser.add_argument("--results-file", default=str(DEFAULT_RESULTS_FILE), help="Where to write the matrix result JSON.")
    parser.add_argument("--scenario", action="append", help="Scenario id to run. May be repeated.")
    parser.add_argument("--actual-findings-dir", help="Directory containing <scenario-id>.json actual finding fixtures.")
    parser.add_argument("--execute", action="store_true", help="Launch Docker targets and run AegisPT via the API.")
    parser.add_argument("--base-url", help="AegisPT API base URL, required with --execute.")
    parser.add_argument("--actor", default="codex-validation-matrix", help="Actor id for AegisPT audit records.")
    parser.add_argument("--wait-seconds", type=int, default=600, help="Maximum wait for each AegisPT run to finish.")
    parser.add_argument("--poll-interval", type=float, default=2.0, help="Polling interval while waiting for AegisPT runs.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    payload = run_matrix(args)
    output = write_json(args.results_file, payload)
    print(json.dumps({**payload, "results_file": str(output.resolve())}, indent=2, sort_keys=True))
    if payload["status"] == "failed":
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
