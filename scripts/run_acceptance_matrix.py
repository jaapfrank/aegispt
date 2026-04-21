#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any

import httpx

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.acceptance_harness import (
    TERMINAL_RUN_STATUSES,
    activate_runtime_target,
    assert_runtime_prerequisites,
    build_allowlist_from_target,
    build_engagement_payload,
    build_inventory_seed_payload,
    build_run_configuration,
    default_target_catalog_path,
    list_real_run_scenarios,
    load_result_history,
    load_target_catalog,
    resolve_safe_target,
    select_next_real_run_scenario,
    select_real_run_scenario,
    summarize_result,
    write_result,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run a safe AegisPT acceptance scenario against an approved catalog target.")
    parser.add_argument("--base-url", required=True, help="AegisPT API base URL, for example http://127.0.0.1:8000")
    parser.add_argument("--catalog", default=str(default_target_catalog_path()), help="Path to the safe target catalog JSON.")
    parser.add_argument("--scenario-id", help="Real-run scenario id from the target catalog.")
    parser.add_argument("--target-id", help="Override the scenario target id with another safe catalog target.")
    parser.add_argument("--actor", default="codex-acceptance", help="Actor id to store in AegisPT audit records.")
    parser.add_argument("--dispatch", action=argparse.BooleanOptionalAction, default=True, help="Dispatch the created run after it is queued.")
    parser.add_argument("--wait-seconds", type=int, default=120, help="Maximum time to wait for a dispatched run to reach a terminal state.")
    parser.add_argument("--poll-interval", type=float, default=2.0, help="Polling interval in seconds while waiting for terminal state.")
    parser.add_argument("--output", help="Optional explicit output path for the acceptance result JSON.")
    parser.add_argument("--list-scenarios", action="store_true", help="List enabled real-run scenarios and exit.")
    return parser.parse_args()


def api_headers(actor: str) -> dict[str, str]:
    return {"X-Actor": actor}


def grant_required_approvals(
    client: httpx.Client,
    *,
    run: dict[str, Any],
    scenario: dict[str, Any],
    actor: str,
) -> dict[str, Any]:
    if run.get("status") != "pending_approval":
        return run

    approvers = scenario.get("approval_actors") or [f"{actor}-approver-1"]
    latest = run
    for approver in approvers:
        approval_response = client.post(
            f"/api/v1/runs/{run['id']}/approvals",
            headers=api_headers(approver),
            json={"decision": "approved"},
        )
        approval_response.raise_for_status()
        latest = approval_response.json()
        if latest.get("pending_approvals", 0) == 0:
            break
    return latest


def wait_for_terminal_run(
    client: httpx.Client,
    *,
    run_id: str,
    actor: str,
    dispatch_mode: str,
    wait_seconds: int,
    poll_interval: float,
) -> dict[str, Any]:
    deadline = time.time() + wait_seconds
    manual_queue_deadline = time.time() + min(wait_seconds, 10)
    latest: dict[str, Any] | None = None
    while time.time() < deadline:
        latest = client.get(f"/api/v1/runs/{run_id}", headers=api_headers(actor)).json()
        if latest.get("status") in TERMINAL_RUN_STATUSES:
            return latest
        if dispatch_mode == "manual" and latest.get("status") == "queued" and time.time() >= manual_queue_deadline:
            raise TimeoutError(
                f"Run {run_id} is still queued after manual dispatch. Start a worker for this host or rerun the acceptance harness against an inline-dispatch host."
            )
        time.sleep(poll_interval)
    raise TimeoutError(
        f"Timed out waiting for run {run_id} to reach a terminal state. Last observed status: {latest.get('status') if latest else 'unknown'}"
    )


def collect_task_details(client: httpx.Client, run: dict[str, Any], actor: str) -> list[dict[str, Any]]:
    details = []
    for task in run.get("tasks", []):
        response = client.get(f"/api/v1/tasks/{task['id']}", headers=api_headers(actor))
        response.raise_for_status()
        details.append(response.json())
    return details


def main() -> int:
    args = parse_args()
    catalog = load_target_catalog(args.catalog)

    if args.list_scenarios:
        payload = {
            "scenarios": list_real_run_scenarios(catalog),
            "targets": catalog.get("targets", []),
        }
        print(json.dumps(payload, indent=2))
        return 0

    history = load_result_history()
    scenario = (
        select_real_run_scenario(catalog, args.scenario_id)
        if args.scenario_id
        else select_next_real_run_scenario(catalog, history)
    )
    target_id = args.target_id or scenario.get("target_id")
    target = resolve_safe_target(catalog, target_id)

    with activate_runtime_target(target) as active_target:
        assert_runtime_prerequisites(scenario=scenario, target=active_target)
        with httpx.Client(base_url=args.base_url.rstrip("/"), timeout=180.0) as client:
            engagement_payload = build_engagement_payload(scenario=scenario, target=active_target)
            engagement_response = client.post("/api/v1/engagements", headers=api_headers(args.actor), json=engagement_payload)
            engagement_response.raise_for_status()
            engagement = engagement_response.json()

            scope_response = client.post(
                f"/api/v1/engagements/{engagement['id']}/scope",
                headers=api_headers(args.actor),
                json={"allowlist_json": build_allowlist_from_target(active_target), "denylist_json": {}},
            )
            scope_response.raise_for_status()

            inventory_response = client.post(
                "/api/v1/inventory/runs",
                headers=api_headers(args.actor),
                json=build_inventory_seed_payload(engagement["id"], scenario=scenario, target=active_target),
            )
            inventory_response.raise_for_status()
            inventory_snapshot = inventory_response.json()

            run_response = client.post(
                f"/api/v1/engagements/{engagement['id']}/runs",
                headers=api_headers(args.actor),
                json={
                    "profile_name": scenario.get("run_profile") or active_target.get("recommended_run_profile") or "passive-web-baseline",
                    "source_inventory_snapshot_id": inventory_snapshot["id"],
                    "configuration_json": build_run_configuration(scenario=scenario, target=active_target),
                },
            )
            run_response.raise_for_status()
            run = run_response.json()
            run = grant_required_approvals(
                client,
                run=run,
                scenario=scenario,
                actor=args.actor,
            )

            if args.dispatch:
                dispatch_response = client.post(
                    f"/api/v1/runs/{run['id']}/dispatch",
                    headers=api_headers(args.actor),
                )
                dispatch_response.raise_for_status()
                dispatch_payload = dispatch_response.json()
                run = dispatch_payload["run"]
                dispatch_mode = str(dispatch_payload.get("dispatch_mode") or "manual")
                run = wait_for_terminal_run(
                    client,
                    run_id=run["id"],
                    actor=args.actor,
                    dispatch_mode=dispatch_mode,
                    wait_seconds=args.wait_seconds,
                    poll_interval=args.poll_interval,
                )

            findings_response = client.get(f"/api/v1/runs/{run['id']}/findings", headers=api_headers(args.actor))
            findings_response.raise_for_status()
            findings = findings_response.json()

            reports_response = client.get(f"/api/v1/runs/{run['id']}/reports", headers=api_headers(args.actor))
            reports_response.raise_for_status()
            reports = reports_response.json()

            inventory_list_response = client.get(
                f"/api/v1/engagements/{engagement['id']}/inventory",
                headers=api_headers(args.actor),
            )
            inventory_list_response.raise_for_status()
            inventory = inventory_list_response.json()

            packs_response = client.get(f"/api/v1/engagements/{engagement['id']}/packs", headers=api_headers(args.actor))
            packs_response.raise_for_status()
            packs = packs_response.json()

            task_details = collect_task_details(client, run, args.actor)

    result = summarize_result(
        scenario=scenario,
        target=active_target,
        engagement_id=engagement["id"],
        run=run,
        findings=findings,
        reports=reports,
        inventory=inventory,
        packs=packs,
        task_details=task_details,
        base_url=args.base_url,
    )
    output_path = write_result(result, output_path=args.output)
    print(json.dumps({**result, "result_file": str(Path(output_path).resolve())}, indent=2))
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except TimeoutError as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1) from exc
