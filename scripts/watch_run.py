#!/usr/bin/env python3
"""Live drill-down companion to Mission Control — shows what the agent is
ACTUALLY doing under the surface (picker reasoning, per-task stdout, findings
as they land).

Mission Control v3 is executive-level: tool name + status + count.
This script surfaces the layers below: the Claude picker's reasoning per
hop, the runner's stdout/stderr snippets, and finding titles + severity
as they appear. Read alongside `journalctl --user -u aegispt-api -f` for
the full raw log.

Usage::

    # Watch the most recent in-flight run
    python3 scripts/watch_run.py

    # Or pin to a specific run
    python3 scripts/watch_run.py --run-id 2ff4b8a1-...

    # Tune refresh
    python3 scripts/watch_run.py --interval 3 --tail 6

Reads from the AegisPT API only (no DB / log scraping). Stays under 200
lines so it can stay in sync with the API surface without becoming its
own maintenance burden.
"""
from __future__ import annotations

import argparse
import sys
import time
from datetime import datetime, timezone
from typing import Any

import httpx


def _fmt_time(value: str | None) -> str:
    if not value:
        return "         "
    try:
        ts = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return ts.astimezone(timezone.utc).strftime("%H:%M:%S")
    except (ValueError, TypeError):
        return value[:9] if isinstance(value, str) else "         "


def _pick_run(client: httpx.Client) -> dict[str, Any] | None:
    # No top-level GET /runs endpoint exists; iterate recent engagements and
    # take the freshest run across them. Bounded to recent engagements to keep
    # the cost predictable when the DB has many historical entries.
    eng_resp = client.get("/api/v1/engagements?limit=20")
    if eng_resp.status_code != 200:
        return None
    eng_list = eng_resp.json()
    engagements = eng_list if isinstance(eng_list, list) else eng_list.get("items") or []
    engagements.sort(key=lambda e: str(e.get("created_at") or ""), reverse=True)
    best: dict[str, Any] | None = None
    best_key = ""
    for eng in engagements[:20]:
        eid = eng.get("id")
        if not eid:
            continue
        try:
            runs_resp = client.get(f"/api/v1/engagements/{eid}/runs?limit=5")
        except httpx.HTTPError:
            continue
        if runs_resp.status_code != 200:
            continue
        runs_payload = runs_resp.json()
        runs_list = runs_payload if isinstance(runs_payload, list) else runs_payload.get("items") or []
        for r in runs_list:
            status = str(r.get("status") or "").lower()
            key = ("0" if status in {"running", "queued", "dispatched"} else "1") + str(
                r.get("started_at") or r.get("created_at") or ""
            )
            # "0" prefix beats "1" prefix, so running/queued sort first; within
            # each bucket the freshest timestamp wins.
            if best is None or key < best_key:
                best = r
                best_key = key
    return best


def _short(s: Any, n: int = 220) -> str:
    text = str(s or "").replace("\n", " ").replace("\r", " ").strip()
    return text if len(text) <= n else text[: n - 1] + "…"


def _render(run: dict[str, Any], tasks: list[dict[str, Any]], findings_payload: Any, tail: int) -> str:
    findings = findings_payload if isinstance(findings_payload, list) else findings_payload.get("items") or []
    lines: list[str] = []
    lines.append("=" * 100)
    lines.append(
        f"RUN {str(run.get('id') or '?')[:8]} status={run.get('status')}  "
        f"started={_fmt_time(run.get('started_at'))}  "
        f"target={_short((run.get('configuration_json') or {}).get('target_url'), 50)}"
    )
    lines.append(
        f"  tasks: {len(tasks)} total  |  findings: {len(findings)}  |  "
        f"loop: {(run.get('configuration_json') or {}).get('_assessment_loop', {}).get('status', '?')}"
    )

    # ---- Picker's last decision rationale ----
    loop_state = (run.get("configuration_json") or {}).get("_assessment_loop", {}) or {}
    last_reason = loop_state.get("last_next_step_reason") or loop_state.get("last_action_reason") or loop_state.get("last_rationale")
    if last_reason:
        lines.append("")
        lines.append("PICKER (most recent decision):")
        lines.append(f"  {_short(last_reason, 400)}")
    stop_reason = loop_state.get("stop_reason")
    if stop_reason:
        lines.append(f"  STOPPED: {stop_reason}")

    # ---- Per-task drill-down ----
    lines.append("")
    lines.append(f"TASKS (last {tail}, newest first):")
    sorted_tasks = sorted(
        tasks,
        key=lambda t: str(t.get("updated_at") or t.get("created_at") or ""),
        reverse=True,
    )[:tail]
    for t in sorted_tasks:
        tool = str(t.get("tool") or "?")
        status = str(t.get("status") or "?")
        target = _short(t.get("target_id"), 40)
        when = _fmt_time(t.get("updated_at") or t.get("created_at"))
        lines.append(f"  [{when}] {tool:18s} {status:10s} -> {target}")
        execs = t.get("executions") or []
        if execs:
            exe = execs[0]
            stdout = _short(exe.get("stdout_text"), 200)
            stderr = _short(exe.get("stderr_text"), 200)
            exit_code = exe.get("exit_code")
            if stdout:
                lines.append(f"      stdout: {stdout}")
            if stderr and stderr != stdout:
                lines.append(f"      stderr: {stderr}")
            if exit_code is not None and exit_code != 0:
                lines.append(f"      exit_code: {exit_code}")

    # ---- Findings drill-down ----
    if findings:
        lines.append("")
        lines.append(f"FINDINGS (last {tail}):")
        sorted_findings = sorted(
            findings,
            key=lambda f: str(f.get("created_at") or ""),
            reverse=True,
        )[:tail]
        for f in sorted_findings:
            sev = str(f.get("severity") or "?").upper()[:4]
            title = _short(f.get("title"), 80)
            when = _fmt_time(f.get("created_at"))
            lines.append(f"  [{when}] [{sev:4s}] {title}")

    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Live drill-down for an AegisPT run")
    p.add_argument("--base-url", default="http://127.0.0.1:8000")
    p.add_argument("--actor", default="watch-run")
    p.add_argument("--run-id", default=None, help="Pin to a specific run id; default = most recent running.")
    p.add_argument("--interval", type=float, default=4.0, help="Seconds between refreshes (default 4).")
    p.add_argument("--tail", type=int, default=8, help="How many recent tasks/findings to show (default 8).")
    p.add_argument("--once", action="store_true", help="Print one snapshot and exit.")
    args = p.parse_args(argv)

    headers = {"X-Actor": args.actor}
    with httpx.Client(base_url=args.base_url.rstrip("/"), timeout=30.0, headers=headers) as client:
        run_id = args.run_id
        while True:
            try:
                if run_id is None:
                    picked = _pick_run(client)
                    if picked is None:
                        print("(no runs available)", file=sys.stderr)
                        if args.once:
                            return 1
                        time.sleep(args.interval)
                        continue
                    run_id = str(picked.get("id"))
                run_resp = client.get(f"/api/v1/runs/{run_id}")
                if run_resp.status_code == 404:
                    print(f"run {run_id} not found — will pick again", file=sys.stderr)
                    run_id = None
                    if args.once:
                        return 1
                    time.sleep(args.interval)
                    continue
                run_resp.raise_for_status()
                run = run_resp.json()
                tasks = run.get("tasks") or []
                findings_resp = client.get(f"/api/v1/runs/{run_id}/findings")
                findings_payload = findings_resp.json() if findings_resp.status_code == 200 else []
            except httpx.HTTPError as exc:
                print(f"watch_run: API error: {exc}", file=sys.stderr)
                if args.once:
                    return 1
                time.sleep(args.interval)
                continue
            # ANSI clear + render
            sys.stdout.write("\033[H\033[J")
            sys.stdout.write(_render(run, tasks, findings_payload, args.tail))
            sys.stdout.write("\n")
            sys.stdout.flush()
            if args.once:
                return 0
            time.sleep(args.interval)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        sys.exit(130)
