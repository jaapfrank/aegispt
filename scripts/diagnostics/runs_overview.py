#!/usr/bin/env python3
"""One-shot diagnostic: list every non-terminal run + status + loop state +
last picker rationale. Run this when you suspect runs are stuck or to
understand the current attack-graph state of the system.

Replaces the ad-hoc /tmp/diag_runs.py and /tmp/diag_lastpick.py scripts I
kept rewriting per session.

Example::

    python3 scripts/diagnostics/runs_overview.py
    python3 scripts/diagnostics/runs_overview.py --max-runs 10 --show-rationale
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any

import httpx

DEFAULT_BASE = "http://127.0.0.1:8000"
DEFAULT_ACTOR = "diagnostics-runs"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Non-terminal runs overview")
    p.add_argument("--base-url", default=DEFAULT_BASE)
    p.add_argument("--actor", default=DEFAULT_ACTOR)
    p.add_argument("--max-runs", type=int, default=50)
    p.add_argument("--show-rationale", action="store_true", help="Include last picker rationale per run")
    p.add_argument("--include-terminal", action="store_true", help="Also list completed/failed/cancelled")
    args = p.parse_args(argv)

    with httpx.Client(base_url=args.base_url, headers={"X-Actor": args.actor}, timeout=15) as c:
        engs = c.get("/api/v1/engagements?limit=40").json()
        if isinstance(engs, dict):
            engs = engs.get("items", [])

        rows: list[dict[str, Any]] = []
        for e in engs:
            eid = e.get("id")
            if not eid:
                continue
            try:
                runs = c.get(f"/api/v1/engagements/{eid}/runs?limit=5").json()
            except httpx.HTTPError:
                continue
            if isinstance(runs, dict):
                runs = runs.get("items", [])
            for r in runs:
                status = str(r.get("status") or "").lower()
                if not args.include_terminal and status not in {"running", "queued", "dispatched"}:
                    continue
                try:
                    detail = c.get(f"/api/v1/runs/{r['id']}").json()
                except httpx.HTTPError:
                    continue
                cfg = detail.get("configuration_json") or {}
                loop = cfg.get("ai_assessment_loop") or {}
                tasks = detail.get("tasks") or []
                task_states: dict[str, int] = {}
                for t in tasks:
                    s = str(t.get("status") or "?").lower()
                    task_states[s] = task_states.get(s, 0) + 1
                rows.append({
                    "id": r["id"],
                    "name": (e.get("name") or "")[:40],
                    "status": status,
                    "updated": (r.get("updated_at") or "")[:19],
                    "loop_status": loop.get("status"),
                    "loop_iter": loop.get("iteration_count"),
                    "stop_reason": loop.get("stop_reason"),
                    "task_counts": task_states,
                    "iterations": loop.get("iterations") or [],
                })
                if len(rows) >= args.max_runs:
                    break

        print(f"Found {len(rows)} non-terminal{' + terminal' if args.include_terminal else ''} runs:")
        print()
        for r in rows:
            rid = r["id"][:8]
            print(
                f"  {rid}  status={r['status']:18s} loop={(r['loop_status'] or '-'):18s} "
                f"iter={(r['loop_iter'] or '-')!s:>4s}  tasks={r['task_counts']}  upd={r['updated']}  {r['name']}"
            )
            if r["stop_reason"]:
                print(f"    STOP: {r['stop_reason']}")
            if args.show_rationale and r["iterations"]:
                last = r["iterations"][-1]
                act = last.get("next_action") or {}
                print(f"    LAST pick: tool={act.get('tool')}  target={act.get('target')}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
