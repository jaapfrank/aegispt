#!/usr/bin/env python3
"""Find every non-terminal run whose picker is already done (loop_status=stopped
or all tasks completed/failed) and POST /cancel to finalize it.

Before backlog-finalizer-fix landed, the picker would set
loop_state.status='stopped' but never transition run.status — leaving
"running" rows piling up. The auto-finalizer catches future runs; this
script mops up any historical orphans (and is safe to run anytime — it's
idempotent and only touches runs whose picker is genuinely done).

Example::

    python3 scripts/diagnostics/finalize_orphans.py             # dry-run
    python3 scripts/diagnostics/finalize_orphans.py --execute   # actually cancel
"""
from __future__ import annotations

import argparse
import sys

import httpx

DEFAULT_BASE = "http://127.0.0.1:8000"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Finalize orphan non-terminal runs")
    p.add_argument("--base-url", default=DEFAULT_BASE)
    p.add_argument("--actor", default="orphan-cleanup")
    p.add_argument("--execute", action="store_true", help="Actually cancel (default = dry-run preview)")
    p.add_argument("--max-engs", type=int, default=40)
    args = p.parse_args(argv)

    with httpx.Client(base_url=args.base_url, headers={"X-Actor": args.actor}, timeout=15) as c:
        engs = c.get(f"/api/v1/engagements?limit={args.max_engs}").json()
        if isinstance(engs, dict):
            engs = engs.get("items", [])

        candidates: list[dict] = []
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
                if str(r.get("status") or "").lower() not in {"running", "queued", "dispatched"}:
                    continue
                try:
                    detail = c.get(f"/api/v1/runs/{r['id']}").json()
                except httpx.HTTPError:
                    continue
                tasks = detail.get("tasks") or []
                non_term = [t for t in tasks if (t.get("status") or "").lower() in {"running", "queued", "dispatched", "pending"}]
                if non_term:
                    # Picker / tasks still active — leave alone.
                    continue
                candidates.append({
                    "id": r["id"],
                    "name": (e.get("name") or "")[:40],
                    "loop_status": (detail.get("configuration_json") or {}).get("ai_assessment_loop", {}).get("status"),
                    "total_tasks": len(tasks),
                })

        print(f"Found {len(candidates)} orphan non-terminal runs (all tasks done, picker not progressing).")
        if not candidates:
            return 0

        for r in candidates:
            print(f"  {r['id'][:8]}  loop={r['loop_status']!s:18s} tasks={r['total_tasks']:3d}  {r['name']}")

        if not args.execute:
            print()
            print("Dry-run only. Re-run with --execute to actually /cancel them.")
            return 0

        ok = 0
        fail = 0
        for r in candidates:
            try:
                resp = c.post(f"/api/v1/runs/{r['id']}/cancel")
                if resp.status_code == 200:
                    print(f"  {r['id'][:8]} -> {resp.json().get('status')}")
                    ok += 1
                else:
                    print(f"  {r['id'][:8]} -> FAIL {resp.status_code}: {resp.text[:120]}")
                    fail += 1
            except httpx.HTTPError as exc:
                print(f"  {r['id'][:8]} -> EXC: {exc}")
                fail += 1
        print(f"\nDone: ok={ok}  fail={fail}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
