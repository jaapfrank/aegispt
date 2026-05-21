#!/usr/bin/env python3
"""Cross-run severity histogram + sample critical/high titles. Useful for
the "veel high maar geen critical?" sanity check operators tend to run
after a benchmark batch.

Example::

    python3 scripts/diagnostics/severity_distribution.py
    python3 scripts/diagnostics/severity_distribution.py --eng-limit 60
"""
from __future__ import annotations

import argparse
import sys
from collections import Counter

import httpx

DEFAULT_BASE = "http://127.0.0.1:8000"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Severity distribution across recent runs")
    p.add_argument("--base-url", default=DEFAULT_BASE)
    p.add_argument("--actor", default="diagnostics-severity")
    p.add_argument("--eng-limit", type=int, default=40)
    p.add_argument("--samples", type=int, default=10)
    args = p.parse_args(argv)

    with httpx.Client(base_url=args.base_url, headers={"X-Actor": args.actor}, timeout=15) as c:
        engs = c.get(f"/api/v1/engagements?limit={args.eng_limit}").json()
        if isinstance(engs, dict):
            engs = engs.get("items", [])
        sev = Counter()
        seen_titles: dict[str, list[tuple[str, str]]] = {"critical": [], "high": []}
        for e in engs:
            try:
                runs = c.get(f"/api/v1/engagements/{e['id']}/runs?limit=5").json()
            except httpx.HTTPError:
                continue
            if isinstance(runs, dict):
                runs = runs.get("items", [])
            for r in runs:
                try:
                    fdg = c.get(f"/api/v1/runs/{r['id']}/findings").json()
                except httpx.HTTPError:
                    continue
                if isinstance(fdg, dict):
                    fdg = fdg.get("items", [])
                for f in fdg:
                    severity = (f.get("severity") or "?").lower()
                    sev[severity] += 1
                    if severity in seen_titles and len(seen_titles[severity]) < args.samples:
                        seen_titles[severity].append(
                            ((f.get("title") or "?")[:80], (e.get("name") or "")[:30])
                        )

    order = ["critical", "high", "medium", "low", "info", "unknown", "?"]
    print("severity distribution across all recent runs:")
    for k in order + [k for k in sev if k not in order]:
        if k in sev:
            print(f"  {k:9s} {sev[k]:>5d}")
    print()
    for sev_name in ("critical", "high"):
        print(f"--- {sev_name.upper()} samples ({len(seen_titles[sev_name])} of {sev[sev_name]}) ---")
        for title, eng in seen_titles[sev_name]:
            print(f"  {title}  ({eng})")
        print()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
