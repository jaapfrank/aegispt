#!/usr/bin/env python3
"""Empirical generality test for the 5 probes migrated in Mythos #328.

Runs each probe against a configurable list of targets and prints a
matrix of (probe, target) -> (attempts, findings_count). Used to
validate that the post-migration probes:

- Reach the testing stage (attempts > 0) on at least 3 non-Gruyere
  targets each, AND
- Continue to find Gruyere R1/R2/R3/R5/R7/R10/R15/R20 vulnerabilities
  on Gruyere itself (no-regression).

Default targets:
- http://localhost:8008/482338906867472456097470474631954304306/  (local Gruyere)
- https://juice-shop.herokuapp.com/
- https://demo.testfire.net/
- http://testasp.vulnweb.com/

Override via CLI args: pass any number of base URLs.

This script makes LIVE HTTP requests to external targets. Operator
authorized this in #328 task package. Anthropic credit-burn is
bounded: cache makes repeat acquire_session calls cheap (each fresh
fingerprint = 1 Haiku call ~= $0.01). Worst case 5 probes * 4 targets
* $0.01 = ~$0.20 with cold cache.

Each probe row reports `attempts > 0` (yes/no) and `findings_count`.
Acceptance criterion: per task package, attempts > 0 on >= 3 non-
Gruyere targets per probe.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

DEFAULT_TARGETS: list[str] = [
    "http://localhost:8008/482338906867472456097470474631954304306/",
    "https://juice-shop.herokuapp.com/",
    "https://demo.testfire.net/",
    "http://testasp.vulnweb.com/",
]

PROBES: list[tuple[str, str]] = [
    ("info_disclosure_probe", "execute_info_disclosure_probe"),
    ("stored_xss_probe", "execute_stored_xss_probe"),
    ("file_upload_probe", "execute_file_upload_probe"),
    ("param_pollution_probe", "execute_param_pollution_probe"),
    ("cookie_tamper_probe", "execute_cookie_tamper_probe"),
]


def _extract_metrics(stdout: str) -> tuple[int, int]:
    """Parse the probe's JSON stdout and return (attempts, findings_count)."""
    try:
        payload = json.loads(stdout)
    except json.JSONDecodeError:
        return 0, 0

    findings = payload.get("findings") or []
    findings_count = len(findings)

    # Probes use slightly different shapes; cover the known fields.
    attempts = (
        payload.get("attempt_count")
        or payload.get("probe_count")
        or payload.get("trace_count")
        or 0
    )
    if not isinstance(attempts, int):
        attempts = 0
    if attempts == 0:
        for trace in payload.get("trace") or []:
            attempts += len(trace.get("attempts") or trace.get("steps") or [])
    return attempts, findings_count


def _run_probe(probe_name: str, fn_name: str, target: str) -> dict[str, Any]:
    from importlib import import_module
    module = import_module(f"workers.runners.{probe_name}.runner")
    fn = getattr(module, fn_name)
    start = time.monotonic()
    try:
        execution = fn([target], scope_allowlist=None)
        stdout = execution.stdout
        status = "ok"
    except Exception as exc:
        stdout = "{}"
        status = f"exception: {exc.__class__.__name__}: {str(exc)[:120]}"
    elapsed = time.monotonic() - start
    attempts, findings_count = _extract_metrics(stdout)
    return {
        "probe": probe_name,
        "target": target,
        "status": status,
        "attempts": attempts,
        "findings_count": findings_count,
        "elapsed_seconds": round(elapsed, 2),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "targets",
        nargs="*",
        help="Override the default target list (one URL per arg)",
    )
    parser.add_argument(
        "--probe",
        choices=[p for p, _ in PROBES],
        help="Run only this probe (default: all 5)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit a JSON matrix instead of a human table",
    )
    parser.add_argument(
        "--memory-root",
        default=None,
        help="Override AEGISPT_MEMORY_ROOT (for cache isolation). Default: temp dir.",
    )
    args = parser.parse_args()

    targets = args.targets or DEFAULT_TARGETS
    probes = (
        [(name, fn) for name, fn in PROBES if name == args.probe]
        if args.probe
        else PROBES
    )

    memory_root = args.memory_root or tempfile.mkdtemp(prefix="aegispt-generality-")
    os.environ["AEGISPT_MEMORY_ROOT"] = memory_root

    results: list[dict[str, Any]] = []
    for probe_name, fn_name in probes:
        for target in targets:
            print(
                f"[run] {probe_name} -> {target}",
                file=sys.stderr,
                flush=True,
            )
            row = _run_probe(probe_name, fn_name, target)
            print(
                f"  attempts={row['attempts']} findings={row['findings_count']} "
                f"elapsed={row['elapsed_seconds']}s status={row['status']}",
                file=sys.stderr,
                flush=True,
            )
            results.append(row)

    if args.json:
        print(json.dumps({"matrix": results}, indent=2))
    else:
        print()
        print(f"{'Probe':<24} {'Target':<55} {'Attempts':>9} {'Findings':>9} {'Elapsed':>9}")
        print("-" * 110)
        for row in results:
            target_short = (
                row["target"][:52] + "..."
                if len(row["target"]) > 55
                else row["target"]
            )
            print(
                f"{row['probe']:<24} {target_short:<55} "
                f"{row['attempts']:>9} {row['findings_count']:>9} "
                f"{row['elapsed_seconds']:>8}s"
            )

    # Acceptance check: for each probe, count non-Gruyere targets with attempts > 0.
    # First target in the default list is Gruyere; treat any URL containing the
    # Gruyere-instance numeric path as the Gruyere target.
    def _is_gruyere(url: str) -> bool:
        return "482338906867472456097470474631954304306" in url or "google-gruyere" in url

    rc = 0
    if not args.probe:
        print()
        print("Acceptance check (>=3 non-Gruyere targets with attempts > 0):")
        for probe_name, _ in PROBES:
            non_gru = [
                r for r in results
                if r["probe"] == probe_name and not _is_gruyere(r["target"])
            ]
            with_attempts = [r for r in non_gru if r["attempts"] > 0]
            print(
                f"  {probe_name:<24} "
                f"non-Gruyere targets with attempts>0: {len(with_attempts)}/{len(non_gru)}"
            )
            if len(with_attempts) < 3 and len(non_gru) >= 3:
                rc = 1  # acceptance criterion not met

    return rc


if __name__ == "__main__":
    raise SystemExit(main())
