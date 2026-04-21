#!/usr/bin/env python3
from __future__ import annotations

import argparse
import shlex
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
PYTEST = REPO_ROOT / ".venv" / "bin" / "pytest"

LANES = {
    "api": [
        "api/tests/test_acceptance_harness.py",
        "api/tests/test_nmap_dispatch.py",
        "api/tests/test_product_feature_matrix.py",
        "api/tests/test_reports.py",
        "api/tests/test_runs.py",
        "api/tests/test_task_dispatch.py",
        "api/tests/test_ui_support.py",
    ],
    "ui": [
        "ui/tests/test_operator_console_e2e.py",
        "ui/tests/test_product_feature_matrix_e2e.py",
    ],
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the AegisPT product end-to-end matrix across API and UI lanes."
    )
    parser.add_argument(
        "--lane",
        choices=("all", "api", "ui"),
        default="all",
        help="Select which validation lane to run.",
    )
    parser.add_argument(
        "--pytest-args",
        default="",
        help="Optional extra arguments forwarded to pytest.",
    )
    return parser.parse_args()


def run_lane(name: str, tests: list[str], extra_args: list[str]) -> int:
    command = [str(PYTEST), "-q", "-s", *tests, *extra_args]
    print(f"[aegispt-matrix] running {name} lane")
    print(f"[aegispt-matrix] command: {' '.join(shlex.quote(part) for part in command)}")
    completed = subprocess.run(command, cwd=REPO_ROOT)
    return completed.returncode


def main() -> int:
    args = parse_args()
    if not PYTEST.exists():
        print("Missing .venv/bin/pytest. Run bash scripts/setup_python_dev.sh first.", file=sys.stderr)
        return 1

    extra_args = shlex.split(args.pytest_args)
    selected_lanes = LANES.keys() if args.lane == "all" else [args.lane]

    for lane in selected_lanes:
        code = run_lane(lane, LANES[lane], extra_args)
        if code != 0:
            return code
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
