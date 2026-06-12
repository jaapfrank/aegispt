"""Tests for the generation-campaign runner (mints more winning trajectories).

Only the planning / dry-run path is exercised — no GPU, no harness, no network. The
campaign must emit exactly one harness command per (challenge, repeat) in the same
shape as docs/validation/xbow-xben080-2026-06-03/reproducer.sh.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scripts.training.generate_winning_trajectories import (  # noqa: E402
    DEFAULT_CHALLENGES,
    _normalize_challenge,
    build_parser,
    plan,
)


def _args(argv):
    return build_parser().parse_args(argv)


def test_normalize_challenge_forms():
    assert _normalize_challenge("80") == "XBEN-080-24"
    assert _normalize_challenge("080") == "XBEN-080-24"
    assert _normalize_challenge("XBEN-100-24") == "XBEN-100-24"
    assert _normalize_challenge("xben014") == "XBEN-014-24"


def test_plan_one_step_per_challenge():
    args = _args(["--challenges", "080", "014", "100"])
    steps = plan(args)
    assert len(steps) == 3
    assert [s["target"] for s in steps] == ["XBEN-080-24", "XBEN-014-24", "XBEN-100-24"]


def test_plan_repeats_multiply_steps():
    args = _args(["--challenges", "080", "014", "--repeats", "3"])
    steps = plan(args)
    # 2 challenges * 3 repeats = 6 sequential runs
    assert len(steps) == 6
    assert sum(1 for s in steps if s["target"] == "XBEN-080-24") == 3
    assert sum(1 for s in steps if s["target"] == "XBEN-014-24") == 3


def test_harness_command_matches_reproducer_shape():
    args = _args(["--challenges", "080", "--provider", "chatgpt_oauth",
                  "--budget-seconds", "1500"])
    cmd = list(plan(args)[0]["harness_cmd"])
    # mirrors xben080 reproducer: harness script, target, max-challenges 1,
    # wait-seconds, provider, source-aware.
    assert cmd[1] == "scripts/xbow_benchmark.py"
    assert "--target" in cmd and cmd[cmd.index("--target") + 1] == "XBEN-080-24"
    assert cmd[cmd.index("--max-challenges") + 1] == "1"
    assert cmd[cmd.index("--wait-seconds") + 1] == "1500"
    assert cmd[cmd.index("--llm-provider") + 1] == "chatgpt_oauth"
    assert cmd[cmd.index("--xbow-repo") + 1] == "/home/administrator/xbow-validation-benchmarks"
    assert "--source-aware" in cmd  # default on
    assert "--memory-root" in cmd  # isolated per-run (anti-contamination)


def test_no_source_aware_flag_when_disabled():
    args = _args(["--challenges", "080", "--no-source-aware"])
    cmd = list(plan(args)[0]["harness_cmd"])
    assert "--source-aware" not in cmd


def test_dry_run_emits_one_command_per_challenge(capsys):
    from scripts.training.generate_winning_trajectories import main
    rc = main(["--challenges", "080", "014", "100", "--dry-run"])
    assert rc == 0
    out = capsys.readouterr().out
    harness_lines = [ln for ln in out.splitlines()
                     if ln.startswith(".venv/bin/python scripts/xbow_benchmark.py")]
    assert len(harness_lines) == 3
    for target in ("XBEN-080-24", "XBEN-014-24", "XBEN-100-24"):
        assert any(f"--target {target}" in ln for ln in harness_lines)
    # one harvest command per challenge too
    harvest_lines = [ln for ln in out.splitlines()
                     if "harvest_winning_trajectories.py" in ln]
    assert len(harvest_lines) == 3


def test_dry_run_default_challenge_set():
    args = _args(["--dry-run"])
    assert args.challenges == DEFAULT_CHALLENGES
    steps = plan(args)
    assert len(steps) == len(DEFAULT_CHALLENGES)
