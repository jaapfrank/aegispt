"""Generation campaign: run the XBOW harness over solvable challenges to MINT more
winning multi-turn trajectories, then harvest them for the specialist SFT dataset.

The real lever for MORE and MORE-DIVERSE specialist data is not re-balancing the
trajectories we already have — it is *generating wins on more challenges*. This
runner drives ``scripts/xbow_benchmark.py`` ONCE PER CHALLENGE, **strictly
sequentially** (a hard project rule: concurrent xbow_benchmark wrappers contend on
the inline dispatcher and starve interactive-exploit — see memory
``feedback-no-parallel-xbow-runs``), with a bounded per-challenge budget. After each
challenge it re-runs ``harvest_winning_trajectories.py`` so any new flag-proven
transcript accumulates into the dataset incrementally.

The harness invocation mirrors ``docs/validation/xbow-xben080-2026-06-03/reproducer.sh``:
sources ``~/.aegispt-secrets``, ``--xbow-repo /home/administrator/xbow-validation-benchmarks``,
``--target XBEN-0NN-24``, ``--max-challenges 1``, ``--source-aware`` (white-box).

This module is pure orchestration — it does NOT need a GPU at build time. The actual
model inference happens inside the harness when the operator runs the emitted command.
``--dry-run`` prints the planned commands without executing anything.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

# Default solvable set, inferred from the challenges we have prior winning evidence for
# (docs/validation/xbow-xben*/ dirs + reproducer.sh files). Keep numeric ids; the
# harness target is built as XBEN-0NN-24.
DEFAULT_CHALLENGES = ["002", "005", "009", "014", "020", "032", "033", "038", "053", "080", "096", "100"]

# Paths matching the reproducer (operator's host layout).
DEFAULT_XBOW_REPO = "/home/administrator/xbow-validation-benchmarks"
DEFAULT_SECRETS = "/home/administrator/.aegispt-secrets"
DEFAULT_HARNESS = "scripts/xbow_benchmark.py"
DEFAULT_HARVEST = "scripts/training/harvest_winning_trajectories.py"
DEFAULT_ARTIFACTS = ".aegispt-artifacts"
DEFAULT_DATASET = "codex/results/training/winning_trajectories.jsonl"


def _normalize_challenge(c: str) -> str:
    """Accept '80', '080', 'XBEN-080-24', 'xben080' -> canonical XBEN-080-24 target id."""
    c = c.strip()
    m = re.search(r"(\d{1,3})", c)
    if not m:
        raise ValueError(f"cannot parse challenge id from {c!r}")
    num = int(m.group(1))
    return f"XBEN-{num:03d}-24"


def build_harness_command(
    target: str,
    *,
    provider: str,
    budget_seconds: int,
    xbow_repo: str,
    out_dir: str,
    memory_root: str,
    poll_interval: float,
    source_aware: bool,
    m1_max_revisions: int,
    python_bin: str,
) -> list[str]:
    """One harness command for a single challenge, mirroring the xben080 reproducer."""
    cmd = [
        python_bin, DEFAULT_HARNESS,
        "--xbow-repo", xbow_repo,
        "--memory-root", memory_root,
        "--target", target,
        "--max-challenges", "1",
        "--wait-seconds", str(budget_seconds),
        "--poll-interval", str(poll_interval),
        "--out-dir", out_dir,
        "--log-level", "INFO",
        "--llm-provider", provider,
        "--m1-max-revisions", str(m1_max_revisions),
    ]
    if source_aware:
        cmd.append("--source-aware")
    return cmd


def build_harvest_command(
    *,
    artifacts_dir: str,
    dataset_out: str,
    max_per_challenge: int,
    python_bin: str,
) -> list[str]:
    """Re-run the harvester so any new winning transcript accumulates into the dataset."""
    return [
        python_bin, DEFAULT_HARVEST,
        "--artifacts-dir", artifacts_dir,
        "--out", dataset_out,
        "--dedup",
        "--max-per-challenge", str(max_per_challenge),
    ]


def plan(args: argparse.Namespace) -> list[dict[str, object]]:
    """Build the per-(challenge, repeat) execution plan without running anything."""
    targets = [_normalize_challenge(c) for c in args.challenges]
    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    steps: list[dict[str, object]] = []
    for target in targets:
        for rep in range(1, args.repeats + 1):
            # Isolated memory root + out-dir per run (anti-contamination; harness requires it).
            slug = f"{target.lower()}-r{rep}-{stamp}"
            memory_root = f"/tmp/xbow-mem-{slug}"
            out_dir = f"/tmp/xbow-out-{slug}"
            harness = build_harness_command(
                target,
                provider=args.provider,
                budget_seconds=args.budget_seconds,
                xbow_repo=args.xbow_repo,
                out_dir=out_dir,
                memory_root=memory_root,
                poll_interval=args.poll_interval,
                source_aware=args.source_aware,
                m1_max_revisions=args.m1_max_revisions,
                python_bin=args.python_bin,
            )
            harvest = build_harvest_command(
                artifacts_dir=args.artifacts_dir,
                dataset_out=args.dataset_out,
                max_per_challenge=args.max_per_challenge,
                python_bin=args.python_bin,
            )
            steps.append({
                "target": target,
                "repeat": rep,
                "out_dir": out_dir,
                "memory_root": memory_root,
                "harness_cmd": harness,
                "harvest_cmd": harvest,
            })
    return steps


def _read_outcome(out_dir: str, target: str) -> tuple[bool, str]:
    """Parse the harness JSON sidecar in out_dir to decide win/no-flag for target.

    The harness writes ``xbow-<date>-<phase>.json`` with ``results[].challenge_id`` and
    ``results[].solved``. Returns (solved, status_str)."""
    p = Path(out_dir)
    if not p.exists():
        return False, "no-out-dir"
    sidecars = sorted(p.glob("xbow-*.json"))
    if not sidecars:
        return False, "no-report"
    try:
        data = json.loads(sidecars[-1].read_text(encoding="utf-8", errors="replace"))
    except Exception as exc:  # noqa: BLE001
        return False, f"report-parse-error:{exc}"
    for r in data.get("results", []):
        if r.get("challenge_id") == target:
            solved = bool(r.get("solved"))
            status = str(r.get("run_status") or r.get("error") or r.get("skipped_reason") or "-")
            return solved, ("SOLVED" if solved else f"no-flag({status})")
    return False, "target-not-in-report"


def _run_cmd(cmd: list[str], *, env: dict[str, str], timeout: int | None) -> tuple[int, str]:
    """Run a subprocess from REPO_ROOT, returning (returncode, tail-of-output)."""
    try:
        proc = subprocess.run(
            cmd, cwd=str(REPO_ROOT), env=env, timeout=timeout,
            capture_output=True, text=True,
        )
        tail = (proc.stdout or "")[-2000:] + (proc.stderr or "")[-2000:]
        return proc.returncode, tail
    except subprocess.TimeoutExpired:
        return 124, "TIMEOUT"


def _load_secrets_env(secrets_path: str) -> dict[str, str]:
    """Mirror the reproducer's ``set -a; . ~/.aegispt-secrets; set +a`` so the harness
    subprocess inherits provider credentials. Best-effort: parse simple KEY=VALUE lines."""
    env = dict(os.environ)
    p = Path(secrets_path).expanduser()
    if not p.exists():
        return env
    for raw in p.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):]
        if "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        val = val.strip().strip('"').strip("'")
        if key:
            env[key] = val
    return env


def run_campaign(args: argparse.Namespace) -> dict[str, object]:
    steps = plan(args)
    env = _load_secrets_env(args.secrets)
    # generous wall-clock ceiling: per-challenge budget + build/up/teardown slack.
    per_step_timeout = args.budget_seconds + args.step_overhead_seconds
    summary: dict[str, object] = {
        "started": datetime.now(UTC).isoformat(),
        "provider": args.provider,
        "budget_seconds": args.budget_seconds,
        "repeats": args.repeats,
        "challenges": [_normalize_challenge(c) for c in args.challenges],
        "runs": [],
    }
    runs: list[dict[str, object]] = summary["runs"]  # type: ignore[assignment]
    for i, step in enumerate(steps, start=1):
        target = str(step["target"])
        out_dir = str(step["out_dir"])
        print(f"[{i}/{len(steps)}] {target} (repeat {step['repeat']}) -> running harness "
              f"(budget {args.budget_seconds}s)", flush=True)
        t0 = time.time()
        rc, _tail = _run_cmd(list(step["harness_cmd"]), env=env, timeout=per_step_timeout)  # type: ignore[arg-type]
        solved, status = _read_outcome(out_dir, target)
        elapsed = round(time.time() - t0, 1)
        # Harvest after EVERY challenge so wins accumulate incrementally.
        h_rc, _ = _run_cmd(list(step["harvest_cmd"]), env=env, timeout=600)  # type: ignore[arg-type]
        print(f"[{i}/{len(steps)}] {target} -> {status} ({elapsed}s, harness rc={rc}, harvest rc={h_rc})",
              flush=True)
        runs.append({
            "target": target,
            "repeat": step["repeat"],
            "solved": solved,
            "status": status,
            "harness_returncode": rc,
            "harvest_returncode": h_rc,
            "elapsed_seconds": elapsed,
            "out_dir": out_dir,
        })
        _write_summary(args.summary_out, summary)  # checkpoint after each run

    summary["finished"] = datetime.now(UTC).isoformat()
    summary["wins"] = sum(1 for r in runs if r["solved"])
    summary["total_runs"] = len(runs)
    _write_summary(args.summary_out, summary)
    return summary


def _write_summary(path: str, summary: dict[str, object]) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--challenges", nargs="+", default=DEFAULT_CHALLENGES,
                    help="XBEN challenge ids (e.g. 080 014 XBEN-100-24). Default = known solvable set.")
    ap.add_argument("--provider", default="chatgpt_oauth",
                    help="--llm-provider passed to the harness (default chatgpt_oauth).")
    ap.add_argument("--budget-seconds", type=int, default=1500,
                    help="Per-challenge poll budget (--wait-seconds), bounded. Default 1500.")
    ap.add_argument("--repeats", type=int, default=1,
                    help="Run each challenge K times to harvest multiple winning paths. Default 1.")
    ap.add_argument("--source-aware", action=argparse.BooleanOptionalAction, default=True,
                    help="Pass --source-aware to the harness (white-box). Default on.")
    ap.add_argument("--xbow-repo", default=DEFAULT_XBOW_REPO)
    ap.add_argument("--secrets", default=DEFAULT_SECRETS,
                    help="Secrets file sourced for provider creds (mirrors the reproducer).")
    ap.add_argument("--poll-interval", type=float, default=12.0)
    ap.add_argument("--m1-max-revisions", type=int, default=3)
    ap.add_argument("--artifacts-dir", default=DEFAULT_ARTIFACTS,
                    help="Where interactive-exploit transcripts land (harvester input).")
    ap.add_argument("--dataset-out", default=DEFAULT_DATASET,
                    help="Accumulating harvested dataset JSONL.")
    ap.add_argument("--max-per-challenge", type=int, default=8,
                    help="Per-challenge cap forwarded to the harvester. Default 8.")
    ap.add_argument("--summary-out", default="codex/results/training/generation_campaign_summary.json",
                    help="JSON summary of per-challenge win/no-flag outcomes.")
    ap.add_argument("--python-bin", default=".venv/bin/python",
                    help="Python used to invoke the harness/harvester subprocesses.")
    ap.add_argument("--step-overhead-seconds", type=int, default=1200,
                    help="Extra wall-clock above --budget-seconds for build/up/teardown per run.")
    ap.add_argument("--dry-run", action="store_true",
                    help="Print the planned commands (one harness + one harvest per challenge/repeat) and exit.")
    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.repeats < 1:
        raise SystemExit("--repeats must be >= 1")
    steps = plan(args)
    if args.dry_run:
        for step in steps:
            print(f"# {step['target']} repeat {step['repeat']}")
            print(shlex.join(list(step["harness_cmd"])))  # type: ignore[arg-type]
            print(shlex.join(list(step["harvest_cmd"])))  # type: ignore[arg-type]
        print(f"# {len(steps)} run(s) planned across {len(args.challenges)} challenge(s), "
              f"SEQUENTIAL (never parallel).")
        return 0
    run_campaign(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
