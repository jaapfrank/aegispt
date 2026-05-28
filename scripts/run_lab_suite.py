#!/usr/bin/env python3
"""Drive the AegisPT autonomous AI loop against the standalone lab suite
(labs/aegispt_lab_suite) — a non-XBOW generalization target.

This validates the SAME readiness/isolation/envelope chain the XBOW harness
uses, on an independent set of 5 flag-capture challenges (SSRF, cache-key,
GraphQL authz, signed-URL, coupon-race) behind one HTTP service. The lab
already binds to its own loopback IP (127.0.0.155:8088), so the agent's recon
sees only the lab — the harness on 127.0.0.1 stays invisible.

Flow: bring the lab up -> create an engagement/scope/run targeting it
(scope = the whole IP, no port) -> drive /iterate until budget -> scan the
run's findings + code-exec-attack task outputs for `aegispt{...}` flags ->
POST each to the lab's /grade for byte-equal verification -> report per
challenge. Black-box by default (no source_dir) to test true generalization.
"""
from __future__ import annotations

import argparse
import json
import logging
import re
import subprocess
import time
import urllib.request
from pathlib import Path

import httpx

import sys
REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from scripts.run_acceptance_matrix import api_headers, grant_required_approvals  # noqa: E402
from scripts.xbow_benchmark import (  # noqa: E402
    _drive_ai_loop,
    _probe_target_envelope,
    _register_run,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger("run_lab_suite")

LAB_DIR = REPO / "labs" / "aegispt_lab_suite"
_FLAG_RE = re.compile(r"aegispt\{([a-z0-9-]+):[^}\r\n]{1,200}\}")


def _sh(cmd: list[str], *, cwd: Path | None = None, timeout: float = 300.0) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=str(cwd) if cwd else None, capture_output=True, text=True, timeout=timeout)


def _manifest_challenge_ids() -> list[str]:
    data = json.loads((LAB_DIR / "suite_manifest.json").read_text(encoding="utf-8"))
    return [c["id"] for c in data.get("challenges", [])]


def _grade(base_url: str, challenge_id: str, flag: str) -> bool:
    body = json.dumps({"challenge_id": challenge_id, "flag": flag}).encode("utf-8")
    req = urllib.request.Request(
        base_url.rstrip("/") + "/grade", data=body,
        headers={"Content-Type": "application/json"}, method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return bool(json.loads(resp.read().decode("utf-8")).get("match"))
    except Exception as exc:  # noqa: BLE001
        logger.warning("grade %s failed: %s", challenge_id, exc)
        return False


def _collect_flags_from_run(client: httpx.Client, actor: str, run_id: str) -> set[str]:
    """Scan findings + code-exec-attack task outputs for aegispt{...} flags."""
    flags: set[str] = set()
    try:
        fr = client.get(f"/api/v1/runs/{run_id}/findings", headers=api_headers(actor))
        if fr.status_code == 200:
            for m in _FLAG_RE.finditer(fr.text):
                flags.add(m.group(0))
    except httpx.HTTPError:
        pass
    # also scan task stdout envelopes
    try:
        tr = client.get(f"/api/v1/runs/{run_id}/tasks", headers=api_headers(actor))
        if tr.status_code == 200:
            for m in _FLAG_RE.finditer(tr.text):
                flags.add(m.group(0))
    except httpx.HTTPError:
        pass
    return flags


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url-api", default="http://127.0.0.1:8000", help="AegisPT API base URL")
    parser.add_argument("--lab-ip", default="127.0.0.155")
    parser.add_argument("--lab-port", type=int, default=8088)
    parser.add_argument("--actor", default="lab-suite-operator")
    parser.add_argument("--wait-seconds", type=int, default=1200)
    parser.add_argument("--poll-interval", type=float, default=15.0)
    parser.add_argument("--llm-provider", default="gemini-3.1-pro")
    parser.add_argument("--profile-name", default="autonomous-web")
    parser.add_argument("--m1-max-revisions", type=int, default=3)
    parser.add_argument("--source-aware", action="store_true",
                        help="give the agent the lab source (labs/aegispt_lab_suite) for white-box CPG analysis")
    parser.add_argument("--keep-up", action="store_true", help="leave the lab running after the run")
    args = parser.parse_args()

    lab_base = f"http://{args.lab_ip}:{args.lab_port}"
    challenge_ids = _manifest_challenge_ids()
    logger.info("lab challenges: %s", challenge_ids)

    # Idempotent bring-up.
    _sh(["docker", "compose", "down", "-v", "--remove-orphans"], cwd=LAB_DIR, timeout=120)
    logger.info("building + starting lab suite ...")
    up = _sh(["docker", "compose", "up", "-d", "--build", "--wait"], cwd=LAB_DIR, timeout=600)
    if up.returncode != 0:
        logger.error("lab up failed: %s", (up.stderr or up.stdout)[:400])
        return 2
    # Wait for /healthz.
    healthy = False
    for _ in range(30):
        try:
            with urllib.request.urlopen(lab_base + "/healthz", timeout=3) as r:
                if json.loads(r.read().decode("utf-8")).get("status"):
                    healthy = True
                    break
        except Exception:  # noqa: BLE001
            time.sleep(2)
    if not healthy:
        logger.error("lab did not become healthy at %s", lab_base)
        if not args.keep_up:
            _sh(["docker", "compose", "down", "-v", "--remove-orphans"], cwd=LAB_DIR, timeout=120)
        return 2
    logger.info("lab healthy at %s", lab_base)

    envelope = _probe_target_envelope(args.lab_ip, args.lab_port)
    logger.info("preflight envelope: %s", {k: envelope[k] for k in ("host_header", "first_status", "framework_blocked_default")})

    solved: dict[str, bool] = {cid: False for cid in challenge_ids}
    try:
        with httpx.Client(base_url=args.base_url_api.rstrip("/"), timeout=1800.0) as client:
            run = _register_run(
                client,
                actor=args.actor,
                target_url=lab_base,
                challenge_id="aegispt-lab-suite",
                profile_name=args.profile_name,
                llm_provider=args.llm_provider,
                source_dir=str(LAB_DIR) if args.source_aware else None,
                m1_max_revisions=args.m1_max_revisions,
                wait_seconds=args.wait_seconds,
                allowlist_urls=[f"http://{args.lab_ip}"],  # whole IP, all ports/paths
                target_envelope=envelope,
            )
            run_id = run.get("id")
            logger.info("run created: %s", run_id)
            run = grant_required_approvals(
                client, run=run, scenario={"approval_actors": [f"{args.actor}-approver-1"]}, actor=args.actor,
            )
            max_iter = int(args.wait_seconds // max(args.poll_interval, 1.0)) or 30
            state = _drive_ai_loop(
                client, actor=args.actor, run_id=run_id,
                max_iterations=max_iter, poll_interval=args.poll_interval,
                deadline_seconds=float(args.wait_seconds),
            )
            logger.info("loop finished: status=%s stop=%s iters=%s",
                        state.get("status"), state.get("stop_reason"), state.get("loop_driver_iterations"))
            flags = _collect_flags_from_run(client, args.actor, run_id)
            logger.info("captured flag-shaped strings: %s", sorted(flags))
            for flag in flags:
                m = _FLAG_RE.match(flag)
                if not m:
                    continue
                cid = m.group(1)
                if cid in solved and _grade(lab_base, cid, flag):
                    solved[cid] = True
    finally:
        if not args.keep_up:
            _sh(["docker", "compose", "down", "-v", "--remove-orphans"], cwd=LAB_DIR, timeout=120)

    n_solved = sum(1 for v in solved.values() if v)
    logger.info("LAB SUITE RESULT: %d/%d solved", n_solved, len(challenge_ids))
    for cid, ok in solved.items():
        logger.info("  %s -> %s", cid, "SOLVED" if ok else "no-flag")
    return 0 if n_solved > 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
