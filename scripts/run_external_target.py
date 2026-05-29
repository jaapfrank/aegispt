#!/usr/bin/env python3
"""Drive the AegisPT autonomous AI loop against an ARBITRARY authorized
external target (not a local docker challenge).

Reusable for any host the operator is authorized to test (e.g. Google Gruyere,
the public hacking lab at google-gruyere.appspot.com). Creates an
engagement + scope (host allowlist) + autonomous-intrusive run, drives
/iterate until budget, then reports the severity-bucketed findings from the
DB. No docker, no flag-grading (external apps have no /grade) — the deliverable
is the findings the agent produced.

SAFETY: only ever point this at a target you are explicitly authorized to test
(public training apps, your own systems, or an in-scope bug-bounty asset). The
scope allowlist is hard — the agent cannot touch hosts outside it.
"""
from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path
from urllib.parse import urlparse
from uuid import uuid4

import httpx

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from scripts.run_acceptance_matrix import api_headers, grant_required_approvals  # noqa: E402
from scripts.xbow_benchmark import _drive_ai_loop, _probe_target_envelope  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger("run_external_target")


def _register_external_run(
    client: httpx.Client, *, actor: str, base_url: str, scope_hosts: list[str],
    objective: str, llm_provider: str | None, source_dir: str | None,
    wait_seconds: int, m1_max_revisions: int, profile_name: str,
) -> dict:
    eng = client.post(
        "/api/v1/engagements",
        headers=api_headers(actor),
        json={
            "name": f"ext-{urlparse(base_url).hostname or 'target'}-{uuid4().hex[:6]}",
            "objective": objective,
            "scope_text": base_url,
            "roe_ref": "operator-authorized-external-target",
            "stakeholders": [{"name": actor, "role": "operator"}],
        },
    )
    eng.raise_for_status()
    engagement = eng.json()
    # Hard scope: allow the explicit base URL + each authorized host (scheme
    # http+https, no port = all ports on that host). The agent CANNOT leave it.
    scope_urls = [base_url]
    for h in scope_hosts:
        scope_urls += [f"https://{h}", f"http://{h}"]
    sc = client.post(
        f"/api/v1/engagements/{engagement['id']}/scope",
        headers=api_headers(actor),
        json={"allowlist_json": {"urls": sorted(set(scope_urls))}, "denylist_json": {}},
    )
    sc.raise_for_status()
    cfg = {
        "target_url": base_url,
        "run_mode": "ai_loop",
        "wall_clock_budget_seconds": float(wait_seconds),
    }
    if llm_provider:
        cfg["llm_provider"] = llm_provider
    if source_dir:
        cfg["source_dir"] = source_dir
    if m1_max_revisions and m1_max_revisions > 1:
        cfg["ai_assessment_loop"] = {"m1_max_revisions_per_predecessor": m1_max_revisions}
    run = client.post(
        f"/api/v1/engagements/{engagement['id']}/runs",
        headers=api_headers(actor),
        json={
            "profile_name": profile_name,
            "autonomous_intrusive_allowed": True,
            "configuration_json": cfg,
        },
    )
    if run.status_code >= 400:
        raise RuntimeError(f"run create failed ({run.status_code}): {run.text[:400]}")
    return run.json()


def _report_findings(run_id: str) -> None:
    from sqlalchemy import create_engine, text
    from api.app.config import get_settings
    eng = create_engine(get_settings().database_url)
    with eng.begin() as cx:
        rows = cx.execute(text(
            "SELECT severity, COUNT(*) FROM findings WHERE run_id=:r GROUP BY severity ORDER BY 1"
        ), {"r": run_id}).fetchall()
        logger.info("FINDINGS by severity: %s", {s: n for s, n in rows} or "(none)")
        rows = cx.execute(text(
            "SELECT severity, LEFT(title,100) FROM findings WHERE run_id=:r "
            "AND severity IN ('critical','high','medium') ORDER BY created_at LIMIT 25"
        ), {"r": run_id}).fetchall()
        for sev, title in rows:
            logger.info("  [%s] %s", sev, title)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--base-url-api", default="http://127.0.0.1:8000")
    p.add_argument("--target", required=True, help="external base URL to assess (authorized only)")
    p.add_argument("--scope-host", action="append", default=[],
                   help="extra host(s) to allow (defaults to the target host); repeatable")
    p.add_argument("--objective", default="Authorized external security assessment")
    p.add_argument("--actor", default="external-target-operator")
    p.add_argument("--wait-seconds", type=int, default=1500)
    p.add_argument("--poll-interval", type=float, default=15.0)
    p.add_argument("--llm-provider", default="gemini-3.1-pro")
    p.add_argument("--profile-name", default="autonomous-web")
    p.add_argument("--m1-max-revisions", type=int, default=3)
    p.add_argument("--source-dir", default=None, help="optional local source for white-box CPG")
    args = p.parse_args()

    host = urlparse(args.target).hostname
    if not host:
        logger.error("could not parse host from --target %s", args.target)
        return 2
    scope_hosts = args.scope_host or [host]
    logger.info("external assessment: target=%s scope_hosts=%s", args.target, scope_hosts)

    # Preflight reachability (best-effort) — confirm the target answers before
    # spending budget, and detect the Host envelope.
    parsed = urlparse(args.target)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        env = _probe_target_envelope(host, port)
        logger.info("preflight: host_header=%s first_status=%s", env.get("host_header"), env.get("first_status"))
    except Exception as exc:  # noqa: BLE001
        logger.warning("preflight probe failed (continuing): %s", exc)

    with httpx.Client(base_url=args.base_url_api.rstrip("/"), timeout=1800.0) as client:
        run = _register_external_run(
            client, actor=args.actor, base_url=args.target, scope_hosts=scope_hosts,
            objective=args.objective, llm_provider=args.llm_provider, source_dir=args.source_dir,
            wait_seconds=args.wait_seconds, m1_max_revisions=args.m1_max_revisions,
            profile_name=args.profile_name,
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
    _report_findings(run_id)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
