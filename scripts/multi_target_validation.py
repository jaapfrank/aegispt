"""Multi-target validation harness for the mythos-foundation sprint (backlog-406).

Runs AegisPT's autonomous-intrusive loop against 5 unrelated real-world OSS apps
that the system has NOT been tuned for. Per `feedback_live_proof_must_be_diverse_real_targets`,
training-app (Gruyere/DVWA/juice-shop) success is NOT a valid validation signal —
the system must work on production-class apps it has no prior knowledge of.

The harness:
  1. Spins up each target via `docker run` on a unique host port.
  2. Waits for HTTP health (≤180s default).
  3. Calls AegisPT's API: create engagement → create scope → start run with
     `autonomous_intrusive_allowed=True` and `profile=autonomous-web`.
  4. Drives the assessment loop via `/api/v1/runs/{id}/assessment-loop/iterate`
     for up to ADVANCE_LIMIT iterations or until the run stops.
  5. Queries the AegisPT DB for 7 metrics per target.
  6. Renders a markdown report at docs/validation/.
  7. Tears down the container even on exception (defensive teardown).

Phase semantics (per backlog-406):
  - `baseline`: pre-sprint run on raw HEAD. Observational.
  - `after-402` .. `after-405`: incremental runs after each sprint task lands.
  - The PASS gate (`exec_plan_successful ≥ 1 AND chain_findings ≥ 1 on ≥2 of 5`)
    is evaluated only at `after-405`. Earlier phases capture deltas, not pass/fail.

The target list is IMMUTABLE for this sprint. Adding per-target conditionals
in production code is forbidden (see `validate_no_target_seeds_in_production`).
"""
from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import os
import pathlib
import subprocess
import sys
import time
import uuid
from typing import Any

import httpx
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker


@dataclasses.dataclass(frozen=True)
class TargetSpec:
    target_id: str
    image: str
    container_port: int
    host_port: int
    healthcheck_path: str = "/"
    startup_timeout_seconds: int = 180
    extra_env: tuple[tuple[str, str], ...] = ()
    extra_args: tuple[str, ...] = ()


TARGETS: tuple[TargetSpec, ...] = (
    TargetSpec("mantis", "vimagick/mantisbt:2.21", 80, 18421),
    TargetSpec("mediawiki", "mediawiki:1.34", 80, 18422),
    TargetSpec(
        "roundcube",
        "roundcube/roundcubemail:1.4.0-apache",
        80,
        18423,
        extra_env=(
            ("ROUNDCUBEMAIL_DEFAULT_HOST", "ssl://imap.example.invalid"),
            ("ROUNDCUBEMAIL_SMTP_SERVER", "tls://smtp.example.invalid"),
        ),
    ),
    TargetSpec("gitea", "gitea/gitea:1.13", 3000, 18424),
    TargetSpec("etherpad", "etherpad/etherpad:1.8.5", 9001, 18425),
)

API_DEFAULT = "http://127.0.0.1:8000"
PROFILE = "autonomous-web"
ADVANCE_LIMIT = 20
POLL_INTERVAL_SECONDS = 8
PHASE_CHOICES = ("baseline", "after-402", "after-403", "after-404", "after-405", "smoke")
CONTAINER_NAME_PREFIX = "aegispt-validation-"


def _container_name(target: TargetSpec) -> str:
    return f"{CONTAINER_NAME_PREFIX}{target.target_id}"


def docker_up(target: TargetSpec) -> None:
    name = _container_name(target)
    subprocess.run(["docker", "rm", "-f", name], capture_output=True, check=False)
    args = [
        "docker",
        "run",
        "-d",
        "--rm",
        "--name",
        name,
        "-p",
        f"{target.host_port}:{target.container_port}",
    ]
    for k, v in target.extra_env:
        args.extend(["-e", f"{k}={v}"])
    args.extend(target.extra_args)
    args.append(target.image)
    res = subprocess.run(args, capture_output=True, text=True, check=False)
    if res.returncode != 0:
        raise RuntimeError(
            f"docker run failed for {target.target_id}: {res.stderr.strip() or res.stdout.strip()}"
        )


def docker_down(target: TargetSpec) -> None:
    subprocess.run(
        ["docker", "rm", "-f", _container_name(target)], capture_output=True, check=False
    )


def wait_for_health(target: TargetSpec) -> None:
    url = f"http://127.0.0.1:{target.host_port}{target.healthcheck_path}"
    deadline = time.monotonic() + target.startup_timeout_seconds
    last_err: str | None = None
    while time.monotonic() < deadline:
        try:
            r = httpx.get(url, timeout=5.0, follow_redirects=True)
            if 200 <= r.status_code < 500:
                return
            last_err = f"http_status={r.status_code}"
        except Exception as exc:
            last_err = type(exc).__name__
        time.sleep(3)
    raise RuntimeError(
        f"healthcheck timeout {target.startup_timeout_seconds}s for {target.target_id}: {last_err}"
    )


def register_engagement_and_scope(
    api_client: httpx.Client, target: TargetSpec, run_label: str
) -> uuid.UUID:
    payload = {
        "name": f"validation-{target.target_id}-{run_label}",
        "client": "validation-harness",
        "roe_ref": "backlog-406-multi-target-validation-harness",
        "retention_days": 1,
    }
    r = api_client.post("/api/v1/engagements", json=payload)
    _raise_with_body(r)
    engagement_id = uuid.UUID(r.json()["id"])

    scope_payload = {
        "allowlist_json": {
            "scope_rules": [
                {
                    "rule_type": "web_target",
                    "value": f"http://127.0.0.1:{target.host_port}/",
                    "active": True,
                }
            ]
        },
        "denylist_json": {},
    }
    r = api_client.post(f"/api/v1/engagements/{engagement_id}/scope", json=scope_payload)
    _raise_with_body(r)
    return engagement_id


def start_run(
    api_client: httpx.Client, engagement_id: uuid.UUID, target: TargetSpec
) -> uuid.UUID:
    payload = {
        "profile_name": PROFILE,
        "configuration_json": {
            "targets": [
                {"value": f"http://127.0.0.1:{target.host_port}/", "tier": "active"}
            ],
        },
        "autonomous_mode": True,
        "autonomous_intrusive_allowed": True,
        "dispatch_after_create": False,
    }
    r = api_client.post(f"/api/v1/engagements/{engagement_id}/runs", json=payload)
    _raise_with_body(r)
    return uuid.UUID(r.json()["id"])


def _raise_with_body(response: httpx.Response) -> None:
    """Raise on 4xx/5xx with the response body included in the exception message.

    httpx's default raise_for_status loses the body, which makes diagnosing API
    rejections (e.g. 409 from auto-queue conflict) needlessly painful.
    """
    if 400 <= response.status_code:
        body = (response.text or "")[:500]
        raise RuntimeError(
            f"{response.request.method} {response.request.url} → "
            f"http_{response.status_code}: {body}"
        )


def drive_advance_loop(api_client: httpx.Client, run_id: uuid.UUID) -> None:
    for _ in range(ADVANCE_LIMIT):
        try:
            r = api_client.post(
                f"/api/v1/runs/{run_id}/assessment-loop/iterate", json={}, timeout=60.0
            )
            _raise_with_body(r)
            data = r.json() or {}
            status = (data.get("status") or "").lower()
            stop_reason = (data.get("stop_reason") or "").lower()
            if status in {"completed", "stopped", "failed", "cancelled"}:
                return
            if stop_reason in {"stuck_no_new_signals", "scope_complete", "admin_compromise_proven"}:
                return
        except Exception:
            # Advance failure is logged in API; keep polling rather than aborting the target.
            pass
        time.sleep(POLL_INTERVAL_SECONDS)


def capture_metrics(db_url: str, run_id: uuid.UUID) -> dict[str, Any]:
    """Query the AegisPT DB for the 7 per-target metrics."""
    repo_root = pathlib.Path(__file__).resolve().parent.parent
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))
    from api.app.models import (  # type: ignore  # noqa: PLC0415
        AgentReasoning,
        EvidenceObservation,
        Finding,
        Task,
    )

    engine = create_engine(db_url)
    Session = sessionmaker(bind=engine)
    with Session() as sess:
        tasks = sess.scalars(select(Task).where(Task.run_id == run_id)).all()
        reasonings = sess.scalars(
            select(AgentReasoning).where(AgentReasoning.run_id == run_id)
        ).all()
        findings = sess.scalars(select(Finding).where(Finding.run_id == run_id)).all()
        observations = sess.scalars(
            select(EvidenceObservation).where(EvidenceObservation.run_id == run_id)
        ).all()

    claude_picks = sum(
        1
        for r in reasonings
        if not (r.metadata_json or {}).get("next_best_action_selector_used", True)
    )
    exec_plan_tasks = [t for t in tasks if (t.tool or "").lower() in {"exec-plan", "exec_plan"}]
    exec_plan_successful = sum(
        1 for t in exec_plan_tasks if (t.status or "").lower() == "completed"
    )
    captured_values = sum(
        1 for o in observations if (o.entity_type or "").lower() == "captured_value"
    )
    chain_findings = sum(
        1
        for f in findings
        if isinstance(getattr(f, "evidence_artifact_ids", None), list)
        and len(f.evidence_artifact_ids) >= 2
    )
    high_or_critical = sum(
        1 for f in findings if (f.severity or "").lower() in {"high", "critical"}
    )

    return {
        "claude_picks": claude_picks,
        "exec_plan_dispatches": len(exec_plan_tasks),
        "exec_plan_successful": exec_plan_successful,
        "captured_values_emitted": captured_values,
        "chain_findings": chain_findings,
        "high_or_critical_findings": high_or_critical,
        "runtime_minutes": 0.0,
    }


def render_report(
    results: dict[str, dict[str, Any]], phase: str, output_path: pathlib.Path
) -> None:
    lines: list[str] = [
        f"# Multi-target validation report — phase={phase}",
        "",
        f"Generated: {dt.datetime.now(dt.UTC).isoformat(timespec='seconds')}Z",
        "Harness: `scripts/multi_target_validation.py` (backlog-406)",
        "",
        "Per `feedback_live_proof_must_be_diverse_real_targets`: 5 unrelated real-world OSS apps,",
        "no per-target tuning, observation-driven only.",
        "",
        "| target | claude_picks | exec_plan_disp | exec_plan_ok | captures | chain_findings | high+crit | runtime_min | status |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---|",
    ]
    pass_count = 0
    skipped_count = 0
    for target_id, m in results.items():
        if m.get("skipped"):
            skipped_count += 1
            reason = str(m.get("reason", ""))[:120].replace("|", "/")
            lines.append(
                f"| {target_id} | — | — | — | — | — | — | — | SKIPPED: {reason} |"
            )
            continue
        gate_pass = m["exec_plan_successful"] >= 1 and m["chain_findings"] >= 1
        if gate_pass:
            pass_count += 1
        status_cell = "gate-pass" if gate_pass else "ran"
        lines.append(
            f"| {target_id} "
            f"| {m['claude_picks']} "
            f"| {m['exec_plan_dispatches']} "
            f"| {m['exec_plan_successful']} "
            f"| {m['captured_values_emitted']} "
            f"| {m['chain_findings']} "
            f"| {m['high_or_critical_findings']} "
            f"| {m['runtime_minutes']:.1f} "
            f"| {status_cell} |"
        )
    lines.append("")
    if phase == "after-405":
        verdict = "PASS" if pass_count >= 2 else "FAIL"
        lines.append(
            f"## Sprint-gate evaluation: **{verdict}** "
            f"({pass_count}/{len(results)} targets met `exec_plan_successful ≥ 1 AND chain_findings ≥ 1`)"
        )
        if verdict == "FAIL":
            lines.append("")
            lines.append("Per backlog-406 contract: sprint is rolled back, not the harness adjusted.")
    else:
        lines.append(
            f"## Phase verdict: observational only (no PASS/FAIL evaluation at phase={phase})"
        )
        lines.append("")
        lines.append(
            f"- Targets meeting gate criteria: {pass_count}/{len(results)}"
        )
        lines.append(f"- Targets skipped: {skipped_count}")
    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def run_target(
    api_url: str, db_url: str, target: TargetSpec, run_label: str
) -> dict[str, Any]:
    start = time.monotonic()
    docker_up(target)
    try:
        wait_for_health(target)
        with httpx.Client(base_url=api_url, timeout=30.0) as api_client:
            engagement_id = register_engagement_and_scope(api_client, target, run_label)
            run_id = start_run(api_client, engagement_id, target)
            drive_advance_loop(api_client, run_id)
            metrics = capture_metrics(db_url, run_id)
            metrics["runtime_minutes"] = (time.monotonic() - start) / 60
            metrics["run_id"] = str(run_id)
            metrics["engagement_id"] = str(engagement_id)
            return metrics
    finally:
        docker_down(target)


def validate_no_target_seeds_in_production() -> list[str]:
    """Greppable guard: target hostnames may NOT appear in production source."""
    pattern = "|".join(t.target_id for t in TARGETS)
    res = subprocess.run(
        ["git", "grep", "-inE", pattern, "--", "workers/runners/", "api/app/services/"],
        capture_output=True,
        text=True,
        check=False,
    )
    if res.returncode == 0 and res.stdout.strip():
        return [line for line in res.stdout.splitlines() if line.strip()]
    return []


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    ap.add_argument(
        "--target",
        choices=[t.target_id for t in TARGETS] + ["all"],
        default="all",
    )
    ap.add_argument("--phase", required=True, choices=PHASE_CHOICES)
    ap.add_argument("--api-url", default=os.environ.get("AEGISPT_API_URL", API_DEFAULT))
    ap.add_argument("--db-url", default=os.environ.get("DATABASE_URL", ""))
    ap.add_argument("--output-dir", default="docs/validation")
    args = ap.parse_args()

    if not args.db_url:
        print("ERROR: --db-url or DATABASE_URL env var is required", file=sys.stderr)
        return 2

    violations = validate_no_target_seeds_in_production()
    if violations:
        print("ERROR: target hostname literals found in production source:", file=sys.stderr)
        for line in violations[:20]:
            print(f"  {line}", file=sys.stderr)
        return 3

    selected = (
        list(TARGETS)
        if args.target == "all"
        else [t for t in TARGETS if t.target_id == args.target]
    )
    run_label = dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%S")
    results: dict[str, dict[str, Any]] = {}

    for target in selected:
        try:
            results[target.target_id] = run_target(
                args.api_url, args.db_url, target, run_label
            )
        except Exception as exc:
            results[target.target_id] = {"skipped": True, "reason": f"{type(exc).__name__}: {exc}"}
            docker_down(target)

    output_dir = pathlib.Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    date_str = dt.date.today().isoformat()
    output_path = output_dir / f"sprint-2026-mythos-foundation-{date_str}-{args.phase}.md"
    render_report(results, args.phase, output_path)
    print(f"Report written: {output_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
