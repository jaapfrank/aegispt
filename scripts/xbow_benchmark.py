#!/usr/bin/env python3
"""XBOW benchmark baseline harness — backlog-408 (sprint mythos-exploitation-foundation, task 2/15).

Runs AegisPT against XBOW's 104 cleaned validation benchmarks
(https://github.com/KeygraphHQ/xbow-validation-benchmarks). For each
challenge:

1. Build the challenge container with a randomly-generated FLAG injected
   at build time (so no challenge-specific solution can leak across runs).
2. Bring up the docker-compose stack and wait for healthcheck.
3. Discover the exposed HTTP port from the compose file.
4. Register engagement + scope + autonomous-intrusive run in AegisPT.
5. Poll the run until terminal.
6. Search ingested findings / task outputs for the injected flag.
7. Tear down the docker-compose stack (mandatory finally).

Anti-contamination guard (per Codex refinement on backlog-408):
- The harness REFUSES to run unless ``AEGISPT_MEMORY_ROOT`` points at a
  benchmark-only directory (matching ``*/benchmark*/*`` or
  ``*/xbow*/*``). This ensures Claude's filesystem-backed memory tool
  cannot read/write into the production memory root during a benchmark.
- A companion grep test (``tests/test_xbow_contamination_guard.py``)
  enforces that no XBOW challenge identifier (``XBEN-XXX-YY``) appears
  in ``api/`` or ``workers/`` source. Solutions stay outside production
  code.

CLI::

    python3 scripts/xbow_benchmark.py \
        --xbow-repo /opt/xbow-validation-benchmarks \
        --base-url http://127.0.0.1:8000 \
        --phase baseline \
        --max-challenges 20 \
        --memory-root /home/administrator/.aegispt-bench/memories

Per ANTI_DRIFT.md Rule 1: this script is a MEASUREMENT instrument —
not a capability. The deliverable is a baseline score (may be low) plus
proof the harness runs end-to-end on >=20 challenges.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import re
import secrets
import shutil
import subprocess
import sys
import time
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from uuid import uuid4

import httpx

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.run_acceptance_matrix import (  # noqa: E402
    api_headers,
    grant_required_approvals,
    wait_for_terminal_run,
)

logger = logging.getLogger("xbow_benchmark")

XBEN_RE = re.compile(r"^XBEN-\d{3}-\d{2}$")
# Two compose port forms — long "HOST:CONTAINER" and short "CONTAINER".
COMPOSE_PORT_LONG_RE = re.compile(r'^\s*-\s*"?(\d{1,5}):(\d{1,5})"?\s*$')
COMPOSE_PORT_SHORT_RE = re.compile(r'^\s*-\s*"?(\d{1,5})"?\s*$')
COMPOSE_SERVICE_RE = re.compile(r"^([A-Za-z0-9_-]+):\s*$")
WEB_CONTAINER_PORTS = (80, 443, 8080, 8443, 5000, 5003, 3000, 8000)
DEFAULT_PROFILE_NAME = "autonomous-web"  # seeds target-intel; AI loop drives the rest via /iterate
TERMINAL_STATUSES = {"completed", "completed_with_errors", "failed", "cancelled", "stopped", "errored"}
LOOP_TERMINAL_STATUSES = {"stopped", "completed", "completed_with_errors", "failed", "cancelled"}


@dataclass
class ChallengeResult:
    """Per-challenge outcome captured by the harness."""

    challenge_id: str
    solved: bool
    flag_injected: str
    flag_found_in: list[str] = field(default_factory=list)
    time_to_solve_sec: float = 0.0
    exec_plan_dispatches: int = 0
    exec_plan_successful: int = 0
    refinement_attempts: int = 0
    finding_count: int = 0
    tool_chain_length: int = 0
    loop_iterations: int = 0
    loop_stop_reason: str | None = None
    run_id: str | None = None
    run_status: str | None = None
    error: str | None = None
    skipped_reason: str | None = None
    notes: list[str] = field(default_factory=list)


def _check_anti_contamination(memory_root: Path) -> None:
    """Refuse to run unless memory_root is benchmark-isolated.

    Per backlog-408 ``contamination_guard_strict``: a benchmark run MUST
    NOT touch the production AEGISPT_MEMORY_ROOT. The path must contain
    ``bench`` or ``xbow`` to make accidental misconfiguration impossible.
    """
    text = str(memory_root).lower()
    if "bench" not in text and "xbow" not in text:
        raise SystemExit(
            f"Refusing to run XBOW benchmark with memory_root={memory_root!r}: "
            "path must contain 'bench' or 'xbow' so the production memory root "
            "cannot be reused (anti-contamination guard, backlog-408)."
        )
    memory_root.mkdir(parents=True, exist_ok=True)


def _discover_challenges(xbow_repo: Path) -> list[Path]:
    """Return sorted XBEN-NNN-YY directories under ``xbow_repo/benchmarks``."""
    bench_dir = xbow_repo / "benchmarks"
    if not bench_dir.is_dir():
        raise SystemExit(
            f"--xbow-repo {xbow_repo!r} does not contain a benchmarks/ subdirectory. "
            "Clone https://github.com/KeygraphHQ/xbow-validation-benchmarks first."
        )
    return sorted(
        p for p in bench_dir.iterdir()
        if p.is_dir() and XBEN_RE.match(p.name)
    )


def _parse_compose_port(compose_path: Path) -> int | None:
    """Best-effort: scan ``docker-compose.yml`` for a static HOST:CONTAINER
    mapping pointing at a web-shaped container port.

    XBOW challenges mix two compose port forms:
    - Long form ``- "8080:80"`` → returns 8080 here (static host port).
    - Short form ``- 80`` → host port assigned dynamically by Docker
      at ``up`` time. Returns None here; resolved later by
      :func:`_resolve_runtime_port` after the stack is up.

    Returns a static host port if one is encoded in the compose file,
    otherwise None (caller must consult Docker after ``up``).
    """
    if not compose_path.is_file():
        return None
    for raw_line in compose_path.read_text(encoding="utf-8", errors="replace").splitlines():
        m = COMPOSE_PORT_LONG_RE.match(raw_line)
        if not m:
            continue
        host_port = int(m.group(1))
        container_port = int(m.group(2))
        if container_port in WEB_CONTAINER_PORTS:
            return host_port
    return None


def _challenge_has_web_service(compose_path: Path) -> bool:
    """Return True if any service exposes a web-shaped container port.

    Accepts both long and short forms. Used as a cheap pre-filter to skip
    non-HTTP challenges (DB-only, IoT-protocol-only, etc.) without firing
    up Docker.
    """
    if not compose_path.is_file():
        return False
    text = compose_path.read_text(encoding="utf-8", errors="replace")
    for raw_line in text.splitlines():
        m = COMPOSE_PORT_LONG_RE.match(raw_line)
        if m and int(m.group(2)) in WEB_CONTAINER_PORTS:
            return True
        m = COMPOSE_PORT_SHORT_RE.match(raw_line)
        if m and int(m.group(1)) in WEB_CONTAINER_PORTS:
            return True
    return False


def _resolve_runtime_port(challenge_dir: Path, *, timeout: float = 30.0) -> int | None:
    """After ``docker compose up``, query Docker for the published host
    port of any service exposing a web-shaped container port.

    Uses ``docker compose ps --format json`` (one service per line in
    recent compose versions). Returns the first match, or None.
    """
    proc = _run(
        ["docker", "compose", "ps", "--format", "json"],
        cwd=challenge_dir,
        timeout=timeout,
    )
    if proc.returncode != 0:
        return None
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        # Docker compose ps json shape: Publishers: [{PublishedPort, TargetPort}]
        for pub in entry.get("Publishers") or []:
            target = pub.get("TargetPort")
            published = pub.get("PublishedPort")
            if isinstance(target, int) and isinstance(published, int) and target in WEB_CONTAINER_PORTS and published > 0:
                return int(published)
    return None


def _run(cmd: list[str], *, cwd: Path | None = None, timeout: float, env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    """Wrapper around subprocess.run with consistent timeout/env handling."""
    return subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        env={**os.environ, **(env or {})},
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def _normalize_compose(challenge_dir: Path) -> Path:
    """Some upstream XBOW compose files have duplicate YAML keys at the same
    nesting level (e.g. XBEN-001-24/docker-compose.yml has ``depends_on:``
    defined twice on the same service). Docker's compose parser rejects this;
    PyYAML accepts it (last value wins). Round-trip through PyYAML to produce
    a normalized variant we then point ``docker compose`` at via ``-f``.

    Returns the path to use for compose commands — the original if no
    duplicate keys were found, otherwise the normalized sibling file.
    """
    original = challenge_dir / "docker-compose.yml"
    if not original.is_file():
        return original
    try:
        import yaml  # local import keeps the module top-level deps unchanged
    except ImportError:
        return original
    try:
        raw = original.read_text(encoding="utf-8", errors="replace")
        parsed = yaml.safe_load(raw)
    except (yaml.YAMLError, OSError):
        return original
    if not isinstance(parsed, dict):
        return original
    # Strip fixed host-port mappings (e.g. "8000:80" → "80") so XBEN challenges
    # that hard-code popular host ports don't clash with the AegisPT API on
    # :8000 or local Postgres on :5432. Docker assigns a free host port when
    # only the container port is specified, and the harness resolves the
    # published port via `docker compose ps --format json` already.
    services = parsed.get("services")
    if isinstance(services, dict):
        for svc_cfg in services.values():
            if not isinstance(svc_cfg, dict):
                continue
            ports = svc_cfg.get("ports")
            if not isinstance(ports, list):
                continue
            rewritten: list[Any] = []
            for entry in ports:
                if isinstance(entry, str) and ":" in entry:
                    # "HOST:CONTAINER" or "HOST:CONTAINER/proto" — keep just container side.
                    container_side = entry.split(":", 1)[1]
                    rewritten.append(container_side)
                elif isinstance(entry, dict) and "published" in entry:
                    # long-form { target, published, ... } — drop "published"
                    cleaned = {k: v for k, v in entry.items() if k != "published"}
                    rewritten.append(cleaned)
                else:
                    rewritten.append(entry)
            svc_cfg["ports"] = rewritten
    # Round-trip serialisation. PyYAML's default Dumper collapses any duplicate
    # keys to the last seen value, which fixes the XBEN-001 class of bug.
    try:
        normalized = yaml.safe_dump(parsed, sort_keys=False, default_flow_style=False)
    except yaml.YAMLError:
        return original
    if normalized.strip() == raw.strip():
        return original
    out = challenge_dir / "docker-compose.normalized.yml"
    out.write_text(normalized, encoding="utf-8")
    logger.info("xbow harness: normalized compose written for %s", challenge_dir.name)
    return out


@contextmanager
def _docker_challenge(challenge_dir: Path, flag: str, *, build_timeout: float, up_timeout: float):
    """Bring up a single XBOW challenge; tear down unconditionally on exit.

    Pad-1 reliability fixes 2026-05-23:
    - Compose pre-scan: refuse challenges that pin arm64 platform on
      a non-arm64 host (was 100% failure in Phase A baseline). The
      ChallengeResult upstream maps RuntimeError("PLATFORM_INCOMPATIBLE
      …") to skipped_reason instead of crashed.
    - Compose-up failure now distinguishes "platform-not-amd64" vs other
      crash modes so the harness can classify reliability buckets.
    """
    import platform as _platform
    host_arch = _platform.machine().lower()
    compose_text = ""
    for candidate in (challenge_dir / "docker-compose.normalized.yml",
                      challenge_dir / "docker-compose.yml"):
        if candidate.exists():
            try:
                compose_text = candidate.read_text(encoding="utf-8")
                break
            except OSError:
                continue
    if (
        host_arch not in {"aarch64", "arm64"}
        and "platform: linux/arm64" in compose_text
        and "platform: linux/amd64" not in compose_text
    ):
        raise RuntimeError(
            f"PLATFORM_INCOMPATIBLE — compose pins arm64 only; host is {host_arch}. "
            "Install qemu-user-static + docker buildx to enable cross-arch emulation."
        )

    env_overlay = {"FLAG": flag}
    compose_file = _normalize_compose(challenge_dir)
    compose_flags = ["-f", compose_file.name] if compose_file.name != "docker-compose.yml" else []

    # FLAG is a per-run build-arg that gets baked into the image, so a
    # cached image from a prior smoke embeds the PREVIOUS flag. Reusing it
    # causes the AI to "solve" by extracting the stale flag from cache,
    # which the harness then fails to recognize against its newly-injected
    # one. ALWAYS rebuild when a flag is being injected. Image-cache layers
    # for unchanged layers (pip deps etc.) still apply, so the rebuild is
    # fast for the second-and-later runs.
    cached_image_name = f"{challenge_dir.name.lower()}-trading_platform:latest"
    try:
        subprocess.run(
            ["docker", "image", "rm", "-f", cached_image_name],
            check=False, capture_output=True, text=True,
        )
    except Exception:
        pass

    build = _run(
        ["docker", "compose", *compose_flags, "build", "--build-arg", f"flag={flag}"],
        cwd=challenge_dir,
        timeout=build_timeout,
        env=env_overlay,
    )
    if build.returncode != 0:
        err = (build.stderr or build.stdout)[:400]
        if "buildx isn't installed" in err or "buildx" in err.lower():
            raise RuntimeError(
                f"BUILDX_MISSING — docker compose build needs buildx but it's not installed. "
                f"Run: sudo apt-get install -y docker-buildx-plugin. Original error: {err}"
            )
        if "failed to resolve source metadata" in err or "registry-1.docker.io" in err:
            raise RuntimeError(
                f"REGISTRY_DNS — docker registry unreachable. Check WSL DNS / proxy. "
                f"Original error: {err}"
            )
        raise RuntimeError(
            f"docker compose build failed (exit {build.returncode}): {err}"
        )
    up = _run(
        ["docker", "compose", *compose_flags, "up", "-d", "--wait"],
        cwd=challenge_dir,
        timeout=up_timeout,
        env=env_overlay,
    )
    if up.returncode != 0:
        try:
            _run(["docker", "compose", *compose_flags, "down", "-v"], cwd=challenge_dir, timeout=120, env=env_overlay)
        except Exception:
            pass
        raise RuntimeError(
            f"docker compose up failed (exit {up.returncode}): "
            f"{(up.stderr or up.stdout)[:400]}"
        )
    try:
        yield
    finally:
        try:
            _run(["docker", "compose", *compose_flags, "down", "-v"], cwd=challenge_dir, timeout=120, env=env_overlay)
        except Exception as exc:  # noqa: BLE001
            logger.warning("teardown of %s raised %s — investigate manually", challenge_dir.name, exc)


def _register_run(
    client: httpx.Client,
    *,
    actor: str,
    target_url: str,
    challenge_id: str,
    profile_name: str,
    llm_provider: str | None = None,
    source_dir: str | None = None,
    m1_max_revisions: int = 1,
    m6_cross_model_critic: bool = False,
) -> dict[str, Any]:
    """Create engagement + scope + autonomous-intrusive run."""
    engagement_response = client.post(
        "/api/v1/engagements",
        headers=api_headers(actor),
        json={
            "name": f"xbow-bench-{challenge_id}-{uuid4().hex[:6]}",
            "objective": f"XBOW baseline measurement: {challenge_id} (backlog-408)",
            "scope_text": target_url,
            "roe_ref": "backlog-408-xbow-baseline-harness",
            "stakeholders": [{"name": actor, "role": "operator"}],
        },
    )
    engagement_response.raise_for_status()
    engagement = engagement_response.json()

    scope_response = client.post(
        f"/api/v1/engagements/{engagement['id']}/scope",
        headers=api_headers(actor),
        json={
            "allowlist_json": {"urls": [target_url]},
            "denylist_json": {},
        },
    )
    scope_response.raise_for_status()

    # NB: deliberately omit the challenge_id from configuration_json so no
    # XBOW-specific identifier ever lands in api/ or workers/ state. The
    # contamination guard (tests/test_xbow_contamination_guard.py) enforces
    # this at the source level. run_mode=ai_loop enables /iterate driving
    # below (without it, the run only fires the profile's initial tools and
    # terminates — exactly the empty-loop bug discovered 2026-05-20).
    run_response = client.post(
        f"/api/v1/engagements/{engagement['id']}/runs",
        headers=api_headers(actor),
        json={
            "profile_name": profile_name,
            "autonomous_intrusive_allowed": True,
            "configuration_json": {
                "target_url": target_url,
                "run_mode": "ai_loop",
                # backlog-387 A/B: when --llm-provider passed, embed it so
                # _claude_select_next_action picks the right backend
                # (Anthropic default OR ChatGPT-OAuth).
                **({"llm_provider": llm_provider} if llm_provider else {}),
                # Phase 4 2026-05-22: source-aware mode opt-in. When set,
                # orchestrator dispatches pre-recon-source FIRST and
                # concatenates the white-box deliverable with network recon.
                **({"source_dir": source_dir} if source_dir else {}),
                # M4 multi-trajectory + M6 cross-model critic per-run config.
                # Default {} keeps M1 baseline behavior.
                **(
                    {"ai_assessment_loop": {
                        **({"m1_max_revisions_per_predecessor": m1_max_revisions} if m1_max_revisions and m1_max_revisions > 1 else {}),
                        **({"m6_cross_model_critic": True} if m6_cross_model_critic else {}),
                    }}
                    if ((m1_max_revisions and m1_max_revisions > 1) or m6_cross_model_critic)
                    else {}
                ),
            },
        },
    )
    if run_response.status_code >= 400:
        # Surface the API's actual reason so debugging the next layer up is fast.
        raise RuntimeError(
            f"run create failed ({run_response.status_code}): "
            f"{run_response.text[:400]}"
        )
    return run_response.json()


def _drive_ai_loop(
    client: httpx.Client,
    *,
    actor: str,
    run_id: str,
    max_iterations: int,
    poll_interval: float,
    deadline_seconds: float,
) -> dict[str, Any]:
    """Drive the autonomous AI loop by calling /iterate until the loop says stop.

    Each /iterate call asks the picker to choose the next action, enqueues 1
    task, dispatches it inline, and returns. Loop terminates when the picker
    emits action=stop, max_iterations is hit, or the run reaches a terminal
    status. Returns the final loop state for the report.
    """
    started = time.time()
    iterations = 0
    last_loop_state: dict[str, Any] = {}
    while iterations < max_iterations and (time.time() - started) < deadline_seconds:
        iterations += 1
        try:
            iter_resp = client.post(
                f"/api/v1/runs/{run_id}/assessment-loop/iterate",
                headers=api_headers(actor),
                json={"operator_note": "xbow-benchmark autonomous drive"},
                # 1800s tolerates a single iterate that runs the full
                # CPG-CEA cycle (picker + Claude exploit-developer +
                # script_critic revisions) synchronously. Empirical
                # 2026-05-27 smoke 47a/b: iterate calls during the
                # critic-revision loop took >600s and the old 600s
                # bound caused the wrapper to crash, then teardown the
                # docker target while the API run was still trying to
                # exploit. The result: 10+ code-exec-attack tasks all
                # hit ConnectError on the dead target.
                timeout=1800.0,
            )
        except httpx.HTTPError as exc:
            last_loop_state = {"iterate_error": str(exc)[:200], "iterations": iterations}
            break
        if iter_resp.status_code == 409:
            # 409 typically means: waiting for execution OR loop already terminal.
            # Either way we should poll the run status to decide.
            pass
        elif iter_resp.status_code >= 400:
            last_loop_state = {
                "iterate_http_error": iter_resp.status_code,
                "body": iter_resp.text[:200],
                "iterations": iterations,
            }
            break
        else:
            last_loop_state = iter_resp.json()
            loop_status = str(last_loop_state.get("status") or "").lower()
            stop_reason = str(last_loop_state.get("stop_reason") or "")
            if loop_status in LOOP_TERMINAL_STATUSES or stop_reason:
                break
        # Poll run status as the authoritative terminal-check.
        run_resp = client.get(f"/api/v1/runs/{run_id}", headers=api_headers(actor))
        if run_resp.status_code == 200:
            run_status = str(run_resp.json().get("status") or "").lower()
            if run_status in TERMINAL_STATUSES:
                break
        time.sleep(poll_interval)
    last_loop_state["loop_driver_iterations"] = iterations
    last_loop_state["loop_driver_elapsed_sec"] = round(time.time() - started, 1)
    return last_loop_state


def _scan_for_flag(client: httpx.Client, actor: str, run_id: str, flag: str) -> list[str]:
    """Look for the injected flag in findings + per-task stdout. Return list of locations."""
    hits: list[str] = []
    try:
        findings_resp = client.get(f"/api/v1/runs/{run_id}/findings", headers=api_headers(actor))
        findings_resp.raise_for_status()
        if flag in findings_resp.text:
            hits.append("findings")
    except Exception:
        pass
    try:
        run_resp = client.get(f"/api/v1/runs/{run_id}", headers=api_headers(actor))
        run_resp.raise_for_status()
        run_payload = run_resp.json()
        for task in run_payload.get("tasks") or []:
            # The run endpoint does not include execution stdout_text
            # inline. Fetch per-task to get executions[].stdout_text.
            tid = task.get("id")
            if not tid:
                continue
            try:
                task_resp = client.get(f"/api/v1/tasks/{tid}", headers=api_headers(actor))
                task_resp.raise_for_status()
                task_payload = task_resp.json()
            except Exception:
                continue
            for exe in (task_payload.get("executions") or task.get("executions") or []):
                stdout = str(exe.get("stdout_text") or "")
                stderr = str(exe.get("stderr_text") or "")
                if flag in stdout or flag in stderr:
                    hits.append(f"task:{tid}:{task.get('tool','?')}")
                    break
    except Exception:
        pass
    return hits


def _aggregate_metrics(client: httpx.Client, actor: str, run_id: str) -> dict[str, int]:
    """Pull exec_plan + refinement + tool chain counts from the run payload."""
    counters = {
        "exec_plan_dispatches": 0,
        "exec_plan_successful": 0,
        "refinement_attempts": 0,
        "finding_count": 0,
        "tool_chain_length": 0,
    }
    try:
        run_resp = client.get(f"/api/v1/runs/{run_id}", headers=api_headers(actor))
        run_resp.raise_for_status()
        run_payload = run_resp.json()
        for task in run_payload.get("tasks") or []:
            tool = str(task.get("tool") or "")
            status = str(task.get("status") or "").lower()
            counters["tool_chain_length"] += 1
            if tool == "exec-plan":
                counters["exec_plan_dispatches"] += 1
                if status == "completed":
                    counters["exec_plan_successful"] += 1
            loop_state = task.get("loop_state") or {}
            counters["refinement_attempts"] += int(loop_state.get("refinement_attempts") or 0)
        findings_resp = client.get(f"/api/v1/runs/{run_id}/findings", headers=api_headers(actor))
        findings_resp.raise_for_status()
        findings_payload = findings_resp.json()
        counters["finding_count"] = len(findings_payload if isinstance(findings_payload, list) else findings_payload.get("items") or [])
    except Exception as exc:  # noqa: BLE001
        logger.warning("metric aggregation for %s failed: %s", run_id, exc)
    return counters


def _run_one_challenge(
    challenge_dir: Path,
    *,
    base_url: str,
    actor: str,
    profile_name: str,
    wait_seconds: int,
    poll_interval: float,
    build_timeout: float,
    up_timeout: float,
    llm_provider: str | None = None,
    source_aware: bool = False,
    m1_max_revisions: int = 1,
    m6_cross_model_critic: bool = False,
) -> ChallengeResult:
    challenge_id = challenge_dir.name
    flag = f"xbow-{secrets.token_hex(16)}"
    result = ChallengeResult(challenge_id=challenge_id, solved=False, flag_injected=flag)

    compose_path = challenge_dir / "docker-compose.yml"
    if not _challenge_has_web_service(compose_path):
        result.skipped_reason = "no web-shaped container port in docker-compose.yml (non-HTTP challenge)"
        return result

    started = time.time()
    try:
        with _docker_challenge(challenge_dir, flag, build_timeout=build_timeout, up_timeout=up_timeout):
            # ALWAYS resolve the host port AFTER docker compose up.
            # The compose file may hardcode a static host port like ``8000:80``
            # that collides with a host service (e.g. AegisPT API itself on
            # 127.0.0.1:8000). When that happens Docker rebinds to a different
            # host port, and a pre-up static-port read would point the agent
            # at the wrong service (catastrophic: agent attacks the harness
            # API instead of the challenge). Always trust the Docker-reported
            # PublishedPort.
            host_port = _resolve_runtime_port(challenge_dir)
            if host_port is None:
                result.error = "could not resolve published host port after docker compose up"
                return result
            target_url = f"http://127.0.0.1:{host_port}"
            # Belt-and-braces safety: refuse to point the agent at the API itself.
            api_port_in_base_url = urlparse(base_url).port
            if api_port_in_base_url is not None and host_port == api_port_in_base_url:
                result.error = (
                    f"challenge published port {host_port} collides with the AegisPT API "
                    f"({base_url}); refusing to drive the agent against the harness itself"
                )
                return result
            result.notes.append(f"target_url={target_url}")
            # Default client timeout is 1800s — matches the iterate-call
            # explicit override (d5cccea). Empirical 2026-05-27 smoke 47a/b/c:
            # the wrapper crashed at exactly 641s on the GET /runs/{id} poll
            # call when the API server was busy in a synchronous critic-
            # revision cycle. The wrapper-side reachability budget must
            # exceed any one heavy-LLM iterate cycle. v6 (2026-05-22) had
            # the same root cause at 220s.
            with httpx.Client(base_url=base_url.rstrip("/"), timeout=1800.0) as client:
                # Phase 4: source-aware mode points the picker at the
                # XBEN challenge's app/ folder (the running container's
                # source). When --source-aware is OFF (default), source_dir
                # is None and the orchestrator stays in network-only mode.
                source_dir_arg: str | None = None
                if source_aware:
                    # XBOW challenges scatter source under different names:
                    # XBEN-002 uses app/, XBEN-010 uses src/, others use code/.
                    # Try the conventional names in order; first hit wins. If
                    # none match, fall back to ANY first-level dir that contains
                    # a Dockerfile (the build-context is almost always source).
                    candidates = [
                        challenge_dir / name for name in ("app", "src", "code")
                    ]
                    source_path = next((c for c in candidates if c.is_dir()), None)
                    if source_path is None:
                        for child in sorted(challenge_dir.iterdir()):
                            if child.is_dir() and (child / "Dockerfile").is_file():
                                source_path = child
                                break
                    if source_path is not None:
                        source_dir_arg = str(source_path)
                        result.notes.append(f"source_aware=on source_dir={source_dir_arg}")
                    else:
                        result.notes.append(
                            f"source_aware=on but no app/src/code or Dockerfile-bearing dir in {challenge_dir}; skipping"
                        )
                run = _register_run(
                    client,
                    actor=actor,
                    target_url=target_url,
                    challenge_id=challenge_id,
                    profile_name=profile_name,
                    llm_provider=llm_provider,
                    source_dir=source_dir_arg,
                    m1_max_revisions=m1_max_revisions,
                    m6_cross_model_critic=m6_cross_model_critic,
                )
                result.run_id = run.get("id")
                run = grant_required_approvals(
                    client,
                    run=run,
                    scenario={"approval_actors": [f"{actor}-approver-1"]},
                    actor=actor,
                )
                try:
                    dispatch_resp = client.post(
                        f"/api/v1/runs/{run['id']}/dispatch",
                        headers=api_headers(actor),
                    )
                    dispatch_resp.raise_for_status()
                    dispatch_mode = str(dispatch_resp.json().get("dispatch_mode") or "manual")
                except httpx.HTTPStatusError as exc:
                    # Some configs autodispatch — tolerate 409 / 400 from explicit dispatch.
                    dispatch_mode = "inline"
                    result.notes.append(f"explicit-dispatch returned {exc.response.status_code}; assuming inline")
                # Drive the AI loop autonomously: /iterate until picker says stop
                # OR run reaches terminal. WITHOUT this, the profile's seed tasks
                # run once and the run completes with only target-intel — no
                # actual agent attempt.
                loop_state = _drive_ai_loop(
                    client,
                    actor=actor,
                    run_id=run["id"],
                    max_iterations=int(wait_seconds // max(poll_interval, 1.0)) or 30,
                    poll_interval=poll_interval,
                    deadline_seconds=wait_seconds,
                )
                result.loop_iterations = int(loop_state.get("loop_driver_iterations") or 0)
                result.loop_stop_reason = str(loop_state.get("stop_reason") or "")
                # When the AI loop emits a stop_reason, treat that as end-of-attempt
                # — the run-status auto-transition is a separate concern (the AI
                # loop status IS the agent's done-signal). Only fall back to the
                # terminal-poll when the loop driver returned without a stop_reason
                # (e.g. driver hit its own deadline).
                if not result.loop_stop_reason:
                    try:
                        run = wait_for_terminal_run(
                            client,
                            run_id=run["id"],
                            actor=actor,
                            dispatch_mode=dispatch_mode,
                            wait_seconds=min(60, wait_seconds),
                            poll_interval=poll_interval,
                        )
                    except TimeoutError:
                        run_resp = client.get(f"/api/v1/runs/{run['id']}", headers=api_headers(actor))
                        run = run_resp.json() if run_resp.status_code == 200 else run
                else:
                    run_resp = client.get(f"/api/v1/runs/{run['id']}", headers=api_headers(actor))
                    run = run_resp.json() if run_resp.status_code == 200 else run
                result.run_status = run.get("status")
                # Belt-and-braces: never abandon a run in non-terminal state.
                # If the picker stopped without the auto-finalizer kicking in
                # (older API revisions), OR if our driver hit its deadline
                # before the picker emitted STOP, force-terminate via the
                # existing /cancel endpoint. Without this, the harness leaks
                # "running" rows across batches — exactly the 34-orphan
                # pattern we just cleaned up.
                if str(result.run_status or "").lower() not in TERMINAL_STATUSES:
                    try:
                        cancel_resp = client.post(
                            f"/api/v1/runs/{run['id']}/cancel",
                            headers=api_headers(actor),
                            timeout=30.0,
                        )
                        if cancel_resp.status_code == 200:
                            run = cancel_resp.json()
                            result.run_status = run.get("status")
                            result.notes.append("harness-finalized via /cancel (non-terminal at abandon)")
                        else:
                            result.notes.append(
                                f"finalize attempt returned {cancel_resp.status_code}: "
                                + cancel_resp.text[:120]
                            )
                    except httpx.HTTPError as exc:
                        result.notes.append(f"finalize cancel failed: {exc}")
                hits = _scan_for_flag(client, actor, run["id"], flag)
                result.flag_found_in = hits
                result.solved = bool(hits)
                metrics = _aggregate_metrics(client, actor, run["id"])
                result.exec_plan_dispatches = metrics["exec_plan_dispatches"]
                result.exec_plan_successful = metrics["exec_plan_successful"]
                result.refinement_attempts = metrics["refinement_attempts"]
                result.finding_count = metrics["finding_count"]
                result.tool_chain_length = metrics["tool_chain_length"]
    except subprocess.TimeoutExpired as exc:
        result.error = f"subprocess timeout: {exc.cmd!r}"
    except RuntimeError as exc:
        msg = str(exc)
        # Pad-1 reliability classification: distinguish known
        # infra-skip reasons from actual harness crashes. These
        # challenges never reached the AI loop and should not
        # weigh on the solve-rate denominator the same way crashes do.
        if msg.startswith("PLATFORM_INCOMPATIBLE"):
            result.skipped_reason = msg[:300]
        elif msg.startswith("BUILDX_MISSING"):
            result.skipped_reason = msg[:300]
        elif msg.startswith("REGISTRY_DNS"):
            result.skipped_reason = msg[:300]
        else:
            result.error = msg[:600]
    except httpx.HTTPError as exc:
        result.error = f"API call failed: {exc}"[:600]
    except Exception as exc:  # noqa: BLE001
        result.error = f"unexpected: {type(exc).__name__}: {exc}"[:600]
    finally:
        result.time_to_solve_sec = round(time.time() - started, 1)
    return result


def _write_report(results: list[ChallengeResult], *, phase: str, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    today = datetime.now(UTC).strftime("%Y-%m-%d")
    md_path = out_dir / f"xbow-{today}-{phase}.md"
    json_path = out_dir / f"xbow-{today}-{phase}.json"

    solved = [r for r in results if r.solved]
    ran = [r for r in results if not r.skipped_reason]
    crashed = [r for r in results if r.error]
    skipped = [r for r in results if r.skipped_reason]
    total = len(results)

    score_line = (
        f"**Baseline: {len(solved)}/{total} solved "
        f"({100.0 * len(solved) / total:.1f}%)** "
        f"— {len(ran)} ran, {len(crashed)} crashed, {len(skipped)} skipped"
    ) if total else "**No challenges ran**"

    lines: list[str] = [
        f"# XBOW baseline — phase `{phase}` — {today}",
        "",
        score_line,
        "",
        "## Per-challenge results",
        "",
        "| Challenge | Solved | Status | Time (s) | Tools | Loop iters | Findings | exec_plan ok/total | Flag location |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for r in results:
        solved_mark = "yes" if r.solved else ("crash" if r.error else ("skip" if r.skipped_reason else "no"))
        status_cell = r.run_status or r.error or r.skipped_reason or "-"
        exec_plan_cell = f"{r.exec_plan_successful}/{r.exec_plan_dispatches}"
        flag_loc = ",".join(r.flag_found_in) if r.flag_found_in else "-"
        lines.append(
            f"| {r.challenge_id} | {solved_mark} | {status_cell[:60]} | {r.time_to_solve_sec} | "
            f"{r.tool_chain_length} | {r.loop_iterations} | {r.finding_count} | {exec_plan_cell} | {flag_loc} |"
        )

    lines += [
        "",
        "## Notes",
        "",
        "- The score is a baseline measurement; per backlog-408 (ANTI_DRIFT Rule 1) a low score is acceptable — the deliverable is the harness running end-to-end and producing the number.",
        "- Each challenge built with a randomly-generated FLAG (no challenge-specific solutions embedded in this harness).",
        "- Anti-contamination guard active: AegisPT memory root was isolated to a benchmark-only directory throughout the run.",
        "- Cleanup: every challenge issues `docker compose down -v` regardless of outcome.",
        "",
    ]
    md_path.write_text("\n".join(lines), encoding="utf-8")
    json_path.write_text(
        json.dumps(
            {
                "phase": phase,
                "date": today,
                "total_challenges": total,
                "solved": len(solved),
                "crashed": len(crashed),
                "skipped": len(skipped),
                "score_pct": round(100.0 * len(solved) / total, 2) if total else None,
                "results": [asdict(r) for r in results],
            },
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    return md_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="XBOW baseline harness for AegisPT (backlog-408)")
    parser.add_argument("--xbow-repo", required=True, type=Path, help="Path to KeygraphHQ/xbow-validation-benchmarks clone.")
    parser.add_argument("--base-url", default="http://127.0.0.1:8000", help="AegisPT API base URL.")
    parser.add_argument("--actor", default="xbow-harness", help="Actor identity for API calls.")
    parser.add_argument("--profile", default=DEFAULT_PROFILE_NAME, help="Run profile name (must be autonomous-intrusive).")
    parser.add_argument("--phase", default="baseline", help="Phase label (baseline/iter1/...).")
    parser.add_argument("--memory-root", required=True, type=Path, help="Isolated AEGISPT_MEMORY_ROOT for the benchmark.")
    parser.add_argument("--target", default="all", help="Comma-separated XBEN-NNN-YY ids OR 'all'.")
    parser.add_argument("--max-challenges", type=int, default=0, help="Cap total challenges run (0 = no cap).")
    parser.add_argument("--wait-seconds", type=int, default=1200, help="Per-challenge poll budget (default 20 min).")
    parser.add_argument("--poll-interval", type=float, default=10.0, help="Run-status poll interval.")
    parser.add_argument("--build-timeout", type=float, default=900.0, help="Docker compose build timeout (sec). mysql/postgres image pulls can need 600+; default 900.")
    parser.add_argument("--up-timeout", type=float, default=300.0, help="Docker compose up --wait timeout (sec); db healthchecks can need 120-300.")
    parser.add_argument("--out-dir", default=str(REPO_ROOT / "docs" / "validation"), help="Report output dir.")
    parser.add_argument("--log-level", default="INFO")
    parser.add_argument(
        "--llm-provider",
        default=None,
        help="Override picker LLM provider (e.g. claude-opus-4-7, chatgpt_oauth, gpt-5.4). "
             "Default = whatever the run-config / KNOWN_PROVIDERS resolves to.",
    )
    parser.add_argument(
        "--source-aware",
        action="store_true",
        help=(
            "Enable Shannon-style white-box source audit (Phase 4 2026-05-22). "
            "Sets source_dir=<challenge_dir>/app in the run config so the picker "
            "dispatches pre-recon-source BEFORE network recon. Use ONLY when the "
            "engagement explicitly authorises source-aware testing — XBOW source-aware "
            "score-board is measured separately from black-box."
        ),
    )
    parser.add_argument(
        "--m1-max-revisions",
        type=int,
        default=1,
        help=(
            "M4 multi-trajectory cap — max script_critic revisions per failed "
            "code-exec-attack predecessor (default 1 = M1 baseline). At 3, the "
            "critic gets to try 3 different revisions before giving up on a "
            "predecessor."
        ),
    )
    parser.add_argument(
        "--m6-cross-model-critic",
        action="store_true",
        help=(
            "M6 v1 — run the script_critic on the OPPOSITE provider from the "
            "picker (e.g. picker=chatgpt-oauth → critic=Anthropic) when both "
            "credentials are available. Adversarial cross-model review."
        ),
    )
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=args.log_level.upper(),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

    memory_root = args.memory_root.expanduser().resolve()
    _check_anti_contamination(memory_root)
    os.environ["AEGISPT_MEMORY_ROOT"] = str(memory_root)
    logger.info("anti-contamination: AEGISPT_MEMORY_ROOT pinned to %s", memory_root)

    if shutil.which("docker") is None:
        raise SystemExit("docker CLI not found on PATH; install Docker before running this harness.")

    all_dirs = _discover_challenges(args.xbow_repo)
    if args.target.lower() != "all":
        wanted = {t.strip() for t in args.target.split(",") if t.strip()}
        all_dirs = [d for d in all_dirs if d.name in wanted]
    if args.max_challenges > 0:
        all_dirs = all_dirs[: args.max_challenges]
    if not all_dirs:
        raise SystemExit("No challenges matched the --target filter.")

    logger.info("xbow baseline harness — %d challenges queued", len(all_dirs))

    results: list[ChallengeResult] = []
    for i, challenge_dir in enumerate(all_dirs, start=1):
        logger.info("[%d/%d] %s", i, len(all_dirs), challenge_dir.name)
        result = _run_one_challenge(
            challenge_dir,
            base_url=args.base_url,
            actor=args.actor,
            profile_name=args.profile,
            wait_seconds=args.wait_seconds,
            poll_interval=args.poll_interval,
            build_timeout=args.build_timeout,
            up_timeout=args.up_timeout,
            llm_provider=args.llm_provider,
            source_aware=args.source_aware,
            m1_max_revisions=args.m1_max_revisions,
            m6_cross_model_critic=args.m6_cross_model_critic,
        )
        results.append(result)
        verdict = "SOLVED" if result.solved else ("CRASH" if result.error else ("SKIP" if result.skipped_reason else "no-flag"))
        logger.info(
            "[%d/%d] %s -> %s (%.1fs, %d findings, run_status=%s)",
            i, len(all_dirs), challenge_dir.name, verdict, result.time_to_solve_sec,
            result.finding_count, result.run_status,
        )

    out_dir = Path(args.out_dir).expanduser().resolve()
    md_path = _write_report(results, phase=args.phase, out_dir=out_dir)
    logger.info("wrote baseline report to %s", md_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
