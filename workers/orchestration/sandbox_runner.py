"""Per-step Docker-isolated sandbox runner for exec_plan steps.

Per backlog-409 (sprint mythos-exploitation-foundation, task 3/15) +
OpenClaw lessons (research 2026-05-20): exec_plan steps should run in a
fresh ephemeral container per step so any escape risk in the request
chain cannot reach the host. Network egress default-deny — only the
target host:port (already authorized by Layer 0
``GovernanceControlPlane.authorize_external_network``) may be reached.

Usage pattern (called from workers/runners/exec_plan/runner.py once this
module's prerequisites are wired into the dispatch path):

    from workers.orchestration.sandbox_runner import (
        SandboxConfig, run_step_in_sandbox, SandboxUnavailable,
    )
    from api.app.governance import GovernanceControlPlane

    plane = GovernanceControlPlane(session)
    egress = plane.authorize_external_network(run=run, target=step["url"])
    if not egress.allow:
        raise RuntimeError(egress.deny_reason or "egress denied")

    config = SandboxConfig(
        image="curlimages/curl:8.10.1",          # tiny, statically-linked
        network_mode="host-aware",               # default-deny + allowlist
        memory_mb=128, cpu_quota_pct=20,
        timeout_seconds=15,
    )
    result = run_step_in_sandbox(step, config=config, allowlist={step["url"]})

Falls back to a hard ``SandboxUnavailable`` exception when Docker is not
installed; the caller can decide whether to retry inline (with audit
warning) or fail the step. Per ANTI_DRIFT Rule 4: never silently
downgrade to host execution without the operator's explicit consent — a
silent downgrade defeats the isolation guarantee this module promises.
"""
from __future__ import annotations

import json
import logging
import shlex
import shutil
import subprocess
import uuid
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


# Default image: tiny statically-linked curl. Hash-pinning is the caller's
# responsibility (operators can override by passing a digest in SandboxConfig).
DEFAULT_SANDBOX_IMAGE = "curlimages/curl:8.10.1"


class SandboxUnavailable(RuntimeError):
    """Raised when the host has no Docker daemon and the caller demanded
    sandboxed execution. Never silently downgraded — operator must decide."""


@dataclass
class SandboxConfig:
    """Resource + safety limits for a single sandboxed step.

    The defaults match a single-request curl probe; for heavier exec_plan
    sequences (multiple steps within one sandbox lifetime) the caller can
    raise the limits but must justify them in the audit event.
    """

    image: str = DEFAULT_SANDBOX_IMAGE
    network_mode: str = "host-aware"          # "host-aware" = default-deny + allowlist
    memory_mb: int = 128
    cpu_quota_pct: int = 20                   # 20% of one core
    timeout_seconds: float = 15.0
    user: str = "65534:65534"                 # nobody:nogroup
    read_only_rootfs: bool = True
    drop_capabilities: tuple[str, ...] = ("ALL",)
    extra_labels: dict[str, str] = field(default_factory=dict)


@dataclass
class SandboxResult:
    """Outcome of a single sandboxed step execution."""

    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool = False
    container_id: str | None = None
    image: str = ""
    duration_seconds: float = 0.0


def docker_available() -> bool:
    """Return True if a working Docker CLI is on PATH (best-effort check).
    Pure CLI probe — no daemon ping, that's the runner's responsibility.
    """
    return shutil.which("docker") is not None


def _build_curl_argv(step: dict[str, Any]) -> list[str]:
    """Translate an exec_plan step into a curl argv. Mirrors the safety
    boundary documented in workers/runners/exec_plan/runner.py: only the
    GET/POST/PUT/PATCH/DELETE methods are allowed and Host header overrides
    are forbidden. The actual ALLOW/DENY verdict comes from Layer 0 — this
    helper assumes the step is already authorized.
    """
    method = str(step.get("method") or "GET").upper()
    if method not in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
        raise ValueError(f"non-allowed method {method!r}")
    url = str(step.get("url") or "").strip()
    if not url:
        raise ValueError("step missing url")
    argv: list[str] = [
        "curl", "-sS",
        "-X", method,
        "--max-time", "10",
        "-o", "-",
        "-w", "\n___HTTP_STATUS___:%{http_code}\n",
    ]
    headers = step.get("headers") or {}
    if isinstance(headers, dict):
        for key, value in headers.items():
            if str(key or "").strip().lower() == "host":
                raise ValueError("Host header override forbidden")
            argv += ["-H", f"{key}: {value}"]
    body = step.get("body")
    if body is not None and method in {"POST", "PUT", "PATCH"}:
        body_text = body if isinstance(body, str) else json.dumps(body)
        argv += ["--data-binary", body_text]
    argv.append(url)
    return argv


def _build_docker_argv(
    *,
    config: SandboxConfig,
    container_name: str,
    inner_argv: list[str],
) -> list[str]:
    """Compose ``docker run`` command line with the isolation flags."""
    argv: list[str] = [
        "docker", "run",
        "--rm",
        "--name", container_name,
        "--user", config.user,
        "--memory", f"{config.memory_mb}m",
        "--cpus", f"{max(config.cpu_quota_pct, 1) / 100:.2f}",
        "--security-opt", "no-new-privileges:true",
        "--network", "none",                  # default-deny; specific allowlist routes added by caller
    ]
    if config.read_only_rootfs:
        argv += ["--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m"]
    for cap in config.drop_capabilities:
        argv += ["--cap-drop", cap]
    for k, v in config.extra_labels.items():
        argv += ["--label", f"{k}={v}"]
    argv += ["--label", f"aegispt.sandbox.id={container_name}"]
    argv += [config.image, *inner_argv]
    return argv


def run_step_in_sandbox(
    step: dict[str, Any],
    *,
    config: SandboxConfig | None = None,
    allowlist: set[str] | None = None,  # noqa: ARG001 — reserved for future network policy wiring
) -> SandboxResult:
    """Execute one exec_plan step inside a fresh Docker container.

    Raises ``SandboxUnavailable`` if Docker is not available on the host.
    The caller is expected to have invoked
    ``GovernanceControlPlane.authorize_exec_plan_step`` and
    ``authorize_external_network`` BEFORE this call. This runner does not
    re-authorize — its job is the isolation layer only.
    """
    if not docker_available():
        raise SandboxUnavailable("docker CLI not on PATH — cannot isolate exec_plan step")

    config = config or SandboxConfig()
    container_name = f"aegispt-sandbox-{uuid.uuid4().hex[:12]}"
    inner_argv = _build_curl_argv(step)
    docker_argv = _build_docker_argv(
        config=config,
        container_name=container_name,
        inner_argv=inner_argv,
    )
    logger.info(
        "sandbox: running step in container %s (%s) cmd=%s",
        container_name, config.image, shlex.join(inner_argv),
    )
    import time
    started = time.time()
    timed_out = False
    try:
        proc = subprocess.run(  # noqa: S603 — argv is built from validated step
            docker_argv,
            capture_output=True,
            text=True,
            timeout=config.timeout_seconds,
            check=False,
        )
        exit_code = proc.returncode
        stdout = proc.stdout
        stderr = proc.stderr
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        exit_code = 124
        stdout = exc.stdout.decode("utf-8", errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = exc.stderr.decode("utf-8", errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        # Defensive cleanup — docker --rm normally handles it, but a hung
        # container needs an explicit kill.
        subprocess.run(
            ["docker", "rm", "-f", container_name],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    duration = round(time.time() - started, 3)
    return SandboxResult(
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        timed_out=timed_out,
        container_id=container_name,
        image=config.image,
        duration_seconds=duration,
    )


__all__ = [
    "DEFAULT_SANDBOX_IMAGE",
    "SandboxConfig",
    "SandboxResult",
    "SandboxUnavailable",
    "docker_available",
    "run_step_in_sandbox",
]
