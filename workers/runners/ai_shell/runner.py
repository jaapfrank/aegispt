from __future__ import annotations

import json
import os
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from api.app.services.ai_shell_safety import (
    AI_SHELL_DEFAULT_OUTPUT_CAP_CHARS,
    AI_SHELL_TOOL_ID,
    AiShellSafetyError,
    ai_shell_command_preview,
    build_ai_shell_ssh_command,
    normalize_ai_shell_params,
)
from workers.runners.base.contracts import EvidenceArtifact, RunnerExecution

AI_SHELL_RESULTS_ARTIFACT_NAME = "ai-shell-results.json"
AI_SHELL_RUNNER_DIGEST = "workers.ai_shell.runner:v1"
AI_SHELL_TOOL_VERSION = "ai-shell ssh-controlled v1"
DEFAULT_TIMEOUT_SECONDS = 30.0


@dataclass(frozen=True, slots=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False


CommandRunner = Callable[[list[str], float], CommandResult]
KillSwitchCheck = Callable[[], bool]


def _default_command_runner(command: list[str], timeout_seconds: float) -> CommandResult:
    try:
        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        return CommandResult(
            returncode=124,
            stdout=exc.stdout or "",
            stderr=exc.stderr or "ai-shell SSH command timed out",
            timed_out=True,
        )
    return CommandResult(
        returncode=process.returncode,
        stdout=process.stdout,
        stderr=process.stderr,
    )


def execute_ai_shell_command(
    *,
    targets: list[str],
    scope_allowlist: dict[str, Any] | None = None,
    command: str | None = None,
    via: str = "ssh",
    credentials_ref: str | None = None,
    username: str | None = None,
    ssh_port: int | None = None,
    output_cap_chars: int = AI_SHELL_DEFAULT_OUTPUT_CAP_CHARS,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    command_runner: CommandRunner | None = None,
    kill_switch_check: KillSwitchCheck | None = None,
    ssh_binary: str | None = None,
) -> RunnerExecution:
    proposed_target = next((str(target).strip() for target in targets if str(target).strip()), "")
    params = {
        "command": command,
        "via": via,
        "credentials_ref": credentials_ref,
        "username": username,
        "ssh_port": ssh_port,
        "output_cap_chars": output_cap_chars,
    }
    try:
        contract = normalize_ai_shell_params(
            params=params,
            proposed_target=proposed_target,
            scope_allowlist=scope_allowlist,
            require_runtime_scope=True,
        )
    except AiShellSafetyError as exc:
        return _blocked_execution(
            reason=exc.reason, message=str(exc), proposed_target=proposed_target
        )

    if kill_switch_check is not None and kill_switch_check():
        return _blocked_execution(
            reason="ai_shell_kill_switch",
            message="ai-shell execution is disabled by the engagement kill switch",
            proposed_target=contract.target,
            command_sha256=contract.command_sha256,
        )

    binary = ssh_binary or os.getenv("SSH_BINARY", "ssh")
    ssh_command = build_ai_shell_ssh_command(contract=contract, ssh_binary=binary)
    runner = command_runner or _default_command_runner
    result = runner(ssh_command, max(float(timeout_seconds), 1.0))
    stdout, stdout_truncated = _cap_text(result.stdout, contract.output_cap_chars)
    stderr, stderr_truncated = _cap_text(result.stderr, contract.output_cap_chars)
    status = (
        "timeout" if result.timed_out else ("completed" if result.returncode == 0 else "failed")
    )
    payload = {
        "kind": "ai_shell_results",
        "status": status,
        "target": contract.target,
        "via": contract.via,
        "ssh_port": contract.ssh_port,
        "credentials_ref": contract.credentials_ref,
        "command": contract.command,
        "command_sha256": contract.command_sha256,
        "exit_code": result.returncode,
        "stdout": stdout,
        "stderr": stderr,
        "stdout_truncated": stdout_truncated,
        "stderr_truncated": stderr_truncated,
        "output_cap_chars": contract.output_cap_chars,
        "ssh_preview": ai_shell_command_preview(contract=contract, ssh_binary=binary),
        "safety": {
            "ssh_only": True,
            "per_command_approval_required": True,
            "aegispt_host_execution_blocked": True,
            "banned_command_patterns_enforced": True,
            "scope_checked": True,
        },
    }
    return RunnerExecution(
        tool=AI_SHELL_TOOL_ID,
        exit_code=result.returncode,
        stdout=stdout,
        stderr=stderr,
        metadata={
            "status": status,
            "tool_version": AI_SHELL_TOOL_VERSION,
            "runner_digest": AI_SHELL_RUNNER_DIGEST,
            "command_sha256": contract.command_sha256,
            "output_cap_chars": contract.output_cap_chars,
            "stdout_truncated": stdout_truncated,
            "stderr_truncated": stderr_truncated,
            "timeout": result.timed_out,
        },
        artifacts=[_json_artifact(payload)],
    )


def _blocked_execution(
    *,
    reason: str,
    message: str,
    proposed_target: str,
    command_sha256: str | None = None,
) -> RunnerExecution:
    payload = {
        "kind": "ai_shell_results",
        "status": "blocked",
        "target": proposed_target,
        "reason": reason,
        "message": message,
        "command_sha256": command_sha256,
        "safety": {
            "ssh_only": True,
            "per_command_approval_required": True,
            "scope_checked": True,
            "blocked_before_execution": True,
        },
    }
    return RunnerExecution(
        tool=AI_SHELL_TOOL_ID,
        exit_code=1,
        stdout="",
        stderr=message,
        metadata={
            "status": "blocked",
            "reason": reason,
            "tool_version": AI_SHELL_TOOL_VERSION,
            "runner_digest": AI_SHELL_RUNNER_DIGEST,
            **({"command_sha256": command_sha256} if command_sha256 else {}),
        },
        artifacts=[_json_artifact(payload)],
    )


def _cap_text(value: str | None, cap: int) -> tuple[str, bool]:
    text = str(value or "")
    if len(text) <= cap:
        return text, False
    return text[:cap], True


def _json_artifact(payload: dict[str, Any]) -> EvidenceArtifact:
    return EvidenceArtifact(
        name=AI_SHELL_RESULTS_ARTIFACT_NAME,
        content_type="application/json",
        data=(json.dumps(payload, sort_keys=True) + "\n").encode("utf-8"),
        kind="runner-results",
    )
