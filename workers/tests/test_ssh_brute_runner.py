from __future__ import annotations

import json
from types import SimpleNamespace

from workers.orchestration.findings import extract_findings
from workers.orchestration.tasks import SUPPORTED_TOOLS, dispatch_runner
from workers.runners.base.contracts import EvidenceArtifact, RunnerRequest
from workers.runners.ssh_brute.runner import (
    SSH_BRUTE_RESULTS_ARTIFACT_NAME,
    CommandResult,
    build_hydra_command,
    execute_ssh_brute_force,
)


class ArtifactRecord:
    uri = "artifact://ssh-brute/results"


def _payload(execution) -> dict:
    artifact = next(
        item for item in execution.artifacts if item.name == SSH_BRUTE_RESULTS_ARTIFACT_NAME
    )
    return json.loads(artifact.data.decode("utf-8"))


def test_hydra_command_is_single_pair_and_service_scoped() -> None:
    command = build_hydra_command(
        binary="hydra",
        host="10.0.20.10",
        port=2222,
        protocol="ssh",
        username="root",
        password="password",
    )

    assert command == [
        "hydra",
        "-I",
        "-l",
        "root",
        "-p",
        "password",
        "-s",
        "2222",
        "-t",
        "1",
        "-f",
        "10.0.20.10",
        "ssh",
    ]


def test_ssh_brute_detects_weak_credential_and_extracts_standard_finding() -> None:
    commands: list[list[str]] = []

    def fake_hydra(command: list[str], timeout_seconds: float) -> CommandResult:
        commands.append(command)
        return CommandResult(
            returncode=0,
            stdout="[2222][ssh] host: 10.0.20.10   login: root   password: password\n",
            stderr="",
        )

    execution = execute_ssh_brute_force(
        ["10.0.20.10:2222"],
        scope_allowlist={"hosts": ["10.0.20.10"]},
        usernames=["root", "admin"],
        hydra_binary="fake-hydra",
        hydra_executor=fake_hydra,
        sleep_func=lambda seconds: None,
    )
    payload = _payload(execution)

    assert execution.tool == "ssh-brute"
    assert execution.exit_code == 0
    assert payload["summary"]["finding_count"] == 1
    assert payload["safety"]["rate_limit_per_second"] == 5.0
    assert payload["safety"]["rockyou_used"] is False
    assert payload["targets"][0]["attempts"][0]["password"] == "[REDACTED]"
    assert payload["findings"][0]["severity"] == "critical"
    assert payload["findings"][0]["title"] == (
        "Weak Credential: SSH root:password on 10.0.20.10:2222"
    )
    assert commands[0][0] == "fake-hydra"
    assert commands[0][-1] == "ssh"
    assert execution.protected_outputs

    artifact = next(
        item for item in execution.artifacts if item.name == SSH_BRUTE_RESULTS_ARTIFACT_NAME
    )
    findings = extract_findings(
        task=SimpleNamespace(tool="ssh-brute", target_id="10.0.20.10", params_json={}),
        artifact=EvidenceArtifact(
            name=SSH_BRUTE_RESULTS_ARTIFACT_NAME,
            content_type="application/json",
            data=artifact.data,
            kind="runner-results",
        ),
        artifact_record=ArtifactRecord(),
    )

    assert findings
    assert findings[0].severity == "critical"
    assert findings[0].title == "Weak Credential: SSH root:password on 10.0.20.10:2222"
    assert "ssh-brute-validation" in findings[0].methodology_tags


def test_ssh_brute_stops_after_three_lockout_signals_and_rate_limits() -> None:
    sleep_calls: list[float] = []

    def fake_hydra(command: list[str], timeout_seconds: float) -> CommandResult:
        return CommandResult(returncode=1, stdout="", stderr="Account locked due to failures")

    execution = execute_ssh_brute_force(
        ["10.0.20.10"],
        scope_allowlist={"hosts": ["10.0.20.10"]},
        usernames=["root"],
        hydra_executor=fake_hydra,
        sleep_func=lambda seconds: sleep_calls.append(seconds),
        time_func=lambda: 0.0,
    )
    payload = _payload(execution)

    assert payload["summary"]["attempt_count"] == 3
    assert payload["summary"]["lockout_signal_count"] == 3
    assert payload["targets"][0]["status"] == "stopped"
    assert len(sleep_calls) == 2
    assert all(seconds >= 0.2 for seconds in sleep_calls)


def test_ssh_brute_dispatch_registration_uses_inventory_services(monkeypatch) -> None:
    assert "ssh-brute" in SUPPORTED_TOOLS

    captured: dict[str, object] = {}

    def fake_execute(targets: list[str], **kwargs):
        captured["targets"] = targets
        captured.update(kwargs)
        return execute_ssh_brute_force(
            targets,
            hydra_executor=lambda command, timeout_seconds: CommandResult(
                returncode=0,
                stdout="[21][ftp] host: 10.0.20.11   login: root   password: password\n",
                stderr="",
            ),
            sleep_func=lambda seconds: None,
            **kwargs,
        )

    import workers.orchestration.tasks as orchestration_tasks

    monkeypatch.setattr(orchestration_tasks, "execute_ssh_brute_force", fake_execute)

    execution = dispatch_runner(
        RunnerRequest(
            tool="ssh-brute",
            targets=["10.0.20.0/24"],
            params={
                "inventory": {"services": [{"host": "10.0.20.11", "port": 21, "service": "ftp"}]},
                "usernames": ["root"],
                "timeout_seconds": 5,
            },
            scope_allowlist={"cidr_ranges": ["10.0.20.0/24"]},
        )
    )

    assert execution.tool == "ssh-brute"
    assert captured["inventory"] == {
        "services": [{"host": "10.0.20.11", "port": 21, "service": "ftp"}]
    }
