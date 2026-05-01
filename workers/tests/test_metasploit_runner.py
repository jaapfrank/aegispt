from __future__ import annotations

import json

import pytest

from workers.orchestration.findings import extract_findings
from workers.runners.base.contracts import EvidenceArtifact
from workers.runners.metasploit.runner import (
    METASPLOIT_LOG_ARTIFACT_NAME,
    METASPLOIT_RESULTS_ARTIFACT_NAME,
    build_msfrpcd_command,
    execute_metasploit_exploit,
)


class FakeMetasploitRpcClient:
    def __init__(
        self,
        *,
        base_url: str,
        username: str,
        password: str,
        verify_ssl: bool = False,
        timeout_seconds: float = 10.0,
        kill_switch=None,
    ) -> None:
        self.base_url = base_url
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.timeout_seconds = timeout_seconds
        self.kill_switch = kill_switch
        self.calls: list[tuple[str, tuple[object, ...]]] = []
        self.logged_in = False
        self.exploit_started = False
        self.last_meterpreter_command = ""
        self.session_stopped: list[str] = []
        self.jobs_stopped: list[str] = []
        self.core_stopped = False

    def close(self) -> None:
        return None

    def login(self) -> str:
        self.logged_in = True
        return "token"

    def call(self, method: str, *params: object) -> dict[str, object]:
        self.calls.append((method, params))
        if method == "session.list":
            if self.exploit_started and "1" not in self.session_stopped:
                return {
                    "1": {
                        "type": "meterpreter",
                        "target_host": "10.0.20.25",
                        "username": "CORP\\backup-admin",
                        "session_host": "FS01.corp.example",
                    }
                }
            return {}
        if method == "module.execute":
            module_name = str(params[1])
            if module_name == "windows/smb/psexec":
                self.exploit_started = True
                return {"job_id": 10}
            return {"job_id": 5}
        if method == "job.list":
            return {}
        if method == "session.meterpreter_run_single":
            self.last_meterpreter_command = str(params[1])
            return {"result": "success"}
        if method == "session.meterpreter_read":
            if self.last_meterpreter_command == "getuid":
                return {"data": "Server username: CORP\\backup-admin"}
            if self.last_meterpreter_command == "sysinfo":
                return {"data": "Computer : FS01"}
            if self.last_meterpreter_command == "shell whoami /groups":
                return {"data": "BUILTIN\\Administrators"}
            return {"data": ""}
        if method == "session.stop":
            self.session_stopped.append(str(params[0]))
            return {"result": "success"}
        if method == "job.stop":
            self.jobs_stopped.append(str(params[0]))
            return {"result": "success"}
        if method == "core.stop":
            self.core_stopped = True
            return {"result": "success"}
        return {"result": "success"}


def test_build_msfrpcd_command_uses_loopback_rpc_endpoint() -> None:
    command = build_msfrpcd_command(
        "msfrpcd",
        rpc_url="http://127.0.0.1:55553/api/1.0",
        username="aegispt",
        password="secret",
    )

    assert command == [
        "msfrpcd",
        "-U",
        "aegispt",
        "-P",
        "secret",
        "-a",
        "127.0.0.1",
        "-p",
        "55553",
        "-S",
        "false",
        "-f",
    ]


def test_metasploit_runner_rejects_unmatched_findings_and_non_loopback_lhost() -> None:
    with pytest.raises(ValueError, match="No curated Metasploit module matches"):
        execute_metasploit_exploit(
            ["10.0.20.25"],
            source_finding={
                "title": "Weak password policy signals observed",
                "target_id": "10.0.20.25",
                "summary": "Policy issue only",
                "methodology_tags": ["authentication"],
            },
            rpc_username="user",
            rpc_password="pass",
            start_rpc_daemon=False,
            rpc_client_factory=FakeMetasploitRpcClient,
            scope_allowlist={"hosts": ["10.0.20.25"]},
        )

    with pytest.raises(ValueError, match="LHOST must stay on loopback"):
        execute_metasploit_exploit(
            ["10.0.20.25"],
            source_finding={
                "title": "Pass-the-hash SMB access succeeded on 10.0.20.25",
                "target_id": "10.0.20.25",
                "summary": "Pass-the-hash validated over SMB.",
                "methodology_tags": ["smb", "pass_the_hash"],
            },
            auth_contexts=[
                {
                    "username": "backup-admin",
                    "ntlm_hash": "31d6cfe0d16ae931b73c59d7e0c089c0",
                }
            ],
            lhost="10.0.0.5",
            rpc_username="user",
            rpc_password="pass",
            start_rpc_daemon=False,
            rpc_client_factory=FakeMetasploitRpcClient,
            scope_allowlist={"hosts": ["10.0.20.25"]},
        )


def test_metasploit_runner_collects_protected_session_evidence_and_closes_session() -> None:
    created_clients: list[FakeMetasploitRpcClient] = []

    def client_factory(**kwargs):
        client = FakeMetasploitRpcClient(**kwargs)
        created_clients.append(client)
        return client

    execution = execute_metasploit_exploit(
        ["10.0.20.25"],
        source_finding={
            "title": "Pass-the-hash SMB access succeeded on 10.0.20.25",
            "target_id": "10.0.20.25",
            "summary": "Pass-the-hash validated over SMB.",
            "methodology_tags": ["smb", "pass_the_hash"],
        },
        auth_contexts=[
            {
                "label": "Backup Admin",
                "username": "backup-admin",
                "domain": "CORP",
                "ntlm_hash": "31d6cfe0d16ae931b73c59d7e0c089c0",
            }
        ],
        rpc_username="user",
        rpc_password="pass",
        start_rpc_daemon=False,
        rpc_client_factory=client_factory,
        scope_allowlist={"hosts": ["10.0.20.25"]},
    )

    assert execution.tool == "metasploit"
    assert execution.exit_code == 0
    assert execution.metadata["persistence_actions_performed"] is False
    assert execution.protected_outputs
    protected_output = execution.protected_outputs[0]
    assert protected_output.secret_kind == "metasploit_session_bundle"
    assert "BUILTIN\\\\Administrators" in protected_output.value

    results_artifact = next(
        artifact
        for artifact in execution.artifacts
        if artifact.name == METASPLOIT_RESULTS_ARTIFACT_NAME
    )
    payload = json.loads(results_artifact.data.decode("utf-8"))
    target = payload["targets"][0]
    assert target["confirmed_user"] == "CORP\\backup-admin"
    assert target["persistence_actions_performed"] is False
    assert target["analysis_findings"][0]["title"].startswith("Confirmed RCE")

    task = type(
        "TaskStub", (), {"tool": "metasploit", "target_id": "10.0.20.25", "params_json": {}}
    )()
    artifact_record = type("ArtifactRecord", (), {"uri": "artifact://metasploit/results"})()
    findings = extract_findings(
        task=task,
        artifact=EvidenceArtifact(
            name=METASPLOIT_RESULTS_ARTIFACT_NAME,
            content_type="application/json",
            data=results_artifact.data,
            kind="exploitation-results",
        ),
        artifact_record=artifact_record,
    )
    assert {finding.title for finding in findings} == {
        "Confirmed RCE — credentialed SMB remote code execution on 10.0.20.25 as CORP\\backup-admin"
    }

    log_artifact = next(
        artifact
        for artifact in execution.artifacts
        if artifact.name == METASPLOIT_LOG_ARTIFACT_NAME
    )
    log_text = log_artifact.data.decode("utf-8")
    assert "31d6cfe0d16ae931b73c59d7e0c089c0" not in log_text
    assert created_clients[0].session_stopped == ["1"]
    assert created_clients[0].core_stopped is True


def test_metasploit_runner_kill_switch_stops_job_session_and_rpc_core() -> None:
    created_clients: list[FakeMetasploitRpcClient] = []
    kill_calls = {"count": 0}

    def kill_switch() -> bool:
        kill_calls["count"] += 1
        return kill_calls["count"] >= 7

    def client_factory(**kwargs):
        client = FakeMetasploitRpcClient(**kwargs)
        created_clients.append(client)
        return client

    execution = execute_metasploit_exploit(
        ["10.0.20.25"],
        source_finding={
            "title": "Pass-the-hash SMB access succeeded on 10.0.20.25",
            "target_id": "10.0.20.25",
            "summary": "Pass-the-hash validated over SMB.",
            "methodology_tags": ["smb", "pass_the_hash"],
        },
        auth_contexts=[
            {
                "username": "backup-admin",
                "domain": "CORP",
                "ntlm_hash": "31d6cfe0d16ae931b73c59d7e0c089c0",
            }
        ],
        rpc_username="user",
        rpc_password="pass",
        start_rpc_daemon=False,
        rpc_client_factory=client_factory,
        scope_allowlist={"hosts": ["10.0.20.25"]},
        kill_switch_check=kill_switch,
    )

    assert execution.exit_code == 0
    assert execution.metadata["terminated_by_kill_switch"] is True
    assert execution.metadata["status"] == "cancelled"
    assert created_clients[0].jobs_stopped == ["10"]
    assert created_clients[0].session_stopped == ["1"]
    assert created_clients[0].core_stopped is True

    executed_modules = [
        params[1] for method, params in created_clients[0].calls if method == "module.execute"
    ]
    assert "post/windows/manage/persistence" not in executed_modules
