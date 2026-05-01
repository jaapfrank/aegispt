from __future__ import annotations

import json
from pathlib import Path

import pytest

from workers.orchestration.findings import extract_findings
from workers.runners.base.contracts import EvidenceArtifact
from workers.runners.impacket.remote_exec import (
    BOUNDED_REMOTE_COMMAND,
    build_remote_exec_command,
)
from workers.runners.impacket.runner import (
    IMPACKET_LOG_ARTIFACT_NAME,
    IMPACKET_RESULTS_ARTIFACT_NAME,
    execute_impacket_lateral,
)


def _write_fake_secretsdump_binary(tmp_path: Path, *, wait_forever: bool = False) -> str:
    script_path = tmp_path / "fake_secretsdump.py"
    if wait_forever:
        script_path.write_text(
            ("#!/usr/bin/env python3\n" "import time\n" "while True:\n" "    time.sleep(0.1)\n"),
            encoding="utf-8",
        )
    else:
        script_path.write_text(
            (
                "#!/usr/bin/env python3\n"
                "import sys\n"
                "if '-just-dc-user' in sys.argv:\n"
                "    sys.stdout.write('krbtgt:502:aad3b435b51404eeaad3b435b51404ee:11223344556677889900aabbccddeeff:::\\n')\n"
                "else:\n"
                "    sys.stdout.write('Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::\\n')\n"
            ),
            encoding="utf-8",
        )
    script_path.chmod(0o755)
    return str(script_path)


def _write_fake_remote_exec_binary(tmp_path: Path, name: str) -> str:
    script_path = tmp_path / name
    script_path.write_text(
        (
            "#!/usr/bin/env python3\n"
            "import sys\n"
            "command = sys.argv[-1]\n"
            f"expected = {BOUNDED_REMOTE_COMMAND!r}\n"
            "if command != expected:\n"
            "    sys.stderr.write(f'unexpected command: {command}\\n')\n"
            "    sys.exit(2)\n"
            "sys.stdout.write('CORP\\\\backup-admin\\nFS01\\n')\n"
        ),
        encoding="utf-8",
    )
    script_path.chmod(0o755)
    return str(script_path)


def test_build_remote_exec_command_stays_bounded_to_whoami_and_hostname() -> None:
    command = build_remote_exec_command(
        "psexec.py",
        method="psexec",
        target="10.0.20.25",
        auth_context={
            "username": "backup-admin",
            "domain": "CORP",
            "ntlm_hash": "31d6cfe0d16ae931b73c59d7e0c089c0",
        },
    )

    assert command[:3] == [
        "psexec.py",
        "-hashes",
        "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
    ]
    assert command[-1] == BOUNDED_REMOTE_COMMAND


def test_impacket_secretsdump_runner_stores_hashes_only_in_protected_output(tmp_path: Path) -> None:
    binary = _write_fake_secretsdump_binary(tmp_path)
    raw_hash = "31d6cfe0d16ae931b73c59d7e0c089c0"

    execution = execute_impacket_lateral(
        ["10.0.20.25"],
        mode="secretsdump",
        auth_contexts=[
            {
                "label": "Backup Admin",
                "username": "backup-admin",
                "domain": "CORP",
                "password": "Winter2026!",
            }
        ],
        scope_allowlist={"hosts": ["10.0.20.25"]},
        secretsdump_binary=binary,
    )

    assert execution.tool == "impacket-lateral"
    assert execution.exit_code == 0
    assert execution.protected_outputs
    protected_output = execution.protected_outputs[0]
    assert protected_output.secret_kind == "impacket_hash_bundle"
    assert raw_hash in protected_output.value

    results_artifact = next(
        artifact
        for artifact in execution.artifacts
        if artifact.name == IMPACKET_RESULTS_ARTIFACT_NAME
    )
    payload = json.loads(results_artifact.data.decode("utf-8"))
    target = payload["targets"][0]
    assert target["extracted_account_count"] == 1
    assert raw_hash not in json.dumps(target)

    task = type(
        "TaskStub", (), {"tool": "impacket-lateral", "target_id": "10.0.20.25", "params_json": {}}
    )()
    artifact_record = type("ArtifactRecord", (), {"uri": "artifact://impacket/results"})()
    findings = extract_findings(
        task=task,
        artifact=EvidenceArtifact(
            name=IMPACKET_RESULTS_ARTIFACT_NAME,
            content_type="application/json",
            data=results_artifact.data,
            kind="impacket-results",
        ),
        artifact_record=artifact_record,
    )
    assert {finding.title for finding in findings} == {
        "Credential extraction confirmed on 10.0.20.25"
    }

    log_artifact = next(
        artifact for artifact in execution.artifacts if artifact.name == IMPACKET_LOG_ARTIFACT_NAME
    )
    log_text = log_artifact.data.decode("utf-8")
    assert raw_hash not in log_text
    assert "Winter2026!" not in log_text


def test_impacket_remote_exec_runner_executes_only_bounded_command(tmp_path: Path) -> None:
    psexec_binary = _write_fake_remote_exec_binary(tmp_path, "fake_psexec.py")

    execution = execute_impacket_lateral(
        ["10.0.20.25"],
        mode="remote_exec",
        remote_exec_method="psexec",
        auth_contexts=[
            {
                "label": "Backup Admin",
                "username": "backup-admin",
                "domain": "CORP",
                "ntlm_hash": "31d6cfe0d16ae931b73c59d7e0c089c0",
            }
        ],
        scope_allowlist={"hosts": ["10.0.20.25"]},
        psexec_binary=psexec_binary,
    )

    assert execution.exit_code == 0
    assert execution.metadata["no_destructive_execution"] is True
    assert not execution.protected_outputs

    results_artifact = next(
        artifact
        for artifact in execution.artifacts
        if artifact.name == IMPACKET_RESULTS_ARTIFACT_NAME
    )
    payload = json.loads(results_artifact.data.decode("utf-8"))
    target = payload["targets"][0]
    assert target["whoami"] == "CORP\\backup-admin"
    assert target["hostname"] == "FS01"
    assert target["bounded_command"] == BOUNDED_REMOTE_COMMAND


def test_impacket_dcsync_runner_stores_krbtgt_only_as_protected_output(tmp_path: Path) -> None:
    binary = _write_fake_secretsdump_binary(tmp_path)

    execution = execute_impacket_lateral(
        ["dc01.corp.example"],
        mode="dcsync",
        auth_contexts=[
            {
                "label": "Domain Admin",
                "username": "administrator",
                "domain": "CORP",
                "password": "Winter2026!",
            }
        ],
        scope_allowlist={"hosts": ["dc01.corp.example"]},
        secretsdump_binary=binary,
    )

    assert execution.exit_code == 0
    protected_output = execution.protected_outputs[0]
    assert protected_output.secret_kind == "dcsync_hash_bundle"
    assert "krbtgt" in protected_output.value

    results_artifact = next(
        artifact
        for artifact in execution.artifacts
        if artifact.name == IMPACKET_RESULTS_ARTIFACT_NAME
    )
    payload = json.loads(results_artifact.data.decode("utf-8"))
    target = payload["targets"][0]
    assert (
        target["analysis_findings"][0]["title"] == "Domain compromise confirmed — DCSync successful"
    )


def test_impacket_runner_kill_switch_terminates_process(tmp_path: Path) -> None:
    binary = _write_fake_secretsdump_binary(tmp_path, wait_forever=True)
    calls = {"count": 0}

    def kill_switch() -> bool:
        calls["count"] += 1
        return calls["count"] >= 2

    execution = execute_impacket_lateral(
        ["10.0.20.25"],
        mode="secretsdump",
        auth_contexts=[
            {
                "label": "Backup Admin",
                "username": "backup-admin",
                "domain": "CORP",
                "password": "Winter2026!",
            }
        ],
        scope_allowlist={"hosts": ["10.0.20.25"]},
        secretsdump_binary=binary,
        kill_switch_check=kill_switch,
    )

    assert execution.exit_code == 0
    assert execution.metadata["terminated_by_kill_switch"] is True
    assert execution.metadata["status"] == "cancelled"
