from __future__ import annotations

import json
from pathlib import Path

import pytest

from workers.orchestration.findings import extract_findings
from workers.runners.base.contracts import EvidenceArtifact
from workers.runners.netexec.runner import (
    NETEXEC_LOG_ARTIFACT_NAME,
    NETEXEC_RESULTS_ARTIFACT_NAME,
    build_netexec_command,
    execute_netexec_smb,
)


def _write_fake_netexec_binary(tmp_path: Path) -> str:
    script_path = tmp_path / "fake_nxc.py"
    script_path.write_text(
        (
            "#!/usr/bin/env python3\n"
            "import json\n"
            "import pathlib\n"
            "import sys\n"
            "\n"
            "if '--version' in sys.argv:\n"
            "    sys.stdout.write('nxc test 1.0\\n')\n"
            "    sys.exit(0)\n"
            "\n"
            "target = sys.argv[2]\n"
            "args = sys.argv[3:]\n"
            "host_record = {\n"
            "    'record_type': 'host',\n"
            "    'target': target,\n"
            "    'hostname': 'FS01',\n"
            "    'domain': 'CORP',\n"
            "    'os': 'Windows Server 2022',\n"
            "    'signing': False,\n"
            "    'smb_v1': False,\n"
            "    'reachable': True,\n"
            "}\n"
            "if '--shares' in args and '-u' in args and '-H' not in args and '-p' in args:\n"
            "    username = args[args.index('-u') + 1]\n"
            "    password = args[args.index('-p') + 1]\n"
            "    if username == '' and password == '':\n"
            "        print(json.dumps(host_record))\n"
            "        print(json.dumps({'record_type': 'null_session', 'target': target, 'enabled': True}))\n"
            "        print(json.dumps({'record_type': 'share', 'target': target, 'name': 'IPC$', 'permissions': ['READ'], 'anonymous': True}))\n"
            "        sys.exit(0)\n"
            "\n"
            "if '--shares' in args and '-H' in args:\n"
            "    username = args[args.index('-u') + 1]\n"
            "    ntlm_hash = args[args.index('-H') + 1]\n"
            "    print(json.dumps(host_record))\n"
            "    print(json.dumps({'record_type': 'auth', 'target': target, 'success': True, 'admin_access': True}))\n"
            "    print(json.dumps({'record_type': 'share', 'target': target, 'name': 'Finance', 'permissions': ['READ', 'WRITE'], 'anonymous': False}))\n"
            "    print(f'validated {username} with hash {ntlm_hash}')\n"
            "    sys.exit(0)\n"
            "\n"
            "if '--loggedon-users' in args:\n"
            "    print(json.dumps({'record_type': 'loggedon_user', 'target': target, 'username': 'CORP\\\\alice'}))\n"
            "    sys.exit(0)\n"
            "\n"
            "if '--local-group' in args:\n"
            "    print(json.dumps({'record_type': 'local_group', 'target': target, 'name': 'Administrators', 'members': ['CORP\\\\backup-admin']}))\n"
            "    sys.exit(0)\n"
            "\n"
            "if '-M' in args and 'spider_plus' in args:\n"
            "    payload = {\n"
            "        'target': target,\n"
            "        'files': [\n"
            "            {'share': 'Finance', 'path': r'\\\\Finance\\\\Passwords.xlsx'},\n"
            "            {'share': 'Finance', 'path': r'\\\\Finance\\\\Quarterly-Budget.xlsx'},\n"
            "        ],\n"
            "    }\n"
            "    pathlib.Path.cwd().joinpath(f'{target}.json').write_text(json.dumps(payload), encoding='utf-8')\n"
            "    print('spider completed')\n"
            "    sys.exit(0)\n"
            "\n"
            "print(json.dumps(host_record))\n"
        ),
        encoding="utf-8",
    )
    script_path.chmod(0o755)
    return str(script_path)


def test_build_netexec_command_supports_local_hash_auth() -> None:
    command = build_netexec_command(
        binary="nxc",
        target="10.0.20.15",
        action="shares",
        auth_context={
            "username": "Administrator",
            "ntlm_hash": "31d6cfe0d16ae931b73c59d7e0c089c0",
            "local_auth": True,
        },
    )

    assert command == [
        "nxc",
        "smb",
        "10.0.20.15",
        "-u",
        "Administrator",
        "-H",
        "31d6cfe0d16ae931b73c59d7e0c089c0",
        "--local-auth",
        "--shares",
    ]


def test_netexec_passive_runner_enumerates_signing_and_null_session(tmp_path: Path) -> None:
    binary = _write_fake_netexec_binary(tmp_path)

    execution = execute_netexec_smb(
        ["10.0.20.15"],
        mode="passive",
        binary=binary,
        scope_allowlist={"hosts": ["10.0.20.15"]},
    )

    assert execution.tool == "netexec"
    assert execution.exit_code == 0
    assert execution.metadata["mode"] == "passive"
    assert execution.metadata["read_only"] is True
    assert not execution.protected_outputs

    results_artifact = next(
        artifact for artifact in execution.artifacts if artifact.name == NETEXEC_RESULTS_ARTIFACT_NAME
    )
    payload = json.loads(results_artifact.data.decode("utf-8"))
    target = payload["targets"][0]
    assert target["host"]["signing"] is False
    assert target["null_session_enabled"] is True
    assert any(share["anonymous"] is True for share in target["shares"])

    task = type("TaskStub", (), {"tool": "netexec", "target_id": "10.0.20.15", "params_json": {}})()
    artifact_record = type("ArtifactRecord", (), {"uri": "artifact://netexec/results"})()
    findings = extract_findings(
        task=task,
        artifact=EvidenceArtifact(
            name=NETEXEC_RESULTS_ARTIFACT_NAME,
            content_type="application/json",
            data=results_artifact.data,
            kind="smb-results",
        ),
        artifact_record=artifact_record,
    )
    titles = {finding.title for finding in findings}
    assert "SMB signing disabled on 10.0.20.15" in titles
    assert "Anonymous SMB null session access on 10.0.20.15" in titles


def test_netexec_intrusive_runner_stores_protected_hash_evidence_without_plaintext_leakage(
    tmp_path: Path,
) -> None:
    binary = _write_fake_netexec_binary(tmp_path)
    raw_hash = "31d6cfe0d16ae931b73c59d7e0c089c0"

    execution = execute_netexec_smb(
        ["10.0.20.25"],
        mode="intrusive",
        binary=binary,
        scope_allowlist={"hosts": ["10.0.20.25"]},
        auth_contexts=[
            {
                "label": "Backup Admin",
                "username": "backup-admin",
                "ntlm_hash": raw_hash,
                "local_auth": True,
            }
        ],
    )

    assert execution.exit_code == 0
    assert execution.metadata["mode"] == "intrusive"
    assert execution.metadata["pass_the_hash_success_count"] == 1
    assert execution.protected_outputs
    protected_output = execution.protected_outputs[0]
    assert protected_output.secret_kind == "ntlm_hash_validation_bundle"
    assert raw_hash in protected_output.value

    results_artifact = next(
        artifact for artifact in execution.artifacts if artifact.name == NETEXEC_RESULTS_ARTIFACT_NAME
    )
    results_payload = json.loads(results_artifact.data.decode("utf-8"))
    target = results_payload["targets"][0]
    assert target["auth_attempts"][0]["credential_type"] == "ntlm_hash"
    assert target["auth_attempts"][0]["success"] is True
    assert raw_hash not in json.dumps(target)

    per_host_artifact = next(
        artifact for artifact in execution.artifacts if artifact.name == "netexec-10.0.20.25.json"
    )
    per_host_payload = json.loads(per_host_artifact.data.decode("utf-8"))
    titles = {finding["title"] for finding in per_host_payload["analysis_findings"]}
    assert "Pass-the-hash SMB access succeeded on 10.0.20.25" in titles
    assert "Sensitive SMB share content exposed on 10.0.20.25" in titles

    task = type("TaskStub", (), {"tool": "netexec", "target_id": "10.0.20.25", "params_json": {}})()
    artifact_record = type("ArtifactRecord", (), {"uri": "artifact://netexec/results"})()
    findings = extract_findings(
        task=task,
        artifact=EvidenceArtifact(
            name=NETEXEC_RESULTS_ARTIFACT_NAME,
            content_type="application/json",
            data=results_artifact.data,
            kind="smb-results",
        ),
        artifact_record=artifact_record,
    )
    finding_titles = {finding.title for finding in findings}
    assert "Pass-the-hash SMB access succeeded on 10.0.20.25" in finding_titles
    assert "Sensitive SMB share content exposed on 10.0.20.25" in finding_titles

    log_artifact = next(
        artifact for artifact in execution.artifacts if artifact.name == NETEXEC_LOG_ARTIFACT_NAME
    )
    log_text = log_artifact.data.decode("utf-8")
    assert raw_hash not in log_text
    assert "backup-admin" not in log_text


def test_netexec_runner_rejects_target_outside_scope(tmp_path: Path) -> None:
    binary = _write_fake_netexec_binary(tmp_path)

    with pytest.raises(ValueError, match="target outside scope"):
        execute_netexec_smb(
            ["10.0.20.15"],
            mode="passive",
            binary=binary,
            scope_allowlist={"hosts": ["10.0.99.15"]},
        )
