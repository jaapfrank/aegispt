from __future__ import annotations

import base64
import json
import zipfile
from pathlib import Path

import pytest

from api.app.services.inventory import bloodhound_observation_from_json
from workers.orchestration.findings import extract_findings
from workers.runners.base.contracts import EvidenceArtifact
from workers.runners.bloodhound.runner import (
    BLOODHOUND_COLLECTION_ARTIFACT_NAME,
    BLOODHOUND_LOG_ARTIFACT_NAME,
    BLOODHOUND_RESULTS_ARTIFACT_NAME,
    build_bloodhound_command,
    execute_bloodhound_collect,
)


def _write_fake_bloodhound_binary(tmp_path: Path) -> str:
    script_path = tmp_path / "fake_bloodhound.py"
    script_path.write_text(
        (
            "#!/usr/bin/env python3\n"
            "import json\n"
            "import pathlib\n"
            "import sys\n"
            "import zipfile\n"
            "\n"
            "username = sys.argv[sys.argv.index('-u') + 1]\n"
            "password = sys.argv[sys.argv.index('-p') + 1]\n"
            "archive_path = pathlib.Path.cwd() / 'bloodhound-test.zip'\n"
            "users = {\n"
            "  'meta': {'type': 'users', 'count': 2},\n"
            "  'data': [\n"
            "    {'ObjectIdentifier': 'USER-ALICE', 'Properties': {'name': 'alice@corp.example', 'enabled': True}},\n"
            "    {\n"
            "      'ObjectIdentifier': 'USER-SVCSQL',\n"
            "      'Properties': {\n"
            "        'name': 'svc-sql@corp.example',\n"
            "        'enabled': True,\n"
            "        'hasspn': True,\n"
            "        'serviceprincipalnames': ['MSSQLSvc/sql01.corp.example:1433'],\n"
            "        'dontreqpreauth': True,\n"
            "      },\n"
            "    },\n"
            "  ],\n"
            "}\n"
            "groups = {\n"
            "  'meta': {'type': 'groups', 'count': 3},\n"
            "  'data': [\n"
            "    {\n"
            "      'ObjectIdentifier': 'GROUP-HELPDESK',\n"
            "      'Properties': {'name': 'HELPDESK@CORP.EXAMPLE'},\n"
            "      'Members': [{'ObjectIdentifier': 'USER-ALICE'}],\n"
            "    },\n"
            "    {\n"
            "      'ObjectIdentifier': 'GROUP-DA',\n"
            "      'Properties': {'name': 'DOMAIN ADMINS@CORP.EXAMPLE', 'highvalue': True},\n"
            "      'Aces': [{'PrincipalSID': 'GROUP-HELPDESK', 'RightName': 'AddMember'}],\n"
            "    },\n"
            "    {\n"
            "      'ObjectIdentifier': 'GROUP-EA',\n"
            "      'Properties': {'name': 'ENTERPRISE ADMINS@CORP.EXAMPLE', 'highvalue': True},\n"
            "      'Aces': [{'PrincipalSID': 'GROUP-HELPDESK', 'RightName': 'WriteDacl'}],\n"
            "    },\n"
            "  ],\n"
            "}\n"
            "computers = {\n"
            "  'meta': {'type': 'computers', 'count': 1},\n"
            "  'data': [\n"
            "    {\n"
            "      'ObjectIdentifier': 'COMP-DC01',\n"
            "      'Properties': {\n"
            "        'name': 'DC01.CORP.EXAMPLE',\n"
            "        'dnshostname': 'dc01.corp.example',\n"
            "        'distinguishedname': 'CN=DC01,OU=Domain Controllers,DC=corp,DC=example',\n"
            "        'highvalue': True,\n"
            "      },\n"
            "      'Aces': [{'PrincipalSID': 'GROUP-HELPDESK', 'RightName': 'AdminTo'}],\n"
            "    },\n"
            "  ],\n"
            "}\n"
            "with zipfile.ZipFile(archive_path, 'w') as archive:\n"
            "    archive.writestr('users.json', json.dumps(users))\n"
            "    archive.writestr('groups.json', json.dumps(groups))\n"
            "    archive.writestr('computers.json', json.dumps(computers))\n"
            "print(f'collecting as {username} with {password}')\n"
            "sys.stdout.flush()\n"
        ),
        encoding="utf-8",
    )
    script_path.chmod(0o755)
    return str(script_path)


def test_build_bloodhound_command_is_read_only_and_structured() -> None:
    command = build_bloodhound_command(
        binary="bloodhound-python",
        target="corp.example",
        auth_context={"username": "alice@corp.example", "password": "Password123!"},
        nameserver="10.0.0.10",
        collection_methods=["All"],
        dns_tcp=True,
    )

    assert command[:8] == [
        "bloodhound-python",
        "-u",
        "alice@corp.example",
        "-p",
        "Password123!",
        "-d",
        "corp.example",
        "-c",
    ]
    assert "--zip" in command
    assert "--dns-tcp" in command
    assert "-ns" in command
    assert "--CollectionMethod" not in command


def test_bloodhound_runner_collects_protected_zip_and_sanitized_analysis(tmp_path: Path) -> None:
    binary = _write_fake_bloodhound_binary(tmp_path)

    execution = execute_bloodhound_collect(
        ["corp.example"],
        auth_contexts=[
            {
                "label": "Read-only AD",
                "username": "alice@corp.example",
                "password": "Password123!",
            }
        ],
        scope_allowlist={"ad_domains": ["corp.example"]},
        binary=binary,
        nameserver="10.0.0.10",
        collection_methods=["All"],
    )

    assert execution.tool == "bloodhound-collect"
    assert execution.exit_code == 0
    assert execution.metadata["read_only"] is True
    assert execution.protected_outputs
    protected_output = execution.protected_outputs[0]
    assert protected_output.secret_kind == "bloodhound_collection_zip"
    decoded_zip = base64.b64decode(protected_output.value.encode("ascii"))
    with zipfile.ZipFile(Path(tmp_path) / "decoded.zip", "w") as sink:
        sink.writestr("bloodhound.zip", decoded_zip)
    assert "Password123!" not in execution.stdout
    assert "alice@corp.example" not in execution.stdout

    placeholder_artifact = next(
        artifact
        for artifact in execution.artifacts
        if artifact.name == BLOODHOUND_COLLECTION_ARTIFACT_NAME
    )
    placeholder_payload = json.loads(placeholder_artifact.data.decode("utf-8"))
    assert placeholder_payload["stored_as"] == "protected_secret_ref"

    results_artifact = next(
        artifact for artifact in execution.artifacts if artifact.name == BLOODHOUND_RESULTS_ARTIFACT_NAME
    )
    results_payload = json.loads(results_artifact.data.decode("utf-8"))
    result = results_payload["targets"][0]
    assert result["summary"]["attack_path_count"] >= 2
    assert result["summary"]["kerberoastable_account_count"] == 1
    assert result["summary"]["asrep_roastable_account_count"] == 1

    observation = bloodhound_observation_from_json(
        json_bytes=results_artifact.data,
        target_id="corp.example",
    )
    assert len(observation["data"]["bloodhound_attack_paths"]) >= 2
    assert any(entry["host"] == "dc01.corp.example" for entry in observation["data"]["hosts"])

    task = type("TaskStub", (), {"tool": "bloodhound-collect", "target_id": "corp.example", "params_json": {}})()
    artifact_record = type("ArtifactRecord", (), {"uri": "artifact://bloodhound/results"})()
    findings = extract_findings(
        task=task,
        artifact=EvidenceArtifact(
            name=BLOODHOUND_RESULTS_ARTIFACT_NAME,
            content_type="application/json",
            data=results_artifact.data,
            kind="identity-graph-results",
        ),
        artifact_record=artifact_record,
    )
    titles = {finding.title for finding in findings}
    assert any(title.startswith("Read-only AD attack path to Domain Admins") for title in titles)
    assert "Kerberoastable account exposure observed" in titles
    assert "AS-REP roastable account exposure observed" in titles

    log_artifact = next(artifact for artifact in execution.artifacts if artifact.name == BLOODHOUND_LOG_ARTIFACT_NAME)
    log_text = log_artifact.data.decode("utf-8")
    assert "Password123!" not in log_text
    assert "alice@corp.example" not in log_text


def test_bloodhound_runner_rejects_target_outside_scope(tmp_path: Path) -> None:
    binary = _write_fake_bloodhound_binary(tmp_path)

    with pytest.raises(ValueError, match="target outside scope"):
        execute_bloodhound_collect(
            ["corp.example"],
            auth_contexts=[
                {
                    "username": "alice@corp.example",
                    "password": "Password123!",
                }
            ],
            scope_allowlist={"ad_domains": ["other.example"]},
            binary=binary,
        )
