from __future__ import annotations

import json
from pathlib import Path

import pytest

from workers.orchestration.findings import extract_findings
from workers.runners.base.contracts import EvidenceArtifact
from workers.runners.credential_attacks.runner import (
    CREDENTIAL_ATTACK_LOG_ARTIFACT_NAME,
    CREDENTIAL_ATTACK_RESULTS_ARTIFACT_NAME,
    execute_credential_attacks,
)


def _write_fake_getuserspns_binary(tmp_path: Path) -> str:
    script_path = tmp_path / "fake_getuserspns.py"
    script_path.write_text(
        (
            "#!/usr/bin/env python3\n"
            "import pathlib\n"
            "import sys\n"
            "output_file = pathlib.Path(sys.argv[sys.argv.index('-outputfile') + 1])\n"
            "raw_hash = '$krb5tgs$23$*svc-sql$CORP.EXAMPLE$MSSQLSvc/sql01.corp.example:1433*$112233$445566'\n"
            "output_file.write_text(raw_hash + '\\n', encoding='utf-8')\n"
            "sys.stdout.write('requested Kerberoast with alice@corp.example / Password123!\\n')\n"
        ),
        encoding="utf-8",
    )
    script_path.chmod(0o755)
    return str(script_path)


def _write_fake_getnpusers_binary(tmp_path: Path) -> str:
    script_path = tmp_path / "fake_getnpusers.py"
    script_path.write_text(
        (
            "#!/usr/bin/env python3\n"
            "import pathlib\n"
            "import sys\n"
            "output_file = pathlib.Path(sys.argv[sys.argv.index('-outputfile') + 1])\n"
            "raw_hash = '$krb5asrep$23$legacy-user@CORP.EXAMPLE:11223344556677889900AABBCCDDEEFF'\n"
            "output_file.write_text(raw_hash + '\\n', encoding='utf-8')\n"
            "sys.stdout.write('queried AS-REP roastable accounts\\n')\n"
        ),
        encoding="utf-8",
    )
    script_path.chmod(0o755)
    return str(script_path)


def _write_fake_hashcat_binary(tmp_path: Path) -> str:
    script_path = tmp_path / "fake_hashcat.py"
    script_path.write_text(
        (
            "#!/usr/bin/env python3\n"
            "import pathlib\n"
            "import sys\n"
            "hash_file = pathlib.Path(sys.argv[5])\n"
            "outfile = pathlib.Path(sys.argv[sys.argv.index('--outfile') + 1])\n"
            "lines = [line.strip() for line in hash_file.read_text(encoding='utf-8').splitlines() if line.strip()]\n"
            "output_lines = []\n"
            "for line in lines:\n"
            "    if line.startswith('$krb5tgs$'):\n"
            "        output_lines.append(line + ':ServicePass!2026')\n"
            "    elif line.startswith('alice::EXAMPLE'):\n"
            "        output_lines.append(line + ':Winter2026!')\n"
            "outfile.write_text('\\n'.join(output_lines) + ('\\n' if output_lines else ''), encoding='utf-8')\n"
            "sys.stdout.write('hashcat cracked material\\n')\n"
        ),
        encoding="utf-8",
    )
    script_path.chmod(0o755)
    return str(script_path)


def _write_fake_kerbrute_binary(tmp_path: Path) -> str:
    script_path = tmp_path / "fake_kerbrute.py"
    script_path.write_text(
        (
            "#!/usr/bin/env python3\n"
            "import pathlib\n"
            "import sys\n"
            "users_file = pathlib.Path(sys.argv[-2])\n"
            "password = sys.argv[-1]\n"
            "users = [line.strip() for line in users_file.read_text(encoding='utf-8').splitlines() if line.strip()]\n"
            "for user in users:\n"
            "    if password == 'Winter2026!' and user.lower().startswith('backup-admin'):\n"
            "        sys.stdout.write(f'VALID LOGIN: {user}:{password}\\n')\n"
            "sys.stdout.write('spray complete\\n')\n"
        ),
        encoding="utf-8",
    )
    script_path.chmod(0o755)
    return str(script_path)


def test_kerberoast_runner_stores_hashes_only_in_protected_outputs(tmp_path: Path) -> None:
    binary = _write_fake_getuserspns_binary(tmp_path)

    execution = execute_credential_attacks(
        ["corp.example"],
        mode="kerberoast",
        auth_contexts=[
            {
                "label": "Read-only AD",
                "username": "alice@corp.example",
                "password": "Password123!",
            }
        ],
        candidate_accounts=[
            {
                "account_name": "svc-sql",
                "user_principal_name": "svc-sql@corp.example",
                "service_principal_names": ["MSSQLSvc/sql01.corp.example:1433"],
                "privilege_level": "service",
            }
        ],
        scope_allowlist={"ad_domains": ["corp.example"]},
        getuserspns_binary=binary,
    )

    assert execution.tool == "credential-attacks"
    assert execution.exit_code == 0
    assert execution.metadata["mode"] == "kerberoast"
    assert execution.protected_outputs
    protected_output = execution.protected_outputs[0]
    assert protected_output.secret_kind == "kerberoast_tgs_hash_bundle"
    assert "$krb5tgs$23$*svc-sql$CORP.EXAMPLE" in protected_output.value

    results_artifact = next(
        artifact for artifact in execution.artifacts if artifact.name == CREDENTIAL_ATTACK_RESULTS_ARTIFACT_NAME
    )
    payload = json.loads(results_artifact.data.decode("utf-8"))
    target = payload["targets"][0]
    assert target["candidate_accounts"][0]["hash_extracted"] is True
    assert "$krb5tgs$23$" not in json.dumps(target)

    task = type("TaskStub", (), {"tool": "credential-attacks", "target_id": "corp.example", "params_json": {}})()
    artifact_record = type("ArtifactRecord", (), {"uri": "artifact://credential-attacks/results"})()
    findings = extract_findings(
        task=task,
        artifact=EvidenceArtifact(
            name=CREDENTIAL_ATTACK_RESULTS_ARTIFACT_NAME,
            content_type="application/json",
            data=results_artifact.data,
            kind="credential-attack-results",
        ),
        artifact_record=artifact_record,
    )
    assert {finding.title for finding in findings} == {
        "Kerberoast hash extracted for account svc-sql"
    }

    log_artifact = next(
        artifact for artifact in execution.artifacts if artifact.name == CREDENTIAL_ATTACK_LOG_ARTIFACT_NAME
    )
    log_text = log_artifact.data.decode("utf-8")
    assert "Password123!" not in log_text
    assert "alice@corp.example" not in log_text


def test_asreproast_runner_stores_hashes_only_in_protected_outputs(tmp_path: Path) -> None:
    binary = _write_fake_getnpusers_binary(tmp_path)

    execution = execute_credential_attacks(
        ["corp.example"],
        mode="asreproast",
        candidate_accounts=[
            {
                "account_name": "legacy-user",
                "user_principal_name": "legacy-user@corp.example",
                "privilege_level": "standard",
            }
        ],
        scope_allowlist={"ad_domains": ["corp.example"]},
        getnpusers_binary=binary,
    )

    assert execution.exit_code == 0
    assert execution.protected_outputs[0].secret_kind == "asrep_hash_bundle"

    results_artifact = next(
        artifact for artifact in execution.artifacts if artifact.name == CREDENTIAL_ATTACK_RESULTS_ARTIFACT_NAME
    )
    payload = json.loads(results_artifact.data.decode("utf-8"))
    target = payload["targets"][0]
    assert target["candidate_accounts"][0]["account_name"] == "legacy-user"
    assert "$krb5asrep$23$" not in json.dumps(target)


def test_hashcat_runner_stores_plaintext_only_in_protected_password_refs(tmp_path: Path) -> None:
    binary = _write_fake_hashcat_binary(tmp_path)
    wordlist_path = tmp_path / "wordlist.txt"
    wordlist_path.write_text("Winter2026!\nServicePass!2026\n", encoding="utf-8")

    execution = execute_credential_attacks(
        ["corp.example"],
        mode="hashcat",
        hash_inputs=[
            {
                "label": "Responder capture",
                "secret_kind": "ntlmv2_hash_bundle",
                "value": "alice::EXAMPLE:1122334455667788:99AABBCCDDEEFF001122334455667788:0101000000000000",
            },
            {
                "label": "Kerberoast bundle",
                "secret_kind": "kerberoast_tgs_hash_bundle",
                "value": json.dumps(
                    {
                        "records": [
                            {
                                "account_name": "svc-sql",
                                "user_principal_name": "svc-sql@corp.example",
                                "hash": "$krb5tgs$23$*svc-sql$CORP.EXAMPLE$MSSQLSvc/sql01.corp.example:1433*$112233$445566",
                                "hashcat_mode": 13100,
                                "privilege_level": "privileged",
                                "source": "kerberoast",
                            }
                        ]
                    }
                ),
            },
        ],
        scope_allowlist={"ad_domains": ["corp.example"]},
        hashcat_binary=binary,
        wordlist_path=str(wordlist_path),
    )

    assert execution.exit_code == 0
    assert len(execution.protected_outputs) == 2
    assert {output.secret_kind for output in execution.protected_outputs} == {"password"}
    assert {output.value for output in execution.protected_outputs} == {
        "Winter2026!",
        "ServicePass!2026",
    }

    results_artifact = next(
        artifact for artifact in execution.artifacts if artifact.name == CREDENTIAL_ATTACK_RESULTS_ARTIFACT_NAME
    )
    payload = json.loads(results_artifact.data.decode("utf-8"))
    cracked_accounts = payload["targets"][0]["cracked_accounts"]
    assert {item["account_name"] for item in cracked_accounts} == {"alice", "svc-sql"}
    assert "Winter2026!" not in json.dumps(payload)
    assert "ServicePass!2026" not in json.dumps(payload)


def test_password_spray_runner_enforces_rate_limit_and_hides_passwords(tmp_path: Path) -> None:
    binary = _write_fake_kerbrute_binary(tmp_path)

    execution = execute_credential_attacks(
        ["corp.example"],
        mode="spray",
        candidate_accounts=[
            {
                "account_name": "backup-admin",
                "user_principal_name": "backup-admin@corp.example",
                "privilege_level": "privileged",
            },
            {
                "account_name": "alice",
                "user_principal_name": "alice@corp.example",
                "privilege_level": "standard",
            },
        ],
        password_candidates=[
            {
                "label": "Seasonal password",
                "value": "Winter2026!",
            }
        ],
        scope_allowlist={"ad_domains": ["corp.example"]},
        spray_binary=binary,
        attempts_per_window=1,
        window_minutes=30,
        lockout_threshold=5,
    )

    assert execution.exit_code == 0
    assert execution.metadata["attempts_per_window"] == 1
    assert execution.metadata["lockout_threshold"] == 5
    assert execution.protected_outputs[0].secret_kind == "password"

    results_artifact = next(
        artifact for artifact in execution.artifacts if artifact.name == CREDENTIAL_ATTACK_RESULTS_ARTIFACT_NAME
    )
    payload = json.loads(results_artifact.data.decode("utf-8"))
    spray_successes = payload["targets"][0]["spray_successes"]
    assert [item["account_name"] for item in spray_successes] == ["backup-admin"]
    assert "Winter2026!" not in json.dumps(payload)

    with pytest.raises(ValueError, match="below the confirmed lockout threshold"):
        execute_credential_attacks(
            ["corp.example"],
            mode="spray",
            candidate_accounts=[
                {
                    "account_name": "alice",
                    "user_principal_name": "alice@corp.example",
                    "privilege_level": "standard",
                }
            ],
            password_candidates=[{"label": "Seasonal password", "value": "Winter2026!"}],
            scope_allowlist={"ad_domains": ["corp.example"]},
            spray_binary=binary,
            attempts_per_window=5,
            window_minutes=30,
            lockout_threshold=5,
        )
