from __future__ import annotations

import json
import subprocess
from typing import Any

import pytest

from workers.runners.cve_intel import runner as cve_runner
from workers.runners.cve_intel.runner import (
    FINDING_PREFIX,
    build_searchsploit_command,
    execute_cve_intel,
    extract_fingerprints_from_params,
)

# A representative slice of `searchsploit -j` output for `vsftpd 2.3.4`.
VSFTPD_SEARCHSPLOIT_JSON = json.dumps(
    {
        "SEARCH": "vsftpd 2.3.4",
        "RESULTS_EXPLOIT": [
            {
                "Title": "vsftpd 2.3.4 - Backdoor Command Execution",
                "EDB-ID": "17491",
                "Path": "/usr/share/exploitdb/exploits/unix/remote/17491.rb",
                "Codes": "CVE-2011-2523",
            }
        ],
        "RESULTS_SHELLCODE": [],
    }
)


class _FakeCompletedProcess:
    def __init__(self, stdout: str = "", stderr: str = "", returncode: int = 0) -> None:
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


def _patch_searchsploit_present(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cve_runner.shutil, "which", lambda _binary: "/usr/bin/searchsploit")


def _finding_lines(stdout: str) -> list[str]:
    return [line for line in stdout.splitlines() if line.startswith(FINDING_PREFIX)]


def _finding_payload(stdout: str, index: int = 0) -> dict[str, Any]:
    line = _finding_lines(stdout)[index]
    return json.loads(line[len(FINDING_PREFIX):].strip())


def test_build_searchsploit_command_includes_product_and_version() -> None:
    command = build_searchsploit_command("vsftpd", "2.3.4")
    assert command == ["searchsploit", "--colour", "-j", "vsftpd", "2.3.4"]


def test_build_searchsploit_command_without_version() -> None:
    command = build_searchsploit_command("Apache httpd")
    assert command == ["searchsploit", "--colour", "-j", "Apache", "httpd"]


def test_extract_fingerprints_from_recon_observations() -> None:
    params: dict[str, Any] = {
        "observations": [
            {
                "tool": "nmap",
                "data": {
                    "services": [
                        {"product": "vsftpd", "version": "2.3.4", "port": 21},
                        {"product": "vsftpd", "version": "2.3.4", "port": 21},  # duplicate
                    ],
                    "fingerprints": [
                        {"product": "OpenSSH", "version": "7.2p2", "vendor": "openbsd"},
                    ],
                },
            }
        ]
    }

    fingerprints = extract_fingerprints_from_params(params)
    products = {(fp["product"], fp["version"]) for fp in fingerprints}
    assert ("vsftpd", "2.3.4") in products
    assert ("OpenSSH", "7.2p2") in products
    assert len(fingerprints) == 2  # de-duplicated


def test_execute_emits_findings_for_matched_cve(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_searchsploit_present(monkeypatch)

    captured_commands: list[list[str]] = []

    def fake_run(command: list[str], **_kwargs: Any) -> _FakeCompletedProcess:
        captured_commands.append(command)
        return _FakeCompletedProcess(stdout=VSFTPD_SEARCHSPLOIT_JSON)

    monkeypatch.setattr(subprocess, "run", fake_run)

    execution = execute_cve_intel(
        params={"product": "vsftpd", "version": "2.3.4"},
    )

    assert execution.tool == "cve_intel"
    assert execution.exit_code == 0
    assert execution.metadata["skipped"] is False
    assert execution.metadata["finding_count"] == 1
    assert captured_commands == [["searchsploit", "--colour", "-j", "vsftpd", "2.3.4"]]

    assert len(_finding_lines(execution.stdout)) == 1

    payload = _finding_payload(execution.stdout)
    assert payload["id"] == "CVE-2011-2523"
    assert payload["cves"] == ["CVE-2011-2523"]
    assert payload["severity"] == "high"
    assert payload["edb_id"] == "17491"
    assert payload["exploit_url"] == "https://www.exploit-db.com/exploits/17491"
    assert payload["exploit_path"] == "/usr/share/exploitdb/exploits/unix/remote/17491.rb"
    assert payload["matched_product"] == "vsftpd"
    assert payload["matched_version"] == "2.3.4"

    # The findings are also persisted into the evidence artifact.
    assert execution.artifacts
    artifact_payload = json.loads(execution.artifacts[0].data.decode("utf-8"))
    assert artifact_payload["findings"][0]["id"] == "CVE-2011-2523"


def test_execute_auto_correlates_from_recon_observations(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_searchsploit_present(monkeypatch)

    def fake_run(command: list[str], **_kwargs: Any) -> _FakeCompletedProcess:
        # Only the vsftpd query returns a hit; OpenSSH query returns empty.
        if "vsftpd" in command:
            return _FakeCompletedProcess(stdout=VSFTPD_SEARCHSPLOIT_JSON)
        return _FakeCompletedProcess(stdout=json.dumps({"RESULTS_EXPLOIT": []}))

    monkeypatch.setattr(subprocess, "run", fake_run)

    execution = execute_cve_intel(
        params={
            "observations": [
                {
                    "tool": "nmap",
                    "data": {
                        "services": [
                            {"product": "vsftpd", "version": "2.3.4", "port": 21},
                            {"product": "OpenSSH", "version": "9.9", "port": 22},
                        ]
                    },
                }
            ]
        },
    )

    assert execution.metadata["fingerprint_count"] == 2
    assert execution.metadata["finding_count"] == 1
    payload = _finding_payload(execution.stdout)
    assert payload["matched_product"] == "vsftpd"


def test_execute_skips_gracefully_when_searchsploit_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cve_runner.shutil, "which", lambda _binary: None)

    def fail_run(*_args: Any, **_kwargs: Any) -> _FakeCompletedProcess:  # pragma: no cover
        raise AssertionError("subprocess.run must not be invoked when searchsploit is absent")

    monkeypatch.setattr(subprocess, "run", fail_run)

    execution = execute_cve_intel(params={"product": "vsftpd", "version": "2.3.4"})

    assert execution.tool == "cve_intel"
    assert execution.exit_code == 0
    assert execution.metadata["skipped"] is True
    assert execution.metadata["status"] == "skipped"
    assert execution.stdout == ""
    assert execution.artifacts == []


def test_execute_skips_gracefully_without_fingerprints(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_searchsploit_present(monkeypatch)

    def fail_run(*_args: Any, **_kwargs: Any) -> _FakeCompletedProcess:  # pragma: no cover
        raise AssertionError("subprocess.run must not be invoked without fingerprints")

    monkeypatch.setattr(subprocess, "run", fail_run)

    execution = execute_cve_intel(params={})

    assert execution.metadata["skipped"] is True
    assert execution.metadata["reason"] == "no fingerprints"
    assert execution.metadata["fingerprint_count"] == 0
