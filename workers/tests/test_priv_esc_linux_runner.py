from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from workers.orchestration.findings import extract_standard_json_findings
from workers.orchestration.tasks import SUPPORTED_TOOLS
from workers.runners.priv_esc_linux.runner import (
    PRIV_ESC_LINUX_RESULTS_ARTIFACT_NAME,
    execute_priv_esc_linux,
)


def _payload(execution) -> dict:
    artifact = next(
        item for item in execution.artifacts if item.name == PRIV_ESC_LINUX_RESULTS_ARTIFACT_NAME
    )
    return json.loads(artifact.data.decode("utf-8"))


def test_priv_esc_linux_detects_read_only_privilege_escalation_signals() -> None:
    execution = execute_priv_esc_linux(
        ["10.0.20.35"],
        scope_allowlist={"hosts": ["10.0.20.35"]},
        auth_contexts=[
            {
                "label": "lowpriv",
                "username": "alice",
                "password": "CorrectHorseBatteryStaple!",
            }
        ],
        command_outputs={
            "suid_sgid": "4755 root root /usr/bin/find\n2755 root shadow /usr/bin/vim\n",
            "sudo_l": (
                "Matching Defaults entries for alice on host:\n"
                "User alice may run the following commands on host:\n"
                "    (root) NOPASSWD: /usr/bin/vim\n"
                "    ALL=(ALL:ALL) ALL\n"
            ),
            "cron": "0777 root root /etc/cron.d/backup\n",
            "path": "PATH=/tmp:/usr/local/bin:/usr/bin:/bin\nwritable 1 /tmp\n",
            "permissions": (
                "0666 root root /etc/passwd\n"
                "0644 root shadow /etc/shadow\n"
                "0644 root root /var/backups/app.conf.bak\n"
                "grep_excerpt password=CorrectHorseBatteryStaple!\n"
                "contains_secret_marker /var/backups/app.conf.bak\n"
            ),
            "versions": "Linux kernel release: 5.10.0\nSudo version 1.8.31\n",
        },
    )

    assert execution.tool == "priv-esc-linux"
    assert execution.exit_code == 0
    payload = _payload(execution)
    titles = {finding["title"] for finding in payload["findings"]}
    assert "SUID Binary Exploitable via GTFOBins: /usr/bin/find" in titles
    assert "Sudo NOPASSWD - Privilege Escalation Possible" in titles
    assert "Writable Cron Script - Privilege Escalation via Cron" in titles
    assert "Writable Directory Precedes System Path - PATH Hijacking Possible" in titles
    assert "World-Writable /etc/passwd - Privilege Escalation Possible" in titles
    assert "Readable /etc/shadow - Credential Exposure" in titles
    assert "Credential Backup File Exposed" in titles
    assert "Kernel Version Potentially Affected by CVE-2022-0847 DirtyPipe" in titles
    assert "Sudo Version Potentially Affected by CVE-2021-3156 Baron Samedit" in titles
    assert payload["safety"]["read_only_enumeration"] is True
    assert payload["safety"]["exploitation_attempted"] is False
    assert payload["safety"]["privilege_escalation_attempted"] is False
    assert payload["safety"]["target_filesystem_write_attempted"] is False
    assert "CorrectHorseBatteryStaple!" not in json.dumps(payload)


def test_priv_esc_linux_scope_rejects_out_of_scope_host() -> None:
    with pytest.raises(ValueError, match="outside approved Linux privilege escalation scope"):
        execute_priv_esc_linux(
            ["10.0.20.99"],
            scope_allowlist={"hosts": ["10.0.20.35"]},
            auth_contexts=[{"username": "alice", "password": "secret"}],
            command_outputs={"versions": "Linux kernel release: 6.1.0\n"},
        )


def test_priv_esc_linux_supported_tool_and_standard_finding_extraction() -> None:
    assert "priv-esc-linux" in SUPPORTED_TOOLS

    execution = execute_priv_esc_linux(
        ["10.0.20.35"],
        scope_allowlist={"hosts": ["10.0.20.35"]},
        auth_contexts=[{"username": "alice", "password": "secret"}],
        command_outputs={"suid_sgid": "4755 root root /usr/bin/find\n"},
    )
    artifact = next(
        item for item in execution.artifacts if item.name == PRIV_ESC_LINUX_RESULTS_ARTIFACT_NAME
    )

    findings = extract_standard_json_findings(
        target_id="10.0.20.35",
        artifact=artifact,
        artifact_record=SimpleNamespace(uri="artifact://priv-esc-linux/results"),
        accepted_artifact_names={PRIV_ESC_LINUX_RESULTS_ARTIFACT_NAME},
        default_title="priv-esc-linux finding",
    )

    assert findings
    assert any(
        finding.title == "SUID Binary Exploitable via GTFOBins: /usr/bin/find"
        for finding in findings
    )
    assert all("priv-esc-linux-validation" in finding.methodology_tags for finding in findings)
