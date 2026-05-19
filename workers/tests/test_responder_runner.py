from __future__ import annotations

import json
from pathlib import Path

import pytest

from workers.orchestration.findings import extract_findings
from workers.runners.base.contracts import EvidenceArtifact
from workers.runners.responder.runner import (
    RESPONDER_LOG_ARTIFACT_NAME,
    RESPONDER_RESULTS_ARTIFACT_NAME,
    execute_responder_capture,
)


def _write_fake_responder_binary(tmp_path: Path, *, wait_forever: bool = False) -> str:
    script_path = tmp_path / "fake_responder.py"
    script_path.write_text(
        (
            "#!/usr/bin/env python3\n"
            "import pathlib\n"
            "import signal\n"
            "import sys\n"
            "import time\n"
            "\n"
            "WAIT_FOREVER = " + ("True" if wait_forever else "False") + "\n"
            "if '--version' in sys.argv:\n"
            "    sys.stdout.write('Responder test 1.0\\n')\n"
            "    sys.exit(0)\n"
            "logs_dir = pathlib.Path.cwd() / 'logs'\n"
            "logs_dir.mkdir(parents=True, exist_ok=True)\n"
            "session_log = logs_dir / 'Responder-Session.log'\n"
            "hash_log = logs_dir / 'SMB-NTLMv2-SSP-10.0.20.44.txt'\n"
            "raw_hash = 'alice::EXAMPLE:1122334455667788:99AABBCCDDEEFF001122334455667788:0101000000000000'\n"
            "session_log.write_text('NTLMv2-SSP Hash     : ' + raw_hash + '\\n', encoding='utf-8')\n"
            "hash_log.write_text(raw_hash + '\\n', encoding='utf-8')\n"
            "\n"
            "def _handle_term(signum, frame):\n"
            "    session_log.write_text(session_log.read_text(encoding='utf-8') + 'terminated cleanly\\n', encoding='utf-8')\n"
            "    sys.exit(0)\n"
            "\n"
            "signal.signal(signal.SIGTERM, _handle_term)\n"
            "sys.stdout.write('NTLMv2-SSP Hash     : ' + raw_hash + '\\n')\n"
            "sys.stdout.flush()\n"
            "if WAIT_FOREVER:\n"
            "    while True:\n"
            "        time.sleep(0.1)\n"
            "time.sleep(0.05)\n"
        ),
        encoding="utf-8",
    )
    script_path.chmod(0o755)
    return str(script_path)


def test_responder_runner_captures_hashes_and_sanitizes_output(tmp_path: Path) -> None:
    binary = _write_fake_responder_binary(tmp_path)

    execution = execute_responder_capture(
        ["10.0.20.0/24"],
        interface="eth0",
        duration_minutes=0.01,
        binary=binary,
        scope_allowlist={"cidrs": ["10.0.20.0/24"]},
        kill_switch_check=lambda: False,
    )

    assert execution.tool == "responder"
    assert execution.exit_code == 0
    assert execution.metadata["capture_count"] == 1
    assert execution.protected_outputs
    protected_output = execution.protected_outputs[0]
    assert protected_output.secret_kind == "ntlmv2_hash_bundle"
    assert "alice::EXAMPLE" in protected_output.value
    assert "alice::EXAMPLE" not in execution.stdout
    assert "99AABBCCDDEEFF" not in execution.stdout

    results_artifact = next(
        artifact for artifact in execution.artifacts if artifact.name == RESPONDER_RESULTS_ARTIFACT_NAME
    )
    results_payload = json.loads(results_artifact.data.decode("utf-8"))
    assert results_payload["summary"]["capture_count"] == 1
    assert results_payload["captures"][0]["host"] == "10.0.20.44"
    assert results_payload["captures"][0]["username"] == "alice"
    assert "raw_hash" not in json.dumps(results_payload)

    task = type("TaskStub", (), {"tool": "responder", "target_id": "10.0.20.0/24", "params_json": {}})()
    artifact_record = type("ArtifactRecord", (), {"uri": "artifact://responder/results"})()
    findings = extract_findings(
        task=task,
        artifact=EvidenceArtifact(
            name=RESPONDER_RESULTS_ARTIFACT_NAME,
            content_type="application/json",
            data=results_artifact.data,
            kind="credential-capture-results",
        ),
        artifact_record=artifact_record,
    )
    assert len(findings) == 1
    assert findings[0].target_id == "10.0.20.44"
    assert findings[0].summary is not None
    assert "raw hash" not in findings[0].summary.lower()

    log_artifact = next(
        artifact for artifact in execution.artifacts if artifact.name == RESPONDER_LOG_ARTIFACT_NAME
    )
    log_text = log_artifact.data.decode("utf-8")
    assert "[REDACTED]" in log_text
    assert "alice::EXAMPLE" not in log_text


def test_responder_runner_rejects_targets_outside_scope(tmp_path: Path) -> None:
    binary = _write_fake_responder_binary(tmp_path)

    with pytest.raises(ValueError, match="target outside scope"):
        execute_responder_capture(
            ["10.0.20.0/24"],
            interface="eth0",
            duration_minutes=0.01,
            binary=binary,
            scope_allowlist={"cidrs": ["10.0.99.0/24"]},
            kill_switch_check=lambda: False,
        )


def test_responder_runner_terminates_cleanly_on_kill_switch(tmp_path: Path) -> None:
    binary = _write_fake_responder_binary(tmp_path, wait_forever=True)
    calls = {"count": 0}

    def kill_switch_check() -> bool:
        calls["count"] += 1
        return calls["count"] >= 2

    execution = execute_responder_capture(
        ["10.0.20.0/24"],
        interface="eth0",
        duration_minutes=0.02,
        binary=binary,
        scope_allowlist={"cidrs": ["10.0.20.0/24"]},
        kill_switch_check=kill_switch_check,
        poll_interval_seconds=0.05,
    )

    assert execution.exit_code == 0
    assert execution.metadata["terminated_by_kill_switch"] is True
    log_artifact = next(
        artifact for artifact in execution.artifacts if artifact.name == RESPONDER_LOG_ARTIFACT_NAME
    )
    assert "terminated cleanly" in log_artifact.data.decode("utf-8")
