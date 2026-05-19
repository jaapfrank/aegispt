from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from api.app.services.runner_registry import runner_capability_registry
from workers.orchestration.findings import extract_findings
from workers.orchestration.tasks import (
    SUPPORTED_TOOLS,
    _runner_command_preview,
    dispatch_runner,
)
from workers.runners.base.contracts import EvidenceArtifact, RunnerRequest
from workers.runners.c2_ingest.runner import (
    C2_INGEST_RESULTS_ARTIFACT_NAME,
    TOOL_NAME,
    execute_c2_ingest,
)


class ArtifactRecord:
    uri = "artifact://c2-ingest/results"


def _c2_export() -> dict[str, object]:
    return {
        "framework": "Mythic",
        "sessions": [
            {
                "id": "session-1",
                "host": "workstation-01",
                "user": "alice",
                "ip": "10.20.30.40",
                "platform": "windows",
            }
        ],
        "commands": [
            {
                "session_id": "session-1",
                "timestamp": "2026-05-10T10:00:00Z",
                "command": "whoami",
                "status": "completed",
            },
            {
                "session_id": "session-1",
                "timestamp": "2026-05-10T10:03:00Z",
                "command": "psexec \\\\server01 cmd.exe /c hostname",
                "status": "completed",
            },
            {
                "session_id": "session-1",
                "timestamp": "2026-05-10T10:05:00Z",
                "command": "secretsdump password=CorrectHorseBatteryStaple!",
                "status": "completed",
                "token": "raw-c2-token",
            },
        ],
    }


def _payload(execution) -> dict[str, object]:
    artifact = next(
        item for item in execution.artifacts if item.name == C2_INGEST_RESULTS_ARTIFACT_NAME
    )
    return json.loads(artifact.data.decode("utf-8"))


def test_c2_ingest_imports_read_only_timeline_and_redacts_secrets() -> None:
    execution = execute_c2_ingest(
        ["assumed-breach-drill"],
        c2_export=_c2_export(),
        framework="mythic",
    )

    assert execution.tool == TOOL_NAME
    assert execution.exit_code == 0
    assert execution.protected_outputs == []
    assert execution.metadata["c2_command_execution_performed"] is False
    assert execution.metadata["session_mutation_performed"] is False

    payload = _payload(execution)
    assert payload["safety"]["read_only_import"] is True
    assert payload["safety"]["c2_command_execution_performed"] is False
    assert payload["safety"]["session_mutation_performed"] is False
    assert payload["safety"]["payload_deployment_performed"] is False
    assert payload["safety"]["credential_materialization_performed"] is False
    assert payload["summary"]["session_count"] == 1
    assert payload["summary"]["command_count"] == 3
    assert payload["summary"]["credential_access_command_count"] == 1
    assert payload["summary"]["lateral_movement_command_count"] == 1

    artifact_text = execution.artifacts[0].data.decode("utf-8")
    assert "CorrectHorseBatteryStaple!" not in artifact_text
    assert "raw-c2-token" not in artifact_text
    assert "alice" not in artifact_text

    findings = extract_findings(
        task=SimpleNamespace(tool=TOOL_NAME, target_id="assumed-breach-drill", params_json={}),
        artifact=EvidenceArtifact(
            name=C2_INGEST_RESULTS_ARTIFACT_NAME,
            content_type="application/json",
            data=execution.artifacts[0].data,
            kind="runner-results",
        ),
        artifact_record=ArtifactRecord(),
    )

    assert {finding.title for finding in findings} == {
        "C2 Session Evidence Imported",
        "C2 Lateral Movement Command Evidence",
        "C2 Credential Access Command Evidence",
    }
    assert all("c2_ingest" in finding.methodology_tags for finding in findings)


def test_c2_ingest_blocks_command_execution_and_dispatch_stays_read_only() -> None:
    with pytest.raises(ValueError, match="read-only"):
        execute_c2_ingest(
            ["assumed-breach-drill"],
            c2_export=_c2_export(),
            command_execution_requested=True,
        )

    execution = dispatch_runner(
        RunnerRequest(
            tool=TOOL_NAME,
            targets=["assumed-breach-drill"],
            params={"c2_export": _c2_export(), "framework": "sliver"},
        )
    )

    payload = _payload(execution)
    assert payload["framework"] == "sliver"
    assert payload["safety"]["c2_command_execution_performed"] is False
    assert payload["safety"]["automatic_approval_created"] is False
    assert payload["safety"]["runtime_binding_bypassed"] is False


def test_c2_ingest_is_registered_with_read_only_preview() -> None:
    registry = runner_capability_registry()
    capability = next(item for item in registry["capabilities"] if item["name"] == TOOL_NAME)
    preview = _runner_command_preview(TOOL_NAME, ["assumed-breach-drill"], {"framework": "mythic"})

    assert TOOL_NAME in SUPPORTED_TOOLS
    assert registry["complete"] is True
    assert capability["risk_tier"] == "intrusive"
    assert capability["required_approvals"] == 1
    assert "command_execution_requested" in capability["blockers"]
    assert "--read-only" in preview
    assert "--no-command-exec" in preview
