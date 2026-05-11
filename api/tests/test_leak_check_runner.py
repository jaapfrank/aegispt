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
from workers.runners.leak_check.runner import (
    LEAK_CHECK_RESULTS_ARTIFACT_NAME,
    TOOL_NAME,
    execute_leak_check_review,
)


class ArtifactRecord:
    uri = "artifact://leak-check/results"


def _leak_export() -> dict[str, object]:
    return {
        "source": "authorized-osint-fixture",
        "records": [
            {
                "email": "alice@example.com",
                "source": "Example breach",
                "password": "CorrectHorseBatteryStaple!",
                "breach_date": "2024-01-01",
            },
            {
                "email": "bob@example.com",
                "source": "Hash corpus",
                "password_hash": "deadbeef",
            },
            {
                "email": "mallory@outside.test",
                "source": "Outside breach",
                "password": "outside-secret",
            },
        ],
    }


def _payload(execution) -> dict[str, object]:
    artifact = next(
        item for item in execution.artifacts if item.name == LEAK_CHECK_RESULTS_ARTIFACT_NAME
    )
    return json.loads(artifact.data.decode("utf-8"))


def test_leak_check_imports_metadata_and_redacts_raw_credentials() -> None:
    execution = execute_leak_check_review(["example.com"], leak_export=_leak_export())

    assert execution.tool == TOOL_NAME
    assert execution.exit_code == 0
    assert execution.protected_outputs == []
    assert execution.metadata["credential_values_stored"] is False
    assert execution.metadata["credential_attack_auto_queue_created"] is False

    payload = _payload(execution)
    assert payload["safety"]["metadata_only"] is True
    assert payload["safety"]["credential_values_stored"] is False
    assert payload["safety"]["raw_passwords_stored"] is False
    assert payload["safety"]["raw_hashes_stored"] is False
    assert payload["safety"]["credential_attack_auto_queue_created"] is False
    assert payload["safety"]["login_attempts_performed"] is False
    assert payload["summary"]["record_count"] == 3
    assert payload["summary"]["in_scope_record_count"] == 2
    assert payload["summary"]["plaintext_record_count"] == 1
    assert payload["summary"]["hash_record_count"] == 1

    artifact_text = execution.artifacts[0].data.decode("utf-8")
    assert "CorrectHorseBatteryStaple!" not in artifact_text
    assert "outside-secret" not in artifact_text
    assert "deadbeef" not in artifact_text
    assert "alice@example.com" not in artifact_text
    assert "bob@example.com" not in artifact_text

    findings = extract_findings(
        task=SimpleNamespace(tool=TOOL_NAME, target_id="example.com", params_json={}),
        artifact=EvidenceArtifact(
            name=LEAK_CHECK_RESULTS_ARTIFACT_NAME,
            content_type="application/json",
            data=execution.artifacts[0].data,
            kind="runner-results",
        ),
        artifact_record=ArtifactRecord(),
    )

    assert {finding.title for finding in findings} == {
        "Credential Leak Metadata Observed",
        "Plaintext Credential Exposure Reported",
        "Credential Hash Exposure Reported",
    }
    assert all("credential_leak_review" in finding.methodology_tags for finding in findings)


def test_leak_check_blocks_auto_spray_and_dispatch_stays_metadata_only() -> None:
    with pytest.raises(ValueError, match="metadata-only"):
        execute_leak_check_review(
            ["example.com"],
            leak_export=_leak_export(),
            credential_attack_auto_queue_requested=True,
        )

    execution = dispatch_runner(
        RunnerRequest(
            tool=TOOL_NAME,
            targets=["example.com"],
            params={"leak_export": _leak_export()},
        )
    )

    payload = _payload(execution)
    assert payload["safety"]["credential_attack_auto_queue_created"] is False
    assert payload["safety"]["login_attempts_performed"] is False
    assert payload["safety"]["runtime_binding_bypassed"] is False


def test_leak_check_is_registered_with_metadata_only_preview() -> None:
    registry = runner_capability_registry()
    capability = next(item for item in registry["capabilities"] if item["name"] == TOOL_NAME)
    preview = _runner_command_preview(TOOL_NAME, ["example.com"], {"source": "hibp-fixture"})

    assert TOOL_NAME in SUPPORTED_TOOLS
    assert registry["complete"] is True
    assert capability["risk_tier"] == "active"
    assert capability["required_approvals"] == 1
    assert "credential_attack_auto_queue_requested" in capability["blockers"]
    assert "--metadata-only" in preview
    assert "--no-auto-spray" in preview
