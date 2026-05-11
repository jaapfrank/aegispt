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
from workers.runners.social_campaign.runner import (
    SOCIAL_CAMPAIGN_RESULTS_ARTIFACT_NAME,
    TOOL_NAME,
    execute_social_campaign_review,
)


class ArtifactRecord:
    uri = "artifact://social-campaign/results"


def _campaign_export() -> dict[str, object]:
    return {
        "campaign": {
            "id": "gophish-campaign-42",
            "name": "Quarterly Awareness Drill",
            "status": "Completed",
            "results": [
                {
                    "email": "alice@example.com",
                    "status": "Clicked Link",
                    "events": [
                        {"message": "Email Opened"},
                        {"message": "Clicked Link"},
                    ],
                },
                {
                    "email": "bob@example.com",
                    "status": "Submitted Data",
                    "events": [
                        {
                            "message": "Submitted Data",
                            "details": {"password": "CorrectHorseBatteryStaple!"},
                        }
                    ],
                    "submitted_password": "CorrectHorseBatteryStaple!",
                },
                {
                    "email": "mallory@outside.test",
                    "status": "Clicked Link",
                    "events": [{"message": "Clicked Link"}],
                },
            ],
        }
    }


def _artifact_payload(execution) -> dict[str, object]:
    artifact = next(
        item
        for item in execution.artifacts
        if item.name == SOCIAL_CAMPAIGN_RESULTS_ARTIFACT_NAME
    )
    return json.loads(artifact.data.decode("utf-8"))


def test_social_campaign_import_normalizes_metrics_and_redacts_credentials() -> None:
    execution = execute_social_campaign_review(
        ["Quarterly Awareness Drill"],
        campaign_export=_campaign_export(),
        approved_recipient_domains=["example.com"],
        operator_approved=False,
    )

    assert execution.tool == TOOL_NAME
    assert execution.exit_code == 0
    assert execution.protected_outputs == []
    assert execution.metadata["runtime_campaign_dispatch_performed"] is False
    assert execution.metadata["credential_values_stored_in_artifacts"] is False

    payload = _artifact_payload(execution)
    assert payload["safety"]["review_only"] is True
    assert payload["safety"]["runtime_campaign_dispatch_performed"] is False
    assert payload["safety"]["external_send_performed"] is False
    assert payload["safety"]["automatic_approval_created"] is False
    assert payload["safety"]["credential_values_stored_in_artifacts"] is False
    assert payload["safety"]["submitted_secret_values_stored"] is False
    assert payload["summary"]["recipient_count"] == 3
    assert payload["summary"]["clicked_count"] == 3
    assert payload["summary"]["submitted_count"] == 1
    assert payload["out_of_scope_recipient_domains"] == ["outside.test"]

    artifact_text = execution.artifacts[0].data.decode("utf-8")
    assert "CorrectHorseBatteryStaple!" not in artifact_text
    assert "alice@example.com" not in artifact_text
    assert "bob@example.com" not in artifact_text
    assert "mallory@outside.test" not in artifact_text

    finding_titles = {finding["title"] for finding in payload["findings"]}
    assert finding_titles >= {
        "Credential Submission Observed in Social Engineering Campaign",
        "High Click Rate in Social Engineering Campaign",
        "Low Reporting Rate in Social Engineering Campaign",
        "Campaign Evidence Contains Out-of-Scope Recipient Domains",
    }

    findings = extract_findings(
        task=SimpleNamespace(tool=TOOL_NAME, target_id="Quarterly Awareness Drill", params_json={}),
        artifact=EvidenceArtifact(
            name=SOCIAL_CAMPAIGN_RESULTS_ARTIFACT_NAME,
            content_type="application/json",
            data=execution.artifacts[0].data,
            kind="runner-results",
        ),
        artifact_record=ArtifactRecord(),
    )

    assert len(findings) == payload["summary"]["finding_count"]
    assert {finding.severity for finding in findings} >= {"high", "medium", "low"}
    assert all("social_engineering" in finding.methodology_tags for finding in findings)


def test_social_campaign_blocks_runtime_launch_and_dispatch_remains_review_only() -> None:
    with pytest.raises(ValueError, match="review-only"):
        execute_social_campaign_review(
            ["Quarterly Awareness Drill"],
            campaign_export=_campaign_export(),
            launch_requested=True,
            operator_approved=True,
        )

    execution = dispatch_runner(
        RunnerRequest(
            tool=TOOL_NAME,
            targets=["Quarterly Awareness Drill"],
            params={
                "campaign_export": _campaign_export(),
                "operator_approved": True,
                "approved_recipient_domains": ["example.com"],
            },
        )
    )

    payload = _artifact_payload(execution)
    assert payload["safety"]["runtime_campaign_dispatch_performed"] is False
    assert payload["safety"]["external_send_performed"] is False
    assert payload["safety"]["operator_approval_required_for_send"] is True


def test_social_campaign_is_registered_with_review_only_contract() -> None:
    registry = runner_capability_registry()
    capability = next(item for item in registry["capabilities"] if item["name"] == TOOL_NAME)
    preview = _runner_command_preview(
        TOOL_NAME,
        ["Quarterly Awareness Drill"],
        {"campaign_ref": "quarterly-awareness"},
    )

    assert TOOL_NAME in SUPPORTED_TOOLS
    assert registry["complete"] is True
    assert capability["risk_tier"] == "active"
    assert capability["required_approvals"] == 1
    assert "live_send_requested" in capability["blockers"]
    assert "--review-only" in preview
    assert "--no-send" in preview
