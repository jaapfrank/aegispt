from __future__ import annotations

import json
from types import SimpleNamespace

import httpx
import pytest

from api.app.services.runner_registry import runner_capability_registry
from workers.orchestration.findings import extract_findings
from workers.orchestration.tasks import (
    SUPPORTED_TOOLS,
    _runner_command_preview,
    dispatch_runner,
)
from workers.runners.base.contracts import EvidenceArtifact, RunnerRequest
from workers.runners.waf_detect.runner import (
    TOOL_NAME,
    WAF_DETECT_RESULTS_ARTIFACT_NAME,
    execute_waf_detection,
)


class ArtifactRecord:
    uri = "artifact://waf-detect/results"


def _client_factory(handler):
    transport = httpx.MockTransport(handler)

    def factory(**kwargs):
        return httpx.Client(transport=transport, **kwargs)

    return factory


def _payload(execution) -> dict[str, object]:
    artifact = next(
        item for item in execution.artifacts if item.name == WAF_DETECT_RESULTS_ARTIFACT_NAME
    )
    return json.loads(artifact.data.decode("utf-8"))


def test_waf_detect_fingerprints_vendor_and_blocked_request_without_evasion() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["user-agent"] == "AegisPT/waf-detect defensive fingerprint"
        return httpx.Response(
            403,
            headers={"Server": "cloudflare", "CF-Ray": "abc123"},
            text="Access denied by web application firewall",
        )

    execution = execute_waf_detection(
        ["https://app.example.test/"],
        scope_allowlist={"urls": ["https://app.example.test/"]},
        client_factory=_client_factory(handler),
    )

    assert execution.tool == TOOL_NAME
    assert execution.exit_code == 0
    assert execution.protected_outputs == []
    assert execution.metadata["automatic_evasion_enabled"] is False
    assert execution.metadata["web_runner_mutation_performed"] is False

    payload = _payload(execution)
    assert payload["safety"]["defensive_detection_only"] is True
    assert payload["safety"]["automatic_evasion_enabled"] is False
    assert payload["safety"]["web_runner_mutation_performed"] is False
    assert payload["safety"]["operator_approval_required_for_evasion"] is True
    assert payload["safety"]["destructive_payloads_sent"] is False
    assert payload["safety"]["credential_materialization_performed"] is False
    assert payload["detected_vendors"] == ["Cloudflare"]
    assert payload["summary"]["blocked_target_count"] == 1
    assert all(item["operator_review_only"] is True for item in payload["recommendations"])
    assert all(item["runtime_change"] is False for item in payload["recommendations"])

    findings = extract_findings(
        task=SimpleNamespace(tool=TOOL_NAME, target_id="https://app.example.test/", params_json={}),
        artifact=EvidenceArtifact(
            name=WAF_DETECT_RESULTS_ARTIFACT_NAME,
            content_type="application/json",
            data=execution.artifacts[0].data,
            kind="runner-results",
        ),
        artifact_record=ArtifactRecord(),
    )

    assert len(findings) == payload["summary"]["finding_count"]
    assert {finding.title for finding in findings} == {
        "Web Application Firewall Detected",
        "WAF or Edge Control Blocked Request Evidence",
    }
    assert all("waf_detection" in finding.methodology_tags for finding in findings)


def test_waf_detect_blocks_auto_evasion_and_accepts_imported_samples() -> None:
    with pytest.raises(ValueError, match="never enables automatic evasion"):
        execute_waf_detection(
            ["https://app.example.test/"],
            scope_allowlist={"urls": ["https://app.example.test/"]},
            auto_evasion_enabled=True,
            client_factory=_client_factory(lambda request: httpx.Response(200)),
        )

    execution = dispatch_runner(
        RunnerRequest(
            tool=TOOL_NAME,
            targets=["https://app.example.test/"],
            scope_allowlist={"urls": ["https://app.example.test/"]},
            params={
                "response_samples": [
                    {
                        "target": "https://app.example.test/",
                        "status_code": 503,
                        "headers": {"X-Amzn-Waf": "blocked"},
                        "body": "request blocked by security policy",
                    }
                ]
            },
        )
    )

    payload = _payload(execution)
    assert payload["source"] == "imported_response_samples"
    assert payload["detected_vendors"] == ["AWS WAF"]
    assert payload["safety"]["automatic_approval_created"] is False


def test_waf_detect_is_registered_with_review_only_preview() -> None:
    registry = runner_capability_registry()
    capability = next(item for item in registry["capabilities"] if item["name"] == TOOL_NAME)
    preview = _runner_command_preview(
        TOOL_NAME,
        ["https://app.example.test/"],
        {},
    )

    assert TOOL_NAME in SUPPORTED_TOOLS
    assert registry["complete"] is True
    assert capability["risk_tier"] == "active"
    assert capability["required_approvals"] == 1
    assert "auto_evasion_requested" in capability["blockers"]
    assert "--no-auto-evasion" in preview
    assert "--operator-review" in preview
