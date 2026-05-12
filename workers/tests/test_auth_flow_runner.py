from __future__ import annotations

import json
from types import SimpleNamespace

import httpx
import pytest

from workers.orchestration.findings import extract_findings
from workers.orchestration.tasks import SUPPORTED_TOOLS
from workers.runners.auth_flow.runner import (
    AUTH_FLOW_RESULTS_ARTIFACT_NAME,
    execute_auth_flow_analysis,
)
from workers.runners.base.contracts import EvidenceArtifact


class ArtifactRecord:
    uri = "artifact://auth-flow/results"


def _client_factory(handler):
    transport = httpx.MockTransport(handler)

    def factory(**kwargs):
        return httpx.Client(transport=transport, **kwargs)

    return factory


def test_auth_flow_detects_reset_and_login_flow_weaknesses() -> None:
    reset_counter = {"value": 1000}
    brute_force_attempts = {"value": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/reset") and request.headers.get("host") == "evil.example.test":
            return httpx.Response(
                200,
                text="sent https://evil.example.test/reset/consume?token=9999",
            )
        if path.endswith("/reset"):
            reset_counter["value"] += 1
            return httpx.Response(
                200,
                text=f"sent https://app.example.test/app/reset/consume?token={reset_counter['value']}",
            )
        if path.endswith("/reset/consume"):
            return httpx.Response(200, text="password changed")
        if path.endswith("/login"):
            username = str(request.url.params.get("username") or "")
            body = request.content.decode("utf-8") if request.content else ""
            username = username or ("alice%40example.test" if "alice%40example.test" in body else "")
            if username:
                brute_force_attempts["value"] += 1
            if "missing%40example.test" in body or "missing@example.test" in str(request.url):
                return httpx.Response(200, text="No such user")
            return httpx.Response(401, text="Bad password")
        return httpx.Response(404, text="not found")

    execution = execute_auth_flow_analysis(
        ["http://app.example.test/app/"],
        scope_allowlist={"urls": ["http://app.example.test/app/"]},
        auth_contexts=[
            {
                "label": "Reset User",
                "username": "alice@example.test",
                "password": "CorrectHorseBatteryStaple!",
            }
        ],
        login_url="login",
        password_reset_url="reset",
        reset_consume_url="reset/consume",
        reset_poison_host="evil.example.test",
        invalid_usernames=["missing@example.test"],
        reset_token_samples=5,
        failed_login_attempts=10,
        client_factory=_client_factory(handler),
    )

    assert execution.tool == "auth-flow"
    assert execution.exit_code == 0
    assert execution.artifacts[0].name == AUTH_FLOW_RESULTS_ARTIFACT_NAME

    payload = json.loads(execution.artifacts[0].data.decode("utf-8"))
    assert payload["safety"]["requires_active_approval"] is True
    assert payload["safety"]["configured_test_accounts_only"] is True
    assert payload["safety"]["brute_force_attempt_limit"] == 10
    assert payload["safety"]["credential_values_stored_in_artifacts"] is False
    assert payload["safety"]["reset_token_values_stored_in_artifacts"] is False
    assert payload["summary"]["predictable_reset_token_findings"] == 1
    assert payload["summary"]["reset_token_reuse_findings"] == 1
    assert payload["summary"]["reset_poisoning_findings"] == 1
    assert payload["summary"]["username_enumeration_findings"] == 1
    assert payload["summary"]["brute_force_findings"] == 1
    assert payload["summary"]["insecure_credential_submission_findings"] == 1
    assert brute_force_attempts["value"] <= 12
    assert {finding["title"] for finding in payload["findings"]} >= {
        "Predictable Password Reset Token",
        "Password Reset Token Reuse Accepted",
        "Password Reset Host Header Injection",
        "Username Enumeration in Authentication Flow",
        "Missing Brute Force Protection on Login",
        "Credentials Submitted Over HTTP",
    }
    artifact_text = execution.artifacts[0].data.decode("utf-8")
    assert "CorrectHorseBatteryStaple!" not in artifact_text
    assert "1001" not in artifact_text

    task = SimpleNamespace(tool="auth-flow", target_id="http://app.example.test/app/", params_json={})
    findings = extract_findings(
        task=task,
        artifact=EvidenceArtifact(
            name=AUTH_FLOW_RESULTS_ARTIFACT_NAME,
            content_type="application/json",
            data=execution.artifacts[0].data,
            kind="runner-results",
        ),
        artifact_record=ArtifactRecord(),
    )

    assert len(findings) == payload["summary"]["finding_count"]
    assert {finding.severity for finding in findings} >= {"high", "medium"}
    assert all("auth_flow" in finding.methodology_tags for finding in findings)


def test_auth_flow_skips_gracefully_when_credentials_missing() -> None:
    # Missing credentials -> graceful skip with exit_code=0
    result = execute_auth_flow_analysis(
        ["https://app.example.test/app/"],
        scope_allowlist={"urls": ["https://app.example.test/app/"]},
        auth_contexts=[{"username": "analyst@example.test"}],
    )
    assert result.exit_code == 0
    assert result.metadata.get("skipped") is True

    # Out-of-scope target still raises ValueError (scope always enforced)
    with pytest.raises(ValueError, match="outside approved web scope"):
        execute_auth_flow_analysis(
            ["https://other.example.test/app/"],
            scope_allowlist={"urls": ["https://app.example.test/app/"]},
            auth_contexts=[{"username": "analyst@example.test", "password": "secret"}],
        )



def test_auth_flow_is_supported() -> None:
    assert "auth-flow" in SUPPORTED_TOOLS
