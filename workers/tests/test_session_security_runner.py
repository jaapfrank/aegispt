from __future__ import annotations

import json
from types import SimpleNamespace

import httpx
import pytest

from workers.orchestration.findings import extract_findings
from workers.orchestration.tasks import SUPPORTED_TOOLS
from workers.runners.base.contracts import EvidenceArtifact
from workers.runners.session_security.runner import (
    SESSION_SECURITY_RESULTS_ARTIFACT_NAME,
    execute_session_security_analysis,
)


class ArtifactRecord:
    uri = "artifact://session-security/results"


def _client_factory(handler):
    transport = httpx.MockTransport(handler)

    def factory(**kwargs):
        return httpx.Client(transport=transport, **kwargs)

    return factory


def test_session_security_detects_fixation_logout_replay_entropy_cookie_flags_and_token_url() -> None:
    entropy_counter = {"value": 1000}

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/login") and request.method == "POST":
            return httpx.Response(
                200,
                headers={"Set-Cookie": "sessionid=1000; Path=/"},
                text="welcome analyst",
            )
        if path.endswith("/logout"):
            return httpx.Response(200, text="logged out")
        if path.endswith("/account"):
            if "sessionid=1000" in request.headers.get("Cookie", ""):
                return httpx.Response(200, text="welcome analyst account")
            return httpx.Response(401, text="login required")
        if path.endswith("/token"):
            entropy_counter["value"] += 1
            return httpx.Response(
                200,
                headers={"Set-Cookie": f"sessionid={entropy_counter['value']}; Path=/"},
                text="token issued",
            )
        return httpx.Response(
            200,
            headers={"Set-Cookie": "sessionid=1000; Path=/"},
            text="login form",
        )

    execution = execute_session_security_analysis(
        ["https://app.example.test/app/"],
        scope_allowlist={"urls": ["https://app.example.test/app/"]},
        auth_contexts=[
            {
                "label": "Analyst",
                "username": "analyst@example.test",
                "password": "CorrectHorseBatteryStaple!",
            }
        ],
        login_url="login",
        logout_url="logout",
        protected_url="account",
        token_sample_url="token",
        success_markers=["welcome analyst"],
        request_contexts=[{"url": "https://app.example.test/app/view?sessionid=abc123"}],
        sample_count=4,
        client_factory=_client_factory(handler),
    )

    assert execution.tool == "session-security"
    assert execution.exit_code == 0
    assert execution.artifacts[0].name == SESSION_SECURITY_RESULTS_ARTIFACT_NAME

    payload = json.loads(execution.artifacts[0].data.decode("utf-8"))
    assert payload["safety"]["requires_active_approval"] is True
    assert payload["safety"]["configured_credentials_only"] is True
    assert payload["safety"]["other_user_session_hijacking"] is False
    assert payload["summary"]["session_fixation_findings"] == 1
    assert payload["summary"]["logout_replay_findings"] == 1
    assert payload["summary"]["entropy_findings"] == 1
    assert payload["summary"]["token_url_findings"] == 1
    assert payload["summary"]["cookie_flag_findings"] >= 3
    assert {finding["title"] for finding in payload["findings"]} >= {
        "Session Fixation - Token Not Rotated After Login",
        "Session Not Invalidated on Logout - Allows Session Replay Attacks",
        "Session Token Entropy Weakness",
        "Session Token in URL",
        "Session Cookie Missing Secure Flag",
        "Session Cookie Missing HttpOnly Flag",
        "Session Cookie Missing SameSite Lax/Strict",
    }
    assert "CorrectHorseBatteryStaple!" not in execution.artifacts[0].data.decode("utf-8")

    task = SimpleNamespace(
        tool="session-security",
        target_id="https://app.example.test/app/",
        params_json={},
    )
    findings = extract_findings(
        task=task,
        artifact=EvidenceArtifact(
            name=SESSION_SECURITY_RESULTS_ARTIFACT_NAME,
            content_type="application/json",
            data=execution.artifacts[0].data,
            kind="runner-results",
        ),
        artifact_record=ArtifactRecord(),
    )

    assert len(findings) == payload["summary"]["finding_count"]
    assert {finding.severity for finding in findings} >= {"high", "medium"}
    assert all("session_security" in finding.methodology_tags for finding in findings)


def test_session_security_rejects_missing_credentials_and_out_of_scope_targets() -> None:
    with pytest.raises(ValueError, match="configured username/password"):
        execute_session_security_analysis(
            ["https://app.example.test/app/"],
            scope_allowlist={"urls": ["https://app.example.test/app/"]},
            auth_contexts=[{"username": "analyst@example.test"}],
        )

    with pytest.raises(ValueError, match="outside approved web scope"):
        execute_session_security_analysis(
            ["https://other.example.test/app/"],
            scope_allowlist={"urls": ["https://app.example.test/app/"]},
            auth_contexts=[{"username": "analyst@example.test", "password": "secret"}],
        )


def test_session_security_is_supported() -> None:
    assert "session-security" in SUPPORTED_TOOLS

