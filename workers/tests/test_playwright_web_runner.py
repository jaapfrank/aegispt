from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from workers.orchestration.findings import extract_findings
from workers.runners.base.contracts import EvidenceArtifact
from workers.runners.playwright_web.runner import (
    PLAYWRIGHT_WEB_CONSOLE_ARTIFACT_NAME,
    PLAYWRIGHT_WEB_DOM_ARTIFACT_NAME,
    PLAYWRIGHT_WEB_NETWORK_ARTIFACT_NAME,
    PLAYWRIGHT_WEB_RESULTS_ARTIFACT_NAME,
    PLAYWRIGHT_WEB_SCREENSHOT_ARTIFACT_NAME,
    BrowserObservation,
    execute_playwright_web_validation,
)


class ArtifactRecord:
    uri = "artifact://playwright-web/results"


def test_playwright_web_rejects_out_of_scope_target() -> None:
    with pytest.raises(ValueError, match="outside scope"):
        execute_playwright_web_validation(
            ["https://evil.example.test"],
            scope_allowlist={"urls": ["https://app.example.test"]},
        )


def test_playwright_web_missing_auth_fallback_is_truthful() -> None:
    execution = execute_playwright_web_validation(
        ["https://app.example.test"],
        scope_allowlist={"urls": ["https://app.example.test"]},
        mode="active",
        requires_auth_context=True,
    )

    assert execution.exit_code == 0
    assert execution.metadata["status"] == "skipped"
    assert execution.metadata["reason"] == "missing_auth_context"
    payload = json.loads(execution.artifacts[0].data.decode("utf-8"))
    assert payload["status"] == "skipped"
    assert payload["safety"]["destructive_actions"] is False
    assert payload["targets"][0]["status"] == "skipped"


def test_playwright_web_collects_browser_artifacts_and_normalizes_findings() -> None:
    def collector(**kwargs):
        assert kwargs["proof_marker"] == "aegispt-proof-123"
        return BrowserObservation(
            url=kwargs["target"],
            final_url=f"{kwargs['target']}/dashboard",
            title="Operator Portal",
            dom="<html><body>aegispt-proof-123<form method='post'></form></body></html>",
            screenshot=b"\x89PNG\r\n\x1a\nbrowser-proof",
            console=[{"type": "log", "text": "loaded"}],
            network=[
                {
                    "event": "request",
                    "method": "GET",
                    "url": kwargs["target"],
                    "headers": {"Authorization": "Bearer secret-token"},
                }
            ],
            storage={
                "localStorage": {"access_token": "secret-token"},
                "sessionStorage": {},
            },
            forms=[{"method": "post", "action": f"{kwargs['target']}/change", "inputNames": []}],
        )

    execution = execute_playwright_web_validation(
        ["https://app.example.test"],
        scope_allowlist={"urls": ["https://app.example.test"]},
        mode="active",
        proof_marker="aegispt-proof-123",
        collector=collector,
    )

    assert execution.exit_code == 0
    assert execution.tool == "playwright-web"
    assert execution.metadata["finding_count"] == 3
    artifact_names = {artifact.name for artifact in execution.artifacts}
    assert PLAYWRIGHT_WEB_RESULTS_ARTIFACT_NAME in artifact_names
    assert PLAYWRIGHT_WEB_NETWORK_ARTIFACT_NAME in artifact_names
    assert PLAYWRIGHT_WEB_CONSOLE_ARTIFACT_NAME in artifact_names
    assert PLAYWRIGHT_WEB_DOM_ARTIFACT_NAME in artifact_names
    assert PLAYWRIGHT_WEB_SCREENSHOT_ARTIFACT_NAME in artifact_names

    network_artifact = next(
        artifact for artifact in execution.artifacts if artifact.name == PLAYWRIGHT_WEB_NETWORK_ARTIFACT_NAME
    )
    assert "secret-token" not in network_artifact.data.decode("utf-8")
    assert "[redacted]" in network_artifact.data.decode("utf-8")

    results_artifact = next(
        artifact for artifact in execution.artifacts if artifact.name == PLAYWRIGHT_WEB_RESULTS_ARTIFACT_NAME
    )
    task = SimpleNamespace(tool="playwright-web", target_id="https://app.example.test", params_json={})
    findings = extract_findings(
        task=task,
        artifact=EvidenceArtifact(
            name=PLAYWRIGHT_WEB_RESULTS_ARTIFACT_NAME,
            content_type="application/json",
            data=results_artifact.data,
            kind="browser-validation-results",
        ),
        artifact_record=ArtifactRecord(),
    )

    titles = {finding.title for finding in findings}
    assert "Reflected browser proof marker observed" in titles
    assert "Browser storage exposes sensitive token-like state" in titles
    assert "State-changing browser form lacks visible anti-CSRF signal" in titles
    assert all(finding.evidence_ref == ArtifactRecord.uri for finding in findings)


def test_playwright_web_applies_stored_session_without_leaking_secret() -> None:
    captured: dict[str, object] = {}

    def collector(**kwargs):
        captured["auth_contexts"] = kwargs["auth_contexts"]
        return {"url": kwargs["target"], "dom": "<html>ok</html>", "storage": {}, "forms": []}

    execution = execute_playwright_web_validation(
        ["https://app.example.test"],
        scope_allowlist={"urls": ["https://app.example.test"]},
        auth_contexts=[
            {
                "label": "Portal User",
                "headers": {"Cookie": "sessionid=super-secret-session"},
            }
        ],
        collector=collector,
    )

    assert execution.metadata["auth_context_count"] == 1
    assert captured["auth_contexts"][0]["headers"]["Cookie"] == "sessionid=super-secret-session"
    for artifact in execution.artifacts:
        assert "super-secret-session" not in artifact.data.decode("utf-8", errors="ignore")
