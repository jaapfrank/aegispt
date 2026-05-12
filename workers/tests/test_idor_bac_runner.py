from __future__ import annotations

import json
from types import SimpleNamespace

import httpx
import pytest

from workers.orchestration.findings import extract_findings
from workers.orchestration.tasks import SUPPORTED_TOOLS
from workers.runners.base.contracts import EvidenceArtifact
from workers.runners.idor_bac.runner import IDOR_BAC_ARTIFACT_NAME, execute_idor_bac_probe


class ArtifactRecord:
    uri = "artifact://idor-bac/results"


def _client_factory(handler):
    transport = httpx.MockTransport(handler)

    def factory(**kwargs):
        return httpx.Client(transport=transport, **kwargs)

    return factory


def test_idor_bac_skips_gracefully_when_credentials_missing() -> None:
    result = execute_idor_bac_probe(
        ["https://app.example.test/app/"],
        auth_contexts=[],
        scope_allowlist={"urls": ["https://app.example.test/app/"]},
    )
    assert result.exit_code == 0
    assert result.metadata.get("skipped") is True


def test_idor_bac_detects_confirmed_broken_access_control_signals() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        cookie = request.headers.get("Cookie", "")
        if request.url.path == "/app/":
            return httpx.Response(
                200,
                text='<a href="/app/api/users/100">profile</a>',
            )
        if request.url.path == "/app/api/users/120" and "session=alice" in cookie:
            return httpx.Response(200, json={"id": 120, "email": "bob@example.test"})
        if request.url.path == "/app/settings" and request.url.params.get("role") == "admin":
            return httpx.Response(200, text="admin-panel-ready")
        if (
            request.url.path == "/app/api/users/100"
            and request.method == "POST"
            and request.headers.get("X-HTTP-Method-Override") == "DELETE"
        ):
            return httpx.Response(200, text="delete accepted")
        if request.url.path == "/app/admin":
            return httpx.Response(200, text="admin console")
        return httpx.Response(404, text="not found")

    execution = execute_idor_bac_probe(
        ["https://app.example.test/app/"],
        auth_contexts=[
            {
                "label": "Alice User",
                "role": "User",
                "username": "alice@example.test",
                "headers": {"Cookie": "session=alice"},
                "marker_tokens": ["alice@example.test"],
                "owned_object_ids": ["100"],
            },
            {
                "label": "Bob User",
                "role": "User",
                "username": "bob@example.test",
                "headers": {"Cookie": "session=bob"},
                "marker_tokens": ["bob@example.test"],
                "owned_object_ids": ["120"],
            },
        ],
        request_contexts=[
            {
                "url": "settings?role=user",
                "success_markers": ["admin-panel-ready"],
            }
        ],
        method_override_paths=["api/users/100"],
        admin_paths=["admin"],
        scope_allowlist={"urls": ["https://app.example.test/app/"]},
        client_factory=_client_factory(handler),
    )

    assert execution.tool == "idor-bac"
    assert execution.exit_code == 0
    assert execution.artifacts[0].name == IDOR_BAC_ARTIFACT_NAME
    assert execution.metadata["finding_count"] == 4

    payload = json.loads(execution.artifacts[0].data.decode("utf-8"))
    assert payload["safety"]["max_id_delta"] == 20
    assert payload["safety"]["bruteforce"] is False
    finding_titles = {finding["title"] for finding in payload["findings"]}
    assert "IDOR - Horizontal Privilege Escalation" in finding_titles
    assert "Broken Access Control - Privilege Escalation via Parameter" in finding_titles
    assert "Broken Access Control - Method Override Accepted" in finding_titles
    assert "Broken Access Control - Admin Path Exposed" in finding_titles
    confirmed_idor = next(
        finding
        for finding in payload["findings"]
        if finding["title"] == "IDOR - Horizontal Privilege Escalation"
    )
    assert confirmed_idor["severity"] == "critical"
    assert confirmed_idor["confirmed"] is True

    task = SimpleNamespace(tool="idor-bac", target_id="https://app.example.test/app/", params_json={})
    findings = extract_findings(
        task=task,
        artifact=EvidenceArtifact(
            name=IDOR_BAC_ARTIFACT_NAME,
            content_type="application/json",
            data=execution.artifacts[0].data,
            kind="probe-results",
        ),
        artifact_record=ArtifactRecord(),
    )

    assert len(findings) == 4
    assert {finding.severity for finding in findings} == {"critical", "high"}
    assert any("authorization" in finding.methodology_tags for finding in findings)


def test_idor_bac_is_supported() -> None:
    assert "idor-bac" in SUPPORTED_TOOLS
