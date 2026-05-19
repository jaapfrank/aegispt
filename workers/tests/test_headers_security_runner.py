from __future__ import annotations

import json
from types import SimpleNamespace

import httpx
import pytest

from workers.orchestration.findings import extract_findings
from workers.orchestration.tasks import SUPPORTED_TOOLS
from workers.runners.base.contracts import EvidenceArtifact
from workers.runners.headers_security.runner import (
    HEADERS_SECURITY_RESULTS_ARTIFACT_NAME,
    execute_headers_security_analysis,
)


class ArtifactRecord:
    uri = "artifact://headers-security/results"


def _client_factory(handler):
    transport = httpx.MockTransport(handler)

    def factory(**kwargs):
        return httpx.Client(transport=transport, **kwargs)

    return factory


def test_headers_security_detects_cors_csp_clickjacking_hsts_and_disclosure() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        origin = request.headers.get("Origin")
        headers = {
            "Content-Security-Policy": "script-src 'self' 'unsafe-inline' 'unsafe-eval' * data: https://ajax.googleapis.com",
            "Server": "Apache/2.4.49",
            "X-Powered-By": "PHP/7.2.0",
        }
        if origin:
            headers["Access-Control-Allow-Origin"] = origin
            headers["Access-Control-Allow-Credentials"] = "true"
        return httpx.Response(
            200,
            headers=headers,
            text='<form action="/app/login"><input type="password" name="password"></form>',
        )

    execution = execute_headers_security_analysis(
        ["https://app.example.test/app/login"],
        scope_allowlist={"urls": ["https://app.example.test/app/"]},
        client_factory=_client_factory(handler),
    )

    assert execution.tool == "headers-security"
    assert execution.exit_code == 0
    assert execution.artifacts[0].name == HEADERS_SECURITY_RESULTS_ARTIFACT_NAME
    payload = json.loads(execution.artifacts[0].data.decode("utf-8"))
    assert payload["safety"]["actual_cors_data_extraction"] is False
    assert payload["safety"]["csp_nonce_bypass_attempted"] is False
    assert payload["safety"]["clickjacking_poc_created"] is False
    assert payload["safety"]["zap_configuration_changed"] is False
    assert payload["summary"]["cors_findings"] >= 2
    assert payload["summary"]["csp_findings"] >= 5
    assert payload["summary"]["clickjacking_findings"] == 1
    assert payload["summary"]["hsts_findings"] == 1
    assert payload["summary"]["information_disclosure_findings"] >= 2

    finding_titles = {finding["title"] for finding in payload["findings"]}
    assert {
        "CORS Credential Reflection Allows Cross-Origin Authenticated Reads",
        "CSP Allows unsafe-inline Scripts",
        "CSP Allows unsafe-eval Scripts",
        "CSP Uses Wildcard Script Source",
        "CSP Missing default-src Directive",
        "CSP Allows data: Script Source",
        "CSP Script Allowlist Includes JSONP-Capable Source",
        "Sensitive Page Missing Clickjacking Frame Protection",
        "HSTS Missing on HTTPS Target",
        "Information Disclosure Header Exposes Platform Detail",
    }.issubset(finding_titles)

    task = SimpleNamespace(
        tool="headers-security",
        target_id="https://app.example.test/app/login",
        params_json={},
    )
    findings = extract_findings(
        task=task,
        artifact=EvidenceArtifact(
            name=HEADERS_SECURITY_RESULTS_ARTIFACT_NAME,
            content_type="application/json",
            data=execution.artifacts[0].data,
            kind="runner-results",
        ),
        artifact_record=ArtifactRecord(),
    )

    assert len(findings) >= 10
    assert "critical" in {finding.severity for finding in findings}
    assert all("headers-security-validation" in finding.methodology_tags for finding in findings)


def test_headers_security_rejects_out_of_scope_targets_and_bad_timeout() -> None:
    with pytest.raises(ValueError, match="outside approved web scope"):
        execute_headers_security_analysis(
            ["https://outside.example.test/app/"],
            scope_allowlist={"urls": ["https://app.example.test/app/"]},
        )

    with pytest.raises(ValueError, match="timeout_seconds"):
        execute_headers_security_analysis(
            ["https://app.example.test/app/"],
            scope_allowlist={"urls": ["https://app.example.test/app/"]},
            timeout_seconds=0,
        )


def test_headers_security_is_supported() -> None:
    assert "headers-security" in SUPPORTED_TOOLS
