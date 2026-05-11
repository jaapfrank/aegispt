from __future__ import annotations

import json
from types import SimpleNamespace

import httpx
import pytest

from workers.orchestration.findings import extract_findings
from workers.orchestration.tasks import SUPPORTED_TOOLS
from workers.runners.base.contracts import EvidenceArtifact
from workers.runners.xss_extended.runner import (
    DEFAULT_XSS_PAYLOAD,
    XSS_EXTENDED_RESULTS_ARTIFACT_NAME,
    execute_xss_extended_scan,
)


class ArtifactRecord:
    uri = "artifact://xss-extended/results"


def _client_factory(handler):
    transport = httpx.MockTransport(handler)

    def factory(**kwargs):
        return httpx.Client(transport=transport, **kwargs)

    return factory


def test_xss_extended_detects_file_upload_ajax_json_and_xssi() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST" and request.url.path == "/app/upload":
            return httpx.Response(201, json={"url": "/app/uploads/aegispt-xss.html"})
        if request.method == "GET" and request.url.path == "/app/uploads/aegispt-xss.html":
            return httpx.Response(
                200,
                headers={"Content-Type": "text/html"},
                text=DEFAULT_XSS_PAYLOAD,
            )
        if request.method == "GET" and request.url.path == "/app/api/search":
            return httpx.Response(
                200,
                headers={"Content-Type": "text/html"},
                text=f'{{"query":"{request.url.params.get("q", "")}"}}',
            )
        if request.method == "GET" and request.url.path == "/app/api/profile.json":
            return httpx.Response(
                200,
                headers={"Content-Type": "application/json"},
                json={"email": "alice@example.test", "token": "session-token"},
            )
        return httpx.Response(404, text="not found")

    execution = execute_xss_extended_scan(
        ["https://app.example.test/app/"],
        scope_allowlist={"urls": ["https://app.example.test/app/"]},
        upload_contexts=[
            {"url": "upload", "uploaded_url": "uploads/aegispt-xss.html"},
        ],
        ajax_contexts=[
            {"url": "api/search?q=baseline", "parameters": ["q"]},
        ],
        xssi_contexts=[
            {"url": "api/profile.json"},
        ],
        client_factory=_client_factory(handler),
    )

    assert execution.tool == "xss-extended"
    assert execution.exit_code == 0
    assert execution.artifacts[0].name == XSS_EXTENDED_RESULTS_ARTIFACT_NAME
    assert execution.metadata["finding_count"] == 3

    payload = json.loads(execution.artifacts[0].data.decode("utf-8"))
    assert payload["safety"]["zap_configuration_changed"] is False
    assert payload["safety"]["approved_web_root_only"] is True
    assert payload["summary"]["file_upload_findings"] == 1
    assert payload["summary"]["ajax_json_findings"] == 1
    assert payload["summary"]["xssi_findings"] == 1
    finding_titles = {finding["title"] for finding in payload["findings"]}
    assert "Stored XSS via Unrestricted HTML Upload" in finding_titles
    assert "AJAX/JSON XSS in Response Context" in finding_titles
    assert (
        "Cross-Site Script Inclusion - Data Leakage via JSONP or JSON without protection"
        in finding_titles
    )
    assert payload["checks"][2]["payload_reflected"] is True

    task = SimpleNamespace(tool="xss-extended", target_id="https://app.example.test/app/", params_json={})
    findings = extract_findings(
        task=task,
        artifact=EvidenceArtifact(
            name=XSS_EXTENDED_RESULTS_ARTIFACT_NAME,
            content_type="application/json",
            data=execution.artifacts[0].data,
            kind="runner-results",
        ),
        artifact_record=ArtifactRecord(),
    )

    assert len(findings) == 3
    assert {finding.severity for finding in findings} == {"high"}
    assert all("xss" in finding.methodology_tags for finding in findings)


def test_xss_extended_detects_gruyere_style_upload_url_and_jsonp_xssi() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST" and request.url.path == "/gruyere/upload2":
            return httpx.Response(
                200,
                headers={"Content-Type": "text/html"},
                text=(
                    '<a href="/gruyere/">Home</a> File accessible at: '
                    "https://gruyere.example.test/gruyere/None/aegispt-xss.html"
                ),
            )
        if request.method == "GET" and request.url.path == "/gruyere/None/aegispt-xss.html":
            return httpx.Response(
                200,
                headers={"Content-Type": "text/html"},
                text=DEFAULT_XSS_PAYLOAD,
            )
        if request.method == "GET" and request.url.path == "/gruyere/feed.gtl":
            return httpx.Response(
                200,
                headers={"Content-Type": "text/html"},
                text='_feed(({"private_snippet":"operator-only","cheddar":"snippet"}))',
            )
        return httpx.Response(404, text="not found")

    execution = execute_xss_extended_scan(
        ["https://gruyere.example.test/gruyere/"],
        scope_allowlist={"urls": ["https://gruyere.example.test/gruyere/"]},
        upload_contexts=[
            {"url": "upload2", "file_field": "upload_file"},
        ],
        xssi_contexts=[
            {"url": "feed.gtl"},
        ],
        client_factory=_client_factory(handler),
    )

    payload = json.loads(execution.artifacts[0].data.decode("utf-8"))
    assert execution.exit_code == 0
    assert payload["summary"]["file_upload_findings"] == 1
    assert payload["summary"]["xssi_findings"] == 1
    assert payload["checks"][0]["returned_url"] == (
        "https://gruyere.example.test/gruyere/None/aegispt-xss.html"
    )
    assert payload["checks"][2]["sensitive_json"] is True


def test_xss_extended_rejects_out_of_scope_targets() -> None:
    with pytest.raises(ValueError, match="outside approved web scope"):
        execute_xss_extended_scan(
            ["https://other.example.test/app/"],
            scope_allowlist={"urls": ["https://app.example.test/app/"]},
        )


def test_xss_extended_is_supported() -> None:
    assert "xss-extended" in SUPPORTED_TOOLS
