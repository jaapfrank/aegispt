from __future__ import annotations

import json
from types import SimpleNamespace

import httpx
import pytest

from workers.orchestration.findings import extract_findings
from workers.orchestration.tasks import SUPPORTED_TOOLS
from workers.runners.base.contracts import EvidenceArtifact
from workers.runners.ssrf_probe.runner import SSRF_RESULTS_ARTIFACT_NAME, execute_ssrf_probe


class ArtifactRecord:
    uri = "artifact://ssrf-probe/results"


def _client_factory(handler):
    transport = httpx.MockTransport(handler)

    def factory(**kwargs):
        return httpx.Client(transport=transport, **kwargs)

    return factory


def test_ssrf_probe_detects_oob_internal_service_and_cloud_metadata() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        payload = request.url.params.get("url", "")
        if "127.0.0.1" in payload:
            return httpx.Response(200, text="internal admin console internal-only")
        if "169.254.169.254" in payload:
            return httpx.Response(200, text="iam/security-credentials role-name")
        return httpx.Response(200, text="queued")

    execution = execute_ssrf_probe(
        ["https://app.example.test/app/"],
        scope_allowlist={
            "urls": ["https://app.example.test/app/"],
            "cidrs": ["127.0.0.0/8"],
        },
        request_contexts=[{"url": "fetch?url=baseline", "parameters": ["url"]}],
        header_contexts=[{"url": "fetch?url=baseline"}],
        callback_base_url="https://callback.example.test/aegispt",
        callback_token="ssrf-token",
        oob_confirmation_refs=[{"token": "ssrf-token", "interaction_id": "oob-1"}],
        internal_service_urls=["http://127.0.0.1/admin"],
        cloud_metadata_probe_enabled=True,
        cloud_hosted=True,
        cloud_provider="aws",
        client_factory=_client_factory(handler),
    )

    assert execution.tool == "ssrf-probe"
    assert execution.exit_code == 0
    assert execution.artifacts[0].name == SSRF_RESULTS_ARTIFACT_NAME
    assert execution.metadata["finding_count"] == 3

    payload = json.loads(execution.artifacts[0].data.decode("utf-8"))
    assert payload["safety"]["requires_active_approval"] is True
    assert payload["safety"]["cloud_metadata_probe_enabled"] is True
    assert payload["summary"]["blind_oob_findings"] == 1
    assert payload["summary"]["internal_service_findings"] == 1
    assert payload["summary"]["cloud_metadata_findings"] == 1
    assert {finding["title"] for finding in payload["findings"]} == {
        "SSRF - Blind (OOB Confirmed)",
        "SSRF - Internal Service Accessible",
        "SSRF - Cloud Metadata Exposed",
    }

    task = SimpleNamespace(tool="ssrf-probe", target_id="https://app.example.test/app/", params_json={})
    findings = extract_findings(
        task=task,
        artifact=EvidenceArtifact(
            name=SSRF_RESULTS_ARTIFACT_NAME,
            content_type="application/json",
            data=execution.artifacts[0].data,
            kind="runner-results",
        ),
        artifact_record=ArtifactRecord(),
    )

    assert len(findings) == 3
    assert {finding.severity for finding in findings} == {"high", "critical"}
    assert all("ssrf" in finding.methodology_tags for finding in findings)


def test_ssrf_probe_rejects_out_of_scope_targets() -> None:
    with pytest.raises(ValueError, match="outside approved web scope"):
        execute_ssrf_probe(
            ["https://other.example.test/app/"],
            scope_allowlist={"urls": ["https://app.example.test/app/"]},
        )


def test_ssrf_probe_skips_unapproved_internal_service_urls() -> None:
    seen_payloads: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_payloads.append(request.url.params.get("url", ""))
        return httpx.Response(200, text="ok")

    execution = execute_ssrf_probe(
        ["https://app.example.test/app/"],
        scope_allowlist={"urls": ["https://app.example.test/app/"]},
        request_contexts=[{"url": "fetch", "parameters": ["url"]}],
        internal_service_urls=["http://10.0.0.5/admin"],
        client_factory=_client_factory(handler),
    )

    payload = json.loads(execution.artifacts[0].data.decode("utf-8"))
    assert payload["summary"]["internal_service_findings"] == 0
    assert "http://10.0.0.5/admin" not in seen_payloads


def test_ssrf_probe_is_supported() -> None:
    assert "ssrf-probe" in SUPPORTED_TOOLS
