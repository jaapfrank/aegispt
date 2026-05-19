from __future__ import annotations

import json
from types import SimpleNamespace

import httpx
import pytest

from workers.orchestration.findings import extract_findings
from workers.orchestration.tasks import SUPPORTED_TOOLS
from workers.runners.base.contracts import EvidenceArtifact
from workers.runners.http_smuggling.runner import (
    HTTP_SMUGGLING_RESULTS_ARTIFACT_NAME,
    ProbeSpec,
    SmugglingProbeResult,
    execute_http_smuggling_probe,
)


class ArtifactRecord:
    uri = "artifact://http-smuggling/results"


def _client_factory(handler):
    transport = httpx.MockTransport(handler)

    def factory(**kwargs):
        return httpx.Client(transport=transport, **kwargs)

    return factory


def test_http_smuggling_detects_timing_signal_only_with_proxy_evidence() -> None:
    observed_variants: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"Via": "1.1 lab-proxy"}, text="ok")

    def probe_sender(
        target: str,
        spec: ProbeSpec,
        timeout_seconds: float,
    ) -> SmugglingProbeResult:
        observed_variants.append(spec.variant)
        if spec.variant == "CL.TE":
            return SmugglingProbeResult(
                variant=spec.variant,
                elapsed_seconds=5.0,
                timed_out=True,
            )
        return SmugglingProbeResult(
            variant=spec.variant,
            elapsed_seconds=0.2,
            timed_out=False,
            response_status_line="HTTP/1.1 400 Bad Request",
        )

    execution = execute_http_smuggling_probe(
        ["https://proxy.example.test/app/"],
        scope_allowlist={"urls": ["https://proxy.example.test/app/"]},
        client_factory=_client_factory(handler),
        probe_sender=probe_sender,
        timeout_seconds=12.0,
    )

    assert execution.tool == "http-smuggling"
    assert execution.exit_code == 0
    assert execution.artifacts[0].name == HTTP_SMUGGLING_RESULTS_ARTIFACT_NAME
    assert observed_variants == ["CL.TE", "TE.CL", "TE.TE"]

    payload = json.loads(execution.artifacts[0].data.decode("utf-8"))
    assert payload["summary"]["sent_probe_count"] == 3
    assert payload["summary"]["finding_count"] == 1
    assert payload["summary"]["cl_te_findings"] == 1
    assert payload["safety"]["max_probe_timeout_seconds"] == 5.0
    assert payload["safety"]["confirming_request_sent"] is False
    assert payload["safety"]["request_hijacking_attempted"] is False
    assert payload["safety"]["cache_poisoning_attempted"] is False
    finding = payload["findings"][0]
    assert finding["title"] == "HTTP Request Smuggling (CL.TE) - Timing Confirmed"
    assert finding["severity"] == "critical"
    assert finding["evidence"]["timed_out"] is True
    assert finding["evidence"]["confirming_request_sent"] is False
    assert finding["evidence"]["visible_side_effect_request_sent"] is False
    assert finding["evidence"]["proxy_evidence"][0]["header"].lower() == "via"

    task = SimpleNamespace(
        tool="http-smuggling",
        target_id="https://proxy.example.test/app/",
        params_json={},
    )
    findings = extract_findings(
        task=task,
        artifact=EvidenceArtifact(
            name=HTTP_SMUGGLING_RESULTS_ARTIFACT_NAME,
            content_type="application/json",
            data=execution.artifacts[0].data,
            kind="runner-results",
        ),
        artifact_record=ArtifactRecord(),
    )

    assert len(findings) == 1
    assert findings[0].severity == "critical"
    assert "http-smuggling-validation" in findings[0].methodology_tags


def test_http_smuggling_refuses_to_probe_without_proxy_evidence() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"Server": "single-origin"}, text="ok")

    def probe_sender(
        target: str,
        spec: ProbeSpec,
        timeout_seconds: float,
    ) -> SmugglingProbeResult:
        raise AssertionError("probe sender must not be called without proxy evidence")

    execution = execute_http_smuggling_probe(
        ["https://single.example.test/app/"],
        scope_allowlist={"urls": ["https://single.example.test/app/"]},
        client_factory=_client_factory(handler),
        probe_sender=probe_sender,
    )

    payload = json.loads(execution.artifacts[0].data.decode("utf-8"))
    assert payload["summary"]["skipped_target_count"] == 1
    assert payload["summary"]["sent_probe_count"] == 0
    assert payload["findings"] == []
    assert payload["checks"][0]["skip_reason"] == "proxy evidence missing"


def test_http_smuggling_rejects_out_of_scope_and_caps_timeout() -> None:
    with pytest.raises(ValueError, match="outside approved HTTP smuggling/web scope"):
        execute_http_smuggling_probe(
            ["https://outside.example.test/app/"],
            scope_allowlist={"urls": ["https://proxy.example.test/app/"]},
        )

    observed_timeouts: list[float] = []

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"X-Forwarded-For": "203.0.113.10"}, text="ok")

    def probe_sender(
        target: str,
        spec: ProbeSpec,
        timeout_seconds: float,
    ) -> SmugglingProbeResult:
        observed_timeouts.append(timeout_seconds)
        return SmugglingProbeResult(variant=spec.variant, elapsed_seconds=0.1)

    execution = execute_http_smuggling_probe(
        ["https://proxy.example.test/app/"],
        scope_allowlist={"urls": ["https://proxy.example.test/app/"]},
        client_factory=_client_factory(handler),
        probe_sender=probe_sender,
        timeout_seconds=30.0,
        timing_threshold_seconds=15.0,
    )

    payload = json.loads(execution.artifacts[0].data.decode("utf-8"))
    assert observed_timeouts == [5.0, 5.0, 5.0]
    assert payload["safety"]["max_probe_timeout_seconds"] == 5.0
    assert payload["safety"]["timing_threshold_seconds"] == 5.0


def test_http_smuggling_is_supported() -> None:
    assert "http-smuggling" in SUPPORTED_TOOLS
