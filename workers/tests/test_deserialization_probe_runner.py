from __future__ import annotations

import base64
import json
from types import SimpleNamespace

import httpx
import pytest

from workers.orchestration.findings import extract_findings
from workers.orchestration.tasks import SUPPORTED_TOOLS
from workers.runners.base.contracts import EvidenceArtifact
from workers.runners.deserialization_probe.runner import (
    DESERIALIZATION_RESULTS_ARTIFACT_NAME,
    execute_deserialization_probe,
)


class ArtifactRecord:
    uri = "artifact://deserialization-probe/results"


def _client_factory(handler):
    transport = httpx.MockTransport(handler)

    def factory(**kwargs):
        return httpx.Client(transport=transport, **kwargs)

    return factory


def test_deserialization_probe_detects_java_php_pickle_and_viewstate() -> None:
    java_seen_payloads: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        payload = request.url.params.get("data", "")
        if payload.startswith("rO0AB"):
            java_seen_payloads.append(payload)
            return httpx.Response(200, text="queued")
        if payload == 'O:4:"Test":0:{}':
            return httpx.Response(500, text="Warning: unserialize(): Error at offset 0")
        if payload.startswith("gAS"):
            return httpx.Response(200, text="pickle probe accepted")
        return httpx.Response(200, text="ok")

    viewstate = base64.b64encode(b"\xff\x01System.Web.UI.Pair").decode("ascii")
    execution = execute_deserialization_probe(
        ["https://app.example.test/app/"],
        scope_allowlist={"urls": ["https://app.example.test/app/"]},
        request_contexts=[
            {
                "url": "deserialize?data=rO0ABXNy",
                "parameters": ["data"],
                "java_serialized_marker": True,
            },
            {
                "url": "php?data=baseline",
                "parameters": ["data"],
                "php_object_candidate": True,
            },
            {
                "url": "pickle?data=gASVAAAA",
                "parameters": ["data"],
                "content_type": "application/x-python-pickle",
            },
            {
                "url": "view",
                "parameters": {"__VIEWSTATE": viewstate},
            },
        ],
        callback_base_url="https://callback.example.test/aegispt",
        callback_token="deser-token",
        oob_confirmation_refs=[{"token": "deser-token", "interaction_id": "dns-1"}],
        client_factory=_client_factory(handler),
    )

    assert execution.tool == "deserialization-probe"
    assert execution.exit_code == 0
    assert execution.artifacts[0].name == DESERIALIZATION_RESULTS_ARTIFACT_NAME
    assert execution.metadata["finding_count"] == 4
    assert java_seen_payloads
    assert all("CommonsCollections" not in payload for payload in java_seen_payloads)
    assert all("Runtime" not in payload and "exec" not in payload for payload in java_seen_payloads)

    payload = json.loads(execution.artifacts[0].data.decode("utf-8"))
    assert payload["safety"]["command_execution_payloads"] is False
    assert payload["safety"]["rce_gadget_chains"] is False
    assert payload["safety"]["java_payload_family"] == "ysoserial-url-dns-only"
    assert payload["summary"]["java_urldns_findings"] == 1
    assert payload["summary"]["php_object_findings"] == 1
    assert payload["summary"]["python_pickle_findings"] == 1
    assert payload["summary"]["viewstate_findings"] == 1

    task = SimpleNamespace(
        tool="deserialization-probe",
        target_id="https://app.example.test/app/",
        params_json={},
    )
    findings = extract_findings(
        task=task,
        artifact=EvidenceArtifact(
            name=DESERIALIZATION_RESULTS_ARTIFACT_NAME,
            content_type="application/json",
            data=execution.artifacts[0].data,
            kind="runner-results",
        ),
        artifact_record=ArtifactRecord(),
    )

    assert len(findings) == 4
    assert {finding.severity for finding in findings} == {"critical", "high", "medium"}
    assert all("deserialization" in finding.methodology_tags for finding in findings)


def test_deserialization_probe_rejects_out_of_scope_targets() -> None:
    with pytest.raises(ValueError, match="outside approved web scope"):
        execute_deserialization_probe(
            ["https://other.example.test/app/"],
            scope_allowlist={"urls": ["https://app.example.test/app/"]},
        )


def test_deserialization_probe_is_supported() -> None:
    assert "deserialization-probe" in SUPPORTED_TOOLS
