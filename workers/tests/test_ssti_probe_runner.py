from __future__ import annotations

import json
from types import SimpleNamespace
from urllib.parse import parse_qs

import httpx
import pytest

from workers.orchestration.findings import extract_findings
from workers.orchestration.tasks import SUPPORTED_TOOLS
from workers.runners.base.contracts import EvidenceArtifact
from workers.runners.ssti_probe.runner import (
    PAYLOAD_SPECS,
    SSTI_RESULTS_ARTIFACT_NAME,
    execute_ssti_probe,
)


class ArtifactRecord:
    uri = "artifact://ssti-probe/results"


def _client_factory(handler):
    transport = httpx.MockTransport(handler)

    def factory(**kwargs):
        return httpx.Client(transport=transport, **kwargs)

    return factory


def test_ssti_probe_detects_reflected_and_gruyere_stored_math_only_ssti() -> None:
    stored_render = {"body": ""}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and request.url.path == "/search":
            params = parse_qs(request.url.query.decode("utf-8"))
            value = (params.get("name") or [""])[0]
            if "aegispt{{7*7}}ssti" in value:
                return httpx.Response(200, text="<html>aegispt49ssti</html>")
            if "aegispt{{7*'7'}}ssti" in value:
                return httpx.Response(200, text="<html>aegispt7777777ssti</html>")
            return httpx.Response(200, text=f"<html>{value}</html>")

        if request.method == "POST" and request.url.path == "/newsnippet":
            body = request.content.decode("utf-8")
            if "aegispt%24%7B7%2A7%7Dssti" in body:
                stored_render["body"] = "<article>aegispt49ssti</article>"
            else:
                stored_render["body"] = "<article>stored</article>"
            return httpx.Response(201, text="created")

        if request.method == "GET" and request.url.path == "/snippets":
            return httpx.Response(200, text=stored_render["body"])

        return httpx.Response(404, text="not found")

    execution = execute_ssti_probe(
        ["https://app.example.test/search"],
        scope_allowlist={"urls": ["https://app.example.test/"]},
        parameter_names=["name"],
        gruyere_contexts=[
            {
                "url": "https://app.example.test/newsnippet",
                "render_url": "https://app.example.test/snippets",
                "field": "snippet",
                "fields": {"title": "AegisPT"},
            }
        ],
        client_factory=_client_factory(handler),
    )

    assert execution.tool == "ssti-probe"
    assert execution.exit_code == 0
    assert execution.artifacts[0].name == SSTI_RESULTS_ARTIFACT_NAME
    payload = json.loads(execution.artifacts[0].data.decode("utf-8"))
    assert payload["summary"]["confirmed_ssti_count"] >= 2
    assert payload["safety"]["math_expression_payloads_only"] is True
    assert payload["safety"]["command_payloads_sent"] is False
    assert payload["safety"]["config_dump_payloads_sent"] is False

    engines = {
        finding["evidence"]["engine"]
        for finding in payload["findings"]
        if isinstance(finding.get("evidence"), dict)
    }
    assert "Jinja2/Twig/GTL-style" in engines
    assert "Gruyere GTL/custom template language" in engines
    assert all(finding["severity"] == "critical" for finding in payload["findings"])

    task = SimpleNamespace(
        tool="ssti-probe",
        target_id="https://app.example.test/search",
        params_json={},
    )
    findings = extract_findings(
        task=task,
        artifact=EvidenceArtifact(
            name=SSTI_RESULTS_ARTIFACT_NAME,
            content_type="application/json",
            data=execution.artifacts[0].data,
            kind="runner-results",
        ),
        artifact_record=ArtifactRecord(),
    )

    assert findings
    assert {finding.severity for finding in findings} == {"critical"}
    assert all("ssti-probe-validation" in finding.methodology_tags for finding in findings)


def test_ssti_probe_rejects_out_of_scope_targets_and_payloads_stay_math_only() -> None:
    with pytest.raises(ValueError, match="outside approved SSTI/web scope"):
        execute_ssti_probe(
            ["https://outside.example.test/search"],
            scope_allowlist={"urls": ["https://app.example.test/search"]},
        )

    payload_text = "\n".join(spec.payload for spec in PAYLOAD_SPECS)
    forbidden_tokens = ("__import__", "os.system", "subprocess", "cat /", "/etc/passwd")
    assert not any(token in payload_text for token in forbidden_tokens)


def test_ssti_probe_is_supported() -> None:
    assert "ssti-probe" in SUPPORTED_TOOLS
