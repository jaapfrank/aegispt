from __future__ import annotations

import json
import re
from types import SimpleNamespace

import httpx
import pytest

from workers.orchestration.findings import extract_findings
from workers.orchestration.tasks import SUPPORTED_TOOLS
from workers.runners.base.contracts import EvidenceArtifact
from workers.runners.graphql_probe.runner import (
    GRAPHQL_RESULTS_ARTIFACT_NAME,
    execute_graphql_probe,
)


class ArtifactRecord:
    uri = "artifact://graphql-probe/results"


def _client_factory(handler):
    transport = httpx.MockTransport(handler)

    def factory(**kwargs):
        return httpx.Client(transport=transport, **kwargs)

    return factory


def _schema() -> dict:
    return {
        "queryType": {"name": "Query"},
        "mutationType": {"name": "Mutation"},
        "types": [
            {
                "kind": "OBJECT",
                "name": "Query",
                "fields": [
                    {
                        "name": "viewer",
                        "args": [],
                        "type": {"kind": "OBJECT", "name": "User"},
                    },
                    {
                        "name": "user",
                        "args": [{"name": "id", "type": {"kind": "SCALAR", "name": "String"}}],
                        "type": {"kind": "OBJECT", "name": "User"},
                    },
                ],
            },
            {
                "kind": "OBJECT",
                "name": "User",
                "fields": [
                    {"name": "id", "args": [], "type": {"kind": "SCALAR", "name": "String"}},
                    {"name": "name", "args": [], "type": {"kind": "SCALAR", "name": "String"}},
                    {
                        "name": "friend",
                        "args": [],
                        "type": {"kind": "OBJECT", "name": "User"},
                    },
                ],
            },
            {
                "kind": "OBJECT",
                "name": "Mutation",
                "fields": [
                    {
                        "name": "updateProfile",
                        "args": [{"name": "name", "type": {"kind": "SCALAR", "name": "String"}}],
                        "type": {"kind": "OBJECT", "name": "User"},
                    },
                ],
            },
        ],
    }


def test_graphql_probe_detects_introspection_depth_suggestions_injection_and_ide() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and request.url.path == "/graphiql":
            return httpx.Response(200, text="<title>GraphiQL</title><div>GraphQL IDE</div>")
        if request.method != "POST" or request.url.path != "/graphql":
            return httpx.Response(404, json={"error": "not found"})

        payload = json.loads(request.content.decode("utf-8"))
        if isinstance(payload, list):
            return httpx.Response(200, json=[{"data": {"__typename": "Query"}} for _ in payload])

        query = payload.get("query", "")
        variables = payload.get("variables") or {}
        value = str(variables.get("value") or "")
        if "__schema" in query:
            return httpx.Response(200, json={"data": {"__schema": _schema()}})
        if re.search(r"\b(uer|vewer)\b", query):
            return httpx.Response(
                200,
                json={"errors": [{"message": 'Cannot query field on type "Query". Did you mean "viewer" or "user"?'}]},
            )
        if "friend" in query:
            return httpx.Response(200, json={"data": {"viewer": {"friend": {"__typename": "User"}}}})
        if "user" in query and ("OR" in value or "$ne" in value):
            return httpx.Response(500, text="SQL syntax error near injected GraphQL variable")
        return httpx.Response(200, json={"data": {"__typename": "Query"}})

    execution = execute_graphql_probe(
        ["https://api.example.test/graphql"],
        scope_allowlist={"urls": ["https://api.example.test/"]},
        client_factory=_client_factory(handler),
    )

    assert execution.tool == "graphql-probe"
    assert execution.exit_code == 0
    assert execution.artifacts[0].name == GRAPHQL_RESULTS_ARTIFACT_NAME
    payload = json.loads(execution.artifacts[0].data.decode("utf-8"))
    assert payload["summary"]["discovered_endpoint_count"] == 1
    assert payload["summary"]["schema_map_count"] == 1
    assert payload["summary"]["introspection_findings"] == 1
    assert payload["summary"]["depth_findings"] == 1
    assert payload["summary"]["suggestion_findings"] == 1
    assert payload["summary"]["injection_findings"] == 1
    assert payload["safety"]["depth_probe_max_levels"] == 20
    assert payload["safety"]["batch_probe_size"] == 2
    assert payload["safety"]["rate_limit_bypass_attempted"] is False
    assert payload["safety"]["api_assessment_runner_changed"] is False
    assert payload["safety"]["zap_configuration_changed"] is False

    titles = {finding["title"] for finding in payload["findings"]}
    assert {
        "GraphQL Playground or IDE Exposed",
        "GraphQL Introspection Enabled - Full Schema Disclosed",
        "GraphQL Missing Query Depth Limit",
        "GraphQL Field Suggestion Leakage",
        "GraphQL Argument Injection Error Signal",
    }.issubset(titles)

    task = SimpleNamespace(
        tool="graphql-probe",
        target_id="https://api.example.test/graphql",
        params_json={},
    )
    findings = extract_findings(
        task=task,
        artifact=EvidenceArtifact(
            name=GRAPHQL_RESULTS_ARTIFACT_NAME,
            content_type="application/json",
            data=execution.artifacts[0].data,
            kind="runner-results",
        ),
        artifact_record=ArtifactRecord(),
    )

    assert len(findings) >= 5
    assert "high" in {finding.severity for finding in findings}
    assert all("graphql-probe-validation" in finding.methodology_tags for finding in findings)


def test_graphql_probe_rejects_out_of_scope_targets_and_caps_depth() -> None:
    with pytest.raises(ValueError, match="outside approved GraphQL/web scope"):
        execute_graphql_probe(
            ["https://outside.example.test/graphql"],
            scope_allowlist={"urls": ["https://api.example.test/graphql"]},
        )

    execution = execute_graphql_probe(
        ["https://api.example.test/graphql"],
        scope_allowlist={"urls": ["https://api.example.test/graphql"]},
        max_depth=50,
        endpoint_paths=[],
        ide_paths=[],
        client_factory=_client_factory(lambda request: httpx.Response(404, json={"error": "no"})),
    )
    payload = json.loads(execution.artifacts[0].data.decode("utf-8"))
    assert payload["safety"]["depth_probe_max_levels"] == 20


def test_graphql_probe_is_supported() -> None:
    assert "graphql-probe" in SUPPORTED_TOOLS
