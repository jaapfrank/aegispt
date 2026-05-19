from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from workers.orchestration.findings import extract_findings
from workers.runners.api_assessment.runner import (
    API_ASSESSMENT_INVENTORY_ARTIFACT_NAME,
    API_ASSESSMENT_RESULTS_ARTIFACT_NAME,
    execute_api_assessment,
)
from workers.runners.base.contracts import EvidenceArtifact


class ArtifactRecord:
    uri = "artifact://api-assessment/results"


def crapi_style_openapi_spec() -> dict[str, object]:
    return {
        "openapi": "3.0.3",
        "servers": [{"url": "http://127.0.0.1:8888/identity/api"}],
        "paths": {
            "/v2/user/{id}": {
                "get": {
                    "operationId": "getUser",
                    "responses": {
                        "200": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "id": {"type": "string"},
                                            "email": {"type": "string"},
                                            "refresh_token": {"type": "string"},
                                        },
                                    }
                                }
                            }
                        }
                    },
                }
            },
            "/admin/users": {
                "delete": {
                    "operationId": "deleteUser",
                    "responses": {"204": {"description": "deleted"}},
                }
            },
            "/vehicle/health": {
                "get": {
                    "operationId": "vehicleHealth",
                    "security": [{"bearerAuth": []}],
                    "responses": {"200": {"description": "ok"}},
                }
            },
        },
    }


def test_api_assessment_rejects_out_of_scope_target() -> None:
    with pytest.raises(ValueError, match="outside scope"):
        execute_api_assessment(
            ["https://evil.example.test/api"],
            scope_allowlist={"api_base_urls": ["https://api.example.test"]},
            openapi_spec=crapi_style_openapi_spec(),
        )


def test_api_assessment_missing_spec_fallback_is_truthful() -> None:
    execution = execute_api_assessment(
        ["https://api.example.test"],
        scope_allowlist={"api_base_urls": ["https://api.example.test"]},
    )

    assert execution.exit_code == 0
    assert execution.metadata["status"] == "skipped"
    assert execution.metadata["reason"] == "missing_api_spec"
    payload = json.loads(execution.artifacts[0].data.decode("utf-8"))
    assert payload["status"] == "skipped"
    assert payload["safety"]["uncontrolled_fuzzing"] is False


def test_api_assessment_unsupported_schema_fallback_is_truthful() -> None:
    execution = execute_api_assessment(
        ["https://api.example.test"],
        scope_allowlist={"api_base_urls": ["https://api.example.test"]},
        openapi_spec={"info": {"title": "not-openapi"}},
    )

    assert execution.exit_code == 0
    assert execution.metadata["status"] == "skipped"
    assert execution.metadata["reason"] == "unsupported_schema_format"
    assert "missing openapi/swagger marker" in execution.stderr


def test_api_assessment_missing_auth_context_fallback_is_truthful() -> None:
    execution = execute_api_assessment(
        ["https://api.example.test"],
        scope_allowlist={"api_base_urls": ["https://api.example.test"]},
        openapi_spec=crapi_style_openapi_spec(),
        requires_auth_context=True,
    )

    assert execution.exit_code == 0
    assert execution.metadata["status"] == "skipped"
    assert execution.metadata["reason"] == "missing_auth_context"


def test_api_assessment_openapi_and_graphql_create_inventory_and_findings() -> None:
    execution = execute_api_assessment(
        ["http://127.0.0.1:8888/identity/api"],
        scope_allowlist={
            "urls": ["http://127.0.0.1:8888"],
            "api_base_urls": ["http://127.0.0.1:8888/identity/api"],
        },
        openapi_spec=crapi_style_openapi_spec(),
        graphql_introspection={"data": {"__schema": {"types": [{"name": "Query"}]}}},
        graphql_endpoint_url="http://127.0.0.1:8888/graphql",
    )

    assert execution.exit_code == 0
    assert execution.tool == "api-assessment"
    assert execution.metadata["endpoint_count"] == 4
    assert execution.metadata["finding_count"] >= 4
    artifact_names = {artifact.name for artifact in execution.artifacts}
    assert API_ASSESSMENT_RESULTS_ARTIFACT_NAME in artifact_names
    assert API_ASSESSMENT_INVENTORY_ARTIFACT_NAME in artifact_names

    results_artifact = next(
        artifact for artifact in execution.artifacts if artifact.name == API_ASSESSMENT_RESULTS_ARTIFACT_NAME
    )
    payload = json.loads(results_artifact.data.decode("utf-8"))
    assert payload["safety"]["load_testing"] is False
    assert any(
        finding["type"] == "object_level_authorization"
        for finding in payload["findings"]
    )
    assert any(finding["type"] == "graphql_schema_exposure" for finding in payload["findings"])

    task = SimpleNamespace(tool="api-assessment", target_id="http://127.0.0.1:8888", params_json={})
    findings = extract_findings(
        task=task,
        artifact=EvidenceArtifact(
            name=API_ASSESSMENT_RESULTS_ARTIFACT_NAME,
            content_type="application/json",
            data=results_artifact.data,
            kind="api-assessment-results",
        ),
        artifact_record=ArtifactRecord(),
    )
    assert {finding.evidence_ref for finding in findings} == {ArtifactRecord.uri}
    assert "Object-level authorization missing on API object route" in {
        finding.title for finding in findings
    }


def test_api_assessment_postman_collection_populates_endpoint_inventory() -> None:
    execution = execute_api_assessment(
        ["https://api.example.test"],
        scope_allowlist={"api_base_urls": ["https://api.example.test"]},
        postman_collection={
            "item": [
                {
                    "name": "List orders",
                    "request": {
                        "method": "GET",
                        "url": {"raw": "https://api.example.test/orders"},
                    },
                }
            ]
        },
    )

    assert execution.exit_code == 0
    inventory = next(
        artifact for artifact in execution.artifacts if artifact.name == API_ASSESSMENT_INVENTORY_ARTIFACT_NAME
    )
    payload = json.loads(inventory.data.decode("utf-8"))
    assert payload["data"]["endpoints"][0]["url"] == "https://api.example.test/orders"
