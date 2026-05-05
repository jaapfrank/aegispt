from __future__ import annotations

import json
from types import SimpleNamespace

import httpx
import pytest

from workers.orchestration.findings import extract_findings
from workers.orchestration.tasks import SUPPORTED_TOOLS
from workers.runners.base.contracts import EvidenceArtifact
from workers.runners.client_state.runner import (
    CLIENT_STATE_RESULTS_ARTIFACT_NAME,
    execute_client_state_analysis,
)


class ArtifactRecord:
    uri = "artifact://client-state/results"


def _client_factory(handler):
    transport = httpx.MockTransport(handler)

    def factory(**kwargs):
        return httpx.Client(transport=transport, **kwargs)

    return factory


def test_client_state_detects_configured_authorization_bypass_variants() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        cookie = request.headers.get("Cookie", "")
        body = request.content.decode("utf-8") if request.content else ""
        if path == "/app/save" and "role=admin" in body:
            return httpx.Response(200, text="admin panel saved")
        if path == "/app/admin" and "admin=true" in cookie:
            return httpx.Response(200, text="admin console accepted")
        if path == "/app/newsnippet" and "is_admin=True" in cookie:
            return httpx.Response(200, text="Gruyere newsnippet admin accepted")
        if path == "/app/profile" and request.method == "POST":
            payload = json.loads(body.decode("utf-8") if isinstance(body, bytes) else body)
            if payload.get("isAdmin") is True:
                return httpx.Response(200, text="admin profile updated")
        if path == "/app/checkout" and request.method == "POST":
            payload = json.loads(body.decode("utf-8") if isinstance(body, bytes) else body)
            if str(payload.get("price")) == "0.01":
                return httpx.Response(200, text="order confirmed")
        if path == "/app/checkout/confirm":
            return httpx.Response(200, text="checkout complete")
        return httpx.Response(403, text="forbidden")

    execution = execute_client_state_analysis(
        ["https://shop.example.test/app/"],
        scope_allowlist={"urls": ["https://shop.example.test/app/"]},
        auth_contexts=[
            {
                "label": "Standard User",
                "username": "alice@example.test",
                "headers": {"Cookie": "session=alice"},
            }
        ],
        form_contexts=[
            {
                "url": "settings",
                "html": (
                    '<form action="/app/save" method="post">'
                    '<input type="hidden" name="role" value="user">'
                    '<input type="text" name="name" value="Alice">'
                    "</form>"
                ),
                "success_markers": ["admin panel saved"],
            }
        ],
        cookie_contexts=[
            {
                "url": "admin",
                "cookie_name": "admin",
                "original_value": "false",
                "mutated_value": "true",
                "success_markers": ["admin console accepted"],
            }
        ],
        request_contexts=[
            {
                "url": "profile",
                "method": "POST",
                "json": {"isAdmin": False, "display": "Alice"},
                "success_markers": ["admin profile updated"],
            }
        ],
        price_contexts=[
            {
                "url": "checkout",
                "method": "POST",
                "json": {"sku": "A1", "price": "99.00"},
                "success_markers": ["order confirmed"],
            }
        ],
        workflow_contexts=[
            {
                "final_url": "checkout/confirm",
                "success_markers": ["checkout complete"],
            }
        ],
        gruyere_contexts=[
            {
                "url": "newsnippet",
                "cookie_name": "is_admin",
                "original_value": "False",
                "mutated_value": "True",
                "success_markers": ["newsnippet admin accepted"],
            }
        ],
        client_factory=_client_factory(handler),
    )

    assert execution.tool == "client-state"
    assert execution.exit_code == 0
    assert execution.artifacts[0].name == CLIENT_STATE_RESULTS_ARTIFACT_NAME

    payload = json.loads(execution.artifacts[0].data.decode("utf-8"))
    assert payload["safety"]["requires_active_approval"] is True
    assert payload["safety"]["configured_credentials_only"] is True
    assert payload["safety"]["parameter_and_cookie_manipulation_only"] is True
    assert payload["safety"]["post_exploitation_chaining"] is False
    assert payload["safety"]["raw_cookie_values_stored_in_artifacts"] is False
    assert payload["summary"]["hidden_field_findings"] == 1
    assert payload["summary"]["cookie_privilege_findings"] == 2
    assert payload["summary"]["request_parameter_findings"] == 1
    assert payload["summary"]["price_manipulation_findings"] == 1
    assert payload["summary"]["workflow_step_skipping_findings"] == 1

    finding_titles = {finding["title"] for finding in payload["findings"]}
    assert finding_titles >= {
        "Client-State Manipulation - Hidden Field Privilege Escalation",
        "Cookie-Based Privilege Escalation",
        "Server-Side Authorization Bypass via Request Parameter",
        "Business Logic - Price or Amount Manipulation",
        "Business Logic - Workflow Step Skipping Accepted",
    }
    artifact_text = execution.artifacts[0].data.decode("utf-8")
    assert "session=alice" not in artifact_text
    assert '"raw_values_recorded": false' in artifact_text

    task = SimpleNamespace(tool="client-state", target_id="https://shop.example.test/app/", params_json={})
    findings = extract_findings(
        task=task,
        artifact=EvidenceArtifact(
            name=CLIENT_STATE_RESULTS_ARTIFACT_NAME,
            content_type="application/json",
            data=execution.artifacts[0].data,
            kind="runner-results",
        ),
        artifact_record=ArtifactRecord(),
    )

    assert len(findings) == payload["summary"]["finding_count"]
    assert {finding.severity for finding in findings} >= {"high", "medium"}
    assert all("client_state" in finding.methodology_tags for finding in findings)


def test_client_state_rejects_missing_auth_contexts_and_out_of_scope_targets() -> None:
    with pytest.raises(ValueError, match="authenticated access account"):
        execute_client_state_analysis(
            ["https://shop.example.test/app/"],
            scope_allowlist={"urls": ["https://shop.example.test/app/"]},
            auth_contexts=[],
        )

    with pytest.raises(ValueError, match="outside approved web scope"):
        execute_client_state_analysis(
            ["https://outside.example.test/app/"],
            scope_allowlist={"urls": ["https://shop.example.test/app/"]},
            auth_contexts=[{"headers": {"Cookie": "session=alice"}}],
        )


def test_client_state_is_supported() -> None:
    assert "client-state" in SUPPORTED_TOOLS
