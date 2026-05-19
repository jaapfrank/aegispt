from __future__ import annotations

import json
from types import SimpleNamespace

import httpx
import pytest

from workers.orchestration.findings import extract_findings
from workers.runners.base.contracts import EvidenceArtifact
from workers.runners.biz_logic.runner import BIZ_LOGIC_ARTIFACT_NAME, execute_biz_logic_probe


class ArtifactRecord:
    uri = "artifact://biz-logic/results"


def _client_factory(handler):
    transport = httpx.MockTransport(handler)

    def factory(**kwargs):
        return httpx.Client(transport=transport, **kwargs)

    return factory


def test_biz_logic_probe_rejects_missing_auth_contexts() -> None:
    with pytest.raises(ValueError, match="authenticated access account"):
        execute_biz_logic_probe(
            ["https://app.example.test"],
            auth_contexts=[],
            scope_allowlist={"urls": ["https://app.example.test"]},
        )


def test_biz_logic_probe_detects_idor_and_normalizes_findings() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        authz = request.headers.get("Authorization", "")
        if request.url.path == "/api/orders/202" and "alice-token" in authz:
            return httpx.Response(200, text='{"order_id":202,"owner":"bob@example.com"}')
        return httpx.Response(404, text="not found")

    execution = execute_biz_logic_probe(
        ["https://app.example.test"],
        auth_contexts=[
            {
                "label": "Alice User",
                "role": "User",
                "username": "alice@example.com",
                "marker_tokens": ["alice@example.com"],
                "headers": {"Authorization": "Bearer alice-token"},
            },
            {
                "label": "Bob User",
                "role": "User",
                "username": "bob@example.com",
                "marker_tokens": ["bob@example.com"],
                "headers": {"Authorization": "Bearer bob-token"},
            },
        ],
        test_types=["idor"],
        idor_paths=["/api/orders/{id}"],
        candidate_object_ids=["202"],
        scope_allowlist={"urls": ["https://app.example.test"]},
        client_factory=_client_factory(handler),
    )

    assert execution.tool == "biz-logic-probe"
    assert execution.exit_code == 0
    assert execution.metadata["finding_count"] == 1
    assert execution.artifacts[0].name == BIZ_LOGIC_ARTIFACT_NAME

    task = SimpleNamespace(tool="biz-logic-probe", target_id="https://app.example.test", params_json={})
    findings = extract_findings(
        task=task,
        artifact=EvidenceArtifact(
            name=BIZ_LOGIC_ARTIFACT_NAME,
            content_type="application/json",
            data=execution.artifacts[0].data,
            kind="probe-results",
        ),
        artifact_record=ArtifactRecord(),
    )

    assert len(findings) == 1
    assert findings[0].title == "Insecure direct object reference detected"
    assert findings[0].severity == "high"
    assert "authorization" in findings[0].methodology_tags
    assert findings[0].evidence_ref == ArtifactRecord.uri


def test_biz_logic_probe_rejects_out_of_scope_absolute_paths() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="ok")

    with pytest.raises(ValueError, match="target outside scope"):
        execute_biz_logic_probe(
            ["https://app.example.test"],
            auth_contexts=[
                {
                    "label": "Standard User",
                    "role": "User",
                    "headers": {"Authorization": "Bearer user-token"},
                }
            ],
            test_types=["privilege_escalation"],
            admin_paths=["https://evil.example.test/admin"],
            scope_allowlist={"urls": ["https://app.example.test"]},
            client_factory=_client_factory(handler),
        )


def test_biz_logic_probe_detects_broken_access_and_cross_tenant() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        authz = request.headers.get("Authorization", "")
        if request.url.path == "/api/private":
            if authz:
                return httpx.Response(200, text='{"ok":true}')
            return httpx.Response(200, text='{"ok":true}')
        if request.url.path == "/tenant/tenant-b/dashboard" and "tenant-a-token" in authz:
            return httpx.Response(200, text='{"tenant":"tenant-b"}')
        return httpx.Response(403, text="forbidden")

    execution = execute_biz_logic_probe(
        ["https://app.example.test"],
        auth_contexts=[
            {
                "label": "Tenant A",
                "role": "User",
                "tenant": "tenant-a",
                "headers": {"Authorization": "Bearer tenant-a-token"},
            },
            {
                "label": "Tenant B",
                "role": "User",
                "tenant": "tenant-b",
                "headers": {"Authorization": "Bearer tenant-b-token"},
            },
        ],
        test_types=["broken_access", "cross_tenant"],
        protected_paths=["/api/private"],
        cross_tenant_paths=["/tenant/{tenant}/dashboard"],
        scope_allowlist={"urls": ["https://app.example.test"]},
        client_factory=_client_factory(handler),
    )

    payload = json.loads(execution.artifacts[0].data.decode("utf-8"))
    finding_titles = {
        item["title"]
        for target in payload["targets"]
        for item in target.get("findings", [])
    }
    assert "Broken access control detected" in finding_titles
    assert "Cross-tenant broken access control detected" in finding_titles
