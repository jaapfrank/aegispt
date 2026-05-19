from __future__ import annotations

import json
from types import SimpleNamespace

import httpx
import pytest

from workers.orchestration.findings import extract_findings
from workers.orchestration.tasks import SUPPORTED_TOOLS, dispatch_runner
from workers.runners.base.contracts import EvidenceArtifact, RunnerRequest
from workers.runners.graphql_command_injection.runner import (
    DEFAULT_COMMAND,
    GRAPHQL_COMMAND_INJECTION_RESULTS_ARTIFACT_NAME,
    TOOL_NAME,
    execute_graphql_command_injection,
)


class ArtifactRecord:
    uri = "artifact://graphql-command-injection/results"


def _client_factory(handler):
    transport = httpx.MockTransport(handler)

    def factory(**kwargs):
        return httpx.Client(transport=transport, **kwargs)

    return factory


def _artifact_payload(execution):
    artifact = next(
        item
        for item in execution.artifacts
        if item.name == GRAPHQL_COMMAND_INJECTION_RESULTS_ARTIFACT_NAME
    )
    return json.loads(artifact.data.decode("utf-8"))


def test_dvga_command_injection_runner_confirms_allowlisted_local_lab_proof() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert request.url.path == "/graphql"
        payload = json.loads(request.content.decode("utf-8"))
        assert payload["operationName"] == "AegisPTCommandInjection"
        assert "systemDiagnostics" in payload["query"]
        assert payload["variables"] == {
            "cmd": DEFAULT_COMMAND,
            "username": "admin",
            "password": "changeme",
        }
        return httpx.Response(
            200,
            json={"data": {"systemDiagnostics": "aegispt-command-injection-proof\n"}},
        )

    execution = execute_graphql_command_injection(
        ["http://127.0.0.1:5013/"],
        scope_allowlist={"urls": ["http://127.0.0.1:5013/"]},
        intrusive_authorized=True,
        allow_command_injection_proof=True,
        client_factory=_client_factory(handler),
    )

    payload = _artifact_payload(execution)
    assert execution.tool == TOOL_NAME
    assert execution.exit_code == 0
    assert payload["summary"]["confirmed_command_injection_count"] == 1
    assert payload["request_summary"]["command_allowlist_entry"] == DEFAULT_COMMAND
    assert payload["request_summary"]["password_stored"] is False
    assert payload["safety"]["local_dvga_lab_only"] is True
    assert payload["safety"]["credential_attack"] is False
    assert payload["safety"]["safe_command_allowlist_enforced"] is True
    assert payload["safety"]["generic_graphql_probe_changed"] is False
    assert payload["checks"][0]["cleanup_status"] == "not_required_no_state_change"
    assert payload["findings"][0]["title"] == "DVGA GraphQL Command Injection Confirmed"
    assert payload["findings"][0]["replay_recipe"]["intrusive_approval_required"] is True

    task = SimpleNamespace(
        tool=TOOL_NAME,
        target_id="http://127.0.0.1:5013/",
        params_json={},
    )
    findings = extract_findings(
        task=task,
        artifact=EvidenceArtifact(
            name=GRAPHQL_COMMAND_INJECTION_RESULTS_ARTIFACT_NAME,
            content_type="application/json",
            data=execution.artifacts[0].data,
            kind="runner-results",
        ),
        artifact_record=ArtifactRecord(),
    )

    assert len(findings) == 1
    assert findings[0].severity == "critical"
    assert "graphql-command-injection-validation" in findings[0].methodology_tags


def test_dvga_command_injection_runner_refuses_without_intrusive_approval() -> None:
    with pytest.raises(ValueError, match="requires explicit intrusive"):
        execute_graphql_command_injection(
            ["http://127.0.0.1:5013/"],
            scope_allowlist={"urls": ["http://127.0.0.1:5013/"]},
            client_factory=_client_factory(lambda request: httpx.Response(500)),
        )


def test_dvga_command_injection_runner_refuses_out_of_scope_and_nonlocal_targets() -> None:
    with pytest.raises(ValueError, match="local DVGA lab"):
        execute_graphql_command_injection(
            ["https://dvga.example.test/graphql"],
            scope_allowlist={"urls": ["https://dvga.example.test/"]},
            intrusive_authorized=True,
            allow_command_injection_proof=True,
            client_factory=_client_factory(lambda request: httpx.Response(500)),
        )

    with pytest.raises(ValueError, match="outside approved GraphQL command-injection scope"):
        execute_graphql_command_injection(
            ["http://localhost:5013/"],
            scope_allowlist={"urls": ["http://127.0.0.1:5013/"]},
            intrusive_authorized=True,
            allow_command_injection_proof=True,
            client_factory=_client_factory(lambda request: httpx.Response(500)),
        )


def test_dvga_command_injection_runner_enforces_command_allowlist_and_kill_switch() -> None:
    with pytest.raises(ValueError, match="safe allowlist"):
        execute_graphql_command_injection(
            ["http://127.0.0.1:5013/"],
            scope_allowlist={"urls": ["http://127.0.0.1:5013/"]},
            intrusive_authorized=True,
            allow_command_injection_proof=True,
            command="cat /etc/passwd",
            client_factory=_client_factory(lambda request: httpx.Response(500)),
        )

    with pytest.raises(ValueError, match="blocked shell metacharacters"):
        execute_graphql_command_injection(
            ["http://127.0.0.1:5013/"],
            scope_allowlist={"urls": ["http://127.0.0.1:5013/"]},
            intrusive_authorized=True,
            allow_command_injection_proof=True,
            command="whoami; id",
            allowed_commands=["whoami; id"],
            client_factory=_client_factory(lambda request: httpx.Response(500)),
        )

    with pytest.raises(ValueError, match="kill switch"):
        execute_graphql_command_injection(
            ["http://127.0.0.1:5013/"],
            scope_allowlist={"urls": ["http://127.0.0.1:5013/"]},
            intrusive_authorized=True,
            allow_command_injection_proof=True,
            kill_switch_enabled=True,
            client_factory=_client_factory(lambda request: httpx.Response(500)),
        )


def test_dispatch_supports_graphql_command_injection_runner() -> None:
    assert TOOL_NAME in SUPPORTED_TOOLS

    execution = dispatch_runner(
        RunnerRequest(
            tool=TOOL_NAME,
            targets=["http://127.0.0.1:5013/"],
            scope_allowlist={"urls": ["http://127.0.0.1:5013/"]},
            params={
                "intrusive_authorized": True,
                "allow_command_injection_proof": True,
                "timeout_seconds": 0.1,
            },
        )
    )

    payload = _artifact_payload(execution)
    assert execution.tool == TOOL_NAME
    assert payload["safety"]["local_dvga_lab_only"] is True
