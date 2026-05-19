from __future__ import annotations

from uuid import UUID

from sqlalchemy import select

from api.app.models import (
    CapabilityPack,
    CapabilityPackArtifact,
    CapabilityPackDeployment,
    CapabilityPackValidationResult,
    EvidenceArtifact,
    Finding,
    Run,
    Task,
    ToolExecution,
)


def _create_engagement_run(client) -> tuple[str, str]:
    engagement_response = client.post(
        "/api/v1/engagements",
        headers={"X-Actor": "mcp-tester"},
        json={
            "name": "MCP Read Only Validation",
            "client": "Acme Corp",
            "roe_ref": "ROE-2026-MCP",
        },
    )
    assert engagement_response.status_code == 201
    engagement_id = engagement_response.json()["id"]

    scope_response = client.post(
        f"/api/v1/engagements/{engagement_id}/scope",
        headers={"X-Actor": "mcp-tester"},
        json={
            "allowlist_json": {
                "domains": ["example.com"],
                "urls": ["https://example.com"],
            },
            "denylist_json": {"domains": ["admin.example.com"]},
        },
    )
    assert scope_response.status_code == 201

    run_response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "passive-web-baseline",
            "configuration_json": {
                "targets": {"urls": ["https://example.com"]},
                "access": {
                    "accounts": [
                        {
                            "label": "test account",
                            "username": "alice",
                            "secret_ref": "CorrectHorseBatteryStaple!",
                            "api_key_ref": "raw-api-token",
                            "bearer_token_ref": "raw-bearer-token",
                            "session_ref": "raw-session-cookie",
                        }
                    ]
                },
                "custom_token": "raw-custom-token",
            },
        },
    )
    assert run_response.status_code == 201
    return engagement_id, run_response.json()["id"]


def _seed_pack_finding_and_evidence(client, *, engagement_id: str, run_id: str) -> None:
    with client.app.state.session_factory() as session:
        run = session.scalar(select(Run).where(Run.id == UUID(run_id)))
        task = session.scalar(select(Task).where(Task.run_id == UUID(run_id)))
        assert run is not None
        assert task is not None

        pack = CapabilityPack(
            engagement_id=UUID(engagement_id),
            name="Read-only MCP pack",
            version="2026.04.22",
            status="deployed",
            generated_by="codex",
            generation_mode="codex-supervised",
            description="Pack metadata should be visible without artifact content.",
            methodology_tags=["WSTG-INFO"],
            manifest_json={"tools": ["httpx"], "api_token": "raw-manifest-token"},
            provenance_json={"source": "test", "secret": "raw-pack-provenance-secret"},
        )
        session.add(pack)
        session.flush()

        session.add(
            CapabilityPackArtifact(
                pack_id=pack.id,
                artifact_type="runner-config",
                logical_name="httpx-read-only-config",
                status="generated",
                checksum_sha256="b" * 64,
                methodology_tags=["WSTG-INFO"],
                content_text="raw pack content should not leak",
                content_json={"payload": "raw pack json content should not leak"},
                provenance_json={"note": "safe", "api_key": "raw-pack-artifact-api-key"},
            )
        )
        session.add(
            CapabilityPackValidationResult(
                pack_id=pack.id,
                validator="unit-test",
                executed_by="mcp-tester",
                status="passed",
                summary="Validation summary is safe.",
                artifact_results_json=[{"secret": "raw-validation-secret"}],
                validation_artifacts_json=[{"uri": "artifact://validation/result"}],
                blocking_issues_json=[],
            )
        )
        deployment = CapabilityPackDeployment(
            pack_id=pack.id,
            engagement_id=UUID(engagement_id),
            deployed_by="mcp-tester",
            deployment_target="engagement-runtime",
            run_profile_name="passive-web-baseline",
            status="deployed",
            runtime_binding_json={
                "runner_digest": "sha256:test",
                "api_token": "raw-deployment-token",
            },
        )
        session.add(deployment)
        session.flush()

        run.bound_pack_id = pack.id
        run.bound_pack_version = pack.version
        run.bound_pack_deployment_id = deployment.id

        session.add(
            Finding(
                run_id=run.id,
                source_pack_id=pack.id,
                title="Missing Security Header",
                severity="medium",
                target_id="https://example.com",
                evidence_ref="artifact://httpx/security-header",
                status="open",
                summary="The application did not return a test header.",
                methodology_tags=["WSTG-CONF"],
                ptes_phase="vulnerability-analysis",
                nist_phase="analysis",
                wstg_id="WSTG-CONF-07",
                wstg_version="4.2",
                control_family="configuration",
            )
        )
        execution = ToolExecution(
            task_id=task.id,
            runner_digest="sha256:httpx",
            tool_version="httpx/test",
            exit_code=0,
            stdout_text="raw stdout should not leak",
            stderr_text="raw stderr should not leak",
        )
        session.add(execution)
        session.flush()
        session.add(
            EvidenceArtifact(
                tool_execution_id=execution.id,
                kind="httpx-json",
                uri="artifact://httpx/security-header",
                sha256="a" * 64,
                redaction_state="redacted",
                metadata_json={
                    "name": "security-header-result",
                    "api_token": "raw-evidence-token",
                    "nested": {"session_cookie": "raw-evidence-session-cookie"},
                },
            )
        )
        session.commit()


def test_mcp_resource_manifest_is_read_only(client) -> None:
    response = client.get("/api/v1/mcp/resources", headers={"X-Actor": "operator"})

    assert response.status_code == 200
    payload = response.json()
    assert payload["read_only"] is True
    assert payload["tools"] == []
    assert payload["write_methods_allowed"] == []
    assert "scan_launch" in payload["disabled_actions"]
    assert "pack_deployment" in payload["disabled_actions"]
    assert "secret_access" in payload["disabled_actions"]
    assert all(resource["read_only"] is True for resource in payload["resources"])
    assert {resource["name"] for resource in payload["resources"]} >= {
        "engagement.scope",
        "run.summary",
        "finding.summary",
        "report.catalog",
        "evidence.metadata",
        "pack.metadata",
    }


def test_mcp_read_only_context_routes_do_not_expose_write_methods(client) -> None:
    unsafe_methods = {"POST", "PUT", "PATCH", "DELETE"}

    mcp_routes = [
        route
        for route in client.app.routes
        if str(getattr(route, "path", "")) in {
            "/api/v1/mcp/resources",
            "/api/v1/mcp/engagements/{engagement_id}/context",
        }
    ]

    assert mcp_routes
    for route in mcp_routes:
        assert unsafe_methods.isdisjoint(set(getattr(route, "methods", set())))


def test_mcp_context_exposes_safe_metadata_without_secrets_or_actions(client) -> None:
    engagement_id, run_id = _create_engagement_run(client)
    _seed_pack_finding_and_evidence(client, engagement_id=engagement_id, run_id=run_id)

    response = client.get(
        f"/api/v1/mcp/engagements/{engagement_id}/context",
        headers={"X-Actor": "operator"},
        params={"run_id": run_id},
    )

    assert response.status_code == 200
    payload = response.json()
    raw_payload = response.text

    assert payload["read_only"] is True
    assert payload["tools"] == []
    assert payload["write_methods_allowed"] == []
    assert payload["safety"]["action_tools_enabled"] is False
    assert payload["safety"]["artifact_content_exposed"] is False
    assert payload["safety"]["runtime_output_exposed"] is False
    assert payload["selected_run"]["id"] == run_id
    assert payload["selected_run"]["task_summaries"]
    assert "params_json" not in payload["selected_run"]["task_summaries"][0]
    assert "stdout_text" not in raw_payload
    assert "stderr_text" not in raw_payload

    for protected_value in (
        "CorrectHorseBatteryStaple!",
        "raw-api-token",
        "raw-bearer-token",
        "raw-session-cookie",
        "raw-custom-token",
        "raw-manifest-token",
        "raw-pack-provenance-secret",
        "raw pack content should not leak",
        "raw pack json content should not leak",
        "raw-pack-artifact-api-key",
        "raw-validation-secret",
        "raw-deployment-token",
        "raw stdout should not leak",
        "raw stderr should not leak",
        "raw-evidence-token",
        "raw-evidence-session-cookie",
    ):
        assert protected_value not in raw_payload

    pack_artifact = payload["packs"][0]["artifacts"][0]
    assert pack_artifact["content_available"] is True
    assert pack_artifact["content_exposed"] is False
    assert "content_text" not in pack_artifact
    assert "content_json" not in pack_artifact

    evidence = payload["evidence"][0]
    assert evidence["uri"] == "artifact://httpx/security-header"
    assert evidence["content_exposed"] is False
    assert evidence["runtime_output_exposed"] is False
    assert evidence["metadata_json"]["api_token"] == "[redacted]"
    assert evidence["metadata_json"]["nested"]["session_cookie"] == "[redacted]"
    assert payload["reports"]
    assert payload["findings"][0]["theater_path"].startswith("/api/v1/findings/")
