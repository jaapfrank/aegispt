from __future__ import annotations

from uuid import UUID

from sqlalchemy import select

from api.app.models import AuditEvent, Finding, FindingRemediation, Run


def _create_retest_proposal_fixture(client) -> tuple[str, str, str]:
    engagement_response = client.post(
        "/api/v1/engagements",
        headers={"X-Actor": "mcp-tool-fixture"},
        json={
            "name": "MCP Action Tool Validation",
            "client": "Acme Corp",
            "roe_ref": "ROE-MCP-TOOLS",
        },
    )
    assert engagement_response.status_code == 201
    engagement_id = engagement_response.json()["id"]

    scope_response = client.post(
        f"/api/v1/engagements/{engagement_id}/scope",
        headers={"X-Actor": "mcp-tool-fixture"},
        json={
            "allowlist_json": {"urls": ["https://app.example.test"]},
            "denylist_json": {"domains": ["out-of-scope.example.test"]},
        },
    )
    assert scope_response.status_code == 201

    run_response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "passive-web-baseline",
            "configuration_json": {
                "assessment_type": "Website / Web App",
                "targets": {"urls": ["https://app.example.test"]},
            },
        },
    )
    assert run_response.status_code == 201
    run_id = run_response.json()["id"]

    with client.app.state.session_factory() as session:
        finding = Finding(
            run_id=UUID(run_id),
            title="Missing Security Header",
            severity="medium",
            target_id="https://app.example.test",
            evidence_ref="artifact://httpx/security-header",
            status="open",
            summary="The application did not return a required hardening header.",
            methodology_tags=["WSTG-CONF"],
            wstg_id="WSTG-CONF-07",
            control_family="configuration",
        )
        session.add(finding)
        session.flush()
        session.add(
            FindingRemediation(
                finding_id=finding.id,
                state="ready_for_retest",
                notes="Header patch is staged for verification.",
                owner="app-team",
                created_by="remediation-owner",
                updated_by="remediation-owner",
            )
        )
        session.commit()
        finding_id = str(finding.id)

    return engagement_id, run_id, finding_id


def test_mcp_action_tool_manifest_keeps_actions_explicit_and_gated(client) -> None:
    response = client.get("/api/v1/mcp/tools", headers={"X-Actor": "operator"})

    assert response.status_code == 200
    payload = response.json()
    assert payload["interface"] == "aegispt.controlled_action_tools.v1"
    assert payload["read_only_context_interface"] == "aegispt.read_only_operator_context.v1"
    assert payload["action_tools_enabled"] is True
    assert "POST /api/v1/mcp/tools/{tool_name}/invoke" in payload["write_methods_allowed"]
    assert "scan_launch" in payload["disabled_actions"]
    assert "pack_deployment" in payload["disabled_actions"]
    assert "secret_access" in payload["disabled_actions"]
    assert "must not expose raw secrets" in payload["secret_policy"].lower()

    tools = {tool["name"]: tool for tool in payload["tools"]}
    retest_proposal = tools["finding.retest.proposal"]
    assert retest_proposal["status"] == "enabled"
    assert retest_proposal["state_changing"] is False
    assert retest_proposal["confirmation_required"] is False
    assert retest_proposal["operator_review_required"] is True
    assert retest_proposal["output_contract"]["domain_state_changed"] is False

    webhook_handoff = tools["finding.webhook.handoff.request"]
    assert webhook_handoff["status"] == "disabled_pending_follow_up_task"
    assert webhook_handoff["state_changing"] is True
    assert webhook_handoff["confirmation_required"] is True


def test_mcp_finding_retest_proposal_is_allowed_and_does_not_create_runtime_work(client) -> None:
    engagement_id, run_id, finding_id = _create_retest_proposal_fixture(client)

    with client.app.state.session_factory() as session:
        before_runs = len(session.scalars(select(Run).where(Run.engagement_id == UUID(engagement_id))).all())

    response = client.post(
        "/api/v1/mcp/tools/finding.retest.proposal/invoke",
        headers={"X-Actor": "mcp-operator"},
        json={
            "engagement_id": engagement_id,
            "finding_id": finding_id,
            "arguments": {"notes": "Retest only the fixed header on the original target."},
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["tool_name"] == "finding.retest.proposal"
    assert payload["status"] == "completed"
    assert payload["state_changed"] is False
    assert payload["domain_state_changed"] is False
    assert payload["audit_recorded"] is True
    assert payload["operator_review_required"] is True
    assert payload["safety"]["approval_bypass"] is False
    assert payload["safety"]["dispatch_bypass"] is False
    assert payload["safety"]["pack_deployment_bypass"] is False
    assert payload["safety"]["secret_access"] is False

    result = payload["result"]
    assert result["proposal_type"] == "single_finding_retest"
    assert result["finding"]["id"] == finding_id
    assert result["finding"]["status"] == "open"
    assert result["finding"]["evidence_ref"] == "artifact://httpx/security-header"
    assert result["source_run"]["id"] == run_id
    assert result["remediation"]["state"] == "ready_for_retest"
    assert result["proposed_action"]["method"] == "POST"
    assert result["proposed_action"]["endpoint"] == f"/api/v1/findings/{finding_id}/retest"
    assert result["proposed_action"]["must_be_performed_by_operator"] is True
    assert result["review"]["run_created"] is False
    assert result["review"]["tasks_queued"] is False
    assert result["review"]["approval_bypass"] is False

    with client.app.state.session_factory() as session:
        after_runs = len(session.scalars(select(Run).where(Run.engagement_id == UUID(engagement_id))).all())
        finding = session.get(Finding, UUID(finding_id))
        audit = session.get(AuditEvent, UUID(payload["audit_event_id"]))

    assert after_runs == before_runs
    assert finding.status == "open"
    assert audit is not None
    assert audit.action == "mcp.tool.proposal_generated"
    assert audit.actor == "mcp-operator"
    assert audit.metadata_json["domain_state_changed"] is False


def test_mcp_action_tools_require_explicit_actor_header(client) -> None:
    tools_response = client.get("/api/v1/mcp/tools")
    assert tools_response.status_code == 401
    assert "X-Actor" in tools_response.json()["detail"]

    invoke_response = client.post(
        "/api/v1/mcp/tools/finding.retest.proposal/invoke",
        json={"arguments": {}},
    )
    assert invoke_response.status_code == 401
    assert "X-Actor" in invoke_response.json()["detail"]


def test_mcp_action_tools_deny_forbidden_runtime_and_pack_actions(client) -> None:
    response = client.post(
        "/api/v1/mcp/tools/scan_launch/invoke",
        headers={"X-Actor": "mcp-operator"},
        json={"arguments": {}},
    )

    assert response.status_code == 403
    assert "forbidden" in response.json()["detail"]


def test_mcp_state_changing_action_requires_confirmation_and_remains_disabled(client) -> None:
    engagement_id, _run_id, finding_id = _create_retest_proposal_fixture(client)

    missing_confirmation = client.post(
        "/api/v1/mcp/tools/finding.webhook.handoff.request/invoke",
        headers={"X-Actor": "mcp-operator"},
        json={
            "engagement_id": engagement_id,
            "finding_id": finding_id,
            "arguments": {"operator_note": "Please open a workflow handoff."},
        },
    )
    assert missing_confirmation.status_code == 409
    assert "explicit operator confirmation required" in missing_confirmation.json()["detail"]

    confirmed_but_disabled = client.post(
        "/api/v1/mcp/tools/finding.webhook.handoff.request/invoke",
        headers={"X-Actor": "mcp-operator"},
        json={
            "engagement_id": engagement_id,
            "finding_id": finding_id,
            "arguments": {"operator_note": "Please open a workflow handoff."},
            "confirmation": {
                "confirmed": True,
                "statement": "I understand this would be state-changing if enabled.",
            },
        },
    )
    assert confirmed_but_disabled.status_code == 403
    assert "not enabled in this first MCP action-tool slice" in confirmed_but_disabled.json()["detail"]
