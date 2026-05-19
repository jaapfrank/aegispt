from __future__ import annotations

from uuid import UUID

from sqlalchemy import func, select

from api.app.models import (
    AgentProposal,
    AgentReasoning,
    Approval,
    Engagement,
    EvidenceArtifact,
    Finding,
    InventorySnapshot,
    RationaleLedgerEntry,
    Run,
    RunProfile,
    Scope,
    SecretRef,
    TargetContextDocument,
    Task,
    ToolExecution,
)
from api.app.services.assessment_graph import (
    build_assessment_graph,
    build_assessment_graph_with_hypotheses,
    build_assessment_hypotheses,
    build_normalized_evidence_graph,
)


def _create_graph_fixture(client) -> str:
    profiles_response = client.get("/api/v1/run-profiles")
    assert profiles_response.status_code == 200

    with client.app.state.session_factory() as session:
        profile = session.scalar(select(RunProfile).where(RunProfile.name == "autonomous-web"))
        assert profile is not None
        engagement = Engagement(
            name="Assessment Graph Validation",
            client="Acme Corp",
            roe_ref="ROE-GRAPH-2026",
            status="active",
        )
        scope = Scope(
            engagement=engagement,
            allowlist_json={"urls": ["https://graph.example.test"]},
            denylist_json={},
        )
        snapshot = InventorySnapshot(
            engagement=engagement,
            requested_by="graph-tester",
            status="completed",
            source_tools_json=["httpx"],
            raw_inputs_json={},
            normalized_inventory_json={
                "targets": ["https://graph.example.test"],
                "hosts": [{"hostname": "graph.example.test"}],
                "services": [{"name": "https", "port": 443}],
                "tech_stack_profile": {
                    "technologies": ["python", "flask"],
                    "api_endpoints": ["https://graph.example.test/login"],
                },
                "api_endpoints": ["https://graph.example.test/api/v1/users"],
                "identity_subjects": [
                    {"subject": "service-account:report-export", "type": "service_account"}
                ],
                "saas_connectors": [
                    {
                        "name": "Canva bulk export connector",
                        "type": "oauth_connector",
                        "target_dataset": "marketing-assets",
                    }
                ],
                "oauth_scopes": [
                    {"scope": "files:read:all", "type": "oauth_scope"}
                ],
                "permissions": [
                    {"permission": "bulk_export", "type": "connector_permission"}
                ],
            },
            summary_json={
                "host_count": 1,
                "service_count": 1,
                "endpoint_count": 1,
                "technology_count": 2,
            },
            confidence_score=0.91,
        )
        run = Run(
            engagement=engagement,
            profile=profile,
            source_inventory_snapshot=snapshot,
            requested_by="graph-tester",
            status="completed",
            autonomous_mode=True,
            autonomous_intrusive_allowed=False,
            configuration_json={
                "targets": {"urls": ["https://graph.example.test"]},
                "run_mode": "ai_loop",
            },
        )
        finding = Finding(
            run=run,
            source_inventory_snapshot=snapshot,
            title="Session exposure risk on authenticated route",
            severity="high",
            target_id="https://graph.example.test/login",
            evidence_ref="evidence://session-json",
            status="open",
            validation_status="validated",
            summary=(
                "A login form was found and a session cookie was present. "
                "The graph should ask for the next safe auth observation."
            ),
            methodology_tags=["OWASP-WSTG", "session_cookie_present"],
            wstg_id="WSTG-SESS-02",
        )
        task = Task(
            run=run,
            source_finding=finding,
            tool="session-security",
            target_id="https://graph.example.test/login",
            status="completed",
            params_json={"approved_scope": True},
        )
        execution = ToolExecution(
            task=task,
            runner_digest="sha256:session-runner",
            tool_version="2026.05",
            exit_code=0,
            stdout_text='{"session_cookie_present": true}',
            stderr_text=None,
        )
        artifact = EvidenceArtifact(
            execution=execution,
            kind="json",
            uri="evidence://session-json",
            sha256="a" * 64,
            redaction_state="redacted",
            metadata_json={"contains_raw_secret": False},
        )
        context = TargetContextDocument(
            run=run,
            layer_name="phase_1_session_context",
            context_kind="target_context",
            status="recorded",
            source_targets_json=[{"kind": "url", "value": "https://graph.example.test/login"}],
            technologies_detected_json=["flask"],
            endpoints_discovered_json=["https://graph.example.test/login"],
            recommended_tools_json=["session-security"],
            micro_plan_json=[{"runner": "session-security", "decision": "RUN"}],
            evidence_refs_json=[{"uri": artifact.uri}],
            context_summary="Session evidence links a login route to cookie observations.",
            provenance_json={"live_target_actions_performed": False},
        )
        reasoning = AgentReasoning(
            run=run,
            task=task,
            reasoning_type="assessment_loop",
            status="recorded",
            context_snapshot_json={},
            observations_json=[],
            hypotheses_json=[],
            proposals_json=[],
            provider="deterministic",
        )
        proposal = AgentProposal(
            run=run,
            agent_reasoning=reasoning,
            proposed_tool="session-security",
            proposed_target="https://graph.example.test/login",
            proposed_params_json={"approved_scope": True},
            reasoning_text="Stored context supports a session-security observation.",
            risk_tier="active",
            priority=10,
            confidence_score=0.82,
            status="approved",
        )
        approval = Approval(
            run=run,
            step_id="session-security",
            approver_id="graph-tester",
            decision="approved",
        )
        session.add_all(
            [
                engagement,
                scope,
                snapshot,
                run,
                finding,
                task,
                execution,
                artifact,
                context,
                reasoning,
                proposal,
                approval,
            ]
        )
        session.flush()
        secret_ref = SecretRef(
            engagement_id=engagement.id,
            vault_pointer="aegispt://secret-ref/graph-redacted-session",
            purpose="run.ephemeral_credential_vault.session",
            secret_kind="session",
            storage_backend="encrypted_local",
            display_label="Redacted authenticated session",
            encrypted_value="encrypted-test-value",
            metadata_json={
                "ephemeral_run_vault": True,
                "run_id": str(run.id),
                "target": "https://graph.example.test/login",
                "raw_secret_material_exposed": False,
            },
        )
        session.add(secret_ref)
        rationale = RationaleLedgerEntry(
            run=run,
            context_document=context,
            task_id=task.id,
            agent_proposal_id=proposal.id,
            action_type="tool_dispatch",
            tool_name="session-security",
            target="https://graph.example.test/login",
            rationale_text=(
                "I observed session evidence in a stored context document, therefore I am "
                "dispatching Tool session-security with parameters from approved scope."
            ),
            decision_source_json={
                "observed_context": {"context_document_id": str(context.id)},
                "dispatch_contract": {"dispatch_path": "registered_runner_queue"},
            },
            parameters_json={"approved_scope": True},
            status="recorded",
            provenance_json={"registered_runner_required": True},
        )
        session.add(rationale)
        session.commit()
        return str(run.id)


def test_assessment_graph_builds_stable_evidence_nodes_and_edges(client) -> None:
    run_id = _create_graph_fixture(client)

    with client.app.state.session_factory() as session:
        graph = build_assessment_graph(session, run_id=UUID(run_id))
        second_graph = build_assessment_graph(session, run_id=UUID(run_id))

    assert graph["execution_contract"]["analysis_only"] is True
    assert graph["execution_contract"]["dispatches_work_directly"] is False
    assert [node["id"] for node in graph["nodes"]] == [node["id"] for node in second_graph["nodes"]]
    assert [edge["id"] for edge in graph["edges"]] == [edge["id"] for edge in second_graph["edges"]]

    node_kinds = {node["kind"] for node in graph["nodes"]}
    assert {
        "run",
        "scope",
        "inventory_snapshot",
        "inventory_endpoint",
        "inventory_host",
        "inventory_service",
        "inventory_technology",
        "task",
        "tool_execution",
        "evidence_artifact",
        "finding",
        "approval",
        "runner_metadata",
        "context_document",
        "agent_proposal",
        "rationale_entry",
        "report_evidence",
    }.issubset(node_kinds)

    relationships = {edge["relationship"] for edge in graph["edges"]}
    assert {
        "authorizes_run_scope",
        "uses_inventory_snapshot",
        "contains_inventory_node",
        "has_task",
        "uses_runner",
        "produced_execution",
        "produced_artifact",
        "has_finding",
        "supported_by_artifact",
        "has_approval",
        "has_context_document",
        "context_uses_artifact",
        "has_rationale_entry",
        "rationale_dispatches_task",
        "reports_finding",
        "reports_rationale_entry",
    }.issubset(relationships)

    report_node = next(node for node in graph["nodes"] if node["kind"] == "report_evidence")
    assert report_node["data"]["finding_count"] == 1
    assert report_node["data"]["task_count"] == 1
    runner_names = {
        node["source_id"]
        for node in graph["nodes"]
        if node["kind"] == "runner_metadata"
    }
    assert {"session-security", "auth-flow", "client-state"}.issubset(runner_names)


def test_normalized_evidence_graph_covers_evidence_domains_and_edge_provenance(client) -> None:
    run_id = _create_graph_fixture(client)

    with client.app.state.session_factory() as session:
        graph = build_normalized_evidence_graph(session, run_id=run_id)

    assert graph["graph_version"] == "normalized-evidence-graph-v1"
    assert graph["execution_contract"]["analysis_only"] is True
    assert graph["execution_contract"]["dispatches_work_directly"] is False
    assert graph["execution_contract"]["creates_tasks"] is False
    assert graph["execution_contract"]["approves_proposals"] is False
    assert graph["execution_contract"]["materializes_secrets"] is False

    node_types = {node["type"] for node in graph["nodes"]}
    assert {
        "asset",
        "api",
        "credential_ref",
        "evidence_ref",
        "finding",
        "identity",
        "permission",
        "saas_connector",
        "task",
    }.issubset(node_types)

    assert all("confidence" in node for node in graph["nodes"])
    assert all(isinstance(node["evidence_refs"], list) for node in graph["nodes"])
    assert graph["edges"]
    for edge in graph["edges"]:
        assert edge["provenance"]
        assert "confidence" in edge
        assert isinstance(edge["evidence_refs"], list)

    credential_node = next(node for node in graph["nodes"] if node["type"] == "credential_ref")
    assert credential_node["data"]["raw_secret_material_exposed"] is False
    assert "encrypted-test-value" not in str(credential_node)

    response = client.get(f"/api/v1/runs/{run_id}/evidence-graph", headers={"X-Actor": "graph-tester"})
    assert response.status_code == 200
    payload = response.json()
    assert payload["graph_version"] == "normalized-evidence-graph-v1"
    assert payload["summary"]["node_count"] == len(payload["nodes"])
    assert "saas_connector" in payload["summary"]["node_types"]


def test_assessment_hypotheses_link_sources_and_missing_prerequisites(client) -> None:
    run_id = _create_graph_fixture(client)

    with client.app.state.session_factory() as session:
        graph = build_assessment_graph(session, run_id=run_id)
        report = build_assessment_hypotheses(graph)
        combined = build_assessment_graph_with_hypotheses(session, run_id=run_id)

    assert report["execution_contract"]["dispatches_work_directly"] is False
    assert combined["hypothesis_report"]["hypotheses"]
    hypothesis = report["hypotheses"][0]
    assert hypothesis["source_ids"]
    assert hypothesis["confidence"] >= 0.7
    assert hypothesis["claims_unobserved_impact"] is False
    assert hypothesis["unsupported_claims"] == []
    assert "observed_evidence" in hypothesis
    assert "inferred_next_question" in hypothesis
    assert any(candidate["runner"] == "auth-flow" for candidate in hypothesis["safe_next_observation_candidates"])
    auth_flow_missing = [
        item
        for item in hypothesis["missing_prerequisites"]
        if item["runner"] == "auth-flow"
    ]
    assert auth_flow_missing
    assert auth_flow_missing[0]["missing"] == ["operator_auth_context"]
    assert "no stored evidence" in auth_flow_missing[0]["explanation"]
    assert all(candidate["dispatches_work"] is False for candidate in hypothesis["safe_next_observation_candidates"])


def test_assessment_graph_is_read_only(client) -> None:
    run_id = _create_graph_fixture(client)

    with client.app.state.session_factory() as session:
        before = {
            model.__name__: session.scalar(select(func.count()).select_from(model))
            for model in (Task, Finding, Approval, AgentProposal, RationaleLedgerEntry, SecretRef)
        }
        graph = build_assessment_graph(session, run_id=run_id)
        build_assessment_hypotheses(graph)
        build_normalized_evidence_graph(session, run_id=run_id)
        after = {
            model.__name__: session.scalar(select(func.count()).select_from(model))
            for model in (Task, Finding, Approval, AgentProposal, RationaleLedgerEntry, SecretRef)
        }

    assert after == before
