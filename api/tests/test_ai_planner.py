from __future__ import annotations

from uuid import UUID

from sqlalchemy import select

from api.app.models import (
    AgentProposal,
    InventorySnapshot,
    RationaleLedgerEntry,
    Run,
    RunProfile,
    TargetContextDocument,
    Task,
)
from api.app.services import reports as report_service
from api.app.services.ai_planner import ensure_context_document, generate_sub_plan
from api.app.services.assessment_loop import LOOP_PROPOSAL_KIND


def _create_engagement_and_scope(client, allowlist: dict) -> str:
    response = client.post(
        "/api/v1/engagements",
        headers={"X-Actor": "context-planner-tester"},
        json={
            "name": "AI Context Planner Validation",
            "client": "Acme Corp",
            "roe_ref": "ROE-CONTEXT-2026",
        },
    )
    assert response.status_code == 201
    engagement_id = response.json()["id"]
    scope_response = client.post(
        f"/api/v1/engagements/{engagement_id}/scope",
        headers={"X-Actor": "context-planner-tester"},
        json={"allowlist_json": allowlist, "denylist_json": {}},
    )
    assert scope_response.status_code == 201
    return engagement_id


def _create_loop_run(
    client,
    engagement_id: str,
    *,
    targets: dict,
    snapshot_id: str | None = None,
) -> str:
    client.get("/api/v1/run-profiles")
    with client.app.state.session_factory() as session:
        profile = session.scalar(select(RunProfile).where(RunProfile.name == "autonomous-web"))
        assert profile is not None
        run = Run(
            engagement_id=UUID(engagement_id),
            profile_id=profile.id,
            source_inventory_snapshot_id=UUID(snapshot_id) if snapshot_id else None,
            requested_by="context-planner-tester",
            status="requested",
            autonomous_mode=True,
            autonomous_intrusive_allowed=False,
            configuration_json={"targets": targets, "run_mode": "ai_loop"},
        )
        session.add(run)
        session.commit()
        return str(run.id)


def _create_snapshot(client, engagement_id: str, *, signals: list[dict]) -> str:
    with client.app.state.session_factory() as session:
        snapshot = InventorySnapshot(
            engagement_id=UUID(engagement_id),
            requested_by="context-planner-tester",
            status="completed",
            source_tools_json=["httpx"],
            raw_inputs_json={},
            normalized_inventory_json={
                "targets": ["https://loop.example.test"],
                "signal_profile": {"signals": signals},
                "tech_stack_profile": {
                    "language": ["python"],
                    "api_endpoints": ["https://loop.example.test/api"],
                },
            },
            summary_json={"url_count": 1, "service_count": 1},
            confidence_score=0.86,
        )
        session.add(snapshot)
        session.commit()
        return str(snapshot.id)


def test_contextual_profile_is_created_before_loop_task_dispatch(client) -> None:
    engagement_id = _create_engagement_and_scope(
        client,
        {"urls": ["https://loop.example.test"]},
    )
    run_id = _create_loop_run(
        client,
        engagement_id,
        targets={"urls": ["https://loop.example.test"]},
    )

    response = client.post(
        f"/api/v1/runs/{run_id}/assessment-loop/iterate",
        headers={"X-Actor": "context-planner-tester"},
        json={"operator_note": "Validate context-first execution."},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["context_document_id"]
    assert payload["rationale_ledger_entry_id"]
    assert payload["queued_task_id"]
    assert payload["next_action"]["tool"] == "httpx"
    assert payload["rationale_ledger"]
    ledger_payload = payload["rationale_ledger"][0]
    assert ledger_payload["id"] == payload["rationale_ledger_entry_id"]
    assert ledger_payload["tool_name"] == "httpx"
    assert ledger_payload["decision_source"]["rationale_contract"]["template"].startswith("I observed X")

    with client.app.state.session_factory() as session:
        context = session.get(TargetContextDocument, UUID(payload["context_document_id"]))
        assert context is not None
        assert context.run_id == UUID(run_id)
        assert context.layer_name == "phase_0_contextual_profile"
        assert context.provenance_json["live_target_actions_performed"] is False
        assert "https://loop.example.test" in context.endpoints_discovered_json
        assert "httpx" in context.recommended_tools_json
        assert context.micro_plan_json

        rationale = session.get(RationaleLedgerEntry, UUID(payload["rationale_ledger_entry_id"]))
        assert rationale is not None
        assert rationale.context_document_id == context.id
        assert rationale.tool_name == "httpx"
        assert rationale.task_id == UUID(payload["queued_task_id"])
        assert rationale.agent_proposal_id == UUID(payload["proposal_id"])
        assert rationale.status == "task_queued"
        assert rationale.rationale_text.startswith("I observed ")
        assert "therefore I am dispatching Tool httpx" in rationale.rationale_text
        assert "with parameters" in rationale.rationale_text
        assert rationale.decision_source_json["observed_context"]["context_document_id"] == str(context.id)
        assert rationale.decision_source_json["dispatch_contract"]["dispatch_path"] == "registered_runner_queue"
        assert rationale.decision_source_json["rationale_contract"]["registered_runner_required"] is True

        task = session.get(Task, UUID(payload["queued_task_id"]))
        assert task is not None
        loop_metadata = task.params_json["assessment_loop"]
        assert loop_metadata["context_document_id"] == str(context.id)
        assert loop_metadata["rationale_ledger_entry_id"] == str(rationale.id)

        run = session.get(Run, UUID(run_id))
        assert run is not None
        markdown = report_service.render_markdown_report(run, variant="technical")
        assert "## AI Action Rationale Ledger" in markdown
        assert str(rationale.id) in markdown
        assert "therefore I am dispatching Tool httpx" in markdown


def test_recursive_sub_plan_records_parent_and_evidence_backed_micro_plan(client) -> None:
    engagement_id = _create_engagement_and_scope(
        client,
        {"urls": ["https://loop.example.test"]},
    )
    snapshot_id = _create_snapshot(
        client,
        engagement_id,
        signals=[{"key": "graphql_endpoint", "value": True, "confidence": 0.9}],
    )
    run_id = _create_loop_run(
        client,
        engagement_id,
        targets={"urls": ["https://loop.example.test"]},
        snapshot_id=snapshot_id,
    )

    with client.app.state.session_factory() as session:
        run = session.get(Run, UUID(run_id))
        assert run is not None
        scope = run.engagement.scopes[-1]
        parent = ensure_context_document(
            session,
            run=run,
            scope=scope,
            targets=[{"kind": "url", "value": "https://loop.example.test"}],
            plan={
                "runners": [
                    {
                        "runner": "graphql-probe",
                        "decision": "RUN",
                        "summary": "GraphQL endpoint exists.",
                    }
                ]
            },
        )
        child = generate_sub_plan(
            session,
            run=run,
            parent_context=parent,
            layer_name="api_graphql",
            discovered_layer={
                "technologies": ["graphql"],
                "endpoints": ["https://loop.example.test/api/graphql"],
            },
            plan={
                "runners": [
                    {
                        "runner": "graphql-probe",
                        "decision": "RUN",
                        "summary": "GraphQL endpoint exists.",
                    }
                ]
            },
        )

        assert child.parent_context_document_id == parent.id
        assert child.context_kind == "recursive_surface_micro_plan"
        assert "graphql" in child.technologies_detected_json
        assert "https://loop.example.test/api/graphql" in child.endpoints_discovered_json
        assert "graphql-probe" in child.recommended_tools_json
        assert child.evidence_refs_json
        assert child.micro_plan_json[0]["execution_contract"] == "registered_runner_or_existing_approval_flow_only"


def test_active_action_creates_rationale_before_reviewable_proposal_not_task(client) -> None:
    engagement_id = _create_engagement_and_scope(
        client,
        {"urls": ["https://loop.example.test"]},
    )
    snapshot_id = _create_snapshot(
        client,
        engagement_id,
        signals=[
            {"key": "login_form_found", "value": True, "confidence": 0.9},
            {"key": "auth_flow_present", "value": True, "confidence": 0.9},
            {"key": "session_cookie_present", "value": True, "confidence": 0.9},
        ],
    )
    run_id = _create_loop_run(
        client,
        engagement_id,
        targets={"urls": ["https://loop.example.test"]},
        snapshot_id=snapshot_id,
    )
    with client.app.state.session_factory() as session:
        session.add(
            Task(
                run_id=UUID(run_id),
                tool="httpx",
                target_id="https://loop.example.test",
                status="completed",
                params_json={"assessment_loop": {"iteration": 1}},
            )
        )
        session.commit()

    response = client.post(
        f"/api/v1/runs/{run_id}/assessment-loop/iterate",
        headers={"X-Actor": "context-planner-tester"},
        json={},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["queued_task_id"] is None
    assert payload["proposal_id"]
    assert payload["rationale_ledger_entry_id"]
    assert payload["next_action"]["tool"] == "auth-flow"

    with client.app.state.session_factory() as session:
        proposal = session.get(AgentProposal, UUID(payload["proposal_id"]))
        assert proposal is not None
        assert proposal.status == "pending_review"
        assert proposal.metadata_json["proposal_kind"] == LOOP_PROPOSAL_KIND
        assert proposal.metadata_json["context_document_id"] == payload["context_document_id"]

        rationale = session.get(RationaleLedgerEntry, UUID(payload["rationale_ledger_entry_id"]))
        assert rationale is not None
        assert rationale.task_id is None
        assert rationale.agent_proposal_id == proposal.id
        assert rationale.status == "pending_approval"
        assert rationale.provenance_json["registered_runner_required"] is True
        assert "therefore I am dispatching Tool auth-flow" in rationale.rationale_text
        assert rationale.decision_source_json["dispatch_contract"]["dispatch_path"] == "operator_approval_then_registered_runner"

        auth_task = session.scalar(
            select(Task).where(Task.run_id == UUID(run_id), Task.tool == "auth-flow")
        )
        assert auth_task is None


def test_ai_loop_recurses_to_discovered_graphql_surface_before_next_action(client) -> None:
    engagement_id = _create_engagement_and_scope(
        client,
        {"urls": ["https://loop.example.test"]},
    )
    run_id = _create_loop_run(
        client,
        engagement_id,
        targets={"urls": ["https://loop.example.test"]},
    )

    first_response = client.post(
        f"/api/v1/runs/{run_id}/assessment-loop/iterate",
        headers={"X-Actor": "context-planner-tester"},
        json={},
    )
    assert first_response.status_code == 200
    first_payload = first_response.json()
    assert first_payload["next_action"]["tool"] == "httpx"

    with client.app.state.session_factory() as session:
        first_task = session.get(Task, UUID(first_payload["queued_task_id"]))
        assert first_task is not None
        first_task.status = "completed"
        snapshot = InventorySnapshot(
            engagement_id=UUID(engagement_id),
            requested_by="context-planner-tester",
            status="completed",
            source_tools_json=["httpx"],
            raw_inputs_json={},
            normalized_inventory_json={
                "targets": ["https://loop.example.test"],
                "signal_profile": {
                    "signals": [
                        {
                            "key": "graphql_endpoint",
                            "value": "https://loop.example.test/api/graphql",
                            "confidence": 0.92,
                        }
                    ]
                },
                "tech_stack_profile": {
                    "graphql_endpoints": ["https://loop.example.test/api/graphql"],
                    "api_endpoints": ["https://loop.example.test/api"],
                },
            },
            summary_json={"url_count": 1, "service_count": 1},
            confidence_score=0.91,
        )
        run = session.get(Run, UUID(run_id))
        assert run is not None
        session.add(snapshot)
        session.flush()
        run.source_inventory_snapshot_id = snapshot.id
        session.commit()

    second_response = client.post(
        f"/api/v1/runs/{run_id}/assessment-loop/iterate",
        headers={"X-Actor": "context-planner-tester"},
        json={},
    )

    assert second_response.status_code == 200
    payload = second_response.json()
    assert payload["queued_task_id"] is None
    assert payload["proposal_id"]
    assert payload["next_action"]["tool"] == "graphql-probe"
    assert payload["next_action"]["target"] == "https://loop.example.test/api/graphql"
    assert payload["next_action"]["decision_source"] == "recursive_surface_micro_plan"
    assert payload["target_context"]["context_kind"] == "recursive_surface_micro_plan"

    with client.app.state.session_factory() as session:
        child_context = session.get(TargetContextDocument, UUID(payload["context_document_id"]))
        assert child_context is not None
        assert child_context.parent_context_document_id == UUID(first_payload["context_document_id"])
        assert child_context.context_kind == "recursive_surface_micro_plan"
        assert "graphql-probe" in child_context.recommended_tools_json
        assert "https://loop.example.test/api/graphql" in child_context.endpoints_discovered_json

        rationale = session.get(RationaleLedgerEntry, UUID(payload["rationale_ledger_entry_id"]))
        assert rationale is not None
        assert rationale.context_document_id == child_context.id
        assert rationale.task_id is None
        assert rationale.agent_proposal_id == UUID(payload["proposal_id"])
        assert rationale.status == "pending_approval"

        proposal = session.get(AgentProposal, UUID(payload["proposal_id"]))
        assert proposal is not None
        assert proposal.proposed_params_json["assessment_loop"]["context_document_id"] == str(child_context.id)
        assert proposal.proposed_params_json["assessment_loop"]["rationale_ledger_entry_id"] == str(rationale.id)
