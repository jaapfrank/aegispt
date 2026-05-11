from __future__ import annotations

from uuid import UUID

from sqlalchemy import select

from api.app.models import (
    Engagement,
    InventorySnapshot,
    Run,
    RunProfile,
    Scope,
    TargetContextDocument,
)
from api.app.services.ai_action_selector import (
    rank_next_best_actions,
    select_next_best_action_for_run,
)
from api.app.services.assessment_graph import build_assessment_graph
from api.app.services.assessment_loop import advance_assessment_loop
from api.app.services.runner_contracts import RunnerContractError


def _create_selector_run(
    client,
    *,
    inventory: dict,
    context_tools: list[str],
    context_endpoints: list[str],
) -> str:
    profiles_response = client.get("/api/v1/run-profiles")
    assert profiles_response.status_code == 200
    with client.app.state.session_factory() as session:
        profile = session.scalar(select(RunProfile).where(RunProfile.name == "autonomous-web"))
        assert profile is not None
        engagement = Engagement(
            name="Next Best Action Validation",
            client="Acme Corp",
            roe_ref="ROE-NBA-2026",
            status="active",
        )
        Scope(
            engagement=engagement,
            allowlist_json={"urls": ["https://selector.example.test"]},
            denylist_json={},
        )
        snapshot = InventorySnapshot(
            engagement=engagement,
            requested_by="selector-tester",
            status="completed",
            source_tools_json=["httpx"],
            raw_inputs_json={},
            normalized_inventory_json=inventory,
            summary_json={"url_count": 1, "endpoint_count": len(context_endpoints)},
            confidence_score=0.88,
        )
        run = Run(
            engagement=engagement,
            profile=profile,
            source_inventory_snapshot=snapshot,
            requested_by="selector-tester",
            status="requested",
            autonomous_mode=True,
            autonomous_intrusive_allowed=False,
            configuration_json={
                "targets": {"urls": ["https://selector.example.test"]},
                "run_mode": "ai_loop",
            },
        )
        session.add_all([engagement, snapshot, run])
        session.flush()
        if context_tools or context_endpoints:
            context = TargetContextDocument(
                run=run,
                layer_name="phase_0_contextual_profile",
                context_kind="phase_0_contextual_profile",
                status="recorded",
                source_targets_json=[{"kind": "url", "value": "https://selector.example.test"}],
                technologies_detected_json=["graphql"] if "graphql-probe" in context_tools else ["php", "mysql"],
                endpoints_discovered_json=context_endpoints,
                recommended_tools_json=context_tools,
                micro_plan_json=[
                    {
                        "order": index,
                        "tool": tool,
                        "target_candidates": context_endpoints,
                        "reason": f"{tool} was recommended from stored evidence.",
                    }
                    for index, tool in enumerate(context_tools, start=1)
                ],
                evidence_refs_json=[{"type": "inventory_snapshot", "id": str(snapshot.id)}],
                context_summary="Stored evidence for next-best-action selector validation.",
                provenance_json={"live_target_actions_performed": False},
            )
            session.add(context)
        session.commit()
        return str(run.id)


def test_selector_ranks_graphql_probe_above_unrelated_runners(client) -> None:
    run_id = _create_selector_run(
        client,
        inventory={
            "targets": ["https://selector.example.test"],
            "tech_stack_profile": {
                "graphql_present": True,
                "graphql_endpoints": ["https://selector.example.test/graphql"],
            },
            "signal_profile": {"signals": [{"key": "graphql_endpoint", "value": True}]},
        },
        context_tools=["graphql-probe", "sqlmap"],
        context_endpoints=["https://selector.example.test/graphql"],
    )

    with client.app.state.session_factory() as session:
        run = session.get(Run, UUID(run_id))
        assert run is not None
        graph = build_assessment_graph(session, run=run)
        report = rank_next_best_actions(
            graph,
            approved_targets=[{"kind": "url", "value": "https://selector.example.test/graphql"}],
            tested_action_keys=set(),
        )

    top_action = report["actions"][0]
    assert top_action["runner"] == "graphql-probe"
    assert top_action["decision"] == "APPROVAL"
    assert top_action["approval_required"] is True
    assert top_action["source_ids"]
    assert top_action["prerequisite_state"]["missing"] == []
    assert top_action["expected_proof_value"] > 0
    assert "graphql_endpoint" in top_action["matched_triggers"]
    assert top_action["approval_reason_ids"]
    assert top_action["runner_contract"]["validation"]["valid"] is True
    assert top_action["runner_contract"]["report_mapping"]
    assert top_action["provenance"]["dispatches_work"] is False


def test_selector_marks_sqlmap_wait_without_concrete_parameter_evidence(client) -> None:
    run_id = _create_selector_run(
        client,
        inventory={
            "targets": ["https://selector.example.test"],
            "tech_stack_profile": {"language": ["php"], "database": ["mysql"]},
            "signal_profile": {"signals": [{"key": "form_with_post_action", "value": True}]},
        },
        context_tools=["sqlmap"],
        context_endpoints=["https://selector.example.test/login"],
    )

    with client.app.state.session_factory() as session:
        run = session.get(Run, UUID(run_id))
        assert run is not None
        scope = run.engagement.scopes[-1]
        report = select_next_best_action_for_run(
            session,
            run=run,
            scope=scope,
            approved_targets=[{"kind": "url", "value": "https://selector.example.test/login"}],
            tested_action_keys=set(),
        )

    sqlmap_action = next(action for action in report["actions"] if action["runner"] == "sqlmap")
    assert sqlmap_action["decision"] == "WAIT"
    assert sqlmap_action["prerequisite_state"]["missing"] == [
        "concrete_parameter_or_error_evidence"
    ]
    assert "missing prerequisite: concrete_parameter_or_error_evidence" in sqlmap_action["blocker_reasons"]
    assert "missing_prerequisite:concrete_parameter_or_error_evidence" in sqlmap_action["blocker_reason_ids"]
    assert sqlmap_action["runner_contract"]["contract_id"] == "sqlmap:adaptive-contract:v1"
    assert sqlmap_action["provenance"]["dispatches_work"] is False


def test_assessment_loop_uses_selector_for_initial_seed_action(client) -> None:
    run_id = _create_selector_run(
        client,
        inventory={
            "targets": ["https://selector.example.test"],
            "tech_stack_profile": {},
            "signal_profile": {"signals": [{"key": "web_target_present", "value": True}]},
        },
        context_tools=[],
        context_endpoints=[],
    )

    with client.app.state.session_factory() as session:
        run = session.get(Run, UUID(run_id))
        assert run is not None
        scope = run.engagement.scopes[-1]
        payload = advance_assessment_loop(
            session,
            run=run,
            scope=scope,
            actor="selector-tester",
            operator_note="Use graph evidence and selector ranking.",
        )
        session.commit()

    assert payload["next_action"]["decision_source"] == "next_best_action_selector"
    assert payload["next_action"]["tool"] == "httpx"
    assert payload["next_action"]["selector_decision"] == "RUN"
    assert payload["queued_task_id"]
    assert payload["proposal_id"]
    assert payload["status"] == "waiting_for_execution"
    assert payload["latest_next_action"]["params"]["next_best_action_selector"]["rank"] == 1


def test_selector_skips_contract_valid_runner_when_no_trigger_matches() -> None:
    graph = {
        "graph_version": "test",
        "run_id": "run-skip",
        "nodes": [
            {
                "id": "scope-1",
                "kind": "scope",
                "source_id": "scope-1",
                "label": "Approved scope",
                "data": {"allowlist": ["https://selector.example.test/"]},
            },
            {
                "id": "runner-graphql-probe",
                "kind": "runner_metadata",
                "source_id": "graphql-probe",
                "label": "graphql-probe",
                "data": {"registered": True},
            },
        ],
        "edges": [],
    }

    report = rank_next_best_actions(
        graph,
        approved_targets=[{"kind": "url", "value": "https://selector.example.test/"}],
        tested_action_keys=set(),
    )

    action = report["actions"][0]
    assert action["runner"] == "graphql-probe"
    assert action["decision"] == "SKIP"
    assert "no_matching_trigger" in action["blocker_reason_ids"]
    assert action["runner_contract"]["validation"]["valid"] is True


def test_selector_blocks_runner_when_contract_data_is_missing(monkeypatch) -> None:
    def missing_contract(runner: str):
        raise RunnerContractError(f"runner contract for {runner} is missing")

    monkeypatch.setattr("api.app.services.ai_action_selector.runner_contract_for", missing_contract)
    graph = {
        "graph_version": "test",
        "run_id": "run-contract-blocked",
        "nodes": [
            {
                "id": "runner-httpx",
                "kind": "runner_metadata",
                "source_id": "httpx",
                "label": "httpx",
                "data": {"registered": True},
            }
        ],
        "edges": [],
    }

    report = rank_next_best_actions(
        graph,
        approved_targets=[{"kind": "url", "value": "https://selector.example.test/"}],
        tested_action_keys=set(),
    )

    action = report["actions"][0]
    assert action["runner"] == "httpx"
    assert action["decision"] == "WAIT"
    assert action["expected_proof_value"] == 0.0
    assert action["runner_contract"]["validation"]["valid"] is False
    assert "missing_runner_contract" in action["blocker_reason_ids"]
    assert "missing runner contract data" in action["blocker_reasons"][0]
