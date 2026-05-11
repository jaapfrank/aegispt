from __future__ import annotations

from uuid import UUID

from sqlalchemy import select

from api.app.models import InventorySnapshot, Run, RunProfile, TargetContextDocument


def _create_engagement_and_scope(client, allowlist: dict) -> str:
    response = client.post(
        "/api/v1/engagements",
        headers={"X-Actor": "workbench-tester"},
        json={
            "name": "Operator Workbench Validation",
            "client": "Acme Corp",
            "roe_ref": "ROE-WORKBENCH-2026",
        },
    )
    assert response.status_code == 201
    engagement_id = response.json()["id"]
    scope_response = client.post(
        f"/api/v1/engagements/{engagement_id}/scope",
        headers={"X-Actor": "workbench-tester"},
        json={"allowlist_json": allowlist, "denylist_json": {}},
    )
    assert scope_response.status_code == 201
    return engagement_id


def _create_workbench_run(
    client,
    engagement_id: str,
    *,
    run_mode: str,
) -> str:
    profiles_response = client.get("/api/v1/run-profiles")
    assert profiles_response.status_code == 200
    with client.app.state.session_factory() as session:
        profile = session.scalar(select(RunProfile).where(RunProfile.name == "autonomous-web"))
        assert profile is not None
        snapshot = InventorySnapshot(
            engagement_id=UUID(engagement_id),
            requested_by="workbench-tester",
            status="completed",
            source_tools_json=["httpx"],
            raw_inputs_json={},
            normalized_inventory_json={
                "targets": ["https://workbench.example.test"],
                "tech_stack_profile": {"graphql_present": True},
                "signal_profile": {"signals": [{"key": "graphql_endpoint", "value": True}]},
            },
            summary_json={"url_count": 1},
            confidence_score=0.88,
        )
        run = Run(
            engagement_id=UUID(engagement_id),
            profile=profile,
            source_inventory_snapshot=snapshot,
            requested_by="workbench-tester",
            status="requested",
            autonomous_mode=True,
            autonomous_intrusive_allowed=False,
            configuration_json={
                "targets": {"urls": ["https://workbench.example.test"]},
                "run_mode": run_mode,
            },
        )
        session.add_all([snapshot, run])
        session.flush()
        context = TargetContextDocument(
            run=run,
            layer_name="phase_0_contextual_profile",
            context_kind="phase_0_contextual_profile",
            status="recorded",
            source_targets_json=[{"kind": "url", "value": "https://workbench.example.test"}],
            technologies_detected_json=["graphql"],
            endpoints_discovered_json=["https://workbench.example.test/graphql"],
            recommended_tools_json=["graphql-probe", "session-security"],
            micro_plan_json=[
                {
                    "order": 1,
                    "tool": "graphql-probe",
                    "target_candidates": ["https://workbench.example.test/graphql"],
                    "reason": "GraphQL endpoint evidence is present.",
                }
            ],
            evidence_refs_json=[{"type": "inventory_snapshot", "id": str(snapshot.id)}],
            context_summary="Stored evidence for operator autopilot workbench validation.",
            provenance_json={"live_target_actions_performed": False},
        )
        session.add(context)
        session.commit()
        return str(run.id)


def test_ai_loop_insights_include_autopilot_workbench_cards(client) -> None:
    engagement_id = _create_engagement_and_scope(
        client,
        {"urls": ["https://workbench.example.test", "https://workbench.example.test/graphql"]},
    )
    run_id = _create_workbench_run(client, engagement_id, run_mode="ai_loop")

    goal_response = client.post(
        f"/api/v1/runs/{run_id}/assessment-loop/goal",
        headers={"X-Actor": "workbench-tester"},
        json={
            "objective": "Review session exposure risk with controlled proof and canary evidence",
            "operator_note": "Keep all work inside the approved lab scope.",
        },
    )
    assert goal_response.status_code == 200

    response = client.get(f"/api/v1/runs/{run_id}/ai-insights", headers={"X-Actor": "workbench-tester"})

    assert response.status_code == 200
    payload = response.json()
    ai_loop = payload["operator_workbench"]["ai_loop"]
    assert ai_loop["enabled"] is True
    assert ai_loop["run_mode"] == "ai_loop"
    assert ai_loop["current_goal"]["objective"] == (
        "Review session exposure risk with controlled proof and canary evidence"
    )
    assert ai_loop["hypotheses"]["hypotheses"]
    assert ai_loop["next_best_actions"]["actions"]
    assert ai_loop["coverage_truth"]["summary"]["total_task_count"] == 0
    assert "controlled_proof" in ai_loop["operator_language"]
    assert "canary_evidence" in ai_loop["operator_language"]
    assert "session_exposure_risk" in ai_loop["operator_language"]
    assert ai_loop["execution_contract"]["dispatches_work_directly"] is False
    assert ai_loop["execution_contract"]["proposal_controls_use_existing_review_endpoint"] is True


def test_autopilot_workbench_is_gated_off_for_manual_run(client) -> None:
    engagement_id = _create_engagement_and_scope(
        client,
        {"urls": ["https://workbench.example.test"]},
    )
    run_id = _create_workbench_run(client, engagement_id, run_mode="manual")

    response = client.get(f"/api/v1/runs/{run_id}/ai-insights", headers={"X-Actor": "workbench-tester"})

    assert response.status_code == 200
    ai_loop = response.json()["operator_workbench"]["ai_loop"]
    assert ai_loop["enabled"] is False
    assert "run_mode=ai_loop" in ai_loop["reason"]
