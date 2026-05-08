from __future__ import annotations

from uuid import UUID

from sqlalchemy import select

from api.app.models import AgentProposal, AuditEvent, InventorySnapshot, Run, RunProfile, Task


def _create_engagement_and_scope(client, allowlist: dict) -> str:
    response = client.post(
        "/api/v1/engagements",
        headers={"X-Actor": "loop-tester"},
        json={
            "name": "AI Loop Validation",
            "client": "Acme Corp",
            "roe_ref": "ROE-LOOP-2026",
        },
    )
    assert response.status_code == 201
    engagement_id = response.json()["id"]
    scope_response = client.post(
        f"/api/v1/engagements/{engagement_id}/scope",
        headers={"X-Actor": "loop-tester"},
        json={"allowlist_json": allowlist, "denylist_json": {}},
    )
    assert scope_response.status_code == 201
    return engagement_id


def _create_loop_run(
    client,
    engagement_id: str,
    *,
    profile_name: str = "autonomous-web",
    targets: dict | None = None,
    snapshot_id: str | None = None,
    configuration: dict | None = None,
) -> str:
    profiles_response = client.get("/api/v1/run-profiles")
    assert profiles_response.status_code == 200
    with client.app.state.session_factory() as session:
        profile = session.scalar(select(RunProfile).where(RunProfile.name == profile_name))
        assert profile is not None
        run = Run(
            engagement_id=UUID(engagement_id),
            profile_id=profile.id,
            source_inventory_snapshot_id=UUID(snapshot_id) if snapshot_id else None,
            requested_by="loop-tester",
            status="requested",
            autonomous_mode=True,
            autonomous_intrusive_allowed=False,
            configuration_json={
                "targets": targets or {},
                "run_mode": "ai_loop",
                **(configuration or {}),
            },
        )
        session.add(run)
        session.commit()
        return str(run.id)


def _create_snapshot(client, engagement_id: str, *, signals: list[dict]) -> str:
    with client.app.state.session_factory() as session:
        snapshot = InventorySnapshot(
            engagement_id=UUID(engagement_id),
            requested_by="loop-tester",
            status="completed",
            source_tools_json=["httpx"],
            raw_inputs_json={},
            normalized_inventory_json={
                "targets": ["https://loop.example.test"],
                "signal_profile": {"signals": signals},
                "tech_stack_profile": {},
            },
            summary_json={"url_count": 1, "service_count": 1},
            confidence_score=0.86,
        )
        session.add(snapshot)
        session.commit()
        return str(snapshot.id)


def test_assessment_loop_url_seed_queues_passive_next_action_with_required_shape(client) -> None:
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
        headers={"X-Actor": "loop-tester"},
        json={"operator_note": "Start loop from URL scope."},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["run_mode"] == "ai_loop"
    assert payload["manual_chain_alternative_preserved"] is True
    assert payload["fixed_phase_chains_replaced_globally"] is False
    assert payload["status"] == "waiting_for_execution"
    assert payload["iteration_count"] == 1
    next_action = payload["next_action"]
    assert {
        "tool",
        "target",
        "params",
        "tier",
        "reasoning",
        "confidence",
        "follow_up_hints",
    }.issubset(next_action)
    assert next_action["tool"] == "httpx"
    assert next_action["target"] == "https://loop.example.test"
    assert next_action["tier"] == "passive"
    assert payload["queued_task_id"]
    assert payload["proposal_id"]
    assert payload["reasoning_id"]

    with client.app.state.session_factory() as session:
        task = session.get(Task, UUID(payload["queued_task_id"]))
        assert task is not None
        assert task.status == "queued"
        assert task.tool == "httpx"
        assert task.params_json["assessment_loop"]["iteration"] == 1
        assert task.params_json["assessment_loop"]["dispatch_mode"] == "queued_not_dispatched"
        proposal = session.get(AgentProposal, UUID(payload["proposal_id"]))
        assert proposal is not None
        assert proposal.status == "approved"
        assert proposal.metadata_json["proposal_kind"] == "assessment_loop_next_action"
        assert proposal.metadata_json["queued_task_id"] == str(task.id)


def test_assessment_loop_goal_records_bounded_hypothesis_without_dispatch(client) -> None:
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
        f"/api/v1/runs/{run_id}/assessment-loop/goal",
        headers={"X-Actor": "loop-tester"},
        json={
            "objective": "Access the billing database using controlled proof only",
            "operator_note": "CTF objective inside the approved lab scope.",
        },
    )

    assert response.status_code == 200
    payload = response.json()
    goal = payload["goal_oriented_reasoning"]
    assert goal["objective"] == "Access the billing database using controlled proof only"
    assert goal["objective_type"] == "data_access_objective"
    assert goal["dispatches_work_directly"] is False
    assert goal["registered_runner_required"] is True
    assert goal["scope_enforced"] is True
    assert goal["approval_gates_bypassed"] is False
    assert goal["reasoning_id"]
    path = goal["hypothesis_path"]
    assert path
    assert path[0]["tool"] == "httpx"
    assert path[0]["dispatches_work"] is False
    assert path[0]["evidence_links"]
    assert all(step["registered_runner_required"] is True for step in path)
    assert all(step["scope_enforced"] is True for step in path)
    assert "exploit" not in " ".join(step["reason"].lower() for step in path)

    with client.app.state.session_factory() as session:
        tasks = session.scalars(select(Task).where(Task.run_id == UUID(run_id))).all()
        assert tasks == []
        run = session.get(Run, UUID(run_id))
        assert run is not None
        stored_goal = run.configuration_json["ai_assessment_loop"]["goal_oriented_reasoning"]
        assert stored_goal["objective_type"] == "data_access_objective"


def test_assessment_loop_goal_is_gated_to_ai_loop_runs(client) -> None:
    engagement_id = _create_engagement_and_scope(
        client,
        {"urls": ["https://loop.example.test"]},
    )
    run_id = _create_loop_run(
        client,
        engagement_id,
        targets={"urls": ["https://loop.example.test"]},
        configuration={"run_mode": "manual"},
    )

    response = client.post(
        f"/api/v1/runs/{run_id}/assessment-loop/goal",
        headers={"X-Actor": "loop-tester"},
        json={"objective": "Access the billing database using controlled proof only"},
    )

    assert response.status_code == 409
    assert "run_mode=ai_loop" in response.json()["detail"]


def test_assessment_loop_goal_drives_next_action_through_existing_rationale_path(client) -> None:
    engagement_id = _create_engagement_and_scope(
        client,
        {"urls": ["https://loop.example.test"]},
    )
    run_id = _create_loop_run(
        client,
        engagement_id,
        targets={"urls": ["https://loop.example.test"]},
    )
    goal_response = client.post(
        f"/api/v1/runs/{run_id}/assessment-loop/goal",
        headers={"X-Actor": "loop-tester"},
        json={"objective": "Access the billing database using controlled proof only"},
    )
    assert goal_response.status_code == 200

    response = client.post(
        f"/api/v1/runs/{run_id}/assessment-loop/iterate",
        headers={"X-Actor": "loop-tester"},
        json={"operator_note": "Follow the stored objective path."},
    )

    assert response.status_code == 200
    payload = response.json()
    next_action = payload["next_action"]
    assert next_action["decision_source"] == "goal_oriented_reasoning"
    assert next_action["params"]["source"] == "goal_oriented_reasoning"
    assert next_action["params"]["goal_oriented_reasoning"]["objective_type"] == "data_access_objective"
    assert next_action["params"]["goal_oriented_reasoning"]["evidence_links"]
    assert payload["queued_task_id"]
    assert payload["rationale_ledger_entry_id"]

    with client.app.state.session_factory() as session:
        task = session.get(Task, UUID(payload["queued_task_id"]))
        assert task is not None
        assert task.tool == "httpx"
        goal_meta = task.params_json["goal_oriented_reasoning"]
        assert goal_meta["hypothesis_step_id"] == "goal-step-1-httpx"
        proposal = session.get(AgentProposal, UUID(payload["proposal_id"]))
        assert proposal is not None
        assert proposal.metadata_json["proposal_kind"] == "assessment_loop_next_action"


def test_assessment_loop_active_action_creates_reviewable_proposal_not_task(client) -> None:
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
        run = session.get(Run, UUID(run_id))
        assert run is not None
        session.add(
            Task(
                run_id=run.id,
                tool="httpx",
                target_id="https://loop.example.test",
                status="completed",
                params_json={"assessment_loop": {"iteration": 1}},
            )
        )
        session.commit()

    response = client.post(
        f"/api/v1/runs/{run_id}/assessment-loop/iterate",
        headers={"X-Actor": "loop-tester"},
        json={},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "waiting_for_approval"
    assert payload["queued_task_id"] is None
    assert payload["proposal_id"]
    next_action = payload["next_action"]
    assert next_action["tool"] == "auth-flow"
    assert next_action["tier"] == "active"
    assert next_action["required_approvals"] == 1

    with client.app.state.session_factory() as session:
        proposal = session.get(AgentProposal, UUID(payload["proposal_id"]))
        assert proposal is not None
        assert proposal.status == "pending_review"
        assert proposal.metadata_json["proposal_kind"] == "assessment_loop_next_action"
        assert proposal.metadata_json["dispatches_work"] is False
        auth_task = session.scalar(
            select(Task).where(Task.run_id == UUID(run_id), Task.tool == "auth-flow")
        )
        assert auth_task is None


def test_assessment_loop_cidr_seed_uses_nmap_without_fixed_phase_chain(client) -> None:
    engagement_id = _create_engagement_and_scope(client, {"cidr_ranges": ["10.10.10.0/24"]})
    run_id = _create_loop_run(
        client,
        engagement_id,
        profile_name="autonomous-internal",
        targets={"cidr_ranges": ["10.10.10.0/24"]},
    )

    response = client.post(
        f"/api/v1/runs/{run_id}/assessment-loop/iterate",
        headers={"X-Actor": "loop-tester"},
        json={},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["current_state"]["target_type"] == "cidr"
    assert payload["next_action"]["tool"] == "nmap"
    assert payload["next_action"]["target"] == "10.10.10.0/24"
    assert payload["fixed_phase_chains_replaced_globally"] is False


def test_assessment_loop_stuck_detection_stops_after_three_no_signal_iterations(client) -> None:
    engagement_id = _create_engagement_and_scope(client, {"urls": ["https://loop.example.test"]})
    run_id = _create_loop_run(
        client,
        engagement_id,
        targets={"urls": ["https://loop.example.test"]},
    )
    current = client.get(
        f"/api/v1/runs/{run_id}/assessment-loop",
        headers={"X-Actor": "loop-tester"},
    ).json()
    fingerprint = current["current_state"]["evidence_fingerprint"]
    with client.app.state.session_factory() as session:
        run = session.get(Run, UUID(run_id))
        assert run is not None
        run.configuration_json = {
            **dict(run.configuration_json or {}),
            "ai_assessment_loop": {
                "enabled": True,
                "version": "test",
                "iteration_count": 2,
                "max_iterations": 20,
                "stuck_threshold": 3,
                "no_new_signal_iterations": 2,
                "latest_evidence_fingerprint": fingerprint,
                "iterations": [
                    {"iteration": 1, "next_action": {"tool": "httpx", "target": "https://loop.example.test"}},
                    {"iteration": 2, "next_action": {"tool": "headers-security", "target": "https://loop.example.test"}},
                ],
            },
        }
        session.commit()

    response = client.post(
        f"/api/v1/runs/{run_id}/assessment-loop/iterate",
        headers={"X-Actor": "loop-tester"},
        json={},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "stopped"
    assert payload["stop_reason"] == "stuck_no_new_signals"
    assert payload["no_new_signal_iterations"] == 3
    assert payload["next_action"] is None

    with client.app.state.session_factory() as session:
        audit = session.scalar(
            select(AuditEvent).where(
                AuditEvent.object_id == run_id,
                AuditEvent.action == "assessment_loop.stopped",
            )
        )
        assert audit is not None
        assert audit.metadata_json["reason"] == "stuck_no_new_signals"


def test_assessment_loop_enforces_max_twenty_iterations(client) -> None:
    engagement_id = _create_engagement_and_scope(client, {"domains": ["example.test"]})
    run_id = _create_loop_run(
        client,
        engagement_id,
        targets={"domains": ["example.test"]},
        configuration={
            "ai_assessment_loop": {
                "enabled": True,
                "version": "test",
                "iteration_count": 20,
                "max_iterations": 20,
                "stuck_threshold": 3,
                "iterations": [{"iteration": index + 1} for index in range(20)],
            },
        },
    )

    response = client.post(
        f"/api/v1/runs/{run_id}/assessment-loop/iterate",
        headers={"X-Actor": "loop-tester"},
        json={},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "stopped"
    assert payload["stop_reason"] == "max_iterations_reached"
    assert payload["iteration_count"] == 20
