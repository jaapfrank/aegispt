from __future__ import annotations

from uuid import UUID

from sqlalchemy import select

from api.app.models import (
    AgentProposal,
    Approval,
    AuditEvent,
    Finding,
    InventorySnapshot,
    Run,
    Task,
)
from api.app.services.runs import approval_step_id


def _create_engagement_and_scope(client) -> str:
    response = client.post(
        "/api/v1/engagements",
        headers={"X-Actor": "planner-tester"},
        json={
            "name": "Adaptive Planner Validation",
            "client": "Acme Corp",
            "roe_ref": "ROE-PLANNER-2026",
        },
    )
    assert response.status_code == 201
    engagement_id = response.json()["id"]
    scope_response = client.post(
        f"/api/v1/engagements/{engagement_id}/scope",
        headers={"X-Actor": "planner-tester"},
        json={
            "allowlist_json": {"urls": ["https://portal.example.test"]},
            "denylist_json": {},
        },
    )
    assert scope_response.status_code == 201
    return engagement_id


def _create_inventory_snapshot(client, engagement_id: str, *, signals: list[dict], stack: dict) -> str:
    session_factory = client.app.state.session_factory
    with session_factory() as session:
        snapshot = InventorySnapshot(
            engagement_id=UUID(engagement_id),
            requested_by="planner-tester",
            status="completed",
            source_tools_json=["httpx"],
            raw_inputs_json={},
            normalized_inventory_json={
                "targets": ["https://portal.example.test"],
                "signal_profile": {"signals": signals},
                "tech_stack_profile": stack,
            },
            summary_json={"url_count": 1, "service_count": 1},
            confidence_score=0.86,
        )
        session.add(snapshot)
        session.commit()
        return str(snapshot.id)


def _create_active_api_run(client, engagement_id: str, snapshot_id: str) -> dict:
    response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "planner-tester"},
        json={
            "profile_name": "active-api-assessment",
            "source_inventory_snapshot_id": snapshot_id,
            "configuration_json": {"targets": {"urls": ["https://portal.example.test"]}},
        },
    )
    assert response.status_code == 201
    return response.json()


def _grant_run_approval(client, run_id: str) -> None:
    session_factory = client.app.state.session_factory
    with session_factory() as session:
        run = session.scalar(select(Run).where(Run.id == UUID(run_id)))
        assert run is not None
        assert run.profile is not None
        session.add(
            Approval(
                run_id=run.id,
                step_id=approval_step_id(run.profile),
                approver_id="planner-tester",
                decision="approved",
            )
        )
        run.status = "requested"
        session.commit()


def _runner(plan: dict, name: str) -> dict:
    return next(item for item in plan["runners"] if item["runner"] == name)


def test_assessment_plan_scores_runner_decisions_from_signal_profile(client) -> None:
    engagement_id = _create_engagement_and_scope(client)
    snapshot_id = _create_inventory_snapshot(
        client,
        engagement_id,
        signals=[],
        stack={
            "language": ["php"],
            "cms": ["wordpress"],
            "server": ["nginx"],
            "jwt_present": False,
            "java_present": False,
            "login_forms": [{"url": "https://portal.example.test/login"}],
        },
    )
    run = _create_active_api_run(client, engagement_id, snapshot_id)

    response = client.get(
        f"/api/v1/runs/{run['id']}/assessment-plan",
        headers={"X-Actor": "planner-tester"},
    )

    assert response.status_code == 200
    plan = response.json()
    assert plan["operator_review_required"] is True
    assert plan["dispatches_work"] is False
    assert _runner(plan, "sqlmap")["decision"] == "WAIT"
    assert "not enough without injectable parameter" in _runner(plan, "sqlmap")["summary"]
    assert _runner(plan, "jwt-probe")["decision"] == "SKIP"
    assert _runner(plan, "deserialization-probe")["decision"] == "SKIP"
    assert _runner(plan, "metasploit")["decision"] == "NEEDS_APPROVAL"


def test_assessment_plan_queue_uses_only_operator_approved_run_items(client) -> None:
    engagement_id = _create_engagement_and_scope(client)
    snapshot_id = _create_inventory_snapshot(
        client,
        engagement_id,
        signals=[{"key": "jwt_in_response", "value": True, "confidence": 0.9}],
        stack={
            "language": ["node"],
            "server": ["nginx"],
            "jwt_present": True,
            "graphql_present": False,
        },
    )
    run = _create_active_api_run(client, engagement_id, snapshot_id)
    _grant_run_approval(client, run["id"])

    response = client.post(
        f"/api/v1/runs/{run['id']}/assessment-plan/queue",
        headers={"X-Actor": "planner-tester"},
        json={
            "approved_runners": ["jwt-probe", "sqlmap"],
            "allow_wait_overrides": False,
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["run"]["status"] == "queued"
    assert [task["tool"] for task in payload["run"]["tasks"]] == ["jwt-probe"]
    assert len(payload["queued_task_ids"]) == 1
    assert any(item["runner"] == "sqlmap" and "WAIT" in item["reason"] for item in payload["blocked"])

    session_factory = client.app.state.session_factory
    with session_factory() as session:
        audit = session.scalar(
            select(AuditEvent).where(
                AuditEvent.object_id == run["id"],
                AuditEvent.action == "assessment_plan.queued",
            )
        )
        assert audit is not None
        assert audit.metadata_json["queued_runners"] == ["jwt-probe"]


def test_adaptive_wave_completion_updates_signals_and_proposes_promoted_wait_runner(client) -> None:
    engagement_id = _create_engagement_and_scope(client)
    snapshot_id = _create_inventory_snapshot(
        client,
        engagement_id,
        signals=[],
        stack={
            "language": ["php"],
            "cms": ["wordpress"],
            "server": ["nginx"],
            "jwt_present": False,
            "java_present": False,
            "login_forms": [{"url": "https://portal.example.test/login"}],
        },
    )
    run = _create_active_api_run(client, engagement_id, snapshot_id)

    initial_plan = client.get(
        f"/api/v1/runs/{run['id']}/assessment-plan",
        headers={"X-Actor": "planner-tester"},
    ).json()
    assert _runner(initial_plan, "sqlmap")["decision"] == "WAIT"
    assert _runner(initial_plan, "jwt-probe")["decision"] == "SKIP"

    _grant_run_approval(client, run["id"])
    queue_response = client.post(
        f"/api/v1/runs/{run['id']}/assessment-plan/queue",
        headers={"X-Actor": "planner-tester"},
        json={
            "approved_runners": ["headers-security"],
            "allow_wait_overrides": False,
        },
    )
    assert queue_response.status_code == 200
    assert queue_response.json()["queued_task_ids"]

    session_factory = client.app.state.session_factory
    with session_factory() as session:
        db_run = session.scalar(select(Run).where(Run.id == UUID(run["id"])))
        assert db_run is not None
        queued_task = session.scalar(select(Task).where(Task.run_id == db_run.id))
        assert queued_task is not None
        queued_task.status = "completed"
        db_run.status = "completed"
        session.add(
            Finding(
                run_id=db_run.id,
                source_inventory_snapshot_id=UUID(snapshot_id),
                title="Reflected input field on search form",
                severity="medium",
                target_id="https://portal.example.test",
                evidence_ref="artifact://xss/reflected-search",
                status="open",
                summary=(
                    "A reflected text field echoed the search parameter in the response. "
                    "This is evidence for a concrete parameter candidate."
                ),
                methodology_tags=["reflected parameter", "form input"],
            )
        )
        session.commit()

    complete_response = client.post(
        f"/api/v1/runs/{run['id']}/assessment-plan/waves/complete",
        headers={"X-Actor": "planner-tester"},
        json={"operator_note": "Wave 1 evidence reviewed."},
    )
    assert complete_response.status_code == 200
    payload = complete_response.json()
    wave_state = payload["adaptive_execution_waves"]
    assert wave_state["dispatches_work"] is False
    assert wave_state["operator_approval_required"] is True
    assert len(wave_state["waves"]) == 1
    assert wave_state["waves"][0]["wave_number"] == 1
    assert "sqlmap" in wave_state["waves"][0]["promoted_runners"]
    assert wave_state["waves"][0]["persisted_skip_count"] >= 1
    assert payload["run"]["source_inventory_snapshot_id"] != snapshot_id
    assert _runner(payload["assessment_plan"], "sqlmap")["decision"] == "RUN"
    assert _runner(payload["assessment_plan"], "jwt-probe")["decision"] == "SKIP"

    with session_factory() as session:
        proposals = session.scalars(
            select(AgentProposal).where(
                AgentProposal.run_id == UUID(run["id"]),
                AgentProposal.proposed_tool == "sqlmap",
            )
        ).all()
        assert len(proposals) == 1
        proposal = proposals[0]
        assert proposal.status == "pending_review"
        assert proposal.metadata_json["proposal_kind"] == "adaptive_execution_wave"
        assert proposal.metadata_json["dispatches_work"] is False
        assert proposal.metadata_json["requires_operator_review"] is True
        sqlmap_task = session.scalar(
            select(Task).where(Task.run_id == UUID(run["id"]), Task.tool == "sqlmap")
        )
        assert sqlmap_task is None
        proposal_id = str(proposal.id)

    review_response = client.post(
        f"/api/v1/runs/{run['id']}/ai-proposals/{proposal_id}/review",
        headers={"X-Actor": "planner-reviewer"},
        json={"decision": "approved", "note": "Operator approves the next wave proposal."},
    )
    assert review_response.status_code == 200
    assert review_response.json()["metadata_json"]["dispatches_work"] is True

    with session_factory() as session:
        sqlmap_task = session.scalar(
            select(Task).where(Task.run_id == UUID(run["id"]), Task.tool == "sqlmap")
        )
        assert sqlmap_task is not None
        assert sqlmap_task.status == "queued"
        assert sqlmap_task.params_json["ai_proposal"]["dispatch_mode"] == "queued_not_dispatched"


def test_adaptive_wave_completion_enforces_max_five_waves(client) -> None:
    engagement_id = _create_engagement_and_scope(client)
    snapshot_id = _create_inventory_snapshot(
        client,
        engagement_id,
        signals=[],
        stack={"server": ["nginx"]},
    )
    run = _create_active_api_run(client, engagement_id, snapshot_id)

    with client.app.state.session_factory() as session:
        db_run = session.scalar(select(Run).where(Run.id == UUID(run["id"])))
        assert db_run is not None
        db_run.configuration_json = {
            **dict(db_run.configuration_json or {}),
            "adaptive_execution_waves": {
                "enabled": True,
                "version": "test",
                "max_waves": 5,
                "operator_approval_required": True,
                "dispatches_work": False,
                "waves": [{"wave_number": index + 1, "status": "completed"} for index in range(5)],
                "last_plan_decisions": {},
                "latest_plan_summary": {},
            },
        }
        session.commit()

    response = client.post(
        f"/api/v1/runs/{run['id']}/assessment-plan/waves/complete",
        headers={"X-Actor": "planner-tester"},
        json={},
    )

    assert response.status_code == 409
    assert "capped at 5" in response.json()["detail"]


def test_adaptive_wave_completion_creates_review_only_compound_chain_proposal(client) -> None:
    engagement_id = _create_engagement_and_scope(client)
    snapshot_id = _create_inventory_snapshot(
        client,
        engagement_id,
        signals=[],
        stack={"server": ["nginx"]},
    )
    run = _create_active_api_run(client, engagement_id, snapshot_id)
    _grant_run_approval(client, run["id"])
    queue_response = client.post(
        f"/api/v1/runs/{run['id']}/assessment-plan/queue",
        headers={"X-Actor": "planner-tester"},
        json={
            "approved_runners": ["headers-security"],
            "allow_wait_overrides": False,
        },
    )
    assert queue_response.status_code == 200

    session_factory = client.app.state.session_factory
    with session_factory() as session:
        db_run = session.scalar(select(Run).where(Run.id == UUID(run["id"])))
        assert db_run is not None
        queued_task = session.scalar(select(Task).where(Task.run_id == db_run.id))
        assert queued_task is not None
        queued_task.status = "completed"
        db_run.status = "completed"
        session.add_all(
            [
                Finding(
                    run_id=db_run.id,
                    source_inventory_snapshot_id=UUID(snapshot_id),
                    title="Unrestricted file upload endpoint",
                    severity="high",
                    target_id="https://portal.example.test",
                    evidence_ref="artifact://web/upload-endpoint",
                    status="open",
                    summary="The scoped application exposes a file upload endpoint.",
                    methodology_tags=["file upload", "unrestricted file upload"],
                    wstg_id="WSTG-BUSL-09",
                ),
                Finding(
                    run_id=db_run.id,
                    source_inventory_snapshot_id=UUID(snapshot_id),
                    title="Stored XSS executes during admin panel visit",
                    severity="high",
                    target_id="https://portal.example.test",
                    evidence_ref="artifact://web/stored-xss-admin",
                    status="open",
                    summary="Stored cross-site scripting evidence was observed during an admin review flow.",
                    methodology_tags=["stored xss", "admin panel visited"],
                    wstg_id="WSTG-CLNT-02",
                ),
            ]
        )
        session.commit()

    complete_response = client.post(
        f"/api/v1/runs/{run['id']}/assessment-plan/waves/complete",
        headers={"X-Actor": "planner-tester"},
        json={},
    )

    assert complete_response.status_code == 200
    payload = complete_response.json()
    assert payload["adaptive_execution_waves"]["waves"][0]["compound_chain_count"] == 1

    with session_factory() as session:
        proposal = session.scalar(
            select(AgentProposal).where(
                AgentProposal.run_id == UUID(run["id"]),
                AgentProposal.proposed_tool == "auth-flow",
            )
        )
        assert proposal is not None
        assert proposal.status == "pending_review"
        assert proposal.metadata_json["proposal_kind"] == "adaptive_execution_wave_compound_chain"
        assert proposal.metadata_json["dispatches_work"] is False
        assert proposal.proposed_params_json["adaptive_execution_wave"]["safe_boundaries"][
            "canary_evidence_only"
        ] is True
        auth_task = session.scalar(
            select(Task).where(Task.run_id == UUID(run["id"]), Task.tool == "auth-flow")
        )
        assert auth_task is None
