from __future__ import annotations

from uuid import UUID

from sqlalchemy import select

from api.app.models import Approval, AuditEvent, InventorySnapshot, Run
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
