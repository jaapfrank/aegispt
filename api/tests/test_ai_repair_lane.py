from __future__ import annotations

from uuid import UUID, uuid4

from sqlalchemy import func, select

from api.app.models import AgentProposal, AuditEvent, Engagement, Run, RunProfile, Task, ToolExecution


def _seed_run_with_repairable_task(
    session,
    *,
    task_status: str = "failed",
    execution_exit_code: int = 2,
) -> tuple[Run, Task]:
    suffix = str(uuid4())
    engagement = Engagement(
        name=f"AI Repair Lane {suffix}",
        client="Acme Corp",
        roe_ref=f"ROE-REPAIR-{suffix}",
        status="active",
    )
    profile = RunProfile(
        name=f"repair-profile-{suffix}",
        run_class="active",
        limits_json={"tools": ["nmap"], "approval_required": True},
    )
    run = Run(
        engagement=engagement,
        profile=profile,
        requested_by="repair-operator",
        status="running",
        configuration_json={"targets": {"hosts": ["10.0.0.5"]}},
    )
    task = Task(
        run=run,
        tool="nmap",
        target_id="10.0.0.5",
        params_json={"profile_name": "safe-service-detection"},
        status=task_status,
    )
    execution = ToolExecution(
        task=task,
        runner_digest="sha256:repair-fixture",
        tool_version="nmap 7.94",
        exit_code=execution_exit_code,
        stdout_text="Starting Nmap\n",
        stderr_text="missing runtime dependency\n" if execution_exit_code else "",
    )
    session.add_all([engagement, profile, run, task, execution])
    session.flush()
    return run, task


def test_ai_repair_lane_creates_isolated_review_only_proposal(client) -> None:
    with client.app.state.session_factory() as session:
        run, task = _seed_run_with_repairable_task(session)
        task_count_before = session.scalar(select(func.count()).select_from(Task))
        original_task_state = {"status": task.status, "params_json": dict(task.params_json)}
        session.commit()
        run_id = run.id
        task_id = task.id

    response = client.post(
        f"/api/v1/runs/{run_id}/tasks/{task_id}/ai-repair",
        json={"note": "Explain how to fix this without mutating the active runtime."},
        headers={"X-Actor": "repair-reviewer"},
    )

    assert response.status_code == 200
    payload = response.json()
    proposal = payload["proposal"]
    assert payload["run_id"] == str(run_id)
    assert payload["task_id"] == str(task_id)
    assert payload["boundary"]["isolated_draft_only"] is True
    assert proposal["proposed_tool"] == "ai-repair"
    assert proposal["status"] == "pending_review"
    assert proposal["metadata_json"]["proposal_kind"] == "ai_repair"
    assert proposal["metadata_json"]["dispatches_work"] is False
    assert proposal["metadata_json"]["creates_tasks"] is False
    assert proposal["metadata_json"]["active_runtime_mutated"] is False
    assert proposal["metadata_json"]["isolated_draft_only"] is True
    assert proposal["metadata_json"]["draft_path"].startswith("codex/repair_drafts/")
    assert [action["id"] for action in proposal["metadata_json"]["available_actions"]][:2] == [
        "accept_gap",
        "create_build_lane_fix",
    ]
    assert proposal["metadata_json"]["available_actions"][0]["available"] is True
    assert proposal["proposed_params_json"]["isolated_draft"]["active_runtime_mutated"] is False
    assert proposal["proposed_params_json"]["available_actions"][1]["effect"] == "creates_build_lane_task"
    assert "git diff --check" in proposal["proposed_params_json"]["validation_commands"]

    with client.app.state.session_factory() as session:
        stored_task = session.get(Task, task_id)
        assert stored_task is not None
        assert {"status": stored_task.status, "params_json": stored_task.params_json} == original_task_state
        assert session.scalar(select(func.count()).select_from(Task)) == task_count_before
        audit = session.scalar(
            select(AuditEvent).where(
                AuditEvent.action == "ai_repair.proposal_created",
                AuditEvent.object_id == proposal["id"],
            )
        )
        assert audit is not None
        assert audit.actor == "repair-reviewer"
        assert audit.metadata_json["dispatches_work"] is False
        assert audit.metadata_json["active_runtime_mutated"] is False


def test_ai_repair_proposal_review_records_intent_without_queueing_work(client) -> None:
    with client.app.state.session_factory() as session:
        run, task = _seed_run_with_repairable_task(session, task_status="blocked", execution_exit_code=0)
        task_count_before = session.scalar(select(func.count()).select_from(Task))
        session.commit()
        run_id = run.id
        task_id = task.id

    repair_response = client.post(
        f"/api/v1/runs/{run_id}/tasks/{task_id}/ai-repair",
        json={},
        headers={"X-Actor": "repair-reviewer"},
    )
    assert repair_response.status_code == 200
    proposal_id = UUID(repair_response.json()["proposal"]["id"])

    review_response = client.post(
        f"/api/v1/runs/{run_id}/ai-proposals/{proposal_id}/review",
        json={"decision": "approved", "note": "Use this as a build-lane repair note."},
        headers={"X-Actor": "operator-alice"},
    )

    assert review_response.status_code == 200
    reviewed = review_response.json()
    assert reviewed["status"] == "approved"
    assert reviewed["metadata_json"]["proposal_kind"] == "ai_repair"
    assert reviewed["metadata_json"]["dispatches_work"] is False
    assert reviewed["metadata_json"]["creates_tasks"] is False
    assert reviewed["metadata_json"]["active_runtime_mutated"] is False
    assert reviewed["metadata_json"]["operator_controlled_flow_only"] is True

    with client.app.state.session_factory() as session:
        assert session.scalar(select(func.count()).select_from(Task)) == task_count_before
        stored = session.get(AgentProposal, proposal_id)
        assert stored is not None
        assert stored.proposed_tool == "ai-repair"
        audit = session.scalar(
            select(AuditEvent).where(
                AuditEvent.action == "agent_proposal.reviewed",
                AuditEvent.object_id == str(proposal_id),
            )
        )
        assert audit is not None
        assert audit.metadata_json["dispatches_work"] is False


def test_ai_repair_action_records_build_lane_request_without_runtime_mutation(client, tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("AEGISPT_CODEX_REPO_ROOT", str(tmp_path))
    with client.app.state.session_factory() as session:
        run, task = _seed_run_with_repairable_task(session)
        task_count_before = session.scalar(select(func.count()).select_from(Task))
        original_task_state = {"status": task.status, "params_json": dict(task.params_json)}
        session.commit()
        run_id = run.id
        task_id = task.id

    repair_response = client.post(
        f"/api/v1/runs/{run_id}/tasks/{task_id}/ai-repair",
        json={},
        headers={"X-Actor": "repair-reviewer"},
    )
    assert repair_response.status_code == 200
    proposal_id = UUID(repair_response.json()["proposal"]["id"])

    action_response = client.post(
        f"/api/v1/runs/{run_id}/ai-proposals/{proposal_id}/repair-action",
        json={
            "action": "create_build_lane_fix",
            "note": "Prepare a narrow installer/runtime prerequisite fix.",
        },
        headers={"X-Actor": "operator-alice"},
    )

    assert action_response.status_code == 200
    payload = action_response.json()
    assert payload["status"] == "recorded"
    assert payload["action"] == "create_build_lane_fix"
    assert "Build-lane fix task created" in payload["message"]
    proposal = payload["proposal"]
    assert proposal["status"] == "approved"
    assert proposal["approved_by"] == "operator-alice"
    result = proposal["metadata_json"]["repair_action_result"]
    assert result["action"] == "create_build_lane_fix"
    assert result["dispatches_work"] is False
    assert result["creates_tasks"] is False
    assert result["creates_build_lane_task"] is True
    assert result["active_runtime_mutated"] is False
    assert result["build_lane_fix_request"]["source_task_id"] == str(task_id)
    codex_task_id = result["build_lane_fix_request"]["codex_task_id"]
    task_file = result["build_lane_fix_request"]["task_file"]
    assert codex_task_id.startswith("task-")
    assert task_file.startswith("codex/tasks/")
    created_task_path = tmp_path / task_file
    assert created_task_path.exists()
    created_task = created_task_path.read_text(encoding="utf-8")
    assert str(task_id) in created_task
    assert "active_runtime_mutation_allowed" in created_task

    insights_response = client.get(f"/api/v1/runs/{run_id}/ai-insights")
    assert insights_response.status_code == 200
    workbench = insights_response.json()["operator_workbench"]
    assert workbench["summary"]["build_lane_tasks"] == 1
    assert workbench["boundary"]["active_runtime_mutated"] is False
    assert workbench["boundary"]["can_create_build_lane_tasks"] is True
    assert workbench["build_lane_tasks"][0]["codex_task_id"] == codex_task_id
    assert any(row.get("build_lane_task", {}).get("codex_task_id") == codex_task_id for row in workbench["signals"])

    with client.app.state.session_factory() as session:
        stored_task = session.get(Task, task_id)
        assert stored_task is not None
        assert {"status": stored_task.status, "params_json": stored_task.params_json} == original_task_state
        assert session.scalar(select(func.count()).select_from(Task)) == task_count_before
        audit = session.scalar(
            select(AuditEvent).where(
                AuditEvent.action == "ai_repair.action_recorded",
                AuditEvent.object_id == str(proposal_id),
            )
        )
        assert audit is not None
        assert audit.metadata_json["action"] == "create_build_lane_fix"
        assert audit.metadata_json["dispatches_work"] is False
        assert audit.metadata_json["creates_build_lane_task"] is True
        assert audit.metadata_json["codex_task_id"] == codex_task_id
        assert audit.metadata_json["active_runtime_mutated"] is False


def test_ai_repair_action_explains_unavailable_retry_without_reviewing_proposal(client) -> None:
    with client.app.state.session_factory() as session:
        run, task = _seed_run_with_repairable_task(session, task_status="skipped", execution_exit_code=0)
        session.commit()
        run_id = run.id
        task_id = task.id

    repair_response = client.post(
        f"/api/v1/runs/{run_id}/tasks/{task_id}/ai-repair",
        json={},
        headers={"X-Actor": "repair-reviewer"},
    )
    assert repair_response.status_code == 200
    proposal_id = UUID(repair_response.json()["proposal"]["id"])

    action_response = client.post(
        f"/api/v1/runs/{run_id}/ai-proposals/{proposal_id}/repair-action",
        json={"action": "retry_runner"},
        headers={"X-Actor": "operator-alice"},
    )

    assert action_response.status_code == 200
    payload = action_response.json()
    assert payload["status"] == "unavailable"
    assert "not safe" in payload["message"]
    assert payload["proposal"]["status"] == "pending_review"


def test_ai_repair_lane_rejects_non_repairable_task_without_records(client) -> None:
    with client.app.state.session_factory() as session:
        run, task = _seed_run_with_repairable_task(session, task_status="completed", execution_exit_code=0)
        proposal_count_before = session.scalar(select(func.count()).select_from(AgentProposal))
        session.commit()
        run_id = run.id
        task_id = task.id

    response = client.post(
        f"/api/v1/runs/{run_id}/tasks/{task_id}/ai-repair",
        json={},
        headers={"X-Actor": "repair-reviewer"},
    )

    assert response.status_code == 409
    assert "failed, blocked, or skipped" in response.json()["detail"]
    with client.app.state.session_factory() as session:
        assert session.scalar(select(func.count()).select_from(AgentProposal)) == proposal_count_before
