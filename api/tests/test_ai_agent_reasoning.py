from __future__ import annotations

from uuid import uuid4

import pytest
from sqlalchemy import func, select

from api.app.config import Settings
from api.app.models import (
    AgentProposal,
    AgentReasoning,
    AuditEvent,
    Engagement,
    Finding,
    Run,
    RunProfile,
    Task,
    ToolExecution,
)
from api.app.schemas.runs import AgentReasoningRead
from api.app.services.ai_agent import (
    AgentProposalDraft,
    PostTaskAnalysisResult,
    build_ai_insights_for_run,
    run_post_task_analysis_for_task,
)
from api.app.services.ai_enrichment import (
    list_agent_proposals_for_run,
    list_agent_reasoning_for_run,
    store_agent_proposal_record,
    store_agent_reasoning_record,
)


def _seed_run_with_task(
    session,
    *,
    profile_suffix: str | None = None,
    autonomous_mode: bool = False,
    autonomous_intrusive_allowed: bool = False,
) -> tuple[Run, Task, ToolExecution]:
    suffix = profile_suffix or str(uuid4())
    engagement = Engagement(
        name=f"AI Agent Ledger {suffix}",
        client="Acme Corp",
        roe_ref=f"ROE-LEDGER-{suffix}",
        status="active",
    )
    profile = RunProfile(
        name=f"ledger-profile-{suffix}",
        run_class="active",
        limits_json={"tools": ["nmap"], "approval_required": True},
    )
    run = Run(
        engagement=engagement,
        profile=profile,
        requested_by="ledger-operator",
        status="running",
        configuration_json={"targets": {"hosts": ["10.0.0.5"]}, "safety": {"active_checks": "reviewed"}},
        autonomous_mode=autonomous_mode,
        autonomous_intrusive_allowed=autonomous_intrusive_allowed,
    )
    task = Task(
        run=run,
        tool="nmap",
        target_id="10.0.0.5",
        params_json={"profile": "safe-service-detection"},
        status="completed",
    )
    execution = ToolExecution(
        task=task,
        runner_digest="sha256:ledger-fixture",
        tool_version="nmap 7.94",
        exit_code=0,
        stdout_text="443/tcp open https",
        stderr_text="",
    )
    session.add_all([engagement, profile, run, task, execution])
    session.flush()
    return run, task, execution


def test_agent_reasoning_and_proposal_records_are_additive_and_auditable(client) -> None:
    with client.app.state.session_factory() as session:
        run, task, execution = _seed_run_with_task(session)
        original_task_state = {
            "status": task.status,
            "params_json": dict(task.params_json),
        }
        original_execution_stdout = execution.stdout_text
        task_count_before = session.scalar(select(func.count()).select_from(Task))

        reasoning = store_agent_reasoning_record(
            session=session,
            run=run,
            task=task,
            reasoning_type="recon",
            status="succeeded",
            context_snapshot={
                "run_id": str(run.id),
                "task_id": str(task.id),
                "evidence_refs": ["tool_execution.stdout_text"],
            },
            observations=[{"summary": "HTTPS is exposed", "evidence_ref": "tool_execution.stdout_text"}],
            hypotheses=[{"summary": "Service fingerprinting may be useful", "confidence": 0.73}],
            proposals=[{"tool": "httpx", "target": "10.0.0.5", "risk_tier": "passive"}],
            provider="deterministic-ledger-test",
            model="none",
            llm_tokens_used=0,
            confidence_score=0.81,
            metadata={"provider_mode": "fixture", "dispatches_work": False},
        )
        proposal = store_agent_proposal_record(
            session=session,
            reasoning=reasoning,
            proposed_tool="httpx",
            proposed_target="10.0.0.5",
            proposed_params={"probe": "title-only"},
            reasoning_text="Follow-up remains review-only and is not queued.",
            risk_tier="passive",
            priority=10,
            confidence_score=0.77,
            metadata={"review_only": True},
        )
        session.commit()

        task_count_after = session.scalar(select(func.count()).select_from(Task))
        session.refresh(task)
        session.refresh(execution)

        assert reasoning.run_id == run.id
        assert reasoning.task_id == task.id
        assert reasoning.status == "succeeded"
        assert reasoning.observations_json[0]["summary"] == "HTTPS is exposed"
        assert reasoning.provider == "deterministic-ledger-test"
        assert reasoning.llm_tokens_used == 0
        assert proposal.run_id == run.id
        assert proposal.agent_reasoning_id == reasoning.id
        assert proposal.status == "pending_review"
        assert proposal.approved_by is None
        assert proposal.approved_at is None
        assert proposal.risk_tier == "passive"
        assert task_count_after == task_count_before
        assert {"status": task.status, "params_json": task.params_json} == original_task_state
        assert execution.stdout_text == original_execution_stdout

        serialized = AgentReasoningRead.model_validate(reasoning)
        assert serialized.proposals[0].id == proposal.id
        assert serialized.proposals[0].status == "pending_review"

        reasoning_records = list_agent_reasoning_for_run(session=session, run_id=run.id)
        proposal_records = list_agent_proposals_for_run(session=session, run_id=run.id)
        assert [record.id for record in reasoning_records] == [reasoning.id]
        assert [record.id for record in proposal_records] == [proposal.id]


def test_agent_reasoning_failure_state_requires_no_provider_or_proposal(client) -> None:
    with client.app.state.session_factory() as session:
        run, task, _execution = _seed_run_with_task(session)
        proposal_count_before = session.scalar(select(func.count()).select_from(AgentProposal))

        reasoning = store_agent_reasoning_record(
            session=session,
            run=run,
            task=task,
            reasoning_type="planning",
            status="failed",
            context_snapshot={"task_id": str(task.id), "provider_enabled": False},
            provider="not-configured",
            failure_reason="AI provider disabled; ledger stores failure state only.",
            metadata={"error_type": "ProviderDisabled", "dispatches_work": False},
        )
        session.commit()

        proposal_count_after = session.scalar(select(func.count()).select_from(AgentProposal))
        stored = session.get(AgentReasoning, reasoning.id)

        assert stored is not None
        assert stored.status == "failed"
        assert stored.provider == "not-configured"
        assert stored.failure_reason == "AI provider disabled; ledger stores failure state only."
        assert stored.metadata_json["error_type"] == "ProviderDisabled"
        assert proposal_count_after == proposal_count_before
        assert list_agent_proposals_for_run(session=session, run_id=run.id) == []


def test_agent_reasoning_rejects_cross_run_tasks_and_invalid_proposal_values(client) -> None:
    with client.app.state.session_factory() as session:
        run, _task, _execution = _seed_run_with_task(session, profile_suffix="a")
        other_run, other_task, _other_execution = _seed_run_with_task(session, profile_suffix="b")

        with pytest.raises(ValueError, match="same run"):
            store_agent_reasoning_record(session=session, run=run, task=other_task)

        reasoning = store_agent_reasoning_record(
            session=session,
            run=other_run,
            task=other_task,
            context_snapshot={"task_id": str(other_task.id)},
        )

        with pytest.raises(ValueError, match="risk_tier"):
            store_agent_proposal_record(
                session=session,
                reasoning=reasoning,
                proposed_tool="nuclei",
                proposed_target="10.0.0.6",
                risk_tier="destructive",
            )

        with pytest.raises(ValueError, match="status"):
            store_agent_proposal_record(
                session=session,
                reasoning=reasoning,
                proposed_tool="nuclei",
                proposed_target="10.0.0.6",
                status="executed",
            )


class FailingPostTaskProvider:
    name = "failing-test"

    def analyze(self, context: dict) -> PostTaskAnalysisResult:
        raise RuntimeError("provider unavailable")


class BlockingPostTaskProvider:
    name = "blocking-test"

    def analyze(self, context: dict) -> PostTaskAnalysisResult:
        return PostTaskAnalysisResult(
            observations=[{"summary": "completed task reviewed", "evidence_ref": "task.status"}],
            hypotheses=[{"summary": "blocked proposals should not be stored"}],
            proposals=[
                AgentProposalDraft(
                    proposed_tool="unsupported-ai-tool",
                    proposed_target="10.0.0.5",
                    reasoning_text="Unsupported tools must be blocked before storage.",
                ),
                AgentProposalDraft(
                    proposed_tool="httpx",
                    proposed_target="203.0.113.250",
                    reasoning_text="Out-of-scope targets must be blocked before storage.",
                ),
            ],
        )


class IntrusivePostTaskProvider:
    name = "intrusive-test"

    def analyze(self, context: dict) -> PostTaskAnalysisResult:
        target = str(context.get("task", {}).get("target_id") or "10.0.0.5")
        return PostTaskAnalysisResult(
            proposals=[
                AgentProposalDraft(
                    proposed_tool="zap",
                    proposed_target=target,
                    reasoning_text="Intrusive follow-up should stay blocked unless explicitly allowed.",
                    risk_tier="intrusive",
                )
            ]
        )


def test_post_task_analysis_disabled_by_default_skips_without_records(client) -> None:
    with client.app.state.session_factory() as session:
        run, task, _execution = _seed_run_with_task(session)
        reasoning_count_before = session.scalar(select(func.count()).select_from(AgentReasoning))
        proposal_count_before = session.scalar(select(func.count()).select_from(AgentProposal))

        outcome = run_post_task_analysis_for_task(
            session=session,
            task_id=task.id,
            settings=Settings(ai_agent_post_task_analysis_enabled=False),
        )
        session.commit()

        assert outcome.status == "skipped"
        assert outcome.reason == "disabled"
        assert session.scalar(select(func.count()).select_from(AgentReasoning)) == reasoning_count_before
        assert session.scalar(select(func.count()).select_from(AgentProposal)) == proposal_count_before
        assert run.status == "running"
        assert task.status == "completed"


def test_post_task_analysis_provider_failure_does_not_mutate_task_or_findings(client) -> None:
    with client.app.state.session_factory() as session:
        run, task, _execution = _seed_run_with_task(session)
        finding = Finding(
            run=run,
            title="TLS service exposed",
            severity="medium",
            target_id=task.target_id,
            evidence_ref="tool_execution.stdout_text",
            status="open",
            summary="Original finding summary.",
        )
        session.add(finding)
        session.flush()
        original_task_status = task.status
        original_finding_state = {
            "severity": finding.severity,
            "status": finding.status,
            "summary": finding.summary,
        }

        outcome = run_post_task_analysis_for_task(
            session=session,
            task_id=task.id,
            settings=Settings(
                ai_agent_post_task_analysis_enabled=True,
                ai_agent_post_task_analysis_provider="test",
            ),
            provider=FailingPostTaskProvider(),
        )
        session.commit()

        session.refresh(task)
        session.refresh(finding)
        assert outcome.status == "failed"
        assert outcome.reason == "provider unavailable"
        assert task.status == original_task_status
        assert {
            "severity": finding.severity,
            "status": finding.status,
            "summary": finding.summary,
        } == original_finding_state
        assert list_agent_proposals_for_run(session=session, run_id=run.id) == []

        reasoning_records = list_agent_reasoning_for_run(session=session, run_id=run.id)
        assert len(reasoning_records) == 1
        assert reasoning_records[0].status == "failed"
        assert reasoning_records[0].failure_reason == "provider unavailable"
        assert reasoning_records[0].metadata_json["dispatches_work"] is False


def test_post_task_analysis_blocks_unsupported_tools_and_out_of_scope_targets(client) -> None:
    with client.app.state.session_factory() as session:
        run, task, _execution = _seed_run_with_task(session)

        outcome = run_post_task_analysis_for_task(
            session=session,
            task_id=task.id,
            settings=Settings(
                ai_agent_post_task_analysis_enabled=True,
                ai_agent_post_task_analysis_provider="test",
            ),
            provider=BlockingPostTaskProvider(),
        )
        session.commit()

        assert outcome.status == "succeeded"
        assert outcome.stored_proposal_count == 0
        assert outcome.blocked_proposal_count == 2
        assert list_agent_proposals_for_run(session=session, run_id=run.id) == []

        reasoning_records = list_agent_reasoning_for_run(session=session, run_id=run.id)
        assert len(reasoning_records) == 1
        blocked = reasoning_records[0].metadata_json["blocked_proposals"]
        assert {item["reason"] for item in blocked} == {"unsupported_tool", "out_of_scope_target"}
        assert reasoning_records[0].proposals_json == []


def test_post_task_analysis_stores_pending_review_proposal_without_execution(client) -> None:
    with client.app.state.session_factory() as session:
        run, task, _execution = _seed_run_with_task(session)
        task_count_before = session.scalar(select(func.count()).select_from(Task))

        outcome = run_post_task_analysis_for_task(
            session=session,
            task_id=task.id,
            settings=Settings(
                ai_agent_post_task_analysis_enabled=True,
                ai_agent_post_task_analysis_provider="deterministic",
            ),
        )
        session.commit()

        proposals = list_agent_proposals_for_run(session=session, run_id=run.id)
        assert outcome.status == "succeeded"
        assert outcome.stored_proposal_count == 1
        assert len(proposals) == 1
        assert proposals[0].status == "pending_review"
        assert proposals[0].approved_by is None
        assert proposals[0].approved_at is None
        assert proposals[0].proposed_tool == "httpx"
        assert proposals[0].proposed_target == task.target_id
        assert proposals[0].metadata_json["dispatches_work"] is False
        assert proposals[0].metadata_json["requires_operator_review"] is True
        assert session.scalar(select(func.count()).select_from(Task)) == task_count_before


def test_post_task_analysis_autonomous_mode_queues_approved_follow_up_task(client) -> None:
    with client.app.state.session_factory() as session:
        run, task, _execution = _seed_run_with_task(session, autonomous_mode=True)
        task_count_before = session.scalar(select(func.count()).select_from(Task))

        outcome = run_post_task_analysis_for_task(
            session=session,
            task_id=task.id,
            settings=Settings(
                ai_agent_post_task_analysis_enabled=True,
                ai_agent_post_task_analysis_provider="deterministic",
            ),
        )
        session.commit()

        proposals = list_agent_proposals_for_run(session=session, run_id=run.id)
        created_tasks = [
            item
            for item in session.scalars(select(Task).where(Task.run_id == run.id)).all()
            if item.id != task.id
        ]
        assert outcome.status == "succeeded"
        assert outcome.autonomous_dispatch_count == 1
        assert len(outcome.autonomous_task_ids) == 1
        assert len(proposals) == 1
        assert proposals[0].status == "approved"
        assert proposals[0].approved_by == "autonomous-agent"
        assert proposals[0].approved_at is not None
        assert proposals[0].metadata_json["dispatches_work"] is True
        assert proposals[0].metadata_json["requires_operator_review"] is False
        assert proposals[0].metadata_json["creates_tasks"] is True
        assert len(created_tasks) == 1
        assert created_tasks[0].id == outcome.autonomous_task_ids[0]
        assert created_tasks[0].tool == "httpx"
        assert created_tasks[0].target_id == task.target_id
        assert created_tasks[0].status == "queued"
        assert created_tasks[0].params_json["autonomous_agent"]["enabled"] is True
        assert session.scalar(select(func.count()).select_from(Task)) == task_count_before + 1


def test_post_task_analysis_autonomous_mode_blocks_intrusive_without_flag(client) -> None:
    with client.app.state.session_factory() as session:
        run, task, _execution = _seed_run_with_task(session, autonomous_mode=True)
        task_count_before = session.scalar(select(func.count()).select_from(Task))

        outcome = run_post_task_analysis_for_task(
            session=session,
            task_id=task.id,
            settings=Settings(
                ai_agent_post_task_analysis_enabled=True,
                ai_agent_post_task_analysis_provider="test",
            ),
            provider=IntrusivePostTaskProvider(),
        )
        session.commit()

        proposals = list_agent_proposals_for_run(session=session, run_id=run.id)
        assert outcome.status == "succeeded"
        assert outcome.autonomous_dispatch_count == 0
        assert outcome.autonomous_skipped_count == 1
        assert len(outcome.autonomous_task_ids) == 0
        assert len(proposals) == 1
        assert proposals[0].status == "skipped"
        assert proposals[0].approved_by is None
        assert proposals[0].metadata_json["autonomous_block_reason"] == "intrusive_flag_required"
        assert session.scalar(select(func.count()).select_from(Task)) == task_count_before


def test_post_task_analysis_autonomous_mode_skips_duplicate_follow_up_tasks(client) -> None:
    with client.app.state.session_factory() as session:
        run, task, _execution = _seed_run_with_task(session, autonomous_mode=True)
        duplicate = Task(
            run=run,
            tool="httpx",
            target_id=task.target_id,
            params_json={"profile_name": "ledger-profile"},
            status="completed",
        )
        session.add(duplicate)
        session.flush()
        task_count_before = session.scalar(select(func.count()).select_from(Task))

        outcome = run_post_task_analysis_for_task(
            session=session,
            task_id=task.id,
            settings=Settings(
                ai_agent_post_task_analysis_enabled=True,
                ai_agent_post_task_analysis_provider="deterministic",
            ),
        )
        session.commit()

        proposals = list_agent_proposals_for_run(session=session, run_id=run.id)
        assert outcome.status == "succeeded"
        assert outcome.autonomous_dispatch_count == 0
        assert outcome.autonomous_skipped_count == 1
        assert proposals[0].status == "superseded"
        assert proposals[0].metadata_json["autonomous_block_reason"] == "duplicate_task_exists"
        assert proposals[0].metadata_json["existing_task_id"] == str(duplicate.id)
        assert session.scalar(select(func.count()).select_from(Task)) == task_count_before


def test_post_task_analysis_kill_switch_cancels_queued_autonomous_tasks(client) -> None:
    with client.app.state.session_factory() as session:
        run, task, _execution = _seed_run_with_task(session, autonomous_mode=True)
        queued_autonomous = Task(
            run=run,
            tool="httpx",
            target_id=task.target_id,
            params_json={"autonomous_agent": {"enabled": True, "sequence": 1}},
            status="queued",
        )
        session.add(queued_autonomous)
        session.flush()

        outcome = run_post_task_analysis_for_task(
            session=session,
            task_id=task.id,
            settings=Settings(
                ai_agent_post_task_analysis_enabled=True,
                ai_agent_post_task_analysis_provider="deterministic",
                execution_kill_switch=True,
            ),
        )
        session.commit()

        session.refresh(queued_autonomous)
        assert outcome.status == "skipped"
        assert outcome.reason == "kill_switch"
        assert queued_autonomous.status == "cancelled"
        audit = session.scalar(
            select(AuditEvent).where(AuditEvent.action == "run.autonomous_tasks_cancelled")
        )
        assert audit is not None
        assert audit.metadata_json["cancelled_task_count"] == 1


def test_ai_insights_endpoint_reflects_autonomous_boundary(client) -> None:
    with client.app.state.session_factory() as session:
        run, task, _execution = _seed_run_with_task(session, autonomous_mode=True)
        reasoning = store_agent_reasoning_record(
            session=session,
            run=run,
            task=task,
            reasoning_type="post_task_analysis",
            status="succeeded",
            context_snapshot={"task_id": str(task.id), "autonomous_mode": True},
            provider="deterministic",
            metadata={"dispatches_work": True},
        )
        store_agent_proposal_record(
            session=session,
            reasoning=reasoning,
            proposed_tool="httpx",
            proposed_target=task.target_id,
            status="approved",
            metadata={"dispatches_work": True, "requires_operator_review": False},
        )
        session.commit()
        run_id = run.id

    response = client.get(f"/api/v1/runs/{run_id}/ai-insights")

    assert response.status_code == 200
    payload = response.json()
    assert payload["review_boundary"]["approved_proposals_dispatch_work"] is True
    assert payload["review_boundary"]["kill_switch_halts_queued_autonomous_tasks"] is True
    assert "Autonomous mode is enabled" in payload["review_boundary"]["message"]


def test_ai_insights_provider_status_prefers_connected_chatgpt_oauth_over_guidance_fallback(
    client,
    monkeypatch,
) -> None:
    class ConnectedStatus:
        connected = True
        account_id = "acct_connected"

    with client.app.state.session_factory() as session:
        run, _task, _execution = _seed_run_with_task(session)
        monkeypatch.setattr(
            "api.app.services.ai_agent.chatgpt_oauth_status",
            lambda **_kwargs: ConnectedStatus(),
        )

        payload = build_ai_insights_for_run(
            session=session,
            run=run,
            settings=Settings(
                ai_agent_post_task_analysis_enabled=True,
                ai_agent_post_task_analysis_provider="chatgpt_oauth",
                chatgpt_oauth_client_id="client-id",
                chatgpt_oauth_model="gpt-5.4",
            ),
        )

    assert payload["provider"] == "chatgpt_oauth"
    assert payload["provider_status"]["status"] == "connected"
    assert payload["provider_status"]["connected"] is True
    assert payload["provider_status"]["label"] == "ChatGPT connected"


def _seed_review_proposal(
    session,
    *,
    proposed_tool: str = "httpx",
    proposed_target: str | None = None,
    reasoning_text: str = "Operator review is required before any follow-up.",
) -> tuple[Run, Task, AgentProposal]:
    run, task, _execution = _seed_run_with_task(session)
    reasoning = store_agent_reasoning_record(
        session=session,
        run=run,
        task=task,
        reasoning_type="post_task_analysis",
        status="succeeded",
        context_snapshot={"task_id": str(task.id), "review_only": True},
        observations=[{"summary": "Task output suggests a bounded follow-up.", "evidence_ref": "task.status"}],
        hypotheses=[{"summary": "A passive probe may help review.", "confidence": 0.71}],
        proposals=[{"proposed_tool": proposed_tool, "proposed_target": proposed_target or task.target_id}],
        provider="deterministic",
        model="deterministic",
        metadata={"dispatches_work": False},
    )
    proposal = store_agent_proposal_record(
        session=session,
        reasoning=reasoning,
        proposed_tool=proposed_tool,
        proposed_target=proposed_target or task.target_id,
        proposed_params={"source_task_id": str(task.id), "review_required": True},
        reasoning_text=reasoning_text,
        risk_tier="passive",
        priority=20,
        confidence_score=0.72,
        metadata={"dispatches_work": False, "requires_operator_review": True},
    )
    return run, task, proposal


def test_ai_insights_endpoint_lists_reasoning_and_proposals_with_disabled_truth(client) -> None:
    with client.app.state.session_factory() as session:
        run, task, proposal = _seed_review_proposal(session)
        session.commit()
        run_id = run.id
        task_id = task.id
        proposal_id = proposal.id

    response = client.get(f"/api/v1/runs/{run_id}/ai-insights")

    assert response.status_code == 200
    payload = response.json()
    assert payload["run_id"] == str(run_id)
    assert payload["post_task_analysis_enabled"] is False
    assert payload["provider"] == "disabled"
    assert payload["review_boundary"]["approved_proposals_dispatch_work"] is False
    assert "does not create tasks" in payload["review_boundary"]["message"]
    assert payload["reasoning_records"][0]["task_id"] == str(task_id)
    assert payload["reasoning_records"][0]["proposals"][0]["id"] == str(proposal_id)
    assert payload["proposals"][0]["id"] == str(proposal_id)
    assert payload["proposals"][0]["status"] == "pending_review"


def test_ai_proposal_approval_is_auditable_and_does_not_queue_work(client) -> None:
    with client.app.state.session_factory() as session:
        run, _task, proposal = _seed_review_proposal(session)
        task_count_before = session.scalar(select(func.count()).select_from(Task))
        session.commit()
        run_id = run.id
        proposal_id = proposal.id

    response = client.post(
        f"/api/v1/runs/{run_id}/ai-proposals/{proposal_id}/review",
        json={"decision": "approved", "note": "Looks safe to prepare through existing controls."},
        headers={"X-Actor": "reviewer-alice"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "approved"
    assert payload["approved_by"] == "reviewer-alice"
    assert payload["approved_at"] is not None
    assert payload["metadata_json"]["reviewed_by"] == "reviewer-alice"
    assert payload["metadata_json"]["review_decision"] == "approved"
    assert payload["metadata_json"]["dispatches_work"] is False
    assert payload["metadata_json"]["creates_tasks"] is False

    with client.app.state.session_factory() as session:
        assert session.scalar(select(func.count()).select_from(Task)) == task_count_before
        audit = session.scalar(
            select(AuditEvent).where(
                AuditEvent.action == "agent_proposal.reviewed",
                AuditEvent.object_id == str(proposal_id),
            )
        )
        assert audit is not None
        assert audit.actor == "reviewer-alice"
        assert audit.metadata_json["decision"] == "approved"
        assert audit.metadata_json["dispatches_work"] is False
        assert audit.metadata_json["operator_controlled_flow_only"] is True


def test_ai_proposal_rejection_is_auditable_without_approval_fields(client) -> None:
    with client.app.state.session_factory() as session:
        run, _task, proposal = _seed_review_proposal(
            session,
            proposed_tool="unsupported-ai-tool",
            proposed_target="203.0.113.250",
            reasoning_text="Even unsafe suggestions can be rejected without execution.",
        )
        session.commit()
        run_id = run.id
        proposal_id = proposal.id

    response = client.post(
        f"/api/v1/runs/{run_id}/ai-proposals/{proposal_id}/review",
        json={"decision": "rejected", "note": "Out of boundary."},
        headers={"X-Actor": "reviewer-bob"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "rejected"
    assert payload["approved_by"] is None
    assert payload["approved_at"] is None
    assert payload["metadata_json"]["reviewed_by"] == "reviewer-bob"
    assert payload["metadata_json"]["review_decision"] == "rejected"
    assert payload["metadata_json"]["dispatches_work"] is False

    with client.app.state.session_factory() as session:
        audit = session.scalar(
            select(AuditEvent).where(
                AuditEvent.action == "agent_proposal.reviewed",
                AuditEvent.object_id == str(proposal_id),
            )
        )
        assert audit is not None
        assert audit.metadata_json["decision"] == "rejected"


def test_ai_proposal_approval_blocks_forbidden_action_classes(client) -> None:
    with client.app.state.session_factory() as session:
        unsupported_run, _unsupported_task, unsupported_proposal = _seed_review_proposal(
            session,
            proposed_tool="unsupported-ai-tool",
        )
        out_of_scope_run, _out_of_scope_task, out_of_scope_proposal = _seed_review_proposal(
            session,
            proposed_tool="httpx",
            proposed_target="203.0.113.250",
        )
        task_count_before = session.scalar(select(func.count()).select_from(Task))
        session.commit()
        unsupported_run_id = unsupported_run.id
        unsupported_proposal_id = unsupported_proposal.id
        out_of_scope_run_id = out_of_scope_run.id
        out_of_scope_proposal_id = out_of_scope_proposal.id

    unsupported_response = client.post(
        f"/api/v1/runs/{unsupported_run_id}/ai-proposals/{unsupported_proposal_id}/review",
        json={"decision": "approved"},
        headers={"X-Actor": "reviewer-carol"},
    )
    out_of_scope_response = client.post(
        f"/api/v1/runs/{out_of_scope_run_id}/ai-proposals/{out_of_scope_proposal_id}/review",
        json={"decision": "approved"},
        headers={"X-Actor": "reviewer-carol"},
    )

    assert unsupported_response.status_code == 409
    assert "unsupported AI proposal tool" in unsupported_response.json()["detail"]
    assert out_of_scope_response.status_code == 409
    assert "outside approved scope" in out_of_scope_response.json()["detail"]

    with client.app.state.session_factory() as session:
        unsupported = session.get(AgentProposal, unsupported_proposal_id)
        out_of_scope = session.get(AgentProposal, out_of_scope_proposal_id)
        assert unsupported is not None
        assert out_of_scope is not None
        assert unsupported.status == "pending_review"
        assert out_of_scope.status == "pending_review"
        assert unsupported.approved_by is None
        assert out_of_scope.approved_by is None
        assert session.scalar(select(func.count()).select_from(Task)) == task_count_before
        assert (
            session.scalar(
                select(func.count())
                .select_from(AuditEvent)
                .where(AuditEvent.action == "agent_proposal.reviewed")
            )
            == 0
        )
