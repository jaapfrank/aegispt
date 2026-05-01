from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from api.app.models import AgentProposal, AgentReasoning, Run, Task, ToolExecution
from api.app.services.audit import write_audit_event
from api.app.services.ai_enrichment import (
    store_agent_proposal_record,
    store_agent_reasoning_record,
)
from api.app.schemas.codex import CodexTaskCreate, CodexTaskSourceContext
from api.app.services.codex_tasks import create_codex_task


AI_REPAIR_ELIGIBLE_TASK_STATUSES = {"failed", "blocked", "skipped"}
AI_REPAIR_BOUNDARY = {
    "message": (
        "AI repair proposals are isolated build-lane drafts only. Reviewing one records operator "
        "intent and never edits active runtime state, queues tasks, dispatches tools, installs "
        "capabilities, grants approvals, deploys packs, or binds runtime packs."
    ),
    "approval_effect": "review_status_only",
    "isolated_draft_only": True,
    "active_runtime_mutated": False,
    "dispatches_work": False,
    "creates_tasks": False,
    "forbidden_action_classes": [
        "runtime_self_modification",
        "active_run_mutation",
        "active_pack_mutation",
        "automatic_task_queueing",
        "automatic_dispatch",
        "automatic_approval",
        "tool_installation",
        "pack_validation_approval_deployment_or_runtime_binding_bypass",
        "finding_schema_mutation",
    ],
}


class AiRepairLaneError(RuntimeError):
    def __init__(self, message: str, *, reason: str) -> None:
        super().__init__(message)
        self.reason = reason


@dataclass(frozen=True, slots=True)
class AiRepairProposalOutcome:
    reasoning: AgentReasoning
    proposal: AgentProposal
    boundary: dict[str, Any]


@dataclass(frozen=True, slots=True)
class AiRepairActionOutcome:
    proposal: AgentProposal
    action: str
    status: str
    message: str
    available_actions: list[dict[str, Any]]


def create_ai_repair_proposal(
    *,
    session: Session,
    run: Run,
    task_id: UUID,
    actor: str,
    note: str | None = None,
) -> AiRepairProposalOutcome:
    """Create a review-only repair proposal for a failed, blocked, or skipped runner outcome."""

    if run.id is None:
        raise AiRepairLaneError("run must be persisted before creating an AI repair proposal", reason="invalid_run")

    task = session.scalar(
        select(Task)
        .where(Task.id == task_id, Task.run_id == run.id)
        .options(selectinload(Task.executions).selectinload(ToolExecution.artifacts))
    )
    if task is None:
        raise AiRepairLaneError("task not found for run", reason="not_found")

    task_status = str(task.status or "").strip().lower()
    if task_status not in AI_REPAIR_ELIGIBLE_TASK_STATUSES:
        raise AiRepairLaneError(
            "AI repair proposals are only available for failed, blocked, or skipped tasks",
            reason="task_not_repairable",
        )

    existing = _existing_pending_repair_proposal(session=session, run_id=run.id, task_id=task.id)
    if existing is not None:
        reasoning = session.get(AgentReasoning, existing.agent_reasoning_id)
        if reasoning is None:
            raise AiRepairLaneError("existing AI repair proposal has no reasoning record", reason="invalid_state")
        return AiRepairProposalOutcome(reasoning=reasoning, proposal=existing, boundary=dict(AI_REPAIR_BOUNDARY))

    context = _build_repair_context(run=run, task=task)
    recommendation = _build_repair_recommendation(task=task, context=context)
    available_actions = _repair_actions_for_task(task=task, recommendation_type=recommendation["recommendation_type"])
    now = datetime.now(tz=UTC).isoformat()
    draft_path = f"codex/repair_drafts/{run.id}/{task.id}-repair-proposal.json"
    proposal_payload = {
        **recommendation,
        "available_actions": available_actions,
        "source_task_id": str(task.id),
        "source_run_id": str(run.id),
        "source_status": task_status,
        "operator_note": (note or "").strip() or None,
        "isolated_draft": {
            "path": draft_path,
            "kind": "ai_repair_review_record",
            "active_runtime_mutated": False,
            "requires_build_lane_review": True,
        },
        "boundary": dict(AI_REPAIR_BOUNDARY),
        "validation_commands": _validation_commands_for_repair(task),
    }
    observations = [
        {
            "summary": recommendation["summary"],
            "evidence_ref": "task.status",
            "source_task_id": str(task.id),
        }
    ]
    if context["latest_execution"]:
        observations.append(
            {
                "summary": context["latest_execution"]["summary"],
                "evidence_ref": "tool_execution",
                "source_task_id": str(task.id),
            }
        )

    reasoning = store_agent_reasoning_record(
        session=session,
        run=run,
        task=task,
        reasoning_type="ai_repair",
        status="succeeded",
        context_snapshot=context,
        observations=observations,
        hypotheses=[
            {
                "summary": recommendation["hypothesis"],
                "confidence": recommendation["confidence"],
            }
        ],
        proposals=[proposal_payload],
        provider="deterministic-ai-repair-lane",
        model="ruleset",
        llm_tokens_used=0,
        confidence_score=recommendation["confidence"],
        metadata={
            "proposal_kind": "ai_repair",
            "dispatches_work": False,
            "creates_tasks": False,
            "active_runtime_mutated": False,
            "isolated_draft_only": True,
            "draft_path": draft_path,
            "created_by": actor,
            "created_at": now,
        },
    )
    proposal = store_agent_proposal_record(
        session=session,
        reasoning=reasoning,
        proposed_tool="ai-repair",
        proposed_target=task.target_id,
        proposed_params=proposal_payload,
        reasoning_text=recommendation["operator_summary"],
        risk_tier="passive",
        priority=5,
        confidence_score=recommendation["confidence"],
        status="pending_review",
        metadata={
            "proposal_kind": "ai_repair",
            "recommendation_type": recommendation["recommendation_type"],
            "requires_operator_review": True,
            "dispatches_work": False,
            "creates_tasks": False,
            "grants_approval": False,
            "active_runtime_mutated": False,
            "isolated_draft_only": True,
            "draft_path": draft_path,
            "source_task_id": str(task.id),
            "source_status": task_status,
            "created_by": actor,
            "created_at": now,
            "review_boundary": AI_REPAIR_BOUNDARY["approval_effect"],
            "available_actions": available_actions,
        },
    )
    write_audit_event(
        session=session,
        actor=actor,
        action="ai_repair.proposal_created",
        object_type="agent_proposal",
        object_id=str(proposal.id),
        metadata={
            "run_id": str(run.id),
            "task_id": str(task.id),
            "task_status": task_status,
            "proposal_kind": "ai_repair",
            "draft_path": draft_path,
            "dispatches_work": False,
            "active_runtime_mutated": False,
            "isolated_draft_only": True,
        },
    )
    session.flush()
    return AiRepairProposalOutcome(reasoning=reasoning, proposal=proposal, boundary=dict(AI_REPAIR_BOUNDARY))


def apply_ai_repair_action(
    *,
    session: Session,
    run: Run,
    proposal_id: UUID,
    actor: str,
    action: str,
    note: str | None = None,
) -> AiRepairActionOutcome:
    """Record an explicit operator recovery action for an AI repair proposal.

    The action contract is intentionally narrow: it can close a known coverage gap or
    request build-lane work, but it cannot dispatch tools, install capabilities, grant
    approvals, or mutate active assessment state.
    """

    normalized_action = str(action or "").strip().lower().replace("-", "_")
    proposal = session.scalar(
        select(AgentProposal)
        .where(AgentProposal.id == proposal_id, AgentProposal.run_id == run.id)
        .options(selectinload(AgentProposal.agent_reasoning))
    )
    if proposal is None:
        raise AiRepairLaneError("AI repair proposal not found for run", reason="not_found")

    metadata = _safe_json_object(proposal.metadata_json)
    params = _safe_json_object(proposal.proposed_params_json)
    if metadata.get("proposal_kind") != "ai_repair":
        raise AiRepairLaneError("proposal is not an AI repair proposal", reason="not_repair_proposal")

    source_task_id = _uuid_or_none(metadata.get("source_task_id") or params.get("source_task_id"))
    task = (
        session.scalar(
            select(Task)
            .where(Task.id == source_task_id, Task.run_id == run.id)
            .options(selectinload(Task.executions).selectinload(ToolExecution.artifacts))
        )
        if source_task_id is not None
        else None
    )
    if task is None:
        raise AiRepairLaneError("AI repair proposal source task no longer exists", reason="source_task_not_found")

    actions = _repair_actions_for_task(
        task=task,
        recommendation_type=str(metadata.get("recommendation_type") or params.get("recommendation_type") or ""),
    )
    action_record = next((candidate for candidate in actions if candidate["id"] == normalized_action), None)
    if action_record is None:
        raise AiRepairLaneError("unsupported AI repair action", reason="unsupported_action")
    if not action_record.get("available"):
        return AiRepairActionOutcome(
            proposal=proposal,
            action=normalized_action,
            status="unavailable",
            message=str(action_record.get("unavailable_reason") or "This repair action is not available for the current evidence."),
            available_actions=actions,
        )

    now = datetime.now(tz=UTC)
    action_result = {
        "action": normalized_action,
        "label": action_record["label"],
        "status": "recorded",
        "recorded_by": actor,
        "recorded_at": now.isoformat(),
        "operator_note": (note or "").strip() or None,
        "source_task_id": str(task.id),
        "source_task_status": task.status,
        "dispatches_work": False,
        "creates_tasks": False,
        "active_runtime_mutated": False,
    }

    if normalized_action == "accept_gap":
        message = (
            "Coverage gap accepted and recorded. The failed, blocked, or skipped runner remains visible "
            "in evidence; no task was queued."
        )
        action_result["coverage_gap_accepted"] = True
    elif normalized_action == "create_build_lane_fix":
        codex_task = _create_build_lane_fix_task(
            run=run,
            task=task,
            proposal=proposal,
            actor=actor,
            note=note,
            metadata=metadata,
            params=params,
        )
        message = (
            "Build-lane fix task created. The active runtime was not changed; use the Codex task file "
            "for the next reviewed repair pass."
        )
        action_result["build_lane_fix_request"] = {
            "title": f"Repair {task.tool} runner outcome for {task.target_id}",
            "codex_task_id": codex_task.id,
            "task_file": codex_task.task_file,
            "source_task_id": str(task.id),
            "source_run_id": str(run.id),
            "recommendation_type": metadata.get("recommendation_type") or params.get("recommendation_type"),
            "draft_path": metadata.get("draft_path") or params.get("isolated_draft", {}).get("path"),
            "creates_runtime_tasks": False,
            "creates_build_lane_task": True,
        }
        action_result["creates_build_lane_task"] = True
    else:
        raise AiRepairLaneError("repair action is not implemented safely yet", reason="action_not_implemented")

    proposal.status = "approved"
    proposal.approved_by = actor
    proposal.approved_at = now
    proposal.metadata_json = {
        **metadata,
        "requires_operator_review": True,
        "reviewed_by": actor,
        "reviewed_at": now.isoformat(),
        "review_decision": normalized_action,
        "repair_action_result": action_result,
        "available_actions": actions,
        "dispatches_work": False,
        "creates_tasks": False,
        "grants_approval": False,
        "operator_controlled_flow_only": True,
        "active_runtime_mutated": False,
        "review_boundary": AI_REPAIR_BOUNDARY["approval_effect"],
    }
    proposal.proposed_params_json = {
        **params,
        "available_actions": actions,
        "repair_action_result": action_result,
    }
    write_audit_event(
        session=session,
        actor=actor,
        action="ai_repair.action_recorded",
        object_type="agent_proposal",
        object_id=str(proposal.id),
        metadata={
            "run_id": str(run.id),
            "task_id": str(task.id),
            "proposal_kind": "ai_repair",
            "action": normalized_action,
            "dispatches_work": False,
            "creates_tasks": False,
            "creates_build_lane_task": bool(action_result.get("creates_build_lane_task")),
            "active_runtime_mutated": False,
            "codex_task_id": action_result.get("build_lane_fix_request", {}).get("codex_task_id"),
        },
    )
    session.flush()
    return AiRepairActionOutcome(
        proposal=proposal,
        action=normalized_action,
        status="recorded",
        message=message,
        available_actions=actions,
    )


def _existing_pending_repair_proposal(
    *,
    session: Session,
    run_id: UUID,
    task_id: UUID,
) -> AgentProposal | None:
    return session.scalar(
        select(AgentProposal)
        .where(
            AgentProposal.run_id == run_id,
            AgentProposal.status == "pending_review",
            AgentProposal.metadata_json["proposal_kind"].as_string() == "ai_repair",
            AgentProposal.metadata_json["source_task_id"].as_string() == str(task_id),
        )
        .order_by(AgentProposal.created_at.desc())
    )


def _build_repair_context(*, run: Run, task: Task) -> dict[str, Any]:
    executions = sorted(
        list(task.executions or []),
        key=lambda execution: (execution.updated_at or execution.created_at, execution.id.hex),
    )
    latest = executions[-1] if executions else None
    return {
        "run_id": str(run.id),
        "run_status": run.status,
        "task_id": str(task.id),
        "task_tool": task.tool,
        "task_target": task.target_id,
        "task_status": task.status,
        "task_params": _safe_json_object(task.params_json),
        "latest_execution": _execution_snapshot(latest),
        "evidence_refs": _evidence_refs(latest),
        "safety": {
            "source": "persisted task, execution, and artifact metadata",
            "active_runtime_mutated": False,
            "dispatches_work": False,
        },
    }


def _create_build_lane_fix_task(
    *,
    run: Run,
    task: Task,
    proposal: AgentProposal,
    actor: str,
    note: str | None,
    metadata: dict[str, Any],
    params: dict[str, Any],
):
    context = _build_repair_context(run=run, task=task)
    recommendation_type = str(metadata.get("recommendation_type") or params.get("recommendation_type") or "runner-repair")
    validation_commands = params.get("validation_commands")
    if not isinstance(validation_commands, list):
        validation_commands = _validation_commands_for_repair(task)
    payload = CodexTaskCreate(
        task_type="ai_repair_build_lane_fix",
        scope=(
            f"Repair the failed/blocked/skipped {task.tool} runner outcome for target {task.target_id} "
            "through the Codex build lane only. Do not mutate active runtime state."
        ),
        inputs={
            "run_id": str(run.id),
            "source_task_id": str(task.id),
            "source_task_status": task.status,
            "source_tool": task.tool,
            "source_target": task.target_id,
            "recommendation_type": recommendation_type,
            "operator_note": (note or "").strip() or None,
            "ai_proposal_id": str(proposal.id),
            "ai_reasoning_id": str(proposal.agent_reasoning_id),
            "repair_context": context,
            "suggested_actions": params.get("suggested_actions") if isinstance(params.get("suggested_actions"), list) else [],
        },
        constraints={
            "active_runtime_mutation_allowed": False,
            "dispatches_live_tools": False,
            "creates_runtime_tasks": False,
            "installs_capabilities_during_active_run": False,
            "bypasses_pack_registry_validation_approval_deployment_or_binding": False,
            "bypasses_approval_gates": False,
            "changes_finding_schema": False,
            "requires_repo_review": True,
            "safe_targets_only": True,
            "use_existing_models_provenance_report_structures_and_flows": True,
        },
        expected_output={
            "operator_visible_root_cause": True,
            "minimal_patch_or_configuration_fix": True,
            "tests": [
                "focused API or runner test for the repaired failure path",
                "python3 scripts/validate_backlog_tasks.py",
                "git diff --check",
            ],
            "evidence": [
                "record exact command/result for validation",
                "update DONE_LOG.md and CURRENT_STATE.md when the active task is completed",
            ],
            "no_active_runtime_change": True,
        },
        generation_reason=(
            "AI repair workbench action created this build-lane task from a persisted runner outcome. "
            "It is a safe handoff for code/config repair, not an active runtime continuation."
        ),
        source_context=CodexTaskSourceContext(),
    )
    return create_codex_task(payload, requested_by=actor)


def _execution_snapshot(execution: ToolExecution | None) -> dict[str, Any] | None:
    if execution is None:
        return None
    stdout_tail = _tail_text(execution.stdout_text)
    stderr_tail = _tail_text(execution.stderr_text)
    return {
        "id": str(execution.id),
        "exit_code": execution.exit_code,
        "runner_digest": execution.runner_digest,
        "tool_version": execution.tool_version,
        "stdout_tail": stdout_tail,
        "stderr_tail": stderr_tail,
        "artifact_count": len(execution.artifacts or []),
        "summary": _execution_summary(execution, stdout_tail=stdout_tail, stderr_tail=stderr_tail),
    }


def _execution_summary(
    execution: ToolExecution,
    *,
    stdout_tail: str,
    stderr_tail: str,
) -> str:
    if execution.exit_code != 0:
        return f"Runner exited with code {execution.exit_code}; stderr/stdout should be reviewed before continuing."
    if stderr_tail:
        return "Runner completed with stderr output; confirm whether it is benign before continuing."
    if stdout_tail:
        return "Runner produced stdout that can ground a repair recommendation."
    return "Runner metadata exists, but no stdout or stderr tail was captured."


def _evidence_refs(execution: ToolExecution | None) -> list[dict[str, Any]]:
    if execution is None:
        return [{"kind": "task", "ref": "task.status"}]
    refs: list[dict[str, Any]] = [
        {"kind": "tool_execution", "ref": str(execution.id), "field": "exit_code"},
    ]
    for artifact in execution.artifacts or []:
        refs.append(
            {
                "kind": "artifact",
                "ref": artifact.uri,
                "artifact_id": str(artifact.id),
                "redaction_state": artifact.redaction_state,
            }
        )
    return refs


def _build_repair_recommendation(*, task: Task, context: dict[str, Any]) -> dict[str, Any]:
    status = str(task.status or "").strip().lower()
    latest_execution = context.get("latest_execution") if isinstance(context.get("latest_execution"), dict) else None
    stderr_tail = str(latest_execution.get("stderr_tail") or "") if latest_execution else ""
    params = _safe_json_object(task.params_json)
    skip_reason = str(params.get("skip_reason") or params.get("blocked_reason") or params.get("reason") or "")
    lower_reason = f"{skip_reason}\n{stderr_tail}".lower()

    if status == "blocked":
        recommendation_type = "operator-gate-review"
        title = "Review blocked runner gate"
        summary = "The task is blocked by a guardrail or runner boundary; AI can draft the review notes, but cannot continue the chain automatically."
        hypothesis = "The safest repair is to surface the exact gate, required prerequisite, and validation command for operator review."
    elif status == "skipped":
        recommendation_type = "prerequisite-remediation"
        title = "Resolve skipped runner prerequisite"
        summary = "The task was skipped before execution; the repair should identify the missing prerequisite instead of silently hiding the skipped coverage."
        hypothesis = "The skipped state likely needs scope, credential, product, or pack prerequisite remediation before this runner can add value."
    elif "no such file" in lower_reason or "not found" in lower_reason or "missing" in lower_reason:
        recommendation_type = "environment-remediation"
        title = "Repair missing runtime dependency"
        summary = "The runner appears to lack a required binary, file, or configured dependency."
        hypothesis = "A build-lane installer or pack prerequisite fix is safer than retrying the active runtime blindly."
    elif latest_execution and latest_execution.get("exit_code") not in (None, 0):
        recommendation_type = "runner-diagnostic"
        title = "Diagnose failed runner command"
        summary = "The runner failed with a non-zero exit code; the captured command output should be reviewed before retrying."
        hypothesis = "The failure can likely be reduced to input validation, command flags, environment dependencies, or target reachability."
    else:
        recommendation_type = "evidence-review"
        title = "Review incomplete runner outcome"
        summary = "The runner outcome needs operator review before AegisPT can safely continue or trust this coverage."
        hypothesis = "A concise repair note and validation checklist can prevent hidden gaps in the assessment chain."

    suggested_actions = _suggested_actions_for_type(recommendation_type)
    return {
        "recommendation_type": recommendation_type,
        "title": title,
        "summary": summary,
        "hypothesis": hypothesis,
        "operator_summary": (
            f"{title}: {summary} This is a review-only repair proposal; approving it records intent only."
        ),
        "suggested_actions": suggested_actions,
        "confidence": 0.76,
    }


def _suggested_actions_for_type(recommendation_type: str) -> list[dict[str, Any]]:
    if recommendation_type == "operator-gate-review":
        return [
            {"label": "Inspect gate reason", "mutates_runtime": False},
            {"label": "Confirm whether existing approval already covers this phase", "mutates_runtime": False},
            {"label": "Use existing validation and approval flow before continuing", "mutates_runtime": False},
        ]
    if recommendation_type == "prerequisite-remediation":
        return [
            {"label": "List missing prerequisites in the run dossier", "mutates_runtime": False},
            {"label": "Update configuration through intake or settings, not by editing active run state", "mutates_runtime": False},
            {"label": "Re-run the existing validation checks before dispatch", "mutates_runtime": False},
        ]
    if recommendation_type == "environment-remediation":
        return [
            {"label": "Draft installer or pack prerequisite changes in the build lane", "mutates_runtime": False},
            {"label": "Validate binaries with safe local version checks", "mutates_runtime": False},
            {"label": "Promote through pack validation, approval, deployment, and binding gates", "mutates_runtime": False},
        ]
    return [
        {"label": "Review stdout and stderr evidence", "mutates_runtime": False},
        {"label": "Draft the smallest safe config or pack fix", "mutates_runtime": False},
        {"label": "Validate through the task-defined checks before continuing", "mutates_runtime": False},
    ]


def _repair_actions_for_task(*, task: Task, recommendation_type: str) -> list[dict[str, Any]]:
    status = str(task.status or "").strip().lower()
    latest_execution = _latest_execution(task)
    stderr_text = str(getattr(latest_execution, "stderr_text", "") or "").lower()
    params = _safe_json_object(task.params_json)
    reason_text = str(params.get("skip_reason") or params.get("blocked_reason") or params.get("reason") or "").lower()
    missing_dependency = any(
        marker in f"{stderr_text}\n{reason_text}"
        for marker in ("no such file", "not found", "missing", "requires at least one", "no in-scope")
    )

    retry_available = status == "failed" and latest_execution is not None and latest_execution.exit_code != 0 and not missing_dependency
    continue_available = status in {"failed", "blocked"} and bool(params.get("chain_recoverable"))
    return [
        {
            "id": "accept_gap",
            "label": "Accept documented coverage gap",
            "description": "Record that this runner did not add coverage while keeping the gap visible in evidence.",
            "available": True,
            "effect": "records_review_only",
            "dispatches_work": False,
            "creates_tasks": False,
            "active_runtime_mutated": False,
        },
        {
            "id": "create_build_lane_fix",
            "label": "Create build-lane fix request",
            "description": "Create a repo-backed Codex build-lane task with the source task, evidence, and validation boundaries.",
            "available": True,
            "effect": "creates_build_lane_task",
            "dispatches_work": False,
            "creates_tasks": False,
            "creates_build_lane_task": True,
            "active_runtime_mutated": False,
        },
        {
            "id": "retry_runner",
            "label": "Retry failed runner",
            "description": "Retry is only allowed when the evidence shows a transient runner failure and existing dispatch controls can be reused.",
            "available": retry_available,
            "effect": "operator_must_use_existing_run_controls",
            "dispatches_work": False,
            "creates_tasks": False,
            "active_runtime_mutated": False,
            "unavailable_reason": (
                "Retry is not safe here because the evidence points to a missing prerequisite, blocked/skipped state, "
                "or no retry-safe execution failure."
            )
            if not retry_available
            else None,
        },
        {
            "id": "continue_remaining",
            "label": "Continue remaining eligible checks",
            "description": "Continue is only available for chain steps explicitly marked recoverable by the existing assessment-chain flow.",
            "available": continue_available,
            "effect": "operator_must_use_existing_chain_continue_control",
            "dispatches_work": False,
            "creates_tasks": False,
            "active_runtime_mutated": False,
            "unavailable_reason": (
                "The source task is not marked as a recoverable chain gap, so AI cannot safely continue the remaining checks."
            )
            if not continue_available
            else None,
        },
    ]


def _latest_execution(task: Task) -> ToolExecution | None:
    executions = sorted(
        list(task.executions or []),
        key=lambda execution: (execution.updated_at or execution.created_at, execution.id.hex),
    )
    return executions[-1] if executions else None


def _validation_commands_for_repair(task: Task) -> list[str]:
    commands = [
        "python3 scripts/validate_backlog_tasks.py",
        "git diff --check",
    ]
    tool = str(task.tool or "").strip().lower()
    if tool:
        commands.append(f"# Re-run the existing safe validation for {tool} after operator-approved changes.")
    return commands


def _safe_json_object(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _uuid_or_none(value: Any) -> UUID | None:
    try:
        return UUID(str(value))
    except (TypeError, ValueError):
        return None


def _tail_text(value: str | None, *, limit: int = 2000) -> str:
    text = str(value or "")
    if len(text) <= limit:
        return text
    return text[-limit:]
