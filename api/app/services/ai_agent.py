from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from ipaddress import ip_address, ip_network
from typing import Any, Protocol
from urllib.parse import urlparse
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from api.app.config import Settings, get_settings
from api.app.models import AgentProposal, AgentReasoning, Finding, Run, Scope, Task
from api.app.policy.engine import RunClass, normalize_profile_limits
from api.app.services.ai_enrichment import (
    list_agent_proposals_for_run,
    list_agent_reasoning_for_run,
    store_agent_proposal_record,
    store_agent_reasoning_record,
)
from api.app.services.audit import write_audit_event
from api.app.services.chatgpt_oauth import (
    CHATGPT_OAUTH_PROVIDER,
    ChatGPTOAuthError,
    ChatGPTOAuthPostTaskAnalysisProvider,
    chatgpt_oauth_status,
    effective_ai_provider_name,
)
from api.app.services.runs import (
    derive_targets_for_run,
    derive_targets_from_target_map,
    latest_scope_query,
)
from api.app.services.settings import (
    effective_runtime_settings_for_run,
    effective_runtime_settings_for_task,
)


class PostTaskAnalysisError(RuntimeError):
    pass


class AgentProposalReviewError(RuntimeError):
    def __init__(self, message: str, *, reason: str) -> None:
        super().__init__(message)
        self.reason = reason


SUPPORTED_AI_PROPOSAL_TOOLS = {
    "aws-inventory",
    "content-discovery",
    "deserialization-probe",
    "external-osint",
    "httpx",
    "idor-bac",
    "jwt-probe",
    "ldap-enum",
    "llm-probe",
    "nmap",
    "nikto",
    "nuclei",
    "semgrep",
    "session-security",
    "sqlmap",
    "ssrf-probe",
    "vuln-components",
    "xss-extended",
    "xxe-probe",
    "zap",
}

TOOL_LIBRARY_MANUAL_PROPOSAL_TOOLS = {
    "api-assessment",
    "aws-inventory",
    "bloodhound-collect",
    "biz-logic-probe",
    "burp",
    "camera-test",
    "cicd-security",
    "cloud-native",
    "content-discovery",
    "credential-attacks",
    "desktop-client",
    "deserialization-probe",
    "easm-discover",
    "external-osint",
    "external-infra",
    "httpx",
    "idor-bac",
    "impacket-lateral",
    "iot-default-creds",
    "ipv6-discovery",
    "jwt-probe",
    "ldap-enum",
    "llm-probe",
    "mdns-ssdp",
    "metasploit",
    "mobile-android",
    "netexec",
    "network-segmentation",
    "nmap",
    "nikto",
    "nuclei",
    "playwright-web",
    "responder",
    "semgrep",
    "session-security",
    "smart-home",
    "snmp-enum",
    "sqlmap",
    "ssrf-probe",
    "vuln-components",
    "wifi-survey",
    "xss-extended",
    "xxe-probe",
    "zap",
}


@dataclass(frozen=True, slots=True)
class AgentProposalDraft:
    proposed_tool: str
    proposed_target: str
    proposed_params: dict[str, Any] = field(default_factory=dict)
    reasoning_text: str | None = None
    risk_tier: str = "passive"
    priority: int = 100
    confidence_score: float | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class PostTaskAnalysisResult:
    observations: list[dict[str, Any]] = field(default_factory=list)
    hypotheses: list[dict[str, Any]] = field(default_factory=list)
    proposals: list[AgentProposalDraft] = field(default_factory=list)
    model: str | None = None
    llm_tokens_used: int | None = None
    confidence_score: float | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class PostTaskAnalysisOutcome:
    status: str
    reason: str | None = None
    reasoning: AgentReasoning | None = None
    stored_proposal_count: int = 0
    blocked_proposal_count: int = 0
    autonomous_dispatch_count: int = 0
    autonomous_task_ids: list[UUID] = field(default_factory=list)
    autonomous_skipped_count: int = 0


AI_PROPOSAL_REVIEW_BOUNDARY = {
    "message": (
        "AI proposals are suggestions for operator review only; approving one records review intent "
        "and does not create tasks, dispatch tools, grant approvals, deploy packs, or bind runtime packs."
    ),
    "approval_effect": "review_status_only",
    "approved_proposals_dispatch_work": False,
    "operator_controlled_flow_only": True,
    "forbidden_action_classes": [
        "unsupported_tool",
        "out_of_scope_or_denied_target",
        "automatic_execution",
        "automatic_task_queueing",
        "automatic_run_dispatch",
        "automatic_approval",
        "finding_schema_mutation",
        "pack_validation_approval_deployment_or_runtime_binding_bypass",
        "runtime_self_modification",
        "uncontrolled_plugin_installation",
    ],
}

AI_PROPOSAL_AUTONOMOUS_BOUNDARY = {
    "message": (
        "Autonomous mode is enabled for this run. Passive and active in-scope proposals may be "
        "promoted into queued tasks automatically; intrusive proposals stay blocked unless the run "
        "explicitly enables autonomous intrusive execution."
    ),
    "approval_effect": "autonomous_dispatch_with_scope_and_kill_switch_guardrails",
    "approved_proposals_dispatch_work": True,
    "operator_controlled_flow_only": False,
    "forbidden_action_classes": [
        "out_of_scope_or_denied_target",
        "automatic_scope_expansion",
        "intrusive_execution_without_explicit_run_flag",
        "pack_validation_approval_deployment_or_runtime_binding_bypass",
        "runtime_self_modification",
        "uncontrolled_plugin_installation",
    ],
    "kill_switch_halts_queued_autonomous_tasks": True,
}


class PostTaskAnalysisProvider(Protocol):
    name: str

    def analyze(self, context: dict[str, Any]) -> PostTaskAnalysisResult:
        raise NotImplementedError


class DeterministicPostTaskAnalysisProvider:
    name = "deterministic"

    def analyze(self, context: dict[str, Any]) -> PostTaskAnalysisResult:
        task = context.get("task") if isinstance(context.get("task"), dict) else {}
        task_params = task.get("params_json") if isinstance(task.get("params_json"), dict) else {}
        fixture_mode = str(task_params.get("ai_agent_fixture") or "").strip().lower()
        task_tool = str(task.get("tool") or "unknown")
        task_target = str(task.get("target_id") or "").strip()

        proposed_tool = "httpx" if task_tool != "httpx" else "nuclei"
        proposed_target = task_target
        risk_tier = "passive" if proposed_tool == "httpx" else "active"
        if fixture_mode == "unsupported-tool":
            proposed_tool = "unsupported-ai-tool"
        elif fixture_mode == "out-of-scope":
            proposed_target = "203.0.113.250"

        proposal = AgentProposalDraft(
            proposed_tool=proposed_tool,
            proposed_target=proposed_target,
            proposed_params={
                "review_required": True,
                "source_task_id": task.get("id"),
                "source_tool": task_tool,
            },
            reasoning_text=(
                "Review-only AI follow-up proposal generated from the completed task context; "
                "it is not queued or approved automatically."
            ),
            risk_tier=risk_tier,
            priority=40,
            confidence_score=0.71,
            metadata={
                "dispatches_work": False,
                "requires_operator_review": True,
                "fixture_mode": fixture_mode or "standard",
            },
        )
        return PostTaskAnalysisResult(
            observations=[
                {
                    "summary": f"Task {task.get('id')} completed with tool {task_tool}.",
                    "evidence_ref": "task.status",
                }
            ],
            hypotheses=[
                {
                    "summary": "A bounded follow-up may help the operator review task output.",
                    "confidence": 0.71,
                }
            ],
            proposals=[proposal],
            model="deterministic",
            llm_tokens_used=0,
            confidence_score=0.71,
            metadata={"provider_mode": "deterministic-test"},
        )


def build_post_task_analysis_provider(
    settings: Settings,
    *,
    session: Session | None = None,
) -> PostTaskAnalysisProvider | None:
    if not settings.ai_agent_post_task_analysis_enabled:
        return None

    provider_name = effective_ai_provider_name(settings, settings.ai_agent_post_task_analysis_provider)
    if provider_name in {"", "disabled", "none", "off"}:
        return None
    if provider_name in {"deterministic", "mock", "test"}:
        return DeterministicPostTaskAnalysisProvider()
    if provider_name == CHATGPT_OAUTH_PROVIDER:
        if session is None:
            raise PostTaskAnalysisError("chatgpt_oauth post-task analysis requires a database session")
        return ChatGPTOAuthPostTaskAnalysisProvider(session=session, settings=settings)

    raise PostTaskAnalysisError(f"unsupported post-task AI analysis provider: {provider_name}")


def run_post_task_analysis_for_task(
    *,
    session: Session,
    task_id: UUID,
    settings: Settings | None = None,
    provider: PostTaskAnalysisProvider | None = None,
) -> PostTaskAnalysisOutcome:
    task = _load_task(session=session, task_id=task_id)
    if task is None or task.run is None:
        return PostTaskAnalysisOutcome(status="skipped", reason="task_not_found")
    settings = effective_runtime_settings_for_task(
        session,
        task=task,
        settings=settings or get_settings(),
    )
    if not settings.ai_agent_post_task_analysis_enabled:
        return PostTaskAnalysisOutcome(status="skipped", reason="disabled")
    if settings.execution_kill_switch:
        halted_count = _cancel_queued_autonomous_tasks(run=task.run)
        if halted_count:
            write_audit_event(
                session=session,
                actor="system:kill-switch",
                action="run.autonomous_tasks_cancelled",
                object_type="run",
                object_id=str(task.run.id),
                metadata={
                    "reason": "kill_switch",
                    "cancelled_task_count": halted_count,
                },
            )
        return PostTaskAnalysisOutcome(status="skipped", reason="kill_switch")
    if task.status != "completed":
        return PostTaskAnalysisOutcome(status="skipped", reason="task_not_completed")

    scope = session.scalar(latest_scope_query(task.run.engagement_id))
    context = _build_analysis_context(task=task, scope=scope)
    provider_name = effective_ai_provider_name(settings, settings.ai_agent_post_task_analysis_provider)

    try:
        active_provider = provider or build_post_task_analysis_provider(settings, session=session)
        if active_provider is None:
            return PostTaskAnalysisOutcome(status="skipped", reason="provider_not_configured")
        provider_name = active_provider.name
        result = active_provider.analyze(context)
    except Exception as exc:
        reasoning = store_agent_reasoning_record(
            session=session,
            run=task.run,
            task=task,
            reasoning_type="post_task_analysis",
            status="failed",
            context_snapshot=context,
            provider=provider_name or "unknown",
            model=settings.ai_agent_post_task_analysis_model,
            failure_reason=str(exc),
            metadata={
                "dispatches_work": False,
                "error_type": exc.__class__.__name__,
                "post_task_analysis": True,
            },
        )
        return PostTaskAnalysisOutcome(status="failed", reason=str(exc), reasoning=reasoning)

    accepted_drafts, blocked_drafts = _filter_proposal_drafts(
        drafts=list(result.proposals or []),
        context=context,
    )
    accepted_payloads = [_proposal_draft_payload(draft) for draft in accepted_drafts]
    autonomous_mode = bool(task.run.autonomous_mode)
    autonomous_task_ids: list[UUID] = []
    autonomous_dispatch_count = 0
    autonomous_skipped_count = 0
    proposal_payloads = list(accepted_payloads)
    reasoning_dispatches_work = False
    reasoning = store_agent_reasoning_record(
        session=session,
        run=task.run,
        task=task,
        reasoning_type="post_task_analysis",
        status="succeeded",
        context_snapshot=context,
        observations=list(result.observations or []),
        hypotheses=list(result.hypotheses or []),
        proposals=accepted_payloads,
        provider=provider_name,
        model=result.model or settings.ai_agent_post_task_analysis_model,
        llm_tokens_used=result.llm_tokens_used,
        confidence_score=result.confidence_score,
        metadata={
            **dict(result.metadata or {}),
            "dispatches_work": False,
            "post_task_analysis": True,
            "blocked_proposals": blocked_drafts,
            "stored_proposal_count": len(accepted_drafts),
            "blocked_proposal_count": len(blocked_drafts),
            "autonomous_mode": autonomous_mode,
        },
    )
    if autonomous_mode:
        autonomous_proposals = _materialize_autonomous_proposals(
            session=session,
            run=task.run,
            reasoning=reasoning,
            accepted_drafts=accepted_drafts,
            source_task=task,
            proposed_at=datetime.now(tz=UTC),
        )
        autonomous_task_ids = autonomous_proposals["task_ids"]
        autonomous_dispatch_count = autonomous_proposals["dispatch_count"]
        autonomous_skipped_count = autonomous_proposals["skipped_count"]
        proposal_payloads = autonomous_proposals["proposal_payloads"]
        reasoning_dispatches_work = autonomous_dispatch_count > 0
    else:
        for draft in accepted_drafts:
            store_agent_proposal_record(
                session=session,
                reasoning=reasoning,
                proposed_tool=draft.proposed_tool,
                proposed_target=draft.proposed_target,
                proposed_params=draft.proposed_params,
                reasoning_text=draft.reasoning_text,
                risk_tier=draft.risk_tier,
                priority=draft.priority,
                confidence_score=draft.confidence_score,
                metadata={
                    **dict(draft.metadata or {}),
                    "dispatches_work": False,
                    "requires_operator_review": True,
                },
            )

    reasoning.proposals_json = proposal_payloads
    reasoning.metadata_json = {
        **_safe_json_object(reasoning.metadata_json),
        "dispatches_work": reasoning_dispatches_work,
        "autonomous_mode": autonomous_mode,
        "autonomous_dispatch_count": autonomous_dispatch_count,
        "autonomous_skipped_count": autonomous_skipped_count,
        "autonomous_task_ids": [str(task_uuid) for task_uuid in autonomous_task_ids],
    }

    return PostTaskAnalysisOutcome(
        status="succeeded",
        reasoning=reasoning,
        stored_proposal_count=len(accepted_drafts),
        blocked_proposal_count=len(blocked_drafts),
        autonomous_dispatch_count=autonomous_dispatch_count,
        autonomous_task_ids=autonomous_task_ids,
        autonomous_skipped_count=autonomous_skipped_count,
    )


def build_ai_insights_for_run(
    *,
    session: Session,
    run: Run,
    settings: Settings | None = None,
) -> dict[str, Any]:
    settings = effective_runtime_settings_for_run(
        session,
        run=run,
        settings=settings or get_settings(),
    )
    reasoning_records = list_agent_reasoning_for_run(session=session, run_id=run.id)
    proposals = list_agent_proposals_for_run(session=session, run_id=run.id)
    provider_name = effective_ai_provider_name(settings, settings.ai_agent_post_task_analysis_provider)
    provider_status = _ai_insights_provider_status(
        session=session,
        run=run,
        settings=settings,
        provider_name=provider_name,
    )
    return {
        "run_id": run.id,
        "post_task_analysis_enabled": bool(settings.ai_agent_post_task_analysis_enabled),
        "provider": provider_name or "disabled",
        "provider_status": provider_status,
        "reasoning_records": reasoning_records,
        "proposals": proposals,
        "review_boundary": review_boundary_for_run(run),
        "operator_workbench": _build_operator_workbench(
            run=run,
            reasoning_records=reasoning_records,
            proposals=proposals,
            provider_status=provider_status,
            post_task_analysis_enabled=bool(settings.ai_agent_post_task_analysis_enabled),
        ),
    }


def _ai_insights_provider_status(
    *,
    session: Session,
    run: Run,
    settings: Settings,
    provider_name: str,
) -> dict[str, Any]:
    model = str(settings.ai_agent_post_task_analysis_model or "aegispt-post-task-analysis")
    if not settings.ai_agent_post_task_analysis_enabled:
        return {
            "mode": "deterministic",
            "label": "Deterministic mode",
            "status": "disabled",
            "connected": False,
            "model": model,
        }
    if provider_name == CHATGPT_OAUTH_PROVIDER:
        try:
            status = chatgpt_oauth_status(session=session, engagement_id=run.engagement_id, settings=settings)
        except ChatGPTOAuthError:
            status = None
        connected = bool(status and status.connected)
        return {
            "mode": CHATGPT_OAUTH_PROVIDER if connected else "deterministic",
            "label": "ChatGPT connected" if connected else "Deterministic mode",
            "status": "connected" if connected else "not_connected",
            "connected": connected,
            "model": str(settings.chatgpt_oauth_model or settings.ai_agent_post_task_analysis_model or "gpt-5.4"),
            "account_id": getattr(status, "account_id", None) if status else None,
            "reusable_session_available": bool(
                status and getattr(status, "reusable_session_available", False)
            ),
            "reusable_account_id": getattr(status, "reusable_account_id", None) if status else None,
            "token_exposed": bool(status and getattr(status, "token_exposed", False)),
        }
    return {
        "mode": "deterministic",
        "label": "Deterministic mode",
        "status": provider_name or "disabled",
        "connected": False,
        "model": model,
    }


def _build_operator_workbench(
    *,
    run: Run,
    reasoning_records: list[AgentReasoning],
    proposals: list[AgentProposal],
    provider_status: dict[str, Any],
    post_task_analysis_enabled: bool,
) -> dict[str, Any]:
    repair_proposals = [
        proposal for proposal in proposals if _safe_json_object(proposal.metadata_json).get("proposal_kind") == "ai_repair"
    ]
    pending_repair = [proposal for proposal in repair_proposals if proposal.status == "pending_review"]
    build_lane_tasks = [
        summary
        for proposal in repair_proposals
        for summary in [_build_lane_task_summary(proposal)]
        if summary is not None
    ]
    signals = _operator_signal_rows(reasoning_records=reasoning_records, proposals=proposals)
    feature_status = {
        "signal_inbox": {
            "enabled": True,
            "count": len(signals),
            "description": "Stored reasoning, repair proposals, and provider state for this run.",
        },
        "repair_proposals": {
            "enabled": True,
            "pending": len(pending_repair),
            "created": len(repair_proposals),
            "description": "Failed, skipped, and blocked runner outcomes can be explained and handed to the build lane.",
        },
        "finding_enrichment": {
            "enabled": post_task_analysis_enabled or bool(provider_status.get("connected")),
            "description": "Finding enrichment remains review-only and grounded in stored evidence.",
        },
        "report_draft": {
            "enabled": post_task_analysis_enabled or bool(provider_status.get("connected")),
            "description": "Report draft help is available from the Reports page and never changes evidence.",
        },
        "build_lane_handoff": {
            "enabled": True,
            "created": len(build_lane_tasks),
            "description": "AI can create Codex build-lane task files for reviewed repairs without mutating active runtime.",
        },
    }
    provider_ready = bool(provider_status.get("connected")) or provider_status.get("status") not in {"disabled", "not_connected"}
    return {
        "title": "AI Operator Workbench",
        "run_id": str(run.id),
        "provider": {
            **provider_status,
            "ready": provider_ready,
            "needs_connection": provider_status.get("status") == "not_connected",
            "settings_screen": "settings",
        },
        "summary": {
            "signals": len(signals),
            "pending_repair_proposals": len(pending_repair),
            "build_lane_tasks": len(build_lane_tasks),
            "post_task_analysis_enabled": post_task_analysis_enabled,
        },
        "signals": signals,
        "features": feature_status,
        "build_lane_tasks": build_lane_tasks,
        "boundary": {
            "active_runtime_mutated": False,
            "dispatches_work": False,
            "creates_runtime_tasks": False,
            "can_create_build_lane_tasks": True,
            "message": (
                "AI may explain, summarize, and create reviewed Codex build-lane handoff tasks. "
                "It cannot change active runtime state, grant approvals, dispatch tools, or bypass pack gates."
            ),
        },
    }


def _operator_signal_rows(
    *,
    reasoning_records: list[AgentReasoning],
    proposals: list[AgentProposal],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for record in reasoning_records:
        rows.append(
            {
                "id": str(record.id),
                "kind": record.reasoning_type,
                "status": record.status,
                "title": _reasoning_title(record),
                "summary": _reasoning_summary(record),
                "provider": record.provider,
                "task_id": str(record.task_id) if record.task_id else None,
                "created_at": record.created_at.isoformat() if record.created_at else None,
                "updated_at": record.updated_at.isoformat() if record.updated_at else None,
                "has_failure_detail": bool(record.failure_reason),
            }
        )
    for proposal in proposals:
        metadata = _safe_json_object(proposal.metadata_json)
        params = _safe_json_object(proposal.proposed_params_json)
        actions = metadata.get("available_actions") if isinstance(metadata.get("available_actions"), list) else []
        rows.append(
            {
                "id": str(proposal.id),
                "kind": metadata.get("proposal_kind") or "proposal",
                "status": proposal.status,
                "title": params.get("title") or proposal.proposed_tool,
                "summary": params.get("summary") or proposal.reasoning_text or "AI proposal is available for review.",
                "provider": "proposal",
                "proposal_id": str(proposal.id),
                "task_id": metadata.get("source_task_id") or params.get("source_task_id"),
                "available_action_count": len([action for action in actions if action.get("available")]),
                "available_actions": actions,
                "build_lane_task": _build_lane_task_summary(proposal),
                "created_at": proposal.created_at.isoformat() if proposal.created_at else None,
                "updated_at": proposal.updated_at.isoformat() if proposal.updated_at else None,
            }
        )
    return sorted(rows, key=lambda row: row.get("updated_at") or row.get("created_at") or "", reverse=True)[:25]


def _reasoning_title(record: AgentReasoning) -> str:
    if record.reasoning_type == "ai_repair":
        return "Runner failure triaged"
    if record.reasoning_type == "live_ai_signal":
        return "Live AI signal"
    if record.status in {"failed", "error", "blocked"}:
        return "AI reasoning needs review"
    return "AI reasoning record"


def _reasoning_summary(record: AgentReasoning) -> str:
    if record.failure_reason:
        return str(record.failure_reason)
    observations = record.observations_json if isinstance(record.observations_json, list) else []
    first = next((item for item in observations if isinstance(item, dict)), None)
    if first:
        return str(first.get("summary") or first.get("message") or first.get("title") or "Stored AI signal.")
    metadata = _safe_json_object(record.metadata_json)
    return str(metadata.get("analysis_text") or "Stored AI signal.")


def _build_lane_task_summary(proposal: AgentProposal) -> dict[str, Any] | None:
    metadata = _safe_json_object(proposal.metadata_json)
    params = _safe_json_object(proposal.proposed_params_json)
    result = metadata.get("repair_action_result") or params.get("repair_action_result")
    if not isinstance(result, dict):
        return None
    request = result.get("build_lane_fix_request")
    if not isinstance(request, dict) or not request.get("codex_task_id"):
        return None
    return {
        "codex_task_id": request.get("codex_task_id"),
        "task_file": request.get("task_file"),
        "title": request.get("title") or "Build-lane repair task",
        "source_task_id": request.get("source_task_id"),
        "source_run_id": request.get("source_run_id"),
        "recommendation_type": request.get("recommendation_type"),
        "created_from_proposal_id": str(proposal.id),
        "creates_runtime_tasks": False,
    }


def review_agent_proposal(
    *,
    session: Session,
    run: Run,
    proposal_id: UUID,
    actor: str,
    decision: str,
    note: str | None = None,
) -> AgentProposal:
    normalized_decision = str(decision or "").strip().lower()
    if normalized_decision not in {"approved", "rejected"}:
        raise AgentProposalReviewError("proposal decision must be approved or rejected", reason="invalid_decision")

    proposal = session.scalar(
        select(AgentProposal)
        .where(AgentProposal.id == proposal_id, AgentProposal.run_id == run.id)
        .options(selectinload(AgentProposal.agent_reasoning))
    )
    if proposal is None:
        raise AgentProposalReviewError("agent proposal not found for run", reason="not_found")
    if proposal.status != "pending_review":
        raise AgentProposalReviewError("agent proposal has already been reviewed", reason="already_reviewed")

    if normalized_decision == "approved":
        scope = session.scalar(latest_scope_query(run.engagement_id))
        allowed_targets, denied_targets = _review_targets_for_run(run=run, scope=scope)
        _assert_proposal_is_review_approvable(
            proposal=proposal,
            allowed_targets=allowed_targets,
            denied_targets=denied_targets,
        )

    reviewed_at = datetime.now(tz=UTC)
    proposal.status = normalized_decision
    if normalized_decision == "approved":
        proposal.approved_by = actor
        proposal.approved_at = reviewed_at

    proposal.metadata_json = {
        **_safe_json_object(proposal.metadata_json),
        "requires_operator_review": True,
        "reviewed_by": actor,
        "reviewed_at": reviewed_at.isoformat(),
        "review_decision": normalized_decision,
        "review_note": (note or "").strip() or None,
        "dispatches_work": False,
        "creates_tasks": False,
        "grants_approval": False,
        "operator_controlled_flow_only": True,
        "review_boundary": AI_PROPOSAL_REVIEW_BOUNDARY["approval_effect"],
    }
    write_audit_event(
        session=session,
        actor=actor,
        action="agent_proposal.reviewed",
        object_type="agent_proposal",
        object_id=str(proposal.id),
        metadata={
            "run_id": str(run.id),
            "agent_reasoning_id": str(proposal.agent_reasoning_id),
            "decision": normalized_decision,
            "proposed_tool": proposal.proposed_tool,
            "proposed_target": proposal.proposed_target,
            "dispatches_work": False,
            "creates_tasks": False,
            "operator_controlled_flow_only": True,
        },
    )
    session.flush()
    return proposal


def review_boundary_for_run(run: Run | None) -> dict[str, Any]:
    if run is not None and bool(getattr(run, "autonomous_mode", False)):
        return dict(AI_PROPOSAL_AUTONOMOUS_BOUNDARY)
    return dict(AI_PROPOSAL_REVIEW_BOUNDARY)


def _load_task(*, session: Session, task_id: UUID) -> Task | None:
    return session.scalar(
        select(Task)
        .where(Task.id == task_id)
        .options(
            selectinload(Task.executions),
            selectinload(Task.run).selectinload(Run.tasks),
            selectinload(Task.run).selectinload(Run.findings),
            selectinload(Task.run).selectinload(Run.source_inventory_snapshot),
            selectinload(Task.run).selectinload(Run.profile),
        )
    )


def _build_analysis_context(*, task: Task, scope: Scope | None) -> dict[str, Any]:
    run = task.run
    if run is None:
        return {}

    allowed_targets = _allowed_targets(run=run, task=task, scope=scope)
    denied_targets = derive_targets_from_target_map(scope.denylist_json) if scope is not None else []
    return {
        "run": {
            "id": str(run.id),
            "engagement_id": str(run.engagement_id),
            "status": run.status,
            "profile": run.profile.name if run.profile is not None else None,
            "configuration_json": _safe_json_object(run.configuration_json),
            "source_inventory_snapshot_id": (
                str(run.source_inventory_snapshot_id) if run.source_inventory_snapshot_id else None
            ),
        },
        "task": {
            "id": str(task.id),
            "tool": task.tool,
            "target_id": task.target_id,
            "status": task.status,
            "params_json": _safe_json_object(task.params_json),
        },
        "findings": [_finding_context(finding) for finding in list(run.findings or [])[:25]],
        "inventory": _inventory_context(run),
        "scope": {
            "allowed_targets": allowed_targets,
            "denied_targets": denied_targets,
        },
        "guardrails": {
            "creates_tasks": False,
            "executes_tools": False,
            "auto_approves": False,
            "mutates_findings": False,
            "scope_expansion_allowed": False,
        },
    }


def _allowed_targets(*, run: Run, task: Task, scope: Scope | None) -> list[dict[str, str]]:
    targets: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def add(kind: str, value: str | None) -> None:
        normalized = str(value or "").strip()
        if not normalized:
            return
        key = (kind, normalized)
        if key in seen:
            return
        seen.add(key)
        targets.append({"kind": kind, "value": normalized})

    add("task-target", task.target_id)
    configured_targets = task.params_json.get("targets") if isinstance(task.params_json, dict) else None
    if isinstance(configured_targets, list):
        for target in configured_targets:
            if isinstance(target, str):
                add("task-target", target)

    if scope is not None:
        for target in derive_targets_for_run(scope, run):
            add(target["kind"], target["value"])
    else:
        run_targets = _safe_json_object(run.configuration_json).get("targets")
        if isinstance(run_targets, dict):
            for target in derive_targets_from_target_map(run_targets):
                add(target["kind"], target["value"])

    return targets


def _review_targets_for_run(*, run: Run, scope: Scope | None) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    allowed_targets: list[dict[str, str]] = []
    denied_targets = derive_targets_from_target_map(scope.denylist_json) if scope is not None else []
    seen: set[tuple[str, str]] = set()

    def add(kind: str, value: str | None) -> None:
        normalized = str(value or "").strip()
        if not normalized:
            return
        key = (kind, normalized)
        if key in seen:
            return
        seen.add(key)
        allowed_targets.append({"kind": kind, "value": normalized})

    for task in list(run.tasks or []):
        add("task-target", task.target_id)
        configured_targets = task.params_json.get("targets") if isinstance(task.params_json, dict) else None
        if isinstance(configured_targets, list):
            for target in configured_targets:
                if isinstance(target, str):
                    add("task-target", target)

    if scope is not None:
        for target in derive_targets_for_run(scope, run):
            add(target["kind"], target["value"])
    else:
        run_targets = _safe_json_object(run.configuration_json).get("targets")
        if isinstance(run_targets, dict):
            for target in derive_targets_from_target_map(run_targets):
                add(target["kind"], target["value"])

    return allowed_targets, denied_targets


def _assert_proposal_is_review_approvable(
    *,
    proposal: AgentProposal,
    allowed_targets: list[dict[str, str]],
    denied_targets: list[dict[str, str]],
) -> None:
    tool = str(proposal.proposed_tool or "").strip()
    target = str(proposal.proposed_target or "").strip()
    metadata = _safe_json_object(proposal.metadata_json)
    if metadata.get("proposal_kind") == "ai_repair":
        if metadata.get("dispatches_work") is not False or metadata.get("active_runtime_mutated") is not False:
            raise AgentProposalReviewError(
                "AI repair proposals must be isolated review-only drafts",
                reason="repair_boundary_violation",
            )
        if metadata.get("isolated_draft_only") is not True:
            raise AgentProposalReviewError(
                "AI repair proposal is missing its isolated draft boundary",
                reason="repair_boundary_violation",
            )
        if not _target_allowed(target=target, allowed_targets=allowed_targets, denied_targets=denied_targets):
            raise AgentProposalReviewError(
                f"AI repair proposal target is outside approved scope or denied: {target}",
                reason="out_of_scope_target",
            )
        return
    if metadata.get("proposal_kind") == "tool_library_manual_task":
        if tool not in TOOL_LIBRARY_MANUAL_PROPOSAL_TOOLS:
            raise AgentProposalReviewError(
                f"unsupported Tool Library proposal tool cannot be approved: {tool}",
                reason="unsupported_tool",
            )
        if not _target_allowed(target=target, allowed_targets=allowed_targets, denied_targets=denied_targets):
            raise AgentProposalReviewError(
                f"Tool Library proposal target is outside approved scope or denied: {target}",
                reason="out_of_scope_target",
            )
        return
    if tool not in SUPPORTED_AI_PROPOSAL_TOOLS:
        raise AgentProposalReviewError(
            f"unsupported AI proposal tool cannot be approved: {tool}",
            reason="unsupported_tool",
        )
    if not _target_allowed(target=target, allowed_targets=allowed_targets, denied_targets=denied_targets):
        raise AgentProposalReviewError(
            f"AI proposal target is outside approved scope or denied: {target}",
            reason="out_of_scope_target",
        )


def _filter_proposal_drafts(
    *,
    drafts: list[AgentProposalDraft],
    context: dict[str, Any],
) -> tuple[list[AgentProposalDraft], list[dict[str, Any]]]:
    accepted: list[AgentProposalDraft] = []
    blocked: list[dict[str, Any]] = []
    scope = context.get("scope") if isinstance(context.get("scope"), dict) else {}
    allowed_targets = scope.get("allowed_targets") if isinstance(scope.get("allowed_targets"), list) else []
    denied_targets = scope.get("denied_targets") if isinstance(scope.get("denied_targets"), list) else []

    for draft in drafts:
        tool = str(draft.proposed_tool or "").strip()
        target = str(draft.proposed_target or "").strip()
        if tool not in SUPPORTED_AI_PROPOSAL_TOOLS:
            blocked.append(
                {
                    "reason": "unsupported_tool",
                    "proposed_tool": tool,
                    "proposed_target": target,
                }
            )
            continue
        if not _target_allowed(target=target, allowed_targets=allowed_targets, denied_targets=denied_targets):
            blocked.append(
                {
                    "reason": "out_of_scope_target",
                    "proposed_tool": tool,
                    "proposed_target": target,
                }
            )
            continue
        accepted.append(draft)

    return accepted, blocked


def _target_allowed(
    *,
    target: str,
    allowed_targets: list[Any],
    denied_targets: list[Any],
) -> bool:
    if not target:
        return False
    if any(_target_matches_entry(target, entry) for entry in denied_targets):
        return False
    return any(_target_matches_entry(target, entry) for entry in allowed_targets)


def _target_matches_entry(target: str, entry: Any) -> bool:
    if not isinstance(entry, dict):
        return False
    value = str(entry.get("value") or "").strip()
    if not value:
        return False
    if target == value:
        return True

    target_host = _host_candidate(target)
    value_host = _host_candidate(value)
    if target_host and value_host:
        if target_host == value_host:
            return True
        if target_host.endswith(f".{value_host}"):
            return True

    try:
        candidate_ip = ip_address(target_host or target.split(":", 1)[0])
    except ValueError:
        candidate_ip = None
    if candidate_ip is None:
        return False

    try:
        return candidate_ip in ip_network(value, strict=False)
    except ValueError:
        return False


def _host_candidate(value: str) -> str:
    parsed = urlparse(value if "://" in value else f"//{value}")
    return str(parsed.hostname or value.split(":", 1)[0]).strip().lower()


def _proposal_draft_payload(draft: AgentProposalDraft) -> dict[str, Any]:
    return {
        "proposed_tool": draft.proposed_tool,
        "proposed_target": draft.proposed_target,
        "proposed_params": dict(draft.proposed_params or {}),
        "risk_tier": draft.risk_tier,
        "priority": draft.priority,
        "confidence_score": draft.confidence_score,
        "status": "pending_review",
        "dispatches_work": False,
        "requires_operator_review": True,
    }


def _materialize_autonomous_proposals(
    *,
    session: Session,
    run: Run,
    reasoning: AgentReasoning,
    accepted_drafts: list[AgentProposalDraft],
    source_task: Task,
    proposed_at: datetime,
) -> dict[str, Any]:
    task_ids: list[UUID] = []
    dispatch_count = 0
    skipped_count = 0
    proposal_payloads: list[dict[str, Any]] = []

    for index, draft in enumerate(accepted_drafts, start=1):
        normalized_risk = _normalized_risk_tier(draft.risk_tier)
        base_metadata = {
            **dict(draft.metadata or {}),
            "autonomous_mode": True,
            "source_task_id": str(source_task.id),
            "source_tool": source_task.tool,
            "source_target": source_task.target_id,
        }

        if normalized_risk == RunClass.INTRUSIVE.value and not run.autonomous_intrusive_allowed:
            proposal = store_agent_proposal_record(
                session=session,
                reasoning=reasoning,
                proposed_tool=draft.proposed_tool,
                proposed_target=draft.proposed_target,
                proposed_params=draft.proposed_params,
                reasoning_text=draft.reasoning_text,
                risk_tier=normalized_risk,
                priority=draft.priority,
                confidence_score=draft.confidence_score,
                status="skipped",
                metadata={
                    **base_metadata,
                    "dispatches_work": False,
                    "requires_operator_review": False,
                    "autonomous_block_reason": "intrusive_flag_required",
                },
            )
            proposal_payloads.append(_proposal_record_payload(proposal))
            skipped_count += 1
            continue

        existing_task = _find_existing_task_for_proposal(
            run=run,
            proposed_tool=draft.proposed_tool,
            proposed_target=draft.proposed_target,
        )
        if existing_task is not None:
            proposal = store_agent_proposal_record(
                session=session,
                reasoning=reasoning,
                proposed_tool=draft.proposed_tool,
                proposed_target=draft.proposed_target,
                proposed_params=draft.proposed_params,
                reasoning_text=draft.reasoning_text,
                risk_tier=normalized_risk,
                priority=draft.priority,
                confidence_score=draft.confidence_score,
                status="superseded",
                metadata={
                    **base_metadata,
                    "dispatches_work": False,
                    "requires_operator_review": False,
                    "autonomous_block_reason": "duplicate_task_exists",
                    "existing_task_id": str(existing_task.id),
                    "existing_task_status": existing_task.status,
                },
            )
            proposal_payloads.append(_proposal_record_payload(proposal))
            skipped_count += 1
            continue

        task = Task(
            run=run,
            tool=draft.proposed_tool,
            target_id=draft.proposed_target,
            status="queued",
            params_json=_autonomous_task_params(
                run=run,
                proposal_draft=draft,
                source_task=source_task,
                sequence=index,
            ),
        )
        session.add(task)
        session.flush()

        proposal = store_agent_proposal_record(
            session=session,
            reasoning=reasoning,
            proposed_tool=draft.proposed_tool,
            proposed_target=draft.proposed_target,
            proposed_params=draft.proposed_params,
            reasoning_text=draft.reasoning_text,
            risk_tier=normalized_risk,
            priority=draft.priority,
            confidence_score=draft.confidence_score,
            status="approved",
            metadata={
                **base_metadata,
                "dispatches_work": True,
                "creates_tasks": True,
                "requires_operator_review": False,
                "autonomous_dispatch_mode": True,
                "dispatched_task_id": str(task.id),
                "queued_at": proposed_at.isoformat(),
                "dispatch_mode_planned": "configured-dispatch-mode",
            },
        )
        proposal.approved_by = "autonomous-agent"
        proposal.approved_at = proposed_at
        write_audit_event(
            session=session,
            actor="autonomous-agent",
            action="agent_proposal.autonomously_dispatched",
            object_type="agent_proposal",
            object_id=str(proposal.id),
            metadata={
                "run_id": str(run.id),
                "agent_reasoning_id": str(reasoning.id),
                "task_id": str(task.id),
                "proposed_tool": proposal.proposed_tool,
                "proposed_target": proposal.proposed_target,
                "risk_tier": proposal.risk_tier,
            },
        )
        proposal_payloads.append(_proposal_record_payload(proposal))
        task_ids.append(task.id)
        dispatch_count += 1

    return {
        "task_ids": task_ids,
        "dispatch_count": dispatch_count,
        "skipped_count": skipped_count,
        "proposal_payloads": proposal_payloads,
    }


def _normalized_risk_tier(value: str | None) -> str:
    normalized = str(value or "").strip().lower()
    if normalized in {
        RunClass.PASSIVE.value,
        RunClass.ACTIVE.value,
        RunClass.INTRUSIVE.value,
    }:
        return normalized
    return RunClass.PASSIVE.value


def _find_existing_task_for_proposal(
    *,
    run: Run,
    proposed_tool: str,
    proposed_target: str,
) -> Task | None:
    for task in list(run.tasks or []):
        if task.tool != proposed_tool or task.target_id != proposed_target:
            continue
        if task.status in {"cancelled"}:
            continue
        return task
    return None


def _autonomous_task_params(
    *,
    run: Run,
    proposal_draft: AgentProposalDraft,
    source_task: Task,
    sequence: int,
) -> dict[str, Any]:
    profile = run.profile
    profile_name = profile.name if profile is not None else "autonomous-follow-up"
    run_class = _normalized_risk_tier(proposal_draft.risk_tier)
    base_limits = normalize_profile_limits(
        run_class,
        {
            **(dict(profile.limits_json or {}) if profile is not None else {}),
            "tools": [proposal_draft.proposed_tool],
            "required_approvals": 0,
        },
    )
    params = {
        **dict(proposal_draft.proposed_params or {}),
        "target_kind": _target_kind_for_value(proposal_draft.proposed_target),
        "profile_name": profile_name,
        "run_class": run_class,
        "limits": base_limits,
        "autonomous_agent": {
            "enabled": True,
            "sequence": sequence,
            "source_task_id": str(source_task.id),
            "source_tool": source_task.tool,
            "source_target": source_task.target_id,
            "proposed_tool": proposal_draft.proposed_tool,
            "proposed_target": proposal_draft.proposed_target,
            "risk_tier": run_class,
        },
    }
    params.pop("review_required", None)
    if proposal_draft.proposed_tool == "zap":
        params["targets"] = [proposal_draft.proposed_target]
    return params


def _target_kind_for_value(value: str) -> str:
    normalized = str(value or "").strip()
    if not normalized:
        return "target"
    parsed = urlparse(normalized if "://" in normalized else f"//{normalized}")
    host_or_value = str(parsed.hostname or normalized.split(":", 1)[0]).strip()
    if "://" in normalized:
        return "url"
    try:
        ip_network(normalized, strict=False)
        return "cidr"
    except ValueError:
        pass
    try:
        ip_address(host_or_value)
        return "host"
    except ValueError:
        return "domain" if "." in host_or_value else "target"


def _proposal_record_payload(proposal: AgentProposal) -> dict[str, Any]:
    return {
        "id": str(proposal.id),
        "proposed_tool": proposal.proposed_tool,
        "proposed_target": proposal.proposed_target,
        "proposed_params": dict(proposal.proposed_params_json or {}),
        "risk_tier": proposal.risk_tier,
        "priority": proposal.priority,
        "confidence_score": proposal.confidence_score,
        "status": proposal.status,
        "dispatches_work": bool(_safe_json_object(proposal.metadata_json).get("dispatches_work")),
        "requires_operator_review": bool(
            _safe_json_object(proposal.metadata_json).get("requires_operator_review", False)
        ),
    }


def _cancel_queued_autonomous_tasks(*, run: Run) -> int:
    cancelled = 0
    for task in list(run.tasks or []):
        params = task.params_json if isinstance(task.params_json, dict) else {}
        autonomous = params.get("autonomous_agent") if isinstance(params.get("autonomous_agent"), dict) else {}
        if not autonomous.get("enabled") or task.status != "queued":
            continue
        task.status = "cancelled"
        cancelled += 1
    return cancelled


def _finding_context(finding: Finding) -> dict[str, Any]:
    return {
        "id": str(finding.id),
        "title": finding.title,
        "severity": finding.severity,
        "target_id": finding.target_id,
        "evidence_ref": finding.evidence_ref,
        "status": finding.status,
        "summary": finding.summary,
        "methodology_tags": list(finding.methodology_tags or []),
    }


def _inventory_context(run: Run) -> dict[str, Any]:
    snapshot = run.source_inventory_snapshot
    if snapshot is None:
        return {"available": False}
    return {
        "available": True,
        "id": str(snapshot.id),
        "status": snapshot.status,
        "source_tools": list(snapshot.source_tools_json or []),
        "summary": _safe_json_object(snapshot.summary_json),
        "confidence_score": snapshot.confidence_score,
    }


def _safe_json_object(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, dict) else {}
