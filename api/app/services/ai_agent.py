from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from ipaddress import ip_address, ip_network
from typing import Any, Protocol
from urllib.parse import urlparse
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from api.app.config import Settings, get_settings
from api.app.models import AgentProposal, AgentReasoning, Finding, FindingChain, Run, Scope, Task
from api.app.policy.engine import RunClass, normalize_profile_limits
from api.app.services.ai_action_selector import select_next_best_action_for_run
from api.app.services.ai_enrichment import (
    list_agent_proposals_for_run,
    list_agent_reasoning_for_run,
    store_agent_proposal_record,
    store_agent_reasoning_record,
)
from api.app.services.ai_shell_safety import (
    AI_SHELL_DEFAULT_OUTPUT_CAP_CHARS,
    AI_SHELL_TOOL_ID,
    AiShellSafetyError,
    ai_shell_command_sha256,
    normalize_ai_shell_params,
)
from api.app.services.assessment_graph import build_assessment_graph, build_assessment_hypotheses
from api.app.services.audit import write_audit_event
from api.app.services.chatgpt_oauth import (
    CHATGPT_OAUTH_PROVIDER,
    ChatGPTOAuthError,
    ChatGPTOAuthPostTaskAnalysisProvider,
    chatgpt_oauth_status,
    effective_ai_provider_name,
)
from api.app.services.coverage_truth import build_coverage_truth
from api.app.services.finding_chains import refresh_finding_chains_for_run
from api.app.services.run_credential_vault import inject_run_credential_vault_into_task
from api.app.services.runs import (
    derive_targets_for_run,
    derive_targets_from_target_map,
    latest_scope_query,
    pending_approvals,
)
from api.app.services.settings import (
    effective_runtime_settings_for_run,
    effective_runtime_settings_for_task,
)
from api.app.services.task_dispatch import supported_execution_tools


class PostTaskAnalysisError(RuntimeError):
    pass


class AgentProposalReviewError(RuntimeError):
    def __init__(self, message: str, *, reason: str) -> None:
        super().__init__(message)
        self.reason = reason


SUPPORTED_AI_PROPOSAL_TOOLS = {
    AI_SHELL_TOOL_ID,
    "auth-flow",
    "aws-inventory",
    "client-state",
    "content-discovery",
    "crypto-audit",
    "deserialization-probe",
    "external-osint",
    "graphql-probe",
    "headers-security",
    "http-smuggling",
    "httpx",
    "idor-bac",
    "jwt-probe",
    "ldap-enum",
    "llm-probe",
    "logging-probe",
    "nmap",
    "nikto",
    "nuclei",
    "oauth-probe",
    "semgrep",
    "session-security",
    "sqlmap",
    "ssti-probe",
    "ssrf-probe",
    "vuln-components",
    "xss-extended",
    "xxe-probe",
    "zap",
}

TOOL_LIBRARY_MANUAL_PROPOSAL_TOOLS = {
    "api-assessment",
    "auth-flow",
    "aws-inventory",
    "bloodhound-collect",
    "biz-logic-probe",
    "burp",
    "camera-test",
    "cicd-security",
    "cloud-native",
    "client-state",
    "content-discovery",
    "credential-attacks",
    "crypto-audit",
    "desktop-client",
    "deserialization-probe",
    "easm-discover",
    "external-osint",
    "external-infra",
    "graphql-probe",
    "headers-security",
    "http-smuggling",
    "httpx",
    "idor-bac",
    "impacket-lateral",
    "iot-default-creds",
    "ipv6-discovery",
    "jwt-probe",
    "ldap-enum",
    "llm-probe",
    "logging-probe",
    "mdns-ssdp",
    "metasploit",
    "mobile-android",
    "netexec",
    "network-capture",
    "network-segmentation",
    "nmap",
    "nikto",
    "nuclei",
    "oauth-probe",
    "playwright-web",
    "priv-esc-linux",
    "responder",
    "semgrep",
    "session-security",
    "smart-home",
    "snmp-enum",
    "sqlmap",
    "ssti-probe",
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
    summary_text: str | None = None
    thought_text: str | None = None
    action_text: str | None = None
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
        "AI proposals are suggestions until an operator approves them. Approving a standard "
        "in-scope follow-up creates a queued task only; dispatch remains explicit and existing "
        "scope, approval, pack, runtime-binding, credential, and kill-switch controls still apply. "
        "Repair and Tool Library proposals remain review-only."
    ),
    "approval_effect": "operator_approved_queued_task",
    "approved_proposals_dispatch_work": True,
    "approved_proposals_create_queued_tasks": True,
    "operator_controlled_flow_only": True,
    "forbidden_action_classes": [
        "unsupported_tool",
        "out_of_scope_or_denied_target",
        "risk_tier_escalation_without_matching_run_profile",
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

COMPOUND_CHAIN_PROPOSAL_TEMPLATES: dict[str, dict[str, Any]] = {
    "web-file-upload-plus-stored-xss": {
        "proposed_tool": "xss-extended",
        "risk_tier": "active",
        "priority": 12,
        "title": "Validate uploaded-content stored XSS chain",
        "summary": (
            "Review whether file-upload evidence and stored-XSS evidence combine into an "
            "uploaded-content execution path in an authorized review or admin surface."
        ),
        "verification_goal": (
            "Confirm prerequisites with benign proof markers only: uploaded content renders in the "
            "same scoped application context and stored XSS evidence remains observable."
        ),
        "safe_boundaries": {
            "credential_theft": False,
            "session_hijacking": False,
            "admin_impersonation": False,
            "exploit_chaining": False,
            "operator_review_required": True,
        },
    },
    "path-traversal-plus-writable-execution-signal": {
        "proposed_tool": "nuclei",
        "risk_tier": "active",
        "priority": 14,
        "title": "Review traversal-to-execution prerequisites",
        "summary": (
            "Review whether path-traversal evidence and writable/executable-path evidence combine "
            "into a plausible code-execution prerequisite chain."
        ),
        "verification_goal": (
            "Confirm reachability and prerequisite evidence with detection-only checks; do not write "
            "files, place payloads, or execute code from the AI proposal."
        ),
        "safe_boundaries": {
            "file_write": False,
            "code_execution": False,
            "payload_placement": False,
            "exploit_chaining": False,
            "operator_review_required": True,
        },
    },
}

AI_WORKING_MEMORY_MAX_PRIOR_ANALYSES = 5
AI_WORKING_MEMORY_MAX_APPROVED_PROPOSALS = 10
AI_WORKING_MEMORY_MAX_HIGH_PRIORITY_FINDINGS = 10
AI_WORKING_MEMORY_MAX_NARRATIVE_SENTENCES = 5
AI_WORKING_MEMORY_CONTEXT_CHAR_LIMIT = 24_000
AI_WORKING_MEMORY_TEXT_LIMIT = 480


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

        chain_proposals = _compound_chain_proposal_drafts(context=context, task_target=task_target)
        if chain_proposals:
            chain_count = len(
                context.get("finding_chains")
                if isinstance(context.get("finding_chains"), list)
                else []
            )
            summary_text = (
                f"Task {task.get('id')} completed and the current engagement contains "
                f"{chain_count} compound attack-chain signal(s)."
            )
            thought_text = (
                "The stored findings may combine into a compound web path, but the chain remains "
                "a hypothesis until an operator reviews the evidence and approves a bounded follow-up."
            )
            action_text = (
                "Review the compound-chain proposal in Mission Control and approve only a safe, "
                "in-scope validation task if the evidence matches the rules of engagement."
            )
            return PostTaskAnalysisResult(
                summary_text=summary_text,
                thought_text=thought_text,
                action_text=action_text,
                observations=[
                    {
                        "summary": summary_text,
                        "evidence_ref": "finding_chains",
                    }
                ],
                hypotheses=[
                    {
                        "summary": thought_text,
                        "confidence": max(
                            [draft.confidence_score or 0.0 for draft in chain_proposals],
                            default=0.72,
                        ),
                    }
                ],
                proposals=chain_proposals,
                model="deterministic",
                llm_tokens_used=0,
                confidence_score=max(
                    [draft.confidence_score or 0.0 for draft in chain_proposals],
                    default=0.72,
                ),
                metadata={
                    "provider_mode": "deterministic-test",
                    "compound_attack_chain_reasoning": True,
                    "engagement_context_window": True,
                },
            )

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
        summary_text = f"Task {task.get('id')} completed with tool {task_tool}."
        thought_text = "A bounded follow-up may help the operator review task output."
        action_text = (
            f"Review the suggested {proposal.proposed_tool} follow-up for "
            f"{proposal.proposed_target or 'the selected target'} before queueing work."
        )
        return PostTaskAnalysisResult(
            summary_text=summary_text,
            thought_text=thought_text,
            action_text=action_text,
            observations=[
                {
                    "summary": summary_text,
                    "evidence_ref": "task.status",
                }
            ],
            hypotheses=[
                {
                    "summary": thought_text,
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

    provider_name = effective_ai_provider_name(
        settings, settings.ai_agent_post_task_analysis_provider
    )
    if provider_name in {"", "disabled", "none", "off"}:
        return None
    if provider_name in {"deterministic", "mock", "test"}:
        return DeterministicPostTaskAnalysisProvider()
    if provider_name == CHATGPT_OAUTH_PROVIDER:
        if session is None:
            raise PostTaskAnalysisError(
                "chatgpt_oauth post-task analysis requires a database session"
            )
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
    chain_records = refresh_finding_chains_for_run(session=session, run_id=task.run.id)
    context = _build_analysis_context(
        session=session,
        task=task,
        scope=scope,
        finding_chains=chain_records,
    )
    provider_name = effective_ai_provider_name(
        settings, settings.ai_agent_post_task_analysis_provider
    )

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
        summary_text=result.summary_text,
        thought_text=result.thought_text,
        action_text=result.action_text,
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
            proposal = store_agent_proposal_record(
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
            if proposal.proposed_tool == AI_SHELL_TOOL_ID:
                command = str(draft.proposed_params.get("command") or "").strip()
                write_audit_event(
                    session=session,
                    actor="ai-agent",
                    action="ai_shell.command_proposed",
                    object_type="agent_proposal",
                    object_id=str(proposal.id),
                    metadata={
                        "run_id": str(task.run.id),
                        "agent_reasoning_id": str(reasoning.id),
                        "proposed_target": proposal.proposed_target,
                        "risk_tier": proposal.risk_tier,
                        "command_sha256": ai_shell_command_sha256(command) if command else None,
                        "requires_operator_review": True,
                        "dispatches_work": False,
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
    provider_name = effective_ai_provider_name(
        settings, settings.ai_agent_post_task_analysis_provider
    )
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
            session=session,
            run=run,
            reasoning_records=reasoning_records,
            proposals=proposals,
            provider_status=provider_status,
            settings=settings,
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
            status = chatgpt_oauth_status(
                session=session, engagement_id=run.engagement_id, settings=settings
            )
        except ChatGPTOAuthError:
            status = None
        connected = bool(status and status.connected)
        return {
            "mode": CHATGPT_OAUTH_PROVIDER if connected else "deterministic",
            "label": "ChatGPT connected" if connected else "Deterministic mode",
            "status": "connected" if connected else "not_connected",
            "connected": connected,
            "model": str(
                settings.chatgpt_oauth_model
                or settings.ai_agent_post_task_analysis_model
                or "gpt-5.4"
            ),
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
    session: Session,
    run: Run,
    reasoning_records: list[AgentReasoning],
    proposals: list[AgentProposal],
    provider_status: dict[str, Any],
    settings: Settings,
    post_task_analysis_enabled: bool,
) -> dict[str, Any]:
    repair_proposals = [
        proposal
        for proposal in proposals
        if _safe_json_object(proposal.metadata_json).get("proposal_kind") == "ai_repair"
    ]
    pending_repair = [
        proposal for proposal in repair_proposals if proposal.status == "pending_review"
    ]
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
    provider_ready = bool(provider_status.get("connected")) or provider_status.get(
        "status"
    ) not in {"disabled", "not_connected"}
    configuration = _safe_json_object(run.configuration_json)
    loop_state = _safe_json_object(configuration.get("ai_assessment_loop"))
    ai_loop_enabled = configuration.get("run_mode") == "ai_loop" or loop_state.get("run_mode") == "ai_loop"
    ai_loop_payload: dict[str, Any] = {
        "enabled": False,
        "reason": "operator autopilot workbench is gated to run_mode=ai_loop",
        "manual_chain_alternative_preserved": True,
        "fixed_phase_chains_replaced_globally": False,
    }
    if ai_loop_enabled:
        scope = session.scalar(latest_scope_query(run.engagement_id))
        if scope is None:
            ai_loop_payload = {
                "enabled": True,
                "status": "blocked",
                "reason": "engagement scope missing during operator autopilot workbench build",
                "current_goal": _safe_json_object(loop_state.get("goal_oriented_reasoning")),
                "hypotheses": {"hypotheses": []},
                "next_best_actions": {"actions": []},
                "coverage_truth": {},
                "approval_gates": [],
                "blockers": ["missing engagement scope"],
                "execution_contract": {
                    "analysis_only": True,
                    "dispatches_work_directly": False,
                    "mutates_scope": False,
                    "mutates_approvals": False,
                    "runtime_self_modification": False,
                },
            }
        else:
            tested_action_keys = {
                f"{str(task.tool or '').strip()}::{str(task.target_id or '').strip()}"
                for task in list(run.tasks or [])
                if str(task.tool or "").strip() and str(task.target_id or "").strip()
            }
            tested_action_keys.update(
                f"{str(proposal.proposed_tool or '').strip()}::{str(proposal.proposed_target or '').strip()}"
                for proposal in proposals
                if str(proposal.proposed_tool or "").strip() and str(proposal.proposed_target or "").strip()
            )
            graph = build_assessment_graph(session, run=run)
            hypotheses = build_assessment_hypotheses(graph)
            if not list(hypotheses.get("hypotheses") or []):
                goal_reasoning = _safe_json_object(loop_state.get("goal_oriented_reasoning"))
                goal_path = [
                    item
                    for item in list(goal_reasoning.get("hypothesis_path") or [])
                    if isinstance(item, dict)
                ][:5]
                if goal_path:
                    hypotheses = {
                        **hypotheses,
                        "hypotheses": [
                            {
                                "id": step.get("id") or f"goal-hypothesis-{index}",
                                "source_ids": [
                                    str(link.get("id"))
                                    for link in list(step.get("evidence_links") or [])
                                    if isinstance(link, dict) and link.get("id")
                                ],
                                "observed_evidence": {
                                    "objective": goal_reasoning.get("objective"),
                                    "stage": step.get("stage"),
                                    "tool": step.get("tool"),
                                },
                                "inferred_next_question": step.get("reason"),
                                "safe_next_observation_candidates": [
                                    {
                                        "runner": step.get("tool"),
                                        "target_candidates": list(step.get("target_candidates") or []),
                                        "source_ids": [
                                            str(link.get("id"))
                                            for link in list(step.get("evidence_links") or [])
                                            if isinstance(link, dict) and link.get("id")
                                        ],
                                    }
                                ],
                                "missing_prerequisites": [],
                                "confidence": 0.74,
                                "claims_unobserved_impact": False,
                                "unsupported_claims": [],
                            }
                            for index, step in enumerate(goal_path, start=1)
                        ],
                    }
            # backlog-404 — same flag-thread as in assessment_loop.py: when
            # the operator opted into autonomous-intrusive, the selector
            # returns RUN for active/intrusive runners instead of APPROVAL.
            next_best_actions = select_next_best_action_for_run(
                session,
                run=run,
                scope=scope,
                approved_targets=derive_targets_for_run(scope, run),
                tested_action_keys=tested_action_keys,
                settings=settings,
                allow_active_without_review=bool(
                    getattr(run, "autonomous_intrusive_allowed", False)
                ),
            )
            coverage_truth = build_coverage_truth(session, run=run, scope=scope)
            pending_standard_proposals = [
                proposal
                for proposal in proposals
                if proposal.status == "pending_review"
                and _safe_json_object(proposal.metadata_json).get("proposal_kind") != "ai_repair"
            ]
            action_blockers = [
                reason
                for action in list(next_best_actions.get("actions") or [])
                if isinstance(action, dict)
                for reason in list(action.get("blocker_reasons") or [])
                if reason
            ]
            coverage_blockers = list(
                _safe_json_object(coverage_truth.get("stop_condition")).get("blocker_ids") or []
            )
            ai_loop_payload = {
                "enabled": True,
                "status": loop_state.get("status") or "ready",
                "run_mode": "ai_loop",
                "current_goal": _safe_json_object(loop_state.get("goal_oriented_reasoning")),
                "loop_state": {
                    "iteration_count": int(loop_state.get("iteration_count") or 0),
                    "max_iterations": int(loop_state.get("max_iterations") or 20),
                    "no_new_signal_iterations": int(loop_state.get("no_new_signal_iterations") or 0),
                    "latest_next_action": _safe_json_object(loop_state.get("latest_next_action")),
                    "stop_reason": loop_state.get("stop_reason"),
                },
                "hypotheses": hypotheses,
                "next_best_actions": next_best_actions,
                "coverage_truth": coverage_truth,
                "approval_gates": [
                    {
                        "proposal_id": str(proposal.id),
                        "tool": proposal.proposed_tool,
                        "target": proposal.proposed_target,
                        "risk_tier": proposal.risk_tier,
                        "reasoning_text": proposal.reasoning_text,
                        "status": proposal.status,
                        "controlled_proof_review_required": proposal.risk_tier in {"active", "intrusive"},
                        "session_exposure_risk_review": proposal.proposed_tool
                        in {"auth-flow", "session-security", "jwt-probe", "idor-bac", "client-state"},
                    }
                    for proposal in pending_standard_proposals
                ],
                "blockers": [*action_blockers, *coverage_blockers],
                "evidence_links": {
                    "graph_node_count": len(list(graph.get("nodes") or [])),
                    "graph_edge_count": len(list(graph.get("edges") or [])),
                    "source_ids": sorted(
                        {
                            str(source_id)
                            for action in list(next_best_actions.get("actions") or [])[:5]
                            if isinstance(action, dict)
                            for source_id in list(action.get("source_ids") or [])
                        }
                    ),
                },
                "execution_contract": {
                    "analysis_only": True,
                    "continue_uses_existing_assessment_loop_endpoint": True,
                    "proposal_controls_use_existing_review_endpoint": True,
                    "dispatches_work_directly": False,
                    "mutates_scope": False,
                    "mutates_approvals": False,
                    "runtime_self_modification": False,
                    "runner_registry_bypassed": False,
                    "kill_switch_still_authoritative": True,
                },
                "operator_language": {
                    "controlled_proof": "Controlled proof steps remain approval-gated and bounded to recorded evidence.",
                    "canary_evidence": "Canary evidence is preferred where a proof could otherwise expose sensitive material.",
                    "session_exposure_risk": "Session exposure risk is reviewed through redacted evidence and secret-binding controls.",
                },
                "manual_chain_alternative_preserved": True,
                "fixed_phase_chains_replaced_globally": False,
            }
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
        "ai_loop": ai_loop_payload,
        "boundary": {
            "active_runtime_mutated": False,
            "dispatches_work": False,
            "creates_runtime_tasks": "operator_approved_standard_proposals_only",
            "can_create_build_lane_tasks": True,
            "standard_proposal_approval_creates_queued_tasks": True,
            "message": (
                "AI may explain, summarize, and suggest follow-up tasks. Standard proposals only "
                "become queued tasks after operator approval; dispatch stays explicit and AI cannot "
                "grant approvals, execute tools, or bypass pack gates."
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
        actions = (
            metadata.get("available_actions")
            if isinstance(metadata.get("available_actions"), list)
            else []
        )
        rows.append(
            {
                "id": str(proposal.id),
                "kind": metadata.get("proposal_kind") or "proposal",
                "status": proposal.status,
                "title": params.get("title") or proposal.proposed_tool,
                "summary": params.get("summary")
                or proposal.reasoning_text
                or "AI proposal is available for review.",
                "provider": "proposal",
                "proposal_id": str(proposal.id),
                "task_id": metadata.get("source_task_id") or params.get("source_task_id"),
                "available_action_count": len(
                    [action for action in actions if action.get("available")]
                ),
                "available_actions": actions,
                "build_lane_task": _build_lane_task_summary(proposal),
                "created_at": proposal.created_at.isoformat() if proposal.created_at else None,
                "updated_at": proposal.updated_at.isoformat() if proposal.updated_at else None,
            }
        )
    return sorted(
        rows, key=lambda row: row.get("updated_at") or row.get("created_at") or "", reverse=True
    )[:25]


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
        return str(
            first.get("summary")
            or first.get("message")
            or first.get("title")
            or "Stored AI signal."
        )
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
        raise AgentProposalReviewError(
            "proposal decision must be approved or rejected", reason="invalid_decision"
        )

    proposal = session.scalar(
        select(AgentProposal)
        .where(AgentProposal.id == proposal_id, AgentProposal.run_id == run.id)
        .options(selectinload(AgentProposal.agent_reasoning))
    )
    if proposal is None:
        raise AgentProposalReviewError("agent proposal not found for run", reason="not_found")
    if proposal.status != "pending_review":
        raise AgentProposalReviewError(
            "agent proposal has already been reviewed", reason="already_reviewed"
        )

    if normalized_decision == "approved":
        scope = session.scalar(latest_scope_query(run.engagement_id))
        allowed_targets, denied_targets = _review_targets_for_run(run=run, scope=scope)
        _assert_proposal_is_review_approvable(
            proposal=proposal,
            allowed_targets=allowed_targets,
            denied_targets=denied_targets,
        )
        if _proposal_review_creates_queued_task(proposal):
            _assert_proposal_can_queue_task(run=run, proposal=proposal)

    reviewed_at = datetime.now(tz=UTC)
    queued_task: Task | None = None
    proposal.status = normalized_decision
    if normalized_decision == "approved":
        proposal.approved_by = actor
        proposal.approved_at = reviewed_at
        if _proposal_review_creates_queued_task(proposal):
            queued_task = _queue_task_from_reviewed_proposal(
                session=session,
                run=run,
                proposal=proposal,
                actor=actor,
                queued_at=reviewed_at,
            )

    creates_task = queued_task is not None
    ai_shell_review_metadata: dict[str, Any] = {}
    if proposal.proposed_tool == AI_SHELL_TOOL_ID:
        command = str(_safe_json_object(proposal.proposed_params_json).get("command") or "").strip()
        if command:
            ai_shell_review_metadata = {
                "ai_shell_command_sha256": ai_shell_command_sha256(command),
                "ai_shell_per_command_approval": True,
                "ai_shell_ssh_only": True,
                "ai_shell_output_cap_chars": AI_SHELL_DEFAULT_OUTPUT_CAP_CHARS,
            }
    proposal.metadata_json = {
        **_safe_json_object(proposal.metadata_json),
        "requires_operator_review": True,
        "reviewed_by": actor,
        "reviewed_at": reviewed_at.isoformat(),
        "review_decision": normalized_decision,
        "review_note": (note or "").strip() or None,
        "dispatches_work": creates_task,
        "creates_tasks": creates_task,
        "queued_task_id": str(queued_task.id) if queued_task is not None else None,
        "queued_task_status": queued_task.status if queued_task is not None else None,
        "grants_approval": False,
        "operator_controlled_flow_only": True,
        "review_boundary": (
            "operator_approved_queued_task"
            if creates_task
            else AI_PROPOSAL_REVIEW_BOUNDARY["approval_effect"]
        ),
        **ai_shell_review_metadata,
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
            "dispatches_work": creates_task,
            "creates_tasks": creates_task,
            "queued_task_id": str(queued_task.id) if queued_task is not None else None,
            "operator_controlled_flow_only": True,
            **ai_shell_review_metadata,
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


def _build_analysis_context(
    *,
    session: Session,
    task: Task,
    scope: Scope | None,
    finding_chains: list[FindingChain] | None = None,
) -> dict[str, Any]:
    run = task.run
    if run is None:
        return {}

    allowed_targets = _allowed_targets(run=run, task=task, scope=scope)
    denied_targets = (
        derive_targets_from_target_map(scope.denylist_json) if scope is not None else []
    )
    engagement_findings = _engagement_findings_for_analysis(session=session, run=run)
    engagement_context = _build_engagement_working_memory_context(
        session=session,
        run=run,
        task=task,
        engagement_findings=engagement_findings,
    )
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
            "autonomous_mode": bool(run.autonomous_mode),
        },
        "task": {
            "id": str(task.id),
            "tool": task.tool,
            "target_id": task.target_id,
            "status": task.status,
            "params_json": _safe_json_object(task.params_json),
        },
        "findings": [_finding_context(finding) for finding in list(run.findings or [])[:25]],
        "engagement_findings": [_finding_context(finding) for finding in engagement_findings],
        "engagement_context": engagement_context,
        "finding_chains": [
            _finding_chain_context(chain)
            for chain in sorted(
                finding_chains or [],
                key=lambda item: (item.confidence_score, str(item.id)),
                reverse=True,
            )[:10]
        ],
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
            "stores_additive_chain_records": True,
            "scope_expansion_allowed": False,
        },
    }


def _build_engagement_working_memory_context(
    *,
    session: Session,
    run: Run,
    task: Task,
    engagement_findings: list[Finding],
) -> dict[str, Any]:
    prior_analyses = _prior_task_analysis_context(
        session=session,
        run=run,
        current_task=task,
    )
    approved_proposals = _approved_proposal_context(
        session=session,
        run=run,
    )
    finding_summary = _engagement_finding_summary_context(engagement_findings)
    attack_narrative = _attack_narrative_context(
        prior_analyses=prior_analyses,
        approved_proposals=approved_proposals,
        finding_summary=finding_summary,
    )
    context = {
        "engagement_id": str(run.engagement_id),
        "current_run_id": str(run.id),
        "current_task_id": str(task.id),
        "prior_task_analyses": prior_analyses,
        "approved_proposals": approved_proposals,
        "finding_summary": finding_summary,
        "attack_narrative": attack_narrative,
        "limits": {
            "max_prior_task_analyses": AI_WORKING_MEMORY_MAX_PRIOR_ANALYSES,
            "max_approved_proposals": AI_WORKING_MEMORY_MAX_APPROVED_PROPOSALS,
            "max_high_priority_findings": AI_WORKING_MEMORY_MAX_HIGH_PRIORITY_FINDINGS,
            "max_attack_narrative_sentences": AI_WORKING_MEMORY_MAX_NARRATIVE_SENTENCES,
            "max_serialized_chars": AI_WORKING_MEMORY_CONTEXT_CHAR_LIMIT,
        },
        "boundary": {
            "advisory_context_only": True,
            "creates_tasks": False,
            "executes_tools": False,
            "auto_approves": False,
            "mutates_findings": False,
            "scope_expansion_allowed": False,
        },
    }
    return _cap_working_memory_context(context)


def _prior_task_analysis_context(
    *,
    session: Session,
    run: Run,
    current_task: Task,
) -> list[dict[str, Any]]:
    records = list(
        session.scalars(
            select(AgentReasoning)
            .join(Run, AgentReasoning.run_id == Run.id)
            .where(
                Run.engagement_id == run.engagement_id,
                Run.deleted_at.is_(None),
                AgentReasoning.task_id.is_not(None),
                AgentReasoning.task_id != current_task.id,
                AgentReasoning.reasoning_type == "post_task_analysis",
            )
            .options(selectinload(AgentReasoning.task), selectinload(AgentReasoning.proposals))
            .order_by(
                AgentReasoning.created_at.desc(),
                AgentReasoning.updated_at.desc(),
                AgentReasoning.id.desc(),
            )
            .limit(AI_WORKING_MEMORY_MAX_PRIOR_ANALYSES)
        ).all()
    )
    rows: list[dict[str, Any]] = []
    for record in records:
        task = record.task
        rows.append(
            {
                "id": str(record.id),
                "run_id": str(record.run_id),
                "task_id": str(record.task_id) if record.task_id else None,
                "task_tool": task.tool if task is not None else None,
                "task_target": task.target_id if task is not None else None,
                "status": record.status,
                "created_at": record.created_at.isoformat() if record.created_at else None,
                "summary_text": _trim_working_memory_text(record.summary_text),
                "thought_text": _trim_working_memory_text(record.thought_text),
                "action_text": _trim_working_memory_text(record.action_text),
                "hypotheses": _bounded_json_object_list(
                    record.hypotheses_json,
                    limit=3,
                    text_limit=AI_WORKING_MEMORY_TEXT_LIMIT,
                ),
                "confirmed_proposals": [
                    _proposal_memory_summary(proposal)
                    for proposal in list(record.proposals or [])
                    if proposal.status == "approved"
                ][:3],
            }
        )
    return rows


def _approved_proposal_context(
    *,
    session: Session,
    run: Run,
) -> list[dict[str, Any]]:
    proposals = list(
        session.scalars(
            select(AgentProposal)
            .join(Run, AgentProposal.run_id == Run.id)
            .where(
                Run.engagement_id == run.engagement_id,
                Run.deleted_at.is_(None),
                AgentProposal.status == "approved",
            )
            .options(selectinload(AgentProposal.agent_reasoning))
            .order_by(
                AgentProposal.approved_at.desc().nullslast(),
                AgentProposal.updated_at.desc(),
                AgentProposal.created_at.desc(),
                AgentProposal.id.desc(),
            )
            .limit(AI_WORKING_MEMORY_MAX_APPROVED_PROPOSALS)
        ).all()
    )
    return [_proposal_memory_summary(proposal, session=session) for proposal in proposals]


def _proposal_memory_summary(
    proposal: AgentProposal,
    *,
    session: Session | None = None,
) -> dict[str, Any]:
    metadata = _safe_json_object(proposal.metadata_json)
    queued_task_id = _first_non_empty_value(
        metadata.get("queued_task_id"),
        metadata.get("dispatched_task_id"),
    )
    queued_task = None
    if session is not None and queued_task_id:
        try:
            queued_task = session.get(Task, UUID(str(queued_task_id)))
        except ValueError:
            queued_task = None
    finding_outcome = _proposal_finding_outcome(session=session, proposal=proposal)
    return {
        "id": str(proposal.id),
        "run_id": str(proposal.run_id),
        "agent_reasoning_id": str(proposal.agent_reasoning_id),
        "status": proposal.status,
        "proposed_tool": proposal.proposed_tool,
        "proposed_target": proposal.proposed_target,
        "risk_tier": proposal.risk_tier,
        "reasoning_text": _trim_working_memory_text(proposal.reasoning_text),
        "approved_by": proposal.approved_by,
        "approved_at": proposal.approved_at.isoformat() if proposal.approved_at else None,
        "outcome": {
            "dispatches_work": bool(metadata.get("dispatches_work")),
            "creates_tasks": bool(metadata.get("creates_tasks")),
            "queued_task_id": str(queued_task.id) if queued_task is not None else queued_task_id,
            "queued_task_status": (
                queued_task.status
                if queued_task is not None
                else metadata.get("queued_task_status")
            ),
            "finding_outcome": finding_outcome,
        },
    }


def _proposal_finding_outcome(
    *,
    session: Session | None,
    proposal: AgentProposal,
) -> dict[str, Any]:
    if session is None:
        return {"available": False}
    findings = list(
        session.scalars(
            select(Finding)
            .where(
                Finding.run_id == proposal.run_id,
                Finding.target_id == proposal.proposed_target,
            )
            .order_by(
                Finding.created_at.desc(),
                Finding.id.desc(),
            )
            .limit(10)
        ).all()
    )
    severity_counts = _severity_counts(findings)
    high_priority = [
        _high_priority_finding_summary(finding)
        for finding in sorted(
            findings,
            key=lambda item: (
                _severity_rank(item.severity),
                item.created_at or datetime.min.replace(tzinfo=UTC),
                str(item.id),
            ),
            reverse=True,
        )
        if _severity_rank(finding.severity) >= _severity_rank("high")
    ][:3]
    return {
        "available": bool(findings),
        "finding_count": len(findings),
        "severity_counts": severity_counts,
        "high_priority_findings": high_priority,
    }


def _engagement_finding_summary_context(findings: list[Finding]) -> dict[str, Any]:
    severity_counts = _severity_counts(findings)
    target_ids = sorted(
        {str(finding.target_id) for finding in findings if str(finding.target_id).strip()}
    )
    high_priority = [
        _high_priority_finding_summary(finding)
        for finding in sorted(
            findings,
            key=lambda item: (
                _severity_rank(item.severity),
                item.created_at or datetime.min.replace(tzinfo=UTC),
                str(item.id),
            ),
            reverse=True,
        )
        if _severity_rank(finding.severity) >= _severity_rank("high")
    ][:AI_WORKING_MEMORY_MAX_HIGH_PRIORITY_FINDINGS]
    return {
        "total": len(findings),
        "severity_counts": severity_counts,
        "target_count": len(target_ids),
        "targets": target_ids[:20],
        "high_priority_findings": high_priority,
    }


def _attack_narrative_context(
    *,
    prior_analyses: list[dict[str, Any]],
    approved_proposals: list[dict[str, Any]],
    finding_summary: dict[str, Any],
) -> dict[str, Any]:
    sentences: list[str] = []
    severity_counts = finding_summary.get("severity_counts")
    if isinstance(severity_counts, dict) and finding_summary.get("total"):
        counts = ", ".join(
            f"{severity}={count}" for severity, count in severity_counts.items() if count
        )
        sentences.append(
            f"The engagement currently has {finding_summary.get('total')} recorded finding(s)"
            + (f" ({counts})." if counts else ".")
        )
    elif prior_analyses:
        sentences.append("The engagement has prior AI task analysis but no stored findings yet.")
    else:
        sentences.append("No prior engagement findings or AI task analyses are available yet.")

    first_analysis = next(
        (item for item in prior_analyses if str(item.get("summary_text") or "").strip()),
        None,
    )
    if first_analysis is not None:
        sentences.append(
            "Recent task memory: " f"{_sentence_fragment(first_analysis.get('summary_text'))}."
        )

    high_priority = finding_summary.get("high_priority_findings")
    if isinstance(high_priority, list) and high_priority:
        top_titles = [
            str(item.get("title") or "").strip()
            for item in high_priority[:3]
            if isinstance(item, dict) and str(item.get("title") or "").strip()
        ]
        if top_titles:
            sentences.append(
                "High-priority evidence centers on " f"{_sentence_fragment('; '.join(top_titles))}."
            )

    if approved_proposals:
        proposal_bits = [
            f"{item.get('proposed_tool')} on {item.get('proposed_target')}"
            for item in approved_proposals[:3]
            if isinstance(item, dict) and item.get("proposed_tool") and item.get("proposed_target")
        ]
        if proposal_bits:
            sentences.append(
                "Approved follow-up history includes "
                f"{_sentence_fragment('; '.join(proposal_bits))}."
            )

    sentences.append(
        "Use this memory only as bounded advisory context; scope, ROE, approvals, runtime binding, and kill switch remain authoritative."
    )
    bounded_sentences = sentences[:AI_WORKING_MEMORY_MAX_NARRATIVE_SENTENCES]
    return {
        "text": " ".join(bounded_sentences),
        "sentences": bounded_sentences,
        "sentence_count": len(bounded_sentences),
        "generated_from": [
            "prior_task_analyses",
            "approved_proposals",
            "engagement_findings",
        ],
        "bounded": True,
    }


def _cap_working_memory_context(context: dict[str, Any]) -> dict[str, Any]:
    capped = dict(context)
    capped["estimated_serialized_chars"] = _json_char_count(capped)
    if capped["estimated_serialized_chars"] <= AI_WORKING_MEMORY_CONTEXT_CHAR_LIMIT:
        return capped

    high_priority = (
        capped.get("finding_summary", {}).get("high_priority_findings")
        if isinstance(capped.get("finding_summary"), dict)
        else []
    )
    if isinstance(high_priority, list):
        capped["finding_summary"] = {
            **dict(capped.get("finding_summary") or {}),
            "high_priority_findings": high_priority[:5],
        }
    proposals = capped.get("approved_proposals")
    if isinstance(proposals, list):
        capped["approved_proposals"] = proposals[:5]
    analyses = capped.get("prior_task_analyses")
    if isinstance(analyses, list):
        capped["prior_task_analyses"] = analyses[:3]

    capped["truncated"] = True
    capped["truncation_reason"] = "serialized_context_char_limit"
    capped["estimated_serialized_chars"] = _json_char_count(capped)
    return capped


def _severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "unknown": 0}
    for finding in findings:
        severity = str(finding.severity or "").strip().lower() or "unknown"
        if severity not in counts:
            severity = "unknown"
        counts[severity] += 1
    return counts


def _severity_rank(value: str | None) -> int:
    return {
        "critical": 5,
        "high": 4,
        "medium": 3,
        "low": 2,
        "info": 1,
    }.get(str(value or "").strip().lower(), 0)


def _high_priority_finding_summary(finding: Finding) -> dict[str, Any]:
    return {
        "id": str(finding.id),
        "run_id": str(finding.run_id) if finding.run_id else None,
        "title": _trim_working_memory_text(finding.title, limit=220),
        "severity": finding.severity,
        "target_id": finding.target_id,
        "status": finding.status,
        "summary": _trim_working_memory_text(finding.summary, limit=320),
        "evidence_ref": finding.evidence_ref,
    }


def _bounded_json_object_list(
    value: Any,
    *,
    limit: int,
    text_limit: int,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not isinstance(value, list):
        return rows
    for item in value:
        if not isinstance(item, dict):
            continue
        rows.append(
            {
                str(key): (
                    _trim_working_memory_text(raw, limit=text_limit)
                    if isinstance(raw, str)
                    else raw
                )
                for key, raw in item.items()
            }
        )
        if len(rows) >= limit:
            break
    return rows


def _trim_working_memory_text(value: Any, *, limit: int = AI_WORKING_MEMORY_TEXT_LIMIT) -> str:
    text = str(value or "").strip()
    if len(text) <= limit:
        return text
    return f"{text[: max(limit - 12, 0)].rstrip()} [truncated]"


def _sentence_fragment(value: Any) -> str:
    text = _trim_working_memory_text(value, limit=360).rstrip(". ")
    return text or "no additional detail"


def _first_non_empty_value(*values: Any) -> str | None:
    for value in values:
        text = str(value or "").strip()
        if text:
            return text
    return None


def _json_char_count(value: Any) -> int:
    return len(json.dumps(value, sort_keys=True, default=str))


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
    configured_targets = (
        task.params_json.get("targets") if isinstance(task.params_json, dict) else None
    )
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


def _review_targets_for_run(
    *, run: Run, scope: Scope | None
) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    allowed_targets: list[dict[str, str]] = []
    denied_targets = (
        derive_targets_from_target_map(scope.denylist_json) if scope is not None else []
    )
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
        configured_targets = (
            task.params_json.get("targets") if isinstance(task.params_json, dict) else None
        )
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
        if (
            metadata.get("dispatches_work") is not False
            or metadata.get("active_runtime_mutated") is not False
        ):
            raise AgentProposalReviewError(
                "AI repair proposals must be isolated review-only drafts",
                reason="repair_boundary_violation",
            )
        if metadata.get("isolated_draft_only") is not True:
            raise AgentProposalReviewError(
                "AI repair proposal is missing its isolated draft boundary",
                reason="repair_boundary_violation",
            )
        if not _target_allowed(
            target=target, allowed_targets=allowed_targets, denied_targets=denied_targets
        ):
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
        if not _target_allowed(
            target=target, allowed_targets=allowed_targets, denied_targets=denied_targets
        ):
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
    if not _target_allowed(
        target=target, allowed_targets=allowed_targets, denied_targets=denied_targets
    ):
        raise AgentProposalReviewError(
            f"AI proposal target is outside approved scope or denied: {target}",
            reason="out_of_scope_target",
        )
    if tool == AI_SHELL_TOOL_ID:
        _assert_ai_shell_proposal_contract(
            proposal=proposal,
            allowed_targets=allowed_targets,
        )


def _assert_ai_shell_proposal_contract(
    *,
    proposal: AgentProposal,
    allowed_targets: list[dict[str, str]],
) -> None:
    try:
        normalize_ai_shell_params(
            params=_safe_json_object(proposal.proposed_params_json),
            proposed_target=str(proposal.proposed_target or ""),
            allowed_target_entries=allowed_targets,
            require_runtime_scope=False,
        )
    except AiShellSafetyError as exc:
        raise AgentProposalReviewError(str(exc), reason=exc.reason) from exc


def _ai_shell_disabled_for_run(run: Run) -> bool:
    configuration = _safe_json_object(run.configuration_json)
    ai_shell = (
        configuration.get("ai_shell") if isinstance(configuration.get("ai_shell"), dict) else {}
    )
    safety = configuration.get("safety") if isinstance(configuration.get("safety"), dict) else {}
    return bool(
        ai_shell.get("enabled") is False
        or ai_shell.get("kill_switch") is True
        or safety.get("ai_shell_enabled") is False
    )


def _proposal_review_creates_queued_task(proposal: AgentProposal) -> bool:
    metadata = _safe_json_object(proposal.metadata_json)
    params = _safe_json_object(proposal.proposed_params_json)
    boundary = params.get("boundary") if isinstance(params.get("boundary"), dict) else {}
    proposal_kind = str(metadata.get("proposal_kind") or "").strip().lower()
    if proposal_kind in {"ai_repair", "tool_library_manual_task"}:
        return False
    if boundary.get("isolated_draft_only") is True:
        return False
    return True


def _assert_proposal_can_queue_task(*, run: Run, proposal: AgentProposal) -> None:
    run_status = str(run.status or "").strip().lower()
    if run_status in {"cancelled", "cancelling", "rejected"}:
        raise AgentProposalReviewError(
            "AI proposal cannot queue a task for a cancelled or rejected run",
            reason="run_not_dispatchable",
        )

    tool = str(proposal.proposed_tool or "").strip()
    if tool not in supported_execution_tools():
        raise AgentProposalReviewError(
            f"unsupported execution tool cannot be queued from AI proposal: {tool}",
            reason="unsupported_tool",
        )
    if tool == AI_SHELL_TOOL_ID and _ai_shell_disabled_for_run(run):
        raise AgentProposalReviewError(
            "ai-shell is disabled for this engagement/run by configuration",
            reason="ai_shell_disabled",
        )

    proposal_risk = _normalized_risk_tier(proposal.risk_tier)
    profile_risk = _normalized_risk_tier(run.profile.run_class if run.profile is not None else None)
    if _risk_tier_rank(proposal_risk) > _risk_tier_rank(profile_risk):
        raise AgentProposalReviewError(
            (
                f"AI proposal risk tier {proposal_risk} exceeds selected run profile "
                f"risk tier {profile_risk}; create an appropriately approved run instead"
            ),
            reason="risk_tier_escalation",
        )

    if run.profile is not None and pending_approvals(run, run.profile) > 0:
        raise AgentProposalReviewError(
            "AI proposal cannot queue a task while the selected run still has pending approvals",
            reason="pending_run_approval",
        )

    if (
        _find_existing_task_for_proposal(
            run=run,
            proposed_tool=proposal.proposed_tool,
            proposed_target=proposal.proposed_target,
        )
        is not None
    ):
        raise AgentProposalReviewError(
            "AI proposal already has a matching task on this run",
            reason="duplicate_task_exists",
        )


def _risk_tier_rank(value: str | None) -> int:
    normalized = _normalized_risk_tier(value)
    return {
        RunClass.PASSIVE.value: 0,
        RunClass.ACTIVE.value: 1,
        RunClass.INTRUSIVE.value: 2,
    }.get(normalized, 0)


def _queue_task_from_reviewed_proposal(
    *,
    session: Session,
    run: Run,
    proposal: AgentProposal,
    actor: str,
    queued_at: datetime,
) -> Task:
    params = _approved_proposal_task_params(
        run=run,
        proposal=proposal,
        actor=actor,
        queued_at=queued_at,
    )
    task = Task(
        run=run,
        tool=proposal.proposed_tool,
        target_id=proposal.proposed_target,
        status="queued",
        params_json=params,
    )
    session.add(task)
    session.flush()
    inject_run_credential_vault_into_task(
        session,
        run=run,
        task=task,
        actor=actor,
    )
    if str(run.status or "").lower() not in {"cancelled", "cancelling", "rejected"}:
        run.status = "queued"
    write_audit_event(
        session=session,
        actor=actor,
        action="agent_proposal.task_queued",
        object_type="task",
        object_id=str(task.id),
        metadata={
            "run_id": str(run.id),
            "agent_proposal_id": str(proposal.id),
            "agent_reasoning_id": str(proposal.agent_reasoning_id),
            "proposed_tool": proposal.proposed_tool,
            "proposed_target": proposal.proposed_target,
            "risk_tier": proposal.risk_tier,
            "dispatch_mode": "queued_not_dispatched",
            "operator_controlled_flow_only": True,
        },
    )
    return task


def _approved_proposal_task_params(
    *,
    run: Run,
    proposal: AgentProposal,
    actor: str,
    queued_at: datetime,
) -> dict[str, Any]:
    profile = run.profile
    run_class = _normalized_risk_tier(proposal.risk_tier)
    profile_name = profile.name if profile is not None else "ai-proposal-follow-up"
    normalized_limits = normalize_profile_limits(
        run_class,
        {
            **(dict(profile.limits_json or {}) if profile is not None else {}),
            "tools": [proposal.proposed_tool],
        },
    )
    params = {
        **_safe_json_object(proposal.proposed_params_json),
        "target_kind": _target_kind_for_value(proposal.proposed_target),
        "profile_name": profile_name,
        "run_class": run_class,
        "limits": normalized_limits,
        "ai_proposal": {
            "enabled": True,
            "reviewed_by": actor,
            "reviewed_at": queued_at.isoformat(),
            "proposal_id": str(proposal.id),
            "agent_reasoning_id": str(proposal.agent_reasoning_id),
            "proposed_tool": proposal.proposed_tool,
            "proposed_target": proposal.proposed_target,
            "risk_tier": run_class,
            "confidence_score": proposal.confidence_score,
            "dispatch_mode": "queued_not_dispatched",
            "approval_effect": "operator_approved_queued_task",
        },
    }
    cve_context = params.get("on_demand_cve_intelligence")
    if isinstance(cve_context, dict):
        params["on_demand_cve_intelligence"] = {
            **cve_context,
            "operator_approved": True,
            "queued_by": actor,
            "queued_at": queued_at.isoformat(),
            "automatic_tests_started": False,
        }
    params.pop("review_required", None)
    if proposal.proposed_tool == "zap":
        params["targets"] = [proposal.proposed_target]
    if proposal.proposed_tool == AI_SHELL_TOOL_ID:
        contract = normalize_ai_shell_params(
            params=params,
            proposed_target=proposal.proposed_target,
            require_runtime_scope=False,
        )
        params.update(
            {
                "command": contract.command,
                "via": contract.via,
                "credentials_ref": contract.credentials_ref,
                "target": contract.target,
                "ssh_port": contract.ssh_port,
                "output_cap_chars": contract.output_cap_chars,
                "ai_shell": {
                    "enabled": True,
                    "ssh_only": True,
                    "requires_credentials_ref": True,
                    "per_command_approval_required": True,
                    "approved_by": actor,
                    "approved_at": queued_at.isoformat(),
                    "command_sha256": contract.command_sha256,
                    "output_cap_chars": contract.output_cap_chars,
                    "approval_effect": "operator_approved_queued_task",
                },
            }
        )
        if contract.username:
            params["username"] = contract.username
    return params


def _filter_proposal_drafts(
    *,
    drafts: list[AgentProposalDraft],
    context: dict[str, Any],
) -> tuple[list[AgentProposalDraft], list[dict[str, Any]]]:
    accepted: list[AgentProposalDraft] = []
    blocked: list[dict[str, Any]] = []
    scope = context.get("scope") if isinstance(context.get("scope"), dict) else {}
    allowed_targets = (
        scope.get("allowed_targets") if isinstance(scope.get("allowed_targets"), list) else []
    )
    denied_targets = (
        scope.get("denied_targets") if isinstance(scope.get("denied_targets"), list) else []
    )

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
        if not _target_allowed(
            target=target, allowed_targets=allowed_targets, denied_targets=denied_targets
        ):
            blocked.append(
                {
                    "reason": "out_of_scope_target",
                    "proposed_tool": tool,
                    "proposed_target": target,
                }
            )
            continue
        if tool == AI_SHELL_TOOL_ID:
            try:
                normalize_ai_shell_params(
                    params=draft.proposed_params,
                    proposed_target=target,
                    allowed_target_entries=allowed_targets,
                    require_runtime_scope=False,
                )
            except AiShellSafetyError as exc:
                blocked.append(
                    {
                        "reason": exc.reason,
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

        if draft.proposed_tool == AI_SHELL_TOOL_ID:
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
                status="pending_review",
                metadata={
                    **base_metadata,
                    "dispatches_work": False,
                    "requires_operator_review": True,
                    "autonomous_block_reason": "ai_shell_per_command_review_required",
                    "per_command_approval_required": True,
                },
            )
            proposal_payloads.append(_proposal_record_payload(proposal))
            skipped_count += 1
            continue

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


def _compound_chain_proposal_drafts(
    *,
    context: dict[str, Any],
    task_target: str,
) -> list[AgentProposalDraft]:
    run_context = context.get("run") if isinstance(context.get("run"), dict) else {}
    if run_context.get("autonomous_mode") is True:
        return []

    chains = (
        context.get("finding_chains") if isinstance(context.get("finding_chains"), list) else []
    )
    drafts: list[AgentProposalDraft] = []
    for chain in chains:
        if not isinstance(chain, dict):
            continue
        pattern_id = str(chain.get("pattern_id") or "").strip()
        template = COMPOUND_CHAIN_PROPOSAL_TEMPLATES.get(pattern_id)
        if template is None:
            continue
        target = _chain_proposal_target(chain=chain, fallback_target=task_target)
        component_ids = [
            str(item)
            for item in list(chain.get("component_finding_ids") or [])
            if str(item).strip()
        ]
        evidence_refs = [
            str(item) for item in list(chain.get("evidence_refs") or []) if str(item).strip()
        ]
        confidence = _chain_confidence(chain)
        title = str(template["title"])
        summary = str(template["summary"])
        safe_boundaries = dict(template.get("safe_boundaries") or {})
        drafts.append(
            AgentProposalDraft(
                proposed_tool=str(template["proposed_tool"]),
                proposed_target=target,
                proposed_params={
                    "title": title,
                    "summary": summary,
                    "review_required": True,
                    "source_task_id": (
                        context.get("task", {}).get("id")
                        if isinstance(context.get("task"), dict)
                        else None
                    ),
                    "compound_attack_chain": {
                        "chain_id": chain.get("id"),
                        "pattern_id": pattern_id,
                        "title": chain.get("title"),
                        "status": chain.get("status"),
                        "component_finding_ids": component_ids,
                        "evidence_refs": evidence_refs,
                        "combined_impact": chain.get("combined_impact"),
                        "verification_goal": template["verification_goal"],
                        "safe_boundaries": safe_boundaries,
                    },
                    "boundary": {
                        "operator_review_required": True,
                        "automatic_execution": False,
                        "automatic_approval": False,
                        "no_autonomous_exploit_chaining": True,
                        "scope_expansion_allowed": False,
                    },
                },
                reasoning_text=(
                    f"{summary} This is a review-gated compound-chain proposal derived from "
                    "stored engagement findings; it does not execute tools, steal sessions, write files, "
                    "or bypass approval gates."
                ),
                risk_tier=str(template["risk_tier"]),
                priority=int(template["priority"]),
                confidence_score=confidence,
                metadata={
                    "proposal_kind": "compound_attack_chain",
                    "compound_attack_chain": True,
                    "chain_id": str(chain.get("id") or ""),
                    "chain_pattern_id": pattern_id,
                    "component_finding_ids": component_ids,
                    "evidence_refs": evidence_refs,
                    "dispatches_work": False,
                    "requires_operator_review": True,
                    "autonomous_chain_dispatch_allowed": False,
                    "active_runtime_mutated": False,
                },
            )
        )
        if len(drafts) >= 3:
            break
    return drafts


def _chain_proposal_target(*, chain: dict[str, Any], fallback_target: str) -> str:
    components = (
        chain.get("component_findings") if isinstance(chain.get("component_findings"), list) else []
    )
    targets = [
        str(component.get("target_id") or "").strip()
        for component in components
        if isinstance(component, dict) and str(component.get("target_id") or "").strip()
    ]
    unique_targets = list(dict.fromkeys(targets))
    if len(unique_targets) == 1:
        return unique_targets[0]
    if str(fallback_target or "").strip():
        return str(fallback_target).strip()
    return unique_targets[0] if unique_targets else ""


def _chain_confidence(chain: dict[str, Any]) -> float:
    try:
        return round(float(chain.get("confidence_score")), 2)
    except (TypeError, ValueError):
        return 0.72


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
        autonomous = (
            params.get("autonomous_agent")
            if isinstance(params.get("autonomous_agent"), dict)
            else {}
        )
        if not autonomous.get("enabled") or task.status != "queued":
            continue
        task.status = "cancelled"
        cancelled += 1
    return cancelled


def _finding_context(finding: Finding) -> dict[str, Any]:
    return {
        "id": str(finding.id),
        "run_id": str(finding.run_id) if finding.run_id else None,
        "finding_origin": finding.finding_origin,
        "title": finding.title,
        "severity": finding.severity,
        "target_id": finding.target_id,
        "evidence_ref": finding.evidence_ref,
        "status": finding.status,
        "summary": finding.summary,
        "methodology_tags": list(finding.methodology_tags or []),
        "wstg_id": finding.wstg_id,
        "asvs_reference": finding.asvs_reference,
        "control_family": finding.control_family,
    }


def _engagement_findings_for_analysis(*, session: Session, run: Run) -> list[Finding]:
    return list(
        session.scalars(
            select(Finding)
            .join(Run, Finding.run_id == Run.id)
            .where(Run.engagement_id == run.engagement_id, Run.deleted_at.is_(None))
            .order_by(Finding.created_at.desc(), Finding.id.desc())
            .limit(50)
        ).all()
    )


def _finding_chain_context(chain: FindingChain) -> dict[str, Any]:
    component_findings = [
        {
            "finding_id": str(item.get("finding_id") or ""),
            "title": item.get("title"),
            "severity": item.get("severity"),
            "target_id": item.get("target_id"),
            "evidence_ref": item.get("evidence_ref"),
        }
        for item in list(chain.rationale_json or [])
        if isinstance(item, dict)
    ]
    return {
        "id": str(chain.id),
        "pattern_id": chain.pattern_id,
        "title": chain.title,
        "status": chain.status,
        "component_finding_ids": [
            str(item) for item in list(chain.component_finding_ids_json or [])
        ],
        "component_findings": component_findings,
        "confidence_score": chain.confidence_score,
        "combined_impact": chain.combined_impact_text,
        "evidence_refs": list(chain.evidence_refs_json or []),
        "metadata": _safe_json_object(chain.metadata_json),
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
