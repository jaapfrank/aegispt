from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from api.app.models import Engagement, Finding, FindingRemediation, Run
from api.app.schemas.mcp import McpToolInvocationRead, McpToolRead, McpToolsRead
from api.app.services.audit import write_audit_event
from api.app.services.mcp_context import DISABLED_MCP_ACTIONS, MCP_INTERFACE_NAME, _scrub_sensitive
from api.app.services.runs import required_approvals

MCP_ACTION_INTERFACE_NAME = "aegispt.controlled_action_tools.v1"


class McpToolError(RuntimeError):
    def __init__(self, status_code: int, detail: str) -> None:
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


@dataclass(frozen=True, slots=True)
class McpToolDefinition:
    name: str
    title: str
    description: str
    status: str
    state_changing: bool
    confirmation_required: bool
    input_schema: dict[str, Any]
    output_contract: dict[str, Any]
    safety_notes: tuple[str, ...]


MCP_TOOL_DEFINITIONS: tuple[McpToolDefinition, ...] = (
    McpToolDefinition(
        name="finding.retest.proposal",
        title="Draft a single-finding retest proposal",
        description=(
            "Produces an operator-reviewable proposal for the existing single-finding retest endpoint. "
            "It does not create a run, queue tasks, dispatch work, or change finding state."
        ),
        status="enabled",
        state_changing=False,
        confirmation_required=False,
        input_schema={
            "required": ["engagement_id", "finding_id"],
            "optional_arguments": ["notes"],
            "notes": "notes is copied into the proposal only; it is not persisted by this tool.",
        },
        output_contract={
            "domain_state_changed": False,
            "proposed_endpoint": "/api/v1/findings/{finding_id}/retest",
            "review_required": True,
        },
        safety_notes=(
            "Proposal-only: no run is created and no task is queued.",
            "Operators must use the existing retest endpoint separately if they choose to act.",
        ),
    ),
    McpToolDefinition(
        name="finding.webhook.handoff.request",
        title="Request existing webhook handoff",
        description=(
            "Reserved for a future confirmed low-risk handoff through the existing integration path. "
            "This first slice advertises the confirmation boundary but does not execute it."
        ),
        status="disabled_pending_follow_up_task",
        state_changing=True,
        confirmation_required=True,
        input_schema={
            "required": ["engagement_id", "finding_id", "confirmation.confirmed"],
            "optional_arguments": ["handoff_key", "handoff_url", "operator_note"],
        },
        output_contract={
            "domain_state_changed": True,
            "enabled_in_this_slice": False,
            "review_required": True,
        },
        safety_notes=(
            "Requires explicit operator confirmation before any future state-changing handoff.",
            "Disabled in this slice to avoid accidental external delivery.",
        ),
    ),
)

FORBIDDEN_TOOL_NAMES = {
    "scan_launch",
    "run_dispatch",
    "run_cancel",
    "approval_decision",
    "pack_approval",
    "pack_deployment",
    "pack_rollback",
    "pack_mutation",
    "secret_access",
    "artifact_content_read",
    "runtime_mutation",
    "plugin_installation",
}

ACTION_SECRET_POLICY = (
    "MCP action tools may receive identifiers and review notes only. They must not expose raw "
    "secrets, pack artifact content, runtime output, or bypass existing platform gates."
)


def mcp_action_tool_manifest() -> McpToolsRead:
    return McpToolsRead(
        interface=MCP_ACTION_INTERFACE_NAME,
        read_only_context_interface=MCP_INTERFACE_NAME,
        action_tools_enabled=True,
        tools=[_tool_read(definition) for definition in MCP_TOOL_DEFINITIONS],
        disabled_actions=[*DISABLED_MCP_ACTIONS, *sorted(FORBIDDEN_TOOL_NAMES - set(DISABLED_MCP_ACTIONS))],
        write_methods_allowed=["POST /api/v1/mcp/tools/{tool_name}/invoke"],
        secret_policy=ACTION_SECRET_POLICY,
        safety_notes=[
            "The read-only MCP context endpoints remain available and unchanged.",
            "Only explicitly listed enabled tools can be invoked.",
            "State-changing tools require explicit operator confirmation before execution.",
            "Approval, dispatch, pack deployment, runtime binding, and secret boundaries remain on existing platform APIs.",
        ],
    )


def invoke_mcp_tool(
    session: Session,
    *,
    tool_name: str,
    engagement_id: UUID | None,
    finding_id: UUID | None,
    arguments: dict[str, Any],
    confirmation_confirmed: bool,
    actor: str,
) -> McpToolInvocationRead:
    normalized_tool_name = tool_name.strip()
    if normalized_tool_name in FORBIDDEN_TOOL_NAMES:
        raise McpToolError(403, f"{normalized_tool_name} is forbidden through MCP action tools")

    definition = _tool_definition(normalized_tool_name)
    if definition is None:
        raise McpToolError(404, "mcp tool not found")

    if definition.state_changing and definition.confirmation_required and not confirmation_confirmed:
        raise McpToolError(409, "explicit operator confirmation required before this MCP action can change state")

    if definition.status != "enabled":
        raise McpToolError(403, f"{definition.name} is not enabled in this first MCP action-tool slice")

    if definition.name == "finding.retest.proposal":
        return _finding_retest_proposal(
            session,
            definition=definition,
            engagement_id=engagement_id,
            finding_id=finding_id,
            arguments=arguments,
            actor=actor,
        )

    raise McpToolError(404, "mcp tool not implemented")


def _finding_retest_proposal(
    session: Session,
    *,
    definition: McpToolDefinition,
    engagement_id: UUID | None,
    finding_id: UUID | None,
    arguments: dict[str, Any],
    actor: str,
) -> McpToolInvocationRead:
    if engagement_id is None:
        raise McpToolError(422, "engagement_id is required")
    if finding_id is None:
        raise McpToolError(422, "finding_id is required")

    finding = _load_finding_for_engagement(session, engagement_id=engagement_id, finding_id=finding_id)
    remediation = session.scalar(select(FindingRemediation).where(FindingRemediation.finding_id == finding.id))
    source_run = finding.run
    notes = _optional_text(arguments.get("notes"), max_length=2000)
    pending_approval_count = 0
    profile_name = None
    if source_run is not None and source_run.profile is not None:
        profile_name = source_run.profile.name
        pending_approval_count = required_approvals(source_run.profile)

    result = {
        "proposal_type": "single_finding_retest",
        "finding": {
            "id": str(finding.id),
            "title": finding.title,
            "severity": finding.severity,
            "status": finding.status,
            "target_id": finding.target_id,
            "evidence_ref": finding.evidence_ref,
            "summary": finding.summary,
        },
        "source_run": {
            "id": str(source_run.id) if source_run is not None else None,
            "profile_name": profile_name,
            "status": source_run.status if source_run is not None else None,
            "pending_approval_count_if_requested": pending_approval_count,
        },
        "remediation": {
            "state": remediation.state if remediation is not None else None,
            "owner": remediation.owner if remediation is not None else None,
            "notes": remediation.notes if remediation is not None else None,
        },
        "operator_note": notes,
        "proposed_action": {
            "method": "POST",
            "endpoint": f"/api/v1/findings/{finding.id}/retest",
            "body": {"notes": notes},
            "must_be_performed_by_operator": True,
            "uses_existing_endpoint": True,
        },
        "review": {
            "operator_review_required": True,
            "state_change_performed": False,
            "run_created": False,
            "tasks_queued": False,
            "approval_bypass": False,
            "pack_deployment_bypass": False,
            "secret_access": False,
        },
        "source_trace": [
            "finding.id",
            "finding.run_id",
            "finding.evidence_ref",
            "finding.remediation",
            "run.profile",
        ],
    }
    safe_result = _scrub_sensitive(result)
    audit_event = write_audit_event(
        session=session,
        actor=actor,
        action="mcp.tool.proposal_generated",
        object_type="finding",
        object_id=str(finding.id),
        metadata={
            "tool_name": definition.name,
            "engagement_id": str(engagement_id),
            "domain_state_changed": False,
            "proposed_endpoint": safe_result["proposed_action"]["endpoint"],
        },
    )
    session.commit()
    session.refresh(audit_event)

    return McpToolInvocationRead(
        tool_name=definition.name,
        status="completed",
        state_changed=False,
        domain_state_changed=False,
        audit_recorded=True,
        audit_event_id=audit_event.id,
        confirmation_required=False,
        operator_review_required=True,
        result=safe_result,
        safety=_tool_safety_payload(definition, domain_state_changed=False),
    )


def _load_finding_for_engagement(session: Session, *, engagement_id: UUID, finding_id: UUID) -> Finding:
    engagement = session.scalar(
        select(Engagement).where(
            Engagement.id == engagement_id,
            Engagement.deleted_at.is_(None),
        )
    )
    if engagement is None:
        raise McpToolError(404, "engagement not found")

    finding = session.scalar(
        select(Finding)
        .options(selectinload(Finding.run).selectinload(Run.profile))
        .where(Finding.id == finding_id)
    )
    if finding is None:
        raise McpToolError(404, "finding not found for engagement")
    if finding.run is None or finding.run.deleted_at is not None:
        raise McpToolError(409, "finding has no source run for retest proposal")
    if finding.run.engagement_id != engagement.id:
        raise McpToolError(404, "finding not found for engagement")
    return finding


def _tool_definition(tool_name: str) -> McpToolDefinition | None:
    for definition in MCP_TOOL_DEFINITIONS:
        if definition.name == tool_name:
            return definition
    return None


def _tool_read(definition: McpToolDefinition) -> McpToolRead:
    return McpToolRead(
        name=definition.name,
        title=definition.title,
        description=definition.description,
        status=definition.status,
        state_changing=definition.state_changing,
        confirmation_required=definition.confirmation_required,
        operator_review_required=True,
        input_schema=dict(definition.input_schema),
        output_contract=dict(definition.output_contract),
        safety_notes=list(definition.safety_notes),
    )


def _tool_safety_payload(definition: McpToolDefinition, *, domain_state_changed: bool) -> dict[str, Any]:
    return {
        "tool_status": definition.status,
        "operator_review_required": True,
        "domain_state_changed": domain_state_changed,
        "approval_bypass": False,
        "dispatch_bypass": False,
        "pack_deployment_bypass": False,
        "runtime_binding_bypass": False,
        "secret_access": False,
        "runtime_self_modification": False,
    }


def _optional_text(value: Any, *, max_length: int) -> str | None:
    if value is None:
        return None
    normalized = str(value).strip()
    if not normalized:
        return None
    return normalized[:max_length]
