from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from api.app.models import (
    Approval,
    CapabilityPack,
    Engagement,
    Finding,
    Run,
    Scope,
    Task,
    ToolExecution,
)
from api.app.schemas.mcp import McpOperatorContextRead, McpResourceRead, McpResourcesRead
from api.app.services.ai_enrichment import build_mission_guidance_for_run
from api.app.services.reports import build_report_catalog
from api.app.services.runs import (
    granted_approvals,
    latest_scope_query,
    pending_approvals,
    required_approvals,
    sorted_approvals,
    sorted_findings,
    sorted_tasks,
)
from api.app.services.secrets import sanitize_run_configuration

MCP_INTERFACE_NAME = "aegispt.read_only_operator_context.v1"

MCP_RESOURCE_DEFINITIONS: tuple[dict[str, Any], ...] = (
    {
        "name": "engagement.scope",
        "uri_template": "aegispt://engagements/{engagement_id}/scope",
        "description": "Engagement identity and allowlist/denylist scope metadata.",
        "fields": ["engagement", "scope"],
    },
    {
        "name": "run.summary",
        "uri_template": "aegispt://engagements/{engagement_id}/runs/{run_id}",
        "description": "Selected run metadata, sanitized configuration, approvals, task summaries, and advisory AI mission guidance.",
        "fields": ["selected_run"],
    },
    {
        "name": "finding.summary",
        "uri_template": "aegispt://engagements/{engagement_id}/runs/{run_id}/findings",
        "description": "Finding summaries and pointers to the existing Finding Theater read view.",
        "fields": ["findings"],
    },
    {
        "name": "report.catalog",
        "uri_template": "aegispt://engagements/{engagement_id}/runs/{run_id}/reports",
        "description": "Report catalog metadata and variant availability without generating or exporting reports.",
        "fields": ["reports"],
    },
    {
        "name": "evidence.metadata",
        "uri_template": "aegispt://engagements/{engagement_id}/runs/{run_id}/evidence",
        "description": "Evidence artifact metadata, URI, hash, redaction state, and timestamps only.",
        "fields": ["evidence"],
    },
    {
        "name": "pack.metadata",
        "uri_template": "aegispt://engagements/{engagement_id}/packs",
        "description": "Capability pack metadata, validation/deployment/provenance summaries, and runtime binding context.",
        "fields": ["packs"],
    },
)

DISABLED_MCP_ACTIONS = [
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
]

SENSITIVE_KEY_MARKERS = (
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "bearer",
    "session",
    "credential",
    "authorization",
    "auth_ref",
    "cookie",
)

SENSITIVE_VALUE_MARKERS = (
    "bearer ",
    "password=",
    "passwd=",
    "secret=",
    "token=",
    "sessionid=",
    "cookie=",
)


def mcp_resource_manifest() -> McpResourcesRead:
    return McpResourcesRead(
        interface=MCP_INTERFACE_NAME,
        read_only=True,
        resources=[McpResourceRead(**definition) for definition in MCP_RESOURCE_DEFINITIONS],
        tools=[],
        disabled_actions=list(DISABLED_MCP_ACTIONS),
        write_methods_allowed=[],
        secret_policy="Secrets, protected values, pack artifact contents, runtime output, and raw artifact contents are never exposed.",
        safety_notes=[
            "This interface is a read-only context surface, not an action tool surface.",
            "Approval, validation, deployment, runtime binding, and scan launch paths stay on existing APIs.",
            "Future action tools must be task-packaged and explicitly approved before implementation.",
        ],
    )


def load_mcp_engagement_context(
    session: Session,
    *,
    engagement_id: UUID,
    run_id: UUID | None,
    actor: str,
) -> McpOperatorContextRead | None:
    engagement = session.scalar(
        select(Engagement).where(
            Engagement.id == engagement_id,
            Engagement.deleted_at.is_(None),
        )
    )
    if engagement is None:
        return None

    scope = session.scalar(latest_scope_query(engagement.id))
    run = _load_context_run(session, engagement_id=engagement.id, run_id=run_id)
    if run_id is not None and run is None:
        return None

    packs = session.scalars(
        select(CapabilityPack)
        .options(
            selectinload(CapabilityPack.artifacts),
            selectinload(CapabilityPack.validation_results),
            selectinload(CapabilityPack.approvals),
            selectinload(CapabilityPack.deployments),
        )
        .where(CapabilityPack.engagement_id == engagement.id)
        .order_by(CapabilityPack.created_at.desc(), CapabilityPack.id.desc())
    ).all()

    manifest = mcp_resource_manifest()
    return McpOperatorContextRead(
        interface=MCP_INTERFACE_NAME,
        read_only=True,
        actor=actor,
        resource_allowlist=[resource.name for resource in manifest.resources],
        tools=[],
        disabled_actions=list(DISABLED_MCP_ACTIONS),
        write_methods_allowed=[],
        engagement=_engagement_context(engagement),
        scope=_scope_context(scope),
        selected_run=_run_context(session, run) if run is not None else {},
        findings=_finding_contexts(run) if run is not None else [],
        reports=_report_contexts(run) if run is not None else [],
        packs=[_pack_context(pack) for pack in packs],
        evidence=_evidence_contexts(run) if run is not None else [],
        safety={
            "read_only": True,
            "secret_values_exposed": False,
            "artifact_content_exposed": False,
            "runtime_output_exposed": False,
            "action_tools_enabled": False,
            "write_methods_allowed": [],
        },
    )


def _load_context_run(session: Session, *, engagement_id: UUID, run_id: UUID | None) -> Run | None:
    query = (
        select(Run)
        .options(
            selectinload(Run.engagement).selectinload(Engagement.scopes),
            selectinload(Run.profile),
            selectinload(Run.bound_pack).selectinload(CapabilityPack.validation_results),
            selectinload(Run.bound_pack).selectinload(CapabilityPack.approvals),
            selectinload(Run.bound_pack).selectinload(CapabilityPack.deployments),
            selectinload(Run.bound_pack).selectinload(CapabilityPack.artifacts),
            selectinload(Run.bound_pack_deployment),
            selectinload(Run.approvals),
            selectinload(Run.findings),
            selectinload(Run.tasks).selectinload(Task.executions).selectinload(ToolExecution.artifacts),
        )
        .where(Run.engagement_id == engagement_id, Run.deleted_at.is_(None))
    )
    if run_id is not None:
        return session.scalar(query.where(Run.id == run_id))
    return session.scalar(query.order_by(Run.created_at.desc(), Run.id.desc()).limit(1))


def _engagement_context(engagement: Engagement) -> dict[str, Any]:
    return {
        "id": str(engagement.id),
        "name": engagement.name,
        "client": engagement.client,
        "roe_ref": engagement.roe_ref,
        "starts_at": _isoformat(engagement.starts_at),
        "ends_at": _isoformat(engagement.ends_at),
        "created_at": _isoformat(engagement.created_at),
        "updated_at": _isoformat(engagement.updated_at),
    }


def _scope_context(scope: Scope | None) -> dict[str, Any]:
    if scope is None:
        return {"available": False}

    allowlist = _scrub_sensitive(scope.allowlist_json or {})
    denylist = _scrub_sensitive(scope.denylist_json or {})
    return {
        "available": True,
        "id": str(scope.id),
        "allowlist_json": allowlist,
        "denylist_json": denylist,
        "allowlist_item_count": _target_item_count(allowlist),
        "denylist_item_count": _target_item_count(denylist),
        "created_at": _isoformat(scope.created_at),
        "updated_at": _isoformat(scope.updated_at),
    }


def _run_context(session: Session, run: Run) -> dict[str, Any]:
    profile = run.profile
    approvals = sorted_approvals(run)
    tasks = sorted_tasks(run)
    profile_payload = {}
    if profile is not None:
        profile_payload = {
            "id": str(profile.id),
            "name": profile.name,
            "run_class": profile.run_class,
            "limits_json": _scrub_sensitive(profile.limits_json or {}),
        }

    required = required_approvals(profile) if profile is not None else 0
    return {
        "id": str(run.id),
        "engagement_id": str(run.engagement_id),
        "requested_by": run.requested_by,
        "status": run.status,
        "source_inventory_snapshot_id": _str_or_none(run.source_inventory_snapshot_id),
        "started_at": _isoformat(run.started_at),
        "created_at": _isoformat(run.created_at),
        "updated_at": _isoformat(run.updated_at),
        "profile": profile_payload,
        "configuration_json": _scrub_sensitive(
            sanitize_run_configuration(dict(run.configuration_json or {}))
        ),
        "approvals_summary": {
            "required": required,
            "granted": granted_approvals(run, profile=profile),
            "pending": pending_approvals(run, profile) if profile is not None else 0,
        },
        "approvals": [_approval_context(approval) for approval in approvals],
        "task_summaries": [_task_summary(task) for task in tasks],
        "finding_counts": _finding_counts(sorted_findings(run)),
        "pack_binding": _pack_binding_context(run),
        "ai_mission_guidance": _scrub_sensitive(build_mission_guidance_for_run(session=session, run=run)),
    }


def _approval_context(approval: Approval) -> dict[str, Any]:
    return {
        "id": str(approval.id),
        "step_id": approval.step_id,
        "approver_id": approval.approver_id,
        "decision": approval.decision,
        "created_at": _isoformat(approval.created_at),
    }


def _task_summary(task: Task) -> dict[str, Any]:
    return {
        "id": str(task.id),
        "tool": task.tool,
        "target_id": task.target_id,
        "status": task.status,
        "execution_count": len(task.executions or []),
        "artifact_count": sum(len(execution.artifacts or []) for execution in task.executions or []),
        "created_at": _isoformat(task.created_at),
        "updated_at": _isoformat(task.updated_at),
    }


def _finding_counts(findings: list[Finding]) -> dict[str, Any]:
    by_severity: dict[str, int] = {}
    by_status: dict[str, int] = {}
    for finding in findings:
        by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1
        by_status[finding.status] = by_status.get(finding.status, 0) + 1
    return {
        "total": len(findings),
        "by_severity": by_severity,
        "by_status": by_status,
    }


def _pack_binding_context(run: Run) -> dict[str, Any] | None:
    pack = run.bound_pack
    if pack is None:
        return None
    deployment = run.bound_pack_deployment
    return {
        "pack_id": str(pack.id),
        "pack_version": run.bound_pack_version,
        "deployment_id": str(deployment.id) if deployment is not None else None,
        "deployment_status": deployment.status if deployment is not None else None,
        "deployment_target": deployment.deployment_target if deployment is not None else None,
        "run_profile_name": deployment.run_profile_name if deployment is not None else None,
        "methodology_tags": list(pack.methodology_tags or []),
        "source_inventory_snapshot_id": _str_or_none(pack.source_inventory_snapshot_id),
        "relevance_decision_id": _str_or_none(pack.relevance_decision_id),
        "manifest_json": _scrub_sensitive(pack.manifest_json or {}),
        "runtime_binding_json": (
            _scrub_sensitive(deployment.runtime_binding_json or {}) if deployment is not None else {}
        ),
    }


def _finding_contexts(run: Run) -> list[dict[str, Any]]:
    contexts: list[dict[str, Any]] = []
    for finding in sorted_findings(run):
        contexts.append(
            {
                "id": str(finding.id),
                "run_id": _str_or_none(finding.run_id),
                "source_pack_id": _str_or_none(finding.source_pack_id),
                "source_pack_artifact_id": _str_or_none(finding.source_pack_artifact_id),
                "source_inventory_snapshot_id": _str_or_none(finding.source_inventory_snapshot_id),
                "source_relevance_decision_id": _str_or_none(finding.source_relevance_decision_id),
                "source_pack_version": finding.source_pack_version,
                "finding_origin": finding.finding_origin,
                "title": finding.title,
                "severity": finding.severity,
                "target_id": finding.target_id,
                "evidence_ref": finding.evidence_ref,
                "status": finding.status,
                "summary": finding.summary,
                "methodology_tags": list(finding.methodology_tags or []),
                "ptes_phase": finding.ptes_phase,
                "nist_phase": finding.nist_phase,
                "wstg_id": finding.wstg_id,
                "wstg_version": finding.wstg_version,
                "asvs_reference": finding.asvs_reference,
                "control_family": finding.control_family,
                "theater_path": f"/api/v1/findings/{finding.id}/theater",
                "created_at": _isoformat(finding.created_at),
                "updated_at": _isoformat(finding.updated_at),
            }
        )
    return contexts


def _report_contexts(run: Run) -> list[dict[str, Any]]:
    return [
        _scrub_sensitive(report.model_dump(mode="json", exclude={"export_paths", "download_names"}))
        for report in build_report_catalog(run)
    ]


def _pack_context(pack: CapabilityPack) -> dict[str, Any]:
    return {
        "id": str(pack.id),
        "engagement_id": str(pack.engagement_id),
        "relevance_decision_id": _str_or_none(pack.relevance_decision_id),
        "source_inventory_snapshot_id": _str_or_none(pack.source_inventory_snapshot_id),
        "parent_pack_id": _str_or_none(pack.parent_pack_id),
        "name": pack.name,
        "version": pack.version,
        "status": pack.status,
        "generated_by": pack.generated_by,
        "generation_mode": pack.generation_mode,
        "description": pack.description,
        "source_threat_intel_refs_json": list(pack.source_threat_intel_refs_json or []),
        "methodology_tags": list(pack.methodology_tags or []),
        "manifest_json": _scrub_sensitive(pack.manifest_json or {}),
        "provenance_json": _scrub_sensitive(pack.provenance_json or {}),
        "artifacts": [
            {
                "id": str(artifact.id),
                "artifact_type": artifact.artifact_type,
                "logical_name": artifact.logical_name,
                "status": artifact.status,
                "checksum_sha256": artifact.checksum_sha256,
                "methodology_tags": list(artifact.methodology_tags or []),
                "provenance_json": _scrub_sensitive(artifact.provenance_json or {}),
                "content_available": bool(artifact.content_text or artifact.content_json),
                "content_exposed": False,
                "created_at": _isoformat(artifact.created_at),
            }
            for artifact in sorted(pack.artifacts, key=lambda item: (item.logical_name, item.created_at, item.id.hex))
        ],
        "validations": [
            {
                "id": str(validation.id),
                "validator": validation.validator,
                "executed_by": validation.executed_by,
                "status": validation.status,
                "summary": validation.summary,
                "artifact_result_count": len(validation.artifact_results_json or []),
                "validation_artifact_count": len(validation.validation_artifacts_json or []),
                "blocking_issues": list(validation.blocking_issues_json or []),
                "created_at": _isoformat(validation.created_at),
            }
            for validation in sorted(pack.validation_results, key=lambda item: (item.created_at, item.id.hex))
        ],
        "approvals": [
            {
                "id": str(approval.id),
                "approval_step": approval.approval_step,
                "approver_id": approval.approver_id,
                "decision": approval.decision,
                "notes": approval.notes,
                "created_at": _isoformat(approval.created_at),
            }
            for approval in sorted(pack.approvals, key=lambda item: (item.created_at, item.id.hex))
        ],
        "deployments": [
            {
                "id": str(deployment.id),
                "deployment_target": deployment.deployment_target,
                "run_profile_name": deployment.run_profile_name,
                "status": deployment.status,
                "rollback_from_pack_id": _str_or_none(deployment.rollback_from_pack_id),
                "runtime_binding_json": _scrub_sensitive(deployment.runtime_binding_json or {}),
                "created_at": _isoformat(deployment.created_at),
            }
            for deployment in sorted(pack.deployments, key=lambda item: (item.created_at, item.id.hex))
        ],
        "created_at": _isoformat(pack.created_at),
        "updated_at": _isoformat(pack.updated_at),
    }


def _evidence_contexts(run: Run) -> list[dict[str, Any]]:
    contexts: list[dict[str, Any]] = []
    for task in sorted_tasks(run):
        for execution in sorted(task.executions or [], key=lambda item: (item.created_at, item.id.hex)):
            for artifact in sorted(execution.artifacts or [], key=lambda item: (item.kind, item.created_at, item.id.hex)):
                contexts.append(
                    {
                        "id": str(artifact.id),
                        "task_id": str(task.id),
                        "execution_id": str(execution.id),
                        "tool": task.tool,
                        "target_id": task.target_id,
                        "kind": artifact.kind,
                        "uri": artifact.uri,
                        "sha256": artifact.sha256,
                        "redaction_state": artifact.redaction_state,
                        "metadata_json": _scrub_sensitive(artifact.metadata_json or {}),
                        "content_exposed": False,
                        "runtime_output_exposed": False,
                        "created_at": _isoformat(artifact.created_at),
                        "updated_at": _isoformat(artifact.updated_at),
                    }
                )
    return contexts


def _scrub_sensitive(value: Any) -> Any:
    if isinstance(value, dict):
        scrubbed: dict[str, Any] = {}
        for key, item in value.items():
            normalized_key = str(key).lower()
            if any(marker in normalized_key for marker in SENSITIVE_KEY_MARKERS):
                scrubbed[str(key)] = "[redacted]"
                continue
            scrubbed[str(key)] = _scrub_sensitive(item)
        return scrubbed

    if isinstance(value, list):
        return [_scrub_sensitive(item) for item in value]

    if isinstance(value, tuple):
        return [_scrub_sensitive(item) for item in value]

    if isinstance(value, UUID):
        return str(value)

    if isinstance(value, datetime):
        return _isoformat(value)

    if isinstance(value, str) and any(marker in value.lower() for marker in SENSITIVE_VALUE_MARKERS):
        return "[redacted]"

    return value


def _target_item_count(target_map: dict[str, Any]) -> int:
    count = 0
    for value in target_map.values():
        if isinstance(value, list):
            count += len(value)
        elif value:
            count += 1
    return count


def _isoformat(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def _str_or_none(value: UUID | None) -> str | None:
    return str(value) if value is not None else None
