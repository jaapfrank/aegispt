from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from sqlalchemy import delete, func, or_, select, update
from sqlalchemy.orm import Session

from api.app.models import (
    AgentProposal,
    AgentReasoning,
    Approval,
    AssessmentChain,
    AuditEvent,
    CapabilityPack,
    CicdTrigger,
    CicdTriggerEvent,
    Engagement,
    EvidenceArtifact,
    ExposureScore,
    Finding,
    FindingAiEnrichment,
    FindingChain,
    FindingIntegrationLink,
    FindingRemediation,
    FindingRepositoryLink,
    FindingValidationRecord,
    InternalValidationApproval,
    InternalValidationSession,
    InternalValidationStep,
    InventorySnapshot,
    RelevanceDecision,
    Run,
    ScheduledRun,
    Scope,
    SecretRef,
    Task,
    ToolExecution,
)
from api.app.services.audit import write_audit_event
from api.app.services.secrets import sanitize_run_configuration
from api.app.services.soft_delete import SoftDeleteBlockedError, run_delete_blocker, soft_delete_runs

SENSITIVE_KEY_PARTS = (
    "secret",
    "password",
    "token",
    "api_key",
    "bearer",
    "hash",
    "credential",
    "cookie",
    "session",
)


def utcnow() -> datetime:
    return datetime.now(tz=UTC)


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _next_cleanup_at(now: datetime | None = None) -> datetime:
    effective_now = now or utcnow()
    tomorrow = effective_now.date() + timedelta(days=1)
    return datetime(tomorrow.year, tomorrow.month, tomorrow.day, 2, 0, tzinfo=UTC)


def retention_cutoff(engagement: Engagement, now: datetime | None = None) -> datetime:
    effective_now = now or utcnow()
    return effective_now - timedelta(days=int(engagement.retention_days or 90))


def _run_age_column(run: Run) -> datetime:
    return _as_utc(run.updated_at or run.created_at)


def _json_safe(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, list):
        return [_json_safe(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    return value


def _redact_sensitive(value: Any, parent_key: str = "") -> Any:
    key = parent_key.lower()
    if any(part in key for part in SENSITIVE_KEY_PARTS):
        return "[redacted]"
    if isinstance(value, dict):
        redacted: dict[str, Any] = {}
        for item_key, item_value in value.items():
            normalized_key = str(item_key)
            if any(part in normalized_key.lower() for part in SENSITIVE_KEY_PARTS):
                redacted[normalized_key] = "[redacted]"
            else:
                redacted[normalized_key] = _redact_sensitive(item_value, normalized_key)
        return redacted
    if isinstance(value, list):
        return [_redact_sensitive(item, parent_key) for item in value]
    return _json_safe(value)


def _count(session: Session, statement) -> int:
    return int(session.scalar(statement) or 0)


def _delete_count(session: Session, statement) -> int:
    result = session.execute(statement)
    return int(result.rowcount or 0)


def engagement_retention_status(
    *,
    session: Session,
    engagement: Engagement,
    now: datetime | None = None,
) -> dict[str, Any]:
    effective_now = now or utcnow()
    cutoff = retention_cutoff(engagement, effective_now)
    runs = list(
        session.scalars(
            select(Run)
            .where(Run.engagement_id == engagement.id)
            .order_by(Run.created_at.asc(), Run.id.asc())
        ).all()
    )
    eligible = [
        run
        for run in runs
        if run.deleted_at is None and _run_age_column(run) <= cutoff and run_delete_blocker(run) is None
    ]
    active = [run for run in runs if run.deleted_at is None]
    soft_deleted = [run for run in runs if run.deleted_at is not None]
    return {
        "engagement_id": engagement.id,
        "retention_days": int(engagement.retention_days or 90),
        "cutoff_at": cutoff,
        "next_cleanup_at": _next_cleanup_at(effective_now),
        "eligible_run_count": len(eligible),
        "active_run_count": len(active),
        "soft_deleted_run_count": len(soft_deleted),
        "policy": (
            "Run data older than the engagement retention window is soft-deleted first; "
            "irreversible purge requires typed confirmation."
        ),
    }


def apply_engagement_retention_policy(
    *,
    session: Session,
    engagement: Engagement,
    actor: str = "system:gdpr-retention",
    now: datetime | None = None,
) -> dict[str, Any]:
    cutoff = retention_cutoff(engagement, now)
    candidates = list(
        session.scalars(
            select(Run)
            .where(Run.engagement_id == engagement.id, Run.deleted_at.is_(None))
            .order_by(Run.created_at.asc(), Run.id.asc())
        ).all()
    )
    eligible = [run for run in candidates if _run_age_column(run) <= cutoff and run_delete_blocker(run) is None]
    skipped = [run for run in candidates if _run_age_column(run) <= cutoff and run_delete_blocker(run) is not None]
    if eligible:
        soft_delete_runs(session=session, runs=eligible, actor=actor)
    write_audit_event(
        session=session,
        actor=actor,
        action="engagement.retention_cleanup",
        object_type="engagement",
        object_id=str(engagement.id),
        metadata={
            "retention_days": int(engagement.retention_days or 90),
            "cutoff_at": cutoff.isoformat(),
            "soft_deleted_run_ids": [str(run.id) for run in eligible],
            "skipped_run_ids": [str(run.id) for run in skipped],
        },
    )
    return {
        "engagement_id": engagement.id,
        "retention_days": int(engagement.retention_days or 90),
        "cutoff_at": cutoff,
        "soft_deleted_runs": len(eligible),
        "skipped_runs": len(skipped),
        "soft_deleted_run_ids": [run.id for run in eligible],
        "warnings": ["Running runs are skipped until stopped."] if skipped else [],
    }


def apply_all_engagement_retention_policies(
    *,
    session: Session,
    actor: str = "system:gdpr-retention",
    now: datetime | None = None,
) -> dict[str, Any]:
    engagements = list(
        session.scalars(
            select(Engagement)
            .where(Engagement.deleted_at.is_(None))
            .order_by(Engagement.created_at.asc(), Engagement.id.asc())
        ).all()
    )
    results = [
        apply_engagement_retention_policy(
            session=session,
            engagement=engagement,
            actor=actor,
            now=now,
        )
        for engagement in engagements
    ]
    return {
        "engagements_checked": len(engagements),
        "soft_deleted_runs": sum(int(item["soft_deleted_runs"]) for item in results),
        "skipped_runs": sum(int(item["skipped_runs"]) for item in results),
        "results": results,
    }


def start_gdpr_retention_scheduler(app) -> dict[str, Any]:
    try:
        from apscheduler.schedulers.background import BackgroundScheduler
        from apscheduler.triggers.cron import CronTrigger
    except ImportError:
        status = {"enabled": False, "status": "missing_dependency", "reason": "APScheduler is not installed"}
        app.state.gdpr_retention_scheduler_status = status
        return status

    session_factory = app.state.session_factory

    def cleanup_job() -> None:
        session = session_factory()
        try:
            apply_all_engagement_retention_policies(session=session)
            session.commit()
        except Exception:
            session.rollback()
        finally:
            session.close()

    scheduler = BackgroundScheduler()
    scheduler.add_job(
        cleanup_job,
        CronTrigger(hour=2, minute=0),
        id="gdpr-engagement-retention-cleanup",
        replace_existing=True,
        max_instances=1,
        coalesce=True,
    )
    scheduler.start()
    app.state.gdpr_retention_scheduler = scheduler
    status = {"enabled": True, "status": "scheduled", "cron": "0 2 * * *"}
    app.state.gdpr_retention_scheduler_status = status
    return status


def stop_gdpr_retention_scheduler(app) -> None:
    scheduler = getattr(app.state, "gdpr_retention_scheduler", None)
    if scheduler is not None:
        scheduler.shutdown(wait=False)
        app.state.gdpr_retention_scheduler = None


def _secret_ref_export(secret_ref: SecretRef) -> dict[str, Any]:
    return {
        "id": str(secret_ref.id),
        "purpose": secret_ref.purpose,
        "secret_kind": secret_ref.secret_kind,
        "storage_backend": secret_ref.storage_backend,
        "display_label": secret_ref.display_label,
        "metadata_json": _redact_sensitive(secret_ref.metadata_json or {}),
        "credential_material_included": False,
    }


def build_engagement_data_export(
    *,
    session: Session,
    engagement: Engagement,
    actor: str,
) -> dict[str, Any]:
    runs = list(
        session.scalars(
            select(Run)
            .where(Run.engagement_id == engagement.id)
            .order_by(Run.created_at.asc(), Run.id.asc())
        ).all()
    )
    run_ids = [run.id for run in runs]
    tasks = list(
        session.scalars(select(Task).where(Task.run_id.in_(run_ids)).order_by(Task.created_at.asc(), Task.id.asc())).all()
        if run_ids
        else []
    )
    task_ids = [task.id for task in tasks]
    executions = list(
        session.scalars(
            select(ToolExecution)
            .where(ToolExecution.task_id.in_(task_ids))
            .order_by(ToolExecution.created_at.asc(), ToolExecution.id.asc())
        ).all()
        if task_ids
        else []
    )
    execution_ids = [execution.id for execution in executions]
    artifacts = list(
        session.scalars(
            select(EvidenceArtifact)
            .where(EvidenceArtifact.tool_execution_id.in_(execution_ids))
            .order_by(EvidenceArtifact.created_at.asc(), EvidenceArtifact.id.asc())
        ).all()
        if execution_ids
        else []
    )
    findings = list(
        session.scalars(
            select(Finding)
            .where(Finding.run_id.in_(run_ids))
            .order_by(Finding.created_at.asc(), Finding.id.asc())
        ).all()
        if run_ids
        else []
    )
    inventory = list(
        session.scalars(
            select(InventorySnapshot)
            .where(InventorySnapshot.engagement_id == engagement.id)
            .order_by(InventorySnapshot.created_at.asc(), InventorySnapshot.id.asc())
        ).all()
    )
    scopes = list(
        session.scalars(
            select(Scope)
            .where(Scope.engagement_id == engagement.id)
            .order_by(Scope.created_at.asc(), Scope.id.asc())
        ).all()
    )
    secret_refs = list(
        session.scalars(
            select(SecretRef)
            .where(SecretRef.engagement_id == engagement.id)
            .order_by(SecretRef.created_at.asc(), SecretRef.id.asc())
        ).all()
    )
    object_ids = {str(engagement.id)}
    object_ids.update(str(item_id) for item_id in run_ids + task_ids)
    object_ids.update(str(item.id) for item in findings)
    object_ids.update(str(item.id) for item in artifacts)
    audit_events = list(
        session.scalars(
            select(AuditEvent)
            .where(AuditEvent.object_id.in_(sorted(object_ids)))
            .order_by(AuditEvent.created_at.asc(), AuditEvent.id.asc())
        ).all()
    )

    payload = {
        "exported_at": utcnow().isoformat(),
        "exported_by": actor,
        "credential_material_included": False,
        "engagement": {
            "id": str(engagement.id),
            "name": engagement.name,
            "client": engagement.client,
            "tenant_id": engagement.tenant_id,
            "roe_ref": engagement.roe_ref,
            "status": engagement.status,
            "retention_days": int(engagement.retention_days or 90),
            "created_at": engagement.created_at.isoformat(),
            "updated_at": engagement.updated_at.isoformat(),
            "deleted_at": engagement.deleted_at.isoformat() if engagement.deleted_at else None,
        },
        "scopes": [
            {
                "id": str(scope.id),
                "allowlist_json": _redact_sensitive(scope.allowlist_json),
                "denylist_json": _redact_sensitive(scope.denylist_json),
                "created_at": scope.created_at.isoformat(),
            }
            for scope in scopes
        ],
        "runs": [
            {
                "id": str(run.id),
                "profile_id": str(run.profile_id) if run.profile_id else None,
                "status": run.status,
                "requested_by": run.requested_by,
                "configuration_json": _redact_sensitive(sanitize_run_configuration(dict(run.configuration_json or {}))),
                "started_at": run.started_at.isoformat() if run.started_at else None,
                "created_at": run.created_at.isoformat(),
                "updated_at": run.updated_at.isoformat(),
                "deleted_at": run.deleted_at.isoformat() if run.deleted_at else None,
            }
            for run in runs
        ],
        "tasks": [
            {
                "id": str(task.id),
                "run_id": str(task.run_id) if task.run_id else None,
                "tool": task.tool,
                "target_id": task.target_id,
                "params_json": _redact_sensitive(task.params_json or {}),
                "status": task.status,
                "created_at": task.created_at.isoformat(),
                "updated_at": task.updated_at.isoformat(),
            }
            for task in tasks
        ],
        "tool_executions": [
            {
                "id": str(execution.id),
                "task_id": str(execution.task_id),
                "runner_digest": execution.runner_digest,
                "tool_version": execution.tool_version,
                "exit_code": execution.exit_code,
                "stdout_text": "[redacted task output]" if execution.stdout_text else "",
                "stderr_text": "[redacted task output]" if execution.stderr_text else "",
                "created_at": execution.created_at.isoformat(),
            }
            for execution in executions
        ],
        "artifacts": [
            {
                "id": str(artifact.id),
                "tool_execution_id": str(artifact.tool_execution_id),
                "kind": artifact.kind,
                "uri": artifact.uri,
                "sha256": artifact.sha256,
                "redaction_state": artifact.redaction_state,
                "metadata_json": _redact_sensitive(artifact.metadata_json or {}),
                "created_at": artifact.created_at.isoformat(),
            }
            for artifact in artifacts
        ],
        "findings": [
            {
                "id": str(finding.id),
                "run_id": str(finding.run_id),
                "title": finding.title,
                "severity": finding.severity,
                "target_id": finding.target_id,
                "evidence_ref": finding.evidence_ref,
                "status": finding.status,
                "summary": finding.summary,
                "control_family": finding.control_family,
                "methodology_tags": list(finding.methodology_tags or []),
                "created_at": finding.created_at.isoformat(),
                "updated_at": finding.updated_at.isoformat(),
            }
            for finding in findings
        ],
        "inventory_snapshots": [
            {
                "id": str(snapshot.id),
                "source_tools_json": list(snapshot.source_tools_json or []),
                "summary_json": _redact_sensitive(snapshot.summary_json or {}),
                "normalized_inventory_json": _redact_sensitive(snapshot.normalized_inventory_json or {}),
                "confidence_score": snapshot.confidence_score,
                "created_at": snapshot.created_at.isoformat(),
            }
            for snapshot in inventory
        ],
        "secret_refs": [_secret_ref_export(secret_ref) for secret_ref in secret_refs],
        "audit_events": [
            {
                "id": str(event.id),
                "actor": event.actor,
                "action": event.action,
                "object_type": event.object_type,
                "object_id": event.object_id,
                "metadata_json": _redact_sensitive(event.metadata_json or {}),
                "created_at": event.created_at.isoformat(),
            }
            for event in audit_events
        ],
    }
    write_audit_event(
        session=session,
        actor=actor,
        action="engagement.data_exported",
        object_type="engagement",
        object_id=str(engagement.id),
        metadata={
            "runs": len(runs),
            "findings": len(findings),
            "inventory_snapshots": len(inventory),
            "credential_material_included": False,
        },
    )
    return payload


def _scalars(session: Session, statement) -> list:
    return list(session.scalars(statement).all())


def hard_purge_engagement_assessment_data(
    *,
    session: Session,
    engagement: Engagement,
    actor: str,
) -> dict[str, Any]:
    runs = list(
        session.scalars(
            select(Run)
            .where(Run.engagement_id == engagement.id)
            .order_by(Run.created_at.asc(), Run.id.asc())
        ).all()
    )
    blockers = [run_delete_blocker(run) for run in runs]
    blockers = [blocker for blocker in blockers if blocker]
    if blockers:
        raise SoftDeleteBlockedError(blockers[0])

    purged_at = utcnow()
    run_ids = [run.id for run in runs]
    task_ids = _scalars(session, select(Task.id).where(Task.run_id.in_(run_ids))) if run_ids else []
    execution_ids = (
        _scalars(session, select(ToolExecution.id).where(ToolExecution.task_id.in_(task_ids)))
        if task_ids
        else []
    )
    finding_ids = _scalars(session, select(Finding.id).where(Finding.run_id.in_(run_ids))) if run_ids else []
    validation_filters = []
    if run_ids:
        validation_filters.append(FindingValidationRecord.run_id.in_(run_ids))
    if task_ids:
        validation_filters.append(FindingValidationRecord.task_id.in_(task_ids))
    if execution_ids:
        validation_filters.append(FindingValidationRecord.tool_execution_id.in_(execution_ids))
    if finding_ids:
        validation_filters.append(FindingValidationRecord.finding_id.in_(finding_ids))

    counts = {
        "runs": len(run_ids),
        "tasks": len(task_ids),
        "tool_executions": len(execution_ids),
        "findings": len(finding_ids),
        "inventory_snapshots": _count(
            session, select(func.count(InventorySnapshot.id)).where(InventorySnapshot.engagement_id == engagement.id)
        ),
        "scopes": _count(session, select(func.count(Scope.id)).where(Scope.engagement_id == engagement.id)),
        "secret_refs": _count(
            session,
            select(func.count(SecretRef.id)).where(
                SecretRef.engagement_id == engagement.id,
                or_(SecretRef.purpose.like("run.access.%"), SecretRef.purpose.like("task.%")),
            ),
        ),
    }

    if run_ids:
        session.execute(
            update(AssessmentChain)
            .where(AssessmentChain.current_run_id.in_(run_ids))
            .values(current_run_id=None)
        )
        session.execute(
            update(AssessmentChain)
            .where(AssessmentChain.last_completed_run_id.in_(run_ids))
            .values(last_completed_run_id=None)
        )
        session.execute(
            update(ScheduledRun)
            .where(ScheduledRun.last_launched_run_id.in_(run_ids))
            .values(last_launched_run_id=None)
        )
        session.execute(update(CicdTrigger).where(CicdTrigger.last_run_id.in_(run_ids)).values(last_run_id=None))
        session.execute(update(CicdTriggerEvent).where(CicdTriggerEvent.run_id.in_(run_ids)).values(run_id=None))
        session.execute(
            update(InternalValidationStep)
            .where(InternalValidationStep.launched_run_id.in_(run_ids))
            .values(launched_run_id=None)
        )

    if validation_filters:
        counts["validation_records"] = _delete_count(
            session, delete(FindingValidationRecord).where(or_(*validation_filters))
        )
    else:
        counts["validation_records"] = 0
    if run_ids:
        counts["approvals"] = _delete_count(session, delete(Approval).where(Approval.run_id.in_(run_ids)))
        counts["exposure_scores"] = _delete_count(session, delete(ExposureScore).where(ExposureScore.run_id.in_(run_ids)))
        counts["finding_chains"] = _delete_count(session, delete(FindingChain).where(FindingChain.run_id.in_(run_ids)))
        reasoning_filters = [AgentReasoning.run_id.in_(run_ids)]
        if task_ids:
            reasoning_filters.append(AgentReasoning.task_id.in_(task_ids))
        reasoning_ids = _scalars(session, select(AgentReasoning.id).where(or_(*reasoning_filters)))
        proposal_filters = [AgentProposal.run_id.in_(run_ids)]
        if reasoning_ids:
            proposal_filters.append(AgentProposal.agent_reasoning_id.in_(reasoning_ids))
        counts["agent_proposals"] = _delete_count(session, delete(AgentProposal).where(or_(*proposal_filters)))
        counts["agent_reasoning_records"] = (
            _delete_count(session, delete(AgentReasoning).where(AgentReasoning.id.in_(reasoning_ids)))
            if reasoning_ids
            else 0
        )
    else:
        counts.update(
            {
                "approvals": 0,
                "exposure_scores": 0,
                "finding_chains": 0,
                "agent_proposals": 0,
                "agent_reasoning_records": 0,
            }
        )
    if finding_ids:
        session.execute(
            update(Task)
            .where(Task.source_finding_id.in_(finding_ids))
            .values(source_finding_id=None)
        )
        counts["finding_integration_links"] = _delete_count(
            session, delete(FindingIntegrationLink).where(FindingIntegrationLink.finding_id.in_(finding_ids))
        )
        counts["finding_repository_links"] = _delete_count(
            session, delete(FindingRepositoryLink).where(FindingRepositoryLink.finding_id.in_(finding_ids))
        )
        counts["ai_enrichments"] = _delete_count(
            session, delete(FindingAiEnrichment).where(FindingAiEnrichment.finding_id.in_(finding_ids))
        )
        counts["remediation_records"] = _delete_count(
            session, delete(FindingRemediation).where(FindingRemediation.finding_id.in_(finding_ids))
        )
    else:
        counts.update(
            {
                "finding_integration_links": 0,
                "finding_repository_links": 0,
                "ai_enrichments": 0,
                "remediation_records": 0,
            }
        )

    counts["artifacts"] = (
        _delete_count(session, delete(EvidenceArtifact).where(EvidenceArtifact.tool_execution_id.in_(execution_ids)))
        if execution_ids
        else 0
    )
    counts["tool_executions"] = (
        _delete_count(session, delete(ToolExecution).where(ToolExecution.id.in_(execution_ids)))
        if execution_ids
        else 0
    )
    counts["tasks"] = _delete_count(session, delete(Task).where(Task.id.in_(task_ids))) if task_ids else 0
    counts["findings"] = (
        _delete_count(session, delete(Finding).where(Finding.id.in_(finding_ids))) if finding_ids else 0
    )
    counts["runs"] = _delete_count(session, delete(Run).where(Run.id.in_(run_ids))) if run_ids else 0

    counts["internal_validation_approvals"] = _delete_count(
        session,
        delete(InternalValidationApproval).where(
            InternalValidationApproval.session_id.in_(
                select(InternalValidationSession.id).where(InternalValidationSession.engagement_id == engagement.id)
            )
        ),
    )
    counts["internal_validation_steps"] = _delete_count(
        session,
        delete(InternalValidationStep).where(
            InternalValidationStep.session_id.in_(
                select(InternalValidationSession.id).where(InternalValidationSession.engagement_id == engagement.id)
            )
        ),
    )
    counts["internal_validation_sessions"] = _delete_count(
        session, delete(InternalValidationSession).where(InternalValidationSession.engagement_id == engagement.id)
    )
    counts["assessment_chains"] = _delete_count(
        session, delete(AssessmentChain).where(AssessmentChain.engagement_id == engagement.id)
    )
    counts["scheduled_runs"] = _delete_count(
        session, delete(ScheduledRun).where(ScheduledRun.engagement_id == engagement.id)
    )
    retained_relevance_ids = set(
        _scalars(
            session,
            select(CapabilityPack.relevance_decision_id).where(
                CapabilityPack.engagement_id == engagement.id,
                CapabilityPack.relevance_decision_id.is_not(None),
            ),
        )
    )
    retained_inventory_ids = set(
        _scalars(
            session,
            select(CapabilityPack.source_inventory_snapshot_id).where(
                CapabilityPack.engagement_id == engagement.id,
                CapabilityPack.source_inventory_snapshot_id.is_not(None),
            ),
        )
    )
    retained_inventory_ids.update(
        _scalars(
            session,
            select(RelevanceDecision.inventory_snapshot_id).where(
                RelevanceDecision.engagement_id == engagement.id,
                RelevanceDecision.id.in_(retained_relevance_ids),
            ),
        )
        if retained_relevance_ids
        else []
    )
    relevance_delete = delete(RelevanceDecision).where(RelevanceDecision.engagement_id == engagement.id)
    if retained_relevance_ids:
        relevance_delete = relevance_delete.where(RelevanceDecision.id.notin_(retained_relevance_ids))
    counts["relevance_decisions"] = _delete_count(session, relevance_delete)
    inventory_delete = delete(InventorySnapshot).where(InventorySnapshot.engagement_id == engagement.id)
    if retained_inventory_ids:
        inventory_delete = inventory_delete.where(InventorySnapshot.id.notin_(retained_inventory_ids))
    counts["inventory_snapshots"] = _delete_count(
        session, inventory_delete
    )
    counts["scopes"] = _delete_count(session, delete(Scope).where(Scope.engagement_id == engagement.id))
    counts["engagement_exposure_scores"] = _delete_count(
        session,
        delete(ExposureScore).where(
            ExposureScore.engagement_id == engagement.id,
            ExposureScore.run_id.is_(None),
        ),
    )
    counts["secret_refs"] = _delete_count(
        session,
        delete(SecretRef).where(
            SecretRef.engagement_id == engagement.id,
            or_(SecretRef.purpose.like("run.access.%"), SecretRef.purpose.like("task.%")),
        ),
    )

    retained_records = ["engagement", "audit_events", "capability_packs", "integration_settings"]
    if retained_inventory_ids or retained_relevance_ids:
        retained_records.append("pack-linked_inventory_or_relevance")
    write_audit_event(
        session=session,
        actor=actor,
        action="engagement.assessment_data_purged",
        object_type="engagement",
        object_id=str(engagement.id),
        metadata={
            "purged_at": purged_at.isoformat(),
            "counts": counts,
            "credential_material_exported": False,
            "retained_records": retained_records,
        },
    )
    return {
        "engagement_id": engagement.id,
        "purged_at": purged_at,
        "counts": counts,
        "credential_material_exported": False,
        "retained_records": retained_records,
        "warnings": [
            "The engagement shell and audit trail are retained so the irreversible purge remains accountable."
        ]
        + (
            ["Pack-linked inventory or relevance records were retained to avoid mutating capability pack lineage."]
            if retained_inventory_ids or retained_relevance_ids
            else []
        ),
    }
