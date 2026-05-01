from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import delete, func, or_, select, update
from sqlalchemy.orm import Session

from api.app.models import (
    AgentProposal,
    AgentReasoning,
    Approval,
    AssessmentChain,
    CapabilityPack,
    CapabilityPackDeployment,
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
    IntegrationConfiguration,
    InternalValidationSession,
    InternalValidationStep,
    InventorySnapshot,
    RelevanceDecision,
    RepositoryIntegration,
    Run,
    ScheduledRun,
    Scope,
    Task,
    ToolExecution,
)
from api.app.services.audit import write_audit_event

SOFT_DELETE_RETENTION_DAYS = 30
RUN_DELETE_BLOCKING_STATUSES = {"running", "cancelling"}
TASK_DELETE_BLOCKING_STATUSES = {"running"}


class SoftDeleteBlockedError(ValueError):
    pass


def utcnow() -> datetime:
    return datetime.now(tz=UTC)


def hard_delete_eligible_at(deleted_at: datetime) -> datetime:
    return deleted_at + timedelta(days=SOFT_DELETE_RETENTION_DAYS)


def run_delete_blocker(run: Run) -> str | None:
    status = str(run.status or "").lower()
    if status in RUN_DELETE_BLOCKING_STATUSES:
        return "Stop the run before deleting"
    if any(str(task.status or "").lower() in TASK_DELETE_BLOCKING_STATUSES for task in run.tasks or []):
        return "Stop the run before deleting"
    return None


def run_delete_impact(session: Session, run_ids: list[UUID]) -> dict[str, int]:
    normalized_ids = [run_id for run_id in run_ids if run_id is not None]
    if not normalized_ids:
        return {
            "runs": 0,
            "tasks": 0,
            "tool_executions": 0,
            "artifacts": 0,
            "findings": 0,
            "remediation_records": 0,
            "ai_enrichments": 0,
            "chain_detections": 0,
            "agent_reasoning_records": 0,
            "agent_proposals": 0,
            "approvals": 0,
            "validation_records": 0,
            "exposure_scores": 0,
        }

    def count_scalar(statement) -> int:
        return int(session.scalar(statement) or 0)

    return {
        "runs": len(set(normalized_ids)),
        "tasks": count_scalar(select(func.count(Task.id)).where(Task.run_id.in_(normalized_ids))),
        "tool_executions": count_scalar(
            select(func.count(ToolExecution.id))
            .join(Task, ToolExecution.task_id == Task.id)
            .where(Task.run_id.in_(normalized_ids))
        ),
        "artifacts": count_scalar(
            select(func.count(EvidenceArtifact.id))
            .join(ToolExecution, EvidenceArtifact.tool_execution_id == ToolExecution.id)
            .join(Task, ToolExecution.task_id == Task.id)
            .where(Task.run_id.in_(normalized_ids))
        ),
        "findings": count_scalar(select(func.count(Finding.id)).where(Finding.run_id.in_(normalized_ids))),
        "remediation_records": count_scalar(
            select(func.count(FindingRemediation.id))
            .join(Finding, FindingRemediation.finding_id == Finding.id)
            .where(Finding.run_id.in_(normalized_ids))
        ),
        "ai_enrichments": count_scalar(
            select(func.count(FindingAiEnrichment.id))
            .join(Finding, FindingAiEnrichment.finding_id == Finding.id)
            .where(Finding.run_id.in_(normalized_ids))
        ),
        "chain_detections": count_scalar(
            select(func.count(FindingChain.id)).where(FindingChain.run_id.in_(normalized_ids))
        ),
        "agent_reasoning_records": count_scalar(
            select(func.count(AgentReasoning.id)).where(AgentReasoning.run_id.in_(normalized_ids))
        ),
        "agent_proposals": count_scalar(
            select(func.count(AgentProposal.id)).where(AgentProposal.run_id.in_(normalized_ids))
        ),
        "approvals": count_scalar(select(func.count(Approval.id)).where(Approval.run_id.in_(normalized_ids))),
        "validation_records": count_scalar(
            select(func.count(FindingValidationRecord.id)).where(
                or_(
                    FindingValidationRecord.run_id.in_(normalized_ids),
                    FindingValidationRecord.task_id.in_(
                        select(Task.id).where(Task.run_id.in_(normalized_ids))
                    ),
                )
            )
        ),
        "exposure_scores": count_scalar(
            select(func.count(ExposureScore.id)).where(ExposureScore.run_id.in_(normalized_ids))
        ),
    }


def delete_impact_payload(
    *,
    object_type: str,
    counts: dict[str, int],
    dry_run: bool,
    object_id: UUID | None = None,
    object_ids: list[UUID] | None = None,
    deleted_at: datetime | None = None,
    blocked_reason: str | None = None,
    warnings: list[str] | None = None,
) -> dict:
    effective_deleted_at = deleted_at or utcnow()
    return {
        "object_type": object_type,
        "object_id": object_id,
        "object_ids": object_ids or ([] if object_id is None else [object_id]),
        "dry_run": dry_run,
        "blocked": blocked_reason is not None,
        "blocked_reason": blocked_reason,
        "counts": counts,
        "total_items": sum(int(value or 0) for value in counts.values()),
        "deleted_at": None if dry_run else effective_deleted_at,
        "hard_delete_after_days": SOFT_DELETE_RETENTION_DAYS,
        "hard_delete_eligible_at": hard_delete_eligible_at(effective_deleted_at),
        "deleted_ids": [] if dry_run else (object_ids or ([] if object_id is None else [object_id])),
        "warnings": warnings or [],
    }


def soft_delete_runs(
    *,
    session: Session,
    runs: list[Run],
    actor: str,
    cascade_from_engagement_id: UUID | None = None,
) -> dict:
    blocked = [(run.id, run_delete_blocker(run)) for run in runs]
    blocked = [(run_id, reason) for run_id, reason in blocked if reason]
    if blocked:
        raise SoftDeleteBlockedError(blocked[0][1] or "Stop the run before deleting")

    timestamp = utcnow()
    run_ids = [run.id for run in runs]
    combined_counts = run_delete_impact(session, run_ids)
    for run in runs:
        if run.deleted_at is not None:
            continue
        run.deleted_at = timestamp
        run.updated_at = timestamp
        counts = run_delete_impact(session, [run.id])
        write_audit_event(
            session=session,
            actor=actor,
            action="run.deleted",
            object_type="run",
            object_id=str(run.id),
            metadata={
                "engagement_id": str(run.engagement_id),
                "deleted_at": timestamp.isoformat(),
                "hard_delete_after_days": SOFT_DELETE_RETENTION_DAYS,
                "hard_delete_eligible_at": hard_delete_eligible_at(timestamp).isoformat(),
                "item_count": sum(counts.values()),
                "counts": counts,
                "cascade_from_engagement_id": (
                    str(cascade_from_engagement_id) if cascade_from_engagement_id else None
                ),
            },
        )
    return delete_impact_payload(
        object_type="runs" if len(run_ids) != 1 else "run",
        object_id=run_ids[0] if len(run_ids) == 1 else None,
        object_ids=run_ids,
        counts=combined_counts,
        dry_run=False,
        deleted_at=timestamp,
    )


def engagement_delete_impact(session: Session, engagement_id: UUID) -> tuple[list[UUID], dict[str, int], list[str]]:
    run_ids = list(
        session.scalars(
            select(Run.id).where(Run.engagement_id == engagement_id, Run.deleted_at.is_(None))
        ).all()
    )
    counts = {
        "engagements": 1,
        **run_delete_impact(session, run_ids),
    }

    def count_scalar(statement) -> int:
        return int(session.scalar(statement) or 0)

    counts.update(
        {
            "scopes": count_scalar(select(func.count(Scope.id)).where(Scope.engagement_id == engagement_id)),
            "inventory_snapshots": count_scalar(
                select(func.count(InventorySnapshot.id)).where(InventorySnapshot.engagement_id == engagement_id)
            ),
            "relevance_decisions": count_scalar(
                select(func.count(RelevanceDecision.id)).where(RelevanceDecision.engagement_id == engagement_id)
            ),
            "scheduled_runs": count_scalar(
                select(func.count(ScheduledRun.id)).where(ScheduledRun.engagement_id == engagement_id)
            ),
            "integration_configs": count_scalar(
                select(func.count(IntegrationConfiguration.id)).where(
                    IntegrationConfiguration.engagement_id == engagement_id
                )
            ),
            "repository_integrations": count_scalar(
                select(func.count(RepositoryIntegration.id)).where(RepositoryIntegration.engagement_id == engagement_id)
            ),
            "cicd_triggers": count_scalar(
                select(func.count(CicdTrigger.id)).where(CicdTrigger.engagement_id == engagement_id)
            ),
            "internal_validation_sessions": count_scalar(
                select(func.count(InternalValidationSession.id)).where(
                    InternalValidationSession.engagement_id == engagement_id
                )
            ),
            "assessment_chains": count_scalar(
                select(func.count(AssessmentChain.id)).where(AssessmentChain.engagement_id == engagement_id)
            ),
            "engagement_exposure_scores": count_scalar(
                select(func.count(ExposureScore.id)).where(
                    ExposureScore.engagement_id == engagement_id,
                    ExposureScore.run_id.is_(None),
                )
            ),
        }
    )
    pack_count = count_scalar(select(func.count(CapabilityPack.id)).where(CapabilityPack.engagement_id == engagement_id))
    deployment_count = count_scalar(
        select(func.count(CapabilityPackDeployment.id)).where(CapabilityPackDeployment.engagement_id == engagement_id)
    )
    warnings = []
    if pack_count or deployment_count:
        warnings.append(
            "Capability packs and pack deployment records are retained and are not deleted by this operation."
        )
    return run_ids, counts, warnings


def soft_delete_engagement(
    *,
    session: Session,
    engagement,
    actor: str,
) -> dict:
    run_ids, counts, warnings = engagement_delete_impact(session, engagement.id)
    runs = list(
        session.scalars(
            select(Run).where(Run.id.in_(run_ids)).order_by(Run.created_at.desc(), Run.id.desc())
        ).all()
    )
    blocked = [(run.id, run_delete_blocker(run)) for run in runs]
    blocked = [(run_id, reason) for run_id, reason in blocked if reason]
    if blocked:
        raise SoftDeleteBlockedError(blocked[0][1] or "Stop the run before deleting")

    timestamp = utcnow()
    soft_delete_runs(
        session=session,
        runs=runs,
        actor=actor,
        cascade_from_engagement_id=engagement.id,
    )
    engagement.deleted_at = timestamp
    engagement.updated_at = timestamp
    write_audit_event(
        session=session,
        actor=actor,
        action="engagement.deleted",
        object_type="engagement",
        object_id=str(engagement.id),
        metadata={
            "name": engagement.name,
            "client": engagement.client,
            "deleted_at": timestamp.isoformat(),
            "hard_delete_after_days": SOFT_DELETE_RETENTION_DAYS,
            "hard_delete_eligible_at": hard_delete_eligible_at(timestamp).isoformat(),
            "item_count": sum(counts.values()),
            "counts": counts,
            "run_count": counts.get("runs", 0),
            "warnings": warnings,
        },
    )
    return delete_impact_payload(
        object_type="engagement",
        object_id=engagement.id,
        counts=counts,
        dry_run=False,
        deleted_at=timestamp,
        warnings=warnings,
    )


def _scalars(session: Session, statement) -> list:
    return list(session.scalars(statement).all())


def _delete_count(session: Session, statement) -> int:
    result = session.execute(statement)
    return int(result.rowcount or 0)


def purge_expired_soft_deleted_runs(
    *,
    session: Session,
    actor: str = "system:retention",
    now: datetime | None = None,
) -> dict[str, object]:
    """Hard-delete expired soft-deleted runs without touching retained pack records."""

    effective_now = now or utcnow()
    cutoff = effective_now - timedelta(days=SOFT_DELETE_RETENTION_DAYS)
    expired_runs = list(
        session.scalars(
            select(Run)
            .where(Run.deleted_at.is_not(None), Run.deleted_at <= cutoff)
            .order_by(Run.deleted_at.asc(), Run.id.asc())
        ).all()
    )
    purgeable_runs = [run for run in expired_runs if run_delete_blocker(run) is None]
    skipped_run_ids = [run.id for run in expired_runs if run_delete_blocker(run) is not None]
    run_ids = [run.id for run in purgeable_runs]
    if not run_ids:
        expired_engagement_count = int(
            session.scalar(
                select(func.count(Engagement.id)).where(
                    Engagement.deleted_at.is_not(None),
                    Engagement.deleted_at <= cutoff,
                )
            )
            or 0
        )
        return {
            "eligible_runs": len(expired_runs),
            "purged_runs": 0,
            "skipped_runs": len(skipped_run_ids),
            "skipped_run_ids": [str(run_id) for run_id in skipped_run_ids],
            "expired_engagements_left_soft_deleted": expired_engagement_count,
            "warnings": [
                "Expired engagements remain soft-deleted; hard-purging engagements can remove retained capability pack records."
            ]
            if expired_engagement_count
            else [],
        }

    task_ids = _scalars(session, select(Task.id).where(Task.run_id.in_(run_ids)))
    tool_execution_ids = (
        _scalars(session, select(ToolExecution.id).where(ToolExecution.task_id.in_(task_ids)))
        if task_ids
        else []
    )
    finding_ids = _scalars(session, select(Finding.id).where(Finding.run_id.in_(run_ids)))
    reasoning_conditions = [AgentReasoning.run_id.in_(run_ids)]
    if task_ids:
        reasoning_conditions.append(AgentReasoning.task_id.in_(task_ids))
    reasoning_ids = _scalars(session, select(AgentReasoning.id).where(or_(*reasoning_conditions)))
    counts = run_delete_impact(session, run_ids)

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
    session.execute(
        update(CicdTrigger).where(CicdTrigger.last_run_id.in_(run_ids)).values(last_run_id=None)
    )
    session.execute(
        update(CicdTriggerEvent)
        .where(CicdTriggerEvent.run_id.in_(run_ids))
        .values(run_id=None)
    )
    session.execute(
        update(InternalValidationStep)
        .where(InternalValidationStep.launched_run_id.in_(run_ids))
        .values(launched_run_id=None)
    )
    if finding_ids:
        session.execute(
            update(Task).where(Task.source_finding_id.in_(finding_ids)).values(source_finding_id=None)
        )

    validation_filters = [FindingValidationRecord.run_id.in_(run_ids)]
    if finding_ids:
        validation_filters.append(FindingValidationRecord.finding_id.in_(finding_ids))
    if task_ids:
        validation_filters.append(FindingValidationRecord.task_id.in_(task_ids))
    if tool_execution_ids:
        validation_filters.append(FindingValidationRecord.tool_execution_id.in_(tool_execution_ids))
    deleted_counts = {
        "validation_records": _delete_count(
            session, delete(FindingValidationRecord).where(or_(*validation_filters))
        ),
        "approvals": _delete_count(session, delete(Approval).where(Approval.run_id.in_(run_ids))),
        "exposure_scores": _delete_count(
            session, delete(ExposureScore).where(ExposureScore.run_id.in_(run_ids))
        ),
        "chain_detections": _delete_count(
            session, delete(FindingChain).where(FindingChain.run_id.in_(run_ids))
        ),
    }
    if finding_ids:
        deleted_counts.update(
            {
                "finding_integration_links": _delete_count(
                    session,
                    delete(FindingIntegrationLink).where(FindingIntegrationLink.finding_id.in_(finding_ids)),
                ),
                "finding_repository_links": _delete_count(
                    session,
                    delete(FindingRepositoryLink).where(FindingRepositoryLink.finding_id.in_(finding_ids)),
                ),
                "ai_enrichments": _delete_count(
                    session, delete(FindingAiEnrichment).where(FindingAiEnrichment.finding_id.in_(finding_ids))
                ),
                "remediation_records": _delete_count(
                    session, delete(FindingRemediation).where(FindingRemediation.finding_id.in_(finding_ids))
                ),
            }
        )
    else:
        deleted_counts.update(
            {
                "finding_integration_links": 0,
                "finding_repository_links": 0,
                "ai_enrichments": 0,
                "remediation_records": 0,
            }
        )

    proposal_filters = [AgentProposal.run_id.in_(run_ids)]
    if reasoning_ids:
        proposal_filters.append(AgentProposal.agent_reasoning_id.in_(reasoning_ids))
    deleted_counts["agent_proposals"] = _delete_count(
        session, delete(AgentProposal).where(or_(*proposal_filters))
    )
    if reasoning_ids:
        deleted_counts["agent_reasoning_records"] = _delete_count(
            session, delete(AgentReasoning).where(AgentReasoning.id.in_(reasoning_ids))
        )
    else:
        deleted_counts["agent_reasoning_records"] = 0
    if tool_execution_ids:
        deleted_counts["artifacts"] = _delete_count(
            session, delete(EvidenceArtifact).where(EvidenceArtifact.tool_execution_id.in_(tool_execution_ids))
        )
    else:
        deleted_counts["artifacts"] = 0
    if task_ids:
        deleted_counts["tool_executions"] = _delete_count(
            session, delete(ToolExecution).where(ToolExecution.task_id.in_(task_ids))
        )
    else:
        deleted_counts["tool_executions"] = 0
    if finding_ids:
        deleted_counts["findings"] = _delete_count(session, delete(Finding).where(Finding.id.in_(finding_ids)))
    else:
        deleted_counts["findings"] = 0
    if task_ids:
        deleted_counts["tasks"] = _delete_count(session, delete(Task).where(Task.id.in_(task_ids)))
    else:
        deleted_counts["tasks"] = 0
    deleted_counts["runs"] = _delete_count(session, delete(Run).where(Run.id.in_(run_ids)))

    expired_engagement_count = int(
        session.scalar(
            select(func.count(Engagement.id)).where(
                Engagement.deleted_at.is_not(None),
                Engagement.deleted_at <= cutoff,
            )
        )
        or 0
    )
    warnings = []
    if expired_engagement_count:
        warnings.append(
            "Expired engagements remain soft-deleted; hard-purging engagements can remove retained capability pack records."
        )
    write_audit_event(
        session=session,
        actor=actor,
        action="soft_delete.retention_purged",
        object_type="runs",
        object_id=",".join(str(run_id) for run_id in run_ids),
        metadata={
            "retention_days": SOFT_DELETE_RETENTION_DAYS,
            "cutoff": cutoff.isoformat(),
            "purged_run_ids": [str(run_id) for run_id in run_ids],
            "skipped_run_ids": [str(run_id) for run_id in skipped_run_ids],
            "preview_counts": counts,
            "deleted_counts": deleted_counts,
            "expired_engagements_left_soft_deleted": expired_engagement_count,
            "warnings": warnings,
        },
    )
    return {
        "eligible_runs": len(expired_runs),
        "purged_runs": len(run_ids),
        "skipped_runs": len(skipped_run_ids),
        "skipped_run_ids": [str(run_id) for run_id in skipped_run_ids],
        "counts": deleted_counts,
        "expired_engagements_left_soft_deleted": expired_engagement_count,
        "warnings": warnings,
    }
