from __future__ import annotations

from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from api.app.methodology import (
    control_family_label,
    default_remediation_detail,
    default_remediation_summary,
    format_wstg_reference,
    nist_phase_label,
    ptes_phase_label,
    wstg_area_for_identifier,
)
from api.app.models import CapabilityPack, Finding, FindingRemediation, Run, Task, ToolExecution
from api.app.schemas.finding_views import (
    FindingEvidenceReplayRead,
    FindingRelatedArtifactRead,
    FindingRelatedExecutionRead,
    FindingTheaterRead,
)
from api.app.schemas.findings import FindingRead
from api.app.services.reports import artifact_download_path, remediation_priority_for_finding
from api.app.services.risk_scoring import calculate_risk

SEVERITY_RANK = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
    "unknown": 5,
}


def _load_finding(session: Session, finding_id: UUID | str) -> Finding | None:
    return session.scalar(
        select(Finding)
        .options(
            selectinload(Finding.run)
            .selectinload(Run.tasks)
            .selectinload(Task.executions)
            .selectinload(ToolExecution.artifacts),
            selectinload(Finding.source_pack).selectinload(CapabilityPack.artifacts),
            selectinload(Finding.source_pack_artifact),
            selectinload(Finding.source_inventory_snapshot),
            selectinload(Finding.source_relevance_decision),
        )
        .where(Finding.id == finding_id)
    )


def _confidence_label(finding: Finding) -> str:
    if finding.source_pack_id is not None and finding.evidence_ref:
        return "high"
    if finding.evidence_ref:
        return "medium"
    return "review"


def _business_impact(finding: Finding) -> str:
    severity = (finding.severity or "").lower()
    if severity == "critical":
        return "Likely to create immediate customer or business risk if reachable in the assessed scope."
    if severity == "high":
        return "Could materially affect confidentiality, integrity, or privileged workflows in the assessed environment."
    if severity == "medium":
        return "May enable follow-on abuse, weakened trust boundaries, or meaningful operational disruption."
    if severity == "low":
        return "Limited direct impact, but worth addressing to reduce exposure and attack surface growth."
    return "Business impact has not been fully quantified yet and should be reviewed alongside customer context."


def _technical_details(finding: Finding) -> str:
    parts = [
        f"Target {finding.target_id} produced evidence linked through {finding.evidence_ref}.",
        f"The control family is {control_family_label(finding.control_family) or 'not yet classified'}.",
    ]
    if finding.summary:
        parts.append(finding.summary)
    if finding.wstg_id:
        parts.append(
            f"The mapped technical coverage area is {wstg_area_for_identifier(finding.wstg_id) or 'unassigned'}."
        )
    return " ".join(parts)


def _exploitability(finding: Finding) -> str | None:
    severity = (finding.severity or "").lower()
    if severity in {"critical", "high"}:
        return "operator-validated"
    if severity == "medium":
        return "plausible"
    if severity in {"low", "info"}:
        return "limited"
    return None


def _verification_status(finding: Finding) -> str:
    if finding.status == "resolved":
        return "resolved and ready for retest confirmation"
    if finding.status in {"accepted_risk", "false_positive"}:
        return "closed with analyst disposition"
    if finding.evidence_ref:
        return "evidence-linked and ready for replay"
    return "needs analyst validation"


def _next_steps(finding: Finding) -> list[str]:
    steps = [
        f"Prioritize remediation as {remediation_priority_for_finding(finding)}.",
        default_remediation_summary(finding.control_family),
        default_remediation_detail(finding.control_family),
    ]
    if finding.status in {"open", "triaged", "reopened", "in_progress"}:
        steps.append("Schedule replay or retest after remediation to confirm closure.")
    elif finding.status == "resolved":
        steps.append("Capture retest evidence and update verification status in the next run.")
    return steps


def _format_datetime(value: Any) -> str | None:
    return value.isoformat() if value is not None and hasattr(value, "isoformat") else None


def _load_remediation(session: Session, finding: Finding) -> FindingRemediation | None:
    return session.scalar(select(FindingRemediation).where(FindingRemediation.finding_id == finding.id))


def _linked_retests(session: Session, finding: Finding) -> list[dict[str, Any]]:
    if finding.run is None:
        return []

    runs = session.scalars(
        select(Run)
        .options(selectinload(Run.profile), selectinload(Run.tasks))
        .where(Run.engagement_id == finding.run.engagement_id)
        .order_by(Run.created_at.desc(), Run.id.desc())
    ).all()

    linked_runs: list[dict[str, Any]] = []
    source_finding_id = str(finding.id)
    for run in runs:
        configuration = run.configuration_json if isinstance(run.configuration_json, dict) else {}
        retest = configuration.get("retest")
        if not isinstance(retest, dict) or retest.get("source_finding_id") != source_finding_id:
            continue

        tasks = list(run.tasks or [])
        linked_runs.append(
            {
                "run_id": str(run.id),
                "source_run_id": retest.get("source_run_id"),
                "status": run.status,
                "profile_name": run.profile.name if run.profile is not None else configuration.get("execution_profile"),
                "verification_state": retest.get("verification_state") or "requested",
                "operator_notes": retest.get("operator_notes"),
                "remediation_state": retest.get("remediation_state"),
                "requested_at": _format_datetime(run.created_at),
                "updated_at": _format_datetime(run.updated_at),
                "verification_timestamp": (
                    _format_datetime(run.updated_at)
                    if run.status in {"completed", "completed_with_errors", "failed", "cancelled"}
                    else None
                ),
                "queued_task_count": sum(1 for task in tasks if task.status == "queued"),
                "completed_task_count": sum(1 for task in tasks if task.status == "completed"),
                "failed_task_count": sum(1 for task in tasks if task.status == "failed"),
            }
        )

    return linked_runs


def _remediation_view(
    *,
    finding: Finding,
    remediation: FindingRemediation | None,
    linked_retests: list[dict[str, Any]],
) -> dict[str, Any]:
    latest_retest = linked_retests[0] if linked_retests else None
    return {
        "priority": remediation_priority_for_finding(finding),
        "summary": default_remediation_summary(finding.control_family),
        "detail": default_remediation_detail(finding.control_family),
        "record": {
            "id": str(remediation.id),
            "state": remediation.state,
            "notes": remediation.notes,
            "owner": remediation.owner,
            "created_by": remediation.created_by,
            "updated_by": remediation.updated_by,
            "created_at": _format_datetime(remediation.created_at),
            "updated_at": _format_datetime(remediation.updated_at),
        }
        if remediation is not None
        else None,
        "linked_retests": linked_retests,
        "linked_retest_count": len(linked_retests),
        "latest_retest_status": latest_retest.get("status") if latest_retest is not None else None,
        "proof_of_resolution_ready": any(
            item.get("status") == "completed" and item.get("verification_state") in {"requested", "verified"}
            for item in linked_retests
        ),
    }


def _related_executions(finding: Finding) -> list[FindingRelatedExecutionRead]:
    run = finding.run
    if run is None:
        return []

    matches: list[FindingRelatedExecutionRead] = []
    for task in run.tasks:
        for execution in task.executions:
            related_artifacts = []
            for artifact in execution.artifacts:
                if artifact.uri != finding.evidence_ref and artifact.id != finding.source_pack_artifact_id:
                    continue
                related_artifacts.append(
                    FindingRelatedArtifactRead(
                        artifact_id=artifact.id,
                        kind=artifact.kind,
                        uri=artifact.uri,
                        download_path=artifact_download_path(artifact.id),
                        name=str(artifact.metadata_json.get("name", artifact.id)),
                        redaction_state=artifact.redaction_state,
                        created_at=artifact.created_at,
                    )
                )
            if not related_artifacts:
                continue
            matches.append(
                FindingRelatedExecutionRead(
                    execution_id=execution.id,
                    task_id=task.id,
                    tool=task.tool,
                    target_id=task.target_id,
                    task_status=task.status,
                    exit_code=execution.exit_code,
                    tool_version=execution.tool_version,
                    stdout_excerpt=(execution.stdout_text or "")[:400] or None,
                    stderr_excerpt=(execution.stderr_text or "")[:400] or None,
                    created_at=execution.created_at,
                    artifacts=related_artifacts,
                )
            )
    return matches


def build_finding_theater(session: Session, finding_id: UUID | str) -> FindingTheaterRead | None:
    finding = _load_finding(session, finding_id)
    if finding is None:
        return None
    remediation = _load_remediation(session, finding)
    linked_retests = _linked_retests(session, finding)

    return FindingTheaterRead(
        finding=FindingRead.model_validate(finding),
        severity_rank=SEVERITY_RANK.get(finding.severity, SEVERITY_RANK["unknown"]),
        confidence_label=_confidence_label(finding),
        exploitability=_exploitability(finding),
        business_impact=_business_impact(finding),
        technical_details=_technical_details(finding),
        evidence_summary="Evidence is linked through stored artifact references and replayable task executions."
        if finding.evidence_ref
        else "Evidence linkage is incomplete and should be reviewed.",
        provenance={
            "origin": finding.finding_origin,
            "source_pack_id": str(finding.source_pack_id) if finding.source_pack_id else None,
            "source_pack_version": finding.source_pack_version,
            "source_inventory_snapshot_id": (
                str(finding.source_inventory_snapshot_id) if finding.source_inventory_snapshot_id else None
            ),
            "source_relevance_decision_id": (
                str(finding.source_relevance_decision_id) if finding.source_relevance_decision_id else None
            ),
        },
        methodology={
            "ptes_phase": finding.ptes_phase,
            "ptes_label": ptes_phase_label(finding.ptes_phase),
            "nist_phase": finding.nist_phase,
            "nist_label": nist_phase_label(finding.nist_phase),
            "wstg_reference": format_wstg_reference(finding.wstg_id, finding.wstg_version),
            "wstg_area": wstg_area_for_identifier(finding.wstg_id),
            "asvs_reference": finding.asvs_reference,
            "control_family": control_family_label(finding.control_family),
            "methodology_tags": list(finding.methodology_tags or []),
        },
        remediation=_remediation_view(
            finding=finding,
            remediation=remediation,
            linked_retests=linked_retests,
        ),
        verification_status=_verification_status(finding),
        next_steps=_next_steps(finding),
        risk_snapshot=calculate_risk(finding),
    )


def build_finding_evidence_replay(session: Session, finding_id: UUID | str) -> FindingEvidenceReplayRead | None:
    finding = _load_finding(session, finding_id)
    if finding is None:
        return None

    inventory_source: dict[str, Any] = {}
    if finding.source_inventory_snapshot is not None:
        inventory_source = {
            "snapshot_id": str(finding.source_inventory_snapshot.id),
            "confidence_score": finding.source_inventory_snapshot.confidence_score,
            "summary": dict(finding.source_inventory_snapshot.summary_json or {}),
        }

    relevance_source: dict[str, Any] = {}
    if finding.source_relevance_decision is not None:
        relevance_source = {
            "decision_id": str(finding.source_relevance_decision.id),
            "methodology_tags": list(finding.source_relevance_decision.methodology_tags or []),
            "confidence_score": finding.source_relevance_decision.confidence_score,
            "justification": finding.source_relevance_decision.justification_text,
        }

    pack_provenance: dict[str, Any] = {}
    if finding.source_pack is not None:
        pack_provenance = {
            "pack_id": str(finding.source_pack.id),
            "name": finding.source_pack.name,
            "version": finding.source_pack.version,
            "status": finding.source_pack.status,
            "methodology_tags": list(finding.source_pack.methodology_tags or []),
            "manifest": dict(finding.source_pack.manifest_json or {}),
        }

    related_executions = _related_executions(finding)
    validation_history = [
        {
            "status": finding.status,
            "verification_status": _verification_status(finding),
            "evidence_linked": bool(finding.evidence_ref),
            "related_execution_count": len(related_executions),
        }
    ]

    return FindingEvidenceReplayRead(
        finding=FindingRead.model_validate(finding),
        evidence_ref=finding.evidence_ref,
        methodology_references={
            "ptes": ptes_phase_label(finding.ptes_phase),
            "nist": nist_phase_label(finding.nist_phase),
            "wstg": format_wstg_reference(finding.wstg_id, finding.wstg_version),
            "asvs": finding.asvs_reference,
            "control_family": control_family_label(finding.control_family),
        },
        pack_provenance=pack_provenance,
        inventory_source=inventory_source,
        relevance_source=relevance_source,
        validation_history=validation_history,
        related_executions=related_executions,
    )
