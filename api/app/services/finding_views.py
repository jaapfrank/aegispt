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
from api.app.models import (
    CapabilityPack,
    EvidenceArtifact,
    Finding,
    FindingIntegrationLink,
    FindingRemediation,
    FindingRepositoryLink,
    FindingValidationRecord,
    IntegrationConfiguration,
    Run,
    Task,
    ToolExecution,
)
from api.app.schemas.finding_views import (
    FindingEvidenceReplayRead,
    FindingRelatedArtifactRead,
    FindingRelatedExecutionRead,
    FindingTheaterRead,
    FindingValidationAttemptRead,
)
from api.app.schemas.findings import FindingRead
from api.app.services.ai_enrichment import (
    build_detection_engineering_for_finding,
    build_threat_context_for_finding,
    finding_ai_enrichment_view,
)
from api.app.services.autofix import autofix_view
from api.app.services.finding_chains import build_finding_chain_context
from api.app.services.finding_validator import (
    serialize_validation_attempt,
    validation_summary_for_finding,
)
from api.app.services.reports import artifact_download_path, remediation_priority_for_finding
from api.app.services.repository_integration import repository_context_for_finding
from api.app.services.risk_scoring import calculate_risk
from api.app.services.threat_intel import build_finding_threat_intel_badges

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
            selectinload(Finding.ai_enrichment),
            selectinload(Finding.repository_links).selectinload(FindingRepositoryLink.repo_integration),
            selectinload(Finding.validation_records),
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
    if finding.validation_status == "validated_confirmed":
        return "minimal re-probe confirmed the finding against the current target"
    if finding.validation_status == "validated_not_reproduced":
        return "latest minimal re-probe did not reproduce the original evidence"
    if finding.validation_status == "validation_running":
        return "minimal validation re-probe is currently running"
    if finding.validation_status == "validation_queued":
        return "minimal validation re-probe is queued"
    if finding.validation_status == "validation_skipped":
        return "automated validation was skipped; analyst review remains required"
    if finding.status == "resolved":
        return "resolved and ready for retest confirmation"
    if finding.status in {"accepted_risk", "false_positive"}:
        return "closed with analyst disposition"
    if _finding_has_replay_ready_evidence(finding):
        return "evidence-linked and ready for replay"
    if finding.evidence_ref:
        return "evidence linked, but hash/replay recipe completeness still needs review"
    return "needs analyst validation"


def _finding_artifact(finding: Finding) -> EvidenceArtifact | None:
    run = finding.run
    if run is None:
        return None
    for task in run.tasks:
        for execution in task.executions:
            for artifact in execution.artifacts:
                if artifact.uri == finding.evidence_ref:
                    return artifact
    return None


def _finding_has_replay_ready_evidence(finding: Finding) -> bool:
    artifact = _finding_artifact(finding)
    if artifact is None:
        return False
    sha256 = (artifact.sha256 or "").strip()
    recipe = finding.replay_recipe_json if isinstance(finding.replay_recipe_json, dict) else {}
    return (
        len(sha256) == 64
        and sha256 != "hash-unavailable"
        and bool(recipe.get("tool"))
        and bool(recipe.get("target"))
        and bool(recipe.get("params_json") is not None)
        and bool(recipe.get("scope_allowlist") is not None)
    )


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


def _linked_integrations(session: Session, finding: Finding) -> dict[str, Any]:
    def link_payload(link: FindingIntegrationLink) -> dict[str, Any]:
        configuration = link.integration_configuration
        integration_type = configuration.integration_type if configuration is not None else "unknown"
        return {
            "id": str(link.id),
            "integration_configuration_id": str(link.integration_configuration_id),
            "integration_type": integration_type,
            "display_name": configuration.display_name if configuration is not None else None,
            "issue_key": link.issue_key,
            "issue_url": link.issue_url,
            "issue_status": link.issue_status,
            "last_sync_state": link.last_sync_state,
            "last_synced_at": _format_datetime(link.last_synced_at),
            "last_sync_error": link.last_sync_error,
            "last_sync_payload": dict(link.last_sync_payload_json or {}),
            "created_by": link.created_by,
            "updated_by": link.updated_by,
            "created_at": _format_datetime(link.created_at),
            "updated_at": _format_datetime(link.updated_at),
        }

    links = session.scalars(
        select(FindingIntegrationLink)
        .join(IntegrationConfiguration)
        .options(selectinload(FindingIntegrationLink.integration_configuration))
        .where(
            FindingIntegrationLink.finding_id == finding.id,
        )
        .order_by(FindingIntegrationLink.updated_at.desc(), FindingIntegrationLink.id.desc())
    ).all()

    linked: dict[str, Any] = {
        "jira": None,
        "webhook": None,
    }
    for link in links:
        configuration = link.integration_configuration
        if configuration is None:
            continue
        integration_type = configuration.integration_type
        if integration_type not in linked:
            linked[integration_type] = link_payload(link)
        elif linked[integration_type] is None:
            linked[integration_type] = link_payload(link)

    return linked


def _validation_attempts(finding: Finding) -> list[FindingValidationRecord]:
    return sorted(
        list(finding.validation_records or []),
        key=lambda record: (record.created_at, record.id.hex),
        reverse=True,
    )


def _validation_history(finding: Finding) -> list[FindingValidationAttemptRead]:
    return [
        FindingValidationAttemptRead.model_validate(serialize_validation_attempt(record))
        for record in _validation_attempts(finding)
    ]


def _remediation_view(
    *,
    finding: Finding,
    remediation: FindingRemediation | None,
    linked_retests: list[dict[str, Any]],
    linked_integrations: dict[str, Any],
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
            "ai_fix_suggestion": remediation.ai_fix_suggestion,
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
        "integrations": linked_integrations,
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
                        sha256=artifact.sha256,
                        hash_status=str(artifact.metadata_json.get("hash_status") or "unknown"),
                        timestamp_status=str(artifact.metadata_json.get("timestamp_status") or "not-available"),
                        timestamp_response_uri=(
                            str(artifact.metadata_json.get("timestamp_response_uri"))
                            if artifact.metadata_json.get("timestamp_response_uri")
                            else None
                        ),
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
                    stdout_excerpt=_matched_excerpt(finding, execution.stdout_text),
                    stderr_excerpt=_matched_excerpt(finding, execution.stderr_text),
                    created_at=execution.created_at,
                    artifacts=related_artifacts,
                )
            )
    return matches


def _matched_excerpt(finding: Finding, output: str | None, *, limit: int = 4000) -> str | None:
    text = output or ""
    if not text:
        return None
    tokens = [
        token.strip().lower()
        for token in (
            finding.target_id,
            finding.title,
            finding.summary or "",
            str((finding.replay_recipe_json or {}).get("expected_match_pattern") or ""),
        )
        if isinstance(token, str) and token.strip()
    ]
    matched_lines: list[str] = []
    for line in text.splitlines():
        line_lower = line.lower()
        if any(token and token in line_lower for token in tokens):
            matched_lines.append(line)
    excerpt = "\n".join(matched_lines) if matched_lines else text
    if len(excerpt) <= limit:
        return excerpt or None
    return excerpt[: limit - 32].rstrip() + "\n... [truncated for API view]"


def _evidence_integrity_summary(finding: Finding) -> dict[str, Any]:
    artifact = _finding_artifact(finding)
    recipe = finding.replay_recipe_json if isinstance(finding.replay_recipe_json, dict) else None
    if artifact is None:
        return {
            "status": "incomplete",
            "hash_status": "missing-artifact-record",
            "timestamp_status": "not-available",
            "ready_for_replay": False,
            "replay_recipe": recipe,
        }
    hash_status = str((artifact.metadata_json or {}).get("hash_status") or "unknown")
    timestamp_status = str((artifact.metadata_json or {}).get("timestamp_status") or "not-available")
    ready = _finding_has_replay_ready_evidence(finding)
    return {
        "status": "ready" if ready else "needs-review",
        "artifact_id": str(artifact.id),
        "artifact_uri": artifact.uri,
        "sha256": artifact.sha256,
        "hash_status": hash_status,
        "timestamp_status": timestamp_status,
        "timestamp_response_uri": (artifact.metadata_json or {}).get("timestamp_response_uri"),
        "ready_for_replay": ready,
        "replay_recipe": recipe,
    }


def build_finding_theater(
    session: Session,
    finding_id: UUID | str,
    *,
    autofix_enabled: bool = False,
) -> FindingTheaterRead | None:
    finding = _load_finding(session, finding_id)
    if finding is None:
        return None
    remediation = _load_remediation(session, finding)
    linked_retests = _linked_retests(session, finding)
    linked_integrations = _linked_integrations(session, finding)
    validation_attempts = _validation_attempts(finding)
    ai_enrichment = finding_ai_enrichment_view(finding.ai_enrichment)
    has_ai_enrichment = ai_enrichment.get("available") is True
    business_impact = (
        str(ai_enrichment.get("business_impact"))
        if has_ai_enrichment and ai_enrichment.get("business_impact")
        else _business_impact(finding)
    )
    technical_details = (
        str(ai_enrichment.get("technical_context"))
        if has_ai_enrichment and ai_enrichment.get("technical_context")
        else _technical_details(finding)
    )
    remediation_view = _remediation_view(
        finding=finding,
        remediation=remediation,
        linked_retests=linked_retests,
        linked_integrations=linked_integrations,
    )
    if has_ai_enrichment and ai_enrichment.get("remediation_narrative"):
        remediation_view = {
            **remediation_view,
            "ai_narrative": str(ai_enrichment["remediation_narrative"]),
        }
    repository_context = repository_context_for_finding(
        session=session,
        finding=finding,
        autofix_available=bool(finding.autofix_json),
    )

    return FindingTheaterRead(
        finding=FindingRead.model_validate(finding),
        severity_rank=SEVERITY_RANK.get(finding.severity, SEVERITY_RANK["unknown"]),
        confidence_label=_confidence_label(finding),
        exploitability=_exploitability(finding),
        business_impact=business_impact,
        technical_details=technical_details,
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
        remediation=remediation_view,
        ai_enrichment=ai_enrichment,
        autofix=autofix_view(
            autofix_json=finding.autofix_json,
            enabled=autofix_enabled,
            ai_fix_suggestion=remediation.ai_fix_suggestion if remediation is not None else None,
        ),
        repository_context=repository_context,
        threat_context=build_threat_context_for_finding(finding),
        detection_engineering=build_detection_engineering_for_finding(finding),
        vulnerability_chains=build_finding_chain_context(session=session, finding=finding),
        threat_intel_badges=build_finding_threat_intel_badges(session, finding),
        validation=validation_summary_for_finding(finding=finding, attempts=validation_attempts),
        evidence_integrity=_evidence_integrity_summary(finding),
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
    validation_history = _validation_history(finding)

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
