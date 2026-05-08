from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from api.app.config import Settings
from api.app.models import (
    Engagement,
    Finding,
    FindingRemediation,
    FindingValidationRecord,
    Run,
    RunProfile,
    Task,
    ToolExecution,
)
from api.app.models import (
    EvidenceArtifact as EvidenceArtifactRecord,
)
from api.app.services.audit import write_audit_event
from api.app.services.run_profiles import ensure_default_run_profiles
from api.app.services.runs import (
    align_run_configuration_with_engagement,
    dispatch_queued_run_tasks,
    latest_scope_query,
    load_run,
    queue_run_tasks,
    required_approvals,
    target_is_allowed,
)
from workers.orchestration.findings import extract_findings, finding_signature
from workers.runners.base.contracts import EvidenceArtifact

VALIDATION_ACTIVE_STATES = {"validation_queued", "validation_running"}
SUPPORTED_VALIDATION_TOOLS = {"nuclei", "zap", "semgrep", "ldap-enum", "llm-probe"}


@dataclass(slots=True)
class _ValidationSourceContext:
    finding: Finding
    engagement: Engagement
    scope_target: str
    source_task: Task
    source_execution: ToolExecution
    profile_name: str
    configuration_json: dict[str, Any]
    comparison_pattern: str | None


def is_validation_task(task: Task) -> bool:
    payload = task.params_json.get("validation") if isinstance(task.params_json, dict) else None
    return isinstance(payload, dict) and str(payload.get("mode") or "").strip() == "finding_reprobe"


def queue_automatic_validations(
    *,
    session: Session,
    finding_ids: list[UUID],
    settings: Settings,
    actor: str = "finding-validator",
) -> list[UUID]:
    if not settings.auto_validate_findings:
        return []

    dispatchable_run_ids: list[UUID] = []
    for finding_id in finding_ids:
        finding = session.scalar(
            select(Finding)
            .options(selectinload(Finding.run))
            .where(Finding.id == finding_id)
        )
        if finding is None:
            continue
        queued_run_id = _queue_validation_for_finding(
            session=session,
            finding=finding,
            actor=actor,
        )
        if queued_run_id is not None:
            dispatchable_run_ids.append(queued_run_id)
    return dispatchable_run_ids


def dispatch_validation_runs(
    *,
    session: Session,
    run_ids: list[UUID],
    settings: Settings,
    actor: str = "finding-validator",
) -> None:
    for run_id in run_ids:
        run = load_run(session, run_id)
        if run is None:
            continue
        try:
            dispatch_queued_run_tasks(
                session=session,
                run=run,
                actor=actor,
                settings=settings,
            )
        except ValueError:
            continue
        session.commit()
        session.expire_all()


def mark_validation_running(*, session: Session, task: Task) -> None:
    if not is_validation_task(task) or task.source_finding_id is None:
        return

    finding = session.scalar(select(Finding).where(Finding.id == task.source_finding_id))
    if finding is None:
        return

    record = _validation_record_for_task(session=session, task=task)
    if record is None:
        return

    record.status = "validation_running"
    record.note = f"Minimal {task.tool} re-probe is running against {task.target_id}."
    finding.validation_status = "validation_running"


def finalize_validation_for_task(
    *,
    session: Session,
    task: Task,
    execution_record: ToolExecution,
    artifact_pairs: list[tuple[EvidenceArtifact, Any]],
) -> FindingValidationRecord | None:
    if not is_validation_task(task) or task.source_finding_id is None:
        return None

    finding = session.scalar(select(Finding).where(Finding.id == task.source_finding_id))
    if finding is None:
        return None

    record = _validation_record_for_task(session=session, task=task)
    if record is None:
        record = FindingValidationRecord(
            finding_id=finding.id,
            run_id=task.run_id,
            task_id=task.id,
            validation_profile_name=str(task.params_json.get("profile_name") or "") or None,
            validator_tool=task.tool,
            validator_target_id=task.target_id,
            status="validation_running",
            note=f"Minimal {task.tool} re-probe executed against {task.target_id}.",
            metadata_json={},
        )
        session.add(record)
        session.flush()

    extracted_findings = []
    for artifact, artifact_record in artifact_pairs:
        extracted_findings.extend(
            extract_findings(
                task=task,
                artifact=artifact,
                artifact_record=artifact_record,
            )
        )

    signature = finding_signature(title=finding.title, target_id=finding.target_id)
    matched_finding = next(
        (
            candidate
            for candidate in extracted_findings
            if finding_signature(title=candidate.title, target_id=candidate.target_id) == signature
        ),
        None,
    )
    matched_evidence_ref = next(
        (
            artifact_record.uri
            for artifact, artifact_record in artifact_pairs
            if any(
                finding_signature(title=candidate.title, target_id=candidate.target_id) == signature
                for candidate in extract_findings(
                    task=task,
                    artifact=artifact,
                    artifact_record=artifact_record,
                )
            )
        ),
        None,
    )

    validation_config = task.params_json.get("validation") if isinstance(task.params_json, dict) else {}
    comparison_pattern = ""
    if isinstance(validation_config, dict):
        comparison_pattern = str(validation_config.get("comparison_pattern") or "").strip().lower()

    output_haystack = " ".join(
        part
        for part in (
            execution_record.stdout_text or "",
            execution_record.stderr_text or "",
            _artifact_text_haystack(artifact_pairs),
        )
        if part
    ).lower()
    excerpt_matched = bool(comparison_pattern) and comparison_pattern in output_haystack

    if matched_finding is not None or excerpt_matched:
        final_status = "validated_confirmed"
        note = (
            f"Minimal {task.tool} re-probe reproduced '{finding.title}' against {finding.target_id}."
        )
        if excerpt_matched and matched_finding is None:
            note = (
                f"Minimal {task.tool} re-probe matched the original evidence pattern for {finding.target_id}."
            )
    else:
        final_status = "validated_not_reproduced"
        if execution_record.exit_code == 0:
            note = (
                f"Minimal {task.tool} re-probe completed but did not reproduce '{finding.title}' "
                f"against {finding.target_id}."
            )
        else:
            note = (
                f"Minimal {task.tool} re-probe exited {execution_record.exit_code} and did not "
                f"reproduce '{finding.title}' against {finding.target_id}."
            )

    proof_result = _apply_proof_of_resolution_result(
        session=session,
        finding=finding,
        validation_config=validation_config,
        final_status=final_status,
    )

    record.status = final_status
    record.tool_execution_id = execution_record.id
    record.evidence_ref = matched_evidence_ref or _first_artifact_uri(artifact_pairs)
    record.note = note
    record.metadata_json = {
        "comparison_pattern": comparison_pattern or None,
        "excerpt_matched": excerpt_matched,
        "exit_code": execution_record.exit_code,
        "matched_signature": matched_finding is not None,
        "matched_finding_title": matched_finding.title if matched_finding is not None else None,
        "matched_finding_target": matched_finding.target_id if matched_finding is not None else None,
        "candidate_findings": [
            {
                "title": candidate.title,
                "target_id": candidate.target_id,
                "severity": candidate.severity,
            }
            for candidate in extracted_findings
        ],
        "proof_of_resolution": proof_result,
    }
    finding.validation_status = final_status

    write_audit_event(
        session=session,
        actor="finding-validator",
        action="finding.validation.completed",
        object_type="finding",
        object_id=str(finding.id),
        metadata={
            "validation_record_id": str(record.id),
            "task_id": str(task.id),
            "status": final_status,
            "validator_tool": task.tool,
            "target_id": finding.target_id,
            "exit_code": execution_record.exit_code,
        },
    )
    return record


def _apply_proof_of_resolution_result(
    *,
    session: Session,
    finding: Finding,
    validation_config: dict[str, Any],
    final_status: str,
) -> dict[str, Any] | None:
    proof = validation_config.get("proof_of_resolution") if isinstance(validation_config, dict) else None
    if not isinstance(proof, dict) or proof.get("mode") != "micro_scan":
        return None

    result: dict[str, Any] = {
        "mode": "micro_scan",
        "success_condition": proof.get("success_condition"),
        "replay_recipe_sha256": proof.get("replay_recipe_sha256"),
        "auto_closed": False,
    }
    remediation = session.scalar(select(FindingRemediation).where(FindingRemediation.finding_id == finding.id))

    if final_status == "validated_not_reproduced":
        previous_status = finding.status
        previous_remediation_state = remediation.state if remediation is not None else None
        if remediation is None:
            remediation = FindingRemediation(
                finding_id=finding.id,
                state="verified",
                notes="Proof-of-resolution micro-scan did not reproduce the original evidence pattern.",
                created_by="finding-validator",
                updated_by="finding-validator",
            )
            session.add(remediation)
        else:
            remediation.state = "verified"
            remediation.updated_by = "finding-validator"
            if not remediation.notes:
                remediation.notes = "Proof-of-resolution micro-scan did not reproduce the original evidence pattern."
        finding.status = "resolved"
        finding.sla_breached = False
        result.update(
            {
                "auto_closed": True,
                "finding_status_before": previous_status,
                "finding_status_after": finding.status,
                "remediation_state_before": previous_remediation_state,
                "remediation_state_after": remediation.state,
            }
        )
        write_audit_event(
            session=session,
            actor="finding-validator",
            action="finding.proof_of_resolution.verified",
            object_type="finding",
            object_id=str(finding.id),
            metadata={
                "previous_status": previous_status,
                "new_status": finding.status,
                "previous_remediation_state": previous_remediation_state,
                "new_remediation_state": remediation.state,
                "replay_recipe_sha256": proof.get("replay_recipe_sha256"),
            },
        )
    else:
        result["still_reproduced"] = final_status == "validated_confirmed"
        write_audit_event(
            session=session,
            actor="finding-validator",
            action="finding.proof_of_resolution.not_verified",
            object_type="finding",
            object_id=str(finding.id),
            metadata={
                "validation_status": final_status,
                "replay_recipe_sha256": proof.get("replay_recipe_sha256"),
            },
        )

    return result


def serialize_validation_attempt(record: FindingValidationRecord) -> dict[str, Any]:
    return {
        "id": record.id,
        "status": record.status,
        "validation_profile_name": record.validation_profile_name,
        "validator_tool": record.validator_tool,
        "validator_target_id": record.validator_target_id,
        "run_id": record.run_id,
        "task_id": record.task_id,
        "tool_execution_id": record.tool_execution_id,
        "note": record.note,
        "evidence_ref": record.evidence_ref,
        "metadata": dict(record.metadata_json or {}),
        "created_at": record.created_at,
        "updated_at": record.updated_at,
    }


def validation_summary_for_finding(
    *,
    finding: Finding,
    attempts: list[FindingValidationRecord],
) -> dict[str, Any]:
    latest_attempt = attempts[0] if attempts else None
    status = str(finding.validation_status or "unvalidated")
    if status == "validated_confirmed":
        label = "Verified"
        tone = "verified"
    elif status == "validated_not_reproduced":
        label = "Unconfirmed"
        tone = "warning"
    elif status in {"validation_queued", "validation_running"}:
        label = "Validation queued" if status == "validation_queued" else "Validation running"
        tone = "neutral"
    elif status == "validation_skipped":
        label = "Validation skipped"
        tone = "neutral"
    else:
        label = "Pending review"
        tone = "neutral"
    return {
        "status": status,
        "label": label,
        "tone": tone,
        "note": latest_attempt.note if latest_attempt is not None else None,
        "latest_attempt": serialize_validation_attempt(latest_attempt) if latest_attempt is not None else None,
    }


def _queue_validation_for_finding(
    *,
    session: Session,
    finding: Finding,
    actor: str,
) -> UUID | None:
    existing_pending = session.scalar(
        select(FindingValidationRecord)
        .where(FindingValidationRecord.finding_id == finding.id)
        .where(FindingValidationRecord.status.in_(VALIDATION_ACTIVE_STATES))
        .order_by(FindingValidationRecord.created_at.desc(), FindingValidationRecord.id.desc())
    )
    if existing_pending is not None:
        return None

    source_context = _build_source_context(session=session, finding=finding)
    if isinstance(source_context, str):
        _record_validation_skip(
            session=session,
            finding=finding,
            actor=actor,
            note=source_context,
        )
        return None

    record = FindingValidationRecord(
        finding_id=finding.id,
        status="validation_queued",
        validation_profile_name=source_context.profile_name,
        validator_tool=source_context.source_task.tool,
        validator_target_id=source_context.scope_target,
        note=f"Queued minimal {source_context.source_task.tool} re-probe for {finding.target_id}.",
        metadata_json={},
    )
    session.add(record)
    session.flush()

    validation_config = dict(source_context.configuration_json.get("validation", {}))
    validation_config["validation_record_id"] = str(record.id)
    source_context.configuration_json["validation"] = validation_config

    profile = session.scalar(select(RunProfile).where(RunProfile.name == source_context.profile_name))
    if profile is None:
        _record_validation_skip(
            session=session,
            finding=finding,
            actor=actor,
            note=f"Validation skipped because profile {source_context.profile_name} is unavailable.",
        )
        return None

    run = Run(
        engagement_id=source_context.engagement.id,
        profile_id=profile.id,
        requested_by=actor,
        status="requested",
        configuration_json=align_run_configuration_with_engagement(
            source_context.configuration_json,
            engagement=source_context.engagement,
        ),
    )
    session.add(run)
    session.flush()
    record.run_id = run.id

    if required_approvals(profile) == 0:
        scope = session.scalar(latest_scope_query(source_context.engagement.id))
        if scope is None:
            _record_validation_skip(
                session=session,
                finding=finding,
                actor=actor,
                note="Validation skipped because the engagement scope disappeared before queueing the re-probe.",
            )
            session.delete(run)
            return None
        queued_tasks = queue_run_tasks(
            session=session,
            run=run,
            scope=scope,
            profile=profile,
        )
        if queued_tasks:
            record.task_id = queued_tasks[0].id
        write_audit_event(
            session=session,
            actor=actor,
            action="run.queued",
            object_type="run",
            object_id=str(run.id),
            metadata={
                "engagement_id": str(source_context.engagement.id),
                "profile_name": profile.name,
                "finding_validation": True,
                "source_finding_id": str(finding.id),
            },
        )
    else:
        run.status = "pending_approval"
        record.note = (
            f"Validation queued for {finding.target_id}; approval is required before the active re-probe can run."
        )

    finding.validation_status = "validation_queued"
    write_audit_event(
        session=session,
        actor=actor,
        action="finding.validation.queued",
        object_type="finding",
        object_id=str(finding.id),
        metadata={
            "validation_record_id": str(record.id),
            "validation_run_id": str(run.id),
            "profile_name": source_context.profile_name,
            "validator_tool": source_context.source_task.tool,
            "target_id": source_context.scope_target,
        },
    )
    return run.id if required_approvals(profile) == 0 else None


def _record_validation_skip(
    *,
    session: Session,
    finding: Finding,
    actor: str,
    note: str,
) -> None:
    record = FindingValidationRecord(
        finding_id=finding.id,
        status="validation_skipped",
        note=note,
        metadata_json={},
    )
    session.add(record)
    finding.validation_status = "validation_skipped"
    write_audit_event(
        session=session,
        actor=actor,
        action="finding.validation.skipped",
        object_type="finding",
        object_id=str(finding.id),
        metadata={"note": note},
    )


def _build_source_context(*, session: Session, finding: Finding) -> _ValidationSourceContext | str:
    ensure_default_run_profiles(session)

    if finding.run_id is None:
        return "Validation skipped because the finding has no source run."

    source_run = session.scalar(
        select(Run)
        .options(
            selectinload(Run.engagement),
            selectinload(Run.tasks)
            .selectinload(Task.executions)
            .selectinload(ToolExecution.artifacts),
        )
        .where(Run.id == finding.run_id, Run.deleted_at.is_(None))
    )
    if source_run is None or source_run.engagement is None:
        return "Validation skipped because the source engagement context is unavailable."

    scope = session.scalar(latest_scope_query(source_run.engagement_id))
    if scope is None:
        return "Validation skipped because the engagement no longer has an approved scope."

    source_task, source_execution = _find_source_execution(session=session, finding=finding, run=source_run)
    if source_task is None or source_execution is None:
        return "Validation skipped because the original task evidence could not be resolved."
    if source_task.tool not in SUPPORTED_VALIDATION_TOOLS:
        return f"Validation skipped because {source_task.tool} does not have a bounded validator."

    profile_name = _profile_name_for_task(source_task)
    scope_target = _scope_target_for_task(source_task=source_task, finding=finding)
    if not target_is_allowed(scope, scope_target):
        return (
            f"Validation skipped because {scope_target} is outside the current approved scope for this engagement."
        )

    configuration_json = _validation_configuration(
        finding=finding,
        profile_name=profile_name,
        source_task=source_task,
        source_execution=source_execution,
        scope_target=scope_target,
    )
    return _ValidationSourceContext(
        finding=finding,
        engagement=source_run.engagement,
        scope_target=scope_target,
        source_task=source_task,
        source_execution=source_execution,
        profile_name=profile_name,
        configuration_json=configuration_json,
        comparison_pattern=_comparison_pattern(source_execution=source_execution, finding=finding),
    )


def _find_source_execution(
    *,
    session: Session,
    finding: Finding,
    run: Run,
) -> tuple[Task | None, ToolExecution | None]:
    for task in run.tasks:
        for execution in task.executions:
            for artifact in execution.artifacts:
                if artifact.uri == finding.evidence_ref:
                    return task, execution

    execution = session.scalar(
        select(ToolExecution)
        .join(Task, ToolExecution.task_id == Task.id)
        .join(EvidenceArtifactRecord, EvidenceArtifactRecord.tool_execution_id == ToolExecution.id)
        .where(Task.run_id == finding.run_id)
        .where(EvidenceArtifactRecord.uri == finding.evidence_ref)
        .order_by(ToolExecution.created_at.desc(), ToolExecution.id.desc())
    )
    return (execution.task, execution) if execution is not None else (None, None)


def _profile_name_for_task(task: Task) -> str:
    if task.tool == "zap":
        limits = task.params_json.get("limits") if isinstance(task.params_json, dict) else {}
        scan_mode = ""
        if isinstance(limits, dict):
            scan_mode = str(limits.get("scan_mode") or "").strip().lower()
        return "active-web-zap-active" if scan_mode == "spider-active-passive" else "active-web-safe"
    if task.tool == "semgrep":
        return "passive-code-semgrep-audit"
    if task.tool == "ldap-enum":
        return "passive-identity-ldap-enum"
    if task.tool == "llm-probe":
        return "active-llm-application-probe"
    return "passive-web-nuclei-audit"


def _scope_target_for_task(*, source_task: Task, finding: Finding) -> str:
    if source_task.tool == "semgrep":
        return source_task.target_id
    if source_task.tool == "ldap-enum":
        return source_task.target_id
    if source_task.tool == "llm-probe":
        return source_task.target_id
    return finding.target_id or source_task.target_id


def _validation_configuration(
    *,
    finding: Finding,
    profile_name: str,
    source_task: Task,
    source_execution: ToolExecution,
    scope_target: str,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "assessment_type": "Finding Validation",
        "test_profile": "Finding Validation",
        "execution_profile": profile_name,
        "modules": {"finding_validation": True},
        "safety": {
            "max_validation_depth": "light",
            "note": "Bounded minimal re-probe only.",
        },
        "validation": {
            "mode": "finding_reprobe",
            "source_finding_id": str(finding.id),
            "source_run_id": str(finding.run_id) if finding.run_id else None,
            "source_task_id": str(source_task.id),
            "source_execution_id": str(source_execution.id),
            "original_finding_title": finding.title,
            "original_finding_target": finding.target_id,
            "original_evidence_ref": finding.evidence_ref,
            "comparison_pattern": _comparison_pattern(source_execution=source_execution, finding=finding),
        },
    }

    if source_task.tool == "semgrep":
        payload["targets"] = {"paths": [scope_target]}
    elif source_task.tool == "ldap-enum":
        payload["targets"] = {"ldap_hosts": [scope_target]}
        payload["ldap"] = {
            key: value
            for key, value in (source_task.params_json or {}).items()
            if key in {"base_dn", "bind_dn", "password_env", "use_ssl", "page_size"}
        }
    elif source_task.tool == "llm-probe":
        payload["targets"] = {"llm_endpoints": [scope_target]}
        payload["llm"] = {
            key: value
            for key, value in (source_task.params_json or {}).items()
            if key
            in {
                "provider_mode",
                "deterministic_profile",
                "api_key_env",
                "bearer_token_env",
                "model",
                "max_tokens",
                "max_probes",
            }
        }
    elif source_task.tool == "zap":
        payload["targets"] = {"urls": [_normalized_web_target(scope_target)]}
    else:
        target_key = "urls" if _looks_like_url(scope_target) else "domains"
        payload["targets"] = {target_key: [scope_target]}
    return payload


def _normalized_web_target(value: str) -> str:
    parsed = urlparse(value)
    if parsed.scheme:
        return value
    return f"https://{value}"


def _looks_like_url(value: str) -> bool:
    parsed = urlparse(value)
    return parsed.scheme in {"http", "https"}


def _comparison_pattern(*, source_execution: ToolExecution, finding: Finding) -> str | None:
    for candidate in (
        source_execution.stdout_text,
        source_execution.stderr_text,
        finding.summary,
        finding.title,
    ):
        if isinstance(candidate, str) and candidate.strip():
            return candidate.strip().splitlines()[0][:160]
    return None


def _validation_record_for_task(*, session: Session, task: Task) -> FindingValidationRecord | None:
    return session.scalar(
        select(FindingValidationRecord)
        .where(FindingValidationRecord.task_id == task.id)
        .order_by(FindingValidationRecord.created_at.desc(), FindingValidationRecord.id.desc())
    )


def _first_artifact_uri(artifact_pairs: list[tuple[EvidenceArtifact, Any]]) -> str | None:
    if not artifact_pairs:
        return None
    return str(getattr(artifact_pairs[0][1], "uri", "") or "") or None


def _artifact_text_haystack(artifact_pairs: list[tuple[EvidenceArtifact, Any]]) -> str:
    snippets: list[str] = []
    for artifact, _artifact_record in artifact_pairs:
        if artifact.content_type.startswith("text/") or "json" in artifact.content_type:
            snippets.append(artifact.data.decode("utf-8", errors="replace")[:4000])
    return " ".join(snippets)
