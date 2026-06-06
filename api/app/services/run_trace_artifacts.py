from __future__ import annotations

import json
import logging
from hashlib import sha256
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import selectinload

from api.app.config import Settings, get_settings
from api.app.models import EvidenceArtifact, Finding, Run, Task, ToolExecution
from api.app.services.artifact_storage import (
    artifact_storage_config_from_settings,
    store_artifact_bytes_with_fallback,
)
from api.app.services.audit import write_audit_event
from api.app.services.coverage_truth import build_coverage_truth
from api.app.services.evidence_integrity import apply_artifact_integrity_metadata

logger = logging.getLogger(__name__)

RUN_TRACE_ARTIFACT_NAME = "run-trace.jsonl"
RUN_TRACE_ARTIFACT_KIND = "training-run-trace"
RUN_TRACE_CONTENT_TYPE = "application/x-ndjson"
TERMINAL_STATUSES = {"completed", "completed_with_errors", "failed", "cancelled", "rejected"}


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _trace_config(run: Run) -> dict[str, Any]:
    configuration = _as_dict(run.configuration_json)
    explicit = _as_dict(configuration.get("run_trace_artifact"))
    if explicit:
        return explicit
    training = _as_dict(configuration.get("training"))
    if "run_trace_artifact_enabled" in training:
        return {"enabled": training.get("run_trace_artifact_enabled")}
    loop = _as_dict(configuration.get("ai_assessment_loop"))
    if "run_trace_artifact_enabled" in loop:
        return {"enabled": loop.get("run_trace_artifact_enabled")}
    if "run_trace_artifact_enabled" in configuration:
        return {"enabled": configuration.get("run_trace_artifact_enabled")}
    return {}


def run_trace_artifact_enabled(run: Run) -> bool:
    value = _trace_config(run).get("enabled", False)
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _latest_execution(tasks: list[Task]) -> ToolExecution | None:
    executions = [
        execution
        for task in tasks
        for execution in list(getattr(task, "executions", None) or [])
    ]
    if not executions:
        return None
    return sorted(
        executions,
        key=lambda item: (str(getattr(item, "created_at", "") or ""), str(getattr(item, "id", "") or "")),
    )[-1]


def _existing_trace_artifact(session: Any, run: Run) -> EvidenceArtifact | None:
    if run.id is None:
        return None
    return session.scalar(
        select(EvidenceArtifact)
        .join(ToolExecution, EvidenceArtifact.tool_execution_id == ToolExecution.id)
        .join(Task, ToolExecution.task_id == Task.id)
        .where(Task.run_id == run.id, EvidenceArtifact.kind == RUN_TRACE_ARTIFACT_KIND)
        .limit(1)
    )


def _candidate_ids(run: Run, tasks: list[Task], config: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for key in ("scenario_id", "target_id", "lab_target_id", "challenge_id"):
        value = config.get(key) or _as_dict(run.configuration_json).get(key)
        if value:
            values.append(str(value).strip())
    for task in tasks:
        if task.target_id:
            values.append(str(task.target_id).strip())
        params = _as_dict(task.params_json)
        for key in ("scenario_id", "target_id", "lab_target_id", "challenge_id"):
            if params.get(key):
                values.append(str(params[key]).strip())
    return sorted({value for value in values if value})


def _trace_bytes(trace: list[dict[str, Any]]) -> bytes:
    return (
        "\n".join(json.dumps(step, sort_keys=True) for step in trace) + "\n"
    ).encode("utf-8")


def persist_run_trace_artifact(
    *,
    session: Any,
    run: Run,
    actor: str = "system:run-trace-artifact",
    settings: Settings | None = None,
) -> EvidenceArtifact | None:
    """Persist a derived run_trace.jsonl artifact for opted-in terminal runs.

    The current schema has execution-level artifacts, not run-level artifacts.
    To avoid creating a synthetic task, the derived trace is attached to the
    latest existing ToolExecution and labelled with metadata that marks it as a
    run-scoped training trace.
    """
    if run.id is None or str(run.status or "").lower() not in TERMINAL_STATUSES:
        return None
    if not run_trace_artifact_enabled(run):
        return None

    tasks = list(
        session.scalars(
            select(Task)
            .options(selectinload(Task.executions).selectinload(ToolExecution.artifacts))
            .where(Task.run_id == run.id)
        ).all()
    )
    host_execution = _latest_execution(tasks)
    if host_execution is None:
        return None
    existing = _existing_trace_artifact(session, run)
    if existing is not None:
        return existing

    findings = list(session.scalars(select(Finding).where(Finding.run_id == run.id)).all())
    config = _trace_config(run)

    from scripts.training.trace_record import (
        from_runner_tasks,
        resolve_lab_truth_label,
    )

    lab_truth = resolve_lab_truth_label(
        str(config.get("lab_truth") or "auto"),
        registry_path=config.get("lab_truth_registry"),
        candidate_ids=_candidate_ids(run, tasks, config),
    )
    try:
        coverage_truth = build_coverage_truth(session, run=run)
    except Exception as exc:  # noqa: BLE001
        logger.warning("run_trace_artifact: coverage_truth unavailable for run=%s: %s", run.id, exc)
        coverage_truth = None

    trace = from_runner_tasks(
        tasks,
        run=run,
        findings=findings,
        final_outcome=config.get("final_outcome"),
        lab_truth=lab_truth,
        coverage_truth=coverage_truth,
    )
    data = _trace_bytes(trace)
    digest = sha256(data).hexdigest()
    settings = settings or get_settings()
    storage_config = artifact_storage_config_from_settings(settings)
    host_task = host_execution.task
    stored = store_artifact_bytes_with_fallback(
        config=storage_config,
        artifact_name=RUN_TRACE_ARTIFACT_NAME,
        artifact_kind=RUN_TRACE_ARTIFACT_KIND,
        artifact_digest=digest,
        content_type=RUN_TRACE_CONTENT_TYPE,
        data=data,
        run_id=str(run.id),
        task_id=str(host_task.id),
        execution_id=str(host_execution.id),
    )
    artifact = EvidenceArtifact(
        tool_execution_id=host_execution.id,
        kind=RUN_TRACE_ARTIFACT_KIND,
        uri=stored.uri,
        sha256=digest,
        redaction_state="clean",
        metadata_json={
            "name": RUN_TRACE_ARTIFACT_NAME,
            "content_type": RUN_TRACE_CONTENT_TYPE,
            "derived_run_artifact": True,
            "final_outcome": trace[-1].get("final_outcome") if trace else "",
            "lab_truth": lab_truth,
            "row_count": len(trace),
            "schema": "jury_review.TRACE_FIELDS",
            "size_bytes": len(data),
            **stored.metadata,
        },
    )
    apply_artifact_integrity_metadata(
        settings=settings,
        storage_config=storage_config,
        artifact_record=artifact,
        artifact_name=RUN_TRACE_ARTIFACT_NAME,
        data=data,
        run_id=str(run.id),
        task_id=str(host_task.id),
        execution_id=str(host_execution.id),
    )
    session.add(artifact)
    session.flush()
    write_audit_event(
        session=session,
        actor=actor,
        action="run.trace_artifact.persisted",
        object_type="run",
        object_id=str(run.id),
        metadata={
            "artifact_id": str(artifact.id),
            "artifact_kind": RUN_TRACE_ARTIFACT_KIND,
            "final_outcome": artifact.metadata_json.get("final_outcome"),
            "lab_truth": lab_truth,
            "row_count": len(trace),
        },
    )
    session.flush()
    return artifact


def maybe_persist_run_trace_artifact(
    *,
    session: Any,
    run: Run,
    actor: str = "system:run-trace-artifact",
) -> EvidenceArtifact | None:
    try:
        return persist_run_trace_artifact(session=session, run=run, actor=actor)
    except Exception as exc:  # noqa: BLE001
        logger.warning("run_trace_artifact: skipped for run=%s: %s", getattr(run, "id", None), exc)
        return None
