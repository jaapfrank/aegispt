from __future__ import annotations

import os
from uuid import UUID

import dramatiq
from dramatiq.brokers.redis import RedisBroker
from sqlalchemy import select
from sqlalchemy.orm import joinedload

from api.app.services.artifact_storage import (
    artifact_storage_config_from_env,
    store_artifact_bytes_with_fallback,
)
from api.app.policy.engine import execution_kill_switch_enabled
from api.app.models import EvidenceArtifact as EvidenceArtifactRecord
from api.app.models import Run, Scope, Task, ToolExecution
from api.app.services.redaction import redact_artifact_bytes, redact_text
from api.app.services.runs import derive_targets, latest_scope_query
from workers.runners.base.contracts import EvidenceArtifact, RunnerExecution, RunnerRequest
from workers.runners.httpx.runner import execute_httpx_probe
from workers.runners.nuclei.runner import execute_nuclei_scan
from workers.runners.semgrep.runner import execute_semgrep_scan
from workers.runners.zap.runner import execute_zap_scan
from workers.orchestration.findings import store_findings
from workers.orchestration.runtime import session_scope

redis_broker = RedisBroker(url=os.getenv("REDIS_URL", "redis://localhost:6379/0"))
dramatiq.set_broker(redis_broker)

SUPPORTED_TOOLS = {"httpx", "nuclei", "semgrep", "zap"}


def dispatch_runner(request: RunnerRequest) -> RunnerExecution:
    rate_limit = int(request.params.get("limits", {}).get("max_rps", 2))
    timeout_seconds = float(request.params.get("timeout_seconds", 10.0))

    if request.tool == "httpx":
        return execute_httpx_probe(
            targets=request.targets,
            rate_limit=rate_limit,
            timeout_seconds=timeout_seconds,
        )
    if request.tool == "nuclei":
        return execute_nuclei_scan(
            targets=request.targets,
            rate_limit=rate_limit,
            timeout_seconds=timeout_seconds,
            binary=os.getenv("NUCLEI_BINARY", "nuclei"),
        )
    if request.tool == "semgrep":
        return execute_semgrep_scan(
            targets=request.targets,
            jobs=max(rate_limit, 1),
            binary=os.getenv("SEMGREP_BINARY", "semgrep"),
        )
    if request.tool == "zap":
        return execute_zap_scan(
            targets=request.targets,
            base_url=os.getenv("ZAP_BASE_URL", "http://127.0.0.1:8080"),
            api_key=os.getenv("ZAP_API_KEY", "change-me-zap-key"),
            rate_limit=rate_limit,
            timeout_seconds=timeout_seconds,
            scan_mode=str(request.params.get("limits", {}).get("scan_mode", "spider-passive")),
        )

    raise ValueError(f"unsupported tool runner: {request.tool}")


def _task_query(task_uuid: UUID):
    return (
        select(Task)
        .options(
            joinedload(Task.run).selectinload(Run.tasks),
        )
        .where(Task.id == task_uuid)
    )


def _scope_for_run(session, run: Run | None) -> Scope | None:
    if run is None:
        return None
    return session.scalar(latest_scope_query(run.engagement_id))


def _target_is_allowed(scope: Scope, target_id: str) -> bool:
    allowed_targets = {target["value"] for target in derive_targets(scope)}
    return target_id in allowed_targets


def _task_targets(task: Task) -> list[str]:
    configured_targets = task.params_json.get("targets")
    if isinstance(configured_targets, list):
        normalized_targets = [target.strip() for target in configured_targets if isinstance(target, str) and target.strip()]
        if normalized_targets:
            return normalized_targets

    return [task.target_id]


def _update_run_status(session, run: Run) -> None:
    if run.id is None:
        return

    session.flush()
    statuses = {
        status
        for status in session.scalars(select(Task.status).where(Task.run_id == run.id)).all()
        if isinstance(status, str)
    }

    if not statuses:
        return
    if statuses == {"cancelled"}:
        run.status = "cancelled"
        return
    if "running" in statuses:
        run.status = "running"
        return
    if statuses == {"completed"}:
        run.status = "completed"
        return
    if "failed" in statuses and statuses.issubset({"completed", "failed"}):
        run.status = "completed_with_errors"
        return
    if "queued" in statuses:
        run.status = "queued"


def _store_execution(session, task: Task, execution: RunnerExecution) -> None:
    redacted_stdout = redact_text(execution.stdout)
    redacted_stderr = redact_text(execution.stderr)
    execution_record = ToolExecution(
        task=task,
        runner_digest=str(execution.metadata.get("runner_digest", "workers.unknown.runner:v1")),
        tool_version=str(execution.metadata.get("tool_version", task.tool)),
        exit_code=execution.exit_code,
        stdout_text=redacted_stdout.text,
        stderr_text=redacted_stderr.text,
    )
    session.add(execution_record)
    session.flush()

    storage_config = artifact_storage_config_from_env()
    run_id = str(task.run_id) if task.run_id is not None else "unassigned-run"
    task_id = str(task.id)
    execution_id = str(execution_record.id)
    stored_artifact_pairs: list[tuple[EvidenceArtifact, EvidenceArtifactRecord]] = []

    for artifact in execution.artifacts:
        redacted_artifact = redact_artifact_bytes(
            name=artifact.name,
            content_type=artifact.content_type,
            data=artifact.data,
        )
        redacted_contract_artifact = EvidenceArtifact(
            name=artifact.name,
            content_type=artifact.content_type,
            data=redacted_artifact.data,
            kind=artifact.kind,
        )
        stored_artifact = store_artifact_bytes_with_fallback(
            config=storage_config,
            artifact_name=artifact.name,
            artifact_kind=artifact.kind,
            artifact_digest=redacted_contract_artifact.digest,
            content_type=artifact.content_type,
            data=redacted_artifact.data,
            run_id=run_id,
            task_id=task_id,
            execution_id=execution_id,
        )
        artifact_record = EvidenceArtifactRecord(
            kind=artifact.kind,
            uri=stored_artifact.uri,
            sha256=redacted_contract_artifact.digest,
            redaction_state=redacted_artifact.redaction_state,
            metadata_json={
                "name": artifact.name,
                "content_type": artifact.content_type,
                "size_bytes": len(redacted_artifact.data),
                "redaction_count": redacted_artifact.redaction_count,
                **{
                    key: value
                    for key, value in execution.metadata.items()
                    if key
                    in {
                        "template_id",
                        "template_sha256",
                        "template_source",
                        "rule_ids",
                        "rule_source",
                        "rule_sha256",
                    }
                },
                **stored_artifact.metadata,
            },
        )
        execution_record.artifacts.append(artifact_record)
        stored_artifact_pairs.append((redacted_contract_artifact, artifact_record))

    store_findings(session=session, task=task, artifact_pairs=stored_artifact_pairs)


def process_task_by_id(task_id: str) -> dict[str, object]:
    task_uuid = UUID(task_id)

    with session_scope() as session:
        task = session.scalar(_task_query(task_uuid))
        if task is None:
            raise ValueError(f"task not found: {task_id}")
        if task.run is None:
            raise ValueError(f"task {task_id} is not attached to a run")
        if task.status not in {"queued", "failed"}:
            return {"task_id": task_id, "status": task.status}
        if task.run.status in {"cancelled", "cancelling"}:
            task.status = "cancelled"
            session.commit()
            return {"task_id": task_id, "status": task.status}
        if execution_kill_switch_enabled():
            task.status = "cancelled"
            task.run.status = "cancelled"
            session.commit()
            return {"task_id": task_id, "status": task.status, "reason": "kill_switch"}

        task_targets = _task_targets(task)
        scope = _scope_for_run(session, task.run)
        if scope is None:
            raise ValueError(f"scope missing for run {task.run_id}")
        for task_target in task_targets:
            if not _target_is_allowed(scope, task_target):
                raise ValueError(f"target outside scope: {task_target}")

        task.status = "running"
        task.run.status = "running"
        session.commit()

        try:
            execution = dispatch_runner(
                RunnerRequest(
                    tool=task.tool,
                    targets=task_targets,
                    params={
                        **task.params_json,
                        "timeout_seconds": float(os.getenv("RUNNER_TIMEOUT_SECONDS", "10.0")),
                    },
                    scope_allowlist=scope.allowlist_json,
                    initiated_by=task.run.requested_by,
                )
            )
        except Exception as exc:
            execution = RunnerExecution(
                tool=task.tool,
                exit_code=1,
                stdout="",
                stderr=str(exc),
                metadata={
                    "status": "failed",
                    "tool_version": task.tool,
                    "runner_digest": f"workers.{task.tool}.runner:v1",
                },
                artifacts=[],
            )

        task = session.scalar(_task_query(task_uuid))
        if task is None or task.run is None:
            raise ValueError(f"task disappeared during execution: {task_id}")

        _store_execution(session, task, execution)
        task.status = "completed" if execution.exit_code == 0 else "failed"
        _update_run_status(session, task.run)
        session.commit()

        return {
            "task_id": task_id,
            "status": task.status,
            "run_status": task.run.status,
            "exit_code": execution.exit_code,
        }


@dramatiq.actor(queue_name="aegispt")
def record_heartbeat(tool: str = "scheduler") -> dict[str, str]:
    return {"status": "ok", "tool": tool}


@dramatiq.actor(queue_name="aegispt")
def execute_task(task_id: str) -> dict[str, object]:
    return process_task_by_id(task_id)
