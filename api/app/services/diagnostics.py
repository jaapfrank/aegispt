from __future__ import annotations

import os
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import func, select, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from api.app.config import Settings
from api.app.models import CveFeedSyncLog, Run, Task
from api.app.schemas.diagnostics import (
    DiagnosticFailureRead,
    DiagnosticsRead,
    DiagnosticSubsystemRead,
    SupportBundleRead,
)
from api.app.services.settings import read_settings_readiness, tenant_scope_key

REPO_ROOT = Path(__file__).resolve().parents[3]
SENSITIVE_KEY_PARTS = (
    "secret",
    "token",
    "password",
    "credential",
    "api_key",
    "access_key",
    "private",
    "bearer",
    "authorization",
    "db_key",
)
NON_SECRET_FLAG_KEYS = {
    "plaintext_secrets_included",
    "raw_evidence_payloads_included",
    "task_stdout_included",
    "task_stderr_included",
    "hashes_redacted",
    "secrets_plaintext_exposed",
}
HASH_RE = re.compile(r"\b[a-fA-F0-9]{32,128}\b")
BEARER_RE = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+")
URL_USERINFO_RE = re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)([^/@\s]+@)")
KEY_VALUE_RE = re.compile(
    r"(?i)\b(secret|token|password|api[_-]?key|access[_-]?key|authorization|credential)\s*[:=]\s*[^,\s]+"
)
STATUS_RANK = {"ready": 0, "degraded": 1, "missing": 2, "blocked": 3}


def _now() -> datetime:
    return datetime.now(tz=UTC)


def _is_sensitive_key(key: str) -> bool:
    normalized = key.lower()
    if normalized in NON_SECRET_FLAG_KEYS:
        return False
    return any(part in normalized for part in SENSITIVE_KEY_PARTS)


def redact_text(value: str) -> str:
    redacted = BEARER_RE.sub("Bearer <redacted>", value)
    redacted = URL_USERINFO_RE.sub(r"\1<redacted>@", redacted)
    redacted = KEY_VALUE_RE.sub(lambda match: f"{match.group(1)}=<redacted>", redacted)
    redacted = HASH_RE.sub("<redacted-hash>", redacted)
    return redacted


def redact_payload(value: Any, *, key: str = "") -> Any:
    if _is_sensitive_key(key):
        return "<redacted>"
    if isinstance(value, dict):
        return {str(item_key): redact_payload(item_value, key=str(item_key)) for item_key, item_value in value.items()}
    if isinstance(value, list):
        return [redact_payload(item) for item in value]
    if isinstance(value, tuple):
        return [redact_payload(item) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    return value


def _subsystem(
    *,
    subsystem_id: str,
    title: str,
    status: str,
    summary: str,
    operator_next_step: str,
    details: list[str] | None = None,
    metadata: dict[str, Any] | None = None,
) -> DiagnosticSubsystemRead:
    return DiagnosticSubsystemRead(
        id=subsystem_id,
        title=title,
        status=status,
        summary=summary,
        details=details or [],
        operator_next_step=operator_next_step,
        metadata=redact_payload(metadata or {}),
    )


def _worst_status(statuses: list[str]) -> str:
    normalized = [str(status or "degraded").lower() for status in statuses]
    return max(normalized, key=lambda item: STATUS_RANK.get(item, 1)) if normalized else "ready"


def _alembic_heads() -> list[str]:
    config = Config(str(REPO_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(REPO_ROOT / "migrations"))
    return list(ScriptDirectory.from_config(config).get_heads())


def _database_migration_subsystem(session: Session) -> DiagnosticSubsystemRead:
    heads = _alembic_heads()
    try:
        current = [
            str(row[0])
            for row in session.execute(text("SELECT version_num FROM alembic_version")).all()
        ]
    except SQLAlchemyError:
        return _subsystem(
            subsystem_id="database_migrations",
            title="Database migrations",
            status="blocked",
            summary="The alembic_version table is not readable.",
            details=["Database connectivity or migration state needs operator review."],
            operator_next_step="Run python -m alembic current and inspect the database connection before continuing.",
            metadata={"alembic_heads": heads},
        )
    status = "ready" if set(current) == set(heads) and current else "degraded"
    return _subsystem(
        subsystem_id="database_migrations",
        title="Database migrations",
        status=status,
        summary=f"Database migration state is {'at head' if status == 'ready' else 'not aligned with head'}.",
        details=[f"Current: {', '.join(current) or 'none'}.", f"Head: {', '.join(heads) or 'unknown'}."],
        operator_next_step="Run alembic upgrade head during a planned maintenance window if migration state is behind.",
        metadata={"current": current, "heads": heads},
    )


def _app_health_subsystem(settings: Settings, runtime_state: str) -> DiagnosticSubsystemRead:
    status = "ready" if runtime_state == "healthy" else "degraded"
    return _subsystem(
        subsystem_id="app_health",
        title="App health",
        status=status,
        summary=f"{settings.app_name} runtime state is {runtime_state}.",
        details=[f"Environment: {settings.app_env}.", f"Public base URL: {settings.app_public_base_url}."],
        operator_next_step="If runtime state is shutting_down or unreachable, restart the host service and re-check /health/live.",
        metadata={"runtime_state": runtime_state, "api_prefix": settings.api_prefix},
    )


def _dispatch_subsystem(settings: Settings) -> DiagnosticSubsystemRead:
    mode = str(settings.task_dispatch_mode or "manual").strip().lower() or "manual"
    valid = mode in {"manual", "inline", "dramatiq"}
    status = "ready" if valid and mode != "manual" else "degraded"
    return _subsystem(
        subsystem_id="worker_dispatch",
        title="Worker and dispatch",
        status=status,
        summary=f"Dispatch mode is {mode}; inline workers configured: {settings.inline_task_workers}.",
        details=[
            f"Inline background dispatch: {'enabled' if settings.inline_dispatch_background else 'disabled'}.",
            "Manual mode leaves queued tasks waiting for operator action.",
        ],
        operator_next_step="Use inline or dramatiq mode for automatic dispatch, or use Start Queued Checks when manual mode is intentional.",
        metadata={
            "task_dispatch_mode": mode,
            "inline_task_workers": settings.inline_task_workers,
            "inline_dispatch_background": settings.inline_dispatch_background,
        },
    )


def _queue_subsystem(session: Session) -> DiagnosticSubsystemRead:
    rows = session.execute(select(Task.status, func.count(Task.id)).group_by(Task.status)).all()
    counts = {str(status): int(count) for status, count in rows}
    queued = counts.get("queued", 0)
    running = counts.get("running", 0)
    failed = counts.get("failed", 0)
    status = "blocked" if failed else ("degraded" if queued or running else "ready")
    return _subsystem(
        subsystem_id="queue_state",
        title="Queue state",
        status=status,
        summary=f"{queued} queued, {running} running, {failed} failed task(s).",
        details=["Counts are task lifecycle metadata only; raw stdout and evidence payloads are not included."],
        operator_next_step="Open Mission Control or Live Agents for the selected run; use diagnostics bundle only for redacted support context.",
        metadata={"task_status_counts": counts},
    )


def _run_stuck_subsystem(session: Session) -> DiagnosticSubsystemRead:
    threshold = _now() - timedelta(minutes=30)
    running_runs = session.scalars(select(Run).where(Run.status.in_(["running", "queued", "dispatching"]))).all()
    stuck = [
        run
        for run in running_runs
        if run.updated_at is not None and run.updated_at.replace(tzinfo=run.updated_at.tzinfo or UTC) < threshold
    ]
    status = "blocked" if stuck else ("degraded" if running_runs else "ready")
    return _subsystem(
        subsystem_id="run_stuck",
        title="Active and stuck runs",
        status=status,
        summary=f"{len(running_runs)} active-like run(s), {len(stuck)} older than 30 minutes without update.",
        details=["Diagnostics exposes run IDs and state only, not raw target output."],
        operator_next_step="Review stale run IDs in Mission Control; use Kill Run only when the operator has confirmed it is safe.",
        metadata={
            "active_run_ids": [str(run.id) for run in running_runs[:10]],
            "stuck_run_ids": [str(run.id) for run in stuck[:10]],
            "stuck_after_minutes": 30,
        },
    )


def _feed_sync_subsystem(session: Session, tenant_key: str) -> DiagnosticSubsystemRead:
    latest = session.scalar(
        select(CveFeedSyncLog)
        .where(CveFeedSyncLog.tenant_id == tenant_key)
        .order_by(CveFeedSyncLog.started_at.desc())
    )
    if latest is None:
        return _subsystem(
            subsystem_id="feed_sync",
            title="Threat feed sync",
            status="degraded",
            summary="No threat feed sync has been recorded yet.",
            operator_next_step="Run a threat-intel sync from Settings after configuring optional API keys.",
        )
    status = "blocked" if latest.status == "failed" else ("ready" if latest.status == "completed" else "degraded")
    next_step = "Add an NVD API key in Settings if rate-limited, then retry sync." if latest.status == "failed" else "No action required."
    return _subsystem(
        subsystem_id="feed_sync",
        title="Threat feed sync",
        status=status,
        summary=f"Latest {latest.source} sync is {latest.status}.",
        details=[redact_text(latest.error_text or "No sync error recorded.")],
        operator_next_step=next_step,
        metadata={
            "source": latest.source,
            "status": latest.status,
            "started_at": latest.started_at.isoformat() if latest.started_at else None,
            "completed_at": latest.completed_at.isoformat() if latest.completed_at else None,
        },
    )


def _readiness_subsystems(
    session: Session,
    *,
    tenant_id: str | None,
    settings: Settings,
) -> list[DiagnosticSubsystemRead]:
    readiness = read_settings_readiness(session, tenant_id=tenant_id, settings=settings)
    capabilities = {item.id: item for item in readiness.capabilities}
    tool_summary = capabilities.get("tool_readiness")
    certification = capabilities.get("runner_tool_certification")
    ai = capabilities.get("ai_provider")
    deployment = capabilities.get("deployment_hardening")
    subsystems: list[DiagnosticSubsystemRead] = []
    if tool_summary is not None:
        subsystems.append(
            _subsystem(
                subsystem_id="tool_readiness",
                title="Tool readiness",
                status=tool_summary.status,
                summary=tool_summary.summary,
                details=tool_summary.details,
                operator_next_step=tool_summary.operator_next_step,
                metadata={
                    **tool_summary.metadata,
                    "missing_tools": [
                        {"id": tool.id, "title": tool.title, "status": tool.status}
                        for tool in readiness.tools
                        if tool.status in {"missing", "degraded"}
                    ],
                },
            )
        )
    if certification is not None:
        subsystems.append(
            _subsystem(
                subsystem_id="runner_tool_certification",
                title="Runner/tool certification",
                status=certification.status,
                summary=certification.summary,
                details=certification.details,
                operator_next_step=certification.operator_next_step,
                metadata=certification.metadata,
            )
        )
    if ai is not None:
        subsystems.append(
            _subsystem(
                subsystem_id="ai_provider",
                title="AI provider",
                status=ai.status,
                summary=ai.summary,
                details=ai.details,
                operator_next_step=ai.operator_next_step,
                metadata=ai.metadata,
            )
        )
    if deployment is not None:
        subsystems.append(
            _subsystem(
                subsystem_id="deployment_hardening",
                title="Production deployment hardening",
                status=deployment.status,
                summary=deployment.summary,
                details=deployment.details,
                operator_next_step=deployment.operator_next_step,
                metadata=deployment.metadata,
            )
        )
    return subsystems


def _recent_failures(session: Session, tenant_key: str) -> list[DiagnosticFailureRead]:
    failures: list[DiagnosticFailureRead] = []
    failed_tasks = session.scalars(
        select(Task).where(Task.status.in_(["failed", "blocked"])).order_by(Task.updated_at.desc()).limit(5)
    ).all()
    for task in failed_tasks:
        failures.append(
            DiagnosticFailureRead(
                subsystem="queue_state",
                status=task.status,
                occurred_at=task.updated_at,
                summary=f"Task {task.tool} on {task.target_id} is {task.status}.",
                object_type="task",
                object_id=str(task.id),
                operator_next_step="Open Mission Control task details and review redacted runner status before retrying.",
                metadata={"run_id": str(task.run_id) if task.run_id else None, "tool": task.tool},
            )
        )
    failed_runs = session.scalars(
        select(Run).where(Run.status.in_(["failed", "blocked"])).order_by(Run.updated_at.desc()).limit(5)
    ).all()
    for run in failed_runs:
        failures.append(
            DiagnosticFailureRead(
                subsystem="run_stuck",
                status=run.status,
                occurred_at=run.updated_at,
                summary=f"Run {run.id} is {run.status}.",
                object_type="run",
                object_id=str(run.id),
                operator_next_step="Use Mission Control to inspect safe next action, accepted gap, retry, or cancellation state.",
                metadata={"engagement_id": str(run.engagement_id)},
            )
        )
    failed_sync = session.scalar(
        select(CveFeedSyncLog)
        .where(CveFeedSyncLog.tenant_id == tenant_key, CveFeedSyncLog.status == "failed")
        .order_by(CveFeedSyncLog.started_at.desc())
    )
    if failed_sync is not None:
        failures.append(
            DiagnosticFailureRead(
                subsystem="feed_sync",
                status="failed",
                occurred_at=failed_sync.started_at,
                summary=f"{failed_sync.source} feed sync failed: {redact_text(failed_sync.error_text or 'no error text')}",
                object_type="cve_feed_sync_log",
                object_id=str(failed_sync.id),
                operator_next_step="Check API key/rate-limit guidance in Settings and retry the sync.",
                metadata={"source": failed_sync.source},
            )
        )
    return sorted(failures, key=lambda item: item.occurred_at or datetime.min.replace(tzinfo=UTC), reverse=True)[:10]


def build_diagnostics(
    session: Session,
    *,
    tenant_id: str | None,
    settings: Settings,
    runtime_state: str = "healthy",
) -> DiagnosticsRead:
    tenant_key = tenant_scope_key(tenant_id)
    subsystems = [
        _app_health_subsystem(settings, runtime_state),
        _database_migration_subsystem(session),
        _dispatch_subsystem(settings),
        _queue_subsystem(session),
        _run_stuck_subsystem(session),
        _feed_sync_subsystem(session, tenant_key),
        *_readiness_subsystems(session, tenant_id=tenant_id, settings=settings),
    ]
    failures = _recent_failures(session, tenant_key)
    overall_status = _worst_status([item.status for item in subsystems])
    return DiagnosticsRead(
        tenant_id=tenant_key,
        generated_at=_now(),
        overall_status=overall_status,
        subsystems=subsystems,
        recent_failures=failures,
    )


def _config_shape(settings: Settings) -> dict[str, Any]:
    payload = settings.model_dump()
    shape: dict[str, Any] = {}
    for key, value in payload.items():
        if _is_sensitive_key(key):
            shape[key] = {"configured": bool(value), "value": "<redacted>" if value else None}
        elif key.endswith("_url") or key in {"database_url", "redis_url"}:
            shape[key] = redact_text(str(value)) if value is not None else None
        else:
            shape[key] = value
    return redact_payload(shape)


def _runtime_ids(session: Session) -> dict[str, Any]:
    recent_runs = session.scalars(select(Run).order_by(Run.updated_at.desc()).limit(10)).all()
    recent_tasks = session.scalars(select(Task).order_by(Task.updated_at.desc()).limit(20)).all()
    return {
        "recent_runs": [
            {
                "id": str(run.id),
                "engagement_id": str(run.engagement_id),
                "status": run.status,
                "updated_at": run.updated_at.isoformat() if run.updated_at else None,
            }
            for run in recent_runs
        ],
        "recent_tasks": [
            {
                "id": str(task.id),
                "run_id": str(task.run_id) if task.run_id else None,
                "tool": task.tool,
                "target_id": task.target_id,
                "status": task.status,
                "updated_at": task.updated_at.isoformat() if task.updated_at else None,
                "stdout_included": False,
                "stderr_included": False,
            }
            for task in recent_tasks
        ],
    }


def _candidate_log_paths() -> list[Path]:
    raw_paths = [
        os.getenv("AEGISPT_LOG_FILE"),
        "/tmp/aegispt-inline-host.log",
        "/var/log/aegispt/app/aegispt.log",
    ]
    return [Path(path).expanduser() for path in raw_paths if path]


def _recent_logs() -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for path in _candidate_log_paths():
        if not path.exists() or not path.is_file():
            entries.append({"path": str(path), "available": False})
            continue
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()[-120:]
        interesting = [
            redact_text(line)
            for line in lines
            if any(marker in line.lower() for marker in ("error", "exception", "failed", "traceback", "warning"))
        ][-20:]
        entries.append(
            {
                "path": str(path),
                "available": True,
                "line_count_scanned": len(lines),
                "included_line_count": len(interesting),
                "redacted_excerpt": interesting,
            }
        )
    return entries


def _validation_context() -> dict[str, Any]:
    result_root = REPO_ROOT / "codex" / "results"
    audit_files = []
    if result_root.exists():
        audit_files = [
            str(path.relative_to(REPO_ROOT))
            for path in sorted(result_root.glob("*audit*"), key=lambda item: item.stat().st_mtime, reverse=True)[:10]
            if path.is_file()
        ]
    return {
        "recommended_commands": [
            "python3 scripts/validate_backlog_tasks.py",
            "git diff --check",
            "curl -fsS http://127.0.0.1:8000/health/live",
        ],
        "recent_audit_artifacts": audit_files,
        "raw_validation_output_included": False,
    }


def build_support_bundle(
    session: Session,
    *,
    tenant_id: str | None,
    settings: Settings,
    runtime_state: str = "healthy",
) -> SupportBundleRead:
    diagnostics = build_diagnostics(
        session,
        tenant_id=tenant_id,
        settings=settings,
        runtime_state=runtime_state,
    )
    bundle = SupportBundleRead(
        tenant_id=diagnostics.tenant_id,
        generated_at=_now(),
        diagnostics=diagnostics,
        config_shape=_config_shape(settings),
        runtime_ids=_runtime_ids(session),
        recent_logs=_recent_logs(),
        validation=_validation_context(),
        redaction={
            "plaintext_secrets_included": False,
            "raw_evidence_payloads_included": False,
            "task_stdout_included": False,
            "task_stderr_included": False,
            "hashes_redacted": True,
        },
    )
    return SupportBundleRead.model_validate(redact_payload(bundle.model_dump()))
