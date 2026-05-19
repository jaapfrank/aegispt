from __future__ import annotations

import asyncio
import json
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload
from starlette.responses import StreamingResponse

from api.app.db import get_session
from api.app.models import Task, ToolExecution
from api.app.schemas.tasks import TaskDetailRead
from api.app.services.tenancy import assert_task_tenant, get_current_tenant_id
from workers.runners.base.stdout_stream import (
    empty_task_stdout_snapshot,
    snapshot_task_stdout,
    snapshot_task_stdout_from_text,
)

router = APIRouter(prefix="/api/v1/tasks", tags=["tasks"])

TERMINAL_TASK_STATUSES = {"completed", "failed", "cancelled"}


def _format_sse_event(event: str, payload: dict[str, Any]) -> str:
    data = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return f"event: {event}\ndata: {data}\n\n"


def _latest_execution(task: Task) -> ToolExecution | None:
    executions = list(task.executions or [])
    if not executions:
        return None
    return sorted(
        executions,
        key=lambda execution: (execution.created_at, execution.id.hex),
        reverse=True,
    )[0]


def _load_task_with_executions(session: Session, task_id: UUID) -> Task | None:
    return session.scalar(
        select(Task)
        .options(
            selectinload(Task.executions).selectinload(ToolExecution.artifacts),
        )
        .where(Task.id == task_id)
    )


def _task_stdout_snapshot(task: Task) -> dict[str, Any]:
    task_status = str(task.status or "unknown").lower()
    terminal = task_status in TERMINAL_TASK_STATUSES
    buffered_snapshot = snapshot_task_stdout(task.id)
    if buffered_snapshot is not None:
        return {
            **buffered_snapshot,
            "task_status": task.status,
            "stream_terminal": terminal or buffered_snapshot.get("status") == "completed",
        }

    latest_execution = _latest_execution(task)
    if latest_execution is not None:
        snapshot = snapshot_task_stdout_from_text(
            task.id,
            latest_execution.stdout_text,
            status="completed",
            source="stored-execution",
            reason="Latest execution did not store stdout for the selected task.",
        )
        return {
            **snapshot,
            "task_status": task.status,
            "stream_terminal": True,
        }

    reason = (
        "No safe stdout capture is available yet for this queued or running task."
        if not terminal
        else "Task has no stored execution stdout available for streaming."
    )
    return {
        **empty_task_stdout_snapshot(
            task.id,
            status="unavailable",
            source="no-stream",
            reason=reason,
        ),
        "task_status": task.status,
        "stream_terminal": terminal,
    }


def _task_stdout_fingerprint(snapshot: dict[str, Any]) -> str:
    return json.dumps(
        {
            "status": snapshot.get("status"),
            "task_status": snapshot.get("task_status"),
            "source": snapshot.get("source"),
            "reason": snapshot.get("reason"),
            "updated_at": snapshot.get("updated_at"),
            "lines": [
                {
                    "sequence": line.get("sequence"),
                    "text": line.get("text"),
                }
                for line in snapshot.get("lines", [])
                if isinstance(line, dict)
            ],
        },
        sort_keys=True,
    )


@router.get("/{task_id}", response_model=TaskDetailRead)
def get_task(
    task_id: UUID,
    session: Session = Depends(get_session),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> TaskDetailRead:
    task = _load_task_with_executions(session, task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="task not found")
    assert_task_tenant(task, tenant_id)

    return TaskDetailRead.model_validate(task).model_copy(
        update={"stdout_snapshot": _task_stdout_snapshot(task)}
    )


@router.get("/{task_id}/stdout/events")
async def stream_task_stdout_events(
    task_id: UUID,
    request: Request,
    poll_interval_seconds: float = Query(default=0.5, ge=0.1, le=5.0),
    max_events: int | None = Query(default=None, ge=1, le=1000),
    session: Session = Depends(get_session),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> StreamingResponse:
    task = _load_task_with_executions(session, task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="task not found")
    assert_task_tenant(task, tenant_id)

    session_factory = request.app.state.session_factory

    async def event_generator():
        last_fingerprint: str | None = None
        emitted_events = 0
        first_event = True

        while True:
            if await request.is_disconnected():
                break

            with session_factory() as stream_session:
                task = _load_task_with_executions(stream_session, task_id)
                if task is not None:
                    try:
                        assert_task_tenant(task, tenant_id)
                    except HTTPException:
                        task = None
                snapshot = _task_stdout_snapshot(task) if task is not None else None

            if snapshot is None:
                yield _format_sse_event(
                    "task.stdout.missing",
                    {"task_id": str(task_id), "status": "missing", "stream_terminal": True},
                )
                break

            fingerprint = _task_stdout_fingerprint(snapshot)
            if fingerprint != last_fingerprint:
                event_name = "task.stdout.snapshot" if first_event else "task.stdout.update"
                yield _format_sse_event(event_name, snapshot)
                last_fingerprint = fingerprint
                emitted_events += 1
                first_event = False

                if max_events is not None and emitted_events >= max_events:
                    break
                if snapshot.get("stream_terminal") and snapshot.get("status") in {
                    "completed",
                    "unavailable",
                }:
                    break

            await asyncio.sleep(poll_interval_seconds)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )
