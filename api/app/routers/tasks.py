from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from api.app.db import get_session
from api.app.models import Task, ToolExecution
from api.app.schemas.tasks import TaskDetailRead

router = APIRouter(prefix="/api/v1/tasks", tags=["tasks"])


@router.get("/{task_id}", response_model=TaskDetailRead)
def get_task(task_id: UUID, session: Session = Depends(get_session)) -> TaskDetailRead:
    task = session.scalar(
        select(Task)
        .options(
            selectinload(Task.executions).selectinload(ToolExecution.artifacts),
        )
        .where(Task.id == task_id)
    )
    if task is None:
        raise HTTPException(status_code=404, detail="task not found")

    return TaskDetailRead.model_validate(task)
