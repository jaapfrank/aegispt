from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from api.app.auth import get_current_actor
from api.app.db import get_session
from api.app.schemas.codex import (
    CodexBuildContextRead,
    CodexReviewBundleRead,
    CodexTaskCreate,
    CodexTaskRead,
    CodexTaskResultRead,
    CodexTaskRunCreate,
)
from api.app.services.audit import write_audit_event
from api.app.services.codex_lane import build_codex_context, build_codex_review_bundle
from api.app.services.codex_tasks import (
    create_codex_task,
    list_codex_tasks,
    load_codex_task,
    load_codex_task_result,
    run_codex_task,
)
from api.app.services.packs import load_pack

router = APIRouter(prefix="/api/v1", tags=["codex-build-lane"])


@router.get("/codex/tasks", response_model=list[CodexTaskRead])
def list_tasks() -> list[CodexTaskRead]:
    return list_codex_tasks()


@router.get("/packs/{pack_id}/codex-context", response_model=CodexBuildContextRead)
def get_codex_build_context(
    pack_id: UUID,
    session: Session = Depends(get_session),
) -> CodexBuildContextRead:
    pack = load_pack(session, pack_id)
    if pack is None:
        raise HTTPException(status_code=404, detail="capability pack not found")
    return build_codex_context(pack)


@router.get("/packs/{pack_id}/codex-review-bundle", response_model=CodexReviewBundleRead)
def get_codex_review_bundle(
    pack_id: UUID,
    session: Session = Depends(get_session),
) -> CodexReviewBundleRead:
    pack = load_pack(session, pack_id)
    if pack is None:
        raise HTTPException(status_code=404, detail="capability pack not found")
    return build_codex_review_bundle(pack)


@router.post("/codex/tasks", response_model=CodexTaskRead, status_code=status.HTTP_201_CREATED)
def create_task(
    payload: CodexTaskCreate,
    session: Session = Depends(get_session),
    actor: str = Depends(get_current_actor),
) -> CodexTaskRead:
    pack = None
    if payload.source_context.pack_id is not None:
        pack = load_pack(session, payload.source_context.pack_id)
        if pack is None:
            raise HTTPException(status_code=404, detail="capability pack not found")

    task = create_codex_task(payload, requested_by=actor, pack=pack)
    write_audit_event(
        session=session,
        actor=actor,
        action="codex_task.created",
        object_type="codex_task",
        object_id=task.id,
        metadata={"task_type": task.task_type, "task_file": task.task_file},
    )
    session.commit()
    return task


@router.get("/codex/tasks/{task_id}", response_model=CodexTaskRead)
def get_task(task_id: str) -> CodexTaskRead:
    task = load_codex_task(task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="codex task not found")
    return task


@router.post("/codex/tasks/{task_id}/run", response_model=CodexTaskResultRead)
def run_task(
    task_id: str,
    payload: CodexTaskRunCreate,
    session: Session = Depends(get_session),
    actor: str = Depends(get_current_actor),
) -> CodexTaskResultRead:
    task = load_codex_task(task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="codex task not found")

    pack = None
    if task.source_context.pack_id is not None:
        pack = load_pack(session, task.source_context.pack_id)
        if pack is None:
            raise HTTPException(status_code=404, detail="capability pack not found")

    result = run_codex_task(task, run_request=payload, pack=pack)
    write_audit_event(
        session=session,
        actor=actor,
        action="codex_task.prepared",
        object_type="codex_task_result",
        object_id=task.id,
        metadata={"result_file": result.result_file, "dry_run": result.dry_run},
    )
    session.commit()
    return result


@router.get("/codex/tasks/{task_id}/result", response_model=CodexTaskResultRead)
def get_task_result(task_id: str) -> CodexTaskResultRead:
    result = load_codex_task_result(task_id)
    if result is None:
        raise HTTPException(status_code=404, detail="codex task result not found")
    return result
