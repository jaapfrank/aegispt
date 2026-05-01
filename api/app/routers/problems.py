from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from api.app.auth import get_current_actor
from api.app.config import Settings, get_settings
from api.app.db import get_session
from api.app.schemas.problems import ProblemBulkUpdateCreate, ProblemBulkUpdateRead, ProblemsRead
from api.app.services.problems import (
    DEFAULT_SEVERITIES,
    DEFAULT_STATUSES,
    ProblemBulkDeleteUnsupportedError,
    ProblemFilters,
    build_problems_center,
    bulk_update_problems,
)
from api.app.services.tenancy import get_current_tenant_id

router = APIRouter(prefix="/api/v1", tags=["problems"])


def _parse_csv_filter(value: str | None, *, default: set[str] | None = None) -> set[str] | None:
    if value is None:
        return default
    normalized = {
        item.strip().lower().replace("-", "_")
        for item in value.split(",")
        if item.strip()
    }
    if not normalized or "all" in normalized:
        return None
    return normalized


def _parse_text_filter(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.strip()
    if not normalized or normalized.lower() == "all":
        return None
    return normalized


@router.get("/problems", response_model=ProblemsRead)
def list_problems(
    session: Session = Depends(get_session),
    tenant_id: str | None = Depends(get_current_tenant_id),
    severity: str | None = Query(default=None, description="Comma-separated severities; defaults to critical,high."),
    status: str | None = Query(default=None, description="Comma-separated problem states; defaults to open."),
    engagement_id: UUID | None = Query(default=None),
    assignee: str | None = Query(default=None, max_length=255),
    age: str | None = Query(default=None, pattern="^(all|overdue|due_soon|recent)$"),
    methodology: str | None = Query(default=None, max_length=100),
    cursor: str | None = Query(default=None, max_length=255),
    limit: int = Query(default=50, ge=1, le=100),
) -> ProblemsRead:
    return build_problems_center(
        session=session,
        tenant_id=tenant_id,
        filters=ProblemFilters(
            severities=_parse_csv_filter(severity, default=set(DEFAULT_SEVERITIES)),
            statuses=_parse_csv_filter(status, default=set(DEFAULT_STATUSES)),
            engagement_id=engagement_id,
            assignee=_parse_text_filter(assignee),
            age=_parse_text_filter(age),
            methodology=_parse_text_filter(methodology),
            cursor=cursor,
            limit=limit,
        ),
    )


@router.patch("/problems/bulk", response_model=ProblemBulkUpdateRead)
def bulk_update_problem_records(
    payload: ProblemBulkUpdateCreate,
    session: Session = Depends(get_session),
    actor: str = Depends(get_current_actor),
    settings: Settings = Depends(get_settings),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> ProblemBulkUpdateRead:
    try:
        result = bulk_update_problems(
            session=session,
            payload=payload,
            actor=actor,
            settings=settings,
            tenant_id=tenant_id,
        )
    except ProblemBulkDeleteUnsupportedError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    session.commit()
    return result
