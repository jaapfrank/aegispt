from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.app.auth import get_current_actor
from api.app.db import get_session
from api.app.models import Engagement, Scope
from api.app.schemas.engagements import (
    EngagementCreate,
    EngagementRead,
    ScopeCreate,
    ScopeRead,
)
from api.app.services.audit import write_audit_event

router = APIRouter(prefix="/api/v1/engagements", tags=["engagements"])


@router.get("", response_model=list[EngagementRead])
def list_engagements(session: Session = Depends(get_session)) -> list[EngagementRead]:
    engagements = session.scalars(select(Engagement).order_by(Engagement.created_at.desc(), Engagement.id.desc())).all()
    return [EngagementRead.model_validate(engagement) for engagement in engagements]


@router.get("/{engagement_id}", response_model=EngagementRead)
def get_engagement(engagement_id: UUID, session: Session = Depends(get_session)) -> EngagementRead:
    engagement = session.scalar(select(Engagement).where(Engagement.id == engagement_id))
    if engagement is None:
        raise HTTPException(status_code=404, detail="engagement not found")
    return EngagementRead.model_validate(engagement)


@router.post("", response_model=EngagementRead, status_code=status.HTTP_201_CREATED)
def create_engagement(
    payload: EngagementCreate,
    session: Session = Depends(get_session),
    actor: str = Depends(get_current_actor),
) -> EngagementRead:
    engagement = Engagement(
        name=payload.name,
        client=payload.client,
        roe_ref=payload.roe_ref,
        starts_at=payload.starts_at,
        ends_at=payload.ends_at,
    )
    session.add(engagement)
    session.flush()

    write_audit_event(
        session=session,
        actor=actor,
        action="engagement.created",
        object_type="engagement",
        object_id=str(engagement.id),
        metadata={"name": payload.name},
    )

    session.commit()
    session.refresh(engagement)
    return EngagementRead.model_validate(engagement)


@router.post(
    "/{engagement_id}/scope",
    response_model=ScopeRead,
    status_code=status.HTTP_201_CREATED,
)
def create_scope(
    engagement_id: UUID,
    payload: ScopeCreate,
    session: Session = Depends(get_session),
    actor: str = Depends(get_current_actor),
) -> ScopeRead:
    engagement = session.scalar(select(Engagement).where(Engagement.id == engagement_id))
    if engagement is None:
        raise HTTPException(status_code=404, detail="engagement not found")

    scope = Scope(
        engagement_id=engagement.id,
        allowlist_json=payload.allowlist_json,
        denylist_json=payload.denylist_json,
    )
    session.add(scope)
    session.flush()

    write_audit_event(
        session=session,
        actor=actor,
        action="scope.created",
        object_type="scope",
        object_id=str(scope.id),
        metadata={"engagement_id": str(engagement.id)},
    )

    session.commit()
    session.refresh(scope)
    return ScopeRead.model_validate(scope)


@router.get("/{engagement_id}/scope", response_model=ScopeRead)
def get_latest_scope(
    engagement_id: UUID,
    session: Session = Depends(get_session),
) -> ScopeRead:
    engagement = session.scalar(select(Engagement).where(Engagement.id == engagement_id))
    if engagement is None:
        raise HTTPException(status_code=404, detail="engagement not found")

    scope = session.scalar(
        select(Scope)
        .where(Scope.engagement_id == engagement_id)
        .order_by(Scope.created_at.desc(), Scope.id.desc())
    )
    if scope is None:
        raise HTTPException(status_code=404, detail="scope not found")
    return ScopeRead.model_validate(scope)
