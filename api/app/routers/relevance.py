from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.app.auth import get_current_actor
from api.app.db import get_session
from api.app.models import Engagement, InventorySnapshot, RelevanceDecision, ThreatIntelRecord
from api.app.schemas.relevance import RelevanceAnalyzeCreate, RelevanceDecisionRead
from api.app.services.audit import write_audit_event
from api.app.services.relevance import analyze_relevance

router = APIRouter(prefix="/api/v1", tags=["relevance"])


@router.post("/relevance/analyze", response_model=RelevanceDecisionRead, status_code=status.HTTP_201_CREATED)
def analyze_inventory_relevance(
    payload: RelevanceAnalyzeCreate,
    session: Session = Depends(get_session),
    actor: str = Depends(get_current_actor),
) -> RelevanceDecisionRead:
    engagement = session.scalar(select(Engagement).where(Engagement.id == payload.engagement_id))
    if engagement is None:
        raise HTTPException(status_code=404, detail="engagement not found")

    inventory_snapshot = session.scalar(
        select(InventorySnapshot).where(
            InventorySnapshot.id == payload.inventory_snapshot_id,
            InventorySnapshot.engagement_id == payload.engagement_id,
        )
    )
    if inventory_snapshot is None:
        raise HTTPException(status_code=404, detail="inventory snapshot not found")

    if payload.threat_intel_ids:
        threat_intel_records = session.scalars(
            select(ThreatIntelRecord).where(ThreatIntelRecord.id.in_(payload.threat_intel_ids))
        ).all()
    else:
        threat_intel_records = session.scalars(select(ThreatIntelRecord)).all()

    decision = analyze_relevance(
        session,
        requested_by=actor,
        engagement_id=payload.engagement_id,
        inventory_snapshot=inventory_snapshot,
        threat_intel_records=list(threat_intel_records),
        include_prior_findings=payload.include_prior_findings,
    )
    write_audit_event(
        session=session,
        actor=actor,
        action="relevance.analysis.completed",
        object_type="relevance_decision",
        object_id=str(decision.id),
        metadata={
            "engagement_id": str(payload.engagement_id),
            "inventory_snapshot_id": str(payload.inventory_snapshot_id),
            "threat_intel_count": len(threat_intel_records),
        },
    )
    session.commit()
    session.refresh(decision)
    return RelevanceDecisionRead.model_validate(decision)


@router.get("/relevance/{decision_id}", response_model=RelevanceDecisionRead)
def get_relevance_decision(
    decision_id: UUID,
    session: Session = Depends(get_session),
) -> RelevanceDecisionRead:
    decision = session.scalar(select(RelevanceDecision).where(RelevanceDecision.id == decision_id))
    if decision is None:
        raise HTTPException(status_code=404, detail="relevance decision not found")
    return RelevanceDecisionRead.model_validate(decision)

