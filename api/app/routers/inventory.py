from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.app.auth import get_current_actor
from api.app.db import get_session
from api.app.models import Engagement, InventorySnapshot
from api.app.schemas.inventory import InventoryRunCreate, InventorySnapshotRead, InventorySummaryRead
from api.app.services.audit import write_audit_event
from api.app.services.inventory import inventory_summary_from_normalized, normalize_inventory_observations

router = APIRouter(prefix="/api/v1", tags=["inventory"])


@router.post("/inventory/runs", response_model=InventorySnapshotRead, status_code=status.HTTP_201_CREATED)
def create_inventory_run(
    payload: InventoryRunCreate,
    session: Session = Depends(get_session),
    actor: str = Depends(get_current_actor),
) -> InventorySnapshotRead:
    engagement = session.scalar(select(Engagement).where(Engagement.id == payload.engagement_id))
    if engagement is None:
        raise HTTPException(status_code=404, detail="engagement not found")

    normalized = normalize_inventory_observations(
        observations=[item.model_dump() for item in payload.observations],
        environment_notes=payload.environment_notes,
        assumptions=payload.assumptions,
    )
    summary = inventory_summary_from_normalized(normalized)
    snapshot = InventorySnapshot(
        engagement_id=payload.engagement_id,
        requested_by=actor,
        status="completed",
        source_tools_json=list(dict.fromkeys(payload.source_tools)),
        raw_inputs_json={"observations": [item.model_dump() for item in payload.observations]},
        normalized_inventory_json=normalized,
        summary_json=summary,
        environment_notes_json=list(payload.environment_notes),
        assumptions_json=list(payload.assumptions),
        confidence_score=float(normalized.get("confidence_score") or 0.0),
    )
    session.add(snapshot)
    session.flush()

    write_audit_event(
        session=session,
        actor=actor,
        action="inventory.snapshot.created",
        object_type="inventory_snapshot",
        object_id=str(snapshot.id),
        metadata={"engagement_id": str(payload.engagement_id), "source_tools": payload.source_tools},
    )
    session.commit()
    session.refresh(snapshot)
    return InventorySnapshotRead.model_validate(snapshot)


@router.get("/inventory/{inventory_id}", response_model=InventorySnapshotRead)
def get_inventory_snapshot(
    inventory_id: UUID,
    session: Session = Depends(get_session),
) -> InventorySnapshotRead:
    snapshot = session.scalar(select(InventorySnapshot).where(InventorySnapshot.id == inventory_id))
    if snapshot is None:
        raise HTTPException(status_code=404, detail="inventory snapshot not found")
    return InventorySnapshotRead.model_validate(snapshot)


@router.get("/inventory/{inventory_id}/summary", response_model=InventorySummaryRead)
def get_inventory_summary(
    inventory_id: UUID,
    session: Session = Depends(get_session),
) -> InventorySummaryRead:
    snapshot = session.scalar(select(InventorySnapshot).where(InventorySnapshot.id == inventory_id))
    if snapshot is None:
        raise HTTPException(status_code=404, detail="inventory snapshot not found")
    return InventorySummaryRead(**snapshot.summary_json)

