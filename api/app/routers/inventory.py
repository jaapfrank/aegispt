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
from api.app.services.inventory import create_inventory_snapshot_record

router = APIRouter(prefix="/api/v1", tags=["inventory"])


def _inventory_sort_key(snapshot: InventorySnapshot) -> tuple[object, int, str]:
    source_tools = snapshot.source_tools_json or []
    is_seed_only = bool(source_tools) and all(tool == "wizard-input" for tool in source_tools)
    return (snapshot.created_at, 0 if is_seed_only else 1, snapshot.id.hex)


@router.get("/engagements/{engagement_id}/inventory", response_model=list[InventorySnapshotRead])
def list_inventory_runs(
    engagement_id: UUID,
    session: Session = Depends(get_session),
) -> list[InventorySnapshotRead]:
    snapshots = session.scalars(
        select(InventorySnapshot)
        .where(InventorySnapshot.engagement_id == engagement_id)
    ).all()
    snapshots = sorted(snapshots, key=_inventory_sort_key, reverse=True)
    return [InventorySnapshotRead.model_validate(snapshot) for snapshot in snapshots]


@router.post("/inventory/runs", response_model=InventorySnapshotRead, status_code=status.HTTP_201_CREATED)
def create_inventory_run(
    payload: InventoryRunCreate,
    session: Session = Depends(get_session),
    actor: str = Depends(get_current_actor),
) -> InventorySnapshotRead:
    engagement = session.scalar(select(Engagement).where(Engagement.id == payload.engagement_id))
    if engagement is None:
        raise HTTPException(status_code=404, detail="engagement not found")

    snapshot = create_inventory_snapshot_record(
        engagement_id=payload.engagement_id,
        requested_by=actor,
        source_tools=payload.source_tools,
        observations=[item.model_dump() for item in payload.observations],
        environment_notes=payload.environment_notes,
        assumptions=payload.assumptions,
        raw_inputs_json={"observations": [item.model_dump() for item in payload.observations]},
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
