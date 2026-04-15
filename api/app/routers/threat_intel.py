from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from api.app.auth import get_current_actor
from api.app.db import get_session
from api.app.schemas.threat_intel import ThreatIntelIngestCreate, ThreatIntelRecordRead
from api.app.services.audit import write_audit_event
from api.app.services.threat_intel import load_threat_intel_record, search_threat_intel_records, upsert_threat_intel_record

router = APIRouter(prefix="/api/v1", tags=["threat-intel"])


@router.post("/threat-intel/ingest", response_model=list[ThreatIntelRecordRead], status_code=status.HTTP_201_CREATED)
def ingest_threat_intel(
    payload: ThreatIntelIngestCreate,
    session: Session = Depends(get_session),
    actor: str = Depends(get_current_actor),
) -> list[ThreatIntelRecordRead]:
    ingested = [upsert_threat_intel_record(session, record.model_dump()) for record in payload.records]
    write_audit_event(
        session=session,
        actor=actor,
        action="threat_intel.ingested",
        object_type="threat_intel_batch",
        object_id=str(len(ingested)),
        metadata={"record_count": len(ingested)},
    )
    session.commit()
    return [ThreatIntelRecordRead.model_validate(record) for record in ingested]


@router.get("/threat-intel/search", response_model=list[ThreatIntelRecordRead])
def search_threat_intel(
    q: str | None = Query(default=None),
    product: str | None = Query(default=None),
    attack_surface_type: str | None = Query(default=None),
    session: Session = Depends(get_session),
) -> list[ThreatIntelRecordRead]:
    records = search_threat_intel_records(
        session,
        query=q,
        product=product,
        attack_surface_type=attack_surface_type,
    )
    return [ThreatIntelRecordRead.model_validate(record) for record in records]


@router.get("/threat-intel/{record_id}", response_model=ThreatIntelRecordRead)
def get_threat_intel_record(
    record_id: UUID,
    session: Session = Depends(get_session),
) -> ThreatIntelRecordRead:
    record = load_threat_intel_record(session, record_id)
    if record is None:
        raise HTTPException(status_code=404, detail="threat intel record not found")
    return ThreatIntelRecordRead.model_validate(record)

