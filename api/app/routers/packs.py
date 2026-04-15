from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.app.auth import get_current_actor
from api.app.db import get_session
from api.app.models import CapabilityPack, RelevanceDecision
from api.app.schemas.packs import (
    CapabilityPackArtifactRead,
    CapabilityPackDeploymentCreate,
    CapabilityPackDeploymentRead,
    CapabilityPackGenerateCreate,
    CapabilityPackRead,
    CapabilityPackRollbackCreate,
    CapabilityPackValidationRead,
)
from api.app.services.audit import write_audit_event
from api.app.services.packs import (
    approve_pack,
    deploy_pack,
    generate_pack_from_relevance,
    load_pack,
    rollback_pack,
    validate_pack,
)

router = APIRouter(prefix="/api/v1", tags=["packs"])


@router.get("/engagements/{engagement_id}/packs", response_model=list[CapabilityPackRead])
def list_capability_packs_for_engagement(
    engagement_id: UUID,
    session: Session = Depends(get_session),
) -> list[CapabilityPackRead]:
    packs = session.scalars(
        select(CapabilityPack)
        .where(CapabilityPack.engagement_id == engagement_id)
        .order_by(CapabilityPack.created_at.desc(), CapabilityPack.id.desc())
    ).all()
    return [CapabilityPackRead.model_validate(pack) for pack in packs]


@router.post("/packs/generate", response_model=CapabilityPackRead, status_code=status.HTTP_201_CREATED)
def generate_capability_pack(
    payload: CapabilityPackGenerateCreate,
    session: Session = Depends(get_session),
    actor: str = Depends(get_current_actor),
) -> CapabilityPackRead:
    decision = session.scalar(
        select(RelevanceDecision).where(
            RelevanceDecision.id == payload.relevance_decision_id,
            RelevanceDecision.engagement_id == payload.engagement_id,
        )
    )
    if decision is None:
        raise HTTPException(status_code=404, detail="relevance decision not found")

    pack = generate_pack_from_relevance(
        session,
        requested_by=actor,
        decision=decision,
        name=payload.name,
        description=payload.description,
        generation_mode=payload.generation_mode,
        parent_pack_id=payload.parent_pack_id,
    )
    write_audit_event(
        session=session,
        actor=actor,
        action="capability_pack.generated",
        object_type="capability_pack",
        object_id=str(pack.id),
        metadata={"engagement_id": str(payload.engagement_id), "relevance_decision_id": str(decision.id)},
    )
    session.commit()
    hydrated = load_pack(session, pack.id)
    if hydrated is None:
        raise HTTPException(status_code=500, detail="capability pack could not be reloaded")
    return CapabilityPackRead.model_validate(hydrated)


@router.get("/packs/{pack_id}", response_model=CapabilityPackRead)
def get_capability_pack(
    pack_id: UUID,
    session: Session = Depends(get_session),
) -> CapabilityPackRead:
    pack = load_pack(session, pack_id)
    if pack is None:
        raise HTTPException(status_code=404, detail="capability pack not found")
    return CapabilityPackRead.model_validate(pack)


@router.get("/packs/{pack_id}/artifacts", response_model=list[CapabilityPackArtifactRead])
def get_capability_pack_artifacts(
    pack_id: UUID,
    session: Session = Depends(get_session),
) -> list[CapabilityPackArtifactRead]:
    pack = load_pack(session, pack_id)
    if pack is None:
        raise HTTPException(status_code=404, detail="capability pack not found")
    return [CapabilityPackArtifactRead.model_validate(artifact) for artifact in pack.artifacts]


@router.post("/packs/{pack_id}/validate", response_model=CapabilityPackValidationRead)
def validate_capability_pack(
    pack_id: UUID,
    session: Session = Depends(get_session),
    actor: str = Depends(get_current_actor),
) -> CapabilityPackValidationRead:
    pack = load_pack(session, pack_id)
    if pack is None:
        raise HTTPException(status_code=404, detail="capability pack not found")
    validation = validate_pack(session, pack=pack, executed_by=actor)
    write_audit_event(
        session=session,
        actor=actor,
        action="capability_pack.validated",
        object_type="capability_pack_validation",
        object_id=str(validation.id),
        metadata={"pack_id": str(pack.id), "status": validation.status},
    )
    session.commit()
    return CapabilityPackValidationRead.model_validate(validation)


@router.post("/packs/{pack_id}/approve", response_model=CapabilityPackRead)
def approve_capability_pack(
    pack_id: UUID,
    notes: str | None = Query(default=None),
    session: Session = Depends(get_session),
    actor: str = Depends(get_current_actor),
) -> CapabilityPackRead:
    pack = load_pack(session, pack_id)
    if pack is None:
        raise HTTPException(status_code=404, detail="capability pack not found")
    try:
        approve_pack(session, pack=pack, approver_id=actor, notes=notes)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    write_audit_event(
        session=session,
        actor=actor,
        action="capability_pack.approved",
        object_type="capability_pack",
        object_id=str(pack.id),
        metadata={"notes": notes},
    )
    session.commit()
    hydrated = load_pack(session, pack.id)
    if hydrated is None:
        raise HTTPException(status_code=500, detail="capability pack could not be reloaded")
    return CapabilityPackRead.model_validate(hydrated)


@router.post("/packs/{pack_id}/deploy", response_model=CapabilityPackDeploymentRead)
def deploy_capability_pack(
    pack_id: UUID,
    payload: CapabilityPackDeploymentCreate,
    session: Session = Depends(get_session),
    actor: str = Depends(get_current_actor),
) -> CapabilityPackDeploymentRead:
    pack = load_pack(session, pack_id)
    if pack is None:
        raise HTTPException(status_code=404, detail="capability pack not found")
    try:
        deployment = deploy_pack(
            session,
            pack=pack,
            deployed_by=actor,
            engagement_id=payload.engagement_id,
            deployment_target=payload.deployment_target,
            run_profile_name=payload.run_profile_name,
            notes=payload.notes,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    write_audit_event(
        session=session,
        actor=actor,
        action="capability_pack.deployed",
        object_type="capability_pack_deployment",
        object_id=str(deployment.id),
        metadata={"pack_id": str(pack.id), "engagement_id": str(payload.engagement_id)},
    )
    session.commit()
    return CapabilityPackDeploymentRead.model_validate(deployment)


@router.post("/packs/{pack_id}/rollback", response_model=CapabilityPackDeploymentRead)
def rollback_capability_pack(
    pack_id: UUID,
    payload: CapabilityPackRollbackCreate,
    session: Session = Depends(get_session),
    actor: str = Depends(get_current_actor),
) -> CapabilityPackDeploymentRead:
    pack = load_pack(session, pack_id)
    if pack is None:
        raise HTTPException(status_code=404, detail="capability pack not found")
    try:
        deployment = rollback_pack(
            session,
            current_pack=pack,
            deployed_by=actor,
            engagement_id=payload.engagement_id,
            run_profile_name=payload.run_profile_name,
            notes=payload.notes,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    write_audit_event(
        session=session,
        actor=actor,
        action="capability_pack.rolled_back",
        object_type="capability_pack_deployment",
        object_id=str(deployment.id),
        metadata={"rolled_back_pack_id": str(pack.id), "engagement_id": str(payload.engagement_id)},
    )
    session.commit()
    return CapabilityPackDeploymentRead.model_validate(deployment)
