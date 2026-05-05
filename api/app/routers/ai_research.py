from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from api.app.auth import get_current_actor
from api.app.db import get_session
from api.app.schemas.ai_research import (
    AiResearchGenerationRead,
    AiResearchLabRead,
    AiResearchScriptGenerateCreate,
)
from api.app.schemas.threat_intel import ThreatIntelRecordRead
from api.app.services.ai_research import (
    CveTemplateUnavailable,
    NucleiTemplateValidationError,
    UnsafeNucleiTemplateError,
    cve_records_for_research,
    generate_research_detection_template,
    lifecycle_note,
    list_research_proposals,
    unavailable_generation_payload,
)
from api.app.services.audit import write_audit_event
from api.app.services.chatgpt_oauth import chatgpt_oauth_status
from api.app.services.settings import effective_runtime_settings
from api.app.services.tenancy import get_current_tenant_id, load_engagement_for_tenant

router = APIRouter(prefix="/api/v1/ai/research", tags=["ai-research"])


@router.get("", response_model=AiResearchLabRead)
def get_ai_research_lab(
    engagement_id: UUID,
    session: Session = Depends(get_session),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> AiResearchLabRead:
    engagement = load_engagement_for_tenant(session, engagement_id, tenant_id)
    cve_records = cve_records_for_research(session)
    proposals = list_research_proposals(session, engagement_id=engagement.id)
    return AiResearchLabRead(
        engagement_id=engagement.id,
        cve_records=[ThreatIntelRecordRead.model_validate(record) for record in cve_records],
        research_proposals=proposals,
        lifecycle_note=lifecycle_note(),
    )


@router.post("/generate-script", response_model=AiResearchGenerationRead)
def generate_ai_research_script(
    payload: AiResearchScriptGenerateCreate,
    session: Session = Depends(get_session),
    actor: str = Depends(get_current_actor),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> AiResearchGenerationRead:
    engagement = load_engagement_for_tenant(session, payload.engagement_id, tenant_id)
    settings = effective_runtime_settings(session, tenant_id=tenant_id)

    if payload.output_kind == "python_detection":
        result = generate_research_detection_template(
            session=session,
            engagement_id=engagement.id,
            description=payload.description,
            output_kind=payload.output_kind,
            actor=actor,
            settings=settings,
        )
        write_audit_event(
            session=session,
            actor=actor,
            action="ai_research.generation_blocked",
            object_type="ai_research",
            object_id=str(engagement.id),
            metadata={
                "engagement_id": str(engagement.id),
                "output_kind": payload.output_kind,
                "reason": "no_existing_python_detection_script_validator",
                "auto_deploy": False,
            },
        )
        session.commit()
        return AiResearchGenerationRead(**result)

    status_payload = chatgpt_oauth_status(
        session=session,
        engagement_id=engagement.id,
        settings=settings,
    )
    if not status_payload.connected:
        result = unavailable_generation_payload("ChatGPT OAuth is not connected for this engagement.")
        write_audit_event(
            session=session,
            actor=actor,
            action="ai_research.generation_unavailable",
            object_type="ai_research",
            object_id=str(engagement.id),
            metadata={
                "engagement_id": str(engagement.id),
                "provider": "chatgpt_oauth",
                "connected": False,
                "token_exposed": False,
            },
        )
        session.commit()
        return AiResearchGenerationRead(**result)

    try:
        result = generate_research_detection_template(
            session=session,
            engagement_id=engagement.id,
            description=payload.description,
            output_kind=payload.output_kind,
            actor=actor,
            settings=settings,
        )
    except CveTemplateUnavailable as exc:
        result = unavailable_generation_payload(str(exc))
        write_audit_event(
            session=session,
            actor=actor,
            action="ai_research.generation_unavailable",
            object_type="ai_research",
            object_id=str(engagement.id),
            metadata={
                "engagement_id": str(engagement.id),
                "provider": "chatgpt_oauth",
                "reason": str(exc),
                "token_exposed": False,
            },
        )
        session.commit()
        return AiResearchGenerationRead(**result)
    except UnsafeNucleiTemplateError as exc:
        session.rollback()
        raise HTTPException(status_code=422, detail=f"generated research template rejected: {exc}") from exc
    except NucleiTemplateValidationError as exc:
        session.rollback()
        raise HTTPException(status_code=422, detail=f"generated research template validation failed: {exc}") from exc

    write_audit_event(
        session=session,
        actor=actor,
        action="ai_research.nuclei_template_generated",
        object_type="ai_research",
        object_id=str(result.get("pack_id")),
        metadata={
            "engagement_id": str(engagement.id),
            "pack_id": str(result.get("pack_id")),
            "artifact_id": str(result.get("artifact_id")),
            "provider": "chatgpt_oauth",
            "detection_only": True,
            "auto_deploy": False,
            "pack_lifecycle_required": True,
        },
    )
    session.commit()
    return AiResearchGenerationRead(**result)
