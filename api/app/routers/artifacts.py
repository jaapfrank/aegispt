from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.app.config import Settings, get_settings
from api.app.db import get_session
from api.app.models import EvidenceArtifact
from api.app.services.artifact_storage import (
    artifact_storage_config_from_settings,
    load_artifact_content,
)

router = APIRouter(prefix="/api/v1/artifacts", tags=["artifacts"])


@router.get("/{artifact_id}/content")
def get_artifact_content(
    artifact_id: UUID,
    session: Session = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> Response:
    artifact = session.scalar(select(EvidenceArtifact).where(EvidenceArtifact.id == artifact_id))
    if artifact is None:
        raise HTTPException(status_code=404, detail="artifact not found")

    content = load_artifact_content(
        config=artifact_storage_config_from_settings(settings),
        uri=artifact.uri,
    )
    if content is None:
        raise HTTPException(
            status_code=409,
            detail="artifact content is not available through the configured storage backend",
        )

    file_name = str(artifact.metadata_json.get("name", f"{artifact.id}.bin"))
    headers = {"Content-Disposition": f'attachment; filename="{file_name}"'}

    return Response(content=content.data, media_type=content.content_type, headers=headers)
