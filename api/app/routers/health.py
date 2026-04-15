from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from api.app.config import Settings, get_settings
from api.app.db import database_ready, get_session
from api.app.schemas.health import HealthResponse

router = APIRouter(prefix="/health", tags=["health"])


@router.get("/live", response_model=HealthResponse)
def live(settings: Settings = Depends(get_settings)) -> HealthResponse:
    return HealthResponse(
        status="ok",
        app=settings.app_name,
        environment=settings.app_env,
        detail="service is running",
    )


@router.get("/ready", response_model=HealthResponse)
def ready(
    session: Session = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> HealthResponse:
    try:
        database_ready(session)
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=503, detail=f"database unavailable: {exc}") from exc

    return HealthResponse(
        status="ok",
        app=settings.app_name,
        environment=settings.app_env,
        detail="database connection verified",
    )
