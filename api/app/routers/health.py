from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from api.app.config import Settings, get_settings
from api.app.db import database_ready, get_session
from api.app.schemas.health import HealthResponse

router = APIRouter(prefix="/health", tags=["health"])


@router.get("/live", response_model=HealthResponse)
def live(request: Request, settings: Settings = Depends(get_settings)) -> HealthResponse:
    runtime_state = str(getattr(request.app.state, "runtime_state", "healthy") or "healthy")
    status = "ok" if runtime_state == "healthy" else "degraded"
    detail = "service is running" if runtime_state == "healthy" else f"service is {runtime_state}"
    diagnostics = [
        f"runtime_state={runtime_state}",
        f"public_base_url={settings.app_public_base_url}",
        "local states: healthy, degraded, shutting_down, unreachable",
    ]
    return HealthResponse(
        status=status,
        app=settings.app_name,
        environment=settings.app_env,
        detail=detail,
        runtime_state=runtime_state,
        checked_at=datetime.now(UTC).isoformat(),
        diagnostics=diagnostics,
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
