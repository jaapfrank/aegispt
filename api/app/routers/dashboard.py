from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from api.app.config import Settings, get_settings
from api.app.db import get_session
from api.app.schemas.dashboard import DashboardRead
from api.app.services.dashboard import build_dashboard
from api.app.services.tenancy import get_current_tenant_id

router = APIRouter(prefix="/api/v1/dashboard", tags=["dashboard"])


@router.get("", response_model=DashboardRead)
def get_operator_dashboard(
    engagement_id: UUID | None = None,
    session: Session = Depends(get_session),
    settings: Settings = Depends(get_settings),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> DashboardRead:
    return build_dashboard(session, tenant_id=tenant_id, settings=settings, engagement_id=engagement_id)
