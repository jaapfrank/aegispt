from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from api.app.auth import require_roles
from api.app.config import Settings, get_settings
from api.app.db import get_session
from api.app.schemas.settings import SettingsPatch, SettingsRead, SettingsReadinessRead
from api.app.services.settings import (
    read_instance_settings,
    read_settings_readiness,
    update_instance_settings,
)
from api.app.services.tenancy import get_current_tenant_id

router = APIRouter(prefix="/api/v1/settings", tags=["settings"])


@router.get("", response_model=SettingsRead)
def get_operator_settings(
    session: Session = Depends(get_session),
    settings: Settings = Depends(get_settings),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> SettingsRead:
    return read_instance_settings(session, tenant_id=tenant_id, settings=settings)


@router.patch("", response_model=SettingsRead)
def patch_operator_settings(
    payload: SettingsPatch,
    session: Session = Depends(get_session),
    settings: Settings = Depends(get_settings),
    tenant_id: str | None = Depends(get_current_tenant_id),
    actor: str = Depends(require_roles("admin")),
) -> SettingsRead:
    response = update_instance_settings(
        session,
        tenant_id=tenant_id,
        settings=settings,
        patch=payload.settings,
        actor=actor,
    )
    session.commit()
    return response


@router.get("/readiness", response_model=SettingsReadinessRead)
def get_operator_settings_readiness(
    session: Session = Depends(get_session),
    settings: Settings = Depends(get_settings),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> SettingsReadinessRead:
    return read_settings_readiness(session, tenant_id=tenant_id, settings=settings)
