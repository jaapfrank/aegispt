from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from api.app.auth import require_roles
from api.app.config import Settings, get_settings
from api.app.db import get_session
from api.app.schemas.diagnostics import DiagnosticsRead, SupportBundleRead
from api.app.services.diagnostics import build_diagnostics, build_support_bundle
from api.app.services.tenancy import get_current_tenant_id

router = APIRouter(prefix="/api/v1/diagnostics", tags=["diagnostics"])


@router.get("", response_model=DiagnosticsRead)
def get_diagnostics(
    request: Request,
    session: Session = Depends(get_session),
    settings: Settings = Depends(get_settings),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> DiagnosticsRead:
    runtime_state = str(getattr(request.app.state, "runtime_state", "healthy") or "healthy")
    return build_diagnostics(
        session,
        tenant_id=tenant_id,
        settings=settings,
        runtime_state=runtime_state,
    )


@router.get("/support-bundle", response_model=SupportBundleRead)
def get_support_bundle(
    request: Request,
    session: Session = Depends(get_session),
    settings: Settings = Depends(get_settings),
    tenant_id: str | None = Depends(get_current_tenant_id),
    _actor: str = Depends(require_roles("admin")),
) -> SupportBundleRead:
    runtime_state = str(getattr(request.app.state, "runtime_state", "healthy") or "healthy")
    return build_support_bundle(
        session,
        tenant_id=tenant_id,
        settings=settings,
        runtime_state=runtime_state,
    )
