from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.orm import Session

from api.app.auth import require_roles
from api.app.db import get_session
from api.app.schemas.deception import (
    DeceptionAlertListRead,
    DeceptionBoundaryRead,
    DeceptionProbeRead,
    DeceptionTrapCreate,
    DeceptionTrapListRead,
    DeceptionTrapRead,
)
from api.app.services.deception import (
    create_deception_trap,
    list_deception_alerts,
    list_deception_traps,
    record_deception_probe,
)
from api.app.services.tenancy import get_current_tenant_id

router = APIRouter(prefix="/api/v1/deception", tags=["deception"])


@router.get("/traps", response_model=DeceptionTrapListRead)
def get_deception_traps(
    session: Session = Depends(get_session),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> DeceptionTrapListRead:
    tenant = tenant_id or "default"
    return DeceptionTrapListRead(
        tenant_id=tenant,
        traps=list_deception_traps(session, tenant_id=tenant_id),
        boundary=DeceptionBoundaryRead(),
    )


@router.post("/traps", response_model=DeceptionTrapRead, status_code=201)
def post_deception_trap(
    payload: DeceptionTrapCreate,
    session: Session = Depends(get_session),
    tenant_id: str | None = Depends(get_current_tenant_id),
    actor: str = Depends(require_roles("admin", "operator")),
) -> DeceptionTrapRead:
    trap = create_deception_trap(session, tenant_id=tenant_id, payload=payload, actor=actor)
    session.commit()
    return trap


@router.get("/traps/{trap_id}/probe", response_model=DeceptionProbeRead)
def probe_deception_trap(
    trap_id: UUID,
    request: Request,
    depth: int = Query(default=0, ge=0, le=16),
    session: Session = Depends(get_session),
    tenant_id: str | None = Depends(get_current_tenant_id),
    actor: str = Depends(require_roles("admin", "operator", "reviewer")),
) -> DeceptionProbeRead:
    probe = record_deception_probe(
        session,
        tenant_id=tenant_id,
        trap_id=trap_id,
        actor=actor,
        probed_path=str(request.url.path) + (f"?{request.url.query}" if request.url.query else ""),
        user_agent=request.headers.get("user-agent"),
        depth=depth,
    )
    session.commit()
    return probe


@router.get("/alerts", response_model=DeceptionAlertListRead)
def get_deception_alerts(
    session: Session = Depends(get_session),
    tenant_id: str | None = Depends(get_current_tenant_id),
) -> DeceptionAlertListRead:
    tenant = tenant_id or "default"
    return DeceptionAlertListRead(
        tenant_id=tenant,
        alerts=list_deception_alerts(session, tenant_id=tenant_id),
        boundary=DeceptionBoundaryRead(),
    )
