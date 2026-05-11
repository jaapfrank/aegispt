from __future__ import annotations

from fastapi import APIRouter, Depends

from api.app.auth import require_roles
from api.app.schemas.safe_click import SafeClickEvaluateRequest, SafeClickEvaluationRead
from api.app.services.safe_click import evaluate_safe_click

router = APIRouter(prefix="/api/v1/safe-click", tags=["safe-click"])


@router.post("/evaluate", response_model=SafeClickEvaluationRead)
def evaluate_link(
    payload: SafeClickEvaluateRequest,
    _actor: str = Depends(require_roles("admin", "operator", "reviewer")),
) -> SafeClickEvaluationRead:
    return evaluate_safe_click(payload.model_dump())
