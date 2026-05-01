from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from sqlalchemy.orm import Session

from api.app.auth import get_current_actor
from api.app.db import get_session
from api.app.schemas.mcp import (
    McpOperatorContextRead,
    McpResourcesRead,
    McpToolInvocationRead,
    McpToolInvocationRequest,
    McpToolsRead,
)
from api.app.services.mcp_context import load_mcp_engagement_context, mcp_resource_manifest
from api.app.services.mcp_tools import McpToolError, invoke_mcp_tool, mcp_action_tool_manifest

router = APIRouter(prefix="/api/v1/mcp", tags=["mcp-read-only"])


def require_mcp_action_actor(x_actor: str | None = Header(default=None)) -> str:
    actor = (x_actor or "").strip()
    if not actor:
        raise HTTPException(status_code=401, detail="X-Actor header is required for MCP action tools")
    return actor


@router.get("/resources", response_model=McpResourcesRead)
def list_mcp_resources() -> McpResourcesRead:
    return mcp_resource_manifest()


@router.get("/engagements/{engagement_id}/context", response_model=McpOperatorContextRead)
def get_mcp_engagement_context(
    engagement_id: UUID,
    run_id: UUID | None = Query(default=None),
    session: Session = Depends(get_session),
    actor: str = Depends(get_current_actor),
) -> McpOperatorContextRead:
    context = load_mcp_engagement_context(
        session,
        engagement_id=engagement_id,
        run_id=run_id,
        actor=actor,
    )
    if context is None:
        raise HTTPException(status_code=404, detail="mcp context not found")
    return context


@router.get("/tools", response_model=McpToolsRead, tags=["mcp-action-tools"])
def list_mcp_tools(
    actor: str = Depends(require_mcp_action_actor),
) -> McpToolsRead:
    _ = actor
    return mcp_action_tool_manifest()


@router.post(
    "/tools/{tool_name}/invoke",
    response_model=McpToolInvocationRead,
    tags=["mcp-action-tools"],
)
def invoke_mcp_action_tool(
    tool_name: str,
    payload: McpToolInvocationRequest,
    session: Session = Depends(get_session),
    actor: str = Depends(require_mcp_action_actor),
) -> McpToolInvocationRead:
    try:
        return invoke_mcp_tool(
            session,
            tool_name=tool_name,
            engagement_id=payload.engagement_id,
            finding_id=payload.finding_id,
            arguments=payload.arguments,
            confirmation_confirmed=payload.confirmation.confirmed if payload.confirmation is not None else False,
            actor=actor,
        )
    except McpToolError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc
