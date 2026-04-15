from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class EngagementCreate(BaseModel):
    name: str
    client: str | None = None
    roe_ref: str | None = None
    starts_at: datetime | None = None
    ends_at: datetime | None = None


class EngagementRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    client: str | None
    roe_ref: str | None
    status: str
    starts_at: datetime | None
    ends_at: datetime | None


class ScopeCreate(BaseModel):
    allowlist_json: dict[str, Any] = Field(default_factory=dict)
    denylist_json: dict[str, Any] = Field(default_factory=dict)


class ScopeRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    engagement_id: UUID
    allowlist_json: dict[str, Any]
    denylist_json: dict[str, Any]
