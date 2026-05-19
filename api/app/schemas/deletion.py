from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field


class RunBulkDeleteCreate(BaseModel):
    run_ids: list[UUID] = Field(min_length=1, max_length=200)


class EngagementDeleteCreate(BaseModel):
    confirmation: str | None = None


class DeleteImpactRead(BaseModel):
    object_type: str
    object_id: UUID | None = None
    object_ids: list[UUID] = Field(default_factory=list)
    dry_run: bool = True
    blocked: bool = False
    blocked_reason: str | None = None
    counts: dict[str, int] = Field(default_factory=dict)
    total_items: int = 0
    deleted_at: datetime | None = None
    hard_delete_after_days: int = 30
    hard_delete_eligible_at: datetime | None = None
    deleted_ids: list[UUID] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
