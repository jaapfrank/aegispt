from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator


class EngagementCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    client: str | None = Field(default=None, max_length=255)
    tenant_id: str | None = Field(default=None, max_length=100)
    roe_ref: str | None = Field(default=None, max_length=255)
    retention_days: int = Field(default=90, ge=1, le=3650)
    starts_at: datetime | None = None
    ends_at: datetime | None = None

    @field_validator("name", "client", "roe_ref")
    @classmethod
    def reject_null_bytes(cls, value: str | None) -> str | None:
        if value is not None and "\x00" in value:
            raise ValueError("field must not contain null bytes")
        return value


class EngagementRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    client: str | None
    tenant_id: str | None = None
    roe_ref: str | None
    authorization_confirmed_by: str | None = None
    authorization_confirmed_at: datetime | None = None
    status: str
    retention_days: int = 90
    starts_at: datetime | None
    ends_at: datetime | None


class EngagementAuthorizationConfirmRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    roe_ref: str | None
    authorization_confirmed_by: str | None
    authorization_confirmed_at: datetime | None


class ExposureScorePointRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    run_id: UUID | None = None
    score: float
    severity_breakdown_json: dict[str, int]
    open_critical_count: int
    open_high_count: int
    remediated_count: int
    verified_count: int
    trend: str
    computed_at: datetime


class ExposureScoreRead(BaseModel):
    engagement_id: UUID
    current: ExposureScorePointRead
    history: list[ExposureScorePointRead]
    advisory_note: str


class ScopeCreate(BaseModel):
    allowlist_json: dict[str, Any] = Field(default_factory=dict)
    denylist_json: dict[str, Any] = Field(default_factory=dict)


class ScopeRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    engagement_id: UUID
    allowlist_json: dict[str, Any]
    denylist_json: dict[str, Any]


class EngagementDataRetentionUpdate(BaseModel):
    retention_days: int = Field(ge=1, le=3650)


class EngagementDataRetentionRead(BaseModel):
    engagement_id: UUID
    retention_days: int
    cutoff_at: datetime
    next_cleanup_at: datetime
    eligible_run_count: int
    active_run_count: int
    soft_deleted_run_count: int
    policy: str


class EngagementDataCleanupRead(BaseModel):
    engagement_id: UUID
    retention_days: int
    cutoff_at: datetime
    soft_deleted_runs: int
    skipped_runs: int
    soft_deleted_run_ids: list[UUID] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class EngagementPurgeCreate(BaseModel):
    confirmation: str


class EngagementPurgeRead(BaseModel):
    engagement_id: UUID
    purged_at: datetime
    counts: dict[str, int]
    credential_material_exported: bool = False
    retained_records: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class ScheduledRunCreate(BaseModel):
    profile_name: str = Field(default="passive-web-baseline")
    source_inventory_snapshot_id: UUID | None = None
    cadence: Literal["daily", "weekly"]
    timezone: str = Field(default="UTC", min_length=1, max_length=100)
    starts_at: datetime | None = None
    configuration_json: dict[str, Any] = Field(default_factory=dict)


class ScheduledRunLaunchDueCreate(BaseModel):
    due_at: datetime | None = None


class ScheduledRunLaunchRead(BaseModel):
    scheduled_run_id: UUID
    run_id: UUID
    run_status: str
    scheduled_due_at: datetime
    next_run_at: datetime
    dispatch_state: str
    dispatch_mode: str | None = None
    dispatched_task_ids: list[UUID] = Field(default_factory=list)
    dispatch_error: str | None = None


class ScheduledRunLaunchBatchRead(BaseModel):
    due_at: datetime
    launched_count: int
    launches: list[ScheduledRunLaunchRead] = Field(default_factory=list)


class ScheduledRunRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    engagement_id: UUID
    profile_name: str
    source_inventory_snapshot_id: UUID | None = None
    cadence: str
    cron_expression: str
    timezone: str
    status: str
    next_run_at: datetime
    last_run_at: datetime | None = None
    last_launched_run_id: UUID | None = None
    configuration_json: dict[str, Any]
    created_by: str
    updated_by: str
    paused_at: datetime | None = None
    paused_by: str | None = None
    created_at: datetime
    updated_at: datetime
