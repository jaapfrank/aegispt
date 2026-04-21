from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator


REMEDIATION_STATES = frozenset(
    {
        "not_started",
        "planned",
        "in_progress",
        "ready_for_retest",
        "blocked",
        "verified",
    }
)


class FindingRemediationUpdate(BaseModel):
    state: str = Field(default="not_started", max_length=50)
    notes: str | None = None
    owner: str | None = Field(default=None, max_length=255)

    @field_validator("state")
    @classmethod
    def validate_state(cls, value: str) -> str:
        normalized = value.strip().lower().replace("-", "_")
        if normalized not in REMEDIATION_STATES:
            allowed = ", ".join(sorted(REMEDIATION_STATES))
            raise ValueError(f"state must be one of: {allowed}")
        return normalized


class FindingRemediationRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    finding_id: UUID
    state: str
    notes: str | None
    owner: str | None
    created_by: str
    updated_by: str
    created_at: datetime
    updated_at: datetime


class FindingRetestCreate(BaseModel):
    notes: str | None = None


class FindingRetestRead(BaseModel):
    retest_run_id: UUID
    source_finding_id: UUID
    source_run_id: UUID
    status: str
    profile_name: str
    queued_task_ids: list[UUID]
    configuration_json: dict[str, Any] = Field(default_factory=dict)
