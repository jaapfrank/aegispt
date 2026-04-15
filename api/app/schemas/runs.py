from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from api.app.schemas.packs import RunPackBindingRead


class RunProfileRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    run_class: str
    limits_json: dict[str, Any]


class RunCreate(BaseModel):
    profile_name: str = Field(default="passive-web-baseline")
    source_inventory_snapshot_id: UUID | None = None
    configuration_json: dict[str, Any] = Field(default_factory=dict)


class ApprovalCreate(BaseModel):
    step_id: str = Field(default="run.launch")
    decision: Literal["approved", "rejected"]


class ApprovalRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    step_id: str
    approver_id: str
    decision: str
    created_at: datetime


class TaskRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    tool: str
    target_id: str
    status: str
    params_json: dict[str, Any]


class FindingSummaryRead(BaseModel):
    finding_count: int
    findings_by_severity: dict[str, int]
    findings_by_status: dict[str, int]


class RunDispatchRead(BaseModel):
    run: RunRead
    dispatch_mode: str
    dispatched_task_ids: list[UUID]


class RunRead(BaseModel):
    id: UUID
    engagement_id: UUID
    requested_by: str
    status: str
    source_inventory_snapshot_id: UUID | None = None
    started_at: datetime | None
    created_at: datetime
    profile: RunProfileRead
    required_approvals: int
    granted_approvals: int
    pending_approvals: int
    approvals: list[ApprovalRead]
    tasks: list[TaskRead]
    findings: FindingSummaryRead
    configuration_json: dict[str, Any] = Field(default_factory=dict)
    pack_binding: RunPackBindingRead | None = None
