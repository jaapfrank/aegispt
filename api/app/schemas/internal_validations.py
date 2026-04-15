from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel


class InternalValidationCreate(BaseModel):
    scenario_id: str


class InternalValidationStepApprovalCreate(BaseModel):
    decision: Literal["approved", "rejected"]


class InternalValidationPreflightCheckRead(BaseModel):
    check_id: str
    step_id: str | None
    status: str
    detail: str


class InternalValidationScenarioStepRead(BaseModel):
    step_id: str
    title: str
    description: str
    profile_name: str
    required_approvals: int
    required_scope_keys: list[str]


class InternalValidationScenarioRead(BaseModel):
    scenario_id: str
    name: str
    description: str
    steps: list[InternalValidationScenarioStepRead]


class InternalValidationApprovalRead(BaseModel):
    id: UUID
    approver_id: str
    decision: str
    created_at: datetime


class InternalValidationStepRead(BaseModel):
    id: UUID
    step_id: str
    sequence: int
    title: str
    description: str | None
    profile_name: str
    status: str
    required_approvals: int
    granted_approvals: int
    pending_approvals: int
    approvals: list[InternalValidationApprovalRead]
    launched_run_id: UUID | None
    launched_run_status: str | None
    completed_at: datetime | None


class InternalValidationSessionRead(BaseModel):
    id: UUID
    engagement_id: UUID
    scenario_id: str
    scenario_name: str
    requested_by: str
    status: str
    preflight_state: str
    preflight_checks: list[InternalValidationPreflightCheckRead]
    steps: list[InternalValidationStepRead]
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None


class InternalValidationStepExecuteRead(BaseModel):
    session: InternalValidationSessionRead
    dispatch_mode: str
    launched_run_id: UUID
