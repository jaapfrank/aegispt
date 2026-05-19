from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

DeceptionTrapKind = Literal["hallucination_api", "fake_admin_api", "canary_document"]


class DeceptionBoundaryRead(BaseModel):
    local_controlled_fixture: bool = True
    network_tarpitting: bool = False
    automatic_live_deployment: bool = False
    legitimate_traffic_interference_expected: bool = False
    credential_materialized: bool = False
    dispatches_runtime_work: bool = False


class DeceptionTrapCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=3, max_length=120)
    trap_kind: DeceptionTrapKind = "hallucination_api"
    local_only: bool = True
    enabled: bool = True
    max_depth: int = Field(default=4, ge=1, le=8)
    operator_note: str | None = Field(default=None, max_length=500)


class DeceptionTrapRead(BaseModel):
    id: UUID
    tenant_id: str
    name: str
    trap_kind: DeceptionTrapKind
    enabled: bool
    local_only: bool
    max_depth: int
    endpoint_path: str
    response_preview: dict
    boundary: DeceptionBoundaryRead
    operator_note: str | None = None
    created_at: datetime
    updated_at: datetime
    created_by: str
    updated_by: str


class DeceptionTrapListRead(BaseModel):
    tenant_id: str
    traps: list[DeceptionTrapRead] = Field(default_factory=list)
    boundary: DeceptionBoundaryRead = Field(default_factory=DeceptionBoundaryRead)


class DeceptionProbeRead(BaseModel):
    trap_id: UUID
    trap_kind: DeceptionTrapKind
    name: str
    depth: int
    max_depth: int
    payload: dict
    next_path: str | None = None
    alert_id: UUID
    boundary: DeceptionBoundaryRead


class DeceptionAlertRead(BaseModel):
    id: UUID
    tenant_id: str
    trap_id: UUID
    trap_name: str
    trap_kind: DeceptionTrapKind
    probed_path: str
    actor: str
    user_agent: str | None = None
    source: str = "local_controlled_probe"
    created_at: datetime
    evidence_ref: str
    boundary: DeceptionBoundaryRead


class DeceptionAlertListRead(BaseModel):
    tenant_id: str
    alerts: list[DeceptionAlertRead] = Field(default_factory=list)
    boundary: DeceptionBoundaryRead = Field(default_factory=DeceptionBoundaryRead)
