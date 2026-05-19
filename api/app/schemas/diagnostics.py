from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class DiagnosticSubsystemRead(BaseModel):
    id: str
    title: str
    status: str
    summary: str
    details: list[str] = Field(default_factory=list)
    operator_next_step: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class DiagnosticFailureRead(BaseModel):
    subsystem: str
    status: str
    occurred_at: datetime | None = None
    summary: str
    object_type: str | None = None
    object_id: str | None = None
    operator_next_step: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class DiagnosticsRead(BaseModel):
    tenant_id: str
    generated_at: datetime
    overall_status: str
    subsystems: list[DiagnosticSubsystemRead]
    recent_failures: list[DiagnosticFailureRead] = Field(default_factory=list)
    support_bundle_endpoint: str = "/api/v1/diagnostics/support-bundle"


class SupportBundleRead(BaseModel):
    kind: str = "aegispt.support_bundle"
    tenant_id: str
    generated_at: datetime
    diagnostics: DiagnosticsRead
    config_shape: dict[str, Any] = Field(default_factory=dict)
    runtime_ids: dict[str, Any] = Field(default_factory=dict)
    recent_logs: list[dict[str, Any]] = Field(default_factory=list)
    validation: dict[str, Any] = Field(default_factory=dict)
    redaction: dict[str, Any] = Field(default_factory=dict)
