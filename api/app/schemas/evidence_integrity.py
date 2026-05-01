from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field


class EvidenceIntegrityResultRead(BaseModel):
    finding_id: UUID
    status: str
    artifact_id: UUID | None = None
    artifact_uri: str | None = None
    stored_sha256: str | None = None
    current_sha256: str | None = None
    timestamp_status: str = "not-available"
    timestamp_response_uri: str | None = None
    verified_at: datetime
    audit_event_id: UUID | None = None
    detail: str | None = None


class RunEvidenceIntegrityResultRead(BaseModel):
    run_id: UUID
    verified_at: datetime
    status: str
    total_findings: int
    verified: int
    integrity_failures: int
    unavailable: int
    results: list[EvidenceIntegrityResultRead] = Field(default_factory=list)
    summary: dict[str, Any] = Field(default_factory=dict)
