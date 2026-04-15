from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field

from api.app.schemas.findings import FindingRead


class FindingRelatedArtifactRead(BaseModel):
    artifact_id: UUID
    kind: str
    uri: str
    download_path: str
    name: str
    redaction_state: str
    created_at: datetime


class FindingRelatedExecutionRead(BaseModel):
    execution_id: UUID
    task_id: UUID
    tool: str
    target_id: str
    task_status: str
    exit_code: int
    tool_version: str
    stdout_excerpt: str | None = None
    stderr_excerpt: str | None = None
    created_at: datetime
    artifacts: list[FindingRelatedArtifactRead] = Field(default_factory=list)


class FindingTheaterRead(BaseModel):
    finding: FindingRead
    severity_rank: int
    confidence_label: str
    exploitability: str | None = None
    business_impact: str
    technical_details: str
    evidence_summary: str
    provenance: dict[str, Any] = Field(default_factory=dict)
    methodology: dict[str, Any] = Field(default_factory=dict)
    remediation: dict[str, Any] = Field(default_factory=dict)
    verification_status: str
    next_steps: list[str] = Field(default_factory=list)
    risk_snapshot: dict[str, Any] = Field(default_factory=dict)


class FindingEvidenceReplayRead(BaseModel):
    finding: FindingRead
    evidence_ref: str
    methodology_references: dict[str, Any] = Field(default_factory=dict)
    pack_provenance: dict[str, Any] = Field(default_factory=dict)
    inventory_source: dict[str, Any] = Field(default_factory=dict)
    relevance_source: dict[str, Any] = Field(default_factory=dict)
    validation_history: list[dict[str, Any]] = Field(default_factory=list)
    related_executions: list[FindingRelatedExecutionRead] = Field(default_factory=list)
