from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class EvidenceArtifactRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    kind: str
    uri: str
    sha256: str
    redaction_state: str
    metadata_json: dict[str, Any]
    created_at: datetime


class ToolExecutionRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    runner_digest: str
    tool_version: str
    exit_code: int
    stdout_text: str | None
    stderr_text: str | None
    created_at: datetime
    artifacts: list[EvidenceArtifactRead]


class TaskDetailRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    run_id: UUID | None
    tool: str
    target_id: str
    params_json: dict[str, Any]
    status: str
    created_at: datetime
    updated_at: datetime
    executions: list[ToolExecutionRead]
    stdout_snapshot: dict[str, Any] = Field(default_factory=dict)
