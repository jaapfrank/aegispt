from __future__ import annotations

from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field


class KillChainTechniqueRead(BaseModel):
    technique_id: str
    name: str
    status: str
    source_count: int = 0
    sources: list[dict[str, Any]] = Field(default_factory=list)


class KillChainStageRead(BaseModel):
    id: str
    order: int
    tactic_id: str
    tactic_name: str
    label: str
    status: str
    display_state: str
    progress_weight: int
    finding_count: int = 0
    task_count: int = 0
    phase_count: int = 0
    evidence_count: int = 0
    summary: str
    techniques: list[KillChainTechniqueRead] = Field(default_factory=list)


class KillChainProgressRead(BaseModel):
    engagement_id: UUID
    progress_percentage: int
    completed_stage_count: int
    total_stage_count: int
    confirmed_stage_count: int
    tested_stage_count: int
    current_stage_id: str | None = None
    current_stage_label: str | None = None
    highest_reached_stage_id: str | None = None
    highest_reached_stage_label: str | None = None
    stages: list[KillChainStageRead] = Field(default_factory=list)
    matrix: list[dict[str, Any]] = Field(default_factory=list)
    source_summary: dict[str, Any] = Field(default_factory=dict)
    boundary: dict[str, Any] = Field(default_factory=dict)
