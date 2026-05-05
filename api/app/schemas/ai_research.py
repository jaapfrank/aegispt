from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, Field

from api.app.schemas.threat_intel import ThreatIntelRecordRead


class AiResearchScriptGenerateCreate(BaseModel):
    engagement_id: UUID
    description: str = Field(min_length=8, max_length=2000)
    output_kind: Literal["nuclei_yaml", "python_detection"] = "nuclei_yaml"


class AiResearchGenerationRead(BaseModel):
    record_id: UUID | None = None
    status: str
    message: str
    pack_id: UUID | str | None = None
    artifact_id: UUID | str | None = None
    pack_status: str | None = None
    review_url: str | None = None
    template_yaml: str | None = None
    yaml_diff: str | None = None
    validation: dict[str, Any] = Field(default_factory=dict)
    generated_template: dict[str, Any] = Field(default_factory=dict)
    lifecycle_note: str


class AiResearchProposalRead(BaseModel):
    id: UUID | str
    pack_id: UUID | str
    artifact_id: UUID | str | None = None
    record_id: UUID | str | None = None
    source: str
    title: str
    description: str | None = None
    status: str
    pack_status: str
    review_url: str | None = None
    generation_mode: str
    output_kind: str | None = None
    provider: str | None = None
    model: str | None = None
    advisory_id: str | None = None
    validation: dict[str, Any] = Field(default_factory=dict)
    yaml_diff: str | None = None
    reasoning: str | None = None
    detection_strategy: str | None = None
    safety_notes: list[str] = Field(default_factory=list)
    created_at: datetime | None = None
    updated_at: datetime | None = None


class AiResearchLabRead(BaseModel):
    engagement_id: UUID
    cve_records: list[ThreatIntelRecordRead] = Field(default_factory=list)
    research_proposals: list[AiResearchProposalRead] = Field(default_factory=list)
    lifecycle_note: str
