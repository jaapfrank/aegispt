from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class ThreatIntelRecordCreate(BaseModel):
    source: str
    advisory_id: str
    title: str
    summary: str | None = None
    affected_products: list[str] = Field(default_factory=list)
    affected_versions: list[str] = Field(default_factory=list)
    product_match_hints: list[str] = Field(default_factory=list)
    architecture_hints: list[str] = Field(default_factory=list)
    attack_surface_type: str | None = None
    suggested_test_patterns: list[str] = Field(default_factory=list)
    confidence: float = 0.5
    severity: str | None = None
    references: list[str] = Field(default_factory=list)
    published_at: datetime | None = None
    updated_at: datetime | None = None
    normalization_status: str = "normalized"


class ThreatIntelIngestCreate(BaseModel):
    records: list[ThreatIntelRecordCreate] = Field(default_factory=list)


class ThreatIntelRecordRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    source: str
    advisory_id: str
    title: str
    summary: str | None
    affected_products_json: list[str]
    affected_versions_json: list[str]
    product_match_hints_json: list[str]
    architecture_hints_json: list[str]
    attack_surface_type: str | None
    suggested_test_patterns_json: list[str]
    confidence_score: float
    severity: str | None
    references_json: list[str]
    published_at: datetime | None
    updated_at: datetime | None
    normalization_status: str
    created_at: datetime

