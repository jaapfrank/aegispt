from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class RelevanceAnalyzeCreate(BaseModel):
    engagement_id: UUID
    inventory_snapshot_id: UUID
    threat_intel_ids: list[UUID] = Field(default_factory=list)
    include_prior_findings: bool = True


class ProposedCapabilityRead(BaseModel):
    capability_type: str
    tool: str
    title: str
    rationale: str
    attack_surface_type: str | None = None
    methodology_tags: list[str] = Field(default_factory=list)
    ptes_phase: str | None = None
    nist_phase: str | None = None
    wstg_id: str | None = None
    wstg_version: str | None = None
    asvs_reference: str | None = None
    control_family: str | None = None
    confidence: float = 0.0
    evidence_basis: list[str] = Field(default_factory=list)


class RelevanceRecommendationsRead(BaseModel):
    relevant_advisories: list[dict[str, Any]] = Field(default_factory=list)
    informational_advisories: list[dict[str, Any]] = Field(default_factory=list)
    suppressed_advisories: list[dict[str, Any]] = Field(default_factory=list)
    proposed_capabilities: list[ProposedCapabilityRead] = Field(default_factory=list)
    proposed_templates: list[dict[str, Any]] = Field(default_factory=list)
    proposed_playwright_flows: list[dict[str, Any]] = Field(default_factory=list)
    proposed_semgrep_rules: list[dict[str, Any]] = Field(default_factory=list)
    proposed_scanner_profiles: list[dict[str, Any]] = Field(default_factory=list)
    proposed_methodology_tags: list[str] = Field(default_factory=list)
    justification: str | None = None
    evidence_basis: list[dict[str, Any]] = Field(default_factory=list)
    confidence: float = 0.0


class RelevanceDecisionRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    engagement_id: UUID
    inventory_snapshot_id: UUID
    requested_by: str
    status: str
    threat_intel_refs_json: list[str]
    prior_finding_refs_json: list[str]
    methodology_tags: list[str]
    recommendations_json: dict[str, Any]
    justification_text: str | None
    evidence_basis_json: list[dict[str, Any]]
    confidence_score: float
    created_at: datetime

