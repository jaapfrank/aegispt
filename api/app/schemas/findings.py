from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

from api.app.services.finding_quality import finding_quality_view


class FindingRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    run_id: UUID | None
    source_pack_id: UUID | None
    source_pack_artifact_id: UUID | None
    source_inventory_snapshot_id: UUID | None
    source_relevance_decision_id: UUID | None
    source_pack_version: str | None
    finding_origin: str
    title: str
    severity: str
    target_id: str
    evidence_ref: str
    status: str
    remediation_due_date: datetime | None = None
    sla_breached: bool = False
    false_positive_reason: str | None = None
    false_positive_confirmed_by: str | None = None
    cvss_score: float | None = None
    cvss_vector: str | None = None
    cvss_source: str | None = None
    owasp_framework: str | None = None
    owasp_category: str | None = None
    owasp_reference: str | None = None
    owasp_mapping: dict[str, Any] = Field(default_factory=dict)
    proof_reference: dict[str, Any] = Field(default_factory=dict)
    validation_status: str = "unvalidated"
    summary: str | None
    replay_recipe_json: dict | None = None
    methodology_tags: list[str]
    ptes_phase: str | None
    nist_phase: str | None
    wstg_id: str | None
    wstg_version: str | None
    asvs_reference: str | None
    control_family: str | None
    created_at: datetime

    @model_validator(mode="after")
    def add_finding_quality_defaults(self) -> "FindingRead":
        quality = finding_quality_view(self)
        cvss = quality["cvss"]
        if self.cvss_score is None:
            self.cvss_score = cvss["score"]
        if self.cvss_vector is None:
            self.cvss_vector = cvss.get("vector")
        self.cvss_source = self.cvss_source or cvss.get("source")

        owasp = quality["owasp"]
        self.owasp_framework = self.owasp_framework or owasp.get("framework")
        self.owasp_category = self.owasp_category or owasp.get("category")
        self.owasp_reference = self.owasp_reference or owasp.get("reference")
        self.owasp_mapping = self.owasp_mapping or {
            key: owasp.get(key)
            for key in ("framework", "category", "reference", "source")
            if owasp.get(key) is not None
        }
        self.proof_reference = self.proof_reference or quality["proof_reference"]
        return self


class FindingUpdate(BaseModel):
    status: Literal["open", "triaged", "in_progress", "resolved", "accepted_risk", "false_positive"]
    reason: str | None = None
    false_positive_reason: str | None = None
