from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict


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


class FindingUpdate(BaseModel):
    status: Literal["open", "triaged", "in_progress", "resolved", "accepted_risk", "false_positive"]
    reason: str | None = None
    false_positive_reason: str | None = None
