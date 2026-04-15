from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class FindingRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    run_id: UUID | None
    title: str
    severity: str
    target_id: str
    evidence_ref: str
    status: str
    summary: str | None
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
