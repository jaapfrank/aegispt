from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field


class RunReportCatalogItemRead(BaseModel):
    variant: str
    title: str
    description: str
    source_run_id: UUID
    generated_at: datetime
    available_formats: list[str] = Field(default_factory=list)
    methodology_references: list[str] = Field(default_factory=list)
    source_scope_profile: dict[str, Any] = Field(default_factory=dict)
    included_findings: dict[str, Any] = Field(default_factory=dict)
    evidence_status: dict[str, Any] = Field(default_factory=dict)
    version_label: str
    content_sha256: str
    export_paths: dict[str, str] = Field(default_factory=dict)
