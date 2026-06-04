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
    included_inventory: dict[str, Any] = Field(default_factory=dict)
    evidence_status: dict[str, Any] = Field(default_factory=dict)
    compliance_summary: dict[str, Any] = Field(default_factory=dict)
    assurance_summary: dict[str, Any] = Field(default_factory=dict)
    adaptive_change_summary: dict[str, Any] = Field(default_factory=dict)
    ai_draft_summary: dict[str, Any] = Field(default_factory=dict)
    run_narrative_summary: dict[str, Any] = Field(default_factory=dict)
    version_label: str
    content_sha256: str
    availability_status: str = "export_ready"
    availability_label: str = "Export ready"
    availability_reason: str = "Stored run data is available for export."
    preview_allowed: bool = True
    export_allowed: bool = True
    draft_allowed: bool = True
    lifecycle_summary: dict[str, Any] = Field(default_factory=dict)
    export_paths: dict[str, str] = Field(default_factory=dict)
    download_names: dict[str, str] = Field(default_factory=dict)


class RunReportDraftCreate(BaseModel):
    variant: str = Field(
        default="technical",
        pattern="^(summary|technical|compliance|executive|evidence|retest|soc2|iso27001|pci_dss|nis2|dora|nfir|assurance|attack_narrative)$",
    )
    sections: list[str] = Field(default_factory=list)


class RunReportDraftRead(BaseModel):
    source_run_id: UUID
    variant: str
    status: str
    available: bool
    provider: str
    generated_at: datetime
    sections: list[dict[str, Any]] = Field(default_factory=list)
    draft_markdown: str | None = None
    source_data_categories: list[str] = Field(default_factory=list)
    source_evidence_refs: list[str] = Field(default_factory=list)
    review_required: bool = True
    canonical_report_unchanged: bool = True
    boundary: str
    failure_reason: str | None = None
    structured_payload: dict[str, Any] = Field(default_factory=dict)
    draft_contract: dict[str, Any] = Field(default_factory=dict)
    variant_contract: dict[str, Any] = Field(default_factory=dict)
    tested_scope: dict[str, Any] = Field(default_factory=dict)
    management_decision: dict[str, Any] = Field(default_factory=dict)
    management_story: dict[str, Any] = Field(default_factory=dict)
    supported_findings: list[dict[str, Any]] = Field(default_factory=list)
    not_tested: list[dict[str, Any]] = Field(default_factory=list)
    not_verified: list[dict[str, Any]] = Field(default_factory=list)
    raw_proof_export_non_llm: bool = True
