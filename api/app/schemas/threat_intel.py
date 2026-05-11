from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
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


class ThreatIntelFeedRecordCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    cve_id: str | None = None
    cveID: str | None = None
    id: str | None = None
    advisory_id: str | None = None
    technique_id: str | None = None
    name: str | None = None
    title: str | None = None
    vulnerabilityName: str | None = None
    description: str | None = None
    summary: str | None = None
    vendorProject: str | None = None
    vendor: str | None = None
    product: str | None = None
    affected_products: list[str] = Field(default_factory=list)
    cvss_score: float | None = Field(default=None, ge=0, le=10)
    cvss_severity: str | None = None
    severity: str | None = None
    tactic: str | None = None
    tactics: list[str] = Field(default_factory=list)
    platforms: list[str] = Field(default_factory=list)
    cwe_ids: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    notes: str | None = None
    dateAdded: datetime | None = None
    dueDate: datetime | None = None
    published_at: datetime | None = None
    updated_at: datetime | None = None
    requiredAction: str | None = None
    knownRansomwareCampaignUse: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class ThreatIntelFeedImportCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    feed_type: Literal["cisa_kev", "mitre_attack", "cve_cvss"]
    feed_name: str
    feed_cached_at: datetime
    stale_after_days: int = Field(default=30, ge=1, le=3650)
    records: list[ThreatIntelFeedRecordCreate] = Field(default_factory=list)


class ThreatIntelFeedImportRead(BaseModel):
    imported_count: int
    updated_count: int
    feed_type: str
    feed_name: str
    feed_cached_at: datetime
    stale_after_days: int
    external_lookup_performed: bool = False
    records: list["ThreatIntelRecordRead"] = Field(default_factory=list)


class CveProductWatchlistCreate(BaseModel):
    query: str | None = None
    vendor: str | None = None
    product: str | None = None


class CveProductWatchlistRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    tenant_id: str
    vendor: str | None
    product: str | None
    query: str
    normalized_query: str
    status: str
    source: str
    source_inventory_snapshot_id: UUID | None
    last_seen_at: datetime | None
    approved_at: datetime | None
    approved_by: str | None
    metadata_json: dict[str, Any]
    created_at: datetime
    updated_at: datetime


class CveInventorySuggestionCreate(BaseModel):
    inventory_snapshot_id: UUID


class CveFeedSyncRunCreate(BaseModel):
    sources: list[str] = Field(default_factory=list)


class CveFeedSourceStatusRead(BaseModel):
    source: str
    label: str
    status: str
    started_at: datetime | None = None
    completed_at: datetime | None = None
    imported_count: int = 0
    updated_count: int = 0
    skipped_count: int = 0
    error: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class CveFeedSyncStatusRead(BaseModel):
    tenant_id: str
    sources: list[CveFeedSourceStatusRead]
    watchlist: dict[str, Any]
    policy: dict[str, Any]


class CveFeedSyncRunRead(BaseModel):
    tenant_id: str
    status: str
    sources: list[CveFeedSourceStatusRead]
    imported_count: int = 0
    updated_count: int = 0
    skipped_count: int = 0
    policy: dict[str, Any]


class CveTemplateGenerationCreate(BaseModel):
    engagement_id: UUID


class CveTemplateGenerationRead(BaseModel):
    record_id: UUID
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


class ZeroDayScanNowCreate(BaseModel):
    target: str | None = None


class ZeroDayRapidResponseRead(BaseModel):
    generated_at: datetime
    status: str
    alert_count: int = 0
    exposed_asset_count: int = 0
    alerts: list[dict[str, Any]] = Field(default_factory=list)
    boundary: dict[str, Any] = Field(default_factory=dict)


class ZeroDayScanNowRead(BaseModel):
    accepted: bool
    run_id: UUID
    run_status: str
    profile_name: str
    required_approvals: int
    granted_approvals: int = 0
    target: str
    record_id: UUID
    advisory_id: str
    operator_approval_required: bool = True
    automatic_approval_created: bool = False
    automatic_tests_started: bool = False
    scope_enforced: bool = True
    detail: str


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
    updated_at: datetime | None = Field(validation_alias="advisory_updated_at")
    normalization_status: str
    metadata_json: dict[str, Any]
    created_at: datetime
