from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

CustomVulnerabilitySeverity = Literal["critical", "high", "medium", "low"]
CustomVulnerabilityStatus = Literal["draft", "active", "deprecated"]


class CustomVulnerabilityBase(BaseModel):
    custom_id: str | None = None
    title: str
    description: str
    severity: CustomVulnerabilitySeverity = "medium"
    cvss_score: float | None = Field(default=None, ge=0, le=10)
    affected_products: list[str] = Field(default_factory=list)
    cwe_ids: list[str] = Field(default_factory=list)
    discovery_date: datetime | None = None
    reporter: str | None = None
    status: CustomVulnerabilityStatus = "draft"
    linked_nuclei_template_ref: str | None = None
    linked_threat_intel_record_id: UUID | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class CustomVulnerabilityCreate(CustomVulnerabilityBase):
    pass


class CustomVulnerabilityPatch(BaseModel):
    custom_id: str | None = None
    title: str | None = None
    description: str | None = None
    severity: CustomVulnerabilitySeverity | None = None
    cvss_score: float | None = Field(default=None, ge=0, le=10)
    affected_products: list[str] | None = None
    cwe_ids: list[str] | None = None
    discovery_date: datetime | None = None
    reporter: str | None = None
    status: CustomVulnerabilityStatus | None = None
    linked_nuclei_template_ref: str | None = None
    linked_threat_intel_record_id: UUID | None = None
    metadata: dict[str, Any] | None = None


class CustomVulnerabilityImportCreate(BaseModel):
    format: Literal["nvd_json", "csaf", "plain_text", "aegispt_export"]
    payload: dict[str, Any] | list[dict[str, Any]] | str
    use_ai: bool = False
    engagement_id: UUID | None = None
    default_status: CustomVulnerabilityStatus = "draft"


class CustomVulnerabilityEngagementToggleCreate(BaseModel):
    enabled: bool = True


class CustomVulnerabilityTestCoverageRead(BaseModel):
    status: str
    message: str
    linked_nuclei_template_ref: str | None = None
    artifact_id: UUID | None = None
    pack_id: UUID | None = None
    pack_status: str | None = None
    validation_status: str | None = None
    deployed: bool = False
    deployment_id: UUID | None = None
    runtime_binding_required: bool = True


class CustomVulnerabilityEngagementStateRead(BaseModel):
    engagement_id: UUID
    enabled: bool
    enabled_by: str | None = None
    enabled_at: datetime | None = None


class CustomVulnerabilityRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    tenant_id: str
    custom_id: str
    title: str
    description: str
    severity: str
    cvss_score: float | None
    affected_products_json: list[str]
    cwe_ids_json: list[str]
    discovery_date: datetime | None
    reporter: str | None
    status: str
    linked_nuclei_template_ref: str | None
    linked_threat_intel_record_id: UUID | None
    metadata_json: dict[str, Any]
    deleted_at: datetime | None
    test_coverage: CustomVulnerabilityTestCoverageRead
    engagement_state: CustomVulnerabilityEngagementStateRead | None = None
    created_at: datetime
    updated_at: datetime


class CustomVulnerabilityListRead(BaseModel):
    items: list[CustomVulnerabilityRead]
    total: int
    filters: dict[str, Any] = Field(default_factory=dict)


class CustomVulnerabilityImportRead(BaseModel):
    imported_count: int
    updated_count: int
    skipped_count: int = 0
    ai_assistance: dict[str, Any] = Field(default_factory=dict)
    items: list[CustomVulnerabilityRead] = Field(default_factory=list)


class CustomVulnerabilityExportRead(BaseModel):
    exported_at: datetime
    tenant_id: str
    format: str = "aegispt_custom_vulnerabilities.v1"
    items: list[dict[str, Any]]


class CustomVulnerabilityScanOptionRead(BaseModel):
    id: UUID
    custom_id: str
    title: str
    severity: str
    affected_products: list[str] = Field(default_factory=list)
    enabled: bool
    has_linked_template: bool
    test_coverage: CustomVulnerabilityTestCoverageRead
    profile_option: dict[str, Any] = Field(default_factory=dict)
