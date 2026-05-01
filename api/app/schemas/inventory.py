from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class InventorySourcePayload(BaseModel):
    tool: str
    kind: str
    data: dict[str, Any] = Field(default_factory=dict)


class InventoryHostRecord(BaseModel):
    host: str
    source: str
    confidence: float = 0.5
    notes: list[str] = Field(default_factory=list)


class InventoryServiceRecord(BaseModel):
    host: str
    port: int
    protocol: str = "tcp"
    service: str
    product: str | None = None
    version: str | None = None
    source: str
    confidence: float = 0.5


class InventoryEndpointRecord(BaseModel):
    url: str
    methods: list[str] = Field(default_factory=list)
    status_code: int | None = None
    title: str | None = None
    source: str
    confidence: float = 0.5


class InventoryTechnologyRecord(BaseModel):
    name: str
    vendor: str | None = None
    version: str | None = None
    source: str
    confidence: float = 0.5


class InventoryAuthRecord(BaseModel):
    type: str
    location: str | None = None
    source: str
    confidence: float = 0.5


class InventoryApiRecord(BaseModel):
    type: str
    base_url: str | None = None
    source: str
    confidence: float = 0.5


class InventoryTlsSummary(BaseModel):
    protocols: list[str] = Field(default_factory=list)
    issues: list[str] = Field(default_factory=list)
    certificate_subject: str | None = None
    source: str | None = None
    confidence: float = 0.5


class InventoryFingerprintRecord(BaseModel):
    vendor: str | None = None
    product: str
    version: str | None = None
    source: str
    confidence: float = 0.5


class NormalizedInventoryRead(BaseModel):
    hosts: list[InventoryHostRecord] = Field(default_factory=list)
    services: list[InventoryServiceRecord] = Field(default_factory=list)
    http_endpoints: list[InventoryEndpointRecord] = Field(default_factory=list)
    technologies: list[InventoryTechnologyRecord] = Field(default_factory=list)
    auth_mechanisms: list[InventoryAuthRecord] = Field(default_factory=list)
    api_types: list[InventoryApiRecord] = Field(default_factory=list)
    tls_posture: InventoryTlsSummary = Field(default_factory=InventoryTlsSummary)
    vendor_product_fingerprints: list[InventoryFingerprintRecord] = Field(default_factory=list)
    environment_notes: list[str] = Field(default_factory=list)
    assumptions: list[str] = Field(default_factory=list)
    confidence_score: float = 0.0


class InventoryRunCreate(BaseModel):
    engagement_id: UUID
    source_tools: list[str] = Field(default_factory=list)
    observations: list[InventorySourcePayload] = Field(default_factory=list)
    environment_notes: list[str] = Field(default_factory=list)
    assumptions: list[str] = Field(default_factory=list)


class InventorySummaryRead(BaseModel):
    host_count: int
    service_count: int
    endpoint_count: int
    technology_count: int
    auth_mechanism_count: int
    identity_subject_count: int = 0
    identity_group_count: int = 0
    privileged_membership_count: int = 0
    cloud_account_count: int = 0
    cloud_region_count: int = 0
    cloud_resource_count: int = 0
    cloud_security_group_count: int = 0
    cloud_iam_principal_count: int = 0
    cloud_iam_policy_count: int = 0
    cloud_collection_error_count: int = 0
    kubernetes_cluster_count: int = 0
    kubernetes_workload_count: int = 0
    api_type_count: int
    tls_issue_count: int
    detected_products: list[str]
    detected_vendors: list[str]
    confidence_score: float


class InventorySnapshotRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    engagement_id: UUID
    requested_by: str
    status: str
    source_tools_json: list[str]
    raw_inputs_json: dict[str, Any]
    normalized_inventory_json: dict[str, Any]
    summary_json: dict[str, Any]
    environment_notes_json: list[str]
    assumptions_json: list[str]
    confidence_score: float
    created_at: datetime
