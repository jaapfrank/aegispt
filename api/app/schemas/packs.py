from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class CapabilityPackGenerateCreate(BaseModel):
    engagement_id: UUID
    relevance_decision_id: UUID
    name: str | None = None
    description: str | None = None
    generation_mode: str = "codex-supervised"
    parent_pack_id: UUID | None = None


class CapabilityPackArtifactRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    pack_id: UUID
    artifact_type: str
    logical_name: str
    status: str
    checksum_sha256: str
    methodology_tags: list[str]
    content_text: str | None
    content_json: dict[str, Any] | None
    provenance_json: dict[str, Any]
    created_at: datetime


class CapabilityPackValidationRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    pack_id: UUID
    validator: str
    executed_by: str
    status: str
    summary: str | None
    artifact_results_json: list[dict[str, Any]]
    validation_artifacts_json: list[dict[str, Any]]
    blocking_issues_json: list[str]
    created_at: datetime


class CapabilityPackApprovalRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    pack_id: UUID
    approval_step: str
    approver_id: str
    decision: str
    notes: str | None
    created_at: datetime


class CapabilityPackDeploymentCreate(BaseModel):
    engagement_id: UUID
    deployment_target: str = "engagement-runtime"
    run_profile_name: str | None = None
    notes: str | None = None


class CapabilityPackRollbackCreate(BaseModel):
    engagement_id: UUID
    run_profile_name: str | None = None
    notes: str | None = None


class CapabilityPackDeploymentRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    pack_id: UUID
    engagement_id: UUID
    deployed_by: str
    deployment_target: str
    run_profile_name: str | None
    status: str
    rollback_from_pack_id: UUID | None
    notes: str | None
    runtime_binding_json: dict[str, Any]
    created_at: datetime


class CapabilityPackRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    engagement_id: UUID
    relevance_decision_id: UUID | None
    source_inventory_snapshot_id: UUID | None
    parent_pack_id: UUID | None
    name: str
    version: str
    status: str
    generated_by: str
    generation_mode: str
    description: str | None
    source_threat_intel_refs_json: list[str]
    methodology_tags: list[str]
    manifest_json: dict[str, Any]
    provenance_json: dict[str, Any]
    created_at: datetime


class RunPackBindingRead(BaseModel):
    pack_id: UUID
    pack_version: str | None
    deployment_id: UUID | None
    deployment_status: str | None
    deployment_target: str | None
    run_profile_name: str | None
    methodology_tags: list[str] = Field(default_factory=list)
    source_inventory_snapshot_id: UUID | None = None
    relevance_decision_id: UUID | None = None
    manifest_json: dict[str, Any] = Field(default_factory=dict)


class RunPackBindCreate(BaseModel):
    pack_id: UUID

