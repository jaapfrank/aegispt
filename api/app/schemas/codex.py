from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field

from api.app.schemas.packs import (
    CapabilityPackApprovalRead,
    CapabilityPackArtifactRead,
    CapabilityPackDeploymentRead,
    CapabilityPackRead,
    CapabilityPackValidationRead,
)


class CodexBuildArtifactRead(BaseModel):
    artifact_id: UUID
    artifact_type: str
    logical_name: str
    status: str
    checksum_sha256: str
    methodology_tags: list[str] = Field(default_factory=list)
    provenance_json: dict[str, Any] = Field(default_factory=dict)
    has_content_text: bool
    has_content_json: bool


class CodexValidationHookRead(BaseModel):
    name: str
    method: str
    path: str
    description: str
    blocking: bool = False


class CodexRepoConventionRead(BaseModel):
    suggested_branch_name: str
    workspace_root: str
    artifact_directory: str
    notes_file: str
    change_summary_file: str
    review_bundle_file: str
    export_command: str
    validation_command: str
    rules: list[str] = Field(default_factory=list)


class CodexOperatorVisibilityRead(BaseModel):
    required_badges: list[str] = Field(default_factory=list)
    required_fields: list[str] = Field(default_factory=list)
    review_sections: list[str] = Field(default_factory=list)
    finding_provenance_fields: list[str] = Field(default_factory=list)


class CodexBuildContextRead(BaseModel):
    pack_id: UUID
    engagement_id: UUID
    pack_name: str
    pack_version: str
    pack_status: str
    generation_mode: str
    relevance_decision_id: UUID | None = None
    source_inventory_snapshot_id: UUID | None = None
    source_threat_intel_refs: list[str] = Field(default_factory=list)
    methodology_tags: list[str] = Field(default_factory=list)
    generation_reason: str | None = None
    active_runtime_mutation_allowed: bool = False
    latest_validation_status: str | None = None
    runtime_guardrails: list[str] = Field(default_factory=list)
    repo_conventions: CodexRepoConventionRead
    validation_hooks: list[CodexValidationHookRead] = Field(default_factory=list)
    operator_visibility: CodexOperatorVisibilityRead
    artifacts: list[CodexBuildArtifactRead] = Field(default_factory=list)


class CodexReviewBundleRead(BaseModel):
    context: CodexBuildContextRead
    pack: CapabilityPackRead
    artifacts: list[CapabilityPackArtifactRead] = Field(default_factory=list)
    validations: list[CapabilityPackValidationRead] = Field(default_factory=list)
    approvals: list[CapabilityPackApprovalRead] = Field(default_factory=list)
    deployments: list[CapabilityPackDeploymentRead] = Field(default_factory=list)


class CodexTaskSourceContext(BaseModel):
    pack_id: UUID | None = None
    pack_version: str | None = None
    inventory_snapshot_id: UUID | None = None
    relevance_decision_id: UUID | None = None
    threat_intel_refs: list[str] = Field(default_factory=list)


class CodexTaskCreate(BaseModel):
    task_type: str
    scope: str
    inputs: dict[str, Any] = Field(default_factory=dict)
    constraints: dict[str, Any] = Field(default_factory=dict)
    expected_output: dict[str, Any] = Field(default_factory=dict)
    generation_reason: str
    source_context: CodexTaskSourceContext = Field(default_factory=CodexTaskSourceContext)


class CodexTaskRunCreate(BaseModel):
    base_url: str | None = None
    workspace_root: str | None = None
    dry_run: bool = True


class CodexTaskRead(BaseModel):
    id: str
    task_type: str
    scope: str
    inputs: dict[str, Any] = Field(default_factory=dict)
    constraints: dict[str, Any] = Field(default_factory=dict)
    expected_output: dict[str, Any] = Field(default_factory=dict)
    generated_by: str
    requested_by: str
    generation_reason: str
    source_context: CodexTaskSourceContext = Field(default_factory=CodexTaskSourceContext)
    validation_status: str
    approval_status: str
    status: str
    created_at: datetime
    updated_at: datetime
    task_file: str


class CodexTaskResultRead(BaseModel):
    task_id: str
    status: str
    summary: str
    dry_run: bool = True
    prepared_commands: list[str] = Field(default_factory=list)
    output_files: list[str] = Field(default_factory=list)
    guardrails: list[str] = Field(default_factory=list)
    validation_hooks: list[CodexValidationHookRead] = Field(default_factory=list)
    result_file: str
    created_at: datetime
