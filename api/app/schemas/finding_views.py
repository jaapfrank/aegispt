from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field

from api.app.schemas.findings import FindingRead


class FindingRelatedArtifactRead(BaseModel):
    artifact_id: UUID
    kind: str
    uri: str
    download_path: str
    name: str
    sha256: str
    hash_status: str = "unknown"
    timestamp_status: str = "not-available"
    timestamp_response_uri: str | None = None
    redaction_state: str
    created_at: datetime


class FindingRelatedExecutionRead(BaseModel):
    execution_id: UUID
    task_id: UUID
    tool: str
    target_id: str
    task_status: str
    exit_code: int
    tool_version: str
    stdout_excerpt: str | None = None
    stderr_excerpt: str | None = None
    created_at: datetime
    artifacts: list[FindingRelatedArtifactRead] = Field(default_factory=list)


class FindingAutoFixRead(BaseModel):
    available: bool = False
    enabled: bool = False
    advisory_only: bool = True
    patch_language: str | None = None
    patch_before: str | None = None
    patch_after: str | None = None
    patch_explanation: str | None = None
    verification_command: str | None = None
    confidence: str | None = None
    provider: str | None = None
    model: str | None = None
    generated_at: str | None = None
    auto_apply_allowed: bool = False
    ai_generated: bool = False
    ai_fix_suggestion: str | None = None
    disclaimer: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    detail: str | None = None


class FindingRepositoryPullRequestRead(BaseModel):
    provider: str
    branch_name: str
    pull_request_url: str
    pull_request_id: str
    auto_merge_enabled: bool = False
    created_by: str | None = None


class FindingRepositoryContextRead(BaseModel):
    available: bool = False
    provider: str | None = None
    repository_url: str | None = None
    repository_path: str | None = None
    repository_branch: str | None = None
    line_start: int | None = None
    line_end: int | None = None
    highlighted_line: int | None = None
    snippet_language: str | None = None
    snippet_text: str | None = None
    external_url: str | None = None
    pull_request_supported: bool = False
    detail: str | None = None
    latest_pull_request: FindingRepositoryPullRequestRead | None = None


class FindingValidationAttemptRead(BaseModel):
    id: UUID
    status: str
    validation_profile_name: str | None = None
    validator_tool: str | None = None
    validator_target_id: str | None = None
    run_id: UUID | None = None
    task_id: UUID | None = None
    tool_execution_id: UUID | None = None
    note: str | None = None
    evidence_ref: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
    updated_at: datetime


class FindingValidationSummaryRead(BaseModel):
    status: str = "unvalidated"
    label: str = "Pending review"
    tone: str = "neutral"
    note: str | None = None
    latest_attempt: FindingValidationAttemptRead | None = None


class FindingTheaterRead(BaseModel):
    finding: FindingRead
    severity_rank: int
    confidence_label: str
    exploitability: str | None = None
    business_impact: str
    technical_details: str
    evidence_summary: str
    provenance: dict[str, Any] = Field(default_factory=dict)
    methodology: dict[str, Any] = Field(default_factory=dict)
    remediation: dict[str, Any] = Field(default_factory=dict)
    ai_enrichment: dict[str, Any] = Field(default_factory=dict)
    autofix: FindingAutoFixRead = Field(default_factory=FindingAutoFixRead)
    repository_context: FindingRepositoryContextRead = Field(default_factory=FindingRepositoryContextRead)
    threat_context: dict[str, Any] = Field(default_factory=dict)
    detection_engineering: dict[str, Any] = Field(default_factory=dict)
    vulnerability_chains: dict[str, Any] = Field(default_factory=dict)
    threat_intel_badges: dict[str, Any] = Field(default_factory=dict)
    validation: FindingValidationSummaryRead = Field(default_factory=FindingValidationSummaryRead)
    evidence_integrity: dict[str, Any] = Field(default_factory=dict)
    verification_status: str
    next_steps: list[str] = Field(default_factory=list)
    risk_snapshot: dict[str, Any] = Field(default_factory=dict)


class FindingEvidenceReplayRead(BaseModel):
    finding: FindingRead
    evidence_ref: str
    methodology_references: dict[str, Any] = Field(default_factory=dict)
    pack_provenance: dict[str, Any] = Field(default_factory=dict)
    inventory_source: dict[str, Any] = Field(default_factory=dict)
    relevance_source: dict[str, Any] = Field(default_factory=dict)
    validation_history: list[FindingValidationAttemptRead] = Field(default_factory=list)
    related_executions: list[FindingRelatedExecutionRead] = Field(default_factory=list)


class RemediationPortfolioPolicyRead(BaseModel):
    sla_days: int
    due_soon_days: int
    basis: str
    contractual_enforcement: bool = False
    note: str


class RemediationPortfolioSummaryRead(BaseModel):
    total_items: int
    by_remediation_state: dict[str, int] = Field(default_factory=dict)
    by_sla_status: dict[str, int] = Field(default_factory=dict)
    by_owner: dict[str, int] = Field(default_factory=dict)
    eligible_for_retest: int
    blocked: int
    verified: int
    overdue: int
    due_soon: int


class RemediationRetestReferenceRead(BaseModel):
    run_id: UUID
    status: str
    profile_name: str | None = None
    verification_state: str
    requested_at: datetime | None = None
    updated_at: datetime | None = None
    task_counts: dict[str, int] = Field(default_factory=dict)


class RemediationPortfolioItemRead(BaseModel):
    finding: FindingRead
    run_id: UUID
    run_status: str
    profile_name: str | None = None
    remediation_state: str
    remediation_owner: str | None = None
    remediation_notes: str | None = None
    remediation_updated_at: datetime | None = None
    sla_started_at: datetime | None = None
    sla_due_at: datetime | None = None
    sla_status: str
    sla_detail: str
    verification_state: str
    linked_retest_count: int
    latest_retest: RemediationRetestReferenceRead | None = None
    eligible_for_retest: bool
    retest_planning_reason: str
    approval_required_count: int = 0


class RemediationRetestPlanGroupRead(BaseModel):
    source_run_id: UUID
    profile_name: str | None = None
    approval_required_count: int
    finding_ids: list[UUID] = Field(default_factory=list)
    targets: list[str] = Field(default_factory=list)
    next_operator_action: str


class RemediationRetestPlanRead(BaseModel):
    engagement_id: UUID
    generated_at: datetime
    plan_mode: str = "planning_only"
    explicit_operator_action_required: bool = True
    automatic_dispatch_performed: bool = False
    created_run_ids: list[UUID] = Field(default_factory=list)
    approval_boundary: str
    groups: list[RemediationRetestPlanGroupRead] = Field(default_factory=list)
    excluded_items: list[dict[str, Any]] = Field(default_factory=list)


class RemediationPortfolioRead(BaseModel):
    engagement_id: UUID
    generated_at: datetime
    policy: RemediationPortfolioPolicyRead
    summary: RemediationPortfolioSummaryRead
    items: list[RemediationPortfolioItemRead] = Field(default_factory=list)
    retest_plan: RemediationRetestPlanRead


class RemediationRetestPlanCreate(BaseModel):
    finding_ids: list[UUID] | None = None
    owner: str | None = None
    remediation_state: str | None = None
    sla_status: str | None = None
    eligible_for_retest: bool | None = None
    sla_days: int = Field(default=30, ge=1, le=3650)
    due_soon_days: int = Field(default=7, ge=0, le=365)
    notes: str | None = None
