from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from api.app.schemas.kill_chain import KillChainProgressRead
from api.app.schemas.packs import RunPackBindingRead


class RunProfileRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    run_class: str
    limits_json: dict[str, Any]


class RunCreate(BaseModel):
    profile_name: str = Field(default="passive-web-baseline")
    source_inventory_snapshot_id: UUID | None = None
    configuration_json: dict[str, Any] = Field(default_factory=dict)
    autonomous_mode: bool | None = None
    autonomous_intrusive_allowed: bool | None = None
    assessment_mode: str | None = None
    assessment_auto_advance_on_phase_complete: bool | None = None
    dispatch_after_create: bool = False


class AssessmentChainPhaseDecisionCreate(BaseModel):
    decision: Literal["approved", "rejected"] = "approved"


class AssessmentChainRead(BaseModel):
    id: UUID
    engagement_id: UUID
    assessment_mode: str
    status: str
    current_phase_index: int
    current_step_index: int
    current_phase_key: str | None = None
    current_run_id: UUID | None = None
    last_completed_run_id: UUID | None = None
    auto_advance_on_phase_complete: bool
    halt_requested: bool = False
    completed_phase_count: int = 0
    phase_count: int = 0
    phases: list[dict[str, Any]] = Field(default_factory=list)
    operator_state: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
    updated_at: datetime


class RunIntakeInterpretationCreate(BaseModel):
    question_id: str | None = None
    answer: str | None = None
    engagement_id: UUID | None = None
    configuration_json: dict[str, Any] = Field(default_factory=dict)


class RunIntakeInterpretationRead(BaseModel):
    status: str
    available: bool
    provider: str
    generated_at: str
    question_id: str
    warnings: list[str] = Field(default_factory=list)
    safe_inferences: list[dict[str, Any]] = Field(default_factory=list)
    follow_up_questions: list[dict[str, Any]] = Field(default_factory=list)
    methodology_suggestions: list[dict[str, Any]] = Field(default_factory=list)
    pack_suggestions: list[dict[str, Any]] = Field(default_factory=list)
    blocked_suggestions: list[dict[str, Any]] = Field(default_factory=list)
    boundary: dict[str, Any] = Field(default_factory=dict)
    operator_confirmation_required: bool = True
    deterministic_intake_preserved: bool = True
    scope_expansion_blocked: bool = True
    failure_reason: str | None = None
    provider_metadata: dict[str, Any] = Field(default_factory=dict)
    explicit_target_count: int | None = None


class ApprovalCreate(BaseModel):
    step_id: str = Field(default="run.launch")
    decision: Literal["approved", "rejected"]


class ApprovalRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    step_id: str
    approver_id: str
    decision: str
    created_at: datetime


class TaskRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    source_finding_id: UUID | None = None
    tool: str
    target_id: str
    status: str
    params_json: dict[str, Any]
    stale_recovery: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
    updated_at: datetime


class AgentProposalRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    run_id: UUID
    agent_reasoning_id: UUID
    proposed_tool: str
    proposed_target: str
    proposed_params_json: dict[str, Any]
    reasoning_text: str | None = None
    risk_tier: str
    priority: int
    confidence_score: float | None = None
    status: str
    approved_by: str | None = None
    approved_at: datetime | None = None
    metadata_json: dict[str, Any]
    created_at: datetime
    updated_at: datetime


class AgentReasoningRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    run_id: UUID
    task_id: UUID | None = None
    reasoning_type: str
    status: str
    context_snapshot_json: dict[str, Any]
    observations_json: list[dict[str, Any]]
    hypotheses_json: list[dict[str, Any]]
    proposals_json: list[dict[str, Any]]
    summary_text: str = ""
    thought_text: str = ""
    action_text: str = ""
    provider: str
    model: str | None = None
    llm_tokens_used: int | None = None
    confidence_score: float | None = None
    failure_reason: str | None = None
    metadata_json: dict[str, Any]
    proposals: list[AgentProposalRead] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime


class AgentProposalReviewCreate(BaseModel):
    decision: Literal["approved", "rejected"]
    note: str | None = None


class ToolLibraryProposalCreate(BaseModel):
    tool_id: str
    proposed_tool: str
    proposed_target: str | None = None
    proposed_params: dict[str, Any] = Field(default_factory=dict)
    reasoning_text: str | None = None
    risk_tier: Literal["passive", "active", "intrusive"] = "passive"


class AiRepairProposalCreate(BaseModel):
    note: str | None = None


class AiRepairActionCreate(BaseModel):
    action: Literal["accept_gap", "create_build_lane_fix", "retry_runner", "continue_remaining"]
    note: str | None = None


class AiRepairActionRead(BaseModel):
    run_id: UUID
    action: str
    status: str
    message: str
    proposal: AgentProposalRead
    available_actions: list[dict[str, Any]] = Field(default_factory=list)


class AiRepairProposalRead(BaseModel):
    run_id: UUID
    task_id: UUID
    reasoning: AgentReasoningRead
    proposal: AgentProposalRead
    boundary: dict[str, Any] = Field(default_factory=dict)


class RunCveIntelRefreshCreate(BaseModel):
    live_nvd_lookup: bool = False


class RunCveIntelActionRead(BaseModel):
    id: str
    label: str
    requires_operator_approval: bool | None = None
    requires_pack_lifecycle: bool | None = None
    starts_automatically: bool = False


class RunCveIntelRowRead(BaseModel):
    cve_id: str
    record_id: str | None = None
    title: str
    summary: str | None = None
    severity: str
    cvss_score: float | None = None
    kev: bool = False
    sources: list[str] = Field(default_factory=list)
    affected_product: dict[str, Any] = Field(default_factory=dict)
    affected_versions: list[str] = Field(default_factory=list)
    matched_terms: list[str] = Field(default_factory=list)
    test_status: str
    template: dict[str, Any] | None = None
    generated_template: dict[str, Any] | None = None
    actions: list[RunCveIntelActionRead] = Field(default_factory=list)
    fix_guidance: str
    references: list[str] = Field(default_factory=list)
    operator_boundary: dict[str, Any] = Field(default_factory=dict)


class RunCveIntelRead(BaseModel):
    run_id: UUID
    engagement_id: UUID
    status: str
    generated_at: datetime
    product_count: int = 0
    cve_count: int = 0
    products: list[dict[str, Any]] = Field(default_factory=list)
    rows: list[RunCveIntelRowRead] = Field(default_factory=list)
    failures: list[dict[str, Any]] = Field(default_factory=list)
    boundary: dict[str, Any] = Field(default_factory=dict)


class RunAiInsightsRead(BaseModel):
    run_id: UUID
    post_task_analysis_enabled: bool
    provider: str
    provider_status: dict[str, Any] = Field(default_factory=dict)
    reasoning_records: list[AgentReasoningRead] = Field(default_factory=list)
    proposals: list[AgentProposalRead] = Field(default_factory=list)
    review_boundary: dict[str, Any] = Field(default_factory=dict)
    operator_workbench: dict[str, Any] = Field(default_factory=dict)


class RunDriftRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    run_id: UUID
    previous_run_id: UUID
    new_finding_count: int
    resolved_finding_count: int
    exposure_delta: float
    computed_at: datetime


class FindingSummaryRead(BaseModel):
    finding_count: int
    findings_by_severity: dict[str, int]
    findings_by_status: dict[str, int]


class RunDispatchRead(BaseModel):
    run: RunRead
    dispatch_mode: str
    dispatched_task_ids: list[UUID]


class AssessmentPlanQueueCreate(BaseModel):
    approved_runners: list[str] = Field(default_factory=list)
    allow_wait_overrides: bool = False
    operator_note: str | None = Field(default=None, max_length=1000)


class AssessmentPlanWaveCompleteCreate(BaseModel):
    operator_note: str | None = Field(default=None, max_length=1000)


class AssessmentLoopAdvanceCreate(BaseModel):
    operator_note: str | None = Field(default=None, max_length=1000)


class AssessmentLoopGoalCreate(BaseModel):
    objective: str = Field(min_length=3, max_length=1000)
    operator_note: str | None = Field(default=None, max_length=1000)


class RunCredentialVaultCreate(BaseModel):
    secret_kind: Literal["api_key", "bearer_token", "password", "session"]
    value: str = Field(min_length=1)
    label: str | None = Field(default=None, max_length=255)
    source_task_id: UUID | None = None
    source_finding_id: UUID | None = None
    target: str | None = Field(default=None, max_length=255)
    username: str | None = Field(default=None, max_length=255)
    discovery_source: str = Field(default="ai_loop", max_length=100)


class RunRead(BaseModel):
    id: UUID
    engagement_id: UUID
    requested_by: str
    status: str
    autonomous_mode: bool = False
    autonomous_intrusive_allowed: bool = False
    source_inventory_snapshot_id: UUID | None = None
    started_at: datetime | None
    created_at: datetime
    updated_at: datetime
    profile: RunProfileRead
    approval_step_id: str = "run.launch"
    required_approvals: int
    granted_approvals: int
    pending_approvals: int
    approvals: list[ApprovalRead]
    tasks: list[TaskRead]
    findings: FindingSummaryRead
    configuration_json: dict[str, Any] = Field(default_factory=dict)
    pack_binding: RunPackBindingRead | None = None
    ai_mission_guidance: dict[str, Any] = Field(default_factory=dict)
    multi_agent_orchestration: dict[str, Any] = Field(default_factory=dict)
    assessment_chain: dict[str, Any] = Field(default_factory=dict)
    assessment_plan: dict[str, Any] = Field(default_factory=dict)
    kill_chain_progress: KillChainProgressRead | None = None
    drift_summary: RunDriftRead | None = None
    stale_recovery: dict[str, Any] = Field(default_factory=dict)


class AssessmentPlanQueueRead(BaseModel):
    run: RunRead
    assessment_plan: dict[str, Any] = Field(default_factory=dict)
    queued_task_ids: list[UUID] = Field(default_factory=list)
    blocked: list[dict[str, Any]] = Field(default_factory=list)


class AssessmentPlanWaveCompleteRead(BaseModel):
    run: RunRead
    assessment_plan: dict[str, Any] = Field(default_factory=dict)
    adaptive_execution_waves: dict[str, Any] = Field(default_factory=dict)
    proposal_ids: list[UUID] = Field(default_factory=list)
    reasoning_id: UUID | None = None


class AssessmentLoopRead(BaseModel):
    available: bool = True
    run_id: UUID
    run_mode: str = "ai_loop"
    loop_version: str
    status: str
    stop_reason: str | None = None
    iteration_count: int
    max_iterations: int
    stuck_threshold: int
    no_new_signal_iterations: int
    current_state: dict[str, Any] = Field(default_factory=dict)
    target_context: dict[str, Any] | None = None
    latest_next_action: dict[str, Any] | None = None
    active_tasks: list[dict[str, Any]] = Field(default_factory=list)
    assessment_plan_summary: dict[str, Any] = Field(default_factory=dict)
    goal_oriented_reasoning: dict[str, Any] = Field(default_factory=dict)
    rationale_ledger: list[dict[str, Any]] = Field(default_factory=list)
    iterations: list[dict[str, Any]] = Field(default_factory=list)
    dispatches_work_directly: bool = False
    manual_chain_alternative_preserved: bool = True
    fixed_phase_chains_replaced_globally: bool = False
    next_action: dict[str, Any] | None = None
    queued_task_id: UUID | None = None
    proposal_id: UUID | None = None
    reasoning_id: UUID | None = None
    context_document_id: UUID | None = None
    rationale_ledger_entry_id: UUID | None = None


class RunStaleRecoveryCreate(BaseModel):
    reason: str = Field(min_length=8, max_length=1000)
    task_outcome: Literal["cancelled", "failed"] = "cancelled"


class RunCveIntelQueueTestRead(BaseModel):
    run: RunRead
    task: TaskRead
    cve_intelligence: RunCveIntelRead
