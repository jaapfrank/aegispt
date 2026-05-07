export type UUID = string;
export type IsoDateTime = string;
export type JsonMap = Record<string, unknown>;

export interface Engagement {
  id: UUID;
  name: string;
  client: string | null;
  tenant_id: string | null;
  roe_ref: string | null;
  authorization_confirmed_by: string | null;
  authorization_confirmed_at: IsoDateTime | null;
  status: string;
  retention_days: number;
  starts_at: IsoDateTime | null;
  ends_at: IsoDateTime | null;
}

export interface RunProfile {
  id: UUID;
  name: string;
  run_class: string;
  limits_json: JsonMap;
}

export interface Approval {
  id: UUID;
  step_id: string;
  approver_id: string;
  decision: string;
  created_at: IsoDateTime;
}

export interface Task {
  id: UUID;
  source_finding_id: UUID | null;
  tool: string;
  target_id: string;
  status: string;
  params_json: JsonMap;
  stale_recovery: JsonMap;
  created_at: IsoDateTime;
  updated_at: IsoDateTime;
}

export interface TaskExecution {
  id: UUID;
  runner_digest: string;
  tool_version: string;
  exit_code: number | null;
  stdout_text: string | null;
  stderr_text: string | null;
  created_at: IsoDateTime;
  artifacts: JsonMap[];
}

export interface TaskStdoutLine {
  sequence?: number;
  text?: string;
}

export interface TaskStdoutSnapshot {
  task_id?: UUID;
  status?: string;
  source?: string;
  reason?: string;
  task_status?: string;
  stream_terminal?: boolean;
  updated_at?: IsoDateTime;
  lines?: TaskStdoutLine[];
}

export interface TaskDetail extends Task {
  run_id: UUID | null;
  executions: TaskExecution[];
  stdout_snapshot: TaskStdoutSnapshot;
}

export interface FindingSummary {
  finding_count: number;
  findings_by_severity: Record<string, number>;
  findings_by_status: Record<string, number>;
}

export interface Finding {
  id: UUID;
  run_id: UUID | null;
  source_pack_id: UUID | null;
  source_pack_artifact_id: UUID | null;
  source_inventory_snapshot_id: UUID | null;
  source_relevance_decision_id: UUID | null;
  source_pack_version: string | null;
  finding_origin: string;
  title: string;
  severity: string;
  target_id: string;
  evidence_ref: string;
  status: string;
  remediation_due_date: IsoDateTime | null;
  sla_breached: boolean;
  false_positive_reason: string | null;
  false_positive_confirmed_by: string | null;
  cvss_score: number | null;
  cvss_vector: string | null;
  cvss_source: string | null;
  owasp_framework: string | null;
  owasp_category: string | null;
  owasp_reference: string | null;
  owasp_mapping: JsonMap;
  proof_reference: JsonMap;
  validation_status: string;
  summary: string | null;
  replay_recipe_json: JsonMap | null;
  methodology_tags: string[];
  ptes_phase: string | null;
  nist_phase: string | null;
  wstg_id: string | null;
  wstg_version: string | null;
  asvs_reference: string | null;
  control_family: string | null;
  created_at: IsoDateTime;
}

export interface InventorySnapshot {
  id: UUID;
  engagement_id: UUID;
  requested_by: string;
  status: string;
  source_tools_json: string[];
  raw_inputs_json: JsonMap;
  normalized_inventory_json: JsonMap;
  summary_json: JsonMap;
  environment_notes_json: string[];
  assumptions_json: string[];
  confidence_score: number;
  created_at: IsoDateTime;
}

export interface AgentProposal {
  id: UUID;
  run_id: UUID;
  agent_reasoning_id: UUID;
  proposed_tool: string;
  proposed_target: string;
  proposed_params_json: JsonMap;
  reasoning_text: string | null;
  risk_tier: string;
  priority: number;
  confidence_score: number | null;
  status: string;
  approved_by: string | null;
  approved_at: IsoDateTime | null;
  metadata_json: JsonMap;
  created_at: IsoDateTime;
  updated_at: IsoDateTime;
}

export interface AgentReasoning {
  id: UUID;
  run_id: UUID;
  task_id: UUID | null;
  reasoning_type: string;
  status: string;
  context_snapshot_json: JsonMap;
  observations_json: JsonMap[];
  hypotheses_json: JsonMap[];
  proposals_json: JsonMap[];
  summary_text: string;
  thought_text: string;
  action_text: string;
  provider: string;
  model: string | null;
  llm_tokens_used: number | null;
  confidence_score: number | null;
  failure_reason: string | null;
  metadata_json: JsonMap;
  proposals: AgentProposal[];
  created_at: IsoDateTime;
  updated_at: IsoDateTime;
}

export interface RunAiInsights {
  run_id: UUID;
  post_task_analysis_enabled: boolean;
  provider: string;
  provider_status: JsonMap;
  reasoning_records: AgentReasoning[];
  proposals: AgentProposal[];
  review_boundary: JsonMap;
  operator_workbench: JsonMap;
}

export interface AssessmentChain {
  id: UUID;
  engagement_id: UUID;
  assessment_mode: string;
  status: string;
  current_phase_index: number;
  current_step_index: number;
  current_phase_key: string | null;
  current_run_id: UUID | null;
  last_completed_run_id: UUID | null;
  auto_advance_on_phase_complete: boolean;
  halt_requested: boolean;
  completed_phase_count: number;
  phase_count: number;
  phases: JsonMap[];
  operator_state: JsonMap;
  created_at: IsoDateTime;
  updated_at: IsoDateTime;
}

export interface RunDispatch {
  run: Run;
  dispatch_mode: string;
  dispatched_task_ids: UUID[];
}

export interface RunIntakeInterpretationInput {
  question_id?: string | null;
  answer?: string | null;
  engagement_id?: UUID | null;
  configuration_json?: JsonMap;
}

export interface RunIntakeInterpretation {
  status: string;
  available: boolean;
  provider: string;
  generated_at: string;
  question_id: string;
  warnings: string[];
  safe_inferences: JsonMap[];
  follow_up_questions: JsonMap[];
  methodology_suggestions: JsonMap[];
  pack_suggestions: JsonMap[];
  blocked_suggestions: JsonMap[];
  boundary: JsonMap;
  operator_confirmation_required: boolean;
  deterministic_intake_preserved: boolean;
  scope_expansion_blocked: boolean;
  failure_reason: string | null;
  provider_metadata: JsonMap;
  explicit_target_count?: number | null;
}

export interface AgentProposalReviewInput {
  decision: 'approved' | 'rejected';
  note?: string | null;
}

export interface Run {
  id: UUID;
  engagement_id: UUID;
  requested_by: string;
  status: string;
  autonomous_mode: boolean;
  autonomous_intrusive_allowed: boolean;
  source_inventory_snapshot_id: UUID | null;
  started_at: IsoDateTime | null;
  created_at: IsoDateTime;
  updated_at: IsoDateTime;
  profile: RunProfile;
  approval_step_id: string;
  required_approvals: number;
  granted_approvals: number;
  pending_approvals: number;
  approvals: Approval[];
  tasks: Task[];
  findings: FindingSummary;
  configuration_json: JsonMap;
  pack_binding: JsonMap | null;
  ai_mission_guidance: JsonMap;
  multi_agent_orchestration: JsonMap;
  assessment_chain: Partial<AssessmentChain> & JsonMap;
  assessment_plan: JsonMap;
  kill_chain_progress: JsonMap | null;
  drift_summary: JsonMap | null;
  stale_recovery: JsonMap;
}

export interface SettingOption {
  value: string;
  label: string;
}

export interface Setting {
  key: string;
  label: string;
  value: unknown;
  input_type: string;
  source: string;
  sensitive: boolean;
  configured: boolean;
  masked_value: string | null;
  read_only: boolean;
  description: string | null;
  options: SettingOption[];
  ui_hidden: boolean;
  min_value: number | null;
  max_value: number | null;
  step: number | null;
  placeholder: string | null;
}

export interface SettingsSection {
  id: string;
  title: string;
  description: string;
  settings: Setting[];
}

export interface Settings {
  tenant_id: string;
  sections: SettingsSection[];
  sensitive_plaintext_exposed: boolean;
}

export interface ToolReadiness {
  id: string;
  title: string;
  status: string;
  installed: boolean;
  missing_binaries: string[];
  operator_next_step: string;
}

export interface SettingsReadiness {
  tenant_id: string;
  generated_at: IsoDateTime;
  overall_status: string;
  capabilities: JsonMap[];
  tools: ToolReadiness[];
  artifact: JsonMap;
}

export interface SettingsEnvelope {
  settings: Settings | null;
  readiness: SettingsReadiness | null;
  chatgpt_connected: boolean;
  tool_readiness: Record<string, ToolReadiness>;
}

export interface EngagementCreateInput {
  name: string;
  client?: string | null;
  tenant_id?: string | null;
  roe_ref?: string | null;
  retention_days?: number;
  starts_at?: IsoDateTime | null;
  ends_at?: IsoDateTime | null;
}

export interface ScopeInput {
  allowlist_json?: JsonMap;
  denylist_json?: JsonMap;
}

export interface RunCreateInput {
  profile_name?: string;
  source_inventory_snapshot_id?: UUID | null;
  configuration_json?: JsonMap;
  autonomous_mode?: boolean | null;
  autonomous_intrusive_allowed?: boolean | null;
  assessment_mode?: string | null;
  assessment_auto_advance_on_phase_complete?: boolean | null;
  dispatch_after_create?: boolean;
}

export interface InventoryRunCreateInput {
  engagement_id: UUID;
  source_tools?: string[];
  observations?: Array<{
    tool: string;
    kind: string;
    data?: JsonMap;
  }>;
  environment_notes?: string[];
  assumptions?: string[];
}
