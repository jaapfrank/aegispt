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

export interface FindingRelatedArtifact {
  artifact_id: UUID;
  kind: string;
  uri: string;
  download_path: string;
  name: string;
  sha256: string;
  hash_status: string;
  timestamp_status: string;
  timestamp_response_uri: string | null;
  redaction_state: string;
  created_at: IsoDateTime;
}

export interface FindingRelatedExecution {
  execution_id: UUID;
  task_id: UUID;
  tool: string;
  target_id: string;
  task_status: string;
  exit_code: number;
  tool_version: string;
  stdout_excerpt: string | null;
  stderr_excerpt: string | null;
  created_at: IsoDateTime;
  artifacts: FindingRelatedArtifact[];
}

export interface FindingEvidenceReplay {
  finding: Finding;
  evidence_ref: string;
  methodology_references: JsonMap;
  pack_provenance: JsonMap;
  inventory_source: JsonMap;
  relevance_source: JsonMap;
  validation_history: JsonMap[];
  related_executions: FindingRelatedExecution[];
}

export interface FindingTheater {
  finding: Finding;
  severity_rank: number;
  confidence_label: string;
  exploitability: string | null;
  business_impact: string;
  technical_details: string;
  evidence_summary: string;
  provenance: JsonMap;
  methodology: JsonMap;
  remediation: JsonMap;
  ai_enrichment: JsonMap;
  autofix: JsonMap;
  repository_context: JsonMap;
  threat_context: JsonMap;
  detection_engineering: JsonMap;
  vulnerability_chains: JsonMap;
  threat_intel_badges: JsonMap;
  validation: JsonMap;
  evidence_integrity: JsonMap;
  verification_status: string;
  next_steps: string[];
  risk_snapshot: JsonMap;
}

export interface RepositoryFixPullRequest {
  provider: 'github' | 'gitlab';
  repository_url: string;
  branch_name: string;
  pull_request_url: string;
  pull_request_id: string;
  auto_merge_enabled: boolean;
}

export interface RunReportCatalogItem {
  variant: string;
  title: string;
  description: string;
  source_run_id: UUID;
  generated_at: IsoDateTime;
  available_formats: string[];
  methodology_references: string[];
  source_scope_profile: JsonMap;
  included_findings: JsonMap;
  included_inventory: JsonMap;
  evidence_status: JsonMap;
  compliance_summary: JsonMap;
  assurance_summary: JsonMap;
  adaptive_change_summary: JsonMap;
  ai_draft_summary: JsonMap;
  run_narrative_summary: JsonMap;
  version_label: string;
  content_sha256: string;
  availability_status: string;
  availability_label: string;
  availability_reason: string;
  preview_allowed: boolean;
  export_allowed: boolean;
  draft_allowed: boolean;
  lifecycle_summary: JsonMap;
  export_paths: Record<string, string>;
  download_names: Record<string, string>;
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
  intent_mission_plan?: JsonMap | null;
}

export interface AgentProposalReviewInput {
  decision: 'approved' | 'rejected';
  note?: string | null;
}

export interface FindingStatusUpdateInput {
  status: 'open' | 'triaged' | 'in_progress' | 'resolved' | 'accepted_risk' | 'false_positive';
  reason?: string | null;
  false_positive_reason?: string | null;
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
  binary_names?: string[];
  required_binary_groups?: string[][];
  status: string;
  required?: boolean;
  installed: boolean;
  detected_path?: string | null;
  detected_paths?: Record<string, string>;
  missing_binaries: string[];
  affected_assessment_families?: string[];
  operator_next_step: string;
  install_command?: string | null;
  repair_command?: string | null;
  repair_action_label?: string | null;
  repair_action_kind?: string;
  software_installable?: boolean;
  hardware_required?: boolean;
}

export interface ReadinessCapability {
  id: string;
  title: string;
  status: string;
  summary: string;
  details: string[];
  operator_next_step: string;
  affected_assessment_families: string[];
  metadata: JsonMap;
}

export interface SettingsReadiness {
  tenant_id: string;
  generated_at: IsoDateTime;
  overall_status: string;
  capabilities: ReadinessCapability[];
  tools: ToolReadiness[];
  artifact: JsonMap;
}

export interface SettingsEnvelope {
  settings: Settings | null;
  readiness: SettingsReadiness | null;
  chatgpt_connected: boolean;
  tool_readiness: Record<string, ToolReadiness>;
}

export interface SettingsPatchInput {
  settings: Record<string, unknown>;
}

export interface ChatGptOAuthStatus {
  provider?: string;
  status?: string;
  configured?: boolean;
  connected?: boolean;
  available?: boolean;
  account_id?: string | null;
  model?: string | null;
  token_count?: number | null;
  reusable_session_count?: number | null;
  failure_reason?: string | null;
  message?: string | null;
  [key: string]: unknown;
}

export interface ChatGptOAuthAuthorize {
  provider: string;
  reused?: boolean;
  authorization_url?: string | null;
  state?: string;
  redirect_uri?: string;
  local_callback_listener?: JsonMap;
  status?: JsonMap;
  token_exposed?: boolean;
  message?: string;
}

export interface ApiKeyRead {
  id: UUID;
  actor_name: string;
  role: string;
  created_at: IsoDateTime;
  last_used_at: IsoDateTime | null;
  revoked_at: IsoDateTime | null;
}

export interface ApiKeyCreateInput {
  actor_name?: string | null;
  role: 'admin' | 'operator' | 'reviewer';
}

export interface ApiKeyCreateRead extends ApiKeyRead {
  api_key: string;
  token_exposed_once: boolean;
}

export interface EnterpriseIdentityStatus {
  tenant_id: string;
  provider: string;
  status: string;
  configured: boolean;
  summary: string;
  operator_next_step: string;
  missing_fields: string[];
  configured_secret_labels: string[];
  session_policy: JsonMap;
  local_auth: JsonMap;
  access_boundaries: JsonMap;
  current_actor: JsonMap;
  users: JsonMap[];
  metadata: JsonMap;
}

export interface ScheduledRun {
  id: UUID;
  engagement_id: UUID;
  profile_name: string;
  source_inventory_snapshot_id: UUID | null;
  cadence: string;
  cron_expression: string;
  timezone: string;
  status: string;
  next_run_at: IsoDateTime;
  last_run_at: IsoDateTime | null;
  last_launched_run_id: UUID | null;
}

export interface DashboardRead {
  generated_at: IsoDateTime;
  has_engagements: boolean;
  active_run: JsonMap | null;
  risk_score: JsonMap;
  blast_radius: JsonMap;
  zero_day_rapid_response: JsonMap;
  open_problems: JsonMap;
  upcoming_scans: JsonMap[];
  recent_activity: JsonMap[];
  activity_feed: JsonMap[];
  quick_actions: JsonMap[];
  setup_checklist_dismissed: boolean;
  setup_checklist: JsonMap[];
  first_run_onboarding: JsonMap | null;
  engagements: JsonMap[];
}

export interface ZeroDayScanNowResponse {
  accepted: boolean;
  run_id: UUID;
  run_status: string;
  profile_name: string;
  required_approvals: number;
  granted_approvals: number;
  target: string;
  record_id: UUID;
  advisory_id: string;
  operator_approval_required: boolean;
  automatic_approval_created: boolean;
  automatic_tests_started: boolean;
  scope_enforced: boolean;
  detail: string;
}

export interface DeceptionBoundary {
  local_controlled_fixture: boolean;
  network_tarpitting: boolean;
  automatic_live_deployment: boolean;
  legitimate_traffic_interference_expected: boolean;
  credential_materialized: boolean;
  dispatches_runtime_work: boolean;
}

export type DeceptionTrapKind = 'hallucination_api' | 'fake_admin_api' | 'canary_document';

export interface DeceptionTrapCreateInput {
  name: string;
  trap_kind: DeceptionTrapKind;
  local_only?: boolean;
  enabled?: boolean;
  max_depth?: number;
  operator_note?: string | null;
}

export interface DeceptionTrap {
  id: UUID;
  tenant_id: string;
  name: string;
  trap_kind: DeceptionTrapKind;
  enabled: boolean;
  local_only: boolean;
  max_depth: number;
  endpoint_path: string;
  response_preview: JsonMap;
  boundary: DeceptionBoundary;
  operator_note: string | null;
  created_at: IsoDateTime;
  updated_at: IsoDateTime;
  created_by: string;
  updated_by: string;
}

export interface DeceptionTrapList {
  tenant_id: string;
  traps: DeceptionTrap[];
  boundary: DeceptionBoundary;
}

export interface DeceptionAlert {
  id: UUID;
  tenant_id: string;
  trap_id: UUID;
  trap_name: string;
  trap_kind: DeceptionTrapKind;
  probed_path: string;
  actor: string;
  user_agent: string | null;
  source: string;
  created_at: IsoDateTime;
  evidence_ref: string;
  boundary: DeceptionBoundary;
}

export interface DeceptionAlertList {
  tenant_id: string;
  alerts: DeceptionAlert[];
  boundary: DeceptionBoundary;
}

export interface PortfolioRun extends Run {
  engagement_name: string;
  engagement_client: string | null;
}

export interface ProblemsRead {
  generated_at: IsoDateTime;
  items: ProblemRead[];
  recently_resolved: ProblemRead[];
  stats: JsonMap;
  filters: JsonMap;
  lifecycle_summary: JsonMap;
  next_cursor: string | null;
}

export interface ProblemRead {
  id: UUID;
  finding_id: UUID;
  run_id: UUID;
  engagement_id: UUID;
  engagement_name: string;
  title: string;
  severity: string;
  target_id: string;
  status: string;
  problem_status: string;
  assignee: string | null;
  days_open: number;
  age_bucket: string;
  remediation_state: string;
  verification_status: string;
  methodology_tags: string[];
  latest_retest_run_id: UUID | null;
  latest_retest_status: string | null;
  lifecycle: JsonMap[];
  created_at: IsoDateTime;
  updated_at: IsoDateTime;
}

export interface ProblemsQuery {
  severity?: string;
  status?: string;
  engagement_id?: UUID;
  assignee?: string;
  age?: string;
  methodology?: string;
  limit?: number;
}

export interface ProblemBulkUpdateInput {
  finding_ids: UUID[];
  action: 'assign' | 'status' | 'resolve' | 'schedule_retest';
  status?: string | null;
  assignee?: string | null;
  retest_notes?: string | null;
}

export interface ProblemBulkUpdateRead {
  action: string;
  requested_count: number;
  updated_count: number;
  retest_run_ids: UUID[];
  skipped: JsonMap[];
  message: string;
}

export interface CapabilityPack {
  id: UUID;
  engagement_id: UUID;
  relevance_decision_id: UUID | null;
  source_inventory_snapshot_id: UUID | null;
  parent_pack_id: UUID | null;
  name: string;
  version: string;
  status: string;
  generated_by: string;
  generation_mode: string;
  description: string | null;
  source_threat_intel_refs_json: string[];
  methodology_tags: string[];
  manifest_json: JsonMap;
  provenance_json: JsonMap;
  created_at: IsoDateTime;
}

export interface CapabilityPackArtifact {
  id: UUID;
  pack_id: UUID;
  artifact_type: string;
  logical_name: string;
  status: string;
  checksum_sha256: string;
  methodology_tags: string[];
  content_text: string | null;
  content_json: JsonMap | null;
  provenance_json: JsonMap;
  created_at: IsoDateTime;
}

export interface CapabilityPackValidation {
  id: UUID;
  pack_id: UUID;
  validator: string;
  executed_by: string;
  status: string;
  summary: string | null;
  artifact_results_json: JsonMap[];
  validation_artifacts_json: JsonMap[];
  blocking_issues_json: string[];
  created_at: IsoDateTime;
}

export interface CapabilityPackDeployment {
  id: UUID;
  pack_id: UUID;
  engagement_id: UUID;
  deployed_by: string;
  deployment_target: string;
  run_profile_name: string | null;
  status: string;
  rollback_from_pack_id: UUID | null;
  notes: string | null;
  runtime_binding_json: JsonMap;
  created_at: IsoDateTime;
}

export interface CustomVulnerability {
  id: UUID;
  tenant_id: string;
  custom_id: string;
  title: string;
  description: string;
  severity: string;
  cvss_score: number | null;
  affected_products_json: string[];
  cwe_ids_json: string[];
  discovery_date: IsoDateTime | null;
  reporter: string | null;
  status: string;
  linked_nuclei_template_ref: string | null;
  linked_threat_intel_record_id: UUID | null;
  metadata_json: JsonMap;
  deleted_at: IsoDateTime | null;
  test_coverage: JsonMap;
  engagement_state: JsonMap | null;
  created_at: IsoDateTime;
  updated_at: IsoDateTime;
}

export interface CustomVulnerabilityList {
  items: CustomVulnerability[];
  total: number;
  filters: JsonMap;
}

export interface CustomVulnerabilityInput {
  custom_id?: string | null;
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  cvss_score?: number | null;
  affected_products?: string[];
  cwe_ids?: string[];
  reporter?: string | null;
  status?: 'draft' | 'active' | 'deprecated';
  linked_nuclei_template_ref?: string | null;
  metadata?: JsonMap;
}

export interface CustomVulnerabilityExport {
  exported_at: IsoDateTime;
  tenant_id: string;
  format: string;
  items: JsonMap[];
}

export interface ThreatIntelRecord {
  id: UUID;
  source: string;
  advisory_id: string;
  title: string;
  summary: string | null;
  affected_products_json: string[];
  affected_versions_json: string[];
  suggested_test_patterns_json: string[];
  confidence_score: number;
  severity: string | null;
  references_json: string[];
  published_at: IsoDateTime | null;
  updated_at: IsoDateTime | null;
  normalization_status: string;
  metadata_json: JsonMap;
  created_at: IsoDateTime;
}

export interface AiResearchProposal {
  id: UUID | string;
  pack_id: UUID | string;
  artifact_id: UUID | string | null;
  record_id: UUID | string | null;
  source: string;
  title: string;
  description: string | null;
  status: string;
  pack_status: string;
  review_url: string | null;
  generation_mode: string;
  output_kind: string | null;
  provider: string | null;
  model: string | null;
  advisory_id: string | null;
  validation: JsonMap;
  yaml_diff: string | null;
  reasoning: string | null;
  detection_strategy: string | null;
  safety_notes: string[];
  created_at: IsoDateTime | null;
  updated_at: IsoDateTime | null;
}

export interface AiResearchLab {
  engagement_id: UUID;
  cve_records: ThreatIntelRecord[];
  research_proposals: AiResearchProposal[];
  lifecycle_note: string;
}

export interface AiResearchGenerationInput {
  engagement_id: UUID;
  description: string;
  output_kind: 'nuclei_yaml' | 'python_detection';
}

export interface AiResearchGeneration {
  record_id: UUID | null;
  status: string;
  message: string;
  pack_id: UUID | string | null;
  artifact_id: UUID | string | null;
  pack_status: string | null;
  review_url: string | null;
  template_yaml: string | null;
  yaml_diff: string | null;
  validation: JsonMap;
  generated_template: JsonMap;
  lifecycle_note: string;
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

export interface AttackPathSimulation {
  status: string;
  run_id: UUID;
  generated_at: IsoDateTime;
  simulation_mode: boolean;
  starting_point: JsonMap;
  anchors: JsonMap[];
  hypothetical_edges: JsonMap[];
  simulated_paths: JsonMap[];
  summary: JsonMap;
  boundary: JsonMap;
  source_attack_path_model: string | null;
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
