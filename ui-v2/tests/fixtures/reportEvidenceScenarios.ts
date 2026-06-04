import type { Finding, Run, RunReportCatalogItem, Task } from '../../src/api/types';

export type ReportEvidenceScenarioKey =
  | 'observed_unverified'
  | 'verified_not_persisted'
  | 'verified_persisted'
  | 'blocked_contradictory_score'
  | 'management_untested_scope';

export interface ReportEvidenceScenario {
  key: ReportEvidenceScenarioKey;
  label: string;
  run: Run;
  tasks: Task[];
  findings: Finding[];
  reports: RunReportCatalogItem[];
  markdownPreview: string;
  expected: {
    canonicalTotal: number;
    runLocalTotal: number;
    runTruthAttention: 'complete' | 'warning' | 'blocked';
    consistencyStatus: 'consistent' | 'review' | 'mismatch' | 'loading' | 'unknown';
    reportCatalogCheck: 'match' | 'warning' | 'mismatch' | 'unknown' | 'loading';
    previewCheck: 'match' | 'warning' | 'mismatch' | 'unknown' | 'loading';
    evidenceLinksCheck: 'match' | 'warning' | 'mismatch' | 'unknown' | 'loading';
    requiredPreviewText: string[];
    forbiddenPreviewText: string[];
  };
}

const startedAt = '2026-06-04T09:00:00.000Z';
const observedAt = '2026-06-04T09:02:00.000Z';
const provenAt = '2026-06-04T09:04:00.000Z';

const baseTask: Task = {
  id: 'm7-task-map',
  source_finding_id: null,
  tool: 'smart-web-probe',
  target_id: 'https://m7.example.test',
  status: 'completed',
  params_json: { safe_mode: true },
  stale_recovery: {},
  created_at: startedAt,
  updated_at: observedAt,
};

const baseRun: Run = {
  id: 'm7-run',
  engagement_id: 'eng-1',
  requested_by: 'operator-ui',
  status: 'completed',
  autonomous_mode: false,
  autonomous_intrusive_allowed: false,
  source_inventory_snapshot_id: 'inv-1',
  started_at: startedAt,
  created_at: startedAt,
  updated_at: provenAt,
  profile: {
    id: 'm7-profile',
    name: 'M7 Report Evidence Fixture',
    run_class: 'active',
    limits_json: {},
  },
  approval_step_id: 'approval-m7',
  required_approvals: 1,
  granted_approvals: 1,
  pending_approvals: 0,
  approvals: [],
  tasks: [baseTask],
  findings: {
    finding_count: 0,
    findings_by_severity: {},
    findings_by_status: {},
  },
  configuration_json: {
    assessment_mode: {
      mode: 'FULL-EXTERNAL-WEB',
      authorization_level: 'fixture',
    },
  },
  pack_binding: null,
  ai_mission_guidance: {},
  multi_agent_orchestration: {},
  assessment_chain: {},
  assessment_plan: {},
  kill_chain_progress: null,
  drift_summary: null,
  stale_recovery: {},
};

const persistedFinding: Finding = {
  id: 'm7-finding-persisted',
  run_id: 'm7-run',
  source_pack_id: null,
  source_pack_artifact_id: null,
  source_inventory_snapshot_id: 'inv-1',
  source_relevance_decision_id: null,
  source_pack_version: null,
  finding_origin: 'fixture_runner',
  title: 'Stored proof for account access protection',
  severity: 'high',
  target_id: 'https://m7.example.test/account',
  evidence_ref: 'evidence://m7-finding-persisted',
  status: 'open',
  remediation_due_date: null,
  sla_breached: false,
  false_positive_reason: null,
  false_positive_confirmed_by: null,
  cvss_score: 8.1,
  cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N',
  cvss_source: 'fixture',
  owasp_framework: 'OWASP WSTG',
  owasp_category: 'Authentication',
  owasp_reference: 'WSTG-ATHN-02',
  owasp_mapping: {},
  proof_reference: { artifact: 'artifact-m7-finding-persisted', task_id: baseTask.id },
  validation_status: 'confirmed',
  summary: 'The fixture proves a saved, evidence-linked finding.',
  replay_recipe_json: { tool: 'smart-web-probe', task_id: baseTask.id },
  methodology_tags: ['wstg', 'ptes'],
  ptes_phase: 'vulnerability_analysis',
  nist_phase: 'analysis',
  wstg_id: 'WSTG-ATHN-02',
  wstg_version: '4.2',
  asvs_reference: 'ASVS 2.1.1',
  control_family: 'identity_management',
  created_at: provenAt,
};

export const reportEvidenceScenarioMatrix: ReportEvidenceScenario[] = [
  scenario({
    key: 'observed_unverified',
    label: 'Observed output only; no finding is persisted',
    run: runWith({
      id: 'm7-run-observed',
      findings: { finding_count: 0, findings_by_severity: {}, findings_by_status: {} },
    }),
    tasks: [taskWith({ id: 'm7-task-observed', status: 'completed' })],
    findings: [],
    markdownPreview: markdownFor({
      runId: 'm7-run-observed',
      canonicalTotal: 0,
      lines: ['Observed task output exists, but no canonical finding has been saved.'],
    }),
    expected: {
      canonicalTotal: 0,
      runLocalTotal: 0,
      runTruthAttention: 'blocked',
      consistencyStatus: 'consistent',
      reportCatalogCheck: 'match',
      previewCheck: 'match',
      evidenceLinksCheck: 'match',
      requiredPreviewText: ['Canonical Findings: 0', 'no canonical finding has been saved'],
      forbiddenPreviewText: ['reportable vulnerability confirmed'],
    },
  }),
  scenario({
    key: 'verified_not_persisted',
    label: 'Run-local signal claims one result, but canonical findings are empty',
    run: runWith({
      id: 'm7-run-verified-not-persisted',
      findings: {
        finding_count: 1,
        findings_by_severity: { high: 1 },
        findings_by_status: { confirmed: 1 },
      },
    }),
    tasks: [taskWith({ id: 'm7-task-verified-not-persisted', status: 'completed' })],
    findings: [],
    markdownPreview: markdownFor({
      runId: 'm7-run-verified-not-persisted',
      canonicalTotal: 0,
      lines: ['A run-local signal was observed, but report output stays at zero until persistence.'],
    }),
    expected: {
      canonicalTotal: 0,
      runLocalTotal: 1,
      runTruthAttention: 'blocked',
      consistencyStatus: 'review',
      reportCatalogCheck: 'match',
      previewCheck: 'match',
      evidenceLinksCheck: 'match',
      requiredPreviewText: ['Canonical Findings: 0', 'stays at zero until persistence'],
      forbiddenPreviewText: ['Canonical Findings: 1'],
    },
  }),
  scenario({
    key: 'verified_persisted',
    label: 'Verified and persisted finding is report-ready',
    run: runWith({
      id: 'm7-run-verified-persisted',
      findings: {
        finding_count: 1,
        findings_by_severity: { high: 1 },
        findings_by_status: { open: 1 },
      },
    }),
    tasks: [taskWith({ id: 'm7-task-verified-persisted', status: 'completed' })],
    findings: [findingWith({ id: 'm7-finding-verified-persisted', run_id: 'm7-run-verified-persisted' })],
    markdownPreview: markdownFor({
      runId: 'm7-run-verified-persisted',
      canonicalTotal: 1,
      lines: ['One evidence-backed finding is ready for report review.'],
    }),
    expected: {
      canonicalTotal: 1,
      runLocalTotal: 1,
      runTruthAttention: 'complete',
      consistencyStatus: 'consistent',
      reportCatalogCheck: 'match',
      previewCheck: 'match',
      evidenceLinksCheck: 'match',
      requiredPreviewText: ['Canonical Findings: 1', 'ready for report review'],
      forbiddenPreviewText: ['unverified finding is report-ready'],
    },
  }),
  scenario({
    key: 'blocked_contradictory_score',
    label: 'Contradictory score state is blocked until reviewed',
    run: runWith({
      id: 'm7-run-blocked-contradictory',
      status: 'completed_with_errors',
      findings: {
        finding_count: 2,
        findings_by_severity: { critical: 2 },
        findings_by_status: { open: 2 },
      },
    }),
    tasks: [taskWith({ id: 'm7-task-blocked-contradictory', status: 'failed' })],
    findings: [],
    reports: reportCatalogFor({
      runId: 'm7-run-blocked-contradictory',
      includedTotal: 2,
      linkedTotal: 2,
    }),
    markdownPreview: markdownFor({
      runId: 'm7-run-blocked-contradictory',
      canonicalTotal: 2,
      lines: ['This preview intentionally exposes a stale catalog claim for review.'],
    }),
    expected: {
      canonicalTotal: 0,
      runLocalTotal: 2,
      runTruthAttention: 'blocked',
      consistencyStatus: 'mismatch',
      reportCatalogCheck: 'mismatch',
      previewCheck: 'mismatch',
      evidenceLinksCheck: 'mismatch',
      requiredPreviewText: ['Canonical Findings: 2', 'stale catalog claim'],
      forbiddenPreviewText: ['customer-ready final report'],
    },
  }),
  scenario({
    key: 'management_untested_scope',
    label: 'Management report names untested scope without claiming coverage',
    run: runWith({
      id: 'm7-run-management-untested',
      findings: {
        finding_count: 1,
        findings_by_severity: { high: 1 },
        findings_by_status: { open: 1 },
      },
    }),
    tasks: [taskWith({ id: 'm7-task-management-untested', status: 'completed' })],
    findings: [findingWith({ id: 'm7-finding-management-untested', run_id: 'm7-run-management-untested' })],
    markdownPreview: markdownFor({
      runId: 'm7-run-management-untested',
      canonicalTotal: 1,
      lines: [
        'Tested scope: public account flow only.',
        'Not tested: internal admin database and supplier VPN.',
        'Management note: untested areas are excluded from the finding count.',
      ],
    }),
    expected: {
      canonicalTotal: 1,
      runLocalTotal: 1,
      runTruthAttention: 'complete',
      consistencyStatus: 'consistent',
      reportCatalogCheck: 'match',
      previewCheck: 'match',
      evidenceLinksCheck: 'match',
      requiredPreviewText: ['Not tested: internal admin database', 'untested areas are excluded'],
      forbiddenPreviewText: ['internal admin database was fully tested'],
    },
  }),
];

export const reportEvidenceScenarios = Object.fromEntries(
  reportEvidenceScenarioMatrix.map((item) => [item.key, item]),
) as Record<ReportEvidenceScenarioKey, ReportEvidenceScenario>;

function scenario(input: Omit<ReportEvidenceScenario, 'reports'> & { reports?: RunReportCatalogItem[] }): ReportEvidenceScenario {
  return {
    ...input,
    reports: input.reports ?? reportCatalogFor({
      runId: input.run.id,
      includedTotal: input.findings.length,
      linkedTotal: input.findings.filter((finding) => finding.evidence_ref.trim()).length,
    }),
  };
}

function runWith(overrides: Partial<Run>): Run {
  return {
    ...baseRun,
    ...overrides,
    profile: {
      ...baseRun.profile,
      ...(overrides.profile ?? {}),
    },
    tasks: overrides.tasks ?? baseRun.tasks,
    configuration_json: {
      ...baseRun.configuration_json,
      ...(overrides.configuration_json ?? {}),
    },
    assessment_chain: overrides.assessment_chain ?? {},
  };
}

function taskWith(overrides: Partial<Task>): Task {
  return {
    ...baseTask,
    ...overrides,
    params_json: {
      ...baseTask.params_json,
      ...(overrides.params_json ?? {}),
    },
  };
}

function findingWith(overrides: Partial<Finding>): Finding {
  return {
    ...persistedFinding,
    ...overrides,
    proof_reference: {
      ...persistedFinding.proof_reference,
      ...(overrides.proof_reference ?? {}),
    },
    replay_recipe_json: {
      ...(persistedFinding.replay_recipe_json ?? {}),
      ...(overrides.replay_recipe_json ?? {}),
    },
  };
}

function reportCatalogFor({
  runId,
  includedTotal,
  linkedTotal,
}: {
  runId: string;
  includedTotal: number;
  linkedTotal: number;
}): RunReportCatalogItem[] {
  return [
    {
      variant: 'executive_summary',
      title: 'Executive Summary',
      description: 'Management-readable summary backed by named M7 fixture evidence.',
      source_run_id: runId,
      generated_at: provenAt,
      available_formats: ['markdown', 'html', 'pdf'],
      methodology_references: ['PTES', 'OWASP WSTG 4.2', 'NIST SP 800-115', 'OWASP ASVS 4.0.3'],
      source_scope_profile: { run_profile: 'M7 Report Evidence Fixture' },
      included_findings: {
        total: includedTotal,
        by_severity: includedTotal > 0 ? { high: includedTotal } : {},
        by_status: includedTotal > 0 ? { open: includedTotal } : {},
      },
      included_inventory: { hosts: 1, services: 1, endpoints: 1 },
      evidence_status: {
        verified: linkedTotal === includedTotal,
        linked_findings: linkedTotal,
        total_findings: includedTotal,
      },
      compliance_summary: {},
      assurance_summary: {},
      adaptive_change_summary: {},
      ai_draft_summary: {},
      run_narrative_summary: {},
      lifecycle_summary: {},
      version_label: 'm7-fixture-v1',
      content_sha256: '7'.repeat(64),
      availability_status: 'export_ready',
      availability_label: 'ready',
      availability_reason: 'Available from named M7 fixture evidence.',
      preview_allowed: true,
      export_allowed: true,
      draft_allowed: false,
      export_paths: { markdown: '/fixture/m7-report.md' },
      download_names: { markdown: 'm7-report.md' },
    },
  ];
}

function markdownFor({
  runId,
  canonicalTotal,
  lines,
}: {
  runId: string;
  canonicalTotal: number;
  lines: string[];
}): string {
  return [
    '# M7 Report Evidence Scenario',
    '',
    `- Source Run: ${runId}`,
    `- Canonical Findings: ${canonicalTotal}`,
    '',
    ...lines,
    '',
  ].join('\n');
}
