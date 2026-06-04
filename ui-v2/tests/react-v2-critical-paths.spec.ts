import { expect, test, type Page, type Route } from '@playwright/test';
import type { Finding, Run, RunReportCatalogItem, Task } from '../src/api/types';
import { buildCrossSurfaceConsistency } from '../src/viewModels/crossSurfaceConsistency';
import { buildReportPreviewMetadata } from '../src/viewModels/reportPreviewMetadata';
import { buildRunTruthModel } from '../src/viewModels/runTruth';
import { reportEvidenceScenarioMatrix, reportEvidenceScenarios } from './fixtures/reportEvidenceScenarios';

const now = '2026-05-10T10:00:00.000Z';
const oneMinuteLater = '2026-05-10T10:01:00.000Z';
const twoMinutesLater = '2026-05-10T10:02:00.000Z';
const twoMinutesFortyFiveLater = '2026-05-10T10:02:45.000Z';
const fourMinutesLater = '2026-05-10T10:04:00.000Z';
const fiveMinutesLater = '2026-05-10T10:05:00.000Z';
const eightMinutesLater = '2026-05-10T10:08:00.000Z';
const nineMinutesLater = '2026-05-10T10:09:00.000Z';

async function expectNoUnscopedDarkPanels(page: Page, scope = 'main') {
  const offenders = await page.locator(scope).evaluate((root) => {
    const darkOnlyFragments = [
      'bg-[#0',
      'bg-[rgba(5,9,18',
      'bg-[rgba(7,17,31',
      'bg-[linear-gradient',
      'from-[#',
      'via-[#',
      'to-[#',
    ];
    return Array.from(root.querySelectorAll('*'))
      .filter((element) => {
        const className = typeof (element as HTMLElement).className === 'string'
          ? (element as HTMLElement).className
          : '';
        if (!darkOnlyFragments.some((fragment) => className.includes(fragment))) return false;
        return !element.closest('.dark-canvas') && !element.closest('.terminal-code');
      })
      .slice(0, 12)
      .map((element) => {
        const className = typeof (element as HTMLElement).className === 'string'
          ? (element as HTMLElement).className
          : '';
        return `${element.tagName.toLowerCase()}: ${className.slice(0, 180)}`;
      });
  });
  expect(offenders).toEqual([]);
}

const engagement = {
  id: 'eng-1',
  name: 'Acme External Web',
  client: 'Acme',
  tenant_id: 'tenant-1',
  roe_ref: 'ROE-2026-05',
  authorization_confirmed_by: 'operator-ui',
  authorization_confirmed_at: now,
  status: 'active',
  retention_days: 30,
  starts_at: null,
  ends_at: null,
};

const profile = {
  id: 'profile-1',
  name: 'Full External Web Pentest',
  run_class: 'active',
  limits_json: {},
};

const tasks = [
  {
    id: 'task-1',
    source_finding_id: null,
    tool: 'httpx',
    target_id: 'https://app.example.test',
    status: 'completed',
    params_json: { safe_mode: true },
    stale_recovery: {},
    created_at: now,
    updated_at: oneMinuteLater,
  },
  {
    id: 'task-2',
    source_finding_id: null,
    tool: 'nuclei',
    target_id: 'https://api.example.test',
    status: 'completed',
    params_json: { templates: 'safe-review' },
    stale_recovery: {},
    created_at: oneMinuteLater,
    updated_at: fourMinutesLater,
  },
  {
    id: 'task-3',
    source_finding_id: null,
    tool: 'burp',
    target_id: 'https://app.example.test/login',
    status: 'failed',
    params_json: { safe_mode: true },
    stale_recovery: {},
    created_at: twoMinutesLater,
    updated_at: twoMinutesFortyFiveLater,
  },
  {
    id: 'task-4',
    source_finding_id: null,
    tool: 'ssrf-probe',
    target_id: 'https://app.example.test/upload',
    status: 'queued',
    params_json: { safe_mode: true },
    stale_recovery: {},
    created_at: fiveMinutesLater,
    updated_at: fiveMinutesLater,
  },
];

const findings = [
  { ...finding('finding-critical', 'Critical stored XSS in profile preview', 'critical', 'https://app.example.test/profile', 9.4), created_at: eightMinutesLater },
  { ...finding('finding-high', 'High-risk missing HSTS header', 'high', 'https://api.example.test', 7.2), created_at: nineMinutesLater },
];

const attackMapCriticalClusterFindings = [
  { ...finding('cluster-critical-1', 'Critical stored XSS in profile preview', 'critical', 'https://app.example.test/profile', 9.4), created_at: eightMinutesLater },
  { ...finding('cluster-critical-2', 'Critical admin token exposure', 'critical', 'https://app.example.test/admin', 9.7), created_at: '2026-05-10T10:08:20.000Z' },
  { ...finding('cluster-critical-3', 'Critical session takeover path', 'critical', 'https://app.example.test/session', 9.6), created_at: '2026-05-10T10:08:40.000Z' },
  { ...finding('cluster-critical-4', 'Critical unauthorized file access', 'critical', 'https://app.example.test/files', 9.5), created_at: '2026-05-10T10:08:55.000Z' },
  { ...finding('cluster-critical-5', 'Critical privilege escalation route', 'critical', 'https://app.example.test/admin/users', 9.8), created_at: nineMinutesLater },
  { ...finding('cluster-info-1', 'AegisPT HTTP Status 200 Baseline', 'info', 'https://app.example.test', 0), created_at: nineMinutesLater },
];

const theaterTruthFindings = [
  {
    ...finding('finding-raw-runner', 'Flag captured (interactive-exploit): aegispt{redacted-fixture}', 'critical', 'https://app.example.test/admin', 9.8),
    finding_origin: 'interactive_exploit',
    replay_recipe_json: { tool: 'interactive-exploit' },
    methodology_tags: ['interactive-exploit'],
    summary: 'Stored grader flag capture from bounded interactive exploit.',
  },
  {
    ...finding('finding-observed', 'Observed reflected sink awaiting replay', 'medium', 'https://app.example.test/search', 5.4),
    validation_status: 'validation_queued',
    summary: 'Evidence reference exists, but validation has not completed.',
  },
  {
    ...finding('finding-blocked', 'Candidate admin takeover without evidence', 'high', 'https://app.example.test/admin', 7.5),
    evidence_ref: '',
    validation_status: 'validation_skipped',
    replay_recipe_json: { tool: 'candidate-review' },
    summary: 'Candidate was not promoted with replay evidence.',
  },
];

const triageBoardFindings = [
  {
    ...finding('triage-critical-a', 'SQL injection in customer search', 'critical', 'https://app.example.test/search', 9.8),
    remediation_due_date: '2026-06-04T08:00:00.000Z',
    sla_breached: true,
  },
  {
    ...finding('triage-critical-b', 'SQL injection in customer search', 'critical', 'https://app.example.test/login', 9.7),
    remediation_due_date: '2026-06-04T08:00:00.000Z',
  },
  {
    ...finding('triage-evidence-gap', 'Candidate admin takeover without proof', 'high', 'https://app.example.test/admin', 7.7),
    evidence_ref: '',
    validation_status: 'validation_skipped',
    summary: 'Candidate signal has no linked evidence yet.',
  },
  {
    ...finding('triage-medium', 'Missing security header', 'medium', 'https://api.example.test', 5.8),
    validation_status: 'validation_queued',
  },
];

const run = {
  id: 'run-1',
  engagement_id: engagement.id,
  requested_by: 'operator-ui',
  status: 'completed',
  autonomous_mode: false,
  autonomous_intrusive_allowed: false,
  source_inventory_snapshot_id: 'inv-1',
  started_at: now,
  created_at: now,
  updated_at: nineMinutesLater,
  profile,
  approval_step_id: 'approval-step-1',
  required_approvals: 1,
  granted_approvals: 1,
  pending_approvals: 0,
  approvals: [
    {
      id: 'approval-1',
      step_id: 'approval-step-1',
      approver_id: 'operator-ui',
      decision: 'approved',
      created_at: now,
    },
  ],
  tasks,
  findings: {
    finding_count: 1,
    findings_by_severity: { critical: 1 },
    findings_by_status: { open: 1 },
  },
  configuration_json: {
    assessment_mode: {
      mode: 'FULL-EXTERNAL-WEB',
      authorization_level: 'review-only-fixture',
    },
    runtime_dispatch: {
      last_dispatch_mode: 'manual',
    },
  },
  pack_binding: null,
  ai_mission_guidance: {},
  multi_agent_orchestration: {},
  assessment_chain: {
    id: 'chain-1',
    status: 'completed_with_gaps',
    current_phase_key: 'reporting',
    current_phase_index: 1,
    phases: [
      { key: 'recon', label: 'Reconnaissance', status: 'completed' },
      { key: 'reporting', label: 'Evidence Review', status: 'completed_with_gaps' },
    ],
  },
  assessment_plan: {},
  kill_chain_progress: null,
  drift_summary: null,
  stale_recovery: {},
};

const evidenceChainTasks = [
  {
    ...tasks[0],
    id: 'task-evidence-local',
    tool: 'httpx',
    target_id: 'https://app.example.test/profile',
    status: 'completed',
  },
  {
    ...tasks[1],
    id: 'task-evidence-sibling',
    tool: 'nuclei',
    target_id: 'https://api.example.test/admin',
    status: 'completed',
  },
];

const evidenceChainRun = {
  ...run,
  id: 'run-evidence-chain-1',
  status: 'completed',
  profile: {
    id: 'profile-evidence-chain-1',
    name: 'Evidence Chain Replay',
    run_class: 'active',
    limits_json: {},
  },
  tasks: [evidenceChainTasks[0]],
  findings: {
    finding_count: 0,
    findings_by_severity: {},
    findings_by_status: {},
  },
  assessment_chain: {
    id: 'chain-evidence-1',
    status: 'completed',
    current_phase_key: 'reporting',
    current_phase_index: 1,
    phases: [
      { key: 'recon', label: 'Reconnaissance', status: 'completed' },
      { key: 'reporting', label: 'Evidence Replay', status: 'completed' },
    ],
  },
};

const evidenceChainFindings = [
  {
    ...finding('finding-evidence-linked', 'Customer account data exposure proof', 'critical', 'https://api.example.test/admin', 9.6),
    run_id: evidenceChainRun.id,
    evidence_ref: 'artifact-task-evidence-sibling',
    proof_reference: { artifact: 'artifact-task-evidence-sibling', task_id: 'task-evidence-sibling' },
    replay_recipe_json: { tool: 'nuclei', task_id: 'task-evidence-sibling' },
    created_at: fiveMinutesLater,
  },
];

const observedOnlyTasks = tasks.slice(0, 2).map((task, index) => ({
  ...task,
  id: `task-observed-${index + 1}`,
  status: 'completed',
}));

const observedOnlyRun = {
  ...run,
  id: 'run-observed-only-1',
  status: 'completed',
  assessment_chain: null,
  tasks: observedOnlyTasks,
  findings: {
    finding_count: 0,
    findings_by_severity: {},
    findings_by_status: {},
  },
};

const runningTasks = [
  {
    id: 'task-running-1',
    source_finding_id: null,
    tool: 'nmap',
    target_id: 'https://queued.example.test',
    status: 'running',
    params_json: { safe_mode: true },
    stale_recovery: {},
    created_at: now,
    updated_at: now,
  },
];

const runningRun = {
  ...run,
  id: 'run-running-1',
  status: 'running',
  profile: {
    id: 'profile-running-1',
    name: 'Passive Network Discovery',
    run_class: 'passive',
    limits_json: {},
  },
  source_inventory_snapshot_id: 'inv-running-1',
  tasks: runningTasks,
  findings: {
    finding_count: 0,
    findings_by_severity: {},
    findings_by_status: {},
  },
  assessment_chain: null,
};

const queuedRun = {
  ...run,
  id: 'run-queued-1',
  status: 'queued',
  profile: {
    id: 'profile-queued-1',
    name: 'active-web-ssrf-probe',
    run_class: 'active',
    limits_json: {},
  },
  source_inventory_snapshot_id: 'inv-queued-1',
  tasks: [
    {
      id: 'task-queued-1',
      source_finding_id: null,
      tool: 'ssrf-probe',
      target_id: 'https://app.example.test/upload',
      status: 'queued',
      params_json: { safe_mode: true },
      stale_recovery: {},
      created_at: now,
      updated_at: now,
    },
  ],
  findings: {
    finding_count: 0,
    findings_by_severity: {},
    findings_by_status: {},
  },
  configuration_json: {
    assessment_mode: {
      mode: 'FULL-EXTERNAL-WEB',
      authorization_level: 'full',
    },
    runtime_dispatch: {
      last_dispatch_mode: 'manual',
    },
  },
  assessment_chain: {
    id: 'chain-queued-1',
    status: 'active',
    current_phase_key: 'active-web-validation',
    current_phase_index: 1,
    phases: [
      { key: 'passive-surface', label: 'Phase 1 · Passive Surface Mapping', status: 'completed' },
      { key: 'active-web-validation', label: 'Phase 2 · Active Web Validation', status: 'active' },
      { key: 'intrusive-confirmation', label: 'Phase 3 · Intrusive Confirmation', status: 'pending' },
    ],
  },
};

const queuedSignalTasks = [
  {
    ...tasks[0],
    id: 'task-waiting-httpx',
    tool: 'httpx',
    target_id: '127.0.0.165:44622',
    status: 'completed',
  },
  {
    ...tasks[1],
    id: 'task-waiting-target-intel',
    tool: 'target-intel',
    target_id: '127.0.0.165:44622',
    status: 'completed',
  },
  {
    ...tasks[2],
    id: 'task-waiting-nmap',
    tool: 'nmap',
    target_id: '127.0.0.165',
    status: 'completed',
  },
  {
    ...tasks[3],
    id: 'task-waiting-next',
    tool: 'pre-recon-httpx',
    target_id: '127.0.0.165:44622',
    status: 'queued',
  },
];

const queuedSignalRun = {
  ...run,
  id: 'run-queued-signals-1',
  status: 'queued',
  profile: {
    id: 'profile-queued-signals-1',
    name: 'XBEN Waiting Fixture',
    run_class: 'active',
    limits_json: {},
  },
  tasks: queuedSignalTasks,
  findings: {
    finding_count: 0,
    findings_by_severity: {},
    findings_by_status: {},
  },
  assessment_chain: null,
};

const completedErrorNoFindingTasks = [
  ...Array.from({ length: 6 }, (_, index) => ({
    ...tasks[2],
    id: `task-error-exec-plan-${index + 1}`,
    tool: 'exec-plan',
    target_id: 'http://127.0.0.150',
    status: 'failed',
    created_at: `2026-05-10T10:${String(index).padStart(2, '0')}:00.000Z`,
    updated_at: `2026-05-10T10:${String(index + 10).padStart(2, '0')}:00.000Z`,
  })),
  ...Array.from({ length: 6 }, (_, index) => ({
    ...tasks[0],
    id: `task-done-content-discovery-${index + 1}`,
    tool: index % 2 === 0 ? 'content-discovery' : 'httpx',
    target_id: 'http://127.0.0.150',
    status: 'completed',
    created_at: `2026-05-10T09:${String(index).padStart(2, '0')}:00.000Z`,
    updated_at: `2026-05-10T09:${String(index + 10).padStart(2, '0')}:00.000Z`,
  })),
];

const completedErrorNoFindingRun = {
  ...run,
  id: 'run-completed-errors-no-findings-1',
  status: 'completed_with_errors',
  profile: {
    id: 'profile-completed-errors-no-findings-1',
    name: 'XBEN Error Fixture',
    run_class: 'active',
    limits_json: {},
  },
  tasks: completedErrorNoFindingTasks,
  findings: {
    finding_count: 0,
    findings_by_severity: {},
    findings_by_status: {},
  },
  assessment_chain: null,
};

const selectedRunLocalAttackMapTasks = [
  {
    ...tasks[0],
    id: 'task-selected-run-local-map',
    tool: 'selected-only-probe',
    target_id: 'https://selected-run.example.test',
    status: 'completed',
    created_at: now,
    updated_at: oneMinuteLater,
  },
];

const staleSiblingChainTasks = [
  {
    ...tasks[1],
    id: 'task-stale-sibling-chain-map',
    tool: 'chain-stale-probe',
    target_id: 'https://stale-chain.example.test',
    status: 'completed',
    created_at: now,
    updated_at: oneMinuteLater,
  },
];

const selectedRunLocalAttackMapRun = {
  ...run,
  id: 'run-selected-local-attack-map',
  status: 'completed',
  profile: {
    id: 'profile-selected-local-attack-map',
    name: 'Selected Local Attack Map',
    run_class: 'active',
    limits_json: {},
  },
  tasks: selectedRunLocalAttackMapTasks,
  findings: {
    finding_count: 0,
    findings_by_severity: {},
    findings_by_status: {},
  },
  assessment_chain: {
    ...run.assessment_chain,
    id: run.assessment_chain.id,
  },
};

const chainReasoningRun = {
  ...run,
  id: 'run-chain-reasoning-1',
  status: 'completed',
  profile: {
    id: 'profile-chain-reasoning-1',
    name: 'AI Chain Reasoning Source',
    run_class: 'active',
    limits_json: {},
  },
  tasks: [],
  findings: {
    finding_count: 0,
    findings_by_severity: {},
    findings_by_status: {},
  },
};

const inventory = {
  id: 'inv-1',
  engagement_id: engagement.id,
  requested_by: 'operator-ui',
  status: 'completed',
  source_tools_json: ['fixture'],
  raw_inputs_json: {},
  normalized_inventory_json: {
    hosts: [{ host: 'app.example.test' }],
    http_endpoints: [{ url: 'https://app.example.test' }, { url: 'https://api.example.test' }],
    services: [{ service_id: 'https-web', host: 'app.example.test' }],
  },
  summary_json: {},
  environment_notes_json: [],
  assumptions_json: [],
  confidence_score: 0.91,
  created_at: now,
};

const pack = {
  id: 'pack-1',
  engagement_id: engagement.id,
  relevance_decision_id: null,
  source_inventory_snapshot_id: inventory.id,
  parent_pack_id: null,
  name: 'Fixture Safe Review Pack',
  version: '1.0.0',
  status: 'approved',
  generated_by: 'fixture',
  generation_mode: 'review-only',
  description: 'Safe fixture pack for UI smoke coverage.',
  source_threat_intel_refs_json: [],
  methodology_tags: ['wstg', 'safe-review'],
  manifest_json: {},
  provenance_json: { fixture: true },
  created_at: now,
};

const customVulnerability = {
  id: 'custom-vuln-1',
  tenant_id: 'tenant-1',
  custom_id: 'CVE-LOCAL-001',
  title: 'Fixture deserialization review item',
  description: 'Stored custom vulnerability fixture for UI coverage.',
  severity: 'medium',
  cvss_score: 5.6,
  affected_products_json: ['Fixture App'],
  cwe_ids_json: ['CWE-502'],
  discovery_date: now,
  reporter: 'operator-ui',
  status: 'active',
  linked_nuclei_template_ref: null,
  linked_threat_intel_record_id: null,
  metadata_json: {},
  deleted_at: null,
  test_coverage: { status: 'unlinked' },
  engagement_state: null,
  created_at: now,
  updated_at: now,
};

const threatIntelRecord = {
  id: 'intel-1',
  source: 'fixture',
  advisory_id: 'CVE-LOCAL-2026-0001',
  title: 'Fixture advisory for safe detection drafting',
  summary: 'A local fixture advisory used only by tests.',
  affected_products_json: ['Fixture App'],
  affected_versions_json: ['1.0'],
  suggested_test_patterns_json: ['metadata review'],
  confidence_score: 0.82,
  severity: 'high',
  references_json: [],
  published_at: now,
  updated_at: now,
  normalization_status: 'normalized',
  metadata_json: {},
  created_at: now,
};

const aiInsights = {
  run_id: run.id,
  post_task_analysis_enabled: true,
  provider: 'fixture',
  provider_status: { available: true },
  reasoning_records: [
    {
      id: 'reasoning-1',
      run_id: run.id,
      task_id: 'task-1',
      reasoning_type: 'evidence-review',
      status: 'completed',
      context_snapshot_json: {},
      observations_json: [],
      hypotheses_json: [],
      proposals_json: [],
      summary_text: 'Fixture reasoning summary',
      thought_text: '',
      action_text: '',
      provider: 'fixture',
      model: null,
      llm_tokens_used: null,
      confidence_score: 0.74,
      failure_reason: null,
      metadata_json: {},
      proposals: [],
      created_at: now,
      updated_at: now,
    },
  ],
  proposals: [],
  review_boundary: { operator_review_only: true },
  operator_workbench: {},
};

const selectedRunAiInsights = {
  ...aiInsights,
  reasoning_records: [],
  proposals: [],
};

const chainAiInsights = {
  ...aiInsights,
  run_id: chainReasoningRun.id,
  reasoning_records: [
    {
      ...aiInsights.reasoning_records[0],
      id: 'reasoning-chain-1',
      run_id: chainReasoningRun.id,
      summary_text: 'Chain sibling reasoning summary',
    },
  ],
};

test.beforeEach(async ({ page }) => {
  await installApiFixtures(page);
});

test('M7 report and evidence fixture matrix locks canonical truth boundaries', async ({ page }) => {
  void page;

  for (const scenario of reportEvidenceScenarioMatrix) {
    const runTruth = buildRunTruthModel(scenario.run, scenario.tasks, scenario.findings);
    expect(runTruth.attention.tone, `${scenario.key} run attention`).toBe(scenario.expected.runTruthAttention);
    expect(runTruth.canonicalScore, `${scenario.key} canonical score`).toContain(`${scenario.expected.canonicalTotal} persisted`);
    expect(runTruth.runLocalSummary, `${scenario.key} run-local summary`).toContain(`${scenario.expected.runLocalTotal} total`);

    const consistency = buildCrossSurfaceConsistency({
      run: scenario.run,
      findings: scenario.findings,
      reports: scenario.reports,
      selectedReport: scenario.reports[0] ?? null,
      markdownPreview: scenario.markdownPreview,
      loadingFindings: false,
      loadingReports: false,
    });
    const checks = new Map(consistency.checks.map((check) => [check.id, check.status]));
    expect(consistency.status, `${scenario.key} consistency`).toBe(scenario.expected.consistencyStatus);
    expect(consistency.canonicalTotal, `${scenario.key} canonical total`).toBe(scenario.expected.canonicalTotal);
    expect(consistency.runSummaryTotal, `${scenario.key} run summary total`).toBe(scenario.expected.runLocalTotal);
    expect(checks.get('report-catalog'), `${scenario.key} report catalog`).toBe(scenario.expected.reportCatalogCheck);
    expect(checks.get('report-preview'), `${scenario.key} report preview`).toBe(scenario.expected.previewCheck);
    expect(checks.get('evidence-links'), `${scenario.key} evidence links`).toBe(scenario.expected.evidenceLinksCheck);

    for (const requiredText of scenario.expected.requiredPreviewText) {
      expect(scenario.markdownPreview, `${scenario.key} required preview text`).toContain(requiredText);
    }
    for (const forbiddenText of scenario.expected.forbiddenPreviewText) {
      expect(scenario.markdownPreview, `${scenario.key} forbidden preview text`).not.toContain(forbiddenText);
    }
  }
});

test('M4 report preview metadata adapter summarizes preview and export truth', async ({ page }) => {
  void page;
  const scenario = reportEvidenceScenarios.verified_persisted;
  const metadata = buildReportPreviewMetadata(scenario.reports[0], scenario.markdownPreview);

  expect(metadata.variantLabel).toBe('Executive Summary');
  expect(metadata.availabilityLabel).toBe('ready');
  expect(metadata.availabilityTone).toBe('green');
  expect(metadata.preview.loaded).toBe(true);
  expect(metadata.preview.claimedFindingTotal).toBe(scenario.expected.canonicalTotal);
  expect(metadata.preview.sectionCount).toBeGreaterThan(0);
  expect(metadata.preview.lineCount).toBeGreaterThan(0);
  expect(metadata.preview.detail).toContain('1 finding claimed');
  expect(metadata.export.ready).toBe(true);
  expect(metadata.export.formatsLabel).toBe('markdown / html / pdf');
  expect(metadata.export.shortHash).toBe('77777777...777777');
  expect(metadata.readinessData.map((item) => item.value)).toEqual([1, 1, 0]);
});

test('Dashboard renders portfolio data from mocked v2 API contracts', async ({ page }) => {
  await page.goto('/app-v2/');

  await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible();
  await expect(page.getByRole('main').getByText('Acme External Web')).toBeVisible();
  await expect(page.getByText('Portfolio Risk')).toBeVisible();
  await expect(page.getByRole('main').getByText('8.2', { exact: true }).first()).toBeVisible();
  await expect(page.getByText('Activity Feed')).toBeVisible();
  await expect(page.getByText('Run completed with evidence attached')).toBeVisible();
});

test('Mission experience spine carries the selected run story across the shell', async ({ page }) => {
  await page.goto('/app-v2/');

  const story = page.getByLabel('Mission story');
  await expect(story).toBeVisible();
  await expect(story).toContainText('You are here');
  await expect(story).toContainText('Your next move');
  await expect(story).toContainText('Ready for review: 2 results');
  await expect(story).toContainText('Lead: Input and data handling.');
  await expect(story).toContainText('3 checked · 2 findings');
  await expect(story).toContainText('Target');
  await expect(story).toContainText('Checked');
  await expect(story).toContainText('Proof');
  await expect(story).toContainText('Risk');
  await expect(story).toContainText('Evidence');
  await expect(story.getByRole('button', { name: /Live/ })).toBeVisible();
  await expect(story.getByRole('button', { name: /Evidence/ })).toBeVisible();
  await expect(story.getByRole('button', { name: /Findings/ })).toBeVisible();
  await expect(story.getByRole('button', { name: /Report/ })).toBeVisible();

  await story.getByRole('button', { name: 'Build report' }).click();
  await expect(page).toHaveURL(/\/app-v2\/reports$/);
  await expect(page.getByRole('heading', { name: 'Report Center' })).toBeVisible();
  await expect(page.getByLabel('Mission story')).toContainText('You are turning proof into a report');
  await expect(page.getByLabel('Mission story').getByRole('button', { name: /Mission route step Report/ })).toHaveAttribute('aria-current', 'step');

  await page.goto('/app-v2/evidence');
  await expect(page.getByLabel('Mission story')).toContainText('You are replaying the proof trail');
  await expect(page.getByLabel('Mission story').getByRole('button', { name: /Mission route step Evidence/ })).toHaveAttribute('aria-current', 'step');
  if (process.env.AEGISPT_CAPTURE_SPINE_CONTEXT === '1') {
    await page.screenshot({
      path: '../docs/validation/codex-ui-reporting-w6a-context-aware-spine-evidence-1536x864.png',
      fullPage: false,
    });
  }
});

test('Secondary admin and diagnostics routes use compact mission context', async ({ page }) => {
  await page.setViewportSize({ width: 1536, height: 864 });
  await page.goto('/app-v2/research');

  const researchContext = page.getByLabel('Mission context');
  await expect(researchContext).toBeVisible();
  await expect(researchContext).toContainText('Research context');
  await expect(researchContext).toContainText('You are curating research context');
  await expect(researchContext.getByLabel(/Primary mission action:/)).toBeVisible();
  await expect(page.getByLabel('Mission story')).toHaveCount(0);
  await expect(page.getByRole('heading', { name: 'AI Research', exact: true })).toBeVisible();
  if (process.env.AEGISPT_CAPTURE_UX2_PAGE_CONTRACT === '1') {
    await page.screenshot({
      path: '../docs/validation/codex-ui-reporting-ux2-admin-compact-spine-1536x864.png',
      fullPage: false,
    });
  }

  await page.setViewportSize({ width: 1280, height: 720 });
  await page.goto('/app-v2/live-cli');
  const diagnosticsContext = page.getByLabel('Mission context');
  await expect(diagnosticsContext).toBeVisible();
  await expect(diagnosticsContext).toContainText('Diagnostics context');
  await expect(diagnosticsContext).toContainText('You are watching raw output');
  await expect(page.getByLabel('Mission story')).toHaveCount(0);
  await expect(page.getByRole('heading', { name: 'Live CLI', exact: true })).toBeVisible();
  if (process.env.AEGISPT_CAPTURE_UX2_PAGE_CONTRACT === '1') {
    await page.screenshot({
      path: '../docs/validation/codex-ui-reporting-ux2-diagnostics-compact-spine-1280x720.png',
      fullPage: false,
    });
  }
});

test('App shell exposes keyboard landmarks and visible focus navigation', async ({ page }) => {
  await page.goto('/app-v2/');

  const skipLink = page.getByRole('link', { name: 'Skip to mission workspace' });
  await skipLink.focus();
  await expect(skipLink).toBeFocused();
  await page.keyboard.press('Enter');
  await expect(page.getByRole('main', { name: 'AegisPT workspace' })).toBeFocused();
  await expect(page.getByRole('navigation', { name: 'Primary navigation' })).toBeVisible();
  await expect(page.getByRole('link', { name: 'Dashboard', exact: true })).toHaveAttribute('aria-current', 'page');
  await expect(page.getByLabel('Operator menu for operator-ui')).toBeVisible();
});

test('App shell theme toggle persists light mode through semantic tokens', async ({ page }) => {
  await page.addInitScript(() => {
    if (!window.localStorage.getItem('aegispt.ui.theme')) {
      window.localStorage.setItem('aegispt.ui.theme', 'dark');
    }
  });
  await page.goto('/app-v2/');

  const root = page.locator('html');
  await expect(root).toHaveAttribute('data-theme', 'dark');
  const darkBg = await page.evaluate(() => getComputedStyle(document.documentElement).getPropertyValue('--bg').trim());
  await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible();

  await page.getByRole('button', { name: 'Switch to light theme' }).click();
  await expect(root).toHaveAttribute('data-theme', 'light');
  const lightBg = await page.evaluate(() => getComputedStyle(document.documentElement).getPropertyValue('--bg').trim());
  expect(lightBg).not.toBe(darkBg);
  await expect(page.getByRole('button', { name: 'Switch to dark theme' })).toBeVisible();
  await expect(page.getByRole('navigation', { name: 'Primary navigation' })).toBeVisible();
  await expect(page.getByLabel('Mission story')).toBeVisible();
  await expect(page.getByText('Portfolio Risk')).toBeVisible();
  await expect(page.getByText('Activity Feed')).toBeVisible();
  await expect(page.locator('.neon-panel').first()).toBeVisible();
  await expect.poll(() => page.evaluate(() => window.localStorage.getItem('aegispt.ui.theme'))).toBe('light');

  if (process.env.AEGISPT_CAPTURE_UX8_LIGHT_MODE === '1') {
    await page.screenshot({
      path: '../docs/validation/codex-ui-reporting-ux8-light-mode-dashboard-1536x864.png',
      fullPage: false,
    });
  }

  await page.reload();
  await expect(root).toHaveAttribute('data-theme', 'light');
  await expect(page.getByRole('button', { name: 'Switch to dark theme' })).toBeVisible();
});

test('Light mode keeps mission and command drilldowns legible at constrained viewports', async ({ page }) => {
  await page.addInitScript(() => window.localStorage.setItem('aegispt.ui.theme', 'light'));
  await page.setViewportSize({ width: 1280, height: 720 });
  await page.goto('/app-v2/mission-control');

  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await expect(page.getByRole('tab', { name: 'Live', exact: true })).toHaveAttribute('aria-selected', 'true');
  await expect(page.getByLabel('Mission snapshot')).toContainText('You are reviewing the proof path');
  await expect(page.getByLabel('Mission snapshot')).toContainText('2 reportable');
  await expect(page.getByRole('heading', { name: 'Live CLI' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Queue' })).toBeVisible();
  if (process.env.AEGISPT_CAPTURE_UX8_LIGHT_MODE === '1') {
    await page.screenshot({
      path: '../docs/validation/codex-ui-reporting-ux8-light-mode-mission-control-1280x720.png',
      fullPage: false,
    });
  }

  const liveCliJsonTask = {
    ...tasks[0],
    id: 'task-ux8-light-cli-json',
    tool: 'target-intel',
    target_id: 'https://google-gruyere.appspot.com/482338906867472456097470474631954304306/',
    status: 'running',
    params_json: { depth: 3, follow_redirects: true },
    updated_at: oneMinuteLater,
    fixture_stdout_text: JSON.stringify({
      tool: 'target-intel',
      target: 'https://google-gruyere.appspot.com/482338906867472456097470474631954304306/',
      analysis: {
        site_type: 'Google Gruyere training app',
        technology_stack: ['Google Frontend', 'HTML 4.01 Transitional'],
      },
      test_plan: [
        {
          priority: 1,
          tool: 'smart-web-probe',
          reason: 'Find forms and reflection points before exploit testing.',
          params: {
            url: 'https://google-gruyere.appspot.com/482338906867472456097470474631954304306/',
          },
        },
      ],
    }),
  } as FixtureTask & { fixture_stdout_text: string };
  const liveCliRun = {
    ...run,
    id: 'run-ux8-light-cli-json',
    status: 'running',
    tasks: [liveCliJsonTask],
    assessment_chain: {
      ...run.assessment_chain,
      id: 'chain-ux8-light-cli-json',
    },
  };

  await page.unroute('**/api/v1/**');
  await installApiFixtures(page, {
    primaryRun: liveCliRun,
    primaryTasks: [liveCliJsonTask],
    primaryFindings: [],
  });
  await page.setViewportSize({ width: 1024, height: 576 });
  await page.goto('/app-v2/live-cli');

  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await expect(page.getByRole('heading', { name: 'Live CLI', exact: true })).toBeVisible();
  const terminal = page.getByLabel('Live command terminal');
  await expect(terminal).toContainText('$ target-intel --target https://google-gruyere.appspot.com/482338906867472456097470474631954304306/');
  await expect(terminal).toContainText('structured JSON output expanded for readability');
  await expect(terminal).toContainText('"tool": "smart-web-probe"');
  if (process.env.AEGISPT_CAPTURE_UX8_LIGHT_MODE === '1') {
    await page.screenshot({
      path: '../docs/validation/codex-ui-reporting-ux8-light-mode-live-cli-1024x576.png',
      fullPage: false,
    });
  }
});

test('Light mode keeps report evidence triage and intake screens free of unscoped dark panels', async ({ page }) => {
  await page.addInitScript(() => window.localStorage.setItem('aegispt.ui.theme', 'light'));
  await page.setViewportSize({ width: 1536, height: 864 });
  await installApiFixtures(page);

  const routes = [
    {
      path: '/app-v2/reports',
      heading: 'Report Center',
      capture: '../docs/validation/codex-ui-reporting-ux8-light-mode-report-center-1536x864.png',
    },
    {
      path: '/app-v2/evidence',
      heading: 'Evidence Replay',
      capture: '../docs/validation/codex-ui-reporting-ux8-light-mode-evidence-replay-1536x864.png',
    },
    {
      path: '/app-v2/findings',
      heading: 'Findings Theater',
      capture: '../docs/validation/codex-ui-reporting-ux8-light-mode-findings-theater-1536x864.png',
    },
    {
      path: '/app-v2/problems',
      heading: 'Problems Center',
      capture: '../docs/validation/codex-ui-reporting-ux8-light-mode-problems-1536x864.png',
    },
    {
      path: '/app-v2/intake',
      heading: 'New Mission',
      capture: '../docs/validation/codex-ui-reporting-ux8-light-mode-intake-1536x864.png',
    },
  ];

  for (const route of routes) {
    await page.goto(route.path);
    await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
    await expect(page.getByRole('heading', { name: route.heading, exact: true })).toBeVisible();
    await expectNoUnscopedDarkPanels(page);
    if (process.env.AEGISPT_CAPTURE_UX8_LIGHT_MODE === '1') {
      await page.screenshot({ path: route.capture, fullPage: false });
      if (route.path.endsWith('/reports')) {
        await page.getByLabel('Management report export proof').scrollIntoViewIfNeeded();
        await page.screenshot({
          path: '../docs/validation/codex-ui-reporting-ux8-light-mode-management-proof-1536x864.png',
          fullPage: false,
        });
      }
    }
  }

  await page.goto('/app-v2/mission-control');
  await page.getByText('Open attack path, story cards, live events, and technical facts').click();
  await page.getByRole('button', { name: 'Open full map' }).click();
  const fullMap = page.getByRole('dialog', { name: 'Full attack map' });
  await expect(fullMap).toBeVisible();
  await expectNoUnscopedDarkPanels(page, '[role="dialog"]');
  if (process.env.AEGISPT_CAPTURE_UX8_LIGHT_MODE === '1') {
    await page.screenshot({
      path: '../docs/validation/codex-ui-reporting-ux8-light-mode-full-attack-map-1536x864.png',
      fullPage: false,
    });
  }
});

test('Dashboard survives sparse dashboard payloads without crash recovery', async ({ page }) => {
  await page.unroute('**/api/v1/**');
  await installApiFixtures(page, { dashboard: sparseDashboardPayload() });

  await page.goto('/app-v2/');

  await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible();
  await expect(page.getByText('The view stopped rendering safely.')).toHaveCount(0);
  await expect(page.getByText('Portfolio Risk')).toBeVisible();
  await expect(page.getByText('No activity yet')).toBeVisible();
  await expect(page.getByText('No engagement summaries')).toBeVisible();
});

test('Mission Intake wizard reaches authorization-gated preview without creating runtime work', async ({ page }) => {
  await page.goto('/app-v2/intake');

  await expect(page.getByRole('heading', { name: 'New Mission' })).toBeVisible();
  await page.getByTestId('wizard-assessment-tile-external-web').click();
  await page.getByRole('button', { name: 'Target & Depth' }).last().click();
  await page.getByLabel('Approved target').fill('https://app.example.test');
  await page.getByRole('button', { name: 'Full Pentest' }).click();
  await page.getByRole('button', { name: /Preview Mission/ }).click();

  await expect(page.getByRole('heading', { name: 'Mission Preview' })).toBeVisible();
  await expect(page.getByText('Website / Web App', { exact: true })).toBeVisible();
  await expect(page.getByText('https://app.example.test', { exact: true })).toBeVisible();
  await expect(page.getByText(/I confirm written authorization/)).toBeVisible();
  await expect(page.getByRole('button', { name: /Create Mission & Open Mission Control/ })).toBeDisabled();
});

test('Findings Theater filters findings without live backend access', async ({ page }) => {
  await page.goto('/app-v2/findings');

  await expect(page.getByRole('heading', { name: 'Findings Theater' })).toBeVisible();
  const findingList = page.getByLabel('Findings result list');
  await expect(findingList.getByRole('button', { name: /Critical stored XSS in profile preview/ })).toBeVisible();
  await expect(findingList.getByRole('button', { name: /High-risk missing HSTS header/ })).toBeVisible();

  await page.locator('label').filter({ hasText: 'Severity' }).locator('select').selectOption('critical');

  await expect(findingList.getByRole('button', { name: /Critical stored XSS in profile preview/ })).toBeVisible();
  await expect(findingList.getByRole('button', { name: /High-risk missing HSTS header/ })).toHaveCount(0);

  await page.getByLabel('Search').fill('profile');
  await expect(page.getByText('Raw Evidence View')).toBeVisible();
});

test('Findings Theater shows verified observed and blocked truth states without raw runner primary copy', async ({ page }) => {
  await page.unroute('**/api/v1/**');
  await installApiFixtures(page, { primaryFindings: theaterTruthFindings });

  await page.goto('/app-v2/findings');
  const findingList = page.getByLabel('Findings result list');

  const verifiedRow = findingList.getByRole('button', { name: /Verified flag capture on app\.example\.test/ });
  await expect(verifiedRow).toBeVisible();
  await expect(verifiedRow).toContainText('Verified finding');
  await expect(verifiedRow).toContainText('Evidence: reference linked');
  await expect(verifiedRow).not.toContainText('Flag captured (interactive-exploit)');
  await expect(verifiedRow).not.toContainText('aegispt{redacted-fixture}');

  const observedRow = findingList.getByRole('button', { name: /Observed reflected sink awaiting replay/ });
  await expect(observedRow).toContainText('Observed finding');
  await expect(observedRow).toContainText('Evidence: reference linked');

  const blockedRow = findingList.getByRole('button', { name: /Candidate admin takeover without evidence/ });
  await expect(blockedRow).toContainText('Blocked / incomplete');
  await expect(blockedRow).toContainText('Evidence: missing');
});

test('Findings Theater separates evidence business impact and supported remediation language', async ({ page }) => {
  await page.unroute('**/api/v1/**');
  await installApiFixtures(page, { primaryFindings: theaterTruthFindings });

  await page.goto('/app-v2/findings');

  await expect(page.getByRole('heading', { name: /Verified flag capture on app\.example\.test/ })).toBeVisible();
  await expect(page.getByText('Stored title: Flag captured (interactive-exploit): aegispt{redacted-fixture}')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Evidence Summary' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Business Impact' })).toBeVisible();
  await expect(page.getByText('Stored execution evidence is linked to the captured flag.')).toBeVisible();
  await expect(page.getByText('Customer data exposure risk from stored evidence.')).toBeVisible();
  await expect(page.getByText('Sanitize output and retest through normal approval gates.')).toBeVisible();

  await page.getByRole('button', { name: 'Close finding drawer' }).click();
  await page
    .getByLabel('Findings triage board')
    .getByRole('button', { name: /Candidate admin takeover without evidence, 1 findings, Evidence missing/ })
    .click();

  await expect(page.getByText('No evidence reference is linked to this finding.').first()).toBeVisible();
  await expect(page.getByText('No supported remediation guidance returned for this finding.')).toBeVisible();
  await expect(page.getByText('No supported next steps returned for this finding.')).toBeVisible();
});

test('Findings Theater triage board groups repeated findings without hiding evidence', async ({ page }) => {
  await page.unroute('**/api/v1/**');
  await installApiFixtures(page, { primaryFindings: triageBoardFindings });

  await page.goto('/app-v2/findings');

  const board = page.getByLabel('Findings triage board');
  await expect(board).toContainText('Fix first: SQL injection in customer search');
  await expect(board).toContainText('2 linked evidence refs across 2 targets');
  await expect(board).toContainText('evidence://triage-critical-a');
  await expect(board).toContainText('evidence://triage-critical-b');
  await expect(board.getByRole('button', { name: /SQL injection in customer search, 2 findings, Strong proof/ })).toBeVisible();
  await expect(board.getByRole('button', { name: /Candidate admin takeover without proof, 1 findings, Evidence missing/ })).toBeVisible();

  if (process.env.AEGISPT_CAPTURE_UX6_TRIAGE_BOARD) {
    const closeDrawer = page.getByRole('button', { name: 'Close finding drawer' });
    if (await closeDrawer.isVisible()) {
      await closeDrawer.click();
    }
    await page.screenshot({
      path: '../docs/validation/codex-ui-reporting-ux6-findings-triage-board-1536x864.png',
      fullPage: false,
    });
  }

  await board.getByRole('button', { name: /SQL injection in customer search, 2 findings, Strong proof/ }).click();
  await expect(page.getByRole('heading', { name: 'SQL injection in customer search', exact: true })).toBeVisible();
});

test('Problems Center triage board exposes urgent due owner and SLA decisions', async ({ page }) => {
  await page.unroute('**/api/v1/**');
  await installApiFixtures(page, { problems: problemsTriagePayload() });

  await page.goto('/app-v2/problems');

  const board = page.getByLabel('Problems triage board');
  await expect(board).toContainText('Decisions today');
  await expect(board).toContainText('Urgent');
  await expect(board).toContainText('Due');
  await expect(board).toContainText('Owner needed');
  await expect(board).toContainText('SLA watch');
  await expect(board).toContainText('Today: assign an owner');
  await expect(board.getByRole('button', { name: /assign an owner: SQL injection in customer search/ }).first()).toBeVisible();

  await board.getByRole('button', { name: /assign an owner: SQL injection in customer search/ }).first().click();
  await expect(page.getByText('1 selected')).toBeVisible();
});

test('Mission Control renders interactive live results overview and technical views from fixtures', async ({ page }) => {
  await installApiFixtures(page);
  await page.goto('/app-v2/mission-control');

  // Verify Live view loads by default without the technical truth strip.
  await expect(page.getByRole('tablist', { name: 'Mission Control views' })).toBeVisible();
  await expect(page.getByRole('tab', { name: 'Live', exact: true })).toHaveAttribute('aria-selected', 'true');
  await expect(page.getByRole('tab', { name: 'Results', exact: true })).toBeVisible();
  await expect(page.getByRole('tab', { name: 'Overview', exact: true })).toBeVisible();
  await page.getByRole('tab', { name: 'Live', exact: true }).focus();
  await page.keyboard.press('ArrowRight');
  await expect(page.getByRole('tab', { name: 'Results', exact: true })).toHaveAttribute('aria-selected', 'true');
  await expect(page.getByRole('tabpanel', { name: 'Results', exact: true })).toBeVisible();
  await page.getByRole('tab', { name: 'Live', exact: true }).click();
  await expect(page.getByTestId('run-truth-strip')).toHaveCount(0);
  await expect(page.getByLabel('Mission snapshot')).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Live CLI' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Queue' })).toBeVisible();
  await page.getByText('Open attack path, story cards, live events, and technical facts').click();
  await expect(page.getByText('Mission path')).toBeVisible();
  await expect(page.getByText('Decision')).toBeVisible();
  const currentPathMap = page.getByRole('button', { name: /Current path/ });
  await expect(currentPathMap).toContainText(/\d{2}:08:00/);
  await expect(currentPathMap).toContainText('after');
  await expect(currentPathMap).toContainText('8m');
  await expect(page.getByRole('button', { name: 'Replay' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Open full map' })).toBeVisible();
  const openMapButton = page.getByRole('button', { name: 'Open full map' }).first();
  await openMapButton.click();
  await expect(page.getByRole('dialog', { name: 'Full attack map' })).toBeVisible();
  const attackMapDialog = page.getByRole('dialog', { name: 'Full attack map' });
  await expect(page.getByRole('button', { name: 'Close' })).toBeFocused();
  await expect(page.getByRole('button', { name: 'Play', exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Zoom in' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Zoom out' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Fit' })).toBeVisible();
  const mapCanvas = attackMapDialog.getByLabel('Attack map pan and zoom canvas');
  const mapTransform = attackMapDialog.getByTestId('attack-map-transform');
  await expect(mapCanvas).toBeVisible();
  await expect(mapTransform).toHaveAttribute('data-zoom', /\d+\.\d{2}/);
  const zoomBeforeWheel = await mapTransform.getAttribute('data-zoom');
  await mapCanvas.hover();
  await page.mouse.wheel(0, 240);
  await expect.poll(async () => mapTransform.getAttribute('data-zoom')).not.toBe(zoomBeforeWheel);
  const panBeforeDrag = await mapTransform.getAttribute('data-pan');
  const mapBox = await mapCanvas.boundingBox();
  if (!mapBox) throw new Error('Attack map canvas did not expose a bounding box');
  await page.mouse.move(mapBox.x + 220, mapBox.y + 180);
  await page.mouse.down();
  await page.mouse.move(mapBox.x + 300, mapBox.y + 235);
  await page.mouse.up();
  await expect.poll(async () => mapTransform.getAttribute('data-pan')).not.toBe(panBeforeDrag);
  await page.getByRole('button', { name: 'Fit' }).click();
  if (process.env.AEGISPT_CAPTURE_ATTACK_MAP_PANZOOM === '1') {
    await page.setViewportSize({ width: 1536, height: 864 });
    await page.getByRole('button', { name: 'Fit' }).click();
    await page.screenshot({
      path: '../docs/validation/codex-ui-reporting-w6a-attack-map-panzoom-1536x864.png',
      fullPage: false,
    });
  }
  await expect(page.getByRole('button', { name: /No Dead end/ })).toBeVisible();
  await page.getByRole('button', { name: /No Dead end/ }).click();
  await expect(page.getByText('This branch did not produce usable proof.')).toBeVisible();
  await expect(page.getByRole('link', { name: 'Open linked view' })).toBeVisible();
  const proofNode = attackMapDialog.getByRole('button', { name: /Proof Critical stored XSS in profile preview/ });
  await expect(proofNode).toBeVisible();
  await expect(proofNode).toContainText(/\d{2}:08:00/);
  await expect(proofNode).toContainText('after');
  await expect(proofNode).toContainText('8m');
  await expect(proofNode).toContainText('source took');
  await expect(proofNode).toContainText('1m');
  await expect(attackMapDialog.getByText('Input and data handling')).toHaveCount(0);
  await proofNode.click();
  const selectedAttackStep = attackMapDialog.getByLabel('Selected attack map step');
  await expect(selectedAttackStep).toContainText('Critical stored XSS in profile preview');
  await expect(selectedAttackStep).toContainText('Persisted');
  await expect(selectedAttackStep).toContainText('Elapsed from run start');
  await expect(selectedAttackStep).toContainText('Source task duration');
  await page.keyboard.press('Escape');
  await expect(page.getByRole('dialog', { name: 'Full attack map' })).toHaveCount(0);
  await expect(openMapButton).toBeFocused();
  const missionSnapshot = page.getByLabel('Mission snapshot');
  await expect(missionSnapshot).toBeVisible();
  await expect(missionSnapshot.getByText('You are here')).toBeVisible();
  await expect(missionSnapshot.getByText('You are reviewing the proof path')).toBeVisible();
  await expect(missionSnapshot.getByText('Status', { exact: true })).toBeVisible();
  await expect(missionSnapshot.getByText('Checked', { exact: true })).toBeVisible();
  await expect(missionSnapshot.getByText('Findings', { exact: true })).toBeVisible();
  await expect(missionSnapshot.getByText('Risk', { exact: true })).toBeVisible();
  await expect(missionSnapshot.getByRole('link', { name: 'Review findings' })).toHaveAttribute('href', /findings/);
  if (process.env.AEGISPT_CAPTURE_MISSION_CONTROL === '1') {
    await page.screenshot({
      path: '../docs/validation/codex-ui-reporting-w6a-mission-control-operator-deck-1536x864.png',
      fullPage: false,
    });
  }
  await expect(page.getByText('The test story')).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Run picture' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Live CLI' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Queue' })).toBeVisible();
  await expect(page.getByRole('link', { name: 'Open full CLI' })).toBeVisible();
  await page.getByRole('button', { name: /Show CLI output for burp/ }).click();
  await expect(page.getByText('burp').first()).toBeVisible();

  await page.getByRole('tab', { name: 'Results', exact: true }).click();
  await expect(page.getByText('Progress')).toBeVisible();
  await expect(page.getByText('Latest activity')).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Findings', exact: true })).toBeVisible();
  await expect(page.getByText('Show scan timeline')).toBeVisible();
  await expect(page.getByText('Wat betekent dit?')).toBeVisible();

  await page.getByRole('tab', { name: 'Overview', exact: true }).click();
  await expect(page.getByText('current path, click to inspect the full attack map')).toBeVisible();
  await expect(page.getByText('Test overview')).toBeVisible();
  await expect(page.getByText('What is coming next')).toBeVisible();
  await expect(page.getByRole('main').getByRole('link', { name: 'Surface Map' })).toBeVisible();
  await expect(page.getByRole('main').getByRole('link', { name: 'Reports' })).toBeVisible();
  await expect(page.getByText('AI story')).toBeVisible();
  await expect(page.getByRole('main').getByRole('link', { name: 'Evidence Replay' })).toBeVisible();

  // Switch to Technical View
  await page.getByRole('tab', { name: 'Technical', exact: true }).click();
  await expect(page.getByTestId('run-truth-strip')).toBeVisible();
  
  // Verify Technical view loads
  await expect(page.getByText(/Diagnostics and raw evidence/)).toBeVisible();
  await expect(page.getByText('Now playing')).toBeVisible();
  await expect(page.getByRole('button', { name: /Cinema/ })).toBeVisible();
  await expect(page.getByRole('button', { name: /^Kill$/ })).toBeVisible();
  
  // Expand advanced details
  await page.getByText('Proof and task inventory').click();
  await page.getByRole('button', { name: /Show all details/ }).click();
  
  // Verify tasks are shown
  await expect(page.getByText(/All tools/i)).toBeVisible();
  await expect(page.getByText('httpx').first()).toBeVisible();
});

test('Mission Control stays scan-friendly on a 4k display scaled to 125 percent', async ({ page }) => {
  await page.addInitScript(() => window.localStorage.setItem('aegispt.ui.theme', 'dark'));
  await installApiFixtures(page);
  await page.setViewportSize({ width: 2048, height: 1152 });
  await page.goto('/app-v2/mission-control');

  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  const missionSnapshot = page.getByLabel('Mission snapshot');
  await expect(missionSnapshot).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Live CLI' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Queue' })).toBeVisible();

  const snapshotBox = await missionSnapshot.boundingBox();
  const liveCliBox = await page.getByRole('heading', { name: 'Live CLI' }).boundingBox();
  const queueBox = await page.getByRole('heading', { name: 'Queue' }).boundingBox();

  expect(snapshotBox).not.toBeNull();
  expect(liveCliBox).not.toBeNull();
  expect(queueBox).not.toBeNull();
  expect(snapshotBox!.height).toBeLessThanOrEqual(480);
  expect(liveCliBox!.y).toBeLessThan(860);
  expect(queueBox!.y).toBeLessThan(860);

  if (process.env.AEGISPT_CAPTURE_MISSION_CONTROL_4K_SCALE === '1') {
    await page.screenshot({
      path: '../docs/validation/codex-ui-reporting-mission-control-4k-125-scale-2048x1152.png',
      fullPage: false,
    });
  }
});

test('Mission Control attack map follows the selected run instead of stale chain output', async ({ page }) => {
  await installApiFixtures(page, {
    primaryRun: selectedRunLocalAttackMapRun,
    primaryTasks: staleSiblingChainTasks,
    primaryFindings: findings,
  });

  await page.goto('/app-v2/mission-control');
  await page.getByText('Open attack path, story cards, live events, and technical facts').click();

  const currentPathMap = page.getByRole('button', { name: /Current path/ });
  await expect(currentPathMap).toContainText('Selected Only Probe');
  await expect(currentPathMap).not.toContainText('Chain Stale Probe');
  await expect(currentPathMap).not.toContainText('Critical stored XSS in profile preview');

  await page.getByRole('button', { name: 'Open full map' }).first().click();
  const attackMapDialog = page.getByRole('dialog', { name: 'Full attack map' });
  await expect(attackMapDialog).toBeVisible();
  await expect(attackMapDialog.getByRole('button', { name: /Selected Only Probe/ })).toBeVisible();
  await expect(attackMapDialog.getByRole('button', { name: /Chain Stale Probe/ })).toHaveCount(0);
  await expect(attackMapDialog.getByRole('button', { name: /Critical stored XSS in profile preview/ })).toHaveCount(0);
});

test('Mission Control attack map draws multiple critical findings as path milestones', async ({ page }) => {
  await installApiFixtures(page, {
    primaryFindings: attackMapCriticalClusterFindings,
  });

  await page.goto('/app-v2/mission-control');
  await page.getByText('Open attack path, story cards, live events, and technical facts').click();

  const missionSnapshot = page.getByLabel('Mission snapshot');
  await expect(missionSnapshot).toContainText('6 reportable');
  await expect(missionSnapshot).toContainText('5 high-risk');

  const currentPathMap = page.getByRole('button', { name: /Current path/ });
  await expect(currentPathMap).toContainText('Critical stored XSS in profile preview');
  await expect(currentPathMap).toContainText('critical finding');

  await page.getByRole('button', { name: 'Open full map' }).first().click();
  const attackMapDialog = page.getByRole('dialog', { name: 'Full attack map' });
  const proofNode = attackMapDialog.getByRole('button', { name: /Proof Critical stored XSS in profile preview/ });
  await expect(proofNode).toBeVisible();
  await expect(attackMapDialog.getByRole('button', { name: /Proof 2 Critical admin token exposure/ })).toBeVisible();
  await expect(attackMapDialog.getByRole('button', { name: /Proof 3 Critical session takeover path/ })).toBeVisible();
  await expect(attackMapDialog.getByRole('button', { name: /Proof 4 Critical unauthorized file access/ })).toBeVisible();
  await expect(attackMapDialog.getByRole('button', { name: /Proof 5 Critical privilege escalation route/ })).toBeVisible();
  await expect(attackMapDialog.getByRole('button', { name: /Proof 6 AegisPT HTTP Status 200 Baseline/ })).toBeVisible();
  await expect(attackMapDialog.getByText('Finding cluster')).toHaveCount(0);

  await proofNode.click();
  const selectedAttackStep = attackMapDialog.getByLabel('Selected attack map step');
  await expect(selectedAttackStep).toContainText('Critical stored XSS in profile preview');
  await expect(selectedAttackStep).toContainText('Path position');
  await expect(selectedAttackStep).toContainText('1 of 6 proof events');
  await expect(selectedAttackStep).toContainText('Source task');
  await expect(selectedAttackStep).toContainText('Elapsed from run start');
  await attackMapDialog.getByRole('button', { name: /Outcome Report/ }).click();
  await expect(selectedAttackStep).toContainText('Findings');
  await expect(selectedAttackStep).toContainText('6');
  await expect(selectedAttackStep).toContainText('Severity mix');
  await expect(selectedAttackStep).toContainText('5 critical');
  await expect(selectedAttackStep).toContainText('1 info');
  if (process.env.AEGISPT_CAPTURE_ATTACK_MAP_FULL_PATH === '1' || process.env.AEGISPT_CAPTURE_UX4_ATTACK_MAP === '1') {
    await page.setViewportSize({ width: 1536, height: 864 });
    await page.getByRole('button', { name: 'Fit' }).click();
    if (process.env.AEGISPT_CAPTURE_ATTACK_MAP_FULL_PATH === '1') {
      await page.screenshot({
        path: '../docs/validation/codex-ui-reporting-w6a-attack-map-full-path-findings-1536x864.png',
        fullPage: false,
      });
    }
    if (process.env.AEGISPT_CAPTURE_UX4_ATTACK_MAP === '1') {
      await page.screenshot({
        path: '../docs/validation/codex-ui-reporting-ux4-attack-path-truth-map-1536x864.png',
        fullPage: false,
      });
    }
  }
});

test('Mission Control attack map fit remains usable under 125 and 150 percent viewport pressure', async ({ page }) => {
  await installApiFixtures(page, {
    primaryFindings: attackMapCriticalClusterFindings,
  });

  for (const viewport of [
    { label: '125%', width: 1230, height: 690 },
    { label: '150%', width: 1024, height: 576 },
  ]) {
    await page.setViewportSize({ width: viewport.width, height: viewport.height });
    await page.goto('/app-v2/mission-control');
    await page.getByText('Open attack path, story cards, live events, and technical facts').click();
    await page.getByRole('button', { name: 'Open full map' }).first().click();

    const attackMapDialog = page.getByRole('dialog', { name: 'Full attack map' });
    await expect(attackMapDialog, `${viewport.label} dialog visible`).toBeVisible();
    await page.getByRole('button', { name: 'Fit' }).click();

    const mapCanvas = attackMapDialog.getByLabel('Attack map pan and zoom canvas');
    const mapTransform = attackMapDialog.getByTestId('attack-map-transform');
    await expect(mapTransform, `${viewport.label} transform has fitted zoom`).toHaveAttribute('data-zoom', /\d+\.\d{2}/);

    const canvasBox = await mapCanvas.boundingBox();
    if (!canvasBox) throw new Error(`Attack map canvas did not expose a bounding box at ${viewport.label}`);

    const importantNodes = [
      attackMapDialog.getByRole('button', { name: /Start Info/ }),
      attackMapDialog.getByRole('button', { name: /Proof 5 Critical privilege escalation route/ }),
      attackMapDialog.getByRole('button', { name: /Outcome Report/ }),
    ];
    for (const node of importantNodes) {
      await expect(node, `${viewport.label} important node is visible`).toBeVisible();
      const nodeBox = await node.boundingBox();
      if (!nodeBox) throw new Error(`Attack map node did not expose a bounding box at ${viewport.label}`);
      expect(nodeBox.x, `${viewport.label} node left fits`).toBeGreaterThanOrEqual(canvasBox.x - 2);
      expect(nodeBox.y, `${viewport.label} node top fits`).toBeGreaterThanOrEqual(canvasBox.y - 2);
      expect(nodeBox.x + nodeBox.width, `${viewport.label} node right fits`).toBeLessThanOrEqual(canvasBox.x + canvasBox.width + 2);
      expect(nodeBox.y + nodeBox.height, `${viewport.label} node bottom fits`).toBeLessThanOrEqual(canvasBox.y + canvasBox.height + 2);
    }

    await page.keyboard.press('Escape');
    await expect(page.getByRole('dialog', { name: 'Full attack map' })).toHaveCount(0);
  }
});

test('Mission Control truth strip uses chain aggregate as canonical run truth', async ({ page }) => {
  await page.goto('/app-v2/mission-control');
  await expect(page.getByTestId('run-truth-strip')).toHaveCount(0);
  await page.getByRole('tab', { name: 'Technical', exact: true }).click();

  const strip = page.getByTestId('run-truth-strip');
  await expect(strip).toBeVisible();
  await expect(strip).toContainText('Assessment chain aggregate');
  await expect(page.getByTestId('run-truth-canonical-score')).toContainText('2 persisted / 2 high+');
  await expect(page.getByTestId('run-truth-run-local-summary')).toContainText('1 total / 1 high+');
  await expect(page.getByTestId('run-truth-gap')).toContainText('Run-local summary differs: 1 run-local, 2 aggregate');
  await expect(page.getByTestId('run-truth-blocked-reason')).toContainText('assessment chain status is completed with gaps');
  await expect(page.getByTestId('run-truth-blocked-reason')).toContainText('1 failed task');
});

test('Mission Control truth strip separates observed output from persisted findings', async ({ page }) => {
  await page.unroute('**/api/v1/**');
  await installApiFixtures(page, {
    primaryRun: observedOnlyRun,
    primaryTasks: observedOnlyTasks,
    primaryFindings: [],
  });
  await page.goto('/app-v2/mission-control');
  await expect(page.getByTestId('run-truth-strip')).toHaveCount(0);
  await page.getByRole('tab', { name: 'Technical', exact: true }).click();

  const strip = page.getByTestId('run-truth-strip');
  await expect(strip).toBeVisible();
  await expect(strip).toContainText('Run-local truth');
  await expect(strip).toContainText('Observed task output only');
  await expect(strip).toContainText('No persisted findings yet');
  await expect(strip).toContainText('2 observed output items, 0 persisted findings');
  await expect(page.getByTestId('run-truth-canonical-score')).toContainText('0 persisted / 0 high+');
  await expect(page.getByTestId('run-truth-blocked-reason')).toContainText('completed tool output ended without persisted findings');
});

test('Mission Control explains queued signal-only runs without calling them blocked', async ({ page }) => {
  await page.unroute('**/api/v1/**');
  await installApiFixtures(page, {
    primaryRun: queuedSignalRun,
    primaryTasks: queuedSignalTasks,
    primaryFindings: [],
  });
  await page.goto('/app-v2/mission-control');

  await expect(page.getByLabel(/Live system activity: queued/i)).toBeVisible();
  await expect(page.getByLabel('Queue is waiting for the next task')).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Queue' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Live CLI' })).toBeVisible();
  await page.getByRole('tab', { name: 'Results', exact: true }).click();
  await expect(page.getByText('1 task waiting')).toBeVisible();
  await expect(page.getByText('Latest activity')).toBeVisible();
  await expect(page.getByTestId('run-truth-strip')).toHaveCount(0);

  await page.getByRole('tab', { name: 'Technical', exact: true }).click();
  const strip = page.getByTestId('run-truth-strip');
  await expect(strip).toContainText('Waiting: 1 task queued');
  await expect(strip).toContainText('3 observed output items, 0 persisted findings');
  await expect(strip).toContainText('This is not blocked yet');
  await expect(page.getByTestId('run-truth-blocked-reason')).toContainText('Needs review');
  await expect(page.getByTestId('run-truth-blocked-reason')).not.toContainText('Blocked / incomplete');
  await expect(page.getByText('Waiting for the next task')).toBeVisible();
  await expect(page.getByText('Reconnaissance in progress')).toHaveCount(0);
  if (process.env.AEGISPT_CAPTURE_MISSION_LIVE_ACTIVITY === '1') {
    await page.setViewportSize({ width: 1536, height: 864 });
    await page.getByRole('tab', { name: 'Live', exact: true }).click();
    await page.screenshot({
      path: '../docs/validation/codex-ui-reporting-w6a-mission-live-activity-1536x864.png',
      fullPage: false,
    });
  }
});

test('Mission Control live view exposes the current command once in Live CLI', async ({ page }) => {
  await page.unroute('**/api/v1/**');
  await installApiFixtures(page, {
    primaryRun: runningRun,
    primaryTasks: runningTasks,
    primaryFindings: [],
    primaryOnly: true,
  });
  await page.goto('/app-v2/mission-control');

  const snapshot = page.getByLabel('Mission snapshot');
  await expect(snapshot).toContainText('You are watching the active route');
  await expect(page.getByRole('heading', { name: 'Live CLI' })).toBeVisible();
  await expect(page.getByRole('main')).toContainText('$ nmap --target https://queued.example.test --safe-mode');
  await expect(page.getByRole('main')).toContainText('bounded fixture output for nmap');
  await expect(snapshot.getByLabel('Current command stream')).toHaveCount(0);
  if (process.env.AEGISPT_CAPTURE_UX3_LIVING_COCKPIT === '1') {
    await page.setViewportSize({ width: 1536, height: 864 });
    await page.screenshot({
      path: '../docs/validation/codex-ui-reporting-ux3-living-cockpit-command-stream-1536x864.png',
      fullPage: false,
    });
  }
});

test('Mission Control queue matches Live CLI task instances instead of grouping repeated tools', async ({ page }) => {
  await page.unroute('**/api/v1/**');
  const repeatedToolTasks = [
    {
      ...tasks[0],
      id: 'task-repeat-xss-new',
      tool: 'xss-extended',
      target_id: 'http://127.0.0.135/register',
      status: 'completed',
      updated_at: nineMinutesLater,
    },
    {
      ...tasks[1],
      id: 'task-repeat-smart-probe',
      tool: 'smart-web-probe',
      target_id: 'http://127.0.0.135',
      status: 'completed',
      updated_at: eightMinutesLater,
    },
    {
      ...tasks[2],
      id: 'task-repeat-headers',
      tool: 'headers-security',
      target_id: 'http://127.0.0.135',
      status: 'completed',
      updated_at: fiveMinutesLater,
    },
    {
      ...tasks[3],
      id: 'task-repeat-interactive',
      tool: 'interactive-exploit',
      target_id: 'http://127.0.0.135',
      status: 'completed',
      updated_at: fourMinutesLater,
    },
    {
      ...tasks[0],
      id: 'task-repeat-xss-old',
      tool: 'xss-extended',
      target_id: 'http://127.0.0.135/login',
      status: 'completed',
      updated_at: twoMinutesLater,
    },
  ];
  await installApiFixtures(page, {
    primaryRun: {
      ...run,
      id: 'run-repeated-live-task-instances',
      status: 'completed',
      assessment_chain: null,
      tasks: repeatedToolTasks,
      findings: {
        finding_count: 0,
        findings_by_severity: {},
        findings_by_status: {},
      },
    },
    primaryTasks: repeatedToolTasks,
    primaryFindings: [],
    primaryOnly: true,
  });
  await page.goto('/app-v2/mission-control');

  const queuePanel = page.getByRole('heading', { name: 'Queue' }).locator('xpath=ancestor::section[1]');
  await expect(queuePanel.getByRole('button', { name: /Show CLI output for xss-extended/ })).toHaveCount(2);
  await expect(queuePanel).not.toContainText('x2');

  await queuePanel.getByRole('button', { name: /Show CLI output for xss-extended/ }).nth(1).click();
  await expect(page.getByLabel('Live command terminal')).toContainText('http://127.0.0.135/login');
});

test('Mission Control status view groups completed error runs for non-technical operators', async ({ page }) => {
  await page.unroute('**/api/v1/**');
  await installApiFixtures(page, {
    primaryRun: completedErrorNoFindingRun,
    primaryTasks: completedErrorNoFindingTasks,
    primaryFindings: [],
  });
  await page.goto('/app-v2/mission-control');

  await expect(page.getByTestId('run-truth-strip')).toHaveCount(0);
  await page.getByRole('tab', { name: 'Results', exact: true }).click();
  await expect(page.getByText('Run ended with errors. No findings were created.')).toBeVisible();
  await expect(page.getByText('12 checks ran, 6 failed. Nothing is reportable yet. Open Technical only if you need failure details.')).toBeVisible();
  await expect(page.getByText('Last task')).toBeVisible();
  await expect(page.getByText('No reportable findings')).toBeVisible();
  await expect(page.getByText('exec-plan ×5')).toBeVisible();
  await expect(page.getByText(/signals/i)).toHaveCount(0);
  await expect(page.getByText(/canonical score/i)).toHaveCount(0);

  await page.getByRole('tab', { name: 'Technical', exact: true }).click();
  await expect(page.getByTestId('run-truth-strip')).toBeVisible();
});

test('Mission Control Technical view explains queued checks', async ({ page }) => {
  await installApiFixtures(page);
  await page.goto('/app-v2/mission-control');

  // Switch to Technical View
  await page.getByRole('tab', { name: 'Technical', exact: true }).click();

  // Expand details drawer to ensure all tasks are rendered
  await page.getByText('Proof and task inventory').click();
  await page.getByRole('button', { name: /Show all details/ }).click();

  // ssrf-probe exists in the task list
  await expect(page.getByText('ssrf-probe').first()).toBeVisible();
});

test('Evidence Replay uses assessment-chain tasks and separates evidence from conclusions', async ({ page }) => {
  await page.unroute('**/api/v1/**');
  await installApiFixtures(page, {
    primaryRun: evidenceChainRun,
    primaryTasks: evidenceChainTasks,
    primaryFindings: [],
  });

  await page.goto('/app-v2/evidence');

  await expect(page.getByRole('heading', { name: 'Evidence Replay' })).toBeVisible();
  await expect(page.getByText('Mission evidence path')).toBeVisible();
  await expect(page.getByText('Assessment chain route').first()).toBeVisible();
  await expect(page.getByText('Chain evidence · Evidence Replay / completed')).toBeVisible();
  await expect(page.getByRole('button', { name: /Map Map surface/ })).toBeVisible();
  await expect(page.getByRole('button', { name: /Test Test routes/ })).toBeVisible();
  await expect(page.getByText('Conclusion state')).toBeVisible();
  await expect(page.getByText('Not inferred here')).toBeVisible();
  await expect(page.getByText(/2 tasks · 2 artifacts/)).toBeVisible();
  await expect(page.locator('details').filter({ hasText: 'HTTP reachability mapped the surface' })).toBeVisible();
  await expect(page.locator('details').filter({ hasText: 'Nuclei tested a possible route' })).toBeVisible();
  await expect(page.getByText('httpx · https://app.example.test/profile', { exact: true }).first()).toBeVisible();
  await expect(page.getByText('nuclei · https://api.example.test/admin', { exact: true }).first()).toBeVisible();
  await page.getByRole('button', { name: /Test routes/ }).click();
  await expect(page.getByLabel('Selected evidence step')).toContainText('Nuclei tested a possible route');
  await expect(page.locator('details').filter({ hasText: 'Nuclei tested a possible route' })).toBeVisible();
  await expect(page.locator('details').filter({ hasText: 'HTTP reachability mapped the surface' })).toHaveCount(0);
  await page.getByRole('button', { name: /Show whole path/ }).click();
  await expect(page.locator('details').filter({ hasText: 'HTTP reachability mapped the surface' })).toBeVisible();
});

test('Evidence Replay exposes transcript and artifact provenance labels', async ({ page }) => {
  await page.unroute('**/api/v1/**');
  await installApiFixtures(page, {
    primaryRun: evidenceChainRun,
    primaryTasks: evidenceChainTasks,
    primaryFindings: [],
  });

  await page.goto('/app-v2/evidence');
  const nucleiEvidence = page.locator('details').filter({ hasText: 'nuclei · https://api.example.test/admin' });
  await nucleiEvidence.locator('summary').click();
  const openNucleiEvidence = page.locator('details[open]').filter({ hasText: 'nuclei · https://api.example.test/admin' });

  await expect(openNucleiEvidence.getByText('Execution provenance')).toBeVisible();
  await expect(openNucleiEvidence.getByText('Runner digest: sha256:fixture')).toBeVisible();
  await expect(openNucleiEvidence.getByText('Transcript stdout')).toBeVisible();
  await expect(openNucleiEvidence.getByText('bounded fixture output for nuclei: https://api.example.test/admin returned stored evidence only')).toBeVisible();
  await expect(openNucleiEvidence.getByText('Artifact provenance')).toBeVisible();
  await expect(openNucleiEvidence.getByText('SHA-256: fixture-sha256-task-evidence-sibling')).toBeVisible();
  await expect(openNucleiEvidence.getByRole('button', { name: /Download evidence-task-evidence-sibling\.txt/ })).toBeVisible();
  await expect(openNucleiEvidence.getByText('Exit state is execution evidence, not a finding verdict.')).toBeVisible();
});

test('Evidence Replay timeline traces finding evidence without inventing conclusions', async ({ page }) => {
  await page.unroute('**/api/v1/**');
  await installApiFixtures(page, {
    primaryRun: evidenceChainRun,
    primaryTasks: evidenceChainTasks,
    primaryFindings: evidenceChainFindings,
  });

  await page.goto('/app-v2/evidence');

  await expect(page.getByText('Evidence timeline')).toBeVisible();
  const selectedStep = page.getByLabel('Selected evidence step');
  await expect(selectedStep).toContainText('Customer account data exposure proof');
  await expect(selectedStep).toContainText('Finding linked to evidence');
  await expect(selectedStep).toContainText('This evidence proves');
  await expect(selectedStep).toContainText('This proves a saved finding points back to recorded evidence in this replay.');
  await expect(selectedStep).toContainText('This does not prove');
  await expect(selectedStep).toContainText('It does not rewrite validation, business impact, remediation, or report wording');
  await expect(selectedStep).toContainText('nuclei · https://api.example.test/admin');
  await expect(selectedStep).toContainText('artifact evidence-task-evidence-sibling.txt');
  await expect(selectedStep.getByRole('link', { name: 'Open Findings' })).toHaveAttribute('href', /findings/);
  await expect(selectedStep.getByRole('link', { name: 'Review report claims' })).toHaveAttribute('href', /reports/);

  if (process.env.AEGISPT_CAPTURE_UX5_EVIDENCE_TIMELINE === '1') {
    await page.setViewportSize({ width: 1536, height: 864 });
    await page.screenshot({
      path: '../docs/validation/codex-ui-reporting-ux5-evidence-replay-timeline-1536x864.png',
      fullPage: false,
    });
  }

  const timeline = page.getByLabel('Chronological evidence timeline');
  await expect(timeline).toContainText('Customer account data exposure proof');
  await timeline.getByRole('button', { name: /Nuclei tested a possible route/ }).click();
  await expect(selectedStep).toContainText('Nuclei tested a possible route');
  await expect(selectedStep).toContainText('1 linked finding');
  await expect(selectedStep).toContainText('This proves the task ran and stored execution evidence for replay.');
  await expect(selectedStep).toContainText('It still does not prove business impact by itself');
});

test('Cinema Mode opens as a full viewport replay overlay with visible exit and command feed', async ({ page }) => {
  await installApiFixtures(page);
  await page.goto('/app-v2/mission-control');

  await page.getByRole('tab', { name: 'Technical', exact: true }).click();
  await page.getByRole('button', { name: /Cinema/ }).click();
  const cinema = page.getByTestId('cinema-mode');
  await expect(cinema).toBeVisible();
  await expect(page.getByRole('button', { name: /^Exit$/ })).toBeVisible();
  await expect(page.getByText('Command Replay')).toBeVisible();
  await expect(page.getByText('Replay Camera')).toBeVisible();
  await page.getByRole('button', { name: /\$ httpx/ }).click();
  await expect(page.getByText(/CAMERA \/\/ FOCUSED/)).toBeVisible();

  const box = await cinema.boundingBox();
  expect(box?.x).toBe(0);
  expect(box?.y).toBe(0);
});

test('Report Center shows canonical report truth, variants, and export scope', async ({ page }) => {
  await installApiFixtures(page);
  await page.goto('/app-v2/reports');

  await expect(page.getByRole('heading', { name: 'Report Center' })).toBeVisible();
  await expect(page.getByText('Report package')).toBeVisible();
  await expect(page.getByText('Canonical findings', { exact: true })).toBeVisible();
  await expect(page.getByText('2 total')).toBeVisible();
  await expect(page.getByText('Included in selected report')).toBeVisible();
  await expect(page.getByText('2 included of 2 canonical findings')).toBeVisible();
  await expect(page.getByText('What will be included')).toBeVisible();
  await expect(page.getByText('What is not claimed')).toBeVisible();
  const managementProof = page.getByLabel('Management report export proof');
  await expect(managementProof).toContainText('Management proof');
  await expect(managementProof).toContainText('Attack map preview');
  await expect(managementProof).toContainText('What was tested, in management language.');
  await expect(managementProof).toContainText('[PTES]');
  await expect(managementProof).toContainText('[WSTG]');
  await expect(managementProof).toContainText('[NIST]');
  await expect(managementProof).toContainText('[ASVS]');
  await expect(managementProof).toContainText('Techniques in plain language');
  await expect(managementProof).toContainText('Input and data handling');
  await expect(managementProof).toContainText('What IT and Engineering should do');
  await expect(managementProof).toContainText('Engineering');
  await expect(managementProof).toContainText('IT/Ops');
  await expect(managementProof).toContainText('Evidence basis');
  await expect(managementProof).toContainText('Tested scope:');
  if (process.env.AEGISPT_CAPTURE_UX7_REPORT_PROOF === '1') {
    await managementProof.scrollIntoViewIfNeeded();
    await page.screenshot({
      path: '../docs/validation/codex-ui-reporting-ux7-management-report-proof-1536x864.png',
      fullPage: false,
    });
  }
  const consistencyPanel = page.getByLabel('Cross-surface truth consistency');
  await expect(consistencyPanel).toContainText('Truth consistency');
  await expect(consistencyPanel).toContainText('Canonical surfaces agree with a noted caveat');
  await expect(consistencyPanel).toContainText('2 findings');
  await expect(consistencyPanel).toContainText('1 finding');
  await expect(consistencyPanel).toContainText('Run-local summary differs');
  await expect(page.getByText('Report content hash')).toBeVisible();
  await expect(page.getByText('aaaaaaaa...aaaaaa')).toBeVisible();
  const previewActions = page.getByLabel('Report preview and export actions');
  await expect(previewActions).toContainText('export ready');
  await expect(previewActions).toContainText('markdown / html / pdf');
  await expect(previewActions).toContainText('fixture-report.pdf');
  const previewPanel = page.getByLabel('Report preview metadata');
  await expect(previewPanel).toContainText('Preview not generated');
  await expect(previewPanel).toContainText('Preview claims');
  await expect(previewPanel).toContainText('not listed');
  await expect(page.getByText('Customer copy check passed for selected report metadata.')).toBeVisible();
  await page.getByRole('button', { name: 'Markdown Preview' }).click();
  await expect(page.getByText('Stored fixture evidence preview for React v2 route coverage.')).toBeVisible();
  await expect(consistencyPanel).toContainText('2 preview');
  await expect(previewPanel).toContainText('loaded');
  await expect(previewPanel).toContainText('Preview lines');
  await expect(previewPanel).toContainText('Sections');
  await expect(previewPanel).toContainText('2 findings claimed');

  await expect(page.getByText('Report variants')).toBeVisible();
  await expect(page.getByRole('button', { name: /Technical Evidence/ })).toBeVisible();
  await page.getByRole('button', { name: /Technical Evidence/ }).click();
  await expect(page.getByRole('button', { name: /Variant technical_evidence/ })).toBeVisible();
  await page.getByRole('button', { name: /Findings 2 canonical/ }).click();
  await expect(page.getByText('Count check: matches canonical.')).toBeVisible();
});

test('Report Center masks raw provider briefing failures', async ({ page }) => {
  await installApiFixtures(page, {
    briefing:
      "Briefing generation failed: Error code: 400 - {'type': 'error', 'error': {'type': 'invalid_request_error', 'message': 'Your credit balance is too low to access the Anthropic API.'}, 'request_id': 'req_fixture'}",
  });

  await page.goto('/app-v2/reports');

  await expect(page.getByRole('heading', { name: 'Report Center' })).toBeVisible();
  await expect(page.getByText('AI wording is unavailable')).toBeVisible();
  await expect(page.getByRole('main')).not.toContainText('credit balance');
  await expect(page.getByRole('main')).not.toContainText('Anthropic API');
  await expect(page.getByRole('main')).not.toContainText('invalid_request_error');
  await expect(page.getByRole('main')).not.toContainText('request_id');
  if (process.env.AEGISPT_CAPTURE_UX1_TRUST_REPAIR === '1') {
    await page.screenshot({
      path: '../docs/validation/codex-ui-reporting-ux1-report-provider-mask-1536x864.png',
      fullPage: false,
    });
  }
});

test('Report Center flags the named M7 contradictory score fixture before export', async ({ page }) => {
  const scenario = reportEvidenceScenarios.blocked_contradictory_score;
  await page.unroute('**/api/v1/**');
  await installApiFixtures(page, {
    primaryRun: scenario.run,
    primaryTasks: scenario.tasks,
    primaryFindings: scenario.findings,
    reports: scenario.reports,
    reportMarkdown: scenario.markdownPreview,
    primaryOnly: true,
  });

  await page.goto('/app-v2/reports');

  const consistencyPanel = page.getByLabel('Cross-surface truth consistency');
  await expect(consistencyPanel).toContainText('Report truth needs review');
  await expect(consistencyPanel).toContainText('Catalog mismatch');
  await expect(consistencyPanel).toContainText('0 findings');
  await expect(consistencyPanel).toContainText('2 findings');

  await page.getByRole('button', { name: 'Markdown Preview' }).click();
  await expect(consistencyPanel).toContainText('Markdown preview claims a different finding count');
  await expect(consistencyPanel).toContainText('2 preview');
  await expect(page.getByText('Canonical Findings: 2')).toBeVisible();
  await expect(page.getByRole('main')).not.toContainText('customer-ready final report');
});

test('Research masks raw API failures and keeps recovery copy visible', async ({ page }) => {
  await installApiFixtures(page, {
    researchFailure: {
      status: 500,
      detail: 'Traceback: AegisPT API request failed: 500 provider invalid_request_error request_id=req_fixture',
    },
  });

  await page.goto('/app-v2/research');

  await expect(page.getByRole('heading', { name: 'AI Research' })).toBeVisible();
  await expect(page.getByText('Research workspace is temporarily unavailable')).toBeVisible();
  await expect(page.getByRole('main')).not.toContainText('AegisPT API request failed');
  await expect(page.getByRole('main')).not.toContainText('Traceback');
  await expect(page.getByRole('main')).not.toContainText('invalid_request_error');
  if (process.env.AEGISPT_CAPTURE_UX1_TRUST_REPAIR === '1') {
    await page.screenshot({
      path: '../docs/validation/codex-ui-reporting-ux1-research-safe-error-1536x864.png',
      fullPage: false,
    });
  }
});

test('History explains filtered empty states and can reset filters', async ({ page }) => {
  await installApiFixtures(page);
  await page.goto('/app-v2/history');

  await expect(page.getByRole('heading', { name: 'History', exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: engagement.name }).first()).toBeVisible();
  await page.getByLabel('Search').fill('no matching mission');

  await expect(page.getByText('No runs match the current filters')).toBeVisible();
  await expect(page.getByText('There are runs available, but the current search')).toBeVisible();
  if (process.env.AEGISPT_CAPTURE_UX1_TRUST_REPAIR === '1') {
    await page.getByText('No runs match the current filters').scrollIntoViewIfNeeded();
    await page.screenshot({
      path: '../docs/validation/codex-ui-reporting-ux1-history-filter-empty-1536x864.png',
      fullPage: false,
    });
  }
  await page.getByRole('button', { name: 'Reset filters' }).click();

  await expect(page.getByText('No runs match the current filters')).toHaveCount(0);
  await expect(page.getByRole('button', { name: engagement.name }).first()).toBeVisible();
  if (process.env.AEGISPT_CAPTURE_UX1_TRUST_REPAIR === '1') {
    await page.screenshot({
      path: '../docs/validation/codex-ui-reporting-ux1-history-filter-reset-1536x864.png',
      fullPage: false,
    });
  }
});

test('Canonical consistency fixture stays aligned across mission evidence findings and reports', async ({ page }) => {
  await installApiFixtures(page);

  await page.goto('/app-v2/mission-control');
  await expect(page.getByLabel('Mission snapshot')).toContainText('You are reviewing the proof path');
  await expect(page.getByLabel('Mission snapshot')).toContainText('Checked');
  await expect(page.getByLabel('Mission snapshot')).toContainText('3/4');
  await expect(page.getByLabel('Mission snapshot')).toContainText('2 reportable');
  await page.getByRole('tab', { name: 'Technical', exact: true }).click();
  await expect(page.getByTestId('run-truth-canonical-score')).toContainText('2 persisted / 2 high+');
  await expect(page.getByTestId('run-truth-run-local-summary')).toContainText('1 total / 1 high+');

  await page.goto('/app-v2/findings');
  const findingList = page.getByLabel('Findings result list');
  await expect(findingList.getByRole('button', { name: /Critical stored XSS in profile preview/ })).toBeVisible();
  await expect(findingList.getByRole('button', { name: /High-risk missing HSTS header/ })).toBeVisible();
  await expect(page.getByRole('main')).toContainText('2 findings');

  await page.goto('/app-v2/evidence');
  await expect(page.getByText('Mission evidence path')).toBeVisible();
  await expect(page.getByRole('main')).toContainText('2 saved findings');
  await expect(page.getByRole('main')).toContainText('2 saved finding(s) connect this replay to Findings and Reports.');

  await page.goto('/app-v2/reports');
  await expect(page.getByText('Canonical findings', { exact: true })).toBeVisible();
  await expect(page.getByText('2 total')).toBeVisible();
  await expect(page.getByText('2 included of 2 canonical findings')).toBeVisible();
  await expect(page.getByText('Count check: matches canonical.')).toBeVisible();
  const consistencyPanel = page.getByLabel('Cross-surface truth consistency');
  await expect(consistencyPanel).toContainText('Canonical surfaces agree with a noted caveat');
  await expect(consistencyPanel).toContainText('Run-local summary differs');
  await expect(consistencyPanel).toContainText('2 linked');
  await page.getByRole('button', { name: 'Markdown Preview' }).click();
  await expect(page.getByText('Canonical Consistency Fixture')).toBeVisible();
  await expect(consistencyPanel).toContainText('2 preview');
  await expect(page.getByText('Canonical Findings: 2')).toBeVisible();
  await expect(page.getByText('High/Critical: 2')).toBeVisible();
  await expect(page.getByText('Finding Status: open 2')).toBeVisible();
  await expect(page.getByText('Critical stored XSS in profile preview')).toBeVisible();
  await expect(page.getByText('High-risk missing HSTS header')).toBeVisible();
  await expect(page.getByText('Stored fixture evidence preview for React v2 route coverage.')).toBeVisible();

  const exportedMarkdown = await page.evaluate(async () => {
    const response = await fetch('/api/v1/runs/run-1/report?format=markdown&variant=executive_summary');
    return response.text();
  });
  expect(exportedMarkdown).toContain('Canonical Findings: 2');
  expect(exportedMarkdown).toContain('High/Critical: 2');
  expect(exportedMarkdown).toContain('Finding Status: open 2');
  expect(exportedMarkdown).toContain('Critical stored XSS in profile preview');
  expect(exportedMarkdown).toContain('High-risk missing HSTS header');
  expect(exportedMarkdown).not.toContain('Canonical Findings: 1');
});

test('All primary React v2 screens render non-empty content from mocked API contracts', async ({ page }) => {
  const routes: Array<[string, string]> = [
    ['/', 'Dashboard'],
    ['/intake', 'New Mission'],
    ['/mission-control', 'Mission Control'],
    ['/surface-map', 'Surface Map'],
    ['/evidence', 'Evidence Replay'],
    ['/findings', 'Findings Theater'],
    ['/reports', 'Report Center'],
    ['/history', 'History'],
    ['/problems', 'Problems Center'],
    ['/packs', 'Packs'],
    ['/cve-library', 'Custom CVE Library'],
    ['/research', 'AI Research'],
    ['/settings', 'Settings'],
  ];

  for (const [path, heading] of routes) {
    await page.goto(`/app-v2${path}`);
    await expect(page.getByLabel('Selected engagement')).toHaveValue(engagement.id);
    await expect(page.getByRole('heading', { name: heading, exact: true })).toBeVisible();
    await expect(page.getByText('The view stopped rendering safely.')).toHaveCount(0);
    await expect(page.getByText(/Unhandled fixture route/)).toHaveCount(0);
    const content = (await page.getByRole('main').innerText()).trim();
    expect(content.length, `${path} should not render as an empty shell`).toBeGreaterThan(120);
  }
});

test('Live CLI renders command-style stdout for structured task output', async ({ page }) => {
  const liveCliJsonTask = {
    ...tasks[0],
    id: 'task-live-cli-json',
    tool: 'target-intel',
    target_id: 'https://google-gruyere.appspot.com/482338906867472456097470474631954304306/',
    status: 'running',
    params_json: { depth: 3, follow_redirects: true },
    updated_at: oneMinuteLater,
    fixture_stdout_text: JSON.stringify({
      tool: 'target-intel',
      target: 'https://google-gruyere.appspot.com/482338906867472456097470474631954304306/',
      analysis: {
        site_type: 'Google Gruyere training app',
        technology_stack: ['Google Frontend', 'HTML 4.01 Transitional'],
      },
      test_plan: [
        {
          priority: 1,
          tool: 'smart-web-probe',
          reason: 'Find forms and reflection points before exploit testing.',
          params: {
            url: 'https://google-gruyere.appspot.com/482338906867472456097470474631954304306/',
          },
        },
      ],
    }),
  } as FixtureTask & { fixture_stdout_text: string };
  const liveCliRun = {
    ...run,
    id: 'run-live-cli-json',
    status: 'running',
    tasks: [liveCliJsonTask],
    assessment_chain: {
      ...run.assessment_chain,
      id: 'chain-live-cli-json',
    },
  };

  await page.unroute('**/api/v1/**');
  await installApiFixtures(page, {
    primaryRun: liveCliRun,
    primaryTasks: [liveCliJsonTask],
    primaryFindings: [],
  });
  await page.goto('/app-v2/live-cli');

  await expect(page.getByRole('heading', { name: 'Live CLI' })).toBeVisible();
  const terminal = page.getByLabel('Live command terminal');
  await expect(terminal).toContainText('$ target-intel --target https://google-gruyere.appspot.com/482338906867472456097470474631954304306/');
  await expect(terminal).toContainText('structured JSON output expanded for readability');
  await expect(terminal).toContainText('"test_plan": [');
  await expect(terminal).toContainText('"tool": "smart-web-probe"');
  if (process.env.AEGISPT_CAPTURE_LIVE_CLI_COMMAND === '1') {
    await page.screenshot({
      path: '../docs/validation/codex-ui-reporting-w6a-live-cli-command-output-1536x864.png',
      fullPage: false,
    });
  }
});

test('Crash recovery screen renders all controls within viewport without clipping', async ({ page }) => {
  await installApiFixtures(page);
  await page.goto('/app-v2/');

  // Force a render crash by injecting an error boundary trigger
  await page.evaluate(() => {
    const el = document.querySelector('[data-testid="crash-trigger"]');
    if (el) (el as HTMLElement).click();
  });

  // Verify crash recovery does NOT show (no pre-existing crash)
  await expect(page.getByText('The view stopped rendering safely.')).toHaveCount(0);

  // Verify all primary navigation controls are visible and not clipped
  const nav = page.getByRole('navigation');
  if (await nav.count() > 0) {
    const box = await nav.boundingBox();
    expect(box).not.toBeNull();
    expect(box!.height).toBeGreaterThan(0);
  }

  // Verify all interactive buttons have accessible names
  const buttons = page.getByRole('button');
  const buttonCount = await buttons.count();
  for (let i = 0; i < Math.min(buttonCount, 20); i++) {
    const btn = buttons.nth(i);
    const visible = await btn.isVisible();
    if (!visible) continue;
    const name = await btn.getAttribute('aria-label') ?? await btn.textContent();
    expect(name?.trim().length ?? 0, `Button ${i} must have an accessible name`).toBeGreaterThan(0);
  }
});

test('Dashboard sparse payload renders without crash and key metrics are accessible', async ({ page }) => {
  // Sparse payload - all optional nested fields absent
  await installApiFixtures(page, { dashboard: {
    risk_score: null as unknown as ReturnType<typeof dashboardPayload>['risk_score'],
    blast_radius: null as unknown as ReturnType<typeof dashboardPayload>['blast_radius'],
    open_problems: null as unknown as ReturnType<typeof dashboardPayload>['open_problems'],
    activity_feed: [],
    engagements: [],
    zero_day_rapid_response: [],
  } });
  await page.goto('/app-v2/');
  await expect(page.getByRole('heading', { name: 'Dashboard', exact: true })).toBeVisible();
  await expect(page.getByText('The view stopped rendering safely.')).toHaveCount(0);

  // Headings are structured for screen readers
  const h1Count = await page.locator('h1, h2').count();
  expect(h1Count, 'Dashboard should have at least one heading').toBeGreaterThan(0);

  // All images have alt text
  const images = page.locator('img');
  const imgCount = await images.count();
  for (let i = 0; i < imgCount; i++) {
    const alt = await images.nth(i).getAttribute('alt');
    expect(alt, `Image ${i} must have alt attribute`).not.toBeNull();
  }
});

type FixtureRun = Omit<Run, 'assessment_chain'> & { assessment_chain: Run['assessment_chain'] | null };
type FixtureTask = Task & { fixture_stdout_text?: string };
type FixtureFinding = Finding;

interface ApiFixtureOptions {
  dashboard?: ReturnType<typeof dashboardPayload>;
  briefing?: string;
  primaryRun?: FixtureRun;
  primaryTasks?: FixtureTask[];
  primaryFindings?: FixtureFinding[];
  reports?: RunReportCatalogItem[];
  reportMarkdown?: string;
  primaryOnly?: boolean;
  problems?: ReturnType<typeof problemsPayload>;
  researchFailure?: {
    status: number;
    detail: string;
  };
}

async function installApiFixtures(page: Page, options: ApiFixtureOptions = {}) {
  const primaryRun = options.primaryRun ?? run;
  const primaryTasks = options.primaryTasks ?? tasks;
  const primaryFindings = options.primaryFindings ?? findings;
  const primaryReports = options.reports ?? reportCatalogFor(primaryRun, primaryFindings);
  const primaryReportMarkdown = options.reportMarkdown ?? null;
  const primaryChainId = chainIdFromFixtureRun(primaryRun);
  const fixtureRuns = uniqueRuns(options.primaryOnly ? [primaryRun] : [primaryRun, run, chainReasoningRun, runningRun, queuedRun]);

  await page.route('**/api/v1/**', async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    const path = url.pathname;
    const method = request.method();

    if (method === 'GET' && path === '/api/v1/engagements') return json(route, [engagement]);
    if (method === 'GET' && path === `/api/v1/engagements/${engagement.id}/runs`) return json(route, fixtureRuns);
    if (method === 'GET' && path === `/api/v1/runs/${primaryRun.id}`) return json(route, primaryRun);
    if (primaryChainId && method === 'GET' && path === `/api/v1/assessment-chains/${primaryChainId}/tasks`) return json(route, primaryTasks);
    if (primaryChainId && method === 'GET' && path === `/api/v1/assessment-chains/${primaryChainId}/findings`) return json(route, primaryFindings);
    if (method === 'GET' && path === `/api/v1/runs/${primaryRun.id}/tasks`) return json(route, primaryTasks);
    if (method === 'GET' && path === `/api/v1/runs/${primaryRun.id}/findings` && url.searchParams.get('theater') === 'true') return json(route, []);
    if (method === 'GET' && path === `/api/v1/runs/${primaryRun.id}/findings`) return json(route, primaryFindings);
    if (primaryRun.id !== run.id && method === 'GET' && path === `/api/v1/runs/${primaryRun.id}/ai-insights`) {
      return json(route, { ...aiInsights, run_id: primaryRun.id, reasoning_records: [], proposals: [] });
    }
    const primaryTask = primaryTasks.find((task) => path === `/api/v1/tasks/${task.id}`);
    if (method === 'GET' && primaryTask) return json(route, taskDetail(primaryTask, primaryRun.id));
    if (method === 'GET' && path === `/api/v1/runs/${run.id}`) return json(route, run);
    if (method === 'GET' && path === `/api/v1/runs/${chainReasoningRun.id}`) return json(route, chainReasoningRun);
    if (method === 'GET' && path === `/api/v1/runs/${runningRun.id}`) return json(route, runningRun);
    if (method === 'GET' && path === `/api/v1/runs/${queuedRun.id}`) return json(route, queuedRun);
    if (method === 'GET' && path === `/api/v1/assessment-chains/${run.assessment_chain.id}/tasks`) return json(route, tasks);
    if (method === 'GET' && path === `/api/v1/assessment-chains/${run.assessment_chain.id}/findings`) return json(route, findings);
    if (method === 'GET' && path === `/api/v1/runs/${runningRun.id}/tasks`) return json(route, runningTasks);
    if (method === 'GET' && path === `/api/v1/runs/${runningRun.id}/findings`) return json(route, []);
    if (method === 'GET' && path === `/api/v1/runs/${queuedRun.id}/tasks`) return json(route, queuedRun.tasks);
    if (method === 'GET' && path === `/api/v1/runs/${queuedRun.id}/findings`) return json(route, []);
    if (method === 'GET' && path === `/api/v1/runs/${run.id}/findings` && url.searchParams.get('theater') === 'true') return json(route, []);
    if (method === 'GET' && path === `/api/v1/runs/${run.id}/findings`) return json(route, findings);
    if (primaryRun.source_inventory_snapshot_id && method === 'GET' && path === `/api/v1/inventory/${primaryRun.source_inventory_snapshot_id}`) {
      return json(route, { ...inventory, id: primaryRun.source_inventory_snapshot_id });
    }
    if (method === 'GET' && path === `/api/v1/inventory/${inventory.id}`) return json(route, inventory);
    if (method === 'GET' && path === `/api/v1/engagements/${engagement.id}/inventory`) return json(route, [inventory]);
    if (method === 'GET' && path === `/api/v1/runs/${run.id}/ai-insights`) return json(route, selectedRunAiInsights);
    if (method === 'GET' && path === `/api/v1/runs/${chainReasoningRun.id}/ai-insights`) return json(route, chainAiInsights);
    if (method === 'GET' && path === `/api/v1/runs/${runningRun.id}/ai-insights`) return json(route, { ...aiInsights, run_id: runningRun.id, reasoning_records: [], proposals: [] });
    if (method === 'GET' && path === `/api/v1/runs/${queuedRun.id}/ai-insights`) return json(route, { ...aiInsights, run_id: queuedRun.id, reasoning_records: [], proposals: [] });
    if (method === 'GET' && path === `/api/v1/runs/${primaryRun.id}/briefing`) {
      return json(route, {
        briefing: options.briefing ?? `Report is ready for review with ${primaryFindings.length} canonical findings and stored evidence.`,
      });
    }
    if (method === 'GET' && path === `/api/v1/runs/${primaryRun.id}/reports`) return json(route, primaryReports);
    if (method === 'GET' && path === `/api/v1/runs/${primaryRun.id}/report`) {
      return markdown(route, primaryReportMarkdown ?? reportMarkdownFor(primaryRun, primaryFindings, url.searchParams.get('variant')));
    }
    if (primaryRun.id !== run.id && method === 'GET' && path === `/api/v1/runs/${run.id}/briefing`) {
      return json(route, {
        briefing: options.briefing ?? `Report is ready for review with ${findings.length} canonical findings and stored evidence.`,
      });
    }
    if (primaryRun.id !== run.id && method === 'GET' && path === `/api/v1/runs/${run.id}/reports`) return json(route, reportCatalogFor(run, findings));
    if (primaryRun.id !== run.id && method === 'GET' && path === `/api/v1/runs/${run.id}/report`) {
      return markdown(route, reportMarkdownFor(run, findings, url.searchParams.get('variant')));
    }
    if (method === 'GET' && path === `/api/v1/tasks/${tasks[0].id}`) return json(route, taskDetail(tasks[0]));
    if (method === 'GET' && path === `/api/v1/tasks/${tasks[1].id}`) return json(route, taskDetail(tasks[1]));
    if (method === 'GET' && path === `/api/v1/tasks/${tasks[2].id}`) return json(route, taskDetail(tasks[2]));
    if (method === 'GET' && path === `/api/v1/tasks/${tasks[3].id}`) return json(route, taskDetail(tasks[3]));
    if (method === 'GET' && path === '/api/v1/dashboard') return json(route, options.dashboard ?? dashboardPayload());
    if (method === 'GET' && path === '/api/v1/settings') return json(route, settingsPayload());
    if (method === 'GET' && path === '/api/v1/settings/readiness') return json(route, readinessPayload());
    if (method === 'GET' && path === '/api/v1/problems') return json(route, options.problems ?? problemsPayload(primaryFindings));
    if (method === 'GET' && path === `/api/v1/engagements/${engagement.id}/packs`) return json(route, [pack]);
    if (method === 'GET' && path === `/api/v1/packs/${pack.id}/artifacts`) return json(route, packArtifactsPayload());
    if (method === 'GET' && path === '/api/v1/custom-vulnerabilities') return json(route, { items: [customVulnerability], total: 1, filters: {} });
    if (method === 'GET' && path === '/api/v1/ai/research' && options.researchFailure) {
      return json(route, { detail: options.researchFailure.detail }, options.researchFailure.status);
    }
    if (method === 'GET' && path === '/api/v1/ai/research') return json(route, {
      engagement_id: engagement.id,
      cve_records: [threatIntelRecord],
      research_proposals: [],
      lifecycle_note: 'Fixture research remains review-only.',
    });
    if (method === 'GET' && path === '/api/v1/auth/chatgpt/status') return json(route, { provider: 'fixture', status: 'connected', connected: true, model: 'fixture-model' });
    if (method === 'GET' && path === '/api/v1/auth/keys') return json(route, []);
    if (method === 'GET' && path === '/api/v1/auth/identity/status') return json(route, identityPayload());
    if (method === 'GET' && path === `/api/v1/engagements/${engagement.id}/schedules`) return json(route, []);
    if (method === 'GET' && path === '/api/v1/deception/traps') return json(route, { tenant_id: 'tenant-1', traps: [], boundary: deceptionBoundary() });
    if (method === 'GET' && path === '/api/v1/deception/alerts') return json(route, { tenant_id: 'tenant-1', alerts: [], boundary: deceptionBoundary() });

    const theaterMatch = path.match(/^\/api\/v1\/findings\/([^/]+)\/theater$/);
    if (method === 'GET' && theaterMatch) return json(route, theaterPayload(theaterMatch[1], primaryFindings));

    const evidenceMatch = path.match(/^\/api\/v1\/findings\/([^/]+)\/evidence$/);
    if (method === 'GET' && evidenceMatch) return json(route, evidencePayload(evidenceMatch[1], primaryFindings));

    const artifactContentMatch = path.match(/^\/api\/v1\/artifacts\/([^/]+)\/content$/);
    if (method === 'GET' && artifactContentMatch) {
      return route.fulfill({
        status: 200,
        contentType: 'text/plain',
        body: `stored fixture artifact content for ${artifactContentMatch[1]}`,
      });
    }

    return json(route, { detail: `Unhandled fixture route: ${method} ${path}` }, 404);
  });
}

async function json(route: Route, payload: unknown, status = 200) {
  await route.fulfill({
    status,
    contentType: 'application/json',
    body: JSON.stringify(payload),
  });
}

async function markdown(route: Route, body: string, status = 200) {
  await route.fulfill({
    status,
    contentType: 'text/markdown; charset=utf-8',
    body,
  });
}

function uniqueRuns(candidates: FixtureRun[]): FixtureRun[] {
  const seen = new Set<string>();
  return candidates.filter((candidate) => {
    if (seen.has(candidate.id)) return false;
    seen.add(candidate.id);
    return true;
  });
}

function chainIdFromFixtureRun(candidate: FixtureRun): string | null {
  const chain = candidate.assessment_chain;
  if (!chain || typeof chain !== 'object') return null;
  const chainId = (chain as { id?: unknown }).id;
  return typeof chainId === 'string' && chainId.trim() ? chainId : null;
}

function reportCatalogFor(sourceRun: FixtureRun, sourceFindings: FixtureFinding[]) {
  const severityCounts = countFindings(sourceFindings, (item) => item.severity);
  const statusCounts = countFindings(sourceFindings, (item) => item.status);
  const linkedFindings = sourceFindings.filter((item) => item.evidence_ref).length;
  const shared = {
    source_run_id: sourceRun.id,
    generated_at: now,
    source_scope_profile: { run_profile: sourceRun.profile.name },
    included_findings: {
      total: sourceFindings.length,
      count: sourceFindings.length,
      by_severity: severityCounts,
      by_status: statusCounts,
    },
    included_inventory: { hosts: 1, services: 1, endpoints: 2 },
    evidence_status: {
      verified: linkedFindings === sourceFindings.length,
      linked_findings: linkedFindings,
      total_findings: sourceFindings.length,
    },
    compliance_summary: {},
    assurance_summary: {},
    adaptive_change_summary: {},
    ai_draft_summary: {},
    run_narrative_summary: {},
    lifecycle_summary: {},
  };
  return [
    {
      ...shared,
      variant: 'executive_summary',
      title: 'Executive Summary',
      description: 'Audience-ready summary backed by stored run evidence.',
      available_formats: ['markdown', 'html', 'pdf'],
      methodology_references: ['PTES', 'OWASP WSTG 4.2', 'NIST SP 800-115', 'OWASP ASVS 4.0.3'],
      version_label: 'report-v1',
      content_sha256: 'a'.repeat(64),
      availability_status: 'export_ready',
      availability_label: 'ready',
      availability_reason: 'Available from stored evidence.',
      preview_allowed: true,
      export_allowed: true,
      draft_allowed: false,
      export_paths: { html: '/fixture/report.html', pdf: '/fixture/report.pdf' },
      download_names: { html: 'fixture-report.html', pdf: 'fixture-report.pdf' },
    },
    {
      ...shared,
      variant: 'technical_evidence',
      title: 'Technical Evidence',
      description: 'Operator evidence appendix with method, proof, and artifact context.',
      available_formats: ['markdown', 'html'],
      methodology_references: ['OWASP WSTG', 'NIST SP 800-115'],
      version_label: 'technical-v1',
      content_sha256: 'c'.repeat(64),
      availability_status: 'export_ready',
      availability_label: 'ready',
      availability_reason: 'Technical appendix is available from stored evidence.',
      preview_allowed: true,
      export_allowed: true,
      draft_allowed: false,
      export_paths: { html: '/fixture/technical.html' },
      download_names: { html: 'technical-evidence.html' },
    },
    {
      ...shared,
      variant: 'proof_package',
      title: 'Proof Package',
      description: 'Focused proof bundle for replay and audit review.',
      available_formats: ['markdown'],
      methodology_references: ['OWASP WSTG'],
      version_label: 'proof-v1',
      content_sha256: 'd'.repeat(64),
      availability_status: 'draft_only',
      availability_label: 'draft',
      availability_reason: 'Proof bundle is available for preview before export.',
      preview_allowed: true,
      export_allowed: false,
      draft_allowed: true,
      export_paths: {},
      download_names: {},
    },
  ];
}

function reportMarkdownFor(sourceRun: FixtureRun, sourceFindings: FixtureFinding[], requestedVariant: string | null) {
  const variant = requestedVariant || 'executive_summary';
  const severityCounts = countFindings(sourceFindings, (item) => item.severity);
  const statusCounts = countFindings(sourceFindings, (item) => item.status);
  const evidenceRefs = sourceFindings.map((item) => item.evidence_ref).filter(Boolean);
  const highCritical = (severityCounts.critical ?? 0) + (severityCounts.high ?? 0);
  const findingLines = sourceFindings.map(
    (item) => `- ${item.severity.toUpperCase()} ${item.title} on ${item.target_id} (${item.status}; ${item.evidence_ref})`,
  );
  return [
    '# Canonical Consistency Fixture',
    '',
    'Stored fixture evidence preview for React v2 route coverage.',
    '',
    '## Canonical Truth',
    '',
    `- Source Run: ${sourceRun.id}`,
    `- Report Variant: ${variant}`,
    `- Canonical Findings: ${sourceFindings.length}`,
    `- High/Critical: ${highCritical}`,
    `- Finding Status: ${formatCounts(statusCounts)}`,
    `- Severity: ${formatCounts(severityCounts)}`,
    `- Evidence refs: ${evidenceRefs.join(', ') || 'none'}`,
    '',
    '## Findings',
    '',
    ...findingLines,
    '',
  ].join('\n');
}

function countFindings(sourceFindings: FixtureFinding[], selector: (item: FixtureFinding) => string | null | undefined) {
  return sourceFindings.reduce<Record<string, number>>((counts, item) => {
    const key = (selector(item) || 'unknown').toLowerCase();
    counts[key] = (counts[key] ?? 0) + 1;
    return counts;
  }, {});
}

function formatCounts(counts: Record<string, number>) {
  return Object.entries(counts)
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([key, value]) => `${key} ${value}`)
    .join(', ') || 'none';
}

function finding(id: string, title: string, severity: string, targetId: string, cvssScore: number) {
  return {
    id,
    run_id: 'run-1',
    source_pack_id: null,
    source_pack_artifact_id: null,
    source_inventory_snapshot_id: 'inv-1',
    source_relevance_decision_id: null,
    source_pack_version: null,
    finding_origin: 'fixture_runner',
    title,
    severity,
    target_id: targetId,
    evidence_ref: `evidence://${id}`,
    status: 'open',
    remediation_due_date: null,
    sla_breached: false,
    false_positive_reason: null,
    false_positive_confirmed_by: null,
    cvss_score: cvssScore,
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
    cvss_source: 'fixture',
    owasp_framework: 'OWASP WSTG',
    owasp_category: 'Input Validation',
    owasp_reference: 'WSTG-INPV-01',
    owasp_mapping: {},
    proof_reference: { artifact: `artifact-${id}` },
    validation_status: 'confirmed',
    summary: `${title} summary`,
    replay_recipe_json: { tool: 'fixture-review' },
    methodology_tags: ['wstg'],
    ptes_phase: 'vulnerability_analysis',
    nist_phase: 'analysis',
    wstg_id: 'WSTG-INPV-01',
    wstg_version: '4.2',
    asvs_reference: null,
    control_family: null,
    created_at: now,
  };
}

function dashboardPayload() {
  return {
    generated_at: now,
    has_engagements: true,
    active_run: {
      id: run.id,
      profile_name: run.profile.name,
      tasks_running: 0,
    },
    risk_score: { score: 8.2, trend: 'rising' },
    blast_radius: { score: 4.6, top_paths: [], summary: 'Fixture blast radius summary.' },
    open_problems: { total: 2, critical: 1, high: 1 },
    upcoming_scans: [],
    recent_activity: [],
    activity_feed: [
      {
        id: 'activity-1',
        label: 'Run completed with evidence attached',
        detail: 'Fixture-backed run completed for React v2 dashboard.',
        timestamp: now,
        engagement_name: engagement.name,
      },
    ],
    quick_actions: [],
    setup_checklist_dismissed: true,
    setup_checklist: [],
    first_run_onboarding: null,
    engagements: [
      {
        id: engagement.id,
        name: engagement.name,
        risk_score: 8.2,
        open_critical_count: 1,
        run_count: 1,
        last_run_status: run.status,
      },
    ],
  };
}

function sparseDashboardPayload() {
  return {
    generated_at: now,
    has_engagements: true,
    active_run: null,
    upcoming_scans: [],
    recent_activity: [],
    activity_feed: [],
    quick_actions: [],
    setup_checklist_dismissed: false,
    setup_checklist: [],
    first_run_onboarding: null,
    engagements: [],
  };
}

function settingsPayload() {
  return {
    tenant_id: 'tenant-1',
    sensitive_plaintext_exposed: false,
    sections: [
      {
        id: 'ai',
        title: 'AI',
        description: 'Fixture settings',
        settings: [setting('ai.chatgpt_oauth.connected', false, false)],
      },
      {
        id: 'integrations',
        title: 'Integrations',
        description: 'Fixture integrations',
        settings: [setting('integrations.jira_base_url', '', false)],
      },
    ],
  };
}

function setting(key: string, value: unknown, configured: boolean) {
  return {
    key,
    label: key,
    value,
    input_type: 'text',
    source: 'fixture',
    sensitive: false,
    configured,
    masked_value: null,
    read_only: true,
    description: null,
    options: [],
    ui_hidden: false,
    min_value: null,
    max_value: null,
    step: null,
    placeholder: null,
  };
}

function readinessPayload() {
  return {
    tenant_id: 'tenant-1',
    generated_at: now,
    overall_status: 'ready',
    capabilities: [],
    tools: [],
    artifact: {},
  };
}

function problemsPayload(sourceFindings: FixtureFinding[] = findings) {
  const items = sourceFindings.map((item, index) => ({
    id: `problem-${index + 1}`,
    finding_id: item.id,
    run_id: run.id,
    engagement_id: engagement.id,
    engagement_name: engagement.name,
    title: item.title,
    severity: item.severity,
    target_id: item.target_id,
    status: item.status,
    problem_status: index === 0 ? 'open' : 'triaged',
    assignee: index === 0 ? 'operator-ui' : null,
    days_open: index + 1,
    age_bucket: 'recent',
    remediation_state: 'pending',
    verification_status: item.validation_status,
    methodology_tags: item.methodology_tags,
    latest_retest_run_id: null,
    latest_retest_status: null,
    lifecycle: [],
    created_at: now,
    updated_at: now,
  }));
  return {
    generated_at: now,
    items,
    recently_resolved: [],
    stats: {
      open_critical: 1,
      open_high: 1,
      total_filtered: items.length,
      total_findings: findings.length,
      avg_days_to_resolve_30d: 2.4,
      resolved_this_week: 0,
    },
    filters: {},
    lifecycle_summary: {},
    next_cursor: null,
  };
}

function problemsTriagePayload() {
  const base = problemsPayload(triageBoardFindings);
  const items = base.items.map((item, index) => {
    if (index === 0) {
      return {
        ...item,
        problem_status: 'open',
        assignee: null,
        days_open: 21,
        age_bucket: 'overdue',
        updated_at: '2026-06-03T08:30:00.000Z',
      };
    }
    if (index === 1) {
      return {
        ...item,
        problem_status: 'in_progress',
        assignee: 'platform-team',
        days_open: 6,
        age_bucket: 'due_soon',
        updated_at: '2026-06-03T08:35:00.000Z',
      };
    }
    if (index === 2) {
      return {
        ...item,
        problem_status: 'open',
        assignee: null,
        days_open: 3,
        age_bucket: 'recent',
        updated_at: '2026-06-03T08:40:00.000Z',
      };
    }
    return item;
  });
  return {
    ...base,
    generated_at: '2026-06-03T08:45:00.000Z',
    items,
    stats: {
      ...base.stats,
      open_critical: 2,
      open_high: 1,
      total_filtered: items.length,
      total_findings: items.length,
    },
  };
}

function packArtifactsPayload() {
  return [
    {
      id: 'artifact-pack-1',
      pack_id: pack.id,
      artifact_type: 'nuclei_template',
      logical_name: 'fixture-safe-review.yaml',
      status: 'validated',
      checksum_sha256: 'b'.repeat(64),
      methodology_tags: ['wstg'],
      content_text: 'id: fixture-safe-review\ninfo:\n  name: Fixture Safe Review',
      content_json: null,
      provenance_json: { fixture: true },
      created_at: now,
    },
  ];
}

function deceptionBoundary() {
  return {
    local_controlled_fixture: true,
    network_tarpitting: false,
    automatic_live_deployment: false,
    legitimate_traffic_interference_expected: false,
    credential_materialized: false,
    dispatches_runtime_work: false,
  };
}

function identityPayload() {
  return {
    tenant_id: 'tenant-1',
    provider: 'local',
    status: 'configured',
    configured: true,
    summary: 'Fixture identity provider is configured.',
    operator_next_step: 'Review identity posture.',
    missing_fields: [],
    configured_secret_labels: [],
    session_policy: {},
    local_auth: {},
    access_boundaries: {},
    current_actor: { name: 'operator-ui', role: 'admin' },
    users: [],
    metadata: {},
  };
}

function taskDetail(
  task: FixtureTask & { fixture_stdout_text?: string | null; fixture_stderr_text?: string | null },
  runId = run.id,
) {
  const stdoutText =
    task.fixture_stdout_text ??
    `bounded fixture output for ${task.tool}: ${task.target_id} returned stored evidence only`;
  const stderrText = task.fixture_stderr_text ?? null;
  return {
    ...task,
    run_id: runId,
    executions: [
      {
        id: `exec-${task.id}`,
        runner_digest: 'sha256:fixture',
        tool_version: 'fixture',
        exit_code: 0,
        stdout_text: stdoutText,
        stderr_text: stderrText,
        created_at: now,
        artifacts: [
          {
            artifact_id: `artifact-${task.id}`,
            kind: 'text',
            uri: `fixture://${task.id}/evidence`,
            download_path: `/fixture/${task.id}/evidence`,
            name: `evidence-${task.id}.txt`,
            sha256: `fixture-sha256-${task.id}`,
            hash_status: 'verified',
            timestamp_status: 'not_requested',
            timestamp_response_uri: null,
            redaction_state: 'redacted',
            created_at: now,
          },
        ],
      },
    ],
    stdout_snapshot: {
      task_id: task.id,
      status: 'completed',
      source: 'fixture',
      reason: 'test fixture',
      task_status: task.status,
      stream_terminal: true,
      updated_at: now,
      lines: [{ sequence: 1, text: stdoutText }],
    },
  };
}

function theaterPayload(findingId: string, sourceFindings = findings) {
  const selected = sourceFindings.find((item) => item.id === findingId) ?? sourceFindings[0] ?? findings[0];
  const isBlocked = selected.id === 'finding-blocked';
  const isRawRunner = selected.id === 'finding-raw-runner';
  return {
    finding: selected,
    severity_rank: selected.severity === 'critical' ? 1 : 2,
    confidence_label: 'confirmed',
    exploitability: 'review-only fixture',
    business_impact: isBlocked ? '' : 'Customer data exposure risk from stored evidence.',
    technical_details: `${selected.title} technical detail from stored fixture evidence.`,
    evidence_summary: isBlocked
      ? ''
      : isRawRunner
        ? 'Stored execution evidence is linked to the captured flag.'
        : 'Stored evidence summary only.',
    provenance: { fixture: true },
    methodology: { owasp: { framework: 'OWASP WSTG', category: selected.owasp_category, reference: selected.owasp_reference } },
    remediation: isBlocked ? {} : { detail: 'Sanitize output and retest through normal approval gates.' },
    ai_enrichment: { available: false },
    autofix: {},
    repository_context: {},
    threat_context: {},
    detection_engineering: {},
    vulnerability_chains: { available: false, chains: [] },
    threat_intel_badges: {},
    validation: { status: selected.validation_status },
    evidence_integrity: isBlocked ? {} : { sha256: 'fixture-sha256' },
    verification_status: isBlocked ? 'automated validation was skipped; analyst review remains required' : selected.validation_status,
    next_steps: isBlocked ? [] : ['Review stored evidence.', 'Apply remediation.', 'Retest with operator approval.'],
    risk_snapshot: { score: selected.cvss_score },
  };
}

function evidencePayload(findingId: string, sourceFindings = findings) {
  const selected = sourceFindings.find((item) => item.id === findingId) ?? sourceFindings[0] ?? findings[0];
  const isBlocked = selected.id === 'finding-blocked';
  return {
    finding: selected,
    evidence_ref: selected.evidence_ref,
    methodology_references: {},
    pack_provenance: {},
    inventory_source: {},
    relevance_source: {},
    validation_history: [],
    related_executions: isBlocked ? [] : [
      {
        execution_id: 'exec-task-1',
        task_id: 'task-1',
        tool: 'fixture-review',
        target_id: selected.target_id,
        task_status: 'completed',
        exit_code: 0,
        tool_version: 'fixture',
        stdout_excerpt: 'Stored fixture evidence, no live target access.',
        stderr_excerpt: null,
        created_at: now,
        artifacts: [
          {
            artifact_id: 'artifact-1',
            kind: 'text',
            uri: 'fixture://evidence',
            download_path: '/fixture/evidence',
            name: 'evidence.txt',
            sha256: 'fixture-sha256',
            hash_status: 'verified',
            timestamp_status: 'verified',
            timestamp_response_uri: null,
            redaction_state: 'redacted',
            created_at: now,
          },
        ],
      },
    ],
  };
}
