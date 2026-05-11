import { expect, test, type Page, type Route } from '@playwright/test';

const now = '2026-05-10T10:00:00.000Z';

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
    updated_at: now,
  },
  {
    id: 'task-2',
    source_finding_id: null,
    tool: 'nuclei',
    target_id: 'https://api.example.test',
    status: 'completed',
    params_json: { templates: 'safe-review' },
    stale_recovery: {},
    created_at: now,
    updated_at: now,
  },
  {
    id: 'task-3',
    source_finding_id: null,
    tool: 'burp',
    target_id: 'https://app.example.test/login',
    status: 'failed',
    params_json: { safe_mode: true },
    stale_recovery: {},
    created_at: now,
    updated_at: now,
  },
  {
    id: 'task-4',
    source_finding_id: null,
    tool: 'ssrf-probe',
    target_id: 'https://app.example.test/upload',
    status: 'queued',
    params_json: { safe_mode: true },
    stale_recovery: {},
    created_at: now,
    updated_at: now,
  },
];

const findings = [
  finding('finding-critical', 'Critical stored XSS in profile preview', 'critical', 'https://app.example.test/profile', 9.4),
  finding('finding-high', 'High-risk missing HSTS header', 'high', 'https://api.example.test', 7.2),
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
  updated_at: now,
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
    finding_count: findings.length,
    findings_by_severity: { critical: 1, high: 1 },
    findings_by_status: { open: 2 },
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

const reportCatalog = [
  {
    variant: 'executive_summary',
    title: 'Executive Summary',
    description: 'Fixture report catalog entry backed by stored run evidence.',
    source_run_id: run.id,
    generated_at: now,
    available_formats: ['markdown', 'html', 'pdf'],
    methodology_references: ['OWASP WSTG'],
    source_scope_profile: { run_profile: run.profile.name },
    included_findings: { total: findings.length },
    included_inventory: { hosts: 1 },
    evidence_status: { verified: true },
    compliance_summary: {},
    assurance_summary: {},
    adaptive_change_summary: {},
    ai_draft_summary: {},
    run_narrative_summary: {},
    version_label: 'fixture-v1',
    content_sha256: 'a'.repeat(64),
    availability_status: 'export_ready',
    availability_label: 'ready',
    availability_reason: 'Available from stored fixture evidence.',
    preview_allowed: true,
    export_allowed: true,
    draft_allowed: false,
    lifecycle_summary: {},
    export_paths: { html: '/fixture/report.html', pdf: '/fixture/report.pdf' },
    download_names: { html: 'fixture-report.html', pdf: 'fixture-report.pdf' },
  },
];

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

test('Dashboard renders portfolio data from mocked v2 API contracts', async ({ page }) => {
  await page.goto('/app-v2/');

  await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible();
  await expect(page.getByRole('main').getByText('Acme External Web')).toBeVisible();
  await expect(page.getByText('Portfolio Risk')).toBeVisible();
  await expect(page.getByRole('main').getByText('8.2', { exact: true }).first()).toBeVisible();
  await expect(page.getByText('Activity Feed')).toBeVisible();
  await expect(page.getByText('Run completed with evidence attached')).toBeVisible();
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
  await expect(page.getByRole('button', { name: /Critical stored XSS in profile preview/ })).toBeVisible();
  await expect(page.getByRole('button', { name: /High-risk missing HSTS header/ })).toBeVisible();

  await page.locator('label').filter({ hasText: 'Severity' }).locator('select').selectOption('critical');

  await expect(page.getByRole('button', { name: /Critical stored XSS in profile preview/ })).toBeVisible();
  await expect(page.getByRole('button', { name: /High-risk missing HSTS header/ })).toHaveCount(0);

  await page.getByLabel('Search').fill('profile');
  await expect(page.getByText('Raw Evidence View')).toBeVisible();
});

test('Mission Control refreshes and expands bounded task output from fixtures', async ({ page }) => {
  await page.goto('/app-v2/mission-control');

  await expect(page.getByRole('heading', { name: 'Mission Control' })).toBeVisible();
  await expect(page.getByText('Active Work')).toBeVisible();
  await expect(page.getByText(/other run\(s\) are active/)).toBeVisible();
  await expect(page.getByText('Live Command Console')).toBeVisible();
  await expect(page.getByText('Task Ledger')).toBeVisible();
  await expect(page.getByText('Single source for selected task command')).toBeVisible();
  await expect(page.getByRole('button', { name: /Cinema Mode/ })).toBeVisible();
  await expect(page.getByRole('button', { name: /Kill Run/ })).toBeVisible();
  await expect(page.getByText('1 reasoning records')).toBeVisible();
  await page.getByRole('button', { name: /Refresh/ }).click();
  await expect(page.getByText('Run data refreshed from backend.')).toBeVisible();
  await expect(page.getByText('Completed with gaps: 1 failed, 1 not run.')).toBeVisible();
  await expect(page.getByText('not run', { exact: true }).first()).toBeVisible();

  await page.getByRole('button', { name: /httpx/ }).click();
  await expect(page.getByText('bounded fixture output: GET /profile returned stored evidence only')).toBeVisible();
  await expect(page.getByText('$ httpx https://app.example.test')).toBeVisible();
  await expect(page.getByRole('img', { name: 'Run inventory scan map' })).toBeVisible();
});

test('Mission Control explains queued checks without calling them running', async ({ page }) => {
  await page.goto('/app-v2/mission-control');

  await page.getByRole('button', { name: /active-web-ssrf-probe/ }).click();

  await expect(page.getByText('ssrf-probe is queued, not running')).toBeVisible();
  await expect(page.getByText('ssrf-probe is running')).toHaveCount(0);
});

test('Cinema Mode opens as a full viewport replay overlay with visible exit and command feed', async ({ page }) => {
  await page.goto('/app-v2/mission-control');

  await page.getByRole('button', { name: /Cinema Mode/ }).click();
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
    await expect(page.getByRole('heading', { name: heading, exact: true })).toBeVisible();
    await expect(page.getByText('The view stopped rendering safely.')).toHaveCount(0);
    await expect(page.getByText(/Unhandled fixture route/)).toHaveCount(0);
    const content = (await page.getByRole('main').innerText()).trim();
    expect(content.length, `${path} should not render as an empty shell`).toBeGreaterThan(120);
  }
});

async function installApiFixtures(page: Page, options: { dashboard?: ReturnType<typeof dashboardPayload> } = {}) {
  await page.route('**/api/v1/**', async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    const path = url.pathname;
    const method = request.method();

    if (method === 'GET' && path === '/api/v1/engagements') return json(route, [engagement]);
    if (method === 'GET' && path === `/api/v1/engagements/${engagement.id}/runs`) return json(route, [run, chainReasoningRun, runningRun, queuedRun]);
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
    if (method === 'GET' && path === `/api/v1/inventory/${inventory.id}`) return json(route, inventory);
    if (method === 'GET' && path === `/api/v1/engagements/${engagement.id}/inventory`) return json(route, [inventory]);
    if (method === 'GET' && path === `/api/v1/runs/${run.id}/ai-insights`) return json(route, selectedRunAiInsights);
    if (method === 'GET' && path === `/api/v1/runs/${chainReasoningRun.id}/ai-insights`) return json(route, chainAiInsights);
    if (method === 'GET' && path === `/api/v1/runs/${runningRun.id}/ai-insights`) return json(route, { ...aiInsights, run_id: runningRun.id, reasoning_records: [], proposals: [] });
    if (method === 'GET' && path === `/api/v1/runs/${queuedRun.id}/ai-insights`) return json(route, { ...aiInsights, run_id: queuedRun.id, reasoning_records: [], proposals: [] });
    if (method === 'GET' && path === `/api/v1/runs/${run.id}/reports`) return json(route, reportCatalog);
    if (method === 'GET' && path === `/api/v1/runs/${run.id}/report`) return json(route, '# Executive Summary\n\nStored fixture evidence preview for React v2 route coverage.');
    if (method === 'GET' && path === `/api/v1/tasks/${tasks[0].id}`) return json(route, taskDetail(tasks[0]));
    if (method === 'GET' && path === `/api/v1/tasks/${tasks[1].id}`) return json(route, taskDetail(tasks[1]));
    if (method === 'GET' && path === `/api/v1/tasks/${tasks[2].id}`) return json(route, taskDetail(tasks[2]));
    if (method === 'GET' && path === `/api/v1/tasks/${tasks[3].id}`) return json(route, taskDetail(tasks[3]));
    if (method === 'GET' && path === '/api/v1/dashboard') return json(route, options.dashboard ?? dashboardPayload());
    if (method === 'GET' && path === '/api/v1/settings') return json(route, settingsPayload());
    if (method === 'GET' && path === '/api/v1/settings/readiness') return json(route, readinessPayload());
    if (method === 'GET' && path === '/api/v1/problems') return json(route, problemsPayload());
    if (method === 'GET' && path === `/api/v1/engagements/${engagement.id}/packs`) return json(route, [pack]);
    if (method === 'GET' && path === `/api/v1/packs/${pack.id}/artifacts`) return json(route, packArtifactsPayload());
    if (method === 'GET' && path === '/api/v1/custom-vulnerabilities') return json(route, { items: [customVulnerability], total: 1, filters: {} });
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
    if (method === 'GET' && theaterMatch) return json(route, theaterPayload(theaterMatch[1]));

    const evidenceMatch = path.match(/^\/api\/v1\/findings\/([^/]+)\/evidence$/);
    if (method === 'GET' && evidenceMatch) return json(route, evidencePayload(evidenceMatch[1]));

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

function problemsPayload() {
  const items = findings.map((item, index) => ({
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

function taskDetail(task: (typeof tasks)[number]) {
  return {
    ...task,
    run_id: run.id,
    executions: [
      {
        id: `exec-${task.id}`,
        runner_digest: 'sha256:fixture',
        tool_version: 'fixture',
        exit_code: 0,
        stdout_text: 'bounded fixture output: GET /profile returned stored evidence only',
        stderr_text: null,
        created_at: now,
        artifacts: [],
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
      lines: [{ sequence: 1, text: 'bounded fixture output: GET /profile returned stored evidence only' }],
    },
  };
}

function theaterPayload(findingId: string) {
  const selected = findings.find((item) => item.id === findingId) ?? findings[0];
  return {
    finding: selected,
    severity_rank: selected.severity === 'critical' ? 1 : 2,
    confidence_label: 'confirmed',
    exploitability: 'review-only fixture',
    business_impact: 'Customer data exposure risk from stored evidence.',
    technical_details: `${selected.title} technical detail from stored fixture evidence.`,
    evidence_summary: 'Stored evidence summary only.',
    provenance: { fixture: true },
    methodology: { owasp: { framework: 'OWASP WSTG', category: selected.owasp_category, reference: selected.owasp_reference } },
    remediation: { detail: 'Sanitize output and retest through normal approval gates.' },
    ai_enrichment: { available: false },
    autofix: {},
    repository_context: {},
    threat_context: {},
    detection_engineering: {},
    vulnerability_chains: { available: false, chains: [] },
    threat_intel_badges: {},
    validation: { status: 'confirmed' },
    evidence_integrity: { sha256: 'fixture-sha256' },
    verification_status: 'confirmed',
    next_steps: ['Review stored evidence.', 'Apply remediation.', 'Retest with operator approval.'],
    risk_snapshot: { score: selected.cvss_score },
  };
}

function evidencePayload(findingId: string) {
  const selected = findings.find((item) => item.id === findingId) ?? findings[0];
  return {
    finding: selected,
    evidence_ref: selected.evidence_ref,
    methodology_references: {},
    pack_provenance: {},
    inventory_source: {},
    relevance_source: {},
    validation_history: [],
    related_executions: [
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
