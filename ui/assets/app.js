const ASSESSMENT_TYPES = [
  "Website / Web App",
  "Domain / Domains",
  "External IP / WAN",
  "Internal Range / LAN",
  "API",
  "SSL/TLS Only",
  "Authenticated App",
  "Mixed Assessment",
];

const TEST_PROFILES = [
  "Light",
  "Standard",
  "Deep",
  "External Surface Only",
  "Authenticated Only",
  "SSL/TLS Only",
  "Internal Validation",
  "Adaptive Customer-Specific Mode",
];

const MODULES = [
  ["discovery", "Discovery"],
  ["web_crawling", "Web Crawling"],
  ["auth_flows", "Auth Flows"],
  ["content_discovery", "Content / Directory Discovery"],
  ["nuclei_checks", "Nuclei Checks"],
  ["zap_active_checks", "ZAP Active Checks"],
  ["ssl_tls_analysis", "SSL / TLS Analysis"],
  ["business_logic_testing", "Business Logic Testing"],
  ["adaptive_ai_generated_tests", "Adaptive AI-Generated Tests"],
  ["internal_validation_modules", "Internal Validation Modules"],
];

const WIZARD_STEPS = [
  "Assessment Type",
  "Scope Input",
  "Credentials / Access",
  "Test Profile",
  "Test Modules",
  "Safety / Limits",
  "Review / Confirm",
];

const DEFAULT_MODULE_STATE = {
  discovery: true,
  web_crawling: true,
  auth_flows: false,
  content_discovery: true,
  nuclei_checks: true,
  zap_active_checks: false,
  ssl_tls_analysis: true,
  business_logic_testing: false,
  adaptive_ai_generated_tests: true,
  internal_validation_modules: false,
};

const DEFAULT_SAFETY = {
  rate_limit_rps: 2,
  concurrency: 2,
  time_budget_minutes: 90,
  active_checks: "guarded",
  adaptive_generation: true,
  max_validation_depth: "standard",
};

const REPORT_VARIANTS = [
  ["executive", "Executive Report"],
  ["technical", "Technical Report"],
  ["evidence", "Evidence Appendix"],
  ["retest", "Retest / Verification Report"],
];

const SEVERITY_RANK = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
  unknown: 5,
};

const state = {
  actor: window.localStorage.getItem("aegispt-actor") || "operator-ui",
  activeScreen: "wizard",
  engagements: [],
  runProfiles: [],
  codexTasks: [],
  internalValidationScenarios: [],
  selectedEngagementId: null,
  selectedRunId: null,
  selectedPackId: null,
  selectedFindingId: null,
  selectedTaskId: null,
  selectedCodexTaskId: null,
  comparisonBaselineRunId: null,
  reportVariant: "technical",
  reportFormat: "markdown",
  reportPreview: "",
  reportHtml: "",
  reportCatalog: [],
  selectedRun: null,
  selectedTask: null,
  selectedPackBundle: null,
  selectedFindingTheater: null,
  selectedFindingEvidence: null,
  selectedCodexResult: null,
  selectedCodexContext: null,
  surfaceOverlays: {
    hotspots: true,
    packZones: true,
    futureAttackPaths: false,
    futureIdentityGraph: false,
    futureRiskOverlay: false,
  },
  findingFilters: {
    runId: "all",
    severity: "all",
    origin: "all",
    status: "all",
    methodology: "all",
    groupBy: "severity",
  },
  mission: {
    scope: null,
    inventory: [],
    relevance: [],
    packs: [],
    runs: [],
    internalValidations: [],
    findingsByRun: {},
  },
  wizard: buildEmptyWizardState(),
};

const dom = {};
const statusFeed = [];
let refreshTimer = null;

document.addEventListener("DOMContentLoaded", () => {
  bindDom();
  bindGlobalEvents();
  boot().catch(handleError);
});

function buildEmptyWizardState() {
  return {
    step: 0,
    errors: [],
    useExistingEngagement: false,
    lastCreated: null,
    submitting: false,
    data: {
      engagement_name: "",
      client: "",
      roe_ref: "",
      assessment_type: "Website / Web App",
      targets: {
        domains: [],
        subdomains: [],
        urls: [],
        ip_addresses: [],
        cidr_ranges: [],
        api_base_urls: [],
      },
      access: {
        accounts: [buildEmptyAccount()],
        manual_auth_steps: "",
        cookie_notes: "",
      },
      test_profile: "Standard",
      modules: { ...DEFAULT_MODULE_STATE },
      safety: { ...DEFAULT_SAFETY },
    },
  };
}

function buildEmptyAccount() {
  return {
    label: "Primary Account",
    username: "",
    role: "User",
    secret_ref: "",
    api_key_ref: "",
    bearer_token_ref: "",
    session_ref: "",
    mfa_notes: "",
  };
}

function bindDom() {
  dom.actorInput = document.getElementById("actor-input");
  dom.heroMetrics = document.getElementById("hero-metrics");
  dom.engagementSelect = document.getElementById("engagement-select");
  dom.refreshBtn = document.getElementById("refresh-btn");
  dom.screenLinks = Array.from(document.querySelectorAll(".screen-link"));
  dom.selectedEngagementSummary = document.getElementById("selected-engagement-summary");
  dom.statusFeed = document.getElementById("status-feed");
  dom.wizardStepper = document.getElementById("wizard-stepper");
  dom.wizardPanel = document.getElementById("wizard-panel");
  dom.wizardSummary = document.getElementById("wizard-summary");
  dom.wizardErrors = document.getElementById("wizard-errors");
  dom.wizardBackBtn = document.getElementById("wizard-back-btn");
  dom.wizardNextBtn = document.getElementById("wizard-next-btn");
  dom.wizardConfirmBtn = document.getElementById("wizard-confirm-btn");
  dom.missionTimeline = document.getElementById("mission-timeline");
  dom.missionActivity = document.getElementById("mission-activity");
  dom.missionGood = document.getElementById("mission-good");
  dom.missionBad = document.getElementById("mission-bad");
  dom.missionUnknown = document.getElementById("mission-unknown");
  dom.missionEta = document.getElementById("mission-eta");
  dom.missionFindingsPulse = document.getElementById("mission-findings-pulse");
  dom.missionAiNarrative = document.getElementById("mission-ai-narrative");
  dom.missionPackStatus = document.getElementById("mission-pack-status");
  dom.missionScopeSummary = document.getElementById("mission-scope-summary");
  dom.surfaceToggleBar = document.getElementById("surface-toggle-bar");
  dom.surfaceMapCanvas = document.getElementById("surface-map-canvas");
  dom.surfaceInsights = document.getElementById("surface-insights");
  dom.surfaceLegend = document.getElementById("surface-legend");
  dom.findingsFilterBar = document.getElementById("findings-filter-bar");
  dom.findingsGroupList = document.getElementById("findings-group-list");
  dom.findingTheaterDetail = document.getElementById("finding-theater-detail");
  dom.evidenceOverview = document.getElementById("evidence-overview");
  dom.evidenceExecutions = document.getElementById("evidence-executions");
  dom.evidenceArtifacts = document.getElementById("evidence-artifacts");
  dom.evidenceLineage = document.getElementById("evidence-lineage");
  dom.adaptiveForm = document.getElementById("adaptive-form");
  dom.validatePackBtn = document.getElementById("validate-pack-btn");
  dom.approvePackBtn = document.getElementById("approve-pack-btn");
  dom.deployPackBtn = document.getElementById("deploy-pack-btn");
  dom.packSummary = document.getElementById("pack-summary");
  dom.packForgeDetail = document.getElementById("pack-forge-detail");
  dom.codexTaskForm = document.getElementById("codex-task-form");
  dom.prepareCodexTaskBtn = document.getElementById("prepare-codex-task-btn");
  dom.codexContext = document.getElementById("codex-context");
  dom.codexTaskResult = document.getElementById("codex-task-result");
  dom.reportCatalog = document.getElementById("report-catalog");
  dom.reportMetadata = document.getElementById("report-metadata");
  dom.reportActions = document.getElementById("report-actions");
  dom.reportPreview = document.getElementById("report-preview");
  dom.reportFrame = document.getElementById("report-frame");
  dom.reportCompare = document.getElementById("report-compare");
  dom.customerIndex = document.getElementById("customer-index");
  dom.engagementDossiers = document.getElementById("engagement-dossiers");
  dom.runDossier = document.getElementById("run-dossier");
  dom.historyToolbar = document.getElementById("history-toolbar");
  dom.comparisonSummary = document.getElementById("comparison-summary");
  dom.historyTrend = document.getElementById("history-trend");
  dom.nextStepsQueue = document.getElementById("next-steps-queue");
}

function bindGlobalEvents() {
  dom.actorInput.value = state.actor;
  dom.actorInput.addEventListener("change", (event) => {
    state.actor = event.target.value.trim() || "operator-ui";
    window.localStorage.setItem("aegispt-actor", state.actor);
    pushStatus("Actor updated for API requests.", "info");
    renderHeader();
    renderStatus();
  });

  dom.engagementSelect.addEventListener("change", async (event) => {
    state.selectedEngagementId = event.target.value || null;
    state.selectedRunId = null;
    state.selectedPackId = null;
    state.selectedFindingId = null;
    state.selectedTaskId = null;
    await refreshSelectedEngagement();
  });

  dom.refreshBtn.addEventListener("click", () => refreshSelectedEngagement().catch(handleError));

  dom.screenLinks.forEach((button) => {
    button.addEventListener("click", () => {
      state.activeScreen = button.dataset.screen;
      renderScreens();
    });
  });

  dom.wizardBackBtn.addEventListener("click", () => {
    syncWizardStepFromDom();
    state.wizard.errors = [];
    state.wizard.step = Math.max(0, state.wizard.step - 1);
    renderWizard();
  });

  dom.wizardNextBtn.addEventListener("click", () => {
    syncWizardStepFromDom();
    const errors = validateWizardStep(state.wizard.step);
    if (errors.length) {
      state.wizard.errors = errors;
      renderWizard();
      return;
    }
    state.wizard.errors = [];
    state.wizard.step = Math.min(WIZARD_STEPS.length - 1, state.wizard.step + 1);
    renderWizard();
  });

  dom.wizardConfirmBtn.addEventListener("click", () => submitWizard().catch(handleError));

  dom.validatePackBtn.addEventListener("click", () => validateSelectedPack().catch(handleError));
  dom.approvePackBtn.addEventListener("click", () => approveSelectedPack().catch(handleError));
  dom.deployPackBtn.addEventListener("click", () => deploySelectedPack().catch(handleError));
  dom.prepareCodexTaskBtn.addEventListener("click", () => prepareSelectedCodexTask().catch(handleError));
}

async function boot() {
  await refreshShell();
  renderAll();
  startAutoRefresh();
}

function startAutoRefresh() {
  if (refreshTimer) {
    window.clearInterval(refreshTimer);
  }
  refreshTimer = window.setInterval(() => {
    if (!state.selectedEngagementId) return;
    refreshSelectedEngagement().catch(handleError);
  }, 20000);
}

async function refreshShell() {
  const [engagements, runProfiles, codexTasks, scenarios] = await Promise.all([
    api("/api/v1/engagements"),
    api("/api/v1/run-profiles"),
    api("/api/v1/codex/tasks"),
    api("/api/v1/internal-validations/scenarios"),
  ]);
  state.engagements = engagements;
  state.runProfiles = runProfiles;
  state.codexTasks = codexTasks;
  state.internalValidationScenarios = scenarios;
  if (!state.selectedEngagementId && engagements.length) {
    state.selectedEngagementId = engagements[0].id;
  }
  populateEngagementSelect();
  if (state.selectedEngagementId) {
    await refreshSelectedEngagement();
  }
}

async function refreshSelectedEngagement() {
  populateEngagementSelect();
  if (!state.selectedEngagementId) {
    state.mission = {
      scope: null,
      inventory: [],
      relevance: [],
      packs: [],
      runs: [],
      internalValidations: [],
      findingsByRun: {},
    };
    state.selectedRun = null;
    state.selectedPackBundle = null;
    state.selectedFindingTheater = null;
    state.selectedFindingEvidence = null;
    state.selectedTask = null;
    state.reportCatalog = [];
    renderAll();
    return;
  }

  const [scope, inventory, relevance, packs, runs, internalValidations, codexTasks] = await Promise.all([
    apiOrNull(`/api/v1/engagements/${state.selectedEngagementId}/scope`),
    api(`/api/v1/engagements/${state.selectedEngagementId}/inventory`),
    api(`/api/v1/engagements/${state.selectedEngagementId}/relevance`),
    api(`/api/v1/engagements/${state.selectedEngagementId}/packs`),
    api(`/api/v1/engagements/${state.selectedEngagementId}/runs`),
    api(`/api/v1/engagements/${state.selectedEngagementId}/internal-validations`),
    api("/api/v1/codex/tasks"),
  ]);

  const findingsEntries = await Promise.all(
    runs.map(async (run) => [run.id, await api(`/api/v1/runs/${run.id}/findings`)])
  );
  state.mission = {
    scope,
    inventory,
    relevance,
    packs,
    runs,
    internalValidations,
    findingsByRun: Object.fromEntries(findingsEntries),
  };
  state.codexTasks = codexTasks;

  if (!state.selectedRunId || !runs.some((run) => run.id === state.selectedRunId)) {
    state.selectedRunId = runs[0]?.id || null;
  }
  if (!state.comparisonBaselineRunId || !runs.some((run) => run.id === state.comparisonBaselineRunId)) {
    state.comparisonBaselineRunId = runs[1]?.id || null;
  }
  if (!state.selectedPackId || !packs.some((pack) => pack.id === state.selectedPackId)) {
    state.selectedPackId = packs[0]?.id || null;
  }

  await Promise.all([loadSelectedRun(), loadSelectedPack()]);
  renderAll();
}

async function loadSelectedRun() {
  if (!state.selectedRunId) {
    state.selectedRun = null;
    state.selectedFindingId = null;
    state.selectedFindingTheater = null;
    state.selectedFindingEvidence = null;
    state.selectedTask = null;
    state.reportCatalog = [];
    return;
  }

  state.reportPreview = "";
  state.reportHtml = "";
  state.selectedRun = await api(`/api/v1/runs/${state.selectedRunId}`);
  state.reportCatalog = await api(`/api/v1/runs/${state.selectedRunId}/reports`);
  const findings = state.mission.findingsByRun[state.selectedRunId] || [];
  if (!state.selectedFindingId || !findings.some((finding) => finding.id === state.selectedFindingId)) {
    state.selectedFindingId = findings[0]?.id || null;
  }
  if (!state.selectedTaskId || !state.selectedRun.tasks.some((task) => task.id === state.selectedTaskId)) {
    state.selectedTaskId = state.selectedRun.tasks[0]?.id || null;
  }
  await Promise.all([loadSelectedFinding(), loadSelectedTask()]);
}

async function loadSelectedFinding() {
  if (!state.selectedFindingId) {
    state.selectedFindingTheater = null;
    state.selectedFindingEvidence = null;
    return;
  }
  const [theater, evidence] = await Promise.all([
    api(`/api/v1/findings/${state.selectedFindingId}/theater`),
    api(`/api/v1/findings/${state.selectedFindingId}/evidence`),
  ]);
  state.selectedFindingTheater = theater;
  state.selectedFindingEvidence = evidence;
  const relatedTaskId = evidence.related_executions[0]?.task_id || null;
  if (relatedTaskId && (!state.selectedTaskId || state.selectedTaskId !== relatedTaskId)) {
    state.selectedTaskId = relatedTaskId;
  }
}

async function loadSelectedTask() {
  if (!state.selectedTaskId) {
    state.selectedTask = null;
    return;
  }
  state.selectedTask = await api(`/api/v1/tasks/${state.selectedTaskId}`);
}

async function loadSelectedPack() {
  if (!state.selectedPackId) {
    state.selectedPackBundle = null;
    state.selectedCodexContext = null;
    return;
  }
  state.selectedPackBundle = await api(`/api/v1/packs/${state.selectedPackId}/codex-review-bundle`);
  state.selectedCodexContext = state.selectedPackBundle.context;
}

function populateEngagementSelect() {
  if (!dom.engagementSelect) return;
  dom.engagementSelect.innerHTML = state.engagements.length
    ? state.engagements
        .map(
          (engagement) =>
            `<option value="${engagement.id}" ${engagement.id === state.selectedEngagementId ? "selected" : ""}>${escapeHtml(engagement.name)}${engagement.client ? ` · ${escapeHtml(engagement.client)}` : ""}</option>`
        )
        .join("")
    : `<option value="">No engagements yet</option>`;
}

function selectedEngagement() {
  return state.engagements.find((engagement) => engagement.id === state.selectedEngagementId) || null;
}

function latestInventorySnapshot() {
  return state.mission.inventory[0] || null;
}

function latestRelevanceDecision() {
  return state.mission.relevance[0] || null;
}

function selectedPack() {
  return state.mission.packs.find((pack) => pack.id === state.selectedPackId) || null;
}

function engagementFindings() {
  return Object.entries(state.mission.findingsByRun).flatMap(([runId, findings]) =>
    findings.map((finding) => ({ ...finding, _runId: runId }))
  );
}

function selectedRunFindings() {
  return state.selectedRunId ? state.mission.findingsByRun[state.selectedRunId] || [] : [];
}

function renderAll() {
  renderHeader();
  renderSelectedEngagementSummary();
  renderStatus();
  renderScreens();
}

function renderHeader() {
  const runCount = state.mission.runs.length || 0;
  const findings = engagementFindings();
  const criticalCount = findings.filter((finding) => finding.severity === "critical").length;
  const openCount = findings.filter((finding) => ["open", "triaged", "in_progress", "reopened"].includes(finding.status)).length;
  const activePack = selectedPack();
  dom.heroMetrics.innerHTML = [
    heroChip(`${state.engagements.length} engagements`, "dossiers"),
    heroChip(`${runCount} runs`, "missions"),
    heroChip(`${findings.length} findings`, `${criticalCount} critical`),
    heroChip(`${openCount} open items`, activePack ? activePack.version : "baseline"),
  ].join("");
}

function renderSelectedEngagementSummary() {
  const engagement = selectedEngagement();
  if (!engagement) {
    dom.selectedEngagementSummary.innerHTML = emptyState("Complete the Assessment Wizard to create the first mission dossier.");
    return;
  }
  const scope = state.mission.scope;
  const currentRun = state.selectedRun;
  const config = currentRun?.configuration_json || {};
  dom.selectedEngagementSummary.innerHTML = `
    <div class="badge">Customer · ${escapeHtml(engagement.client || "Not set")}</div>
    <div class="badge">Engagement · ${escapeHtml(engagement.name)}</div>
    <div class="badge">ROE · ${escapeHtml(engagement.roe_ref || "Not set")}</div>
    <div class="badge">Status · ${escapeHtml(engagement.status)}</div>
    <div class="badge">Targets · ${countScopeTargets(scope)}</div>
    <div class="badge">Profile · ${escapeHtml(config.test_profile || currentRun?.profile?.name || "Not configured")}</div>
  `;
}

function renderStatus() {
  dom.statusFeed.innerHTML = statusFeed.length
    ? statusFeed
        .map(
          (item) => `
            <div class="feed-item">
              <strong>${escapeHtml(item.timestamp)} · ${escapeHtml(item.tone)}</strong>
              <p>${escapeHtml(item.message)}</p>
            </div>
          `
        )
        .join("")
    : emptyState("Wizard actions, pack promotion events, and report activity appear here.");
}

function renderScreens() {
  document.querySelectorAll(".screen").forEach((screen) => {
    screen.classList.toggle("active", screen.id === `screen-${state.activeScreen}`);
  });
  dom.screenLinks.forEach((button) => {
    button.classList.toggle("active", button.dataset.screen === state.activeScreen);
  });
  renderWizard();
  renderMissionControl();
  renderSurfaceMap();
  renderFindingsTheater();
  renderEvidenceReplay();
  renderPackForge();
  renderReportCenter();
  renderExplorer();
  renderHistoryComparison();
}

function renderWizard() {
  const wizard = state.wizard;
  const estimate = estimateMission(wizard.data);
  dom.wizardStepper.innerHTML = WIZARD_STEPS.map((label, index) => `
      <div class="wizard-step ${index === wizard.step ? "active" : ""} ${index < wizard.step ? "complete" : ""}">
        <small>Step ${index + 1}</small>
        <strong>${escapeHtml(label)}</strong>
      </div>
    `).join("");

  dom.wizardPanel.innerHTML = wizardStepContent(wizard.step, wizard.data, wizard.useExistingEngagement);
  dom.wizardErrors.innerHTML = wizard.errors.length
    ? wizard.errors.map((error) => `<div>${escapeHtml(error)}</div>`).join("")
    : "";
  dom.wizardSummary.innerHTML = renderWizardSummary(wizard, estimate);
  dom.wizardBackBtn.disabled = wizard.step === 0 || wizard.submitting;
  dom.wizardNextBtn.classList.toggle("hidden", wizard.step === WIZARD_STEPS.length - 1);
  dom.wizardConfirmBtn.classList.toggle("hidden", wizard.step !== WIZARD_STEPS.length - 1);
  dom.wizardConfirmBtn.disabled = wizard.submitting;
  dom.wizardNextBtn.disabled = wizard.submitting;
  dom.wizardBackBtn.disabled = wizard.step === 0 || wizard.submitting;

  attachWizardHandlers();
}

function wizardStepContent(step, data, useExistingEngagement) {
  if (step === 0) {
    return `
      <div class="wizard-panel-grid">
        <div class="stack-form">
          <label class="field">
            <span>Mission Mode</span>
            <div class="option-card">
              <input id="wizard-use-existing" type="checkbox" ${useExistingEngagement ? "checked" : ""} ${state.engagements.length ? "" : "disabled"} />
              <div>
                <strong>Use the selected engagement dossier</strong>
                <p class="micro-copy">Reuse the engagement selected in the rail and create a new run under it.</p>
              </div>
            </div>
          </label>
          ${useExistingEngagement ? `
            <div class="detail-surface">
              <h4>Selected Engagement</h4>
              <p>${escapeHtml(selectedEngagement()?.name || "No engagement selected")}</p>
              <p class="micro-copy">${escapeHtml(selectedEngagement()?.client || "Client not set")}</p>
            </div>
          ` : `
            <label class="field">
              <span>Engagement Name</span>
              <input id="wizard-engagement-name" type="text" value="${escapeHtml(data.engagement_name)}" placeholder="Acme External Validation" />
            </label>
            <label class="field">
              <span>Customer</span>
              <input id="wizard-client" type="text" value="${escapeHtml(data.client)}" placeholder="Acme Corp" />
            </label>
            <label class="field">
              <span>ROE Reference</span>
              <input id="wizard-roe-ref" type="text" value="${escapeHtml(data.roe_ref)}" placeholder="ROE-2026-200" />
            </label>
          `}
        </div>
        <div class="stack-form">
          <span class="inline-label">Assessment Type</span>
          <div class="toggle-grid">
            ${ASSESSMENT_TYPES.map((type) => `
              <label class="option-card">
                <input type="radio" name="wizard-assessment-type" value="${escapeHtml(type)}" ${data.assessment_type === type ? "checked" : ""} />
                <div>
                  <strong>${escapeHtml(type)}</strong>
                  <p class="micro-copy">${escapeHtml(assessmentTypeCopy(type))}</p>
                </div>
              </label>
            `).join("")}
          </div>
        </div>
      </div>
    `;
  }

  if (step === 1) {
    const visibleGroups = visibleTargetGroups(data.assessment_type);
    return `
      <div class="wizard-panel-grid">
        ${visibleGroups.includes("domains") ? textareaField("wizard-target-domains", "Domains", data.targets.domains, "example.com\nshop.example.com") : ""}
        ${visibleGroups.includes("subdomains") ? textareaField("wizard-target-subdomains", "Subdomains", data.targets.subdomains, "api.example.com\nadmin.example.com") : ""}
        ${visibleGroups.includes("urls") ? textareaField("wizard-target-urls", "URLs", data.targets.urls, "https://example.com\nhttps://example.com/login") : ""}
        ${visibleGroups.includes("ip_addresses") ? textareaField("wizard-target-ip-addresses", "IP Addresses", data.targets.ip_addresses, "203.0.113.5\n203.0.113.8") : ""}
        ${visibleGroups.includes("cidr_ranges") ? textareaField("wizard-target-cidrs", "CIDR Ranges", data.targets.cidr_ranges, "10.10.0.0/24") : ""}
        ${visibleGroups.includes("api_base_urls") ? textareaField("wizard-target-api", "API Base URLs", data.targets.api_base_urls, "https://api.example.com/v1") : ""}
      </div>
    `;
  }

  if (step === 2) {
    return `
      <div class="stack-zone">
        ${data.access.accounts.map((account, index) => `
          <div class="account-card" data-account-card="${index}">
            <div class="panel-head">
              <div>
                <p class="eyebrow">Account ${index + 1}</p>
                <h4>${escapeHtml(account.label || `Account ${index + 1}`)}</h4>
              </div>
              <button class="action ghost wizard-remove-account-btn" type="button" data-account-remove="${index}" ${data.access.accounts.length === 1 ? "disabled" : ""}>Remove</button>
            </div>
            <div class="wizard-panel-grid">
              <label class="field">
                <span>Label</span>
                <input data-account-field="label" data-account-index="${index}" type="text" value="${escapeHtml(account.label)}" placeholder="Primary User" />
              </label>
              <label class="field">
                <span>Username</span>
                <input data-account-field="username" data-account-index="${index}" type="text" value="${escapeHtml(account.username)}" placeholder="tester@example.com" />
              </label>
              <label class="field">
                <span>Role</span>
                <input data-account-field="role" data-account-index="${index}" type="text" value="${escapeHtml(account.role)}" placeholder="Admin" />
              </label>
              <label class="field">
                <span>Password / Secret Reference</span>
                <input data-account-field="secret_ref" data-account-index="${index}" type="text" value="${escapeHtml(account.secret_ref)}" placeholder="vault://prod/app/admin" />
              </label>
              <label class="field">
                <span>API Key Reference</span>
                <input data-account-field="api_key_ref" data-account-index="${index}" type="text" value="${escapeHtml(account.api_key_ref)}" placeholder="vault://prod/api/key" />
              </label>
              <label class="field">
                <span>Bearer Token Reference</span>
                <input data-account-field="bearer_token_ref" data-account-index="${index}" type="text" value="${escapeHtml(account.bearer_token_ref)}" placeholder="vault://prod/api/bearer" />
              </label>
              <label class="field">
                <span>Cookie / Session Label</span>
                <input data-account-field="session_ref" data-account-index="${index}" type="text" value="${escapeHtml(account.session_ref)}" placeholder="session-bundle-A" />
              </label>
              <label class="field">
                <span>MFA Notes / Manual Auth Steps</span>
                <textarea data-account-field="mfa_notes" data-account-index="${index}" rows="3" placeholder="Manual OTP or SSO handoff notes">${escapeHtml(account.mfa_notes)}</textarea>
              </label>
            </div>
          </div>
        `).join("")}
        <div class="action-row">
          <button id="wizard-add-account-btn" class="action ghost" type="button">Add Account / Role</button>
        </div>
        <label class="field">
          <span>Shared Manual Auth Steps</span>
          <textarea id="wizard-manual-auth-steps" rows="3" placeholder="Manual login, device trust, or MFA sequencing">${escapeHtml(data.access.manual_auth_steps)}</textarea>
        </label>
        <label class="field">
          <span>Cookie / Session Notes</span>
          <textarea id="wizard-cookie-notes" rows="3" placeholder="Session capture notes or cookie replay guidance">${escapeHtml(data.access.cookie_notes)}</textarea>
        </label>
      </div>
    `;
  }

  if (step === 3) {
    return `
      <div class="toggle-grid">
        ${TEST_PROFILES.map((profile) => `
          <label class="option-card">
            <input type="radio" name="wizard-test-profile" value="${escapeHtml(profile)}" ${data.test_profile === profile ? "checked" : ""} />
            <div>
              <strong>${escapeHtml(profile)}</strong>
              <p class="micro-copy">${escapeHtml(testProfileCopy(profile))}</p>
            </div>
          </label>
        `).join("")}
      </div>
    `;
  }

  if (step === 4) {
    return `
      <div class="toggle-grid">
        ${MODULES.map(([key, label]) => `
          <label class="toggle-card">
            <input type="checkbox" data-module-key="${key}" ${data.modules[key] ? "checked" : ""} />
            <div>
              <strong>${escapeHtml(label)}</strong>
              <p class="micro-copy">${escapeHtml(moduleCopy(key))}</p>
            </div>
          </label>
        `).join("")}
      </div>
    `;
  }

  if (step === 5) {
    return `
      <div class="wizard-panel-grid">
        <label class="field">
          <span>Rate Limit (requests / second)</span>
          <input id="wizard-rate-limit" type="number" min="1" max="20" value="${escapeHtml(String(data.safety.rate_limit_rps))}" />
        </label>
        <label class="field">
          <span>Concurrency</span>
          <input id="wizard-concurrency" type="number" min="1" max="10" value="${escapeHtml(String(data.safety.concurrency))}" />
        </label>
        <label class="field">
          <span>Time Budget (minutes)</span>
          <input id="wizard-time-budget" type="number" min="15" max="1440" value="${escapeHtml(String(data.safety.time_budget_minutes))}" />
        </label>
        <label class="field">
          <span>Active Checks</span>
          <select id="wizard-active-checks">
            ${["passive-only", "guarded", "active"].map((mode) => `<option value="${mode}" ${data.safety.active_checks === mode ? "selected" : ""}>${escapeHtml(mode)}</option>`).join("")}
          </select>
        </label>
        <label class="field">
          <span>Adaptive Generation</span>
          <select id="wizard-adaptive-generation">
            <option value="true" ${data.safety.adaptive_generation ? "selected" : ""}>Enabled</option>
            <option value="false" ${!data.safety.adaptive_generation ? "selected" : ""}>Disabled</option>
          </select>
        </label>
        <label class="field">
          <span>Maximum Validation Depth</span>
          <select id="wizard-max-depth">
            ${["light", "standard", "deep"].map((value) => `<option value="${value}" ${data.safety.max_validation_depth === value ? "selected" : ""}>${escapeHtml(value)}</option>`).join("")}
          </select>
        </label>
      </div>
    `;
  }

  const estimate = estimateMission(data);
  return `
    <div class="stack-zone">
      <div class="detail-surface">
        <h4>Mission Review</h4>
        <p>${escapeHtml(data.assessment_type)} with the ${escapeHtml(data.test_profile)} operator profile will use the ${escapeHtml(estimate.execution_profile)} execution lane.</p>
        <p>${escapeHtml(estimate.summary)}</p>
      </div>
      <div class="wizard-panel-grid">
        <div class="detail-surface">
          <h4>Targets</h4>
          <p>${renderTargetSummary(data.targets)}</p>
        </div>
        <div class="detail-surface">
          <h4>Access</h4>
          <p>${escapeHtml(renderAccountSummary(data.access.accounts))}</p>
        </div>
        <div class="detail-surface">
          <h4>Modules</h4>
          <p>${escapeHtml(enabledModules(data.modules).join(", ") || "None")}</p>
        </div>
        <div class="detail-surface">
          <h4>Safety</h4>
          <p>${escapeHtml(`RPS ${data.safety.rate_limit_rps}, concurrency ${data.safety.concurrency}, budget ${data.safety.time_budget_minutes}m, checks ${data.safety.active_checks}`)}</p>
        </div>
      </div>
      <div class="detail-surface">
        <h4>Confirmation</h4>
        <p>Confirming creates or reuses the engagement, stores the wizard configuration on the run record, seeds the inventory model from the reviewed scope, and opens Mission Control.</p>
      </div>
    </div>
  `;
}

function renderWizardSummary(wizard, estimate) {
  return `
    ${wizard.lastCreated ? `
      <div class="list-card">
        <h4>Last Mission Created</h4>
        <p>${escapeHtml(wizard.lastCreated.engagementName)}</p>
        <p class="micro-copy">Run ${escapeHtml(wizard.lastCreated.runId)}</p>
      </div>
    ` : ""}
    <div class="list-card">
      <h4>Assessment</h4>
      <p>${escapeHtml(wizard.data.assessment_type)}</p>
      <p class="micro-copy">${escapeHtml(estimate.execution_profile)} execution lane</p>
    </div>
    <div class="list-card">
      <h4>Targets</h4>
      <p>${renderTargetSummary(wizard.data.targets)}</p>
    </div>
    <div class="list-card">
      <h4>Access</h4>
      <p>${escapeHtml(renderAccountSummary(wizard.data.access.accounts))}</p>
    </div>
    <div class="list-card">
      <h4>Modules</h4>
      <p>${escapeHtml(enabledModules(wizard.data.modules).join(", ") || "No modules enabled")}</p>
    </div>
    <div class="list-card">
      <h4>Safety</h4>
      <p>${escapeHtml(`RPS ${wizard.data.safety.rate_limit_rps}, concurrency ${wizard.data.safety.concurrency}, budget ${wizard.data.safety.time_budget_minutes}m`)}</p>
      <p class="micro-copy">${escapeHtml(`${wizard.data.safety.active_checks} checks · depth ${wizard.data.safety.max_validation_depth}`)}</p>
    </div>
    <div class="list-card">
      <h4>ETA Model</h4>
      <p>${escapeHtml(`${estimate.estimated_total_minutes} minutes estimated`)}</p>
      <p class="micro-copy">${escapeHtml(`${estimate.estimated_impact} impact · ${estimate.confidence} confidence`)}</p>
    </div>
  `;
}

function attachWizardHandlers() {
  dom.wizardPanel.querySelectorAll("input, textarea, select").forEach((element) => {
    element.addEventListener("input", onWizardInput);
    element.addEventListener("change", onWizardInput);
  });

  const addAccountButton = document.getElementById("wizard-add-account-btn");
  if (addAccountButton) {
    addAccountButton.addEventListener("click", () => {
      syncWizardStepFromDom();
      state.wizard.data.access.accounts.push(buildEmptyAccount());
      renderWizard();
    });
  }

  dom.wizardPanel.querySelectorAll(".wizard-remove-account-btn").forEach((button) => {
    button.addEventListener("click", () => {
      syncWizardStepFromDom();
      const index = Number(button.dataset.accountRemove);
      state.wizard.data.access.accounts.splice(index, 1);
      renderWizard();
    });
  });
}

function onWizardInput(event) {
  if (state.wizard.step === 3 && event.target.name === "wizard-test-profile") {
    syncWizardStepFromDom();
    applyProfilePreset(state.wizard.data.test_profile);
    renderWizard();
    return;
  }
  syncWizardStepFromDom();
  if (
    (state.wizard.step === 0 && (event.target.id === "wizard-use-existing" || event.target.name === "wizard-assessment-type")) ||
    (state.wizard.step === 2 && event.target.dataset.accountField === "label")
  ) {
    renderWizard();
  } else {
    dom.wizardSummary.innerHTML = renderWizardSummary(state.wizard, estimateMission(state.wizard.data));
  }
}

function syncWizardStepFromDom() {
  const wizard = state.wizard;
  const data = wizard.data;
  if (wizard.step === 0) {
    const useExisting = document.getElementById("wizard-use-existing");
    wizard.useExistingEngagement = Boolean(useExisting?.checked);
    data.engagement_name = stringValue(document.getElementById("wizard-engagement-name")?.value);
    data.client = stringValue(document.getElementById("wizard-client")?.value);
    data.roe_ref = stringValue(document.getElementById("wizard-roe-ref")?.value);
    data.assessment_type =
      document.querySelector('input[name="wizard-assessment-type"]:checked')?.value || data.assessment_type;
    return;
  }
  if (wizard.step === 1) {
    data.targets = {
      domains: splitLines(document.getElementById("wizard-target-domains")?.value),
      subdomains: splitLines(document.getElementById("wizard-target-subdomains")?.value),
      urls: splitLines(document.getElementById("wizard-target-urls")?.value),
      ip_addresses: splitLines(document.getElementById("wizard-target-ip-addresses")?.value),
      cidr_ranges: splitLines(document.getElementById("wizard-target-cidrs")?.value),
      api_base_urls: splitLines(document.getElementById("wizard-target-api")?.value),
    };
    return;
  }
  if (wizard.step === 2) {
    const accounts = Array.from(dom.wizardPanel.querySelectorAll("[data-account-card]")).map((card) => {
      const index = Number(card.dataset.accountCard);
      return {
        label: stringValue(card.querySelector('[data-account-field="label"]')?.value),
        username: stringValue(card.querySelector('[data-account-field="username"]')?.value),
        role: stringValue(card.querySelector('[data-account-field="role"]')?.value),
        secret_ref: stringValue(card.querySelector('[data-account-field="secret_ref"]')?.value),
        api_key_ref: stringValue(card.querySelector('[data-account-field="api_key_ref"]')?.value),
        bearer_token_ref: stringValue(card.querySelector('[data-account-field="bearer_token_ref"]')?.value),
        session_ref: stringValue(card.querySelector('[data-account-field="session_ref"]')?.value),
        mfa_notes: stringValue(card.querySelector('[data-account-field="mfa_notes"]')?.value),
        _index: index,
      };
    }).sort((left, right) => left._index - right._index).map(({ _index, ...account }) => account);
    data.access.accounts = accounts.length ? accounts : [buildEmptyAccount()];
    data.access.manual_auth_steps = stringValue(document.getElementById("wizard-manual-auth-steps")?.value);
    data.access.cookie_notes = stringValue(document.getElementById("wizard-cookie-notes")?.value);
    return;
  }
  if (wizard.step === 3) {
    data.test_profile = document.querySelector('input[name="wizard-test-profile"]:checked')?.value || data.test_profile;
    return;
  }
  if (wizard.step === 4) {
    MODULES.forEach(([key]) => {
      data.modules[key] = Boolean(dom.wizardPanel.querySelector(`[data-module-key="${key}"]`)?.checked);
    });
    return;
  }
  if (wizard.step === 5) {
    data.safety.rate_limit_rps = numberValue(document.getElementById("wizard-rate-limit")?.value, DEFAULT_SAFETY.rate_limit_rps);
    data.safety.concurrency = numberValue(document.getElementById("wizard-concurrency")?.value, DEFAULT_SAFETY.concurrency);
    data.safety.time_budget_minutes = numberValue(document.getElementById("wizard-time-budget")?.value, DEFAULT_SAFETY.time_budget_minutes);
    data.safety.active_checks = document.getElementById("wizard-active-checks")?.value || DEFAULT_SAFETY.active_checks;
    data.safety.adaptive_generation = (document.getElementById("wizard-adaptive-generation")?.value || "true") === "true";
    data.safety.max_validation_depth = document.getElementById("wizard-max-depth")?.value || DEFAULT_SAFETY.max_validation_depth;
  }
}

function validateWizardStep(step) {
  const data = state.wizard.data;
  if (step === 0) {
    const errors = [];
    if (state.wizard.useExistingEngagement && !state.selectedEngagementId) {
      errors.push("Select an existing engagement or create a new one.");
    }
    if (!state.wizard.useExistingEngagement && !data.engagement_name.trim()) {
      errors.push("Enter an engagement name.");
    }
    if (!data.assessment_type) {
      errors.push("Choose an assessment type.");
    }
    return errors;
  }
  if (step === 1) {
    const targets = flattenTargetValues(data.targets);
    const errors = [];
    if (!targets.length) {
      errors.push("Add at least one target in scope.");
    }
    splitLines(document.getElementById("wizard-target-urls")?.value).forEach((value) => {
      if (!isLikelyUrl(value)) errors.push(`Invalid URL: ${value}`);
    });
    splitLines(document.getElementById("wizard-target-api")?.value).forEach((value) => {
      if (!isLikelyUrl(value)) errors.push(`Invalid API base URL: ${value}`);
    });
    splitLines(document.getElementById("wizard-target-ip-addresses")?.value).forEach((value) => {
      if (!isLikelyIp(value)) errors.push(`Invalid IP address: ${value}`);
    });
    splitLines(document.getElementById("wizard-target-cidrs")?.value).forEach((value) => {
      if (!isLikelyCidr(value)) errors.push(`Invalid CIDR range: ${value}`);
    });
    splitLines(document.getElementById("wizard-target-domains")?.value).forEach((value) => {
      if (!isLikelyDomain(value)) errors.push(`Invalid domain: ${value}`);
    });
    return [...new Set(errors)];
  }
  if (step === 2) {
    if (requiresCredentials(data) && !hasMeaningfulAccount(data.access.accounts)) {
      return ["This assessment profile needs at least one account, token reference, or session label."];
    }
    return [];
  }
  if (step === 3) {
    return data.test_profile ? [] : ["Choose a test profile."];
  }
  if (step === 4) {
    return enabledModules(data.modules).length ? [] : ["Enable at least one test module."];
  }
  if (step === 5) {
    const errors = [];
    if (data.safety.rate_limit_rps < 1) errors.push("Rate limit must be at least 1 request per second.");
    if (data.safety.concurrency < 1) errors.push("Concurrency must be at least 1.");
    if (data.safety.time_budget_minutes < 15) errors.push("Time budget must be at least 15 minutes.");
    return errors;
  }
  return validateEntireWizard();
}

function validateEntireWizard() {
  const allErrors = [];
  for (let step = 0; step < WIZARD_STEPS.length - 1; step += 1) {
    allErrors.push(...validateWizardStep(step));
  }
  return [...new Set(allErrors)];
}

async function submitWizard() {
  syncWizardStepFromDom();
  const errors = validateEntireWizard();
  if (errors.length) {
    state.wizard.errors = errors;
    renderWizard();
    return;
  }

  state.wizard.submitting = true;
  state.wizard.errors = [];
  renderWizard();

  const estimate = estimateMission(state.wizard.data);
  const configuration = buildRunConfiguration(state.wizard.data, estimate);
  const engagement = state.wizard.useExistingEngagement
    ? selectedEngagement()
    : await api("/api/v1/engagements", {
        method: "POST",
        body: {
          name: state.wizard.data.engagement_name,
          client: valueOrNull(state.wizard.data.client),
          roe_ref: valueOrNull(state.wizard.data.roe_ref),
        },
      });

  const scopePayload = {
    allowlist_json: buildAllowlistFromWizard(state.wizard.data.targets),
    denylist_json: {},
  };
  await api(`/api/v1/engagements/${engagement.id}/scope`, {
    method: "POST",
    body: scopePayload,
  });

  const inventorySnapshot = await api("/api/v1/inventory/runs", {
    method: "POST",
    body: buildInventorySeedPayload(engagement.id, state.wizard.data),
  });

  const run = await api(`/api/v1/engagements/${engagement.id}/runs`, {
    method: "POST",
    body: {
      profile_name: estimate.execution_profile,
      source_inventory_snapshot_id: inventorySnapshot.id,
      configuration_json: configuration,
    },
  });

  pushStatus(`Mission ${engagement.name} created and bound to run ${run.id}.`, "success");
  state.selectedEngagementId = engagement.id;
  state.selectedRunId = run.id;
  state.wizard = buildEmptyWizardState();
  state.wizard.lastCreated = {
    engagementName: engagement.name,
    runId: run.id,
  };
  state.activeScreen = "mission-control";
  await refreshShell();
}

function renderMissionControl() {
  const phases = buildMissionPhases();
  dom.missionTimeline.innerHTML = phases.map(renderPhaseCard).join("");
  const activity = deriveCurrentActivity(phases);
  dom.missionActivity.innerHTML = `
    <h4>${escapeHtml(activity.title)}</h4>
    <p>${statusPill(activity.status)}</p>
    <p>${escapeHtml(activity.summary)}</p>
    <p class="micro-copy">${escapeHtml(activity.why)}</p>
    <p class="micro-copy">${escapeHtml(activity.expectation)}</p>
  `;

  const statusBoard = deriveStatusBoard();
  dom.missionGood.innerHTML = renderStringList(statusBoard.good, "Healthy signals appear here after scope and run activity are available.");
  dom.missionBad.innerHTML = renderStringList(statusBoard.bad, "No blocking issues detected right now.");
  dom.missionUnknown.innerHTML = renderStringList(statusBoard.unknown, "No unknowns are currently flagged.");

  const eta = deriveMissionEta(phases);
  dom.missionEta.innerHTML = `
    <h4>${escapeHtml(`${eta.elapsed_minutes}m elapsed · ${eta.remaining_minutes}m remaining`)}</h4>
    <p>${escapeHtml(`${eta.total_minutes}m estimated total · ${eta.confidence} confidence`)}</p>
    <p class="micro-copy">${escapeHtml(eta.detail)}</p>
    <div class="progress-track"><div class="progress-bar" style="width:${eta.percent_complete}%"></div></div>
  `;

  const pulse = buildFindingsPulse();
  dom.missionFindingsPulse.innerHTML = `
    <h4>${escapeHtml(`${pulse.confirmed} confirmed · ${pulse.suspected} suspected · ${pulse.dismissed} dismissed`)}</h4>
    <p>${escapeHtml(`${pulse.critical} critical business-impact items · ${pulse.evidence_completeness}% evidence completeness`)}</p>
    <p class="micro-copy">${escapeHtml(`Methodology coverage: ${pulse.coverage}`)}</p>
  `;

  dom.missionAiNarrative.innerHTML = renderStringCards(buildNarratives(), "AI narrative appears as soon as inventory, adaptive decisions, or findings exist.");
  dom.missionPackStatus.innerHTML = renderPackStatusSummary();
  dom.missionScopeSummary.innerHTML = renderScopeProfileSummary();
}

function buildMissionPhases() {
  const run = state.selectedRun;
  const config = run?.configuration_json || {};
  const inventory = latestInventorySnapshot();
  const relevance = latestRelevanceDecision();
  const pack = selectedPack();
  const tasks = run?.tasks || [];
  const findings = selectedRunFindings();
  const hasAccounts = hasMeaningfulAccount(config.access?.accounts || []);
  const activeProfileNeedsAuth = requiresCredentials(config);
  const taskCounts = summarizeTaskStatuses(tasks);
  const deepProgress = tasks.length ? Math.round(((taskCounts.completed + taskCounts.failed + taskCounts.cancelled) / tasks.length) * 100) : 0;
  const adaptiveProgress = pack ? packProgress(pack.status) : (config.safety?.adaptive_generation === false ? 100 : relevance ? 45 : 0);
  const verificationResolved = findings.length ? Math.round((findings.filter((finding) => finding.status === "resolved").length / findings.length) * 100) : 0;
  const phases = [
    {
      key: "recon",
      label: "Recon",
      status: inventory ? "complete" : run ? "active" : "pending",
      progress: inventory ? 100 : run ? 25 : 0,
      summary: inventory ? `${inventory.summary_json.host_count} hosts seeded or discovered.` : "Waiting for inventory seed or discovery activity.",
    },
    {
      key: "surface",
      label: "Surface Mapping",
      status: inventory ? "complete" : "pending",
      progress: inventory ? 100 : 0,
      summary: inventory ? `${inventory.summary_json.endpoint_count} endpoints and ${inventory.summary_json.technology_count} technologies mapped.` : "No mapped surface yet.",
    },
    {
      key: "auth",
      label: "Auth Access",
      status: activeProfileNeedsAuth && !hasAccounts ? "blocked" : (hasAccounts || !activeProfileNeedsAuth ? "complete" : "pending"),
      progress: hasAccounts || !activeProfileNeedsAuth ? 100 : 10,
      summary: hasAccounts ? `${config.access.accounts.length} role contexts loaded.` : activeProfileNeedsAuth ? "Assessment expects authenticated access but no credentials are configured." : "No dedicated auth context required.",
    },
    {
      key: "analysis",
      label: "Deep Analysis",
      status: run?.status === "pending_approval" ? "blocked" : tasks.length ? (deepProgress >= 100 ? "complete" : "active") : (run ? "pending" : "pending"),
      progress: run?.status === "pending_approval" ? 10 : deepProgress,
      summary: tasks.length ? `${taskCounts.completed} complete, ${taskCounts.queued} queued, ${taskCounts.running} running.` : "Run exists but no deep-analysis tasks are queued yet.",
    },
    {
      key: "adaptive",
      label: "Adaptive Testing",
      status: config.safety?.adaptive_generation === false ? "complete" : pack ? packStatusToPhaseStatus(pack.status) : relevance ? "active" : "pending",
      progress: adaptiveProgress,
      summary: pack ? `${pack.name} ${pack.version} is ${pack.status}.` : config.safety?.adaptive_generation === false ? "Adaptive generation was disabled in the wizard." : "No adaptive pack has been generated yet.",
    },
    {
      key: "verification",
      label: "Verification",
      status: findings.length ? (verificationResolved === 100 ? "complete" : "active") : (run?.status === "pending_approval" ? "blocked" : "pending"),
      progress: findings.length ? Math.max(20, verificationResolved) : 0,
      summary: findings.length ? `${findings.length} findings need verification-state review.` : "No findings exist yet for replay or retest handling.",
    },
    {
      key: "reporting",
      label: "Reporting",
      status: state.reportCatalog.length ? "complete" : run ? "active" : "pending",
      progress: state.reportCatalog.length ? 100 : run ? 35 : 0,
      summary: state.reportCatalog.length ? `${state.reportCatalog.length} report variants are ready for preview and export.` : "No run report is available yet.",
    },
  ];
  return phases.map((phase, index) => ({
    ...phase,
    elapsed: formatElapsedMinutes(run?.created_at, index * 3),
  }));
}

function renderPhaseCard(phase) {
  return `
    <div class="phase-card ${phase.status}" style="--phase-progress:${phase.progress}%">
      <p class="eyebrow">${escapeHtml(phase.label)}</p>
      <h4>${escapeHtml(`${phase.progress}%`)}</h4>
      <p>${statusPill(phase.status)}</p>
      <p>${escapeHtml(phase.summary)}</p>
      <p class="micro-copy">${escapeHtml(`Elapsed ${phase.elapsed}`)}</p>
    </div>
  `;
}

function deriveCurrentActivity(phases) {
  const blocked = phases.find((phase) => phase.status === "blocked");
  if (blocked) {
    return {
      title: `${blocked.label} is blocked`,
      status: "blocked",
      summary: blocked.summary,
      why: "The current mission configuration requires an operator input or approval before the flow can continue.",
      expectation: "Clear the blocker, refresh Mission Control, and the phase will resume under the same run dossier.",
    };
  }
  const active = phases.find((phase) => phase.status === "active");
  if (active) {
    return {
      title: `${active.label} is active`,
      status: "active",
      summary: active.summary,
      why: "This phase currently has the highest operational weight in the selected mission.",
      expectation: "Expect progress, ETA changes, and evidence accumulation as the underlying tasks complete.",
    };
  }
  if (state.selectedRun) {
    return {
      title: "Mission is standing by",
      status: state.selectedRun.status,
      summary: `Run ${state.selectedRun.id} is ${state.selectedRun.status}.`,
      why: "No phase currently needs special attention, or the run is waiting for the next operator action.",
      expectation: "Use Pack Forge, Report Center, or History to continue the mission lifecycle.",
    };
  }
  return {
    title: "Wizard first",
    status: "pending",
    summary: "Complete the Assessment Wizard to create the mission and unlock live operations.",
    why: "Mission Control depends on a real run and its inherited configuration.",
    expectation: "The wizard will seed scope, access context, modules, limits, and ETA before the first run exists.",
  };
}

function deriveStatusBoard() {
  const findings = selectedRunFindings();
  const pack = selectedPack();
  const inventory = latestInventorySnapshot();
  const config = state.selectedRun?.configuration_json || {};
  const good = [];
  const bad = [];
  const unknown = [];

  if (inventory) good.push(`Inventory confidence is ${toPercent(inventory.confidence_score)} and the surface model is ready for mapping.`);
  if (pack && ["validated", "approved", "deployed"].includes(pack.status)) good.push(`Selected adaptive pack ${pack.version} is ${pack.status}.`);
  if (state.selectedRun?.status === "queued") good.push("Run tasks are queued and ready for dispatch.");
  if (findings.some((finding) => finding.evidence_ref)) good.push("Evidence-linked findings are already available for replay.");

  if (state.selectedRun?.status === "pending_approval") bad.push("Run launch is blocked pending approval.");
  if (pack && pack.status === "validation_failed") bad.push("The latest adaptive pack failed validation and cannot be promoted.");
  if (requiresCredentials(config) && !hasMeaningfulAccount(config.access?.accounts || [])) bad.push("The mission profile expects authenticated access but no usable account context is stored.");
  if (findings.some((finding) => finding.severity === "critical")) bad.push("Critical findings are present and should be prioritized in remediation and reporting.");

  if (!inventory) unknown.push("No inventory snapshot exists yet for attack-map and coverage decisions.");
  if (!state.mission.relevance.length && config.safety?.adaptive_generation !== false) unknown.push("No relevance analysis exists yet for adaptive testing decisions.");
  if (!state.reportCatalog.length && state.selectedRun) unknown.push("Reports have not been previewed yet for this run.");
  if (findings.some((finding) => finding.severity === "unknown")) unknown.push("At least one finding still has unknown severity and needs analyst review.");

  return { good, bad, unknown };
}

function deriveMissionEta(phases) {
  const configEta = state.selectedRun?.configuration_json?.eta || estimateMission(state.wizard.data);
  const total = Number(configEta.estimated_total_minutes || 90);
  const elapsed = state.selectedRun ? minutesSince(state.selectedRun.created_at) : 0;
  const percentComplete = Math.round(phases.reduce((sum, phase) => sum + phase.progress, 0) / Math.max(phases.length, 1));
  const remaining = Math.max(0, total - elapsed);
  return {
    elapsed_minutes: elapsed,
    remaining_minutes: remaining,
    total_minutes: total,
    confidence: configEta.confidence || "medium",
    percent_complete: percentComplete,
    detail: "ETA is based on wizard scope size, enabled modules, approval gates, and current phase completion.",
  };
}

function buildFindingsPulse() {
  const findings = selectedRunFindings();
  const linked = findings.filter((finding) => Boolean(finding.evidence_ref)).length;
  const tags = new Set();
  findings.forEach((finding) => (finding.methodology_tags || []).forEach((tag) => tags.add(tag)));
  return {
    confirmed: findings.filter((finding) => ["open", "triaged", "in_progress", "resolved", "reopened"].includes(finding.status)).length,
    suspected: findings.filter((finding) => finding.status === "triaged").length,
    dismissed: findings.filter((finding) => ["accepted_risk", "false_positive"].includes(finding.status)).length,
    critical: findings.filter((finding) => ["critical", "high"].includes(finding.severity)).length,
    evidence_completeness: findings.length ? Math.round((linked / findings.length) * 100) : 0,
    coverage: tags.size ? `${tags.size} methodology tags linked` : "Coverage will populate as findings arrive",
  };
}

function buildNarratives() {
  const narratives = [];
  const relevance = latestRelevanceDecision();
  const pack = state.selectedPackBundle?.pack || selectedPack();
  const findings = selectedRunFindings();
  if (relevance) {
    const relevantCount = relevance.recommendations_json?.relevant_advisories?.length || 0;
    narratives.push(`AI matched ${relevantCount} relevant advisories against the latest inventory snapshot.`);
  }
  if (pack) {
    narratives.push(`Capability pack ${pack.name} ${pack.version} is ${pack.status} and carries ${pack.methodology_tags.length} methodology tags.`);
  }
  if (state.selectedPackBundle?.artifacts?.length) {
    narratives.push(`Pack Forge has ${state.selectedPackBundle.artifacts.length} generated artifacts ready for review or promotion.`);
  }
  if (findings.length) {
    narratives.push(`Evidence-first replay lifted confidence across ${findings.length} findings in the selected run.`);
  }
  if (state.selectedFindingTheater?.finding?.finding_origin === "adaptive_pack") {
    narratives.push("The selected finding was produced through adaptive pack coverage rather than baseline tooling alone.");
  }
  return narratives;
}

function renderPackStatusSummary() {
  const pack = state.selectedPackBundle?.pack || selectedPack();
  const deployments = state.selectedPackBundle?.deployments || [];
  const validations = state.selectedPackBundle?.validations || [];
  const bound = state.selectedRun?.pack_binding;
  if (!pack) {
    return emptyState("No adaptive pack has been selected for this engagement yet.");
  }
  return `
    <h4>${escapeHtml(pack.name)} <span class="badge">${escapeHtml(pack.version)}</span></h4>
    <p>${statusPill(pack.status)} ${escapeHtml(pack.generation_mode)}</p>
    <p>${escapeHtml(`${validations.length} validations · ${deployments.length} deployments`)}</p>
    <p class="micro-copy">${escapeHtml(`Runtime binding: ${bound?.pack_version || "standard baseline"}`)}</p>
  `;
}

function renderScopeProfileSummary() {
  const run = state.selectedRun;
  if (!run) {
    return emptyState("Wizard-defined scope, modules, accounts, and limits appear here once a run exists.");
  }
  const config = run.configuration_json || {};
  const targets = config.targets || {};
  const accounts = config.access?.accounts || [];
  return `
    <h4>${escapeHtml(config.assessment_type || "Assessment not recorded")}</h4>
    <p>${escapeHtml(config.test_profile || run.profile.name)}</p>
    <p>${escapeHtml(renderTargetSummary(targets))}</p>
    <p>${escapeHtml(`${enabledModules(config.modules || {}).join(", ") || "No modules recorded"}`)}</p>
    <p class="micro-copy">${escapeHtml(`${accounts.length} account / role contexts · RPS ${config.safety?.rate_limit_rps || "n/a"} · concurrency ${config.safety?.concurrency || "n/a"}`)}</p>
  `;
}

function renderSurfaceMap() {
  const snapshot = latestInventorySnapshot();
  dom.surfaceToggleBar.innerHTML = Object.entries(state.surfaceOverlays)
    .map(
      ([key, enabled]) => `
        <button class="action ${enabled ? "secondary" : "ghost"} surface-toggle" data-overlay="${key}" type="button">
          ${escapeHtml(surfaceOverlayLabel(key))}
        </button>
      `
    )
    .join("");
  dom.surfaceToggleBar.querySelectorAll(".surface-toggle").forEach((button) => {
    button.addEventListener("click", () => {
      state.surfaceOverlays[button.dataset.overlay] = !state.surfaceOverlays[button.dataset.overlay];
      renderSurfaceMap();
    });
  });

  if (!snapshot) {
    dom.surfaceMapCanvas.innerHTML = emptyState("The surface map needs an inventory snapshot. The wizard seeds one automatically for new missions.");
    dom.surfaceInsights.innerHTML = emptyState("Surface insights will appear after inventory is available.");
    dom.surfaceLegend.innerHTML = emptyState("Legend data will populate with mapped assets and overlays.");
    return;
  }

  const inventory = snapshot.normalized_inventory_json || {};
  const hosts = inventory.hosts || [];
  const endpoints = inventory.http_endpoints || [];
  const technologies = inventory.technologies || [];
  const fingerprints = inventory.vendor_product_fingerprints || [];
  const nodes = [
    ...hosts.map((host, index) => ({ kind: "host", title: host.host, meta: `${toPercent(host.confidence)} confidence`, left: 8, top: 18 + index * 16 })),
    ...endpoints.map((endpoint, index) => ({ kind: "endpoint", title: endpoint.url, meta: `${(endpoint.methods || []).join(", ") || "GET"} · ${endpoint.status_code || "unknown"}`, left: 40, top: 18 + index * 16 })),
    ...technologies.map((tech, index) => ({ kind: "tech", title: tech.name, meta: `${tech.vendor || "unknown vendor"} · ${toPercent(tech.confidence)}`, left: 72, top: 18 + index * 16 })),
  ];
  if (!technologies.length) {
    fingerprints.slice(0, 3).forEach((fingerprint, index) => {
      nodes.push({
        kind: "tech",
        title: fingerprint.product,
        meta: `${fingerprint.vendor || "fingerprint"} · ${toPercent(fingerprint.confidence)}`,
        left: 72,
        top: 18 + (technologies.length + index) * 16,
      });
    });
  }

  const hotspotTargets = new Set(selectedRunFindings().map((finding) => finding.target_id));
  const svgLines = [];
  nodes.filter((node) => node.kind === "host").forEach((hostNode, index) => {
    const endpointNode = nodes.filter((node) => node.kind === "endpoint")[index];
    if (endpointNode) {
      svgLines.push(lineSvg(hostNode.left + 14, hostNode.top + 2, endpointNode.left + 6, endpointNode.top + 2));
    }
  });
  nodes.filter((node) => node.kind === "endpoint").forEach((endpointNode, index) => {
    const techNode = nodes.filter((node) => node.kind === "tech")[index];
    if (techNode) {
      svgLines.push(lineSvg(endpointNode.left + 14, endpointNode.top + 2, techNode.left + 6, techNode.top + 2));
    }
  });

  dom.surfaceMapCanvas.innerHTML = `
    <svg viewBox="0 0 100 100" preserveAspectRatio="none">${svgLines.join("")}</svg>
    <div class="map-column hosts"><p class="map-column-label">Hosts</p></div>
    <div class="map-column endpoints"><p class="map-column-label">Apps / APIs</p></div>
    <div class="map-column tech"><p class="map-column-label">Stacks / Pack Zones</p></div>
    ${nodes.map((node) => {
      const hotspot = state.surfaceOverlays.hotspots && hotspotTargets.has(node.title);
      const packZone = state.surfaceOverlays.packZones && Boolean(selectedPack());
      return `
        <div class="map-node ${hotspot ? "hotspot" : ""} ${packZone ? "pack-zone" : ""} ${hotspot ? "active" : ""}" style="left:${node.left}%; top:${node.top}%">
          <strong>${escapeHtml(node.title)}</strong>
          <div class="node-meta">${escapeHtml(node.meta)}</div>
        </div>
      `;
    }).join("")}
  `;

  const previousSnapshot = state.mission.inventory[1] || null;
  dom.surfaceInsights.innerHTML = renderStringCards(
    [
      `${hosts.length} hosts or network objects are visible in the current surface model.`,
      `${endpoints.length} HTTP or API endpoints are mapped for the selected engagement.`,
      `${technologies.length || fingerprints.length} stack indicators are available for adaptive relevance decisions.`,
      previousSnapshot ? `${Math.max(0, (snapshot.summary_json.host_count || 0) - (previousSnapshot.summary_json.host_count || 0))} new host-level items were discovered since the previous snapshot.` : "No prior inventory snapshot exists for delta analysis yet.",
    ],
    "Insights appear after inventory normalization runs."
  );
  dom.surfaceLegend.innerHTML = `
    <div class="pill-grid">
      <span class="legend-chip">Hosts</span>
      <span class="legend-chip">Apps / APIs</span>
      <span class="legend-chip">Stacks / Products</span>
      <span class="legend-chip">Hotspots ${state.surfaceOverlays.hotspots ? "On" : "Off"}</span>
      <span class="legend-chip">Pack Zones ${state.surfaceOverlays.packZones ? "On" : "Off"}</span>
      <span class="legend-chip">Future Attack Paths ${state.surfaceOverlays.futureAttackPaths ? "Reserved" : "Prepared"}</span>
      <span class="legend-chip">Future Identity Graph ${state.surfaceOverlays.futureIdentityGraph ? "Reserved" : "Prepared"}</span>
      <span class="legend-chip">Future Risk Overlay ${state.surfaceOverlays.futureRiskOverlay ? "Reserved" : "Prepared"}</span>
    </div>
  `;
}

function renderFindingsTheater() {
  const allFindings = engagementFindings();
  const methodologyOptions = Array.from(
    new Set(allFindings.flatMap((finding) => finding.methodology_tags || []))
  ).sort();

  dom.findingsFilterBar.innerHTML = `
    <label class="field compact">
      <span>Run</span>
      <select id="finding-filter-run">
        <option value="all">All Runs</option>
        ${state.mission.runs.map((run) => `<option value="${run.id}" ${state.findingFilters.runId === run.id ? "selected" : ""}>${escapeHtml(run.profile.name)} · ${escapeHtml(run.status)}</option>`).join("")}
      </select>
    </label>
    <label class="field compact">
      <span>Severity</span>
      <select id="finding-filter-severity">
        ${["all", "critical", "high", "medium", "low", "info", "unknown"].map((value) => `<option value="${value}" ${state.findingFilters.severity === value ? "selected" : ""}>${escapeHtml(value)}</option>`).join("")}
      </select>
    </label>
    <label class="field compact">
      <span>Origin</span>
      <select id="finding-filter-origin">
        ${["all", "standard", "adaptive_pack"].map((value) => `<option value="${value}" ${state.findingFilters.origin === value ? "selected" : ""}>${escapeHtml(value)}</option>`).join("")}
      </select>
    </label>
    <label class="field compact">
      <span>Status</span>
      <select id="finding-filter-status">
        ${["all", "open", "triaged", "in_progress", "resolved", "accepted_risk", "false_positive", "reopened"].map((value) => `<option value="${value}" ${state.findingFilters.status === value ? "selected" : ""}>${escapeHtml(value)}</option>`).join("")}
      </select>
    </label>
    <label class="field compact">
      <span>Methodology</span>
      <select id="finding-filter-methodology">
        <option value="all">All</option>
        ${methodologyOptions.map((value) => `<option value="${escapeHtml(value)}" ${state.findingFilters.methodology === value ? "selected" : ""}>${escapeHtml(value)}</option>`).join("")}
      </select>
    </label>
    <label class="field compact">
      <span>Group By</span>
      <select id="finding-filter-group-by">
        ${["severity", "origin", "status", "methodology", "run"].map((value) => `<option value="${value}" ${state.findingFilters.groupBy === value ? "selected" : ""}>${escapeHtml(value)}</option>`).join("")}
      </select>
    </label>
  `;

  dom.findingsFilterBar.querySelectorAll("select").forEach((select) => {
    select.addEventListener("change", async () => {
      state.findingFilters = {
        runId: document.getElementById("finding-filter-run").value,
        severity: document.getElementById("finding-filter-severity").value,
        origin: document.getElementById("finding-filter-origin").value,
        status: document.getElementById("finding-filter-status").value,
        methodology: document.getElementById("finding-filter-methodology").value,
        groupBy: document.getElementById("finding-filter-group-by").value,
      };
      renderFindingsTheater();
    });
  });

  const filtered = filterFindings(allFindings);
  if (filtered.length && !filtered.some((finding) => finding.id === state.selectedFindingId)) {
    state.selectedFindingId = filtered[0].id;
    loadSelectedFinding().then(() => {
      renderFindingsTheater();
      renderEvidenceReplay();
    }).catch(handleError);
  }

  const grouped = groupFindings(filtered, state.findingFilters.groupBy);
  dom.findingsGroupList.innerHTML = Object.entries(grouped).length
    ? Object.entries(grouped)
        .map(
          ([group, items]) => `
            <div class="list-card">
              <h4>${escapeHtml(group)}</h4>
              <p class="micro-copy">${escapeHtml(`${items.length} finding${items.length === 1 ? "" : "s"}`)}</p>
              <div class="stack-zone split-top">
                ${items.map((finding) => `
                  <div class="list-card ${finding.id === state.selectedFindingId ? "selected" : ""}" data-finding-pick="${finding.id}">
                    <h4>${escapeHtml(finding.title)}</h4>
                    <p>${statusPill(finding.status)} ${escapeHtml(finding.severity)} · ${escapeHtml(finding.finding_origin)}</p>
                    <p class="micro-copy">${escapeHtml(finding.target_id)}</p>
                  </div>
                `).join("")}
              </div>
            </div>
          `
        )
        .join("")
    : emptyState("No findings match the current filters.");

  dom.findingsGroupList.querySelectorAll("[data-finding-pick]").forEach((item) => {
    item.addEventListener("click", async () => {
      state.selectedFindingId = item.dataset.findingPick;
      await loadSelectedFinding();
      renderFindingsTheater();
      renderEvidenceReplay();
    });
  });

  if (!state.selectedFindingTheater) {
    dom.findingTheaterDetail.innerHTML = emptyState("Select a finding to inspect impact, methodology, evidence posture, and next steps.");
    return;
  }

  const theater = state.selectedFindingTheater;
  dom.findingTheaterDetail.innerHTML = `
    <div class="panel-head">
      <div>
        <p class="eyebrow">Selected Finding</p>
        <h4>${escapeHtml(theater.finding.title)}</h4>
      </div>
      <div class="pill-grid">
        ${statusPill(theater.finding.severity)}
        ${statusPill(theater.finding.status)}
        <span class="badge">${escapeHtml(theater.confidence_label)} confidence</span>
      </div>
    </div>
    <p>${escapeHtml(theater.business_impact)}</p>
    <p>${escapeHtml(theater.technical_details)}</p>
    <div class="wizard-panel-grid split-top">
      <div class="detail-surface">
        <h4>Methodology</h4>
        <p>${escapeHtml(`PTES ${theater.methodology.ptes_label || "Not assigned"}`)}</p>
        <p>${escapeHtml(`NIST ${theater.methodology.nist_label || "Not assigned"}`)}</p>
        <p>${escapeHtml(`WSTG ${theater.methodology.wstg_reference || "Not assigned"}`)}</p>
        <p class="micro-copy">${escapeHtml(`Control family: ${theater.methodology.control_family || "Not assigned"}`)}</p>
      </div>
      <div class="detail-surface">
        <h4>Provenance</h4>
        <p>${escapeHtml(`Origin: ${theater.provenance.origin}`)}</p>
        <p>${escapeHtml(`Pack version: ${theater.provenance.source_pack_version || "Standard coverage"}`)}</p>
        <p class="micro-copy">${escapeHtml(`Inventory ${theater.provenance.source_inventory_snapshot_id || "n/a"} · Relevance ${theater.provenance.source_relevance_decision_id || "n/a"}`)}</p>
      </div>
      <div class="detail-surface">
        <h4>Remediation</h4>
        <p>${escapeHtml(theater.remediation.priority)}</p>
        <p>${escapeHtml(theater.remediation.summary)}</p>
        <p class="micro-copy">${escapeHtml(theater.remediation.detail)}</p>
      </div>
      <div class="detail-surface">
        <h4>Verification</h4>
        <p>${escapeHtml(theater.verification_status)}</p>
        <p>${escapeHtml(theater.evidence_summary)}</p>
        <p class="micro-copy">${escapeHtml(`Exploitability: ${theater.exploitability || "Not recorded"}`)}</p>
      </div>
    </div>
    <div class="detail-surface split-top">
      <h4>Next Steps</h4>
      <ul>${theater.next_steps.map((step) => `<li>${escapeHtml(step)}</li>`).join("")}</ul>
    </div>
    <div class="action-row split-top">
      ${["triaged", "in_progress", "resolved"].map((status) => `<button class="action ghost finding-status-btn" type="button" data-status="${status}">Mark ${escapeHtml(status.replace("_", " "))}</button>`).join("")}
    </div>
  `;

  dom.findingTheaterDetail.querySelectorAll(".finding-status-btn").forEach((button) => {
    button.addEventListener("click", async () => {
      await api(`/api/v1/findings/${state.selectedFindingId}`, {
        method: "PATCH",
        body: { status: button.dataset.status },
      });
      pushStatus(`Finding status updated to ${button.dataset.status}.`, "success");
      await refreshSelectedEngagement();
    });
  });
}

function renderEvidenceReplay() {
  if (!state.selectedFindingEvidence) {
    dom.evidenceOverview.innerHTML = emptyState("Select a finding in Findings Theater to inspect its evidence lineage.");
    dom.evidenceExecutions.innerHTML = emptyState("Related executions appear here.");
    dom.evidenceArtifacts.innerHTML = emptyState("Artifacts and replay details appear here.");
    dom.evidenceLineage.innerHTML = emptyState("Inventory, relevance, and pack lineage appear here.");
    return;
  }

  const evidence = state.selectedFindingEvidence;
  dom.evidenceOverview.innerHTML = `
    <h4>${escapeHtml(evidence.finding.title)}</h4>
    <p>${statusPill(evidence.finding.status)} ${escapeHtml(evidence.finding.severity)}</p>
    <p>${escapeHtml(`Evidence ref: ${evidence.evidence_ref}`)}</p>
    <p class="micro-copy">${escapeHtml(`PTES ${evidence.methodology_references.ptes || "n/a"} · WSTG ${evidence.methodology_references.wstg || "n/a"}`)}</p>
  `;

  dom.evidenceExecutions.innerHTML = evidence.related_executions.length
    ? evidence.related_executions
        .map(
          (execution) => `
            <div class="artifact-card ${execution.task_id === state.selectedTaskId ? "selected" : ""}" data-task-pick="${execution.task_id}">
              <h4>${escapeHtml(`${execution.tool} · ${execution.target_id}`)}</h4>
              <p>${statusPill(execution.task_status)} exit ${execution.exit_code} · ${escapeHtml(execution.tool_version)}</p>
              ${execution.stdout_excerpt ? `<pre class="report-preview split-top">${escapeHtml(execution.stdout_excerpt)}</pre>` : ""}
              ${execution.stderr_excerpt ? `<pre class="report-preview split-top">${escapeHtml(execution.stderr_excerpt)}</pre>` : ""}
            </div>
          `
        )
        .join("")
    : emptyState("No related task executions were matched to this finding.");
  dom.evidenceExecutions.querySelectorAll("[data-task-pick]").forEach((item) => {
    item.addEventListener("click", async () => {
      state.selectedTaskId = item.dataset.taskPick;
      await loadSelectedTask();
      renderEvidenceReplay();
    });
  });

  const artifacts = evidence.related_executions.flatMap((execution) => execution.artifacts);
  dom.evidenceArtifacts.innerHTML = artifacts.length
    ? artifacts
        .map(
          (artifact) => `
            <div class="artifact-card">
              <h4>${escapeHtml(artifact.name)}</h4>
              <p>${escapeHtml(`${artifact.kind} · ${artifact.redaction_state}`)}</p>
              <p class="micro-copy">${escapeHtml(artifact.uri)}</p>
              <a class="link-like" href="${artifact.download_path}" target="_blank" rel="noreferrer">Download Artifact</a>
            </div>
          `
        )
        .join("")
    : emptyState("No replay artifacts are attached to the selected finding.");

  dom.evidenceLineage.innerHTML = `
    <h4>Pack Provenance</h4>
    <p>${escapeHtml(evidence.pack_provenance.name ? `${evidence.pack_provenance.name} ${evidence.pack_provenance.version}` : "Standard coverage")}</p>
    <p class="micro-copy">${escapeHtml(`Inventory ${evidence.inventory_source.snapshot_id || "n/a"} · Relevance ${evidence.relevance_source.decision_id || "n/a"}`)}</p>
    <p class="micro-copy">${escapeHtml(`Validation history entries: ${evidence.validation_history.length}`)}</p>
  `;
}

function renderPackForge() {
  renderAdaptiveForm();
  renderCodexTaskForm();

  if (!state.selectedPackBundle) {
    dom.packSummary.innerHTML = emptyState("Generate or select a capability pack to review promotion readiness.");
    dom.packForgeDetail.innerHTML = emptyState("Pack artifacts, validations, approvals, deployments, and Codex tasks appear here.");
    dom.codexContext.innerHTML = emptyState("Codex context is available once a pack is selected.");
    dom.codexTaskResult.innerHTML = emptyState("Prepared task output appears here.");
    return;
  }

  const bundle = state.selectedPackBundle;
  dom.packSummary.innerHTML = `
    <h4>${escapeHtml(bundle.pack.name)} <span class="badge">${escapeHtml(bundle.pack.version)}</span></h4>
    <p>${statusPill(bundle.pack.status)} ${escapeHtml(bundle.pack.generation_mode)}</p>
    <p>${escapeHtml(bundle.pack.description || "No description recorded.")}</p>
    <p class="micro-copy">${escapeHtml(`Methodology tags: ${(bundle.pack.methodology_tags || []).join(", ") || "None"}`)}</p>
  `;

  const relatedCodexTasks = filteredCodexTasks();
  dom.packForgeDetail.innerHTML = `
    <div class="stack-zone">
      <div class="list-card">
        <h4>Capability Packs</h4>
        <div class="stack-zone split-top">
          ${state.mission.packs.map((pack) => `
            <div class="list-card ${pack.id === state.selectedPackId ? "selected" : ""}" data-pack-pick="${pack.id}">
              <h4>${escapeHtml(pack.name)} <span class="badge">${escapeHtml(pack.version)}</span></h4>
              <p>${statusPill(pack.status)} ${escapeHtml(pack.generation_mode)}</p>
            </div>
          `).join("")}
        </div>
      </div>
      <div class="list-card">
        <h4>Artifacts</h4>
        ${bundle.artifacts.length ? bundle.artifacts.map((artifact) => `
          <div class="artifact-card split-top">
            <h4>${escapeHtml(artifact.logical_name)}</h4>
            <p>${escapeHtml(`${artifact.artifact_type} · ${artifact.status}`)}</p>
            <p class="micro-copy">${escapeHtml(artifact.checksum_sha256)}</p>
          </div>
        `).join("") : "<p>No pack artifacts recorded.</p>"}
      </div>
      <div class="wizard-panel-grid">
        <div class="detail-surface">
          <h4>Validation</h4>
          ${bundle.validations.length ? bundle.validations.map((validation) => `<p>${statusPill(validation.status)} ${escapeHtml(validation.validator)} · ${escapeHtml(validation.summary || "No summary")}</p>`).join("") : "<p>No validation results yet.</p>"}
        </div>
        <div class="detail-surface">
          <h4>Approvals</h4>
          ${bundle.approvals.length ? bundle.approvals.map((approval) => `<p>${statusPill(approval.decision)} ${escapeHtml(approval.approver_id)} · ${escapeHtml(approval.notes || "No notes")}</p>`).join("") : "<p>No pack approvals recorded.</p>"}
        </div>
      </div>
      <div class="detail-surface">
        <h4>Deployments & Codex Tasks</h4>
        <p>${escapeHtml(`${bundle.deployments.length} deployments · ${relatedCodexTasks.length} Codex tasks`)}</p>
        ${bundle.deployments.map((deployment) => `<p class="micro-copy">${escapeHtml(`${deployment.status} to ${deployment.deployment_target}`)}</p>`).join("") || "<p class='micro-copy'>No deployment history yet.</p>"}
      </div>
    </div>
  `;
  dom.packForgeDetail.querySelectorAll("[data-pack-pick]").forEach((item) => {
    item.addEventListener("click", async () => {
      state.selectedPackId = item.dataset.packPick;
      await loadSelectedPack();
      renderPackForge();
      renderMissionControl();
    });
  });

  dom.codexContext.innerHTML = `
    <h4>${escapeHtml(bundle.context.pack_name)} <span class="badge">${escapeHtml(bundle.context.pack_version)}</span></h4>
    <p>${statusPill(bundle.context.pack_status)} ${escapeHtml(bundle.context.generation_mode)}</p>
    <p>${escapeHtml(bundle.context.runtime_guardrails.join(" | "))}</p>
    <p class="micro-copy">${escapeHtml(`Validation hooks: ${bundle.context.validation_hooks.map((hook) => hook.name).join(", ")}`)}</p>
  `;
  dom.codexTaskResult.innerHTML = state.selectedCodexResult
    ? `
      <h4>Prepared Task</h4>
      <p>${statusPill(state.selectedCodexResult.status)} dry run ${String(state.selectedCodexResult.dry_run)}</p>
      <p>${escapeHtml(state.selectedCodexResult.summary)}</p>
      <ul>${state.selectedCodexResult.prepared_commands.map((command) => `<li>${escapeHtml(command)}</li>`).join("")}</ul>
    `
    : emptyState("Create or select a Codex task to view prepared commands and validation hooks.");
}

function renderAdaptiveForm() {
  const inventorySnapshot = latestInventorySnapshot();
  dom.adaptiveForm.innerHTML = `
    <label class="field">
      <span>Inventory Basis</span>
      <div class="detail-surface">
        <p>${inventorySnapshot ? escapeHtml(`${inventorySnapshot.id} · ${inventorySnapshot.summary_json.endpoint_count} endpoints`) : "No inventory snapshot available."}</p>
        <p class="micro-copy">Adaptive planning uses the latest inventory snapshot and selected engagement scope.</p>
      </div>
    </label>
    <label class="field">
      <span>Advisory Source</span>
      <input name="source" type="text" value="vendor-advisory" />
    </label>
    <label class="field">
      <span>Advisory ID</span>
      <input name="advisory_id" type="text" placeholder="CVE-2026-1000" />
    </label>
    <label class="field">
      <span>Title</span>
      <input name="title" type="text" placeholder="Auth regression follow-up" />
    </label>
    <label class="field">
      <span>Summary</span>
      <textarea name="summary" rows="3" placeholder="Summarize the relevant advisory or testing pattern."></textarea>
    </label>
    <label class="field">
      <span>Affected Product</span>
      <input name="product" type="text" placeholder="grafana" />
    </label>
    <label class="field">
      <span>Product Match Hint</span>
      <input name="hint" type="text" placeholder="grafana labs" />
    </label>
    <label class="field">
      <span>Attack Surface Type</span>
      <input name="attack_surface_type" type="text" value="auth" />
    </label>
    <label class="field">
      <span>Severity</span>
      <input name="severity" type="text" value="high" />
    </label>
    <label class="field">
      <span>Suggested Patterns</span>
      <input name="patterns" type="text" value="playwright,zap" />
    </label>
    <label class="field">
      <span>Pack Name</span>
      <input name="pack_name" type="text" placeholder="customer-adaptive-pack" />
    </label>
    <button class="action primary" type="submit">Generate Adaptive Pack</button>
  `;
  dom.adaptiveForm.onsubmit = async (event) => {
    event.preventDefault();
    assertSelectedEngagement();
    const inventoryId = latestInventorySnapshot()?.id;
    if (!inventoryId) {
      throw new Error("Create or seed an inventory snapshot before generating adaptive coverage.");
    }
    const form = new FormData(dom.adaptiveForm);
    const threatIntel = await api("/api/v1/threat-intel/ingest", {
      method: "POST",
      body: {
        records: [
          {
            source: stringValue(form.get("source")) || "vendor-advisory",
            advisory_id: stringValue(form.get("advisory_id")),
            title: stringValue(form.get("title")) || "Adaptive testing advisory",
            summary: valueOrNull(form.get("summary")),
            affected_products: splitComma(form.get("product")),
            product_match_hints: splitComma(form.get("hint")),
            attack_surface_type: valueOrNull(form.get("attack_surface_type")),
            suggested_test_patterns: splitComma(form.get("patterns")),
            confidence: 0.9,
            severity: valueOrNull(form.get("severity")),
            references: [],
          },
        ],
      },
    });
    const relevance = await api("/api/v1/relevance/analyze", {
      method: "POST",
      body: {
        engagement_id: state.selectedEngagementId,
        inventory_snapshot_id: inventoryId,
        threat_intel_ids: [threatIntel[0].id],
        include_prior_findings: true,
      },
    });
    const pack = await api("/api/v1/packs/generate", {
      method: "POST",
      body: {
        engagement_id: state.selectedEngagementId,
        relevance_decision_id: relevance.id,
        name: valueOrNull(form.get("pack_name")) || undefined,
      },
    });
    state.selectedPackId = pack.id;
    pushStatus(`Adaptive pack ${pack.name} ${pack.version} generated.`, "success");
    await refreshSelectedEngagement();
  };
}

function renderCodexTaskForm() {
  dom.codexTaskForm.innerHTML = `
    <label class="field">
      <span>Task Type</span>
      <input name="task_type" type="text" value="pack_refinement" />
    </label>
    <label class="field">
      <span>Scope</span>
      <textarea name="scope" rows="3" placeholder="Refine or review the selected adaptive pack."></textarea>
    </label>
    <label class="field">
      <span>Generation Reason</span>
      <textarea name="generation_reason" rows="3" placeholder="Explain why this supervised Codex task is needed."></textarea>
    </label>
    <button class="action secondary" type="submit">Create Codex Task</button>
    <div class="stack-zone split-top">
      ${filteredCodexTasks().map((task) => `
        <div class="list-card ${task.id === state.selectedCodexTaskId ? "selected" : ""}" data-codex-pick="${task.id}">
          <h4>${escapeHtml(task.task_type)}</h4>
          <p>${statusPill(task.status)} ${escapeHtml(task.validation_status)}</p>
          <p class="micro-copy">${escapeHtml(task.scope)}</p>
        </div>
      `).join("") || emptyState("No Codex tasks are linked to the selected pack yet.")}
    </div>
  `;
  dom.codexTaskForm.onsubmit = async (event) => {
    event.preventDefault();
    assertSelectedPack();
    const form = new FormData(dom.codexTaskForm);
    const task = await api("/api/v1/codex/tasks", {
      method: "POST",
      body: {
        task_type: stringValue(form.get("task_type")) || "pack_refinement",
        scope: stringValue(form.get("scope")) || "Review selected pack artifacts.",
        inputs: { selected_engagement_id: state.selectedEngagementId },
        constraints: { runtime_mutation: false, protected_runtime: true },
        expected_output: { review_bundle: true, validation_required: true },
        generation_reason: stringValue(form.get("generation_reason")) || "Operator requested pack review.",
        source_context: { pack_id: state.selectedPackId },
      },
    });
    state.selectedCodexTaskId = task.id;
    pushStatus("Codex task created in the supervised build lane.", "success");
    state.codexTasks = await api("/api/v1/codex/tasks");
    renderPackForge();
  };
  dom.codexTaskForm.querySelectorAll("[data-codex-pick]").forEach((item) => {
    item.addEventListener("click", async () => {
      state.selectedCodexTaskId = item.dataset.codexPick;
      state.selectedCodexResult = await apiOrNull(`/api/v1/codex/tasks/${state.selectedCodexTaskId}/result`);
      renderPackForge();
    });
  });
}

async function validateSelectedPack() {
  assertSelectedPack();
  await api(`/api/v1/packs/${state.selectedPackId}/validate`, { method: "POST" });
  pushStatus("Pack validation completed.", "success");
  await refreshSelectedEngagement();
}

async function approveSelectedPack() {
  assertSelectedPack();
  await api(`/api/v1/packs/${state.selectedPackId}/approve?notes=Approved%20from%20operator%20console`, { method: "POST" });
  pushStatus("Pack approved for promotion.", "success");
  await refreshSelectedEngagement();
}

async function deploySelectedPack() {
  assertSelectedPack();
  assertSelectedEngagement();
  await api(`/api/v1/packs/${state.selectedPackId}/deploy`, {
    method: "POST",
    body: {
      engagement_id: state.selectedEngagementId,
      deployment_target: "engagement-runtime",
      run_profile_name: state.selectedRun?.profile?.name || null,
    },
  });
  pushStatus("Pack deployed and available for run binding.", "success");
  await refreshSelectedEngagement();
}

async function prepareSelectedCodexTask() {
  const taskId = state.selectedCodexTaskId || filteredCodexTasks()[0]?.id;
  if (!taskId) {
    throw new Error("Create or select a Codex task first.");
  }
  state.selectedCodexResult = await api(`/api/v1/codex/tasks/${taskId}/run`, {
    method: "POST",
    body: {
      base_url: window.location.origin,
      workspace_root: `./codex-workspaces/${slugify(selectedPack()?.name || "pack")}`,
      dry_run: true,
    },
  });
  pushStatus("Codex task prepared in dry-run mode.", "success");
  renderPackForge();
}

function renderReportCenter() {
  dom.reportCatalog.innerHTML = state.reportCatalog.length
    ? state.reportCatalog
        .map(
          (report) => `
            <div class="report-card ${report.variant === state.reportVariant ? "selected" : ""}" data-report-variant="${report.variant}">
              <h4>${escapeHtml(report.title)}</h4>
              <p>${statusPill("complete")} ${escapeHtml(report.description)}</p>
              <p class="micro-copy">${escapeHtml(report.version_label)}</p>
            </div>
          `
        )
        .join("")
    : emptyState("Report variants become available once a run dossier exists.");
  dom.reportCatalog.querySelectorAll("[data-report-variant]").forEach((item) => {
    item.addEventListener("click", () => {
      state.reportVariant = item.dataset.reportVariant;
      renderReportCenter();
    });
  });

  const selectedReport = state.reportCatalog.find((report) => report.variant === state.reportVariant) || null;
  if (!selectedReport) {
    dom.reportMetadata.innerHTML = emptyState("Select or create a run to unlock report workflows.");
    dom.reportActions.innerHTML = "";
    if (!state.reportPreview) dom.reportPreview.textContent = "No report preview loaded yet.";
    if (!state.reportHtml) dom.reportFrame.srcdoc = "<div style='padding:24px;font-family:Aptos,sans-serif'>No HTML report preview loaded.</div>";
    dom.reportCompare.innerHTML = emptyState("Choose a current and baseline run to compare report posture.");
    return;
  }

  dom.reportMetadata.innerHTML = `
    <h4>${escapeHtml(selectedReport.title)}</h4>
    <p>${escapeHtml(selectedReport.description)}</p>
    <p>${escapeHtml(`Hash ${selectedReport.content_sha256.slice(0, 16)}…`)}</p>
    <p class="micro-copy">${escapeHtml(`Run profile ${selectedReport.source_scope_profile.run_profile} · assessment ${selectedReport.source_scope_profile.assessment_type || "n/a"}`)}</p>
    <p class="micro-copy">${escapeHtml(`Findings ${selectedReport.included_findings.count} · evidence completeness ${Math.round((selectedReport.evidence_status.completeness_ratio || 0) * 100)}%`)}</p>
    <p class="micro-copy">${escapeHtml(selectedReport.methodology_references.join(" · "))}</p>
  `;

  dom.reportActions.innerHTML = `
    <button class="action primary" data-report-preview="markdown" type="button">Generate Markdown Preview</button>
    <button class="action secondary" data-report-preview="html" type="button">Generate HTML Preview</button>
    <a class="action ghost" href="${selectedReport.export_paths.markdown}" target="_blank" rel="noreferrer">Download Markdown</a>
    <a class="action ghost" href="${selectedReport.export_paths.html}" target="_blank" rel="noreferrer">Open HTML for PDF Hand-off</a>
  `;
  dom.reportActions.querySelectorAll("[data-report-preview]").forEach((button) => {
    button.addEventListener("click", () => previewReport(button.dataset.reportPreview).catch(handleError));
  });

  if (!state.reportPreview) {
    dom.reportPreview.textContent = "Generate a markdown preview to inspect the selected report variant here.";
  } else {
    dom.reportPreview.textContent = state.reportPreview;
  }
  if (!state.reportHtml) {
    dom.reportFrame.srcdoc = "<div style='padding:24px;font-family:Aptos,sans-serif;color:#182535'>Generate an HTML preview to render the report here.</div>";
  }

  dom.reportCompare.innerHTML = renderReportComparison(selectedReport);
}

async function previewReport(format) {
  if (!state.selectedRunId) {
    throw new Error("Select a run before previewing reports.");
  }
  if (format === "html") {
    state.reportHtml = await api(`/api/v1/runs/${state.selectedRunId}/report?format=html&variant=${state.reportVariant}`, { raw: true });
    dom.reportFrame.srcdoc = state.reportHtml;
    pushStatus(`HTML preview generated for the ${state.reportVariant} report.`, "info");
  } else {
    state.reportPreview = await api(`/api/v1/runs/${state.selectedRunId}/report?format=markdown&variant=${state.reportVariant}`, { raw: true });
    dom.reportPreview.textContent = state.reportPreview;
    pushStatus(`Markdown preview generated for the ${state.reportVariant} report.`, "info");
  }
  state.reportFormat = format;
}

function renderExplorer() {
  const groupedByCustomer = groupBy(state.engagements, (engagement) => engagement.client || "Unassigned Customer");
  dom.customerIndex.innerHTML = Object.entries(groupedByCustomer).length
    ? Object.entries(groupedByCustomer)
        .map(([customer, engagements]) => `
          <div class="list-card">
            <h4>${escapeHtml(customer)}</h4>
            <p>${escapeHtml(`${engagements.length} engagement dossiers`)}</p>
          </div>
        `)
        .join("")
    : emptyState("Customers will populate as engagements are created.");

  dom.engagementDossiers.innerHTML = state.engagements.length
    ? state.engagements
        .map((engagement) => {
          const runs = state.mission.runs.filter((run) => run.engagement_id === engagement.id);
          return `
            <div class="list-card ${engagement.id === state.selectedEngagementId ? "selected" : ""}" data-engagement-pick="${engagement.id}">
              <h4>${escapeHtml(engagement.name)}</h4>
              <p>${escapeHtml(engagement.client || "No customer")}</p>
              <p class="micro-copy">${escapeHtml(`${runs.length} runs · ${engagement.status}`)}</p>
            </div>
          `;
        })
        .join("")
    : emptyState("No engagement dossiers exist yet.");
  dom.engagementDossiers.querySelectorAll("[data-engagement-pick]").forEach((item) => {
    item.addEventListener("click", async () => {
      state.selectedEngagementId = item.dataset.engagementPick;
      await refreshSelectedEngagement();
      state.activeScreen = "explorer";
      renderScreens();
    });
  });

  const run = state.selectedRun;
  if (!run) {
    dom.runDossier.innerHTML = emptyState("Select a run to inspect its dossier.");
    return;
  }
  const config = run.configuration_json || {};
  dom.runDossier.innerHTML = `
    <h4>${escapeHtml(run.profile.name)} <span class="badge">${escapeHtml(run.status)}</span></h4>
    <p>${escapeHtml(`Requested by ${run.requested_by} · created ${formatDateTime(run.created_at)}`)}</p>
    <div class="wizard-panel-grid split-top">
      <div class="detail-surface">
        <h4>Configuration</h4>
        <p>${escapeHtml(config.assessment_type || "Not recorded")}</p>
        <p class="micro-copy">${escapeHtml(renderTargetSummary(config.targets || {}))}</p>
      </div>
      <div class="detail-surface">
        <h4>Capability Pack</h4>
        <p>${escapeHtml(run.pack_binding?.pack_version || "Standard baseline")}</p>
        <p class="micro-copy">${escapeHtml(`Inventory ${run.source_inventory_snapshot_id || "n/a"}`)}</p>
      </div>
      <div class="detail-surface">
        <h4>Findings</h4>
        <p>${escapeHtml(`${run.findings.finding_count} total findings`)}</p>
        <p class="micro-copy">${escapeHtml(JSON.stringify(run.findings.findings_by_severity || {}))}</p>
      </div>
      <div class="detail-surface">
        <h4>Reports</h4>
        <p>${escapeHtml(`${state.reportCatalog.length} variants ready`)}</p>
        <p class="micro-copy">${escapeHtml(state.reportCatalog.map((report) => report.title).join(", ") || "No reports loaded")}</p>
      </div>
    </div>
    <div class="detail-surface split-top">
      <h4>Approvals & Decisions</h4>
      ${run.approvals.length ? run.approvals.map((approval) => `<p>${statusPill(approval.decision)} ${escapeHtml(approval.approver_id)} · ${escapeHtml(approval.step_id)}</p>`).join("") : "<p>No approval records on this run.</p>"}
    </div>
  `;
}

function renderHistoryComparison() {
  dom.historyToolbar.innerHTML = `
    <label class="field compact">
      <span>Current Run</span>
      <select id="history-current-run">
        ${state.mission.runs.map((run) => `<option value="${run.id}" ${run.id === state.selectedRunId ? "selected" : ""}>${escapeHtml(run.profile.name)} · ${escapeHtml(run.status)}</option>`).join("")}
      </select>
    </label>
    <label class="field compact">
      <span>Baseline Run</span>
      <select id="history-baseline-run">
        <option value="">No baseline</option>
        ${state.mission.runs.filter((run) => run.id !== state.selectedRunId).map((run) => `<option value="${run.id}" ${run.id === state.comparisonBaselineRunId ? "selected" : ""}>${escapeHtml(run.profile.name)} · ${escapeHtml(run.status)}</option>`).join("")}
      </select>
    </label>
  `;
  document.getElementById("history-current-run")?.addEventListener("change", async (event) => {
    state.selectedRunId = event.target.value;
    await loadSelectedRun();
    renderAll();
  });
  document.getElementById("history-baseline-run")?.addEventListener("change", (event) => {
    state.comparisonBaselineRunId = event.target.value || null;
    renderHistoryComparison();
    renderReportCenter();
  });

  const comparison = compareRuns(state.selectedRunId, state.comparisonBaselineRunId);
  dom.comparisonSummary.innerHTML = comparison
    ? `
      <h4>${escapeHtml(`Current vs baseline`)}</h4>
      <p>${escapeHtml(`${comparison.newCount} new · ${comparison.fixedCount} fixed · ${comparison.persistingCount} still open`)}</p>
      <p>${escapeHtml(`${comparison.worsenedCount} worsened · pack changed ${comparison.packChanged ? "yes" : "no"}`)}</p>
      <p class="micro-copy">${escapeHtml(comparison.summary)}</p>
    `
    : emptyState("Choose a baseline run to compare changes over time.");

  const sortedRuns = [...state.mission.runs].sort((left, right) => new Date(left.created_at) - new Date(right.created_at));
  dom.historyTrend.innerHTML = sortedRuns.length
    ? sortedRuns
        .map((run) => {
          const findings = state.mission.findingsByRun[run.id] || [];
          const open = findings.filter((finding) => ["open", "triaged", "in_progress", "reopened"].includes(finding.status)).length;
          const percent = Math.min(100, findings.length * 12);
          return `
            <div class="trend-card">
              <h4>${escapeHtml(run.profile.name)}</h4>
              <p>${escapeHtml(`${findings.length} findings · ${open} still open`)}</p>
              <div class="history-bar split-top"><span style="width:${percent}%"></span></div>
              <p class="micro-copy split-top">${escapeHtml(formatDateTime(run.created_at))}</p>
            </div>
          `;
        })
        .join("")
    : emptyState("Run trend history appears after multiple runs exist in the engagement.");

  const nextSteps = buildNextStepsQueue();
  dom.nextStepsQueue.innerHTML = nextSteps.length
    ? nextSteps
        .map(
          (item) => `
            <div class="list-card">
              <h4>${escapeHtml(item.title)}</h4>
              <p>${statusPill(item.status)} ${escapeHtml(item.priority)}</p>
              <p>${escapeHtml(item.action)}</p>
              <p class="micro-copy">${escapeHtml(item.retest)}</p>
            </div>
          `
        )
        .join("")
    : emptyState("Open findings and their recommended follow-up actions appear here.");
}

function filterFindings(allFindings) {
  return allFindings.filter((finding) => {
    if (state.findingFilters.runId !== "all" && finding._runId !== state.findingFilters.runId) return false;
    if (state.findingFilters.severity !== "all" && finding.severity !== state.findingFilters.severity) return false;
    if (state.findingFilters.origin !== "all" && finding.finding_origin !== state.findingFilters.origin) return false;
    if (state.findingFilters.status !== "all" && finding.status !== state.findingFilters.status) return false;
    if (state.findingFilters.methodology !== "all" && !(finding.methodology_tags || []).includes(state.findingFilters.methodology)) return false;
    return true;
  }).sort((left, right) => {
    const leftRank = SEVERITY_RANK[left.severity] ?? SEVERITY_RANK.unknown;
    const rightRank = SEVERITY_RANK[right.severity] ?? SEVERITY_RANK.unknown;
    if (leftRank !== rightRank) return leftRank - rightRank;
    return left.title.localeCompare(right.title);
  });
}

function groupFindings(findings, groupBy) {
  return findings.reduce((groups, finding) => {
    let key = "Ungrouped";
    if (groupBy === "severity") key = finding.severity;
    if (groupBy === "origin") key = finding.finding_origin;
    if (groupBy === "status") key = finding.status;
    if (groupBy === "methodology") key = finding.methodology_tags?.[0] || "Not tagged";
    if (groupBy === "run") key = state.mission.runs.find((run) => run.id === finding._runId)?.profile?.name || "Unknown run";
    groups[key] = groups[key] || [];
    groups[key].push(finding);
    return groups;
  }, {});
}

function renderReportComparison(selectedReport) {
  const comparison = compareRuns(state.selectedRunId, state.comparisonBaselineRunId);
  if (!comparison) {
    return emptyState("Select a baseline run in History & Comparison to compare report posture.");
  }
  return `
    <h4>${escapeHtml(selectedReport.title)}</h4>
    <p>${escapeHtml(`${comparison.newCount} new findings · ${comparison.fixedCount} fixed since the baseline run`)}</p>
    <p>${escapeHtml(`${comparison.persistingCount} findings still open · ${comparison.worsenedCount} worsened`)}</p>
    <p class="micro-copy">${escapeHtml(`Pack changed: ${comparison.packChanged ? "yes" : "no"} · baseline ${comparison.baselineLabel}`)}</p>
  `;
}

function compareRuns(currentRunId, baselineRunId) {
  if (!currentRunId || !baselineRunId) return null;
  const currentRun = state.mission.runs.find((run) => run.id === currentRunId);
  const baselineRun = state.mission.runs.find((run) => run.id === baselineRunId);
  if (!currentRun || !baselineRun) return null;
  const currentFindings = state.mission.findingsByRun[currentRunId] || [];
  const baselineFindings = state.mission.findingsByRun[baselineRunId] || [];
  const baselineMap = new Map(baselineFindings.map((finding) => [findingKey(finding), finding]));
  const currentMap = new Map(currentFindings.map((finding) => [findingKey(finding), finding]));
  let worsenedCount = 0;
  currentFindings.forEach((finding) => {
    const prior = baselineMap.get(findingKey(finding));
    if (!prior) return;
    const currentRank = severityRank(finding.severity);
    const priorRank = severityRank(prior.severity);
    if (currentRank < priorRank) worsenedCount += 1;
  });
  const newCount = currentFindings.filter((finding) => !baselineMap.has(findingKey(finding))).length;
  const fixedCount = baselineFindings.filter((finding) => !currentMap.has(findingKey(finding))).length;
  const persistingCount = currentFindings.filter((finding) => baselineMap.has(findingKey(finding))).length;
  return {
    newCount,
    fixedCount,
    persistingCount,
    worsenedCount,
    packChanged: (currentRun.pack_binding?.pack_version || null) !== (baselineRun.pack_binding?.pack_version || null),
    baselineLabel: `${baselineRun.profile.name} ${formatDateTime(baselineRun.created_at)}`,
    summary: `Compared against ${baselineRun.profile.name}, this run introduced ${newCount} new findings and closed ${fixedCount}.`,
  };
}

function buildNextStepsQueue() {
  return selectedRunFindings()
    .filter((finding) => !["resolved", "accepted_risk", "false_positive"].includes(finding.status))
    .sort((left, right) => severityRank(left.severity) - severityRank(right.severity))
    .slice(0, 8)
    .map((finding) => ({
      title: finding.title,
      status: finding.status,
      priority: finding.severity.toUpperCase(),
      action: `Review ${finding.finding_origin === "adaptive_pack" ? "adaptive" : "standard"} evidence and start remediation planning for ${finding.target_id}.`,
      retest: "Retest is needed after remediation with the same methodology references still attached.",
    }));
}

function renderStringList(items, emptyMessage) {
  return items.length
    ? items.map((item) => `<div class="list-card"><p>${escapeHtml(item)}</p></div>`).join("")
    : emptyState(emptyMessage);
}

function renderStringCards(items, emptyMessage) {
  return items.length
    ? items.map((item) => `<div class="list-card"><p>${escapeHtml(item)}</p></div>`).join("")
    : emptyState(emptyMessage);
}

function buildRunConfiguration(data, estimate) {
  return {
    assessment_type: data.assessment_type,
    test_profile: data.test_profile,
    execution_profile: estimate.execution_profile,
    targets: data.targets,
    access: {
      accounts: data.access.accounts
        .filter((account) => hasMeaningfulAccount([account]))
        .map((account) => ({
          label: account.label,
          username: account.username,
          role: account.role,
          secret_ref: account.secret_ref || null,
          api_key_ref: account.api_key_ref || null,
          bearer_token_ref: account.bearer_token_ref || null,
          session_ref: account.session_ref || null,
          mfa_notes: account.mfa_notes || null,
        })),
      manual_auth_steps: valueOrNull(data.access.manual_auth_steps),
      cookie_notes: valueOrNull(data.access.cookie_notes),
    },
    modules: data.modules,
    safety: data.safety,
    eta: estimate,
  };
}

function buildAllowlistFromWizard(targets) {
  return {
    domains: [...targets.domains, ...targets.subdomains].filter(Boolean),
    urls: [...targets.urls, ...targets.api_base_urls].filter(Boolean),
    hosts: [...targets.ip_addresses].filter(Boolean),
    cidrs: [...targets.cidr_ranges].filter(Boolean),
  };
}

function buildInventorySeedPayload(engagementId, data) {
  const hosts = [...data.targets.domains, ...data.targets.subdomains, ...data.targets.ip_addresses];
  const urls = [...data.targets.urls, ...data.targets.api_base_urls];
  return {
    engagement_id: engagementId,
    source_tools: ["wizard-input"],
    observations: [
      {
        tool: "wizard-input",
        kind: "inventory-seed",
        data: {
          hosts,
          urls,
          endpoints: urls.map((url) => ({ url, methods: ["GET"], status_code: 200 })),
          auth_mechanisms: data.access.accounts.filter((account) => hasMeaningfulAccount([account])).map((account) => ({
            type: account.session_ref ? "session-context" : "credential-reference",
            location: account.role || null,
            confidence: 0.7,
          })),
          api_types: data.targets.api_base_urls.map((url) => ({ type: "rest", base_url: url, confidence: 0.7 })),
          tls: data.assessment_type === "SSL/TLS Only"
            ? { protocols: ["tls"], issues: [], confidence: 0.8 }
            : undefined,
          confidence: 0.72,
        },
      },
    ],
    environment_notes: [
      `Wizard seeded assessment type: ${data.assessment_type}`,
      `Wizard profile: ${data.test_profile}`,
    ],
    assumptions: [
      "Seed inventory was created from operator-reviewed wizard input before active discovery.",
      data.access.manual_auth_steps ? `Manual auth note: ${data.access.manual_auth_steps}` : "No shared manual auth note provided.",
    ],
  };
}

function estimateMission(data) {
  const targetsCount = flattenTargetValues(data.targets).length;
  const moduleCount = enabledModules(data.modules).length;
  const accountCount = data.access.accounts.filter((account) => hasMeaningfulAccount([account])).length;
  const profileMultipliers = {
    "Light": 0.7,
    "Standard": 1,
    "Deep": 1.5,
    "External Surface Only": 0.85,
    "Authenticated Only": 1.15,
    "SSL/TLS Only": 0.65,
    "Internal Validation": 1.85,
    "Adaptive Customer-Specific Mode": 1.55,
  };
  const base = 24 + targetsCount * 9 + moduleCount * 4 + accountCount * 10 + (data.safety.adaptive_generation ? 14 : 0);
  const estimated_total_minutes = Math.round(base * (profileMultipliers[data.test_profile] || 1));
  const execution_profile = resolveExecutionProfile(data);
  const estimated_impact = data.safety.active_checks === "active" || data.test_profile === "Internal Validation"
    ? "high"
    : data.test_profile === "Deep" || data.test_profile === "Authenticated Only"
      ? "medium"
      : "low";
  const confidence = targetsCount >= 2 ? "medium" : "low";
  return {
    estimated_total_minutes,
    estimated_impact,
    confidence,
    execution_profile,
    summary: `Estimated duration ${estimated_total_minutes} minutes with ${estimated_impact} expected impact under ${execution_profile}.`,
  };
}

function resolveExecutionProfile(data) {
  if (data.test_profile === "Internal Validation") return "intrusive-validation";
  if (data.test_profile === "SSL/TLS Only") return "passive-web-baseline";
  if (data.test_profile === "Light" || data.test_profile === "External Surface Only") return "passive-web-baseline";
  if (data.test_profile === "Standard" && data.modules.nuclei_checks) return "passive-web-nuclei-audit";
  if (data.safety.active_checks === "active" && data.modules.zap_active_checks) return "active-web-zap-active";
  if (data.test_profile === "Deep" || data.test_profile === "Authenticated Only" || data.test_profile === "Adaptive Customer-Specific Mode") return "active-web-safe";
  return "passive-web-baseline";
}

function applyProfilePreset(profile) {
  const modules = state.wizard.data.modules;
  if (profile === "SSL/TLS Only") {
    Object.keys(modules).forEach((key) => { modules[key] = false; });
    modules.ssl_tls_analysis = true;
    state.wizard.data.safety.active_checks = "passive-only";
    state.wizard.data.safety.adaptive_generation = false;
    return;
  }
  if (profile === "External Surface Only") {
    Object.keys(modules).forEach((key) => { modules[key] = false; });
    modules.discovery = true;
    modules.web_crawling = true;
    modules.content_discovery = true;
    modules.nuclei_checks = true;
    modules.ssl_tls_analysis = true;
    return;
  }
  if (profile === "Authenticated Only") {
    modules.auth_flows = true;
    modules.business_logic_testing = true;
    modules.web_crawling = true;
    state.wizard.data.safety.active_checks = "guarded";
    return;
  }
  if (profile === "Internal Validation") {
    modules.internal_validation_modules = true;
    modules.auth_flows = true;
    modules.nuclei_checks = true;
    modules.zap_active_checks = true;
    state.wizard.data.safety.active_checks = "active";
    state.wizard.data.safety.adaptive_generation = false;
    return;
  }
  if (profile === "Adaptive Customer-Specific Mode") {
    modules.adaptive_ai_generated_tests = true;
    modules.nuclei_checks = true;
    modules.web_crawling = true;
    modules.auth_flows = true;
    state.wizard.data.safety.adaptive_generation = true;
    return;
  }
  Object.assign(state.wizard.data.modules, { ...DEFAULT_MODULE_STATE });
  Object.assign(state.wizard.data.safety, { ...DEFAULT_SAFETY });
}

function filteredCodexTasks() {
  const selectedPackIds = new Set(state.mission.packs.map((pack) => pack.id));
  return state.codexTasks.filter((task) => !task.source_context?.pack_id || selectedPackIds.has(task.source_context.pack_id));
}

function assessmentTypeCopy(type) {
  const mapping = {
    "Website / Web App": "Crawlable browser-facing surface with standard page and workflow discovery.",
    "Domain / Domains": "Domain-scoped recon and service discovery across named targets.",
    "External IP / WAN": "Perimeter validation against explicit WAN IP targets.",
    "Internal Range / LAN": "Internal network range validation with scope-controlled depth.",
    "API": "API-first assessment with base URLs, auth context, and protocol-aware testing.",
    "SSL/TLS Only": "Certificate, protocol, and crypto posture validation only.",
    "Authenticated App": "Application validation where session or credentialed access is central.",
    "Mixed Assessment": "Combined web, API, network, auth, and adaptive workflows.",
  };
  return mapping[type] || "Assessment type";
}

function testProfileCopy(profile) {
  const mapping = {
    "Light": "Faster low-impact coverage with emphasis on passive discovery and fingerprinting.",
    "Standard": "Balanced baseline suited for most scoped engagements.",
    "Deep": "Broader active depth with more validation time and review overhead.",
    "External Surface Only": "Focus on exposed surface and perimeter posture without deeper auth flows.",
    "Authenticated Only": "Prioritize account-context workflows, auth paths, and role behavior.",
    "SSL/TLS Only": "Only certificate and transport protection analysis.",
    "Internal Validation": "Approval-heavy validation for controlled internal adversary simulation.",
    "Adaptive Customer-Specific Mode": "Inventory-informed plus adaptive pack generation before deeper validation.",
  };
  return mapping[profile] || "Profile";
}

function moduleCopy(key) {
  const mapping = {
    discovery: "Resolve targets, fingerprints, and accessible surface safely.",
    web_crawling: "Build page and route coverage for browser-facing applications.",
    auth_flows: "Exercise login, session, and role-aware access paths.",
    content_discovery: "Enumerate discoverable content and hidden application routes.",
    nuclei_checks: "Run templated security probes through the managed validation lane.",
    zap_active_checks: "Use approval-aware ZAP active checks where safety allows.",
    ssl_tls_analysis: "Inspect certificate and transport security posture.",
    business_logic_testing: "Investigate workflow abuse and privilege or process edge cases.",
    adaptive_ai_generated_tests: "Enable customer-specific adaptive checks from Pack Forge.",
    internal_validation_modules: "Prepare internal validation modules and scenarios.",
  };
  return mapping[key] || key;
}

function visibleTargetGroups(assessmentType) {
  const base = ["domains", "urls"];
  if (assessmentType === "API") return ["api_base_urls", "urls", "domains"];
  if (assessmentType === "SSL/TLS Only") return ["domains", "urls", "ip_addresses"];
  if (assessmentType === "External IP / WAN") return ["ip_addresses", "cidr_ranges"];
  if (assessmentType === "Internal Range / LAN") return ["cidr_ranges", "ip_addresses"];
  if (assessmentType === "Domain / Domains") return ["domains", "subdomains", "urls"];
  if (assessmentType === "Authenticated App") return ["urls", "domains", "api_base_urls"];
  if (assessmentType === "Mixed Assessment") return ["domains", "subdomains", "urls", "ip_addresses", "cidr_ranges", "api_base_urls"];
  return [...base, "subdomains"];
}

function surfaceOverlayLabel(key) {
  const mapping = {
    hotspots: "Hotspots",
    packZones: "Pack Impact Zones",
    futureAttackPaths: "Future Attack Paths",
    futureIdentityGraph: "Future Identity Graph",
    futureRiskOverlay: "Future Risk Overlay",
  };
  return mapping[key] || key;
}

function packProgress(status) {
  const mapping = {
    proposed: 10,
    generated: 40,
    validation_failed: 35,
    validated: 60,
    approved: 80,
    deployed: 100,
    retired: 100,
    superseded: 100,
  };
  return mapping[status] || 0;
}

function packStatusToPhaseStatus(status) {
  if (["validation_failed", "retired"].includes(status)) return "blocked";
  if (["deployed", "approved", "validated", "superseded"].includes(status)) return "complete";
  if (["generated", "proposed"].includes(status)) return "active";
  return "pending";
}

function renderTargetSummary(targets) {
  const normalized = typeof targets === "object" && targets !== null ? targets : {};
  const pieces = [];
  Object.entries(normalized).forEach(([key, values]) => {
    if (!Array.isArray(values) || !values.length) return;
    pieces.push(`${values.length} ${key.replaceAll("_", " ")}`);
  });
  return pieces.join(" · ") || "No targets yet";
}

function enabledModules(modules) {
  if (!modules || typeof modules !== "object") return [];
  return MODULES.filter(([key]) => Boolean(modules[key])).map(([, label]) => label);
}

function renderAccountSummary(accounts) {
  const meaningful = (accounts || []).filter((account) => hasMeaningfulAccount([account]));
  if (!meaningful.length) return "No account context recorded";
  return meaningful.map((account) => `${account.label || account.username || "Account"} (${account.role || "role not set"})`).join(", ");
}

function hasMeaningfulAccount(accounts) {
  return (accounts || []).some((account) =>
    Boolean(
      account &&
      (account.username || account.secret_ref || account.api_key_ref || account.bearer_token_ref || account.session_ref)
    )
  );
}

function requiresCredentials(config) {
  const profile = config.test_profile || "";
  const assessmentType = config.assessment_type || "";
  return ["Authenticated Only", "Authenticated App", "Internal Validation"].includes(profile) ||
    ["Authenticated App"].includes(assessmentType) ||
    Boolean(config.modules?.auth_flows);
}

function countScopeTargets(scope) {
  if (!scope) return 0;
  return Object.values(scope.allowlist_json || {}).reduce((count, values) => count + (Array.isArray(values) ? values.length : 0), 0);
}

function summarizeTaskStatuses(tasks) {
  return tasks.reduce((counts, task) => {
    counts[task.status] = (counts[task.status] || 0) + 1;
    return counts;
  }, { completed: 0, failed: 0, cancelled: 0, queued: 0, running: 0 });
}

function flattenTargetValues(targets) {
  return Object.values(targets || {}).flatMap((values) => Array.isArray(values) ? values.filter(Boolean) : []);
}

function findingKey(finding) {
  return `${finding.title}::${finding.target_id}`;
}

function severityRank(severity) {
  return SEVERITY_RANK[String(severity || "unknown").toLowerCase()] ?? SEVERITY_RANK.unknown;
}

function lineSvg(x1, y1, x2, y2) {
  return `<line x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}" stroke="rgba(107,215,255,0.18)" stroke-width="0.4" stroke-dasharray="1 1" />`;
}

function heroChip(label, meta) {
  return `<div class="hero-chip">${escapeHtml(label)} · ${escapeHtml(meta)}</div>`;
}

function textareaField(id, label, values, placeholder) {
  return `
    <label class="field">
      <span>${escapeHtml(label)}</span>
      <textarea id="${id}" rows="6" placeholder="${escapeHtml(placeholder)}">${escapeHtml((values || []).join("\n"))}</textarea>
    </label>
  `;
}

function emptyState(message) {
  return `<div class="empty-state">${escapeHtml(message)}</div>`;
}

function statusPill(status) {
  const normalized = String(status || "unknown").toLowerCase().replace(/\s+/g, "-");
  const theme = ["complete", "completed", "validated", "approved", "deployed", "passed", "resolved"].includes(normalized)
    ? normalized
    : ["pending", "pending_approval", "requested", "generated", "queued", "draft", "review", "triaged", "in_progress", "open"].includes(normalized)
      ? (normalized === "in_progress" ? "active" : normalized === "pending_approval" ? "blocked" : normalized)
      : ["failed", "blocked", "rejected", "cancelled", "critical"].includes(normalized)
        ? normalized
        : normalized === "running"
          ? "running"
          : "unknown";
  return `<span class="status-pill status-${theme}">${escapeHtml(status || "unknown")}</span>`;
}

function pushStatus(message, tone = "info") {
  statusFeed.unshift({
    message,
    tone,
    timestamp: new Date().toLocaleTimeString(),
  });
  while (statusFeed.length > 10) statusFeed.pop();
  renderStatus();
}

async function apiOrNull(path) {
  try {
    return await api(path);
  } catch (error) {
    if (error.status === 404) return null;
    throw error;
  }
}

async function api(path, options = {}) {
  const headers = new Headers(options.headers || {});
  headers.set("X-Actor", state.actor);
  if (options.body && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }

  const response = await fetch(path, {
    method: options.method || "GET",
    headers,
    body: options.body ? JSON.stringify(options.body) : undefined,
  });

  const contentType = response.headers.get("content-type") || "";
  const payload = contentType.includes("application/json") ? await response.json() : await response.text();
  if (!response.ok) {
    const message = typeof payload === "string" ? payload : payload.detail || payload.message || "Request failed";
    const error = new Error(message);
    error.status = response.status;
    throw error;
  }
  return options.raw ? payload : payload;
}

function handleError(error) {
  console.error(error);
  pushStatus(error.message || "Unexpected UI error.", "error");
}

function assertSelectedEngagement() {
  if (!state.selectedEngagementId) throw new Error("Select or create an engagement first.");
}

function assertSelectedPack() {
  if (!state.selectedPackId) throw new Error("Select or generate a pack first.");
}

function splitLines(value) {
  return String(value || "")
    .split("\n")
    .map((item) => item.trim())
    .filter(Boolean);
}

function splitComma(value) {
  return String(value || "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function stringValue(value) {
  return String(value || "").trim();
}

function numberValue(value, fallback) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function valueOrNull(value) {
  const normalized = stringValue(value);
  return normalized ? normalized : null;
}

function slugify(value) {
  return String(value || "workspace")
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "") || "workspace";
}

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function formatDateTime(value) {
  if (!value) return "Unknown";
  return new Date(value).toLocaleString();
}

function minutesSince(value) {
  if (!value) return 0;
  return Math.max(0, Math.round((Date.now() - new Date(value).getTime()) / 60000));
}

function formatElapsedMinutes(value, offset = 0) {
  return `${minutesSince(value) + offset}m`;
}

function toPercent(value) {
  const number = Number(value || 0);
  return `${Math.round(number * 100)}%`;
}

function isLikelyUrl(value) {
  try {
    const url = new URL(value);
    return Boolean(url.protocol && url.host);
  } catch {
    return false;
  }
}

function isLikelyIp(value) {
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(String(value || "").trim());
}

function isLikelyCidr(value) {
  return /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/.test(String(value || "").trim());
}

function isLikelyDomain(value) {
  return /^[a-z0-9.-]+\.[a-z]{2,}$/i.test(String(value || "").trim());
}

function groupBy(items, selector) {
  return items.reduce((groups, item) => {
    const key = selector(item);
    groups[key] = groups[key] || [];
    groups[key].push(item);
    return groups;
  }, {});
}
