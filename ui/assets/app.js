import { api, apiOrNull } from "./modules/api.js";
import { createExplorerHistoryModule } from "./modules/explorer-history.js";
import { createFindingsModule } from "./modules/findings.js";
import { createMissionModule } from "./modules/mission-control.js";
import { createPacksModule } from "./modules/packs.js";
import { createReportsModule } from "./modules/reports.js";
import { dom, runtime, setRefreshTimer, state, statusFeed } from "./modules/runtime.js";
import { countScopeTargets, emptyState, escapeHtml, heroChip } from "./modules/shared.js";
import { createWizardModule } from "./modules/wizard.js";

let wizardModule;
let missionModule;
let findingsModule;
let packsModule;
let reportsModule;
let explorerHistoryModule;

document.addEventListener("DOMContentLoaded", () => {
  bindDom();
  initializeModules();
  bindRuntimeActions();
  bindGlobalEvents();
  boot().catch(handleError);
});

function initializeModules() {
  wizardModule = createWizardModule();
  missionModule = createMissionModule();
  findingsModule = createFindingsModule();
  packsModule = createPacksModule();
  reportsModule = createReportsModule();
  explorerHistoryModule = createExplorerHistoryModule();
}

function bindDom() {
  dom.actorInput = document.getElementById("actor-input");
  dom.heroMetrics = document.getElementById("hero-metrics");
  dom.flowOverview = document.getElementById("flow-overview");
  dom.nextActions = document.getElementById("next-actions");
  dom.engagementSelect = document.getElementById("engagement-select");
  dom.refreshBtn = document.getElementById("refresh-btn");
  dom.screenLinks = Array.from(document.querySelectorAll(".screen-link"));
  dom.screens = Array.from(document.querySelectorAll(".screen"));
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

function bindRuntimeActions() {
  Object.assign(runtime.actions, {
    compareRuns: explorerHistoryModule.compareRuns,
    engagementFindings,
    handleError,
    latestInventorySnapshot,
    latestRelevanceDecision,
    loadSelectedFinding,
    loadSelectedPack,
    loadSelectedRun,
    loadSelectedTask,
    navigateToScreen,
    pushStatus,
    refreshSelectedEngagement,
    refreshShell,
    renderAll,
    renderFlowOverview,
    renderMissionControl: missionModule.renderMissionControl,
    renderReportCenter: reportsModule.renderReportCenter,
    renderScreens,
    selectedEngagement,
    selectedPack,
    selectedRunFindings,
  });
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
      navigateToScreen(button.dataset.screen);
    });
  });

  document.body.addEventListener("click", (event) => {
    const target = event.target.closest("[data-nav-screen]");
    if (!target) return;
    event.preventDefault();
    navigateToScreen(target.dataset.navScreen);
  });

  dom.wizardBackBtn.addEventListener("click", () => {
    wizardModule.syncWizardStepFromDom();
    state.wizard.errors = [];
    state.wizard.step = Math.max(0, state.wizard.step - 1);
    wizardModule.renderWizard();
  });

  dom.wizardNextBtn.addEventListener("click", () => {
    wizardModule.syncWizardStepFromDom();
    const errors = wizardModule.validateWizardStep(state.wizard.step);
    if (errors.length) {
      state.wizard.errors = errors;
      wizardModule.renderWizard();
      return;
    }
    state.wizard.errors = [];
    state.wizard.step = Math.min(6, state.wizard.step + 1);
    wizardModule.renderWizard();
  });

  dom.wizardConfirmBtn.addEventListener("click", () => wizardModule.submitWizard().catch(handleError));
  dom.validatePackBtn.addEventListener("click", () => packsModule.validateSelectedPack().catch(handleError));
  dom.approvePackBtn.addEventListener("click", () => packsModule.approveSelectedPack().catch(handleError));
  dom.deployPackBtn.addEventListener("click", () => packsModule.deploySelectedPack().catch(handleError));
  dom.prepareCodexTaskBtn.addEventListener("click", () =>
    packsModule.prepareSelectedCodexTask().catch(handleError)
  );
}

async function boot() {
  await refreshShell();
  renderAll();
  startAutoRefresh();
}

function startAutoRefresh() {
  if (runtime.refreshTimer) {
    window.clearInterval(runtime.refreshTimer);
  }
  const timer = window.setInterval(() => {
    if (!state.selectedEngagementId) return;
    refreshSelectedEngagement().catch(handleError);
  }, 20000);
  setRefreshTimer(timer);
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
    return;
  }
  renderAll();
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

  const [scope, inventory, relevance, packs, runs, internalValidations, codexTasks] =
    await Promise.all([
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
  if (
    !state.comparisonBaselineRunId ||
    !runs.some((run) => run.id === state.comparisonBaselineRunId)
  ) {
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
  state.loading.reportPreview = false;
  state.selectedRun = await api(`/api/v1/runs/${state.selectedRunId}`);
  state.reportCatalog = await api(`/api/v1/runs/${state.selectedRunId}/reports`);
  const findings = state.mission.findingsByRun[state.selectedRunId] || [];
  if (!state.selectedFindingId || !findings.some((finding) => finding.id === state.selectedFindingId)) {
    state.selectedFindingId = findings[0]?.id || null;
  }
  if (
    !state.selectedTaskId ||
    !state.selectedRun.tasks.some((task) => task.id === state.selectedTaskId)
  ) {
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
    state.selectedCodexResult = null;
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
  renderFlowOverview();
  renderScreens();
}

function renderHeader() {
  const runCount = state.mission.runs.length || 0;
  const findings = engagementFindings();
  const criticalCount = findings.filter((finding) => finding.severity === "critical").length;
  const openCount = findings.filter((finding) =>
    ["open", "triaged", "in_progress", "reopened"].includes(finding.status)
  ).length;
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
    dom.selectedEngagementSummary.innerHTML = emptyState(
      "Complete the Assessment Wizard to create the first mission dossier."
    );
    return;
  }
  const scope = state.mission.scope;
  const currentRun = state.selectedRun;
  const config = currentRun?.configuration_json || {};
  const secretBindings = config.access?.secret_storage?.binding_count || 0;
  dom.selectedEngagementSummary.innerHTML = `
    <div class="badge">Customer · ${escapeHtml(engagement.client || "Not set")}</div>
    <div class="badge">Engagement · ${escapeHtml(engagement.name)}</div>
    <div class="badge">ROE · ${escapeHtml(engagement.roe_ref || "Not set")}</div>
    <div class="badge">Status · ${escapeHtml(engagement.status)}</div>
    <div class="badge">Targets · ${countScopeTargets(scope)}</div>
    <div class="badge">Profile · ${escapeHtml(config.test_profile || currentRun?.profile?.name || "Not configured")}</div>
    <div class="badge">Protected Secrets · ${escapeHtml(String(secretBindings))}</div>
  `;
}

function renderStatus() {
  dom.statusFeed.innerHTML = statusFeed.length
    ? statusFeed
        .map(
          (item) => `
            <div class="feed-item tone-${escapeHtml(String(item.tone || "info").toLowerCase())}">
              <strong>${escapeHtml(item.timestamp)} · ${escapeHtml(item.tone)}</strong>
              <p>${escapeHtml(item.message)}</p>
            </div>
          `
        )
        .join("")
    : emptyState("Wizard actions, pack promotion events, and report activity appear here.");
}

function renderFlowOverview() {
  const stages = buildLifecycleFlow();
  dom.flowOverview.innerHTML = stages
    .map(
      (stage) => `
        <div class="flow-step ${stage.state}">
          <p class="eyebrow">${escapeHtml(stage.kicker)}</p>
          <strong>${escapeHtml(stage.label)}</strong>
          <small>${escapeHtml(stage.summary)}</small>
        </div>
      `
    )
    .join("");

  const nextActions = buildNextActions();
  dom.nextActions.innerHTML = nextActions.length
    ? nextActions
        .map(
          (action, index) => `
            <button class="action ${index === 0 ? "primary" : "ghost"}" type="button" data-nav-screen="${escapeHtml(action.screen)}">
              ${escapeHtml(action.label)}
            </button>
          `
        )
        .join("")
    : `<button class="action primary" type="button" data-nav-screen="wizard">Start in Wizard</button>`;
}

function buildLifecycleFlow() {
  const run = state.selectedRun;
  const findings = selectedRunFindings();
  const reportReady = Boolean(state.reportCatalog.length);
  const comparisonReady = state.mission.runs.length > 1;
  const phases = missionModule.buildMissionPhases();
  const blocked = phases.find((phase) => phase.status === "blocked");

  return [
    {
      kicker: "1",
      label: "Wizard",
      state: run ? "complete" : "active",
      summary: run
        ? "Mission settings are locked into the current mission record."
        : "Define scope, access, safety, and operator profile.",
    },
    {
      kicker: "2",
      label: "Mission Control",
      state: blocked ? "blocked" : run ? "active" : "pending",
      summary: blocked
        ? blocked.summary
        : run
          ? "Track live progress, blockers, ETA, and adaptive readiness."
          : "Opens once a mission record exists.",
    },
    {
      kicker: "3",
      label: "Drilldowns",
      state: findings.length ? "active" : run ? "pending" : "pending",
      summary: findings.length
        ? `${findings.length} findings and replayable evidence are ready for review.`
        : "Findings and evidence will appear as validation results arrive.",
    },
    {
      kicker: "4",
      label: "Reports",
      state: reportReady ? "complete" : run ? "pending" : "pending",
      summary: reportReady
        ? `${state.reportCatalog.length} report variants are ready for preview or export.`
        : "Generate executive, technical, evidence, or retest outputs when the mission matures.",
    },
    {
      kicker: "5",
      label: "History",
      state: comparisonReady ? "active" : "pending",
      summary: comparisonReady
        ? "Compare the current mission against prior runs and track what changed."
        : "History becomes more valuable as repeat missions accumulate.",
    },
  ];
}

function buildNextActions() {
  if (!state.selectedRun) {
    return [{ label: "Complete Assessment Wizard", screen: "wizard" }];
  }

  const findings = selectedRunFindings();
  const phases = missionModule.buildMissionPhases();
  const blocked = phases.find((phase) => phase.status === "blocked");
  const actions = [];

  if (blocked) {
    actions.push({ label: "Review Mission Control", screen: "mission-control" });
  }
  if (findings.length) {
    actions.push({ label: "Review Findings", screen: "findings-theater" });
    if (state.selectedFindingEvidence) {
      actions.push({ label: "Open Evidence Replay", screen: "evidence-replay" });
    }
  } else if (state.selectedPackBundle || state.mission.relevance.length) {
    actions.push({ label: "Review Pack Forge", screen: "pack-forge" });
  }

  if (state.reportCatalog.length) {
    actions.push({ label: "Open Report Center", screen: "report-center" });
  }
  if (state.mission.runs.length > 1) {
    actions.push({ label: "Compare Mission History", screen: "history" });
  }
  if (!actions.length) {
    actions.push({ label: "Return to Mission Control", screen: "mission-control" });
    actions.push({ label: "Open Explorer", screen: "explorer" });
  }
  return actions.slice(0, 3);
}

function renderScreens() {
  dom.screens.forEach((screen) => {
    screen.classList.toggle("active", screen.id === `screen-${state.activeScreen}`);
  });
  dom.screenLinks.forEach((button) => {
    button.classList.toggle("active", button.dataset.screen === state.activeScreen);
  });
  renderActiveScreen();
}

function renderActiveScreen() {
  const renderers = {
    wizard: wizardModule.renderWizard,
    "mission-control": missionModule.renderMissionControl,
    "surface-map": missionModule.renderSurfaceMap,
    "findings-theater": findingsModule.renderFindingsTheater,
    "evidence-replay": findingsModule.renderEvidenceReplay,
    "pack-forge": packsModule.renderPackForge,
    "report-center": reportsModule.renderReportCenter,
    explorer: explorerHistoryModule.renderExplorer,
    history: explorerHistoryModule.renderHistoryComparison,
  };
  (renderers[state.activeScreen] || wizardModule.renderWizard)();
}

function navigateToScreen(screen) {
  state.activeScreen = screen || "wizard";
  renderScreens();
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

function handleError(error) {
  pushStatus(error.message || "Unexpected UI error.", "error");
}
