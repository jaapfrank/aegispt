import { api, apiOrNull } from "./modules/api.js";
import { createExplorerHistoryModule } from "./modules/explorer-history.js";
import { createFindingsModule } from "./modules/findings.js";
import { createMissionModule } from "./modules/mission-control.js";
import { createPacksModule } from "./modules/packs.js";
import { createReportsModule } from "./modules/reports.js";
import { dom, runtime, setRefreshTimer, state, statusFeed } from "./modules/runtime.js";
import {
  countScopeTargets,
  emptyState,
  enabledModules,
  escapeHtml,
  executionPlanForProfile,
  heroChip,
  humanizeCheckMode,
  isSeedOnlyInventory,
  renderBadgeList,
  renderDisclosure,
  renderTargetSummary,
} from "./modules/shared.js";
import { createWizardModule, estimateMission } from "./modules/wizard.js";

let wizardModule;
let missionModule;
let findingsModule;
let packsModule;
let reportsModule;
let explorerHistoryModule;

const PHASE_DEFINITIONS = {
  intake: {
    label: "Intake",
    title: "Intake",
    eyebrow: "Define",
    description: "Define scope, access, safety, and confirm the run plan.",
  },
  execution: {
    label: "Run",
    title: "Execution",
    eyebrow: "Operate",
    description: "Monitor live run activity, progress, ETA, and pack state.",
  },
  analysis: {
    label: "Analysis",
    title: "Analysis",
    eyebrow: "Inspect",
    description: "Review findings, evidence, reports, history, and next steps.",
  },
};

const SCREEN_PHASE_MAP = {
  wizard: "intake",
  "mission-control": "execution",
  "surface-map": "execution",
  "pack-forge": "execution",
  "findings-theater": "analysis",
  "evidence-replay": "analysis",
  "report-center": "analysis",
  explorer: "analysis",
  history: "analysis",
};

const PHASE_SUBNAV = {
  intake: [
    { screen: "wizard", label: "Conversational Intake", testId: "nav-wizard" },
    { action: "open-advanced", label: "Advanced Settings", testId: "nav-advanced-settings" },
  ],
  execution: [
    { screen: "mission-control", label: "Mission Control", testId: "nav-mission-control" },
    { screen: "surface-map", label: "Surface / Attack Map", testId: "nav-surface-map" },
    { screen: "pack-forge", label: "Pack Status", testId: "nav-packs" },
  ],
  analysis: [
    { screen: "findings-theater", label: "Findings", testId: "nav-findings" },
    { screen: "evidence-replay", label: "Evidence", testId: "nav-evidence" },
    { screen: "report-center", label: "Reports", testId: "nav-reports" },
    { screen: "explorer", label: "Explorer", testId: "nav-explorer" },
    { screen: "history", label: "History / Comparison", testId: "nav-history" },
  ],
};

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
  dom.screens = Array.from(document.querySelectorAll(".screen"));
  dom.selectedEngagementSummary = document.getElementById("selected-engagement-summary");
  dom.phaseSubnav = document.getElementById("phase-subnav");
  dom.phaseSubnavTitle = document.getElementById("phase-subnav-title");
  dom.phaseFeedCard = document.getElementById("phase-feed-card");
  dom.phaseFeedTitle = document.getElementById("phase-feed-title");
  dom.phaseFeedKicker = document.getElementById("phase-feed-kicker");
  dom.statusFeed = document.getElementById("status-feed");
  dom.wizardStepper = document.getElementById("wizard-stepper");
  dom.wizardPanel = document.getElementById("wizard-panel");
  dom.wizardAdvancedDrawer = document.getElementById("wizard-advanced-drawer");
  dom.wizardSummary = document.getElementById("wizard-summary");
  dom.wizardErrors = document.getElementById("wizard-errors");
  dom.wizardBackBtn = document.getElementById("wizard-back-btn");
  dom.wizardNextBtn = document.getElementById("wizard-next-btn");
  dom.wizardConfirmBtn = document.getElementById("wizard-confirm-btn");
  dom.missionTimeline = document.getElementById("mission-timeline");
  dom.missionActivity = document.getElementById("mission-activity");
  dom.missionRunActivity = document.getElementById("mission-run-activity");
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
  dom.surfaceAssetBrowser = document.getElementById("surface-asset-browser");
  dom.surfaceAssetDetail = document.getElementById("surface-asset-detail");
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
  dom.codexSuggestions = document.getElementById("codex-suggestions");
  dom.codexPackPreview = document.getElementById("codex-pack-preview");
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
    inventorySnapshotForRun,
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
    selectedRunInventorySnapshot,
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
    state.selectedCodexTaskId = null;
    state.selectedCodexResult = null;
    state.selectedCodexContext = null;
    await refreshSelectedEngagement();
  });

  dom.refreshBtn.addEventListener("click", () => refreshSelectedEngagement().catch(handleError));

  document.body.addEventListener("click", (event) => {
    const target = event.target.closest("[data-nav-screen]");
    if (!target) return;
    event.preventDefault();
    navigateToScreen(target.dataset.navScreen);
  });

  document.body.addEventListener("click", (event) => {
    const target = event.target.closest("[data-phase-nav]");
    if (!target) return;
    event.preventDefault();
    navigateToPhase(target.dataset.phaseNav);
  });

  document.body.addEventListener("click", (event) => {
    const target = event.target.closest("[data-intake-advanced]");
    if (!target) return;
    event.preventDefault();
    state.wizard.intake.advancedOpen = true;
    navigateToPhase("intake", "wizard");
  });

  document.body.addEventListener("click", (event) => {
    const target = event.target.closest("[data-run-dispatch]");
    if (!target) return;
    event.preventDefault();
    missionModule.dispatchSelectedRun().catch(handleError);
  });

  document.body.addEventListener("click", (event) => {
    const target = event.target.closest("[data-follow-up-launch]");
    if (!target) return;
    event.preventDefault();
    missionModule.launchInventoryFollowUp(target.dataset.followUpLaunch).catch(handleError);
  });

  dom.wizardBackBtn.addEventListener("click", () => {
    state.wizard.errors = [];
    wizardModule.goBackConversation();
    scrollWizardIntoView();
  });

  dom.wizardNextBtn.addEventListener("click", () => {
    wizardModule.submitConversationAnswer().catch(handleError);
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
    window.clearTimeout(runtime.refreshTimer);
  }
  scheduleNextRefresh();
}

function activeRefreshIntervalMs() {
  if (!state.selectedEngagementId) return 20000;
  if (state.loading.dispatchRunId) return 2500;
  const tasks = state.selectedRun?.tasks || [];
  if (tasks.some((task) => ["queued", "running"].includes(String(task.status || "").toLowerCase()))) {
    return 5000;
  }
  return 20000;
}

function scheduleNextRefresh() {
  if (runtime.refreshTimer) {
    window.clearTimeout(runtime.refreshTimer);
  }
  const timer = window.setTimeout(async () => {
    try {
      if (state.selectedEngagementId) {
        await refreshSelectedEngagement();
      }
    } catch (error) {
      handleError(error);
    } finally {
      scheduleNextRefresh();
    }
  }, activeRefreshIntervalMs());
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
    state.selectedCodexTaskId = null;
    state.selectedCodexResult = null;
    state.selectedCodexContext = null;
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
    state.selectedSurfaceAssetKey = null;
    state.surfaceAssetFilter = "";
    state.reportCatalog = [];
    return;
  }

  state.reportPreview = "";
  state.reportHtml = "";
  state.loading.reportPreview = false;
  state.selectedSurfaceAssetKey = null;
  state.surfaceAssetFilter = "";
  state.selectedRun = await api(`/api/v1/runs/${state.selectedRunId}`);
  if (
    state.loading.dispatchRunId &&
    String(state.loading.dispatchRunId) === String(state.selectedRunId) &&
    String(state.selectedRun?.status || "").toLowerCase() !== "queued"
  ) {
    state.loading.dispatchRunId = null;
  }
  if (String(state.selectedRun?.status || "").toLowerCase() !== "queued") {
    delete state.dispatchHintsByRunId[String(state.selectedRunId)];
  }
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
    state.selectedCodexTaskId = null;
    state.selectedCodexResult = null;
    return;
  }
  state.selectedPackBundle = await api(`/api/v1/packs/${state.selectedPackId}/codex-review-bundle`);
  state.selectedCodexContext = state.selectedPackBundle.context;
  const relatedCodexTasks = state.codexTasks.filter(
    (task) => !task.source_context?.pack_id || String(task.source_context.pack_id) === String(state.selectedPackId)
  );
  if (!relatedCodexTasks.some((task) => task.id === state.selectedCodexTaskId)) {
    state.selectedCodexTaskId = relatedCodexTasks[0]?.id || null;
  }
  state.selectedCodexResult = state.selectedCodexTaskId
    ? await apiOrNull(`/api/v1/codex/tasks/${state.selectedCodexTaskId}/result`)
    : null;
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

function inventorySnapshotForRun(runId) {
  if (!runId) return latestInventorySnapshot();
  const normalizedRunId = String(runId);
  const run = state.mission.runs.find((item) => String(item.id) === normalizedRunId) || null;
  const derivedSnapshots = state.mission.inventory.filter(
    (snapshot) => String(snapshot.raw_inputs_json?.run_id || "") === normalizedRunId
  );
  if (derivedSnapshots.length) return aggregateInventorySnapshotsForUi(derivedSnapshots);
  if (run?.source_inventory_snapshot_id) {
    const sourceSnapshot = state.mission.inventory.find(
      (snapshot) => String(snapshot.id) === String(run.source_inventory_snapshot_id)
    );
    if (sourceSnapshot) return sourceSnapshot;
  }
  return latestInventorySnapshot();
}

function selectedRunInventorySnapshot() {
  return inventorySnapshotForRun(state.selectedRunId);
}

function aggregateInventorySnapshotsForUi(snapshots) {
  const snapshotList = Array.isArray(snapshots) ? snapshots.filter(Boolean) : [];
  if (!snapshotList.length) return null;
  if (snapshotList.length === 1) return snapshotList[0];

  const latest = snapshotList[0];
  const mergedHosts = [];
  const mergedServices = [];
  const mergedEndpoints = [];
  const mergedTechnologies = [];
  const mergedAuth = [];
  const mergedApis = [];
  const mergedFingerprints = [];
  const seenHosts = new Set();
  const seenServices = new Set();
  const seenEndpoints = new Set();
  const seenTechnologies = new Set();
  const seenAuth = new Set();
  const seenApis = new Set();
  const seenFingerprints = new Set();
  const tlsProtocols = new Set();
  const tlsIssues = new Set();
  let tlsSubject = null;
  let tlsSource = null;
  let tlsConfidence = 0;
  const environmentNotes = [];
  const assumptions = [];
  const sourceTools = [];
  const confidenceScores = [];

  snapshotList.forEach((snapshot) => {
    const normalized = snapshot.normalized_inventory_json || {};
    (snapshot.environment_notes_json || []).forEach((note) => {
      if (typeof note === "string" && note.trim() && !environmentNotes.includes(note)) environmentNotes.push(note);
    });
    (snapshot.assumptions_json || []).forEach((note) => {
      if (typeof note === "string" && note.trim() && !assumptions.includes(note)) assumptions.push(note);
    });
    (snapshot.source_tools_json || []).forEach((tool) => {
      if (typeof tool === "string" && tool.trim() && !sourceTools.includes(tool)) sourceTools.push(tool);
    });
    confidenceScores.push(Number(snapshot.confidence_score || normalized.confidence_score || 0));

    (normalized.hosts || []).forEach((host) => {
      const key = `${String(host.host || "").toLowerCase()}::${String(host.source || "").toLowerCase()}`;
      if (!host.host || seenHosts.has(key)) return;
      seenHosts.add(key);
      mergedHosts.push(host);
    });
    (normalized.services || []).forEach((service) => {
      const key = `${String(service.host || "").toLowerCase()}::${service.port || ""}::${String(service.service || "").toLowerCase()}`;
      if (!service.host || seenServices.has(key)) return;
      seenServices.add(key);
      mergedServices.push(service);
    });
    (normalized.http_endpoints || []).forEach((endpoint) => {
      const key = `${String(endpoint.url || "").toLowerCase()}::${String(endpoint.source || "").toLowerCase()}`;
      if (!endpoint.url || seenEndpoints.has(key)) return;
      seenEndpoints.add(key);
      mergedEndpoints.push(endpoint);
    });
    (normalized.technologies || []).forEach((tech) => {
      const key = `${String(tech.name || "").toLowerCase()}::${String(tech.vendor || "").toLowerCase()}::${String(tech.source || "").toLowerCase()}`;
      if (!tech.name || seenTechnologies.has(key)) return;
      seenTechnologies.add(key);
      mergedTechnologies.push(tech);
    });
    (normalized.auth_mechanisms || []).forEach((entry) => {
      const key = `${String(entry.type || "").toLowerCase()}::${String(entry.location || "").toLowerCase()}::${String(entry.source || "").toLowerCase()}`;
      if (!entry.type || seenAuth.has(key)) return;
      seenAuth.add(key);
      mergedAuth.push(entry);
    });
    (normalized.api_types || []).forEach((entry) => {
      const key = `${String(entry.type || "").toLowerCase()}::${String(entry.base_url || "").toLowerCase()}::${String(entry.source || "").toLowerCase()}`;
      if (!entry.type || seenApis.has(key)) return;
      seenApis.add(key);
      mergedApis.push(entry);
    });
    (normalized.vendor_product_fingerprints || []).forEach((entry) => {
      const key = `${String(entry.vendor || "").toLowerCase()}::${String(entry.product || "").toLowerCase()}::${String(entry.version || "").toLowerCase()}`;
      if (!entry.product || seenFingerprints.has(key)) return;
      seenFingerprints.add(key);
      mergedFingerprints.push(entry);
    });

    const tls = normalized.tls_posture || {};
    (tls.protocols || []).forEach((protocol) => {
      if (typeof protocol === "string" && protocol.trim()) tlsProtocols.add(protocol);
    });
    (tls.issues || []).forEach((issue) => {
      if (typeof issue === "string" && issue.trim()) tlsIssues.add(issue);
    });
    if (!tlsSubject && tls.certificate_subject) tlsSubject = tls.certificate_subject;
    if (!tlsSource && tls.source) tlsSource = tls.source;
    tlsConfidence = Math.max(tlsConfidence, Number(tls.confidence || 0));
  });

  const confidenceScore = confidenceScores.length
    ? confidenceScores.reduce((total, value) => total + value, 0) / confidenceScores.length
    : 0;
  const normalizedInventory = {
    hosts: mergedHosts,
    services: mergedServices,
    http_endpoints: mergedEndpoints,
    technologies: mergedTechnologies,
    auth_mechanisms: mergedAuth,
    api_types: mergedApis,
    tls_posture: {
      protocols: [...tlsProtocols],
      issues: [...tlsIssues],
      certificate_subject: tlsSubject,
      source: tlsSource,
      confidence: tlsConfidence,
    },
    vendor_product_fingerprints: mergedFingerprints,
    environment_notes: environmentNotes,
    assumptions,
    confidence_score: confidenceScore,
  };

  return {
    ...latest,
    raw_inputs_json: {
      ...(latest.raw_inputs_json || {}),
      aggregated_snapshot_count: snapshotList.length,
    },
    normalized_inventory_json: normalizedInventory,
    summary_json: {
      host_count: mergedHosts.length,
      service_count: mergedServices.length,
      endpoint_count: mergedEndpoints.length,
      technology_count: mergedTechnologies.length,
      auth_mechanism_count: mergedAuth.length,
      api_type_count: mergedApis.length,
      tls_issue_count: tlsIssues.size,
      detected_products: [...new Set(mergedFingerprints.map((entry) => entry.product).filter(Boolean))],
      detected_vendors: [...new Set(mergedFingerprints.map((entry) => entry.vendor).filter(Boolean))],
      confidence_score: confidenceScore,
    },
    source_tools_json: sourceTools,
    environment_notes_json: environmentNotes,
    assumptions_json: assumptions,
    confidence_score: confidenceScore,
  };
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
  syncActivePhase();
  renderHeader();
  renderFlowOverview();
  renderSelectedEngagementSummary();
  renderPhaseSubnav();
  renderPhaseFeedCard();
  renderStatus();
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

function isFirstRunStartState() {
  const history = state.wizard?.intake?.history || [];
  const hasOperatorAnswer = history.some((turn) => turn.role === "user");
  return !state.engagements.length && !state.selectedEngagementId && !state.selectedRun && !hasOperatorAnswer;
}

function renderSelectedEngagementSummary() {
  const engagement = selectedEngagement();
  const currentRun = state.selectedRun;
  const wizardData = state.wizard.data;
  const currentPhase = PHASE_DEFINITIONS[state.activePhase];
  const intakeFocus = isIntakeFocusMode();
  if (isFirstRunStartState()) {
    dom.selectedEngagementSummary.innerHTML = `
      <div class="context-summary-head">
        <div>
          <p class="eyebrow">Mission Context</p>
          <h3>Start your first mission</h3>
        </div>
        <span class="badge">${escapeHtml(currentPhase?.label || "Intake")}</span>
      </div>
      ${renderBadgeList([
        "No engagement yet",
        "Start: answer the intake question",
        "Then: confirm scope and safety",
        "Finish: create the mission",
      ], "compact-badge-list")}
      <p class="micro-copy context-summary-copy">${escapeHtml(
        "Start in Conversational Intake by answering the first question. AegisPT will keep execution, analysis, reports, and Surface Map locked until that mission is created."
      )}</p>
      <p class="micro-copy context-summary-copy">${escapeHtml(
        "Only the essentials stay expanded during intake; exact run, lane, and AI-planning details appear after the mission exists."
      )}</p>
      ${renderDisclosure({
        title: "What Happens Next",
        summary: "Mission creation unlocks run operations",
        open: false,
        testId: "persistent-context-secondary",
        body: `
          ${renderBadgeList([
            "1. Describe the target",
            "2. Confirm guardrails",
            "3. Create Mission & Open Mission Control",
          ], "compact-badge-list")}
          <p class="micro-copy split-top">${escapeHtml(
            "This first-run state is intentionally narrow: no run controls are active until the intake produces a real engagement and run dossier."
          )}</p>
        `,
      })}
    `;
    return;
  }
  const runConfig = currentRun?.configuration_json || wizardData;
  const estimate = currentRun
    ? {
        estimated_total_minutes: Number(currentRun.configuration_json?.eta?.estimated_total_minutes || 0),
        estimated_impact: String(currentRun.configuration_json?.eta?.estimated_impact || "not-set"),
        confidence: String(currentRun.configuration_json?.eta?.confidence || "not-set"),
      }
    : estimateMission(wizardData);
  const plan = executionPlanForProfile(
    currentRun?.profile?.name || estimate.execution_profile,
    state.runProfiles
  );
  const moduleLabels = enabledModules(runConfig.modules || {});
  const targetSummary = renderTargetSummary(runConfig.targets || {});
  const safetyLabel = humanizeCheckMode(runConfig.safety?.active_checks || "passive-only");
  const codexState = state.selectedPackBundle
    ? "Codex build lane linked"
    : state.mission.relevance.length
      ? "Adaptive planning ready"
      : "Deterministic baseline";
  const durationLabel = currentRun?.completed_at && currentRun?.created_at
    ? `${Math.max(1, Math.round((new Date(currentRun.completed_at) - new Date(currentRun.created_at)) / 60000))}m final`
    : `${estimate.estimated_total_minutes || "n/a"}m ETA`;
  const primaryBadges = [
    engagement?.client ? `Customer · ${engagement.client}` : "Customer · Not set",
    `Targets · ${targetSummary}`,
    `Profile · ${runConfig.test_profile || "Not configured"}`,
    `Safety · ${safetyLabel}`,
  ];
  const secondaryBadges = [
    currentRun ? `Run · ${currentRun.profile?.name || currentRun.status}` : "Run · Draft",
    `Modules · ${moduleLabels.length || 0}`,
    durationLabel,
    `AI · ${codexState}`,
    `Lane · ${plan.profileName}`,
  ];

  dom.selectedEngagementSummary.innerHTML = intakeFocus
    ? `
    <div class="context-summary-head">
      <div>
        <p class="eyebrow">Mission Context</p>
        <h3>${escapeHtml(engagement?.name || wizardData.engagement_name || "New mission draft")}</h3>
      </div>
      <span class="badge">${escapeHtml(currentPhase?.label || "Intake")}</span>
    </div>
    ${renderBadgeList(primaryBadges, "compact-badge-list")}
    <p class="micro-copy context-summary-copy">${escapeHtml(
      currentRun
        ? "Only the essentials stay expanded during intake. Open the secondary mission context when you need exact run, module, lane, or AI-planning detail."
        : "Only the essentials stay expanded during intake. Open the secondary mission context when you need exact lane, module, or AI-planning detail."
    )}</p>
    ${renderDisclosure({
      title: "More Mission Context",
      summary: `${secondaryBadges.length} additional mission details`,
      open: false,
      testId: "persistent-context-secondary",
      body: `
        ${renderBadgeList(secondaryBadges, "compact-badge-list")}
        <p class="micro-copy split-top">${escapeHtml(
          currentRun
            ? `${plan.profileName} is active for this mission. Detailed run state stays inside the current phase instead of repeating across the shell.`
            : "Draft scope, profile, and guardrails stay visible here while intake resolves the remaining items."
        )}</p>
      `,
    })}
  `
    : `
    <div class="context-summary-head">
      <div>
        <p class="eyebrow">Mission Context</p>
        <h3>${escapeHtml(engagement?.name || wizardData.engagement_name || "New mission draft")}</h3>
      </div>
      <span class="badge">${escapeHtml(currentPhase?.label || "Intake")}</span>
    </div>
    ${renderBadgeList([...primaryBadges, ...secondaryBadges], "compact-badge-list")}
    <p class="micro-copy context-summary-copy">${escapeHtml(
      currentRun
        ? `${plan.profileName} is active for this mission. Detailed run state stays inside the current phase instead of repeating across the shell.`
        : "Draft scope, profile, and guardrails stay visible here while intake resolves the remaining items."
    )}</p>
  `;
}

function renderStatus() {
  if (!dom.statusFeed) return;
  const latest = statusFeed[0] || null;
  const history = statusFeed.slice(1);
  if (state.activePhase === "intake") {
    dom.statusFeed.innerHTML = latest
      ? `
          <div class="feed-focus tone-${escapeHtml(String(latest?.tone || "info").toLowerCase())}" data-testid="status-feed-focus">
            <strong>${escapeHtml(latest?.timestamp || "Now")} · ${escapeHtml(latest?.tone || "info")}</strong>
            <p>${escapeHtml(latest?.message || "Waiting for the next operator event.")}</p>
          </div>
        `
      : emptyState("Signals appear once the mission is created or an operator action changes run state.");
    return;
  }
  dom.statusFeed.innerHTML = statusFeed.length
    ? `
        <div class="feed-focus tone-${escapeHtml(String(latest?.tone || "info").toLowerCase())}" data-testid="status-feed-focus">
          <strong>${escapeHtml(latest?.timestamp || "Now")} · ${escapeHtml(latest?.tone || "info")}${latest?.count > 1 ? ` · x${escapeHtml(String(latest.count))}` : ""}</strong>
          <p>${escapeHtml(latest?.message || "Waiting for the next operator event.")}</p>
        </div>
        ${
          history.length
            ? renderDisclosure({
                title: "Recent Feed History",
                summary: `${history.length} earlier update${history.length === 1 ? "" : "s"} remain available`,
                open: false,
                testId: "status-feed-history",
                body: history
                  .map(
                    (item) => `
                      <div class="feed-item tone-${escapeHtml(String(item.tone || "info").toLowerCase())}">
                        <strong>${escapeHtml(item.timestamp)} · ${escapeHtml(item.tone)}${item.count > 1 ? ` · x${escapeHtml(String(item.count))}` : ""}</strong>
                        <p>${escapeHtml(item.message)}</p>
                      </div>
                    `
                  )
                  .join(""),
              })
            : ""
        }
      `
    : emptyState("Wizard actions, pack promotion events, and report activity appear here.");
}

function renderFlowOverview() {
  const currentRun = state.selectedRun;
  const findings = selectedRunFindings();
  const inventorySnapshot = runtime.actions.selectedRunInventorySnapshot?.() || null;
  const intakeFocus = isIntakeFocusMode();
  const discoveryReady = Boolean(
    currentRun &&
      isDiscoveryOnlyRun(currentRun) &&
      inventorySnapshot &&
      !isSeedOnlyInventory(inventorySnapshot) &&
      Number(inventorySnapshot.summary_json?.host_count || 0) > 0
  );
  const phaseCards = [
    {
      id: "intake",
      label: "Intake",
      kicker: "1",
      kickerLabel: "Define",
      state: state.activePhase === "intake" ? "active" : currentRun ? "complete" : "active",
      active: state.activePhase === "intake",
      summary: intakeFocus
        ? currentRun
          ? "Scope locked"
          : "Scope, access, and guardrails"
        : currentRun
          ? "Scope and guardrails are already locked."
          : conversationalWizardProgress(),
      hint: "Define scope, access, safety, and review the run plan.",
    },
    {
      id: "execution",
      label: "Run",
      kicker: "2",
      kickerLabel: "Operate",
      state: state.activePhase === "execution" ? "active" : currentRun ? "complete" : "pending",
      active: state.activePhase === "execution",
      summary: intakeFocus
        ? currentRun
          ? "Run state ready"
          : ""
        : currentRun
          ? discoveryReady
            ? "Discovery inventory is ready for follow-up."
            : "Monitor live progress, ETA, and execution health."
          : "Mission Control becomes useful after a run exists.",
      hint: "Monitor live activity, progress, blockers, and the active pack lane.",
    },
    {
      id: "analysis",
      label: "Analysis",
      kicker: "3",
      kickerLabel: "Inspect",
      state: state.activePhase === "analysis" ? "active" : (findings.length || state.reportCatalog.length) ? "complete" : "pending",
      active: state.activePhase === "analysis",
      summary: intakeFocus
        ? currentRun
          ? "Review outputs"
          : ""
        : currentRun
          ? findings.length
            ? `${findings.length} findings are ready for review.`
            : "Review evidence, reports, explorer, and history after run output lands."
          : "Analysis views unlock as soon as a mission exists.",
      hint: "Inspect findings, evidence, reports, explorer, and run comparison.",
    },
  ];
  dom.flowOverview.innerHTML = phaseCards
    .map(
      (phase) => `
        <button
          class="flow-step ${phase.state} ${phase.active ? "nav-active" : ""} ${intakeFocus ? "focus-shell" : ""}"
          type="button"
          data-phase-nav="${escapeHtml(phase.id)}"
          data-testid="phase-nav-${escapeHtml(phase.id)}"
          title="${escapeHtml(phase.hint)}"
          aria-current="${phase.active ? "step" : "false"}"
        >
          <span class="flow-step-index">${escapeHtml(phase.kicker)}</span>
          <span class="flow-step-copy">
            <p class="eyebrow">${escapeHtml(phase.kickerLabel)}</p>
            <strong>${escapeHtml(phase.label)}</strong>
            <small>${escapeHtml(phase.summary)}</small>
          </span>
        </button>
      `
    )
    .join("");

  const nextActions = buildNextActions().filter((action) => action.phase ? action.phase === state.activePhase : true);
  dom.nextActions.innerHTML = nextActions.length
    ? nextActions
        .map(
          (action, index) => `
            <button
              class="action ${index === 0 ? "primary" : "ghost"}"
              type="button"
              ${
                action.action === "dispatch-run"
                  ? 'data-run-dispatch="selected"'
                  : action.action === "follow-up-launch"
                    ? `data-follow-up-launch="${escapeHtml(action.strategy)}"`
                    : action.action === "open-advanced"
                      ? 'data-intake-advanced="true"'
                    : `data-nav-screen="${escapeHtml(action.screen)}"`
              }
            >
              ${escapeHtml(action.label)}
            </button>
          `
        )
        .join("")
    : `<span class="context-note">Only the current phase actions are shown here.</span>`;
}

function conversationalWizardProgress() {
  const sources = state.wizard?.intake?.sources || {};
  const tracked = ["intent", "target_type", "goal", "scope", "auth", "safety", "boundaries"];
  const completed = tracked.filter((key) => {
    const value = sources[key];
    return value && value !== "still-needed";
  }).length;
  const remaining = tracked.length - completed;
  if (!completed) return "Waiting for the first mission answer";
  if (!remaining) return "Ready for confirmation";
  return `${completed} of ${tracked.length} intake topics resolved`;
}

function buildNextActions() {
  if (!state.selectedRun) {
    if (isFirstRunStartState()) {
      return [
        { label: "Start Mission Intake", screen: "wizard", phase: "intake" },
        { label: "Open Advanced Settings", action: "open-advanced", phase: "intake" },
      ];
    }
    return [
      { label: "Stay in Intake", screen: "wizard", phase: "intake" },
      { label: "Open Advanced Settings", action: "open-advanced", phase: "intake" },
    ];
  }

  const findings = selectedRunFindings();
  const inventorySnapshot = runtime.actions.selectedRunInventorySnapshot?.() || null;
  const discoveryReady = Boolean(
    state.selectedRun &&
      isDiscoveryOnlyRun(state.selectedRun) &&
      inventorySnapshot &&
      !isSeedOnlyInventory(inventorySnapshot) &&
      Number(inventorySnapshot.summary_json?.host_count || 0) > 0
  );
  const phases = missionModule.buildMissionPhases();
  const blocked = phases.find((phase) => phase.status === "blocked");
  const actions = [];

  if (blocked) {
    actions.push({ label: "Review Mission Control", screen: "mission-control", phase: "execution" });
  }
  const suppressDispatchShortcut =
    state.activePhase === "execution" &&
    state.activeScreen === "mission-control";
  if (missionModule.canDispatchSelectedRun() && !suppressDispatchShortcut) {
    actions.push({ label: "Start Validation", action: "dispatch-run", phase: "execution" });
  }
  if (discoveryReady && !findings.length) {
    actions.push({
      label: "Identify Discovered Services",
      action: "follow-up-launch",
      strategy: "service-enumeration",
      phase: "execution",
    });
    actions.push({ label: "Open Surface Map", screen: "surface-map", phase: "execution" });
    actions.push({ label: "Open Explorer", screen: "explorer", phase: "analysis" });
  }
  if (findings.length) {
    actions.push({ label: "Review Findings", screen: "findings-theater", phase: "analysis" });
    if (state.selectedFindingEvidence) {
      actions.push({ label: "Open Evidence Replay", screen: "evidence-replay", phase: "analysis" });
    }
  } else if (state.selectedPackBundle || state.mission.relevance.length) {
    actions.push({ label: "Review Pack Forge", screen: "pack-forge", phase: "execution" });
  }

  if (state.reportCatalog.length) {
    actions.push({ label: "Open Report Center", screen: "report-center", phase: "analysis" });
  }
  if (state.mission.runs.length > 1) {
    actions.push({ label: "Compare Mission History", screen: "history", phase: "analysis" });
  }
  if (!actions.length) {
    actions.push({ label: "Return to Mission Control", screen: "mission-control", phase: "execution" });
    actions.push({ label: "Open Explorer", screen: "explorer", phase: "analysis" });
  }
  return actions.slice(0, 2);
}

function isDiscoveryOnlyRun(run) {
  const profileName = String(run?.profile?.name || run?.configuration_json?.execution_profile || "").toLowerCase();
  const modules = run?.configuration_json?.modules || {};
  const enabledModuleKeys = Object.entries(modules)
    .filter(([, enabled]) => Boolean(enabled))
    .map(([key]) => key);
  return profileName === "passive-network-discovery" ||
    (enabledModuleKeys.length === 1 && enabledModuleKeys[0] === "discovery");
}

function renderScreens() {
  dom.screens.forEach((screen) => {
    screen.classList.toggle("active", screen.id === `screen-${state.activeScreen}`);
  });
  document.body.dataset.phase = state.activePhase;
  document.body.dataset.phaseLayout = isIntakeFocusMode() ? "focus" : "standard";
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
  state.activePhase = phaseForScreen(state.activeScreen);
  renderAll();
  if (window.innerWidth <= 1400) {
    const activeScreen = document.getElementById(`screen-${state.activeScreen}`);
    activeScreen?.scrollIntoView({ behavior: "smooth", block: "start" });
  }
}

function navigateToPhase(phase, preferredScreen = null) {
  const normalizedPhase = PHASE_DEFINITIONS[phase] ? phase : "intake";
  state.activePhase = normalizedPhase;
  const targetScreen =
    preferredScreen && phaseForScreen(preferredScreen) === normalizedPhase
      ? preferredScreen
      : phaseScreens(normalizedPhase).includes(state.activeScreen)
        ? state.activeScreen
        : defaultScreenForPhase(normalizedPhase);
  navigateToScreen(targetScreen);
}

function renderPhaseSubnav() {
  if (!dom.phaseSubnav || !dom.phaseSubnavTitle) return;
  const phase = PHASE_DEFINITIONS[state.activePhase];
  dom.phaseSubnavTitle.textContent = phase?.title || "Intake";
  dom.phaseSubnav.innerHTML = (PHASE_SUBNAV[state.activePhase] || [])
    .map((item) => {
      const active =
        item.action === "open-advanced"
          ? state.activeScreen === "wizard" && state.wizard.intake.advancedOpen
          : item.screen === state.activeScreen;
      if (item.action === "open-advanced") {
        return `<button class="screen-link ${active ? "active" : ""}" data-intake-advanced="true" data-testid="${escapeHtml(item.testId)}" type="button">${escapeHtml(item.label)}</button>`;
      }
      return `<button class="screen-link ${active ? "active" : ""}" data-screen="${escapeHtml(item.screen)}" data-nav-screen="${escapeHtml(item.screen)}" data-testid="${escapeHtml(item.testId)}" type="button">${escapeHtml(item.label)}</button>`;
    })
    .join("");
}

function renderPhaseFeedCard() {
  if (!dom.phaseFeedCard || !dom.phaseFeedTitle || !dom.phaseFeedKicker) return;
  const hideFeed = state.activePhase !== "execution";
  dom.phaseFeedCard.classList.toggle("hidden", hideFeed);
  dom.phaseFeedTitle.textContent = state.activePhase === "analysis" ? "Event History" : "Recent Signals";
  dom.phaseFeedKicker.textContent = state.activePhase === "analysis" ? "Context" : "Activity";
}

function syncActivePhase() {
  state.activePhase = phaseForScreen(state.activeScreen);
}

function phaseForScreen(screen) {
  return SCREEN_PHASE_MAP[screen] || "intake";
}

function phaseScreens(phase) {
  return Object.entries(SCREEN_PHASE_MAP)
    .filter(([, value]) => value === phase)
    .map(([screen]) => screen);
}

function defaultScreenForPhase(phase) {
  if (phase === "execution") return "mission-control";
  if (phase === "analysis") {
    return state.selectedFindingTheater || selectedRunFindings().length ? "findings-theater" : "report-center";
  }
  return "wizard";
}

function isIntakeFocusMode() {
  return state.activePhase === "intake";
}

function scrollWizardIntoView() {
  if (window.innerWidth > 1400) return;
  const wizardScreen = document.getElementById("screen-wizard");
  wizardScreen?.scrollIntoView({ behavior: "smooth", block: "start" });
}

function pushStatus(message, tone = "info") {
  const newest = statusFeed[0];
  if (newest && newest.message === message && newest.tone === tone) {
    newest.count = (newest.count || 1) + 1;
    newest.timestamp = new Date().toLocaleTimeString();
    renderStatus();
    return;
  }
  statusFeed.unshift({
    message,
    tone,
    timestamp: new Date().toLocaleTimeString(),
    count: 1,
  });
  while (statusFeed.length > 10) statusFeed.pop();
  renderStatus();
}

function handleError(error) {
  const message = String(error?.message || "Unexpected UI error.");
  const humanized = /failed to fetch|networkerror/i.test(message)
    ? "UI could not reach the API. Refresh the page or confirm the service is still running."
    : message;
  pushStatus(humanized, "error");
}
