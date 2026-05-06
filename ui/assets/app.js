import { api, apiOrNull } from "./modules/api.js";
import { openCinemaMode } from "./modules/cinema.js?v=20260502-a11y-gate-1";
import { createCustomVulnerabilitiesModule } from "./modules/custom-vulnerabilities.js";
import { createDashboardModule } from "./modules/dashboard.js";
import { createExplorerHistoryModule } from "./modules/explorer-history.js?v=20260506-kill-chain-1";
import { createFindingsModule } from "./modules/findings.js?v=20260429-auto-enrichment-1";
import { createMissionModule } from "./modules/mission-control.js?v=20260506-mission-empty-state-1";
import { createPacksModule } from "./modules/packs.js";
import { createProblemsModule } from "./modules/problems.js";
import { createResearchModule } from "./modules/research.js";
import { createReportsModule } from "./modules/reports.js";
import { createSettingsModule } from "./modules/settings.js?v=20260506-settings-tabs-1";
import {
  buildEmptyOnboardingState,
  buildEmptyWizardState,
  dom,
  patchState,
  runtime,
  setRefreshTimer,
  state,
  statusFeed,
} from "./modules/runtime.js";
import {
  emptyState,
  enabledModules,
  escapeHtml,
  exposureScoreTone,
  exposureTrendLabel,
  formatDateTime,
  executionPlanForProfile,
  formatExposureScore,
  humanizeCheckMode,
  isLikelyCidr,
  isSeedOnlyInventory,
  renderExposureSparkline,
  renderBadgeList,
  renderDisclosure,
  renderTargetSummary,
  statusPill,
} from "./modules/shared.js";
import { createWizardModule, estimateMission } from "./modules/wizard.js?v=20260506-multitile-target-1";

let wizardModule;
let dashboardModule;
let customVulnerabilitiesModule;
let missionModule;
let findingsModule;
let packsModule;
let problemsModule;
let researchModule;
let reportsModule;
let explorerHistoryModule;
let settingsModule;
let deleteModalPreviousFocus = null;

const FOCUSABLE_SELECTOR = [
  "a[href]",
  "button:not([disabled])",
  "input:not([disabled])",
  "select:not([disabled])",
  "textarea:not([disabled])",
  "summary",
  "[tabindex]:not([tabindex='-1'])",
].join(",");

const PHASE_DEFINITIONS = {
  home: {
    label: "Home",
    title: "Dashboard",
    eyebrow: "Command",
    description: "See the active mission, open problems, schedule, recent activity, and setup state.",
  },
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
    description: "Review findings with evidence, reports with dossier context, history, and next steps.",
  },
  settings: {
    label: "Settings",
    title: "Settings",
    eyebrow: "Configure",
    description: "Tune instance defaults, provider state, integrations, notifications, and shell identity.",
  },
};

const SCREEN_PHASE_MAP = {
  dashboard: "home",
  wizard: "intake",
  "mission-control": "execution",
  agents: "execution",
  "surface-map": "execution",
  "pack-forge": "execution",
  research: "execution",
  "problems-center": "analysis",
  "custom-vulnerabilities": "analysis",
  "findings-theater": "analysis",
  "evidence-replay": "analysis",
  "report-center": "analysis",
  explorer: "analysis",
  history: "analysis",
  settings: "settings",
};

const RUN_STREAM_ACTIVE_STATUSES = new Set(["queued", "running"]);
const RUN_STREAM_TERMINAL_STATUSES = new Set([
  "completed",
  "completed_with_errors",
  "failed",
  "cancelled",
  "rejected",
]);
const TASK_STDOUT_SCREENS = new Set(["mission-control", "agents"]);
const TASK_STDOUT_POLL_INTERVAL_MS = 3000;

const NAV_GROUPS = [
  { kind: "section", label: "Home" },
  { screen: "dashboard", label: "Dashboard", icon: "◆", testId: "nav-dashboard" },
  { kind: "section", label: "Operate" },
  { screen: "wizard", label: "Intake", icon: "⬡", testId: "nav-wizard" },
  { screen: "mission-control", label: "Mission Control", icon: "◈", testId: "nav-mission-control" },
  { screen: "surface-map", label: "Attack Map", icon: "◉", testId: "nav-attack-map" },
  { kind: "section", label: "Analyze" },
  { screen: "problems-center", label: "Problems", icon: "!", testId: "nav-problems" },
  { screen: "custom-vulnerabilities", label: "Custom CVE Library", icon: "✦", testId: "nav-custom-vulnerabilities" },
  { screen: "findings-theater", label: "Findings", icon: "⚠", testId: "nav-findings", count: "findings" },
  { screen: "report-center", label: "Reports", icon: "☰", testId: "nav-reports" },
  { screen: "history", label: "History", icon: "⊡", testId: "nav-history" },
  { kind: "section", label: "Build" },
  { screen: "research", label: "Research", icon: "✧", testId: "nav-research" },
  { screen: "pack-forge", label: "Packs", icon: "⬖", testId: "nav-packs" },
  { screen: "evidence-replay", label: "Evidence Replay", icon: "▣", testId: "nav-evidence-replay", utility: true },
  { screen: "explorer", label: "Explorer", icon: "⌕", testId: "nav-explorer", utility: true },
  { kind: "spacer" },
  { screen: "settings", label: "Settings", icon: "⚙", testId: "nav-settings", utility: true },
];

document.addEventListener("DOMContentLoaded", () => {
  bindDom();
  initializeModules();
  bindRuntimeActions();
  bindGlobalEvents();
  boot().catch(handleError);
});

function initializeModules() {
  wizardModule = createWizardModule();
  dashboardModule = createDashboardModule();
  customVulnerabilitiesModule = createCustomVulnerabilitiesModule();
  missionModule = createMissionModule();
  findingsModule = createFindingsModule();
  packsModule = createPacksModule();
  problemsModule = createProblemsModule();
  researchModule = createResearchModule();
  reportsModule = createReportsModule();
  explorerHistoryModule = createExplorerHistoryModule();
  settingsModule = createSettingsModule();
}

function bindDom() {
  dom.actorDisplay = document.getElementById("actor-display");
  dom.topbarAvatarMark = document.getElementById("topbar-avatar-mark");
  dom.actorRoleBadge = document.getElementById("actor-role-badge");
  dom.sidebarMetrics = document.getElementById("sidebar-metrics");
  dom.topbarRunStatus = document.getElementById("topbar-run-status");
  dom.topbarNav = document.getElementById("topbar-nav");
  dom.topbarPhaseIndicator = document.getElementById("topbar-phase-indicator");
  dom.topbarEngagementContext = document.getElementById("topbar-engagement-context");
  dom.sidebarNewMissionBtn = document.getElementById("sidebar-new-mission-btn");
  dom.sidebarNav = document.getElementById("sidebar-nav");
  dom.sidebarCompatibilityNav = document.getElementById("sidebar-compatibility-nav");
  dom.nextActions = document.getElementById("next-actions");
  dom.engagementSelect = document.getElementById("engagement-select");
  dom.manageEngagementsBtn = document.getElementById("manage-engagements-btn");
  dom.refreshBtn = document.getElementById("refresh-btn");
  dom.screens = Array.from(document.querySelectorAll(".screen"));
  dom.selectedEngagementSummary = document.getElementById("selected-engagement-summary");
  dom.dashboardContent = document.getElementById("dashboard-content");
  dom.phaseSubnav = document.getElementById("phase-subnav");
  dom.phaseSubnavTitle = document.getElementById("phase-subnav-title");
  dom.phaseFeedCard = document.getElementById("phase-feed-card");
  dom.phaseFeedTitle = document.getElementById("phase-feed-title");
  dom.phaseFeedKicker = document.getElementById("phase-feed-kicker");
  dom.statusFeed = document.getElementById("status-feed");
  dom.wizardStepper = document.getElementById("wizard-stepper");
  dom.wizardPanel = document.getElementById("wizard-panel");
  dom.wizardOnboardingChecklist = document.getElementById("wizard-onboarding-checklist");
  dom.wizardAdvancedDrawer = document.getElementById("wizard-advanced-drawer");
  dom.wizardSummary = document.getElementById("wizard-summary");
  dom.wizardErrors = document.getElementById("wizard-errors");
  dom.wizardBackBtn = document.getElementById("wizard-back-btn");
  dom.wizardNextBtn = document.getElementById("wizard-next-btn");
  dom.wizardConfirmBtn = document.getElementById("wizard-confirm-btn");
  dom.missionDispatchBtn = document.getElementById("mission-dispatch-btn");
  dom.cinemaModeBtn = document.getElementById("cinema-mode-btn");
  dom.missionKillRunBtn = document.getElementById("mission-kill-run-btn");
  dom.missionTimeline = document.getElementById("mission-timeline");
  dom.missionActivity = document.getElementById("mission-activity");
  dom.missionOnboardingChecklist = document.getElementById("mission-onboarding-checklist");
  dom.missionRunActivity = document.getElementById("mission-run-activity");
  dom.missionGood = document.getElementById("mission-good");
  dom.missionBad = document.getElementById("mission-bad");
  dom.missionUnknown = document.getElementById("mission-unknown");
  dom.missionEta = document.getElementById("mission-eta");
  dom.missionFindingsPulse = document.getElementById("mission-findings-pulse");
  dom.missionExposureScore = document.getElementById("mission-exposure-score");
  dom.agentsContent = document.getElementById("agents-content");
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
  dom.remediationPortfolio = document.getElementById("remediation-portfolio");
  dom.findingsGroupList = document.getElementById("findings-group-list");
  dom.findingTheaterDetail = document.getElementById("finding-theater-detail");
  dom.problemsContent = document.getElementById("problems-content");
  dom.customVulnerabilitiesContent = document.getElementById("custom-vulnerabilities-content");
  dom.researchContent = document.getElementById("research-content");
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
  dom.toolLibrary = document.getElementById("tool-library");
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
  dom.reportCenterTabs = document.getElementById("report-center-tabs");
  dom.reportCenterReportsView = document.getElementById("report-center-reports-view");
  dom.reportCenterDossierView = document.getElementById("report-center-dossier-view");
  dom.reportDossierContext = document.getElementById("report-dossier-context");
  dom.reportDossierDetail = document.getElementById("report-dossier-detail");
  dom.customerIndex = document.getElementById("customer-index");
  dom.engagementDossiers = document.getElementById("engagement-dossiers");
  dom.runDossier = document.getElementById("run-dossier");
  dom.historyToolbar = document.getElementById("history-toolbar");
  dom.comparisonSummary = document.getElementById("comparison-summary");
  dom.historyTrend = document.getElementById("history-trend");
  dom.nextStepsQueue = document.getElementById("next-steps-queue");
  dom.settingsContent = document.getElementById("settings-content");
  dom.onboardingOverlayRoot = document.getElementById("onboarding-overlay-root");
  dom.deleteModalRoot = document.getElementById("delete-modal-root");
}

function bindRuntimeActions() {
  Object.assign(runtime.actions, {
    compareRuns: explorerHistoryModule.compareRuns,
    engagementFindings,
    handleError,
    inventorySnapshotForRun,
    latestInventorySnapshot,
    latestRelevanceDecision,
    loadDashboard: dashboardModule.loadDashboard,
    loadProblems: problemsModule.loadProblems,
    loadResearchLab: researchModule.loadResearchLab,
    ensureComparisonFindings,
    loadFindingsForRun,
    loadSelectedFinding,
    loadSelectedPack,
    loadSelectedRun,
    loadSelectedTask,
    navigateToScreen,
    openEngagementCleanup,
    openEngagementDeletePreview,
    openRunDeletePreview,
    pushStatus,
    refreshSelectedEngagement,
    refreshShell,
    renderAll,
    cancelSelectedRun,
    loadCustomVulnerabilities: customVulnerabilitiesModule.loadCustomVulnerabilities,
    renderCustomVulnerabilityLibrary: customVulnerabilitiesModule.renderCustomVulnerabilityLibrary,
    renderDashboard: dashboardModule.renderDashboard,
    renderProblemsCenter: problemsModule.renderProblemsCenter,
    renderResearchLab: researchModule.renderResearchLab,
    renderFlowOverview,
    renderMissionControl: missionModule.renderMissionControl,
    renderReportCenter: reportsModule.renderReportCenter,
    renderSettingsScreen: settingsModule.renderSettingsScreen,
    renderScreens,
    selectedEngagement,
    selectedPack,
    selectedRunAttackPathSummary,
    selectedRunFindings,
    selectedRunInventorySnapshot,
    syncTaskStdoutEventStream,
    toggleEngagementDeleteSelection,
    toggleRunDeleteSelection,
  });
}

function syncActorDisplay() {
  const actorName = String(state.actor || state.currentActor?.actor_name || "operator-ui").trim() || "operator-ui";
  if (dom.actorDisplay) {
    dom.actorDisplay.textContent = actorName;
    dom.actorDisplay.title = `Current operator: ${actorName}`;
  }
  if (dom.topbarAvatarMark) {
    dom.topbarAvatarMark.textContent = actorName.slice(0, 1).toUpperCase() || "O";
    dom.topbarAvatarMark.title = actorName;
  }
}

function bindGlobalEvents() {
  syncActorDisplay();

  dom.engagementSelect.addEventListener("change", async (event) => {
    state.selectedEngagementId = event.target.value || null;
    state.selectedRunId = null;
    state.selectedPackId = null;
    state.selectedFindingId = null;
    state.selectedTaskId = null;
    state.selectedCodexTaskId = null;
    state.selectedCodexResult = null;
    state.selectedCodexContext = null;
    state.chatgptOAuthStatus = null;
    state.diagnostics = null;
    state.diagnosticsLoading = false;
    state.diagnosticsBundleLoading = false;
    state.diagnosticsError = null;
    state.cicdTriggerSettings = null;
    state.cicdTriggerLoading = false;
    state.cicdTriggerSavingSource = null;
    state.cicdTriggerError = null;
    state.siemIntegrationSettings = null;
    state.siemIntegrationLoading = false;
    state.siemIntegrationSavingProvider = null;
    state.siemIntegrationError = null;
    state.jiraIntegrationConfiguration = null;
    state.jiraIntegrationLoadedEngagementId = null;
    state.jiraIntegrationLoading = false;
    state.jiraIntegrationSaving = false;
    state.jiraIntegrationTesting = false;
    state.jiraIntegrationTestResult = null;
    state.jiraIntegrationError = null;
    state.jiraFindingLinks = {};
    state.threatIntelStatus = null;
    state.threatIntelWatchlist = [];
    state.threatIntelRecords = [];
    state.threatIntelTemplateGeneratingId = null;
    state.threatIntelTemplateResult = null;
    state.threatIntelLoading = false;
    state.threatIntelSyncing = false;
    state.threatIntelError = null;
    state.researchLab = null;
    state.researchLoading = false;
    state.researchError = null;
    state.researchCveGeneratingId = null;
    state.researchIdeaGenerating = false;
    state.researchGenerationResult = null;
    state.customVulnerabilities = [];
    state.customVulnerabilityScanOptions = [];
    state.customVulnError = null;
    state.customVulnImportResult = null;
    state.customVulnExport = "";
    state.customVulnSelectedId = null;
    await refreshSelectedEngagement();
    if (state.activeScreen === "settings") {
      await Promise.allSettled([
        settingsModule.loadChatGPTStatus(),
        settingsModule.loadDiagnostics(),
        settingsModule.loadSettingsReadiness(),
        settingsModule.loadEnterpriseIdentityStatus(),
        settingsModule.loadCicdTriggerSettings(),
        settingsModule.loadJiraIntegrationSettings(),
        settingsModule.loadSiemIntegrationSettings(),
        settingsModule.loadThreatIntelControls(),
      ]);
      renderAll();
    }
  });

  dom.refreshBtn?.addEventListener("click", () => refreshSelectedEngagement().catch(handleError));
  dom.manageEngagementsBtn?.addEventListener("click", () => openEngagementCleanup());
  dom.cinemaModeBtn?.addEventListener("click", () => openCinemaMode());

  document.addEventListener("keydown", (event) => {
    if (
      event.key.toLowerCase() !== "f" ||
      event.altKey ||
      event.ctrlKey ||
      event.metaKey ||
      isEditableKeyboardTarget(event.target) ||
      state.activeScreen !== "mission-control" ||
      document.getElementById("cinema-overlay")
    ) {
      return;
    }
    event.preventDefault();
    openCinemaMode();
  });

  document.addEventListener("keydown", (event) => {
    const dialog = dom.deleteModalRoot?.querySelector(".delete-modal");
    if (!dialog) return;
    if (event.key === "Escape") {
      event.preventDefault();
      closeDeleteModal();
      return;
    }
    if (event.key === "Tab") {
      trapFocusWithin(dialog, event);
    }
  });

  document.body.addEventListener("click", (event) => {
    const target = event.target.closest("[data-run-cancel-selected]");
    if (!target) return;
    event.preventDefault();
    cancelSelectedRun().catch(handleError);
  });

  document.body.addEventListener("click", (event) => {
    const target = event.target.closest("[data-agent-task-pick]");
    if (!target) return;
    event.preventDefault();
    patchState({ selectedTaskId: target.dataset.agentTaskPick || null }, "agents.task.select");
    loadSelectedTask()
      .then(() => renderAll())
      .catch(handleError);
  });

  document.body.addEventListener("click", (event) => {
    const target = event.target.closest("[data-nav-screen]");
    if (!target) return;
    event.preventDefault();
    if (target.dataset.navScreen === "report-center") {
      state.reportCenterView = "reports";
    }
    navigateToScreen(target.dataset.navScreen);
  });

  document.body.addEventListener("click", (event) => {
    const target = event.target.closest("[data-dashboard-engagement-id]");
    if (!target) return;
    event.preventDefault();
    state.selectedEngagementId = target.dataset.dashboardEngagementId || state.selectedEngagementId;
    state.selectedRunId = null;
    refreshSelectedEngagement()
      .then(() => navigateToScreen("mission-control"))
      .catch(handleError);
  });

  document.body.addEventListener("click", (event) => {
    const target = event.target.closest("[data-dashboard-dismiss-checklist]");
    if (!target) return;
    event.preventDefault();
    dashboardModule.dismissSetupChecklist().catch(handleError);
  });

  document.body.addEventListener("click", (event) => {
    const target = event.target.closest("[data-report-center-view]");
    if (!target) return;
    event.preventDefault();
    state.reportCenterView = target.dataset.reportCenterView || "reports";
    if (state.activeScreen !== "report-center") {
      navigateToScreen("report-center");
      return;
    }
    renderAll();
  });

  document.body.addEventListener("click", (event) => {
    const target = event.target.closest("[data-intake-advanced]");
    if (!target) return;
    event.preventDefault();
    patchState(
      { wizard: { ...state.wizard, intake: { ...state.wizard.intake, advancedOpen: true } } },
      "wizard.intake.openAdvancedFromShell"
    );
    navigateToScreen("wizard");
  });

  document.body.addEventListener("click", (event) => {
    const target = event.target.closest("[data-onboarding-rerun]");
    if (!target) return;
    event.preventDefault();
    openOnboarding({ forced: true });
  });

  document.body.addEventListener("click", (event) => {
    const target = event.target.closest("[data-onboarding-step]");
    if (!target) return;
    event.preventDefault();
    setOnboardingStep(Number(target.dataset.onboardingStep || 0));
  });

  document.body.addEventListener("click", (event) => {
    const target = event.target.closest("[data-onboarding-provider]");
    if (!target) return;
    event.preventDefault();
    setOnboardingValue("provider", target.dataset.onboardingProvider || "disabled");
  });

  document.body.addEventListener("click", (event) => {
    const target = event.target.closest("[data-onboarding-scope-preset]");
    if (!target) return;
    event.preventDefault();
    setOnboardingValue("defaultScope", target.dataset.onboardingScopePreset || "");
  });

  document.body.addEventListener("click", (event) => {
    const target = event.target.closest("[data-onboarding-dismiss]");
    if (!target) return;
    event.preventDefault();
    dismissOnboarding({ persistDraft: target.dataset.onboardingDismiss === "persist" }).catch(handleError);
  });

  document.body.addEventListener("click", (event) => {
    const target = event.target.closest("[data-onboarding-launch]");
    if (!target) return;
    event.preventDefault();
    completeOnboardingAndLaunchWizard().catch(handleError);
  });

  document.body.addEventListener("click", (event) => {
    const target = event.target.closest("[data-onboarding-connect-chatgpt]");
    if (!target) return;
    event.preventDefault();
    settingsModule.connectChatGPT().catch(handleError);
  });

  document.body.addEventListener("input", (event) => {
    const target = event.target;
    if (!(target instanceof HTMLInputElement)) return;
    if (target.matches("[data-onboarding-field='defaultScope']")) {
      setOnboardingValue("defaultScope", target.value);
      return;
    }
    if (target.matches("[data-onboarding-field='actorName']")) {
      setOnboardingValue("actorName", target.value);
    }
  });

  document.body.addEventListener("click", (event) => {
    const target = event.target.closest("[data-run-dispatch]");
    if (!target) return;
    event.preventDefault();
    missionModule.dispatchSelectedRun().catch(handleError);
  });

  document.body.addEventListener("click", (event) => {
    const target = event.target.closest("[data-run-approval-decision]");
    if (!target) return;
    event.preventDefault();
    missionModule.recordRunApprovalDecision({
      runId: target.dataset.runApprovalRunId || state.selectedRunId,
      stepId: target.dataset.runApprovalStepId || state.selectedRun?.approval_step_id || "run.launch",
      decision: target.dataset.runApprovalDecision || null,
    }).catch(handleError);
  });

  document.body.addEventListener("click", (event) => {
    const target = event.target.closest("[data-focus-actor-settings]");
    if (!target) return;
    event.preventDefault();
    missionModule.focusActorInputForApproval();
  });

  document.body.addEventListener("click", (event) => {
    const target = event.target.closest("[data-follow-up-launch]");
    if (!target) return;
    event.preventDefault();
    missionModule.launchInventoryFollowUp(target.dataset.followUpLaunch).catch(handleError);
  });

  document.body.addEventListener("click", (event) => {
    const control = event.target.closest("[data-run-delete-control]");
    if (control) {
      event.stopPropagation();
    }
  });

  document.body.addEventListener("change", (event) => {
    const target = event.target;
    if (!(target instanceof HTMLInputElement)) return;
    if (target.matches("[data-run-delete-toggle]")) {
      toggleRunDeleteSelection(target.dataset.runDeleteToggle, target.checked);
      return;
    }
    if (target.matches("[data-engagement-delete-toggle]")) {
      toggleEngagementDeleteSelection(target.dataset.engagementDeleteToggle, target.checked);
      return;
    }
    if (target.matches("[data-engagement-delete-select-all]")) {
      const checked = target.checked;
      patchState(
        {
          deleteUi: {
            ...state.deleteUi,
            selectedEngagementIds: checked ? state.engagements.map((engagement) => engagement.id) : [],
          },
        },
        "delete.engagement.selectAll"
      );
      renderDeletionUi();
    }
  });

  document.body.addEventListener("input", (event) => {
    const target = event.target;
    if (!(target instanceof HTMLInputElement)) return;
    if (target.matches("[data-delete-confirmation]")) {
      updateDeleteModal({ confirmation: target.value });
      return;
    }
    if (target.matches("[data-engagement-delete-confirmation]")) {
      const engagementId = target.dataset.engagementDeleteConfirmation;
      updateDeleteModal({
        confirmations: {
          ...(state.deleteUi.modal?.confirmations || {}),
          [engagementId]: target.value,
        },
      });
    }
  });

  document.body.addEventListener("click", (event) => {
    const target = event.target.closest("[data-delete-modal-close]");
    if (!target) return;
    event.preventDefault();
    closeDeleteModal();
  });

  document.body.addEventListener("click", (event) => {
    const target = event.target.closest("[data-run-delete-preview]");
    if (!target) return;
    event.preventDefault();
    const runIds = target.dataset.runDeletePreview === "selected"
      ? state.deleteUi.selectedRunIds
      : [target.dataset.runDeletePreview].filter(Boolean);
    openRunDeletePreview(runIds).catch(handleError);
  });

  document.body.addEventListener("click", (event) => {
    const target = event.target.closest("[data-run-delete-confirm]");
    if (!target) return;
    event.preventDefault();
    confirmRunDelete().catch(handleError);
  });

  document.body.addEventListener("click", (event) => {
    const target = event.target.closest("[data-engagement-delete-preview]");
    if (!target) return;
    event.preventDefault();
    const engagementIds = target.dataset.engagementDeletePreview === "selected"
      ? state.deleteUi.selectedEngagementIds
      : [target.dataset.engagementDeletePreview].filter(Boolean);
    openEngagementDeletePreview(engagementIds).catch(handleError);
  });

  document.body.addEventListener("click", (event) => {
    const target = event.target.closest("[data-engagement-delete-confirm]");
    if (!target) return;
    event.preventDefault();
    confirmEngagementDelete().catch(handleError);
  });

  dom.wizardBackBtn.addEventListener("click", () => {
    patchState({ wizard: { ...state.wizard, errors: [] } }, "wizard.back.clearErrors");
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

function isEditableKeyboardTarget(target) {
  if (!(target instanceof Element)) return false;
  const tagName = target.tagName.toLowerCase();
  return ["input", "textarea", "select"].includes(tagName) || target.isContentEditable;
}

function focusableElements(root) {
  if (!root) return [];
  return Array.from(root.querySelectorAll(FOCUSABLE_SELECTOR)).filter((element) => {
    if (!(element instanceof HTMLElement)) return false;
    if (element.getAttribute("aria-hidden") === "true") return false;
    const style = window.getComputedStyle(element);
    return style.display !== "none" && style.visibility !== "hidden";
  });
}

function trapFocusWithin(root, event) {
  const focusable = focusableElements(root);
  if (!focusable.length) {
    event.preventDefault();
    root.focus?.();
    return;
  }
  const first = focusable[0];
  const last = focusable[focusable.length - 1];
  if (event.shiftKey && document.activeElement === first) {
    event.preventDefault();
    last.focus();
  } else if (!event.shiftKey && document.activeElement === last) {
    event.preventDefault();
    first.focus();
  }
}

function activeScreenElement() {
  return document.getElementById(`screen-${state.activeScreen}`);
}

function isEditableElement(element) {
  if (!element) return false;
  const tagName = String(element.tagName || "").toLowerCase();
  return Boolean(
    element.isContentEditable ||
      ["input", "select", "textarea"].includes(tagName) ||
      element.closest?.("[contenteditable='true']")
  );
}

function selectionTouchesActiveScreen(selection) {
  if (!selection || selection.isCollapsed || !selection.rangeCount) return false;
  const screen = activeScreenElement();
  if (!screen) return false;
  for (let index = 0; index < selection.rangeCount; index += 1) {
    const range = selection.getRangeAt(index);
    const node =
      range.commonAncestorContainer.nodeType === Node.ELEMENT_NODE
        ? range.commonAncestorContainer
        : range.commonAncestorContainer.parentElement;
    if (node && screen.contains(node)) {
      return true;
    }
  }
  return false;
}

function operatorHasActiveTextInteraction() {
  if (state.activeScreen !== "mission-control") return false;
  const screen = activeScreenElement();
  const activeElement = document.activeElement;
  if (screen && activeElement && screen.contains(activeElement) && isEditableElement(activeElement)) {
    return true;
  }
  const selection = window.getSelection?.();
  return Boolean(selection?.toString().trim() && selectionTouchesActiveScreen(selection));
}

function shouldDeferBackgroundScreenRender(options = {}) {
  return Boolean(options.background) && operatorHasActiveTextInteraction();
}

function renderBackgroundUpdate(options = {}) {
  renderAll({ renderScreen: true, background: true, ...options });
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
        await refreshSelectedEngagement({
          renderScreen: shouldRenderActiveScreenDuringBackgroundRefresh(),
          background: true,
        });
      }
    } catch (error) {
      handleError(error);
    } finally {
      scheduleNextRefresh();
    }
  }, activeRefreshIntervalMs());
  setRefreshTimer(timer);
}

function dashboardApiPath() {
  return state.selectedEngagementId
    ? `/api/v1/dashboard?engagement_id=${encodeURIComponent(state.selectedEngagementId)}`
    : "/api/v1/dashboard";
}

function actorNameFromSettings(payload = state.operatorSettings) {
  const sections = Array.isArray(payload?.sections) ? payload.sections : [];
  for (const section of sections) {
    const settings = Array.isArray(section?.settings) ? section.settings : [];
    const match = settings.find((setting) => String(setting?.key || "") === "instance.operator_display_name");
    const value = String(match?.value || "").trim();
    if (value) return value;
  }
  return "";
}

function applyActorIdentity(actorName, currentActor = null) {
  const normalized = String(actorName || "").trim() || "operator-ui";
  state.actor = normalized;
  state.currentActor = {
    ...(currentActor || state.currentActor || {}),
    actor_name: normalized,
    role: String(currentActor?.role || state.currentActor?.role || "admin").trim().toLowerCase() || "admin",
    auth_method: currentActor?.auth_method || state.currentActor?.auth_method || "x_actor_fallback",
  };
  window.localStorage.setItem("aegispt-actor", normalized);
  syncActorDisplay();
}

async function refreshShell() {
  state.dashboardLoading = true;
  const [engagements, runProfiles, codexTasks, scenarios, operatorSettings, dashboard, currentActor] = await Promise.all([
    api("/api/v1/engagements"),
    api("/api/v1/run-profiles"),
    api("/api/v1/codex/tasks"),
    api("/api/v1/internal-validations/scenarios"),
    api("/api/v1/settings"),
    api(dashboardApiPath()),
    apiOrNull("/api/v1/auth/me"),
  ]);
  state.engagements = engagements;
  state.runProfiles = runProfiles;
  state.codexTasks = codexTasks;
  state.internalValidationScenarios = scenarios;
  state.operatorSettings = operatorSettings;
  state.dashboard = dashboard;
  applyActorIdentity(
    actorNameFromSettings(operatorSettings) || currentActor?.actor_name || state.actor,
    currentActor || { actor_name: state.actor, role: "admin", auth_method: "x_actor_fallback" }
  );
  state.dashboardLoading = false;
  state.dashboardError = null;
  if (
    state.selectedEngagementId &&
    !engagements.some((engagement) => String(engagement.id) === String(state.selectedEngagementId))
  ) {
    state.selectedEngagementId = null;
  }
  if (!state.selectedEngagementId && engagements.length) {
    state.selectedEngagementId = engagements[0].id;
  }
  syncDefaultLandingScreen();
  populateEngagementSelect();
  if (state.selectedEngagementId) {
    await refreshSelectedEngagement();
    return;
  }
  renderAll();
}

function wizardHasDraftWork() {
  const wizard = state.wizard || {};
  const data = wizard.data || {};
  const countTargetValues = (source) =>
    Object.values(source || {}).reduce(
      (count, values) => count + (Array.isArray(values) ? values.filter(Boolean).length : 0),
      0
    );
  const hasConversation = (wizard.intake?.history || []).some((entry) => {
    const role = String(entry?.role || "").toLowerCase();
    return role === "user" || Boolean(entry?.answer || entry?.value);
  });
  return Boolean(
    hasConversation ||
      data.engagement_name ||
      data.client ||
      data.roe_ref ||
      countTargetValues(data.targets || {}) ||
      countTargetValues(data.exclusions || {})
  );
}

function syncDefaultLandingScreen() {
  if (!state.engagements.length) {
    if (state.activeScreen === "dashboard") {
      state.activeScreen = "wizard";
    }
    state.activePhase = phaseForScreen(state.activeScreen);
    return;
  }
  if (!state.dashboardHomeAutoRouted && state.activeScreen === "wizard" && !wizardHasDraftWork()) {
    state.activeScreen = "dashboard";
    state.dashboardHomeAutoRouted = true;
  }
  state.activePhase = phaseForScreen(state.activeScreen);
}

function shouldRenderActiveScreenDuringBackgroundRefresh() {
  return state.activeScreen === "mission-control" && !operatorHasActiveTextInteraction();
}

async function refreshSelectedEngagement(options = {}) {
  const renderScreen = options.renderScreen ?? true;
  const background = Boolean(options.background);
  populateEngagementSelect();
  if (!state.selectedEngagementId) {
    closeRunEventStream();
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
    state.selectedAttackPathSummary = null;
    state.selectedAiInsights = null;
    state.exposureScore = null;
    state.scheduledRuns = [];
    state.scheduledRunsError = null;
    state.selectedTask = null;
    state.remediationPortfolio = null;
    state.selectedCodexTaskId = null;
    state.selectedCodexResult = null;
    state.selectedCodexContext = null;
    state.comparisonBaselineRunId = null;
    state.reportCatalog = [];
    state.reportDraft = null;
    renderAll({ renderScreen, background });
    return;
  }

  const [scope, inventory, relevance, packs, runs, internalValidations, schedules, codexTasks, remediationPortfolio, exposureScore, dashboard, chatgptOAuthStatus] =
    await Promise.all([
      apiOrNull(`/api/v1/engagements/${state.selectedEngagementId}/scope?optional=true`),
      api(`/api/v1/engagements/${state.selectedEngagementId}/inventory`),
      api(`/api/v1/engagements/${state.selectedEngagementId}/relevance`),
      api(`/api/v1/engagements/${state.selectedEngagementId}/packs`),
      api(`/api/v1/engagements/${state.selectedEngagementId}/runs`),
      api(`/api/v1/engagements/${state.selectedEngagementId}/internal-validations`),
      apiOrNull(`/api/v1/engagements/${state.selectedEngagementId}/schedules`),
      api("/api/v1/codex/tasks"),
      apiOrNull(`/api/v1/engagements/${state.selectedEngagementId}/remediation/portfolio`),
      apiOrNull(`/api/v1/engagements/${state.selectedEngagementId}/exposure-score`),
      api(dashboardApiPath()),
      apiOrNull(`/api/v1/auth/chatgpt/status?engagement_id=${encodeURIComponent(state.selectedEngagementId)}`),
    ]);

  const selectedRunEntry =
    state.selectedRunId && runs.some((run) => String(run.id) === String(state.selectedRunId))
      ? runs.find((run) => String(run.id) === String(state.selectedRunId)) || null
      : null;
  const chainedCurrentRunId =
    selectedRunEntry?.assessment_chain?.current_run_id &&
    runs.some((run) => String(run.id) === String(selectedRunEntry.assessment_chain.current_run_id))
      ? selectedRunEntry.assessment_chain.current_run_id
      : null;
  const nextSelectedRunId =
    chainedCurrentRunId ||
    (selectedRunEntry ? state.selectedRunId : runs[0]?.id || null);
  state.mission = {
    scope,
    inventory,
    relevance,
    packs,
    runs,
    internalValidations,
    findingsByRun: preserveCachedFindingsByRun(runs),
  };
  state.codexTasks = codexTasks;
  state.scheduledRuns = Array.isArray(schedules) ? schedules : [];
  state.scheduledRunsError = null;
  state.remediationPortfolio = remediationPortfolio;
  state.exposureScore = exposureScore;
  state.dashboard = dashboard;
  state.chatgptOAuthStatus = chatgptOAuthStatus;
  state.dashboardError = null;
  state.dashboardLoading = false;
  state.selectedRunId = nextSelectedRunId;
  state.deleteUi = {
    ...state.deleteUi,
    selectedRunIds: (state.deleteUi.selectedRunIds || []).filter((runId) =>
      runs.some((run) => String(run.id) === String(runId))
    ),
  };

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
  await ensureComparisonFindings();
  syncRunEventStream();
  renderAll({ renderScreen, background });
}

function preserveCachedFindingsByRun(runs) {
  const currentFindings = state.mission.findingsByRun || {};
  return runs.reduce((findingsByRun, run) => {
    findingsByRun[run.id] = currentFindings[run.id] || [];
    return findingsByRun;
  }, {});
}

async function loadFindingsForRun(runId, options = {}) {
  if (!runId) return [];
  const normalizedRunId = String(runId);
  const existing = state.mission.findingsByRun[normalizedRunId];
  if (!options.force && Array.isArray(existing)) {
    return existing;
  }
  const findings = await api(`/api/v1/runs/${encodeURIComponent(normalizedRunId)}/findings`);
  state.mission = {
    ...state.mission,
    findingsByRun: {
      ...(state.mission.findingsByRun || {}),
      [normalizedRunId]: findings,
    },
  };
  return findings;
}

async function ensureComparisonFindings(options = {}) {
  const comparisonScreens = new Set(["history", "report-center"]);
  if (!comparisonScreens.has(state.activeScreen) || !state.comparisonBaselineRunId) return;
  await loadFindingsForRun(state.comparisonBaselineRunId, { force: true, ...options });
}

async function loadSelectedRun() {
  if (!state.selectedRunId) {
    closeRunEventStream();
    closeTaskStdoutEventStream();
    state.selectedRun = null;
    state.selectedFindingId = null;
    state.selectedFindingTheater = null;
    state.selectedFindingEvidence = null;
    state.selectedAttackPathSummary = null;
    state.selectedTask = null;
    state.selectedCveIntelligence = null;
    state.selectedSurfaceAssetKey = null;
    state.surfaceAssetFilter = "";
    state.surfaceView = "hotspots";
    state.reportCatalog = [];
    state.reportDraft = null;
    return;
  }

  state.reportPreview = "";
  state.reportHtml = "";
  state.reportDraft = null;
  state.loading.reportPreview = false;
  state.loading.reportDraft = false;
  state.selectedSurfaceAssetKey = null;
  state.surfaceAssetFilter = "";
  state.surfaceView = "hotspots";
  const selectedRunId = state.selectedRunId;
  const [run, reportCatalog, attackPathSummary, aiInsights, cveIntelligence, findings] = await Promise.all([
    api(`/api/v1/runs/${state.selectedRunId}`),
    api(`/api/v1/runs/${state.selectedRunId}/reports`),
    apiOrNull(`/api/v1/runs/${state.selectedRunId}/attack-paths`),
    apiOrNull(`/api/v1/runs/${state.selectedRunId}/ai-insights`),
    apiOrNull(`/api/v1/runs/${state.selectedRunId}/cve-intelligence`),
    loadFindingsForRun(selectedRunId, { force: true }),
  ]);
  if (String(state.selectedRunId || "") !== String(selectedRunId || "")) {
    return;
  }
  state.selectedRun = run;
  state.reportCatalog = reportCatalog;
  state.selectedAttackPathSummary = attackPathSummary;
  state.selectedAiInsights = aiInsights;
  state.selectedCveIntelligence = cveIntelligence;
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
  if (!state.selectedFindingId || !findings.some((finding) => finding.id === state.selectedFindingId)) {
    state.selectedFindingId = findings[0]?.id || null;
  }
  const selectedTaskStillExists = state.selectedRun.tasks.some((task) => task.id === state.selectedTaskId);
  const selectedTaskSummary = selectedTaskStillExists
    ? state.selectedRun.tasks.find((task) => task.id === state.selectedTaskId)
    : null;
  const runningTask = state.selectedRun.tasks.find((task) => String(task.status || "").toLowerCase() === "running");
  if (
    !state.selectedTaskId ||
    !selectedTaskStillExists ||
    (
      state.activeScreen === "agents" &&
      runningTask &&
      String(selectedTaskSummary?.status || "").toLowerCase() !== "running"
    )
  ) {
    state.selectedTaskId = runningTask?.id || state.selectedRun.tasks[0]?.id || null;
  }
  await Promise.all([loadSelectedFinding(), loadSelectedTask()]);
}

function closeRunEventStream(nextStatus = "idle", fallbackReason = null) {
  if (state.runStream?.source) {
    state.runStream.source.close();
  }
  state.runStream = {
    source: null,
    runId: null,
    status: nextStatus,
    fallbackReason,
    lastEventAt: state.runStream?.lastEventAt || null,
  };
}

function syncRunEventStream() {
  const run = state.selectedRun;
  const runId = run?.id ? String(run.id) : null;
  const runStatus = String(run?.status || "").toLowerCase();
  if (!runId || !RUN_STREAM_ACTIVE_STATUSES.has(runStatus)) {
    closeRunEventStream();
    return;
  }

  if (state.runStream?.source && state.runStream.runId === runId) {
    return;
  }

  closeRunEventStream("connecting");

  if (typeof window.EventSource !== "function") {
    state.runStream = {
      source: null,
      runId,
      status: "fallback",
      fallbackReason: "EventSource unavailable; using polling fallback.",
      lastEventAt: null,
    };
    return;
  }

  const source = new window.EventSource(`/api/v1/runs/${encodeURIComponent(runId)}/events`);
  state.runStream = {
    source,
    runId,
    status: "connecting",
    fallbackReason: null,
    lastEventAt: null,
  };

  const handleRunStreamEvent = (event) => {
    let snapshot;
    try {
      snapshot = JSON.parse(event.data || "{}");
    } catch (error) {
      state.runStream.status = "fallback";
      state.runStream.fallbackReason = "Run stream emitted invalid data; using polling fallback.";
      source.close();
      renderBackgroundUpdate();
      return;
    }

    if (String(snapshot.run_id || "") !== String(state.selectedRunId || "")) {
      return;
    }

    state.runStream.status = "connected";
    state.runStream.fallbackReason = null;
    state.runStream.lastEventAt = new Date().toISOString();
    mergeRunStreamSnapshot(snapshot);
    renderBackgroundUpdate();

    if (RUN_STREAM_TERMINAL_STATUSES.has(String(snapshot.status || "").toLowerCase())) {
      closeRunEventStream("idle");
      refreshSelectedEngagement({ background: true }).catch(handleError);
    }
  };

  source.addEventListener("run.snapshot", handleRunStreamEvent);
  source.addEventListener("run.update", handleRunStreamEvent);
  source.addEventListener("finding.enriched", (event) => {
    let payload;
    try {
      payload = JSON.parse(event.data || "{}");
    } catch (error) {
      return;
    }
    if (String(payload.run_id || "") !== String(state.selectedRunId || "")) {
      return;
    }
    state.runStream.status = "connected";
    state.runStream.fallbackReason = null;
    state.runStream.lastEventAt = new Date().toISOString();
    Promise.all([
      refreshSelectedEngagement({ renderScreen: false, background: true }),
      String(payload.finding_id || "") === String(state.selectedFindingId || "") ? loadSelectedFinding() : Promise.resolve(),
    ])
      .then(() => renderBackgroundUpdate())
      .catch(handleError);
  });
  source.addEventListener("run.missing", () => {
    closeRunEventStream("fallback", "Run stream could not find the selected run; using polling fallback.");
    renderBackgroundUpdate();
  });
  source.onopen = () => {
    if (state.runStream.runId !== runId) return;
    state.runStream.status = "connected";
    state.runStream.fallbackReason = null;
    renderBackgroundUpdate();
  };
  source.onerror = () => {
    if (state.runStream.runId !== runId) return;
    closeRunEventStream("fallback", "Run stream unavailable; using polling fallback.");
    renderBackgroundUpdate();
  };
}

function mergeRunStreamSnapshot(snapshot) {
  const runId = String(snapshot.run_id || "");
  if (!runId || String(state.selectedRunId || "") !== runId || !state.selectedRun) {
    return;
  }

  const tasksById = new Map((state.selectedRun.tasks || []).map((task) => [String(task.id), task]));
  const streamedTasks = Array.isArray(snapshot.tasks) ? snapshot.tasks : [];
  const mergedTasks = (state.selectedRun.tasks || []).map((task) => {
    const streamedTask = streamedTasks.find((candidate) => String(candidate.id || "") === String(task.id));
    return streamedTask ? { ...task, ...streamedTask } : task;
  });
  streamedTasks.forEach((streamedTask) => {
    const streamedTaskId = String(streamedTask.id || "");
    if (streamedTaskId && !tasksById.has(streamedTaskId)) {
      mergedTasks.push(streamedTask);
    }
  });

  state.selectedRun = {
    ...state.selectedRun,
    status: snapshot.status || state.selectedRun.status,
    started_at: snapshot.started_at ?? state.selectedRun.started_at,
    completed_at: snapshot.completed_at ?? state.selectedRun.completed_at,
    updated_at: snapshot.updated_at || state.selectedRun.updated_at,
    assessment_chain: snapshot.assessment_chain?.id ? snapshot.assessment_chain : state.selectedRun.assessment_chain,
    tasks: mergedTasks,
  };
  state.mission.runs = state.mission.runs.map((run) =>
    String(run.id) === runId
      ? {
          ...run,
          status: state.selectedRun.status,
          started_at: state.selectedRun.started_at,
          completed_at: state.selectedRun.completed_at,
          updated_at: state.selectedRun.updated_at,
          assessment_chain: state.selectedRun.assessment_chain,
          tasks: mergedTasks,
        }
      : run
  );
  if (
    state.loading.dispatchRunId &&
    String(state.loading.dispatchRunId) === runId &&
    String(state.selectedRun.status || "").toLowerCase() !== "queued"
  ) {
    state.loading.dispatchRunId = null;
  }
}

function closeTaskStdoutPoller() {
  if (runtime.taskStdoutPollTimer) {
    window.clearInterval(runtime.taskStdoutPollTimer);
  }
  runtime.taskStdoutPollTimer = null;
  runtime.taskStdoutPollTaskId = null;
  runtime.taskStdoutPollInFlight = false;
}

function closeTaskStdoutEventStream(nextStatus = "idle", fallbackReason = null, options = {}) {
  if (state.taskStdoutStream?.source) {
    state.taskStdoutStream.source.close();
  }
  const preserve = options.preserveCurrent && state.taskStdoutStream;
  state.taskStdoutStream = {
    source: null,
    taskId: preserve ? state.taskStdoutStream.taskId : null,
    status: nextStatus,
    sourceLabel: preserve ? state.taskStdoutStream.sourceLabel : null,
    fallbackReason,
    lines: preserve ? state.taskStdoutStream.lines || [] : [],
    lineCount: preserve ? state.taskStdoutStream.lineCount || 0 : 0,
    truncated: preserve ? Boolean(state.taskStdoutStream.truncated) : false,
    terminal: false,
    lastEventAt: state.taskStdoutStream?.lastEventAt || null,
  };
}

function selectedRunHasTask(taskId) {
  return Boolean(
    taskId &&
    state.selectedRun?.tasks?.some((task) => String(task.id || "") === String(taskId))
  );
}

function mergeTaskStdoutLines(previousLines, nextLines) {
  const previous = Array.isArray(previousLines) ? previousLines : [];
  const next = Array.isArray(nextLines) ? nextLines : [];
  if (!previous.length) return next;
  if (!next.length) return previous;
  if (next.length >= previous.length) return next;
  const seen = new Set(next.map((line) => `${line?.sequence ?? ""}:${line?.text ?? ""}`));
  const merged = [...next];
  previous.forEach((line) => {
    const key = `${line?.sequence ?? ""}:${line?.text ?? ""}`;
    if (!seen.has(key)) {
      merged.push(line);
    }
  });
  return merged.sort((a, b) => Number(a?.sequence || 0) - Number(b?.sequence || 0));
}

function applyTaskStdoutSnapshot(snapshot, taskId, options = {}) {
  if (!snapshot || typeof snapshot !== "object" || !taskId) return;
  const snapshotTaskId = String(snapshot.task_id || taskId);
  if (snapshotTaskId !== String(taskId)) return;
  const previous = state.taskStdoutStream || {};
  const sameTask = String(previous.taskId || "") === String(taskId);
  const previousLines = sameTask ? previous.lines : [];
  const nextLines = mergeTaskStdoutLines(previousLines, snapshot.lines);
  const terminal = Boolean(snapshot.stream_terminal);
  const existingSource = sameTask ? previous.source || null : null;
  state.taskStdoutStream = {
    source: terminal ? null : existingSource,
    taskId,
    status: options.status || snapshot.status || (nextLines.length ? "streaming" : "unavailable"),
    sourceLabel: snapshot.source || previous.sourceLabel || null,
    fallbackReason: snapshot.reason || previous.fallbackReason || null,
    lines: nextLines,
    lineCount: Math.max(Number(snapshot.line_count || 0), nextLines.length, Number(previous.lineCount || 0)),
    truncated: Boolean(snapshot.truncated || previous.truncated),
    terminal,
    lastEventAt: new Date().toISOString(),
  };
}

function selectedTaskSummaryForPolling(taskId) {
  return state.selectedRun?.tasks?.find((task) => String(task.id || "") === String(taskId)) || null;
}

function selectedTaskAndStdoutSignature() {
  const task = state.selectedTask || {};
  const stream = state.taskStdoutStream || {};
  const lines = Array.isArray(stream.lines) ? stream.lines : [];
  return JSON.stringify({
    task: {
      id: task.id || null,
      status: task.status || null,
      updated_at: task.updated_at || null,
      started_at: task.started_at || null,
      finished_at: task.finished_at || null,
      execution_count: Array.isArray(task.executions) ? task.executions.length : null,
    },
    stream: {
      taskId: stream.taskId || null,
      status: stream.status || null,
      sourceLabel: stream.sourceLabel || null,
      fallbackReason: stream.fallbackReason || null,
      lineCount: Number(stream.lineCount || 0),
      truncated: Boolean(stream.truncated),
      terminal: Boolean(stream.terminal),
      lines: lines.map((line) => ({
        sequence: Number(line?.sequence || 0),
        text: String(line?.text || ""),
      })),
    },
  });
}

async function pollSelectedTaskStdout(taskId) {
  if (!taskId || runtime.taskStdoutPollInFlight) return;
  const taskSummary = selectedTaskSummaryForPolling(taskId);
  if (String(taskSummary?.status || "").toLowerCase() !== "running") return;
  runtime.taskStdoutPollInFlight = true;
  try {
    const previousSignature = selectedTaskAndStdoutSignature();
    const task = await api(`/api/v1/tasks/${encodeURIComponent(taskId)}`);
    if (String(state.selectedTaskId || "") !== String(taskId)) return;
    state.selectedTask = task;
    if (task.stdout_snapshot) {
      applyTaskStdoutSnapshot(task.stdout_snapshot, taskId, { status: "streaming" });
    }
    if (selectedTaskAndStdoutSignature() !== previousSignature) {
      renderBackgroundUpdate();
    }
  } catch (error) {
    if (String(state.selectedTaskId || "") === String(taskId)) {
      const previousSignature = selectedTaskAndStdoutSignature();
      state.taskStdoutStream = {
        ...(state.taskStdoutStream || {}),
        taskId,
        status: "fallback",
        fallbackReason: error?.message || "Task stdout polling failed; stored execution fallback remains available.",
      };
      if (selectedTaskAndStdoutSignature() !== previousSignature) {
        renderBackgroundUpdate();
      }
    }
  } finally {
    runtime.taskStdoutPollInFlight = false;
  }
}

function syncTaskStdoutPoller() {
  const taskId = state.selectedTaskId ? String(state.selectedTaskId) : null;
  const taskSummary = taskId ? selectedTaskSummaryForPolling(taskId) : null;
  const shouldPoll =
    TASK_STDOUT_SCREENS.has(state.activeScreen) &&
    taskId &&
    selectedRunHasTask(taskId) &&
    String(taskSummary?.status || "").toLowerCase() === "running";

  if (!shouldPoll) {
    closeTaskStdoutPoller();
    return;
  }

  if (runtime.taskStdoutPollTimer && runtime.taskStdoutPollTaskId === taskId) {
    return;
  }

  closeTaskStdoutPoller();
  runtime.taskStdoutPollTaskId = taskId;
  pollSelectedTaskStdout(taskId);
  runtime.taskStdoutPollTimer = window.setInterval(
    () => pollSelectedTaskStdout(taskId),
    TASK_STDOUT_POLL_INTERVAL_MS
  );
}

function syncTaskStdoutEventStream() {
  const taskId = state.selectedTaskId ? String(state.selectedTaskId) : null;
  if (
    !TASK_STDOUT_SCREENS.has(state.activeScreen) ||
    !taskId ||
    !selectedRunHasTask(taskId)
  ) {
    closeTaskStdoutEventStream();
    return;
  }

  if (
    state.taskStdoutStream?.taskId === taskId &&
    (state.taskStdoutStream?.terminal || state.taskStdoutStream?.status === "fallback")
  ) {
    return;
  }

  if (
    state.taskStdoutStream?.source &&
    state.taskStdoutStream.taskId === taskId
  ) {
    return;
  }

  closeTaskStdoutEventStream("connecting", null, { preserveCurrent: true });

  if (typeof window.EventSource !== "function") {
    const previous = state.taskStdoutStream || {};
    const sameTask = String(previous.taskId || "") === String(taskId);
    state.taskStdoutStream = {
      source: null,
      taskId,
      status: "fallback",
      sourceLabel: sameTask ? previous.sourceLabel || null : null,
      fallbackReason: "EventSource unavailable; task stdout is using the stored execution fallback only.",
      lines: sameTask ? previous.lines || [] : [],
      lineCount: sameTask ? Number(previous.lineCount || 0) : 0,
      truncated: sameTask ? Boolean(previous.truncated) : false,
      terminal: false,
      lastEventAt: sameTask ? previous.lastEventAt || null : null,
    };
    return;
  }

  const previous = state.taskStdoutStream || {};
  const sameTask = String(previous.taskId || "") === String(taskId);
  const source = new window.EventSource(`/api/v1/tasks/${encodeURIComponent(taskId)}/stdout/events`);
  state.taskStdoutStream = {
    source,
    taskId,
    status: "connecting",
    sourceLabel: sameTask ? previous.sourceLabel || null : null,
    fallbackReason: null,
    lines: sameTask ? previous.lines || [] : [],
    lineCount: sameTask ? Number(previous.lineCount || 0) : 0,
    truncated: sameTask ? Boolean(previous.truncated) : false,
    terminal: false,
    lastEventAt: sameTask ? previous.lastEventAt || null : null,
  };

  const handleTaskStdoutEvent = (event) => {
    let snapshot;
    try {
      snapshot = JSON.parse(event.data || "{}");
    } catch (error) {
      if (state.taskStdoutStream.taskId !== taskId) return;
      state.taskStdoutStream.status = "fallback";
      state.taskStdoutStream.fallbackReason = "Task stdout stream emitted invalid data; using stored execution fallback only.";
      source.close();
      renderBackgroundUpdate();
      return;
    }

    if (String(snapshot.task_id || "") !== String(state.selectedTaskId || "")) {
      return;
    }

    const terminal = Boolean(snapshot.stream_terminal);
    applyTaskStdoutSnapshot(snapshot, taskId, { status: snapshot.status || "unavailable" });
    state.taskStdoutStream.source = terminal ? null : source;

    if (terminal) {
      source.close();
    }
    renderBackgroundUpdate();
  };

  source.addEventListener("task.stdout.snapshot", handleTaskStdoutEvent);
  source.addEventListener("task.stdout.update", handleTaskStdoutEvent);
  source.addEventListener("task.stdout.missing", () => {
    if (state.taskStdoutStream.taskId !== taskId) return;
    state.taskStdoutStream = {
      source: null,
      taskId,
      status: "missing",
      sourceLabel: null,
      fallbackReason: "Selected task no longer exists; stdout stream stopped.",
      lines: [],
      lineCount: 0,
      truncated: false,
      terminal: true,
      lastEventAt: new Date().toISOString(),
    };
    source.close();
    renderBackgroundUpdate();
  });
  source.onopen = () => {
    if (state.taskStdoutStream.taskId !== taskId) return;
    state.taskStdoutStream.status = "streaming";
    state.taskStdoutStream.fallbackReason = null;
    renderBackgroundUpdate();
  };
  source.onerror = () => {
    if (state.taskStdoutStream.taskId !== taskId) return;
    state.taskStdoutStream.status = "fallback";
    state.taskStdoutStream.fallbackReason = "Task stdout stream unavailable; using stored execution fallback only.";
    state.taskStdoutStream.source = null;
    source.close();
    renderBackgroundUpdate();
  };
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
  if (state.selectedTask?.stdout_snapshot) {
    applyTaskStdoutSnapshot(state.selectedTask.stdout_snapshot, String(state.selectedTaskId));
  }
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

function toggleRunDeleteSelection(runId, selected) {
  const normalized = String(runId || "");
  if (!normalized) return;
  const current = new Set(state.deleteUi.selectedRunIds || []);
  if (selected) {
    current.add(normalized);
  } else {
    current.delete(normalized);
  }
  patchState(
    {
      deleteUi: {
        ...state.deleteUi,
        selectedRunIds: [...current],
      },
    },
    "delete.run.selection"
  );
  renderAll();
}

function toggleEngagementDeleteSelection(engagementId, selected) {
  const normalized = String(engagementId || "");
  if (!normalized) return;
  const current = new Set(state.deleteUi.selectedEngagementIds || []);
  if (selected) {
    current.add(normalized);
  } else {
    current.delete(normalized);
  }
  patchState(
    {
      deleteUi: {
        ...state.deleteUi,
        selectedEngagementIds: [...current],
      },
    },
    "delete.engagement.selection"
  );
  renderDeletionUi();
}

function updateDeleteModal(patch) {
  if (!state.deleteUi.modal) return;
  patchState(
    {
      deleteUi: {
        ...state.deleteUi,
        modal: {
          ...state.deleteUi.modal,
          ...patch,
        },
      },
    },
    "delete.modal.update"
  );
}

function closeDeleteModal() {
  patchState(
    {
      deleteUi: {
        ...state.deleteUi,
        modal: null,
      },
    },
    "delete.modal.close"
  );
  renderDeletionUi();
  if (deleteModalPreviousFocus?.isConnected) {
    deleteModalPreviousFocus.focus();
  }
  deleteModalPreviousFocus = null;
}

function openEngagementCleanup() {
  deleteModalPreviousFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null;
  patchState(
    {
      deleteUi: {
        ...state.deleteUi,
        modal: { type: "engagement-cleanup" },
      },
    },
    "delete.engagement.cleanup"
  );
  renderDeletionUi();
}

async function openRunDeletePreview(runIds) {
  const uniqueRunIds = [...new Set((runIds || []).map((runId) => String(runId || "")).filter(Boolean))];
  if (!uniqueRunIds.length) {
    pushStatus("Select at least one run before deleting.", "warning");
    return;
  }
  deleteModalPreviousFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null;
  patchState(
    {
      deleteUi: {
        ...state.deleteUi,
        modal: { type: "run-delete", runIds: uniqueRunIds, loading: true, confirmation: "", error: null },
      },
    },
    "delete.run.preview.start"
  );
  renderDeletionUi();
  try {
    const preview = await api("/api/v1/runs?dry_run=true", {
      method: "DELETE",
      body: { run_ids: uniqueRunIds },
    });
    updateDeleteModal({ loading: false, preview });
    renderDeletionUi();
  } catch (error) {
    updateDeleteModal({ loading: false, error: error.message || "Could not load delete preview." });
    renderDeletionUi();
  }
}

async function confirmRunDelete() {
  const modal = state.deleteUi.modal;
  if (!modal || modal.type !== "run-delete" || modal.loading || modal.pending) return;
  if (String(modal.confirmation || "").trim() !== "DELETE") {
    updateDeleteModal({ error: "Type DELETE to confirm run deletion." });
    renderDeletionUi();
    return;
  }
  const runIds = modal.runIds || [];
  updateDeleteModal({ pending: true, error: null });
  renderDeletionUi();
  try {
    const result = await api("/api/v1/runs", {
      method: "DELETE",
      body: { run_ids: runIds },
    });
    const deleted = new Set(result.deleted_ids || runIds);
    if (deleted.has(state.selectedRunId)) {
      state.selectedRunId = null;
      state.selectedRun = null;
    }
    patchState(
      {
        deleteUi: {
          ...state.deleteUi,
          selectedRunIds: [],
          modal: null,
        },
      },
      "delete.run.confirmed"
    );
    pushStatus(`${deleted.size || runIds.length} run${(deleted.size || runIds.length) === 1 ? "" : "s"} soft-deleted.`, "success");
    await refreshSelectedEngagement();
  } catch (error) {
    updateDeleteModal({ pending: false, error: error.message || "Run deletion failed." });
    renderDeletionUi();
  }
}

async function openEngagementDeletePreview(engagementIds) {
  const uniqueEngagementIds = [...new Set((engagementIds || []).map((id) => String(id || "")).filter(Boolean))];
  if (!uniqueEngagementIds.length) {
    pushStatus("Select at least one engagement before deleting.", "warning");
    return;
  }
  deleteModalPreviousFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null;
  patchState(
    {
      deleteUi: {
        ...state.deleteUi,
        modal: {
          type: "engagement-delete",
          engagementIds: uniqueEngagementIds,
          loading: true,
          confirmations: {},
          previews: {},
          error: null,
        },
      },
    },
    "delete.engagement.preview.start"
  );
  renderDeletionUi();
  try {
    const previews = {};
    await Promise.all(
      uniqueEngagementIds.map(async (engagementId) => {
        previews[engagementId] = await api(`/api/v1/engagements/${encodeURIComponent(engagementId)}?dry_run=true`, {
          method: "DELETE",
        });
      })
    );
    updateDeleteModal({ loading: false, previews });
    renderDeletionUi();
  } catch (error) {
    updateDeleteModal({ loading: false, error: error.message || "Could not load engagement delete preview." });
    renderDeletionUi();
  }
}

async function confirmEngagementDelete() {
  const modal = state.deleteUi.modal;
  if (!modal || modal.type !== "engagement-delete" || modal.loading || modal.pending) return;
  const engagementIds = modal.engagementIds || [];
  const missing = engagementIds.find((engagementId) => {
    const engagement = state.engagements.find((item) => String(item.id) === String(engagementId));
    return !engagement || String(modal.confirmations?.[engagementId] || "") !== String(engagement.name || "");
  });
  if (missing) {
    updateDeleteModal({ error: "Type each engagement name exactly before deleting." });
    renderDeletionUi();
    return;
  }
  updateDeleteModal({ pending: true, error: null });
  renderDeletionUi();
  try {
    for (const engagementId of engagementIds) {
      const engagement = state.engagements.find((item) => String(item.id) === String(engagementId));
      await api(`/api/v1/engagements/${encodeURIComponent(engagementId)}`, {
        method: "DELETE",
        body: { confirmation: engagement.name },
      });
    }
    if (engagementIds.some((id) => String(id) === String(state.selectedEngagementId))) {
      state.selectedEngagementId = null;
      state.selectedRunId = null;
      state.selectedRun = null;
    }
    patchState(
      {
        deleteUi: {
          selectedRunIds: [],
          selectedEngagementIds: [],
          modal: null,
        },
      },
      "delete.engagement.confirmed"
    );
    pushStatus(`${engagementIds.length} engagement${engagementIds.length === 1 ? "" : "s"} soft-deleted.`, "success");
    await refreshShell();
  } catch (error) {
    updateDeleteModal({ pending: false, error: error.message || "Engagement deletion failed." });
    renderDeletionUi();
  }
}

function pendingAiProposalCount() {
  const proposals = Array.isArray(state.selectedAiInsights?.proposals)
    ? state.selectedAiInsights.proposals
    : [];
  return proposals.filter((proposal) => String(proposal.status || "").toLowerCase() === "pending_review").length;
}

function selectedRunAttackPathSummary() {
  return state.selectedAttackPathSummary || null;
}

function renderShellChrome() {
  syncActivePhase();
  renderHeader();
  renderFlowOverview();
  renderSelectedEngagementSummary();
  renderPhaseSubnav();
  renderPhaseFeedCard();
  renderStatus();
}

function renderAll(options = {}) {
  const renderScreen = (options.renderScreen ?? true) && !shouldDeferBackgroundScreenRender(options);
  syncTaskStdoutEventStream();
  syncTaskStdoutPoller();
  renderShellChrome();
  if (renderScreen) {
    renderScreens();
  }
  renderDeletionUi();
  renderOnboardingExperience();
}

function renderDeletionUi() {
  if (!dom.deleteModalRoot) return;
  const modal = state.deleteUi?.modal || null;
  if (!modal) {
    dom.deleteModalRoot.classList.remove("is-visible");
    dom.deleteModalRoot.innerHTML = "";
    dom.deleteModalRoot.dataset.focusInitialized = "false";
    return;
  }
  dom.deleteModalRoot.classList.add("is-visible");
  if (modal.type === "engagement-cleanup") {
    renderEngagementCleanupModal();
  } else if (modal.type === "run-delete") {
    renderRunDeleteModal(modal);
  } else if (modal.type === "engagement-delete") {
    renderEngagementDeleteModal(modal);
  }
  focusDeleteModalOnce();
}

function renderDeleteModalShell({ title, subtitle, body }) {
  dom.deleteModalRoot.innerHTML = `
    <div class="delete-modal-backdrop" data-delete-modal-close="true"></div>
    <section class="delete-modal" role="dialog" aria-modal="true" aria-labelledby="delete-modal-title" aria-describedby="delete-modal-description" tabindex="-1">
      <div class="delete-modal-head">
        <div>
          <p class="eyebrow">Data Cleanup</p>
          <h3 id="delete-modal-title">${escapeHtml(title)}</h3>
          <p id="delete-modal-description">${escapeHtml(subtitle)}</p>
        </div>
        <button class="topbar-button topbar-icon-button" type="button" data-delete-modal-close="true" aria-label="Close">×</button>
      </div>
      ${body}
    </section>
  `;
}

function focusDeleteModalOnce() {
  if (dom.deleteModalRoot?.dataset.focusInitialized === "true") return;
  const dialog = dom.deleteModalRoot?.querySelector(".delete-modal");
  if (!dialog) return;
  dom.deleteModalRoot.dataset.focusInitialized = "true";
  window.requestAnimationFrame(() => {
    const focusable = focusableElements(dialog);
    (focusable[0] || dialog).focus();
  });
}

function renderEngagementCleanupModal() {
  const selected = new Set(state.deleteUi.selectedEngagementIds || []);
  const allSelected = Boolean(state.engagements.length) && state.engagements.every((engagement) => selected.has(engagement.id));
  renderDeleteModalShell({
    title: "Engagement Cleanup",
    subtitle: "Remove stale engagement dossiers with dry-run impact previews and exact-name confirmation.",
    body: `
      <div class="delete-modal-toolbar">
        <label class="delete-checkline">
          <input type="checkbox" data-engagement-delete-select-all ${allSelected ? "checked" : ""} ${state.engagements.length ? "" : "disabled"} />
          <span>Select all</span>
        </label>
        <button class="action ghost danger-action" type="button" data-engagement-delete-preview="selected" ${selected.size ? "" : "disabled"} data-testid="bulk-delete-engagements">
          Delete ${escapeHtml(String(selected.size))} selected
        </button>
      </div>
      <div class="delete-engagement-list" data-testid="manage-engagements-list">
        ${
          state.engagements.length
            ? state.engagements
                .map((engagement) => {
                  const selectedEngagement = selected.has(engagement.id);
                  const runs = String(engagement.id) === String(state.selectedEngagementId) ? state.mission.runs.length : "Load";
                  return `
                    <article class="delete-engagement-row ${selectedEngagement ? "is-selected" : ""}">
                      <label class="delete-checkline" data-run-delete-control>
                        <input
                          type="checkbox"
                          data-engagement-delete-toggle="${escapeHtml(engagement.id)}"
                          ${selectedEngagement ? "checked" : ""}
                        />
                        <span>
                          <strong>${escapeHtml(engagement.name || "Untitled engagement")}</strong>
                          <small>${escapeHtml(`${engagement.client || "No customer"} · ${engagement.status || "draft"} · ${runs} run${runs === 1 ? "" : "s"}`)}</small>
                        </span>
                      </label>
                      <button class="action ghost tiny danger-action" type="button" data-engagement-delete-preview="${escapeHtml(engagement.id)}" data-testid="delete-engagement">Delete</button>
                    </article>
                  `;
                })
                .join("")
            : emptyState("No engagement dossiers exist yet.")
        }
      </div>
    `,
  });
}

function renderRunDeleteModal(modal) {
  const preview = modal.preview || null;
  const blocked = Boolean(preview?.blocked);
  renderDeleteModalShell({
    title: `Delete ${modal.runIds?.length || 0} Run${(modal.runIds?.length || 0) === 1 ? "" : "s"}`,
    subtitle: "Runs are soft-deleted now and become eligible for retention cleanup after 30 days.",
    body: `
      <div class="delete-modal-body" data-testid="run-delete-preview">
        ${modal.loading ? `<p class="micro-copy">Loading impact preview...</p>` : ""}
        ${preview ? renderImpactCounts(preview.counts, preview.total_items) : ""}
        ${
          blocked
            ? `<div class="delete-warning">${escapeHtml(preview.blocked_reason || "Stop the run before deleting")}</div>`
            : ""
        }
        <label class="field compact">
          <span>Confirmation</span>
          <input type="text" data-delete-confirmation value="${escapeHtml(modal.confirmation || "")}" placeholder="Type DELETE" ${blocked ? "disabled" : ""} />
        </label>
        ${modal.error ? `<div class="delete-warning">${escapeHtml(modal.error)}</div>` : ""}
        <div class="panel-actions">
          <button class="action ghost" type="button" data-delete-modal-close="true">Cancel</button>
          <button
            class="action secondary danger-action"
            type="button"
            data-run-delete-confirm="true"
            ${modal.pending || modal.loading || blocked ? "disabled" : ""}
            data-testid="confirm-run-delete"
          >
            ${modal.pending ? "Deleting..." : "Delete Runs"}
          </button>
        </div>
      </div>
    `,
  });
}

function renderEngagementDeleteModal(modal) {
  const previews = modal.previews || {};
  const engagementIds = modal.engagementIds || [];
  const totalItems = Object.values(previews).reduce((total, preview) => total + Number(preview?.total_items || 0), 0);
  renderDeleteModalShell({
    title: `Delete ${engagementIds.length} Engagement${engagementIds.length === 1 ? "" : "s"}`,
    subtitle: "Each engagement requires its exact name before the cascade soft-delete can proceed.",
    body: `
      <div class="delete-modal-body" data-testid="engagement-delete-preview">
        ${modal.loading ? `<p class="micro-copy">Loading cascade preview...</p>` : ""}
        ${
          engagementIds
            .map((engagementId) => {
              const engagement = state.engagements.find((item) => String(item.id) === String(engagementId));
              const preview = previews[engagementId];
              return `
                <article class="delete-confirm-card">
                  <div>
                    <h4>${escapeHtml(engagement?.name || "Deleted engagement")}</h4>
                    <p class="micro-copy">${escapeHtml(engagement?.client || "No customer recorded")}</p>
                  </div>
                  ${preview ? renderImpactCounts(preview.counts, preview.total_items, "compact-impact-grid") : ""}
                  ${
                    preview?.warnings?.length
                      ? `<div class="delete-warning">${preview.warnings.map((warning) => escapeHtml(warning)).join("<br />")}</div>`
                      : ""
                  }
                  <label class="field compact">
                    <span>Type engagement name</span>
                    <input
                      type="text"
                      data-engagement-delete-confirmation="${escapeHtml(engagementId)}"
                      value="${escapeHtml(modal.confirmations?.[engagementId] || "")}"
                      placeholder="${escapeHtml(engagement?.name || "")}"
                    />
                  </label>
                </article>
              `;
            })
            .join("")
        }
        <p class="micro-copy">${escapeHtml(`${totalItems} total linked records in the current impact preview.`)}</p>
        ${modal.error ? `<div class="delete-warning">${escapeHtml(modal.error)}</div>` : ""}
        <div class="panel-actions">
          <button class="action ghost" type="button" data-delete-modal-close="true">Cancel</button>
          <button
            class="action secondary danger-action"
            type="button"
            data-engagement-delete-confirm="true"
            ${modal.pending || modal.loading ? "disabled" : ""}
            data-testid="confirm-engagement-delete"
          >
            ${modal.pending ? "Deleting..." : "Delete Engagements"}
          </button>
        </div>
      </div>
    `,
  });
}

function renderImpactCounts(counts, totalItems, className = "delete-impact-grid") {
  const entries = Object.entries(counts || {}).filter(([, value]) => Number(value || 0) > 0);
  if (!entries.length) {
    return `<p class="micro-copy">No linked records are included in this impact preview.</p>`;
  }
  return `
    <div class="${escapeHtml(className)}">
      ${entries
        .map(
          ([key, value]) => `
            <div>
              <span>${escapeHtml(key.replaceAll("_", " "))}</span>
              <strong>${escapeHtml(String(value))}</strong>
            </div>
          `
        )
        .join("")}
    </div>
    <p class="micro-copy">${escapeHtml(`${totalItems || 0} total records affected. Capability packs are retained.`)}</p>
  `;
}

function renderHeader() {
  const engagement = selectedEngagement();
  const run = state.selectedRun;
  const runConfig = run?.configuration_json || state.wizard.data || {};
  const runCount = state.mission.runs.length || 0;
  if (dom.sidebarMetrics) {
    dom.sidebarMetrics.innerHTML = "";
  }
  if (dom.topbarRunStatus) {
    const runTasks = run?.tasks || [];
    const queuedTasks = runTasks.filter((task) => String(task.status || "").toLowerCase() === "queued").length;
    const runningTasks = runTasks.filter((task) => String(task.status || "").toLowerCase() === "running").length;
    const status = String(run?.status || "").toLowerCase();
    const runStatusVisible = Boolean(run) && (queuedTasks > 0 || runningTasks > 0 || RUN_STREAM_ACTIVE_STATUSES.has(status));
    const statusLabel = runningTasks
      ? `${runningTasks} Running ${runningTasks === 1 ? "Task" : "Tasks"}`
      : queuedTasks
        ? `${queuedTasks} Queued ${queuedTasks === 1 ? "Task" : "Tasks"}`
        : "1 Active Run";
    dom.topbarRunStatus.classList.toggle("is-hidden", !runStatusVisible);
    dom.topbarRunStatus.innerHTML = runStatusVisible
      ? `
          <span class="topbar-status-dot state-${escapeHtml(status || "idle")}"></span>
          <span data-testid="topbar-run-status-label">${escapeHtml(statusLabel)}</span>
        `
      : "";
  }
  if (dom.topbarPhaseIndicator) {
    dom.topbarPhaseIndicator.innerHTML = "";
    dom.topbarPhaseIndicator.classList.add("hidden");
  }
  if (dom.topbarEngagementContext) {
    dom.topbarEngagementContext.innerHTML = "";
  }
  if (dom.topbarNav) {
    if (shouldShowWizardCompletionCta()) {
      dom.topbarNav.classList.remove("hidden");
      dom.topbarNav.innerHTML = `
        <button
          class="topbar-button topbar-wizard-cta"
          type="button"
          data-nav-screen="wizard"
          data-testid="complete-assessment-wizard-cta"
        >
          Complete Assessment Wizard
        </button>
      `;
    } else {
      dom.topbarNav.innerHTML = "";
      dom.topbarNav.classList.add("hidden");
    }
  }
  if (dom.refreshBtn) {
    dom.refreshBtn.classList.add("hidden");
  }
  if (dom.actorRoleBadge) {
    const role = String(state.currentActor?.role || "admin").trim().toLowerCase() || "admin";
    dom.actorRoleBadge.textContent = role;
    dom.actorRoleBadge.className = `topbar-role-badge role-${role}`;
    dom.actorRoleBadge.title = `Role: ${role}`;
  }
  syncActorDisplay();
}

function isFirstRunStartState() {
  const history = state.wizard?.intake?.history || [];
  const hasOperatorAnswer = history.some((turn) => turn.role === "user");
  return !state.engagements.length && !state.selectedEngagementId && !state.selectedRun && !hasOperatorAnswer;
}

function hasRunContextForWizardCompletionCta() {
  const engagementHasRuns = (engagement) =>
    Number(engagement?.run_count || engagement?.runs_count || engagement?.total_runs || 0) > 0 ||
    (Array.isArray(engagement?.runs) && engagement.runs.length > 0);
  return Boolean(state.selectedRun) ||
    Boolean(state.dashboard?.active_run) ||
    (Array.isArray(state.mission?.runs) && state.mission.runs.length > 0) ||
    (Array.isArray(state.engagements) && state.engagements.some(engagementHasRuns));
}

function shouldShowWizardCompletionCta() {
  return state.activeScreen === "dashboard" &&
    !state.engagements.length &&
    !hasRunContextForWizardCompletionCta();
}

function findOperatorSettingValue(key) {
  const sections = Array.isArray(state.operatorSettings?.sections) ? state.operatorSettings.sections : [];
  for (const section of sections) {
    const settings = Array.isArray(section?.settings) ? section.settings : [];
    const match = settings.find((setting) => String(setting?.key || "") === String(key || ""));
    if (match) return match.value;
  }
  return null;
}

function operatorSettingBoolean(key) {
  const value = findOperatorSettingValue(key);
  if (typeof value === "boolean") return value;
  return ["true", "1", "yes", "on"].includes(String(value || "").trim().toLowerCase());
}

function onboardingHostnameDefault() {
  const hostname = String(window.location.hostname || "").trim();
  if (!hostname || hostname === "127.0.0.1" || hostname === "localhost") return "";
  return hostname;
}

function buildOnboardingDraft() {
  const configuredProvider = String(findOperatorSettingValue("ai.provider") || "disabled").trim().toLowerCase() || "disabled";
  const configuredScope = String(findOperatorSettingValue("network.default_lan_cidr") || "").trim();
  const configuredActor = String(findOperatorSettingValue("instance.operator_display_name") || "").trim();
  return {
    provider: configuredProvider,
    defaultScope: configuredScope,
    actorName: configuredActor || onboardingHostnameDefault() || String(state.actor || "").trim() || "operator-ui",
  };
}

function currentOnboardingState() {
  if (!state.onboarding) {
    state.onboarding = buildEmptyOnboardingState();
  }
  return state.onboarding;
}

function shouldAutoShowOnboarding() {
  if (state.activeScreen === "settings") return false;
  return !state.engagements.length && !operatorSettingBoolean("instance.onboarding_completed");
}

function ensureOnboardingState() {
  const onboarding = currentOnboardingState();
  if (!onboarding.initialized) {
    state.onboarding = {
      ...buildEmptyOnboardingState(),
      initialized: true,
      visible: shouldAutoShowOnboarding(),
      values: buildOnboardingDraft(),
    };
    return state.onboarding;
  }
  if (!onboarding.forced) {
    onboarding.visible = shouldAutoShowOnboarding();
  }
  if (!onboarding.values) {
    onboarding.values = buildOnboardingDraft();
  }
  return onboarding;
}

function onboardingScopePresets() {
  const current = String(currentOnboardingState().values?.defaultScope || "").trim();
  return [...new Set([current, "10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12"].filter(Boolean))];
}

function openOnboarding({ forced = false } = {}) {
  patchState(
    {
      onboarding: {
        ...buildEmptyOnboardingState(),
        initialized: true,
        visible: true,
        forced,
        values: buildOnboardingDraft(),
      },
    },
    "onboarding.open"
  );
  renderAll();
}

function setOnboardingStep(step) {
  const onboarding = ensureOnboardingState();
  patchState(
    {
      onboarding: {
        ...onboarding,
        step: Math.max(0, Math.min(2, Number(step || 0))),
        error: null,
      },
    },
    "onboarding.step"
  );
  renderAll();
}

function setOnboardingValue(field, value) {
  const onboarding = ensureOnboardingState();
  patchState(
    {
      onboarding: {
        ...onboarding,
        error: null,
        values: {
          ...onboarding.values,
          [field]: value,
        },
      },
    },
    "onboarding.value"
  );
  renderAll();
}

function onboardingChecklistItems() {
  const provider = String(findOperatorSettingValue("ai.provider") || "disabled").trim().toLowerCase();
  const scope = String(findOperatorSettingValue("network.default_lan_cidr") || "").trim();
  const findingsCount = engagementFindings().length;
  return [
    {
      id: "ai",
      label: "Connect AI provider",
      done: provider !== "disabled",
      detail: provider !== "disabled" ? `Default ${provider.replaceAll("_", " ")}` : "Optional until you want AI helpers",
    },
    {
      id: "scope",
      label: "Set default scope",
      done: Boolean(scope),
      detail: scope || "Add a LAN CIDR default for faster intake",
    },
    {
      id: "scan",
      label: "Run first scan",
      done: state.engagements.length > 0,
      detail: state.engagements.length ? `${state.engagements.length} mission${state.engagements.length === 1 ? "" : "s"} created` : "Create your first mission",
    },
    {
      id: "finding",
      label: "Review first finding",
      done: findingsCount > 0,
      detail: findingsCount ? `${findingsCount} finding${findingsCount === 1 ? "" : "s"} ready to review` : "Open Findings after the first results land",
    },
  ];
}

function onboardingChecklistComplete() {
  return onboardingChecklistItems().every((item) => item.done);
}

function renderOnboardingChecklist(container, { surface }) {
  if (!container) return;
  const show =
    !onboardingChecklistComplete() &&
    surface === "mission-control" &&
    state.engagements.length;
  if (!show) {
    container.innerHTML = "";
    container.classList.add("hidden");
    return;
  }
  const items = onboardingChecklistItems();
  const completed = items.filter((item) => item.done).length;
  const ctaLabel = currentOnboardingState().visible ? "Continue setup" : "Open setup";
  const compact = surface === "wizard" || surface === "mission-control";
  container.classList.remove("hidden");
  container.innerHTML = `
    <article class="panel onboarding-checklist-card ${compact ? "onboarding-checklist-compact" : ""}" data-testid="${escapeHtml(`${surface}-onboarding-checklist`)}">
      <div class="panel-head">
        <div>
          <p class="eyebrow">Getting Started</p>
          <h3>Setup Checklist</h3>
        </div>
        <div class="onboarding-checklist-head-actions">
          <span class="badge">${escapeHtml(`${completed} / ${items.length} complete`)}</span>
          <button class="action ghost compact-action" type="button" data-onboarding-rerun data-testid="${escapeHtml(`${surface}-onboarding-open`)}">
            ${escapeHtml(ctaLabel)}
          </button>
        </div>
      </div>
      ${
        compact
          ? ""
          : `
            <p class="screen-copy onboarding-checklist-copy">
              Finish the operator basics once, then AegisPT keeps those defaults for the next mission.
            </p>
          `
      }
      <div class="onboarding-checklist-grid">
        ${items
          .map(
            (item) => `
              <div class="onboarding-checklist-item ${item.done ? "is-complete" : ""}">
                <span class="onboarding-checklist-mark" aria-hidden="true">${item.done ? "✓" : "○"}</span>
                <div>
                  <strong>${escapeHtml(item.label)}</strong>
                  <span>${escapeHtml(item.detail)}</span>
                </div>
              </div>
            `
          )
          .join("")}
      </div>
      ${
        compact
          ? ""
          : `
            <div class="settings-oauth-actions onboarding-checklist-actions">
              ${
                state.engagements.length && !items.find((item) => item.id === "finding")?.done
                  ? `<button class="action ghost compact-action" type="button" data-nav-screen="findings-theater">Open Findings</button>`
                  : ""
              }
            </div>
          `
      }
    </article>
  `;
}

function renderOnboardingOverlay() {
  const container = dom.onboardingOverlayRoot;
  if (!container) return;
  const onboarding = ensureOnboardingState();
  if (!onboarding.visible) {
    container.innerHTML = "";
    container.classList.remove("is-visible");
    return;
  }
  const provider = String(onboarding.values?.provider || "disabled").trim().toLowerCase();
  const scopeValue = String(onboarding.values?.defaultScope || "").trim();
  const actorName = String(onboarding.values?.actorName || "").trim();
  const scopeValid = !scopeValue || isLikelyCidr(scopeValue);
  const canPersist = scopeValid;
  const activeEngagement = selectedEngagement();
  const stepBodies = [
    `
      <div class="onboarding-step-copy">
        <p class="eyebrow">Step 1 of 3</p>
        <h3>Welcome to AegisPT</h3>
        <p>Set the few defaults that matter most, then launch your first mission without hunting through the full settings screen.</p>
      </div>
      <div class="onboarding-step-actions">
        <button class="action primary" type="button" data-onboarding-step="1" data-testid="onboarding-start-setup">Start setup</button>
        <button class="action ghost" type="button" data-onboarding-dismiss="skip" data-testid="onboarding-skip-welcome">Skip for now</button>
      </div>
    `,
    `
      <div class="onboarding-step-copy">
        <p class="eyebrow">Step 2 of 3</p>
        <h3>Quick setup</h3>
        <p>Everything here is optional. Save what helps and leave the rest for later.</p>
      </div>
      <div class="onboarding-setup-grid">
        <section class="onboarding-setup-card" data-testid="onboarding-ai-provider-card">
          <div>
            <p class="eyebrow">AI Provider</p>
            <h4>Connect AI provider</h4>
          </div>
          <p>Choose the operator default now. ChatGPT OAuth authorization stays engagement-scoped, so a fresh install finishes the connection after the first mission exists.</p>
          <div class="onboarding-choice-row">
            <button class="action ${provider === "chatgpt_oauth" ? "primary" : "ghost"} compact-action" type="button" data-onboarding-provider="chatgpt_oauth" data-testid="onboarding-provider-chatgpt">Use ChatGPT OAuth</button>
            <button class="action ${provider === "disabled" ? "ghost" : "ghost"} compact-action" type="button" data-onboarding-provider="disabled">Skip for now</button>
            ${
              provider === "chatgpt_oauth" && state.selectedEngagementId
                ? `<button class="action ghost compact-action" type="button" data-onboarding-connect-chatgpt>Connect now</button>`
                : ""
            }
          </div>
          <p class="settings-subtle-note">
            ${
              provider === "chatgpt_oauth"
                ? activeEngagement
                  ? "This engagement can authorize ChatGPT OAuth immediately."
                  : "The provider default is saved now; the engagement-scoped OAuth session can be connected after the first mission is created."
                : "AI stays disabled until you explicitly turn it on later."
            }
          </p>
        </section>
        <section class="onboarding-setup-card" data-testid="onboarding-default-scope-card">
          <div>
            <p class="eyebrow">Scope default</p>
            <h4>Set default network scope</h4>
          </div>
          <label class="field">
            <span>LAN CIDR</span>
            <input
              type="text"
              value="${escapeHtml(scopeValue)}"
              data-onboarding-field="defaultScope"
              data-testid="onboarding-default-scope-input"
              placeholder="10.0.0.0/8"
            />
          </label>
          <div class="pill-grid onboarding-preset-row">
            ${onboardingScopePresets()
              .map(
                (preset) => `
                  <button class="badge" type="button" data-onboarding-scope-preset="${escapeHtml(preset)}">
                    ${escapeHtml(preset)}
                  </button>
                `
              )
              .join("")}
          </div>
          ${
            !scopeValid
              ? `<p class="settings-inline-warning" data-testid="onboarding-default-scope-warning">Enter a valid CIDR such as 10.0.0.0/8 or leave this blank for now.</p>`
              : `<p class="settings-subtle-note">This becomes the suggested LAN scope in Intake. It does not change active missions.</p>`
          }
        </section>
        <section class="onboarding-setup-card" data-testid="onboarding-actor-card">
          <div>
            <p class="eyebrow">Shell identity</p>
            <h4>Actor name</h4>
          </div>
          <label class="field">
            <span>Operator label</span>
            <input
              type="text"
              value="${escapeHtml(actorName)}"
              data-onboarding-field="actorName"
              data-testid="onboarding-actor-name-input"
              placeholder="operator-ui"
            />
          </label>
          <p class="settings-subtle-note">This becomes the default actor name in the topbar and settings.</p>
        </section>
      </div>
      <div class="onboarding-step-actions">
        <button class="action ghost" type="button" data-onboarding-step="0">Back</button>
        <button class="action primary" type="button" data-onboarding-step="2" ${canPersist ? "" : "disabled"} data-testid="onboarding-continue-ready">Continue</button>
      </div>
    `,
    `
      <div class="onboarding-step-copy">
        <p class="eyebrow">Step 3 of 3</p>
        <h3>Ready to go</h3>
        <p>These defaults are about to be saved as operator-facing setup only. You can re-run this flow later from Settings &gt; Instance.</p>
      </div>
      <div class="onboarding-ready-grid" data-testid="onboarding-ready-summary">
        <div class="onboarding-ready-card">
          <span class="eyebrow">AI Provider</span>
          <strong>${escapeHtml(provider === "disabled" ? "Skipped for now" : "ChatGPT OAuth")}</strong>
          <span>${escapeHtml(provider === "chatgpt_oauth" && !state.selectedEngagementId ? "OAuth session completes after the first mission exists." : "Saved as the operator default.")}</span>
        </div>
        <div class="onboarding-ready-card">
          <span class="eyebrow">Default Scope</span>
          <strong>${escapeHtml(scopeValue || "Not set")}</strong>
          <span>${escapeHtml(scopeValue ? "Will prefill LAN intake defaults." : "You can add this later in Settings.")}</span>
        </div>
        <div class="onboarding-ready-card">
          <span class="eyebrow">Actor Name</span>
          <strong>${escapeHtml(actorName || "operator-ui")}</strong>
          <span>Used for operator-facing requests and audit labels.</span>
        </div>
      </div>
      ${onboarding.error ? `<p class="settings-inline-warning">${escapeHtml(onboarding.error)}</p>` : ""}
      <div class="onboarding-step-actions">
        <button class="action ghost" type="button" data-onboarding-step="1">Back</button>
        <button class="action ghost" type="button" data-onboarding-dismiss="persist" ${canPersist ? "" : "disabled"} data-testid="onboarding-explore-first">Explore first</button>
        <button class="action primary" type="button" data-onboarding-launch ${canPersist ? "" : "disabled"} data-testid="onboarding-run-first-scan">
          ${onboarding.saving ? "Saving..." : "Run your first scan →"}
        </button>
      </div>
    `,
  ];
  container.classList.add("is-visible");
  container.innerHTML = `
    <div class="onboarding-overlay-shell" data-testid="onboarding-overlay">
      <div class="onboarding-modal">
        <div class="onboarding-progress">
          ${[0, 1, 2]
            .map(
              (stepIndex) => `
                <span class="onboarding-progress-step ${stepIndex === onboarding.step ? "is-current" : stepIndex < onboarding.step ? "is-complete" : ""}">
                  ${escapeHtml(String(stepIndex + 1))}
                </span>
              `
            )
            .join("")}
        </div>
        ${stepBodies[onboarding.step] || stepBodies[0]}
      </div>
    </div>
  `;
}

function applyOnboardingDefaultsToWizard() {
  const onboarding = ensureOnboardingState();
  const scopeValue = String(onboarding.values?.defaultScope || "").trim();
  const nextWizard = buildEmptyWizardState();
  if (scopeValue) {
    nextWizard.intake.flowMode = "tile";
    nextWizard.intake.selectedAssessmentTileKey = "internal-lan";
    nextWizard.intake.activeQuestionId = "scope";
    nextWizard.intake.draftAnswer = scopeValue;
    nextWizard.intake.sources.intent = "confirmed";
    nextWizard.intake.sources.target_type = "confirmed";
    nextWizard.intake.sources.scope = "confirmed";
    nextWizard.data.assessment_type = "Internal Range / LAN";
    nextWizard.data.targets.cidr_ranges = [scopeValue];
    nextWizard.data.intake_preferences.mission_intent = "Internal LAN assessment";
  }
  patchState({ wizard: nextWizard }, "onboarding.prefillWizard");
}

async function persistOnboardingState({ persistDraft, launchWizard }) {
  const onboarding = ensureOnboardingState();
  const scopeValue = String(onboarding.values?.defaultScope || "").trim();
  if (scopeValue && !isLikelyCidr(scopeValue)) {
    patchState(
      {
        onboarding: {
          ...onboarding,
          step: 2,
          error: "Enter a valid CIDR such as 10.0.0.0/8 or leave the scope blank for now.",
        },
      },
      "onboarding.invalidScope"
    );
    renderAll();
    return;
  }

  const patch = {
    "instance.onboarding_completed": true,
  };
  if (persistDraft) {
    const providerValue = String(onboarding.values?.provider || "disabled").trim().toLowerCase() || "disabled";
    const actorName = String(onboarding.values?.actorName || "").trim();
    patch["ai.provider"] = providerValue;
    if (scopeValue) {
      patch["network.default_lan_cidr"] = scopeValue;
    }
    if (actorName) {
      patch["instance.operator_display_name"] = actorName;
    }
  }

  patchState(
    {
      onboarding: {
        ...onboarding,
        saving: true,
        error: null,
      },
    },
    "onboarding.save.start"
  );
  renderAll();

  const updated = await api("/api/v1/settings", {
    method: "PATCH",
    body: { settings: patch },
  });

  const actorName = String(onboarding.values?.actorName || "").trim();
  if (persistDraft && actorName) {
    state.actor = actorName;
    window.localStorage.setItem("aegispt-actor", actorName);
  }

  patchState(
    {
      operatorSettings: updated,
      onboarding: {
        ...buildEmptyOnboardingState(),
        initialized: true,
        visible: false,
        values: buildOnboardingDraft(),
      },
    },
    "onboarding.save.complete"
  );

  if (launchWizard) {
    applyOnboardingDefaultsToWizard();
    navigateToScreen("wizard");
    runtime.actions.pushStatus?.("First-run defaults saved. Intake is ready for your first mission.", "success");
    return;
  }
  renderAll();
  runtime.actions.pushStatus?.(
    "Onboarding saved. Re-open it from Settings > Instance whenever you want to recheck the defaults.",
    "info"
  );
}

async function dismissOnboarding({ persistDraft }) {
  await persistOnboardingState({ persistDraft, launchWizard: false });
}

async function completeOnboardingAndLaunchWizard() {
  await persistOnboardingState({ persistDraft: true, launchWizard: true });
}

function renderOnboardingExperience() {
  ensureOnboardingState();
  renderOnboardingChecklist(dom.wizardOnboardingChecklist, { surface: "wizard" });
  renderOnboardingChecklist(dom.missionOnboardingChecklist, { surface: "mission-control" });
  renderOnboardingOverlay();
}

function canCancelSelectedRun() {
  const run = state.selectedRun;
  if (!run?.id) return false;
  const status = String(run.status || "").toLowerCase();
  if (RUN_STREAM_TERMINAL_STATUSES.has(status) || ["cancelling", "pending_approval", "rejected"].includes(status)) {
    return false;
  }
  return (run.tasks || []).some((task) => ["queued", "running"].includes(String(task.status || "").toLowerCase()));
}

async function cancelSelectedRun() {
  if (!state.selectedRun?.id) {
    pushStatus("Select a run before using the kill switch.", "warning");
    return;
  }
  if (!canCancelSelectedRun()) {
    pushStatus("Kill switch is unavailable because the selected run has no queued or running tasks.", "warning");
    updateMissionActionStates();
    return;
  }
  pushStatus("Cancelling queued/running tasks for the selected run.", "warning");
  await api(`/api/v1/runs/${state.selectedRun.id}/cancel`, { method: "POST" });
  await refreshSelectedEngagement();
  pushStatus("Run cancellation was recorded. Mission Control has been refreshed.", "success");
}

function updateMissionActionStates() {
  const dispatchEnabled = Boolean(missionModule?.canDispatchSelectedRun?.());
  if (dom.missionDispatchBtn) {
    dom.missionDispatchBtn.classList.toggle("hidden", !dispatchEnabled);
    dom.missionDispatchBtn.disabled = !dispatchEnabled;
    if (dispatchEnabled) {
      dom.missionDispatchBtn.setAttribute("data-testid", "mission-dispatch");
      dom.missionDispatchBtn.title = "Dispatch queued validation tasks for the selected run.";
    } else {
      dom.missionDispatchBtn.removeAttribute("data-testid");
      dom.missionDispatchBtn.title = "No queued validation tasks are ready for dispatch.";
    }
  }
  if (!dom.missionKillRunBtn) return;
  const enabled = canCancelSelectedRun();
  dom.missionKillRunBtn.disabled = !enabled;
  dom.missionKillRunBtn.title = enabled
    ? "Cancel queued or running tasks for the selected run."
    : "No queued or running tasks can be cancelled for the selected run.";
}

function renderSelectedEngagementSummary() {
  if (!dom.selectedEngagementSummary) return;
  const currentRun = state.selectedRun;
  const status = String(currentRun?.status || "").toLowerCase();
  const tasks = currentRun?.tasks || [];
  const queuedTasks = tasks.filter((task) => String(task.status || "").toLowerCase() === "queued").length;
  const runningTasks = tasks.filter((task) => String(task.status || "").toLowerCase() === "running").length;
  const runStatusVisible = Boolean(currentRun) && (queuedTasks > 0 || runningTasks > 0 || RUN_STREAM_ACTIVE_STATUSES.has(status));
  if (!runStatusVisible) {
    dom.selectedEngagementSummary.innerHTML = "";
    dom.selectedEngagementSummary.classList.add("hidden");
    return;
  }
  const chain = currentRun?.assessment_chain || null;
  const phaseIndex = Math.max(0, Number(chain?.current_phase_index || 0));
  const phaseLabel =
    chain?.phases?.[phaseIndex]?.label ||
    currentRun?.profile?.name ||
    currentRun?.configuration_json?.execution_profile ||
    "Execution";
  const runLabel =
    currentRun?.profile?.name ||
    currentRun?.configuration_json?.test_profile ||
    currentRun?.id ||
    "Run active";
  const totalTasks = Math.max(tasks.length, 1);
  const finishedTasks = tasks.filter((task) =>
    ["completed", "completed_with_errors", "failed", "cancelled", "skipped"].includes(String(task.status || "").toLowerCase())
  ).length;
  const progress = Math.min(100, Math.round((finishedTasks / totalTasks) * 100));
  const runCardState = runningTasks ? "Active Run" : queuedTasks ? "Queued Run" : "Run";
  const taskStateCount = runningTasks || queuedTasks || tasks.length || 0;
  const taskStateLabel = runningTasks ? "running" : queuedTasks ? "queued" : "tracked";
  dom.selectedEngagementSummary.classList.remove("hidden");
  dom.selectedEngagementSummary.innerHTML = `
    <div class="sidebar-run-indicator run-card-active" data-testid="sidebar-active-run-indicator">
      <p class="run-card-label">${escapeHtml(runCardState)}</p>
      <p class="run-card-name">${escapeHtml(`${runLabel} · ${taskStateCount} ${taskStateLabel} ${taskStateCount === 1 ? "task" : "tasks"}`)}</p>
      <div class="run-card-progress" aria-hidden="true"><span style="width:${progress}%"></span></div>
      <p class="run-card-meta"><span class="sidebar-run-indicator-dot state-${escapeHtml(status || "idle")}"></span>${escapeHtml(phaseLabel)}</p>
    </div>
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
  if (dom.sidebarNav) {
    const findingCount = selectedRunFindings().length || engagementFindings().length;
    const proposalCount = pendingAiProposalCount();
    dom.sidebarNav.innerHTML = NAV_GROUPS
      .map((item) => {
        if (item.kind === "section") {
          return `<p class="sidebar-section-label">${escapeHtml(item.label)}</p>`;
        }
        if (item.kind === "spacer") {
          return `<div class="sidebar-nav-spacer" aria-hidden="true"></div>`;
        }
        const active = item.screen === state.activeScreen;
        const badge = item.count === "findings" && findingCount
          ? `<span class="sb-count">${escapeHtml(String(findingCount))}</span>`
          : "";
        const proposalBadge = item.screen === "mission-control" && proposalCount
          ? `<span class="sb-count ai-proposal-nav-count" data-testid="nav-mission-control-ai-proposals">${escapeHtml(`● ${proposalCount}`)}</span>`
          : "";
        return `
          <button
            class="sb-item sidebar-link ${active ? "active" : ""} ${item.utility ? "utility" : ""}"
            type="button"
            data-nav-screen="${escapeHtml(item.screen)}"
            data-testid="${escapeHtml(item.testId)}"
            aria-current="${active ? "page" : "false"}"
          >
            <span class="sb-left"><span class="sb-icon">${escapeHtml(item.icon)}</span>${escapeHtml(item.label)}</span>
            ${proposalBadge || badge}
          </button>
        `;
      })
      .join("");
  }
  if (dom.sidebarCompatibilityNav) {
    dom.sidebarCompatibilityNav.innerHTML = "";
  }
  document.querySelectorAll("[data-nav-screen='settings']").forEach((button) => {
    button.classList.toggle("active", state.activeScreen === "settings");
    button.setAttribute("aria-current", state.activeScreen === "settings" ? "page" : "false");
  });
  if (dom.nextActions) {
    dom.nextActions.innerHTML = "";
  }
  if (dom.sidebarMetrics) {
    dom.sidebarMetrics.innerHTML = "";
  }
  if (dom.phaseFeedCard) {
    dom.phaseFeedCard.classList.add("hidden");
  }
  updateMissionActionStates();
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
  if (missionModule.canDispatchSelectedRun()) {
    actions.push({ label: "Start Queued Checks", action: "dispatch-run", phase: "execution" });
  }
  if (discoveryReady && !findings.length) {
    actions.push({
      label: "Identify Discovered Services",
      action: "follow-up-launch",
      strategy: "service-enumeration",
      phase: "execution",
    });
    actions.push({ label: "Open Surface Map", screen: "surface-map", phase: "execution" });
    actions.push({ label: "Review Dossier in Reports", screen: "report-center", phase: "analysis" });
  }
  if (findings.length) {
    actions.push({ label: "Review Findings + Evidence", screen: "findings-theater", phase: "analysis" });
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
    actions.push({ label: "Open Report Dossier", screen: "report-center", phase: "analysis" });
  }
  return actions.slice(0, 3);
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

function renderAgentsScreen() {
  if (!dom.agentsContent) return;
  const run = state.selectedRun;
  if (!run) {
    dom.agentsContent.innerHTML = `
      <article class="panel agents-empty" data-testid="agents-empty-state">
        <p class="eyebrow">Agents</p>
        <h3>No run selected</h3>
        <p>Select or create a mission before reviewing live task cards.</p>
        <div class="panel-actions">
          <button class="action primary" type="button" data-nav-screen="wizard">New Mission</button>
          <button class="action secondary" type="button" data-nav-screen="dashboard">Dashboard</button>
        </div>
      </article>
    `;
    return;
  }
  const cards = buildAgentCardsForRun(run);
  const findings = selectedRunFindings();
  const queuedCount = cards.filter((card) => card.status === "queued").length;
  const runningCount = cards.filter((card) => card.status === "running").length;
  const completedCount = cards.filter((card) => card.status === "completed").length;
  const selectedLiveCard =
    cards.find((card) => card.status === "running" && String(card.id || "") === String(state.selectedTaskId || "")) ||
    cards.find((card) => card.status === "running") ||
    null;
  const primaryCards = primaryAgentCards(cards);
  const primaryCardIds = new Set(primaryCards.map((card) => String(card.id || "")));
  const archiveCards = cards.filter((card) => !primaryCardIds.has(String(card.id || "")));
  const proposalCount = Array.isArray(state.selectedAiInsights?.proposals)
    ? state.selectedAiInsights.proposals.length
    : 0;
  dom.agentsContent.innerHTML = `
    <section class="agents-command-strip" data-testid="agents-command-strip">
      <div>
        <p class="eyebrow">Selected Run</p>
        <h3>${escapeHtml(run.profile?.name || run.configuration_json?.test_profile || "Assessment run")}</h3>
        <p>${escapeHtml(run.id || "run")}</p>
      </div>
      <div class="agents-metrics">
        <span class="metric-pill">${escapeHtml(`${cards.length} task cards`)}</span>
        <span class="metric-pill">${escapeHtml(`${queuedCount} queued`)}</span>
        <span class="metric-pill">${escapeHtml(`${runningCount} running`)}</span>
        <span class="metric-pill">${escapeHtml(`${completedCount} completed`)}</span>
        <span class="metric-pill">${escapeHtml(`${findings.length} findings`)}</span>
        <span class="metric-pill">${escapeHtml(`${proposalCount} AI proposals`)}</span>
      </div>
      <div class="screen-actions">
        ${missionModule.canDispatchSelectedRun() ? `<button class="action primary" type="button" data-run-dispatch="selected">Start Queued Checks</button>` : ""}
        <button class="action secondary" type="button" data-run-cancel-selected="true" ${canCancelSelectedRun() ? "" : "disabled"}>Stop All</button>
        <button class="action primary" type="button" data-nav-screen="mission-control">Back to Mission Control</button>
      </div>
    </section>
    ${renderLiveAgentFocus(selectedLiveCard, queuedCount)}
    ${
      primaryCards.length
        ? `<div class="agents-grid" data-testid="agents-live-grid">${primaryCards.map(renderAgentCard).join("")}</div>`
        : `
          <article class="panel agents-empty">
            ${emptyState("No task cards are attached to this run yet.", {
              label: "Open Mission Control",
              screen: "mission-control",
            })}
          </article>
        `
    }
    ${renderAgentArchive(archiveCards, { queuedCount, completedCount })}
    ${renderAgentProposalLedger()}
  `;
}

function primaryAgentCards(cards) {
  const runningCards = cards.filter((card) => card.status === "running");
  if (runningCards.length) return runningCards;
  const failedCards = cards.filter((card) => ["failed", "blocked"].includes(card.status));
  if (failedCards.length) return failedCards;
  const queuedCards = cards.filter((card) => card.status === "queued");
  if (queuedCards.length) return queuedCards;
  return cards.slice(0, 3);
}

function renderAgentArchive(cards, counts = {}) {
  if (!cards.length) return "";
  const queuedCount = Number(counts.queuedCount || 0);
  const completedCount = Number(counts.completedCount || 0);
  return `
    <details class="panel agents-archive" data-testid="agents-archive">
      <summary>
        <span>Queued/completed task history</span>
        <span>${escapeHtml(`${queuedCount} queued · ${completedCount} completed`)}</span>
      </summary>
      <div class="agents-grid">
        ${cards.map(renderAgentCard).join("")}
      </div>
    </details>
  `;
}

function buildAgentCardsForRun(run) {
  return (run.tasks || []).map((task, index) => {
    const params = task.params_json || {};
    const autonomous = params.autonomous_agent || {};
    const matchedFindings = selectedRunFindings().filter((finding) => {
      const evidenceTaskId = finding.evidence_json?.task_id || finding.provenance_json?.task_id || finding.task_id;
      return evidenceTaskId && String(evidenceTaskId) === String(task.id);
    });
    return {
      id: task.id,
      label: autonomous.enabled ? `Agent #${autonomous.sequence || index + 1}` : `Agent #${index + 1}`,
      name: formatAgentToolLabel(task.tool),
      target: task.target_id || params.target || params.url || "approved scope",
      status: String(task.status || "unknown").toLowerCase(),
      statusLabel: String(task.status || "unknown"),
      findingsCount: matchedFindings.length,
      riskTier: autonomous.risk_tier || params.run_class || params.profile_name || "bounded",
      source: autonomous.source_tool || params.source_tool || "run task",
      updatedAt: task.updated_at || task.created_at,
      stdout: stdoutPreviewForTask(task),
      reason: taskReasonLine(task),
    };
  }).sort((left, right) => {
    const statusDelta = agentStatusSortRank(left.status) - agentStatusSortRank(right.status);
    if (statusDelta !== 0) return statusDelta;
    return timestampMs(right.updatedAt) - timestampMs(left.updatedAt);
  });
}

function agentStatusSortRank(status) {
  const normalized = String(status || "").toLowerCase();
  if (normalized === "running") return 0;
  if (["failed", "blocked"].includes(normalized)) return 1;
  if (normalized === "queued") return 2;
  if (normalized === "skipped") return 3;
  if (normalized === "completed") return 4;
  return 5;
}

function timestampMs(value) {
  const timestamp = new Date(value || 0).getTime();
  return Number.isFinite(timestamp) ? timestamp : 0;
}

function latestStoredStdoutForTask(task) {
  if (String(state.selectedTask?.id || "") !== String(task?.id || "")) return "";
  const executions = Array.isArray(state.selectedTask?.executions) ? state.selectedTask.executions : [];
  const latestExecution = [...executions].sort(
    (left, right) => new Date(right.created_at || 0).getTime() - new Date(left.created_at || 0).getTime()
  )[0];
  return String(latestExecution?.stdout_text || latestExecution?.stderr_text || "").trim();
}

function stdoutPreviewForTask(task) {
  const stream = state.taskStdoutStream || {};
  const attached = String(stream.taskId || "") === String(task?.id || "");
  const lines = attached && Array.isArray(stream.lines) ? stream.lines.map((line) => String(line?.text || "")).filter(Boolean) : [];
  if (lines.length) return lines.slice(-6).join("\n");
  const storedStdout = latestStoredStdoutForTask(task);
  if (storedStdout) return storedStdout.split("\n").slice(-6).join("\n");
  if (String(task?.status || "").toLowerCase() === "queued") return "queued: waiting for controlled dispatch";
  if (String(task?.status || "").toLowerCase() === "running") return "running: waiting for first safe stdout line from the bounded runner";
  if (String(task?.status || "").toLowerCase() === "skipped") return task?.params_json?.skip_reason || "skipped: prerequisites or eligible evidence were not available for this check";
  if (["failed", "blocked"].includes(String(task?.status || "").toLowerCase())) return task?.params_json?.failure_reason || "failed: open Mission Control for runner evidence and safe recovery action";
  return "no stdout tail recorded for this task yet";
}

function taskReasonLine(task) {
  const params = task?.params_json || {};
  return params.reason || params.rationale || params.profile_name || "Existing run task under the selected mission scope.";
}

function renderAgentCard(card) {
  const selected = String(card.id || "") === String(state.selectedTaskId || "");
  return `
    <button
      class="panel agent-card status-${escapeHtml(card.status)} ${selected ? "selected" : ""}"
      type="button"
      data-agent-task-pick="${escapeHtml(String(card.id || ""))}"
      data-testid="agent-card"
    >
      <div class="agent-card-head">
        <span>${escapeHtml(card.label)}</span>
        ${statusPill(card.statusLabel)}
      </div>
      <h3>${escapeHtml(`${card.name} on ${card.target}`)}</h3>
      <div class="agents-metrics">
        <span class="metric-pill">${escapeHtml(card.riskTier)}</span>
        <span class="metric-pill">${escapeHtml(`${card.findingsCount} findings`)}</span>
        <span class="metric-pill">${escapeHtml(card.source)}</span>
      </div>
      <p>${escapeHtml(card.reason)}</p>
      <pre class="agent-terminal" data-testid="agent-card-terminal">${escapeHtml(card.stdout)}</pre>
      <p class="micro-copy">${escapeHtml(`Last change ${formatDateTime(card.updatedAt)}`)}</p>
    </button>
  `;
}

function renderLiveAgentFocus(card, queuedCount = 0) {
  if (!card) {
    if (!queuedCount) return "";
    return `
      <article class="panel agents-live-focus" data-testid="agents-live-focus">
        <p class="eyebrow">Live Task</p>
        <h3>No task is running yet</h3>
        <p>${escapeHtml(`${queuedCount} queued task${queuedCount === 1 ? "" : "s"} are ready for the controlled runtime boundary.`)}</p>
        <div class="panel-actions">
          <button class="action primary" type="button" data-run-dispatch="selected">Start Queued Checks</button>
          <button class="action ghost" type="button" data-nav-screen="mission-control">Open Mission Control</button>
        </div>
      </article>
    `;
  }
  return `
    <article class="panel agents-live-focus" data-testid="agents-live-focus">
      <div class="panel-head">
        <div>
          <p class="eyebrow">Live Task</p>
          <h3>${escapeHtml(`${card.name} on ${card.target}`)}</h3>
        </div>
        ${statusPill(card.statusLabel)}
      </div>
      <p>${escapeHtml(card.reason)}</p>
      <pre class="agent-terminal is-live" data-testid="agents-live-terminal">${escapeHtml(card.stdout)}</pre>
      <p class="micro-copy">${escapeHtml(`Streaming selected task ${card.id}`)}</p>
    </article>
  `;
}

function renderAgentProposalLedger() {
  const proposals = Array.isArray(state.selectedAiInsights?.proposals) ? state.selectedAiInsights.proposals : [];
  const reasoning = Array.isArray(state.selectedAiInsights?.reasoning_records)
    ? state.selectedAiInsights.reasoning_records
    : [];
  if (!proposals.length && !reasoning.length) return "";
  return `
    <article class="panel agents-ledger" data-testid="agents-ledger">
      <div class="panel-head">
        <div>
          <p class="eyebrow">AI Signal</p>
          <h3>Proposal Ledger</h3>
        </div>
      </div>
      <div class="agents-ledger-list">
        ${proposals.slice(0, 5).map((proposal) => `
          <div class="agent-ledger-row">
            <strong>${escapeHtml(proposal.title || proposal.proposal_type || "AI proposal")}</strong>
            <span>${escapeHtml(proposal.status || "review")}</span>
          </div>
        `).join("")}
        ${reasoning.slice(0, 5).map((record) => `
          <div class="agent-ledger-row">
            <strong>${escapeHtml(record.reasoning_type || record.title || "Reasoning record")}</strong>
            <span>${escapeHtml(record.status || "stored")}</span>
          </div>
        `).join("")}
      </div>
    </article>
  `;
}

function formatAgentToolLabel(tool) {
  const mapping = {
    httpx: "HTTP probe",
    nmap: "Network discovery",
    nuclei: "Template validation",
    semgrep: "Code pattern check",
    zap: "Active web validation",
  };
  return mapping[String(tool || "").toLowerCase()] || String(tool || "Task agent");
}

function renderActiveScreen() {
  const renderers = {
    dashboard: dashboardModule.renderDashboard,
    wizard: wizardModule.renderWizard,
    "mission-control": missionModule.renderMissionControl,
    agents: renderAgentsScreen,
    "surface-map": missionModule.renderSurfaceMap,
    "problems-center": problemsModule.renderProblemsCenter,
    "custom-vulnerabilities": customVulnerabilitiesModule.renderCustomVulnerabilityLibrary,
    research: researchModule.renderResearchLab,
    "findings-theater": findingsModule.renderFindingsTheater,
    "evidence-replay": findingsModule.renderEvidenceReplay,
    "pack-forge": packsModule.renderPackForge,
    "report-center": reportsModule.renderReportCenter,
    explorer: explorerHistoryModule.renderExplorer,
    history: explorerHistoryModule.renderHistoryComparison,
    settings: settingsModule.renderSettingsScreen,
  };
  (renderers[state.activeScreen] || wizardModule.renderWizard)();
}

function navigateToScreen(screen) {
  state.activeScreen = screen || "wizard";
  state.activePhase = phaseForScreen(state.activeScreen);
  renderAll();
  scrollScreenToTop();
  if (state.activeScreen === "dashboard") {
    dashboardModule.loadDashboard().then(renderAll).catch(handleError);
  }
  if (state.activeScreen === "problems-center") {
    problemsModule.loadProblems().then(renderAll).catch(handleError);
  }
  if (state.activeScreen === "custom-vulnerabilities") {
    customVulnerabilitiesModule.loadCustomVulnerabilities().then(renderAll).catch(handleError);
  }
  if (state.activeScreen === "research") {
    researchModule.loadResearchLab().then(renderAll).catch(handleError);
  }
  if (["history", "report-center"].includes(state.activeScreen)) {
    ensureComparisonFindings().then(renderAll).catch(handleError);
  }
  if (state.activeScreen === "settings") {
    Promise.allSettled([
      settingsModule.loadSettings(),
      settingsModule.loadDiagnostics(),
      settingsModule.loadSettingsReadiness(),
      settingsModule.loadEnterpriseIdentityStatus(),
      settingsModule.loadChatGPTStatus(),
      settingsModule.loadScheduledRuns(),
      settingsModule.loadCicdTriggerSettings(),
      settingsModule.loadJiraIntegrationSettings(),
      settingsModule.loadSiemIntegrationSettings(),
      settingsModule.loadThreatIntelControls(),
      settingsModule.loadApiKeys(),
    ])
      .then(() => renderAll());
  }
  if (window.innerWidth <= 1400) {
    const activeScreen = document.getElementById(`screen-${state.activeScreen}`);
    activeScreen?.scrollIntoView({ behavior: "smooth", block: "start" });
  }
}

function scrollScreenToTop() {
  window.requestAnimationFrame(() => {
    document.querySelector(".stage")?.scrollTo?.({ top: 0, left: 0 });
    document.querySelector(".workspace")?.scrollTo?.({ top: 0, left: 0 });
    window.scrollTo({ top: 0, left: 0 });
  });
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
  if (dom.phaseSubnavTitle) {
    dom.phaseSubnavTitle.textContent = "Navigation";
  }
}

function renderPhaseFeedCard() {
  if (!dom.phaseFeedCard || !dom.phaseFeedTitle || !dom.phaseFeedKicker) return;
  dom.phaseFeedCard.classList.add("hidden");
  dom.phaseFeedTitle.textContent = "Recent Signals";
  dom.phaseFeedKicker.textContent = "Activity";
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
  if (phase === "home") return "dashboard";
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
    renderPhaseFeedCard();
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
  renderPhaseFeedCard();
  renderStatus();
}

function handleError(error) {
  const message = String(error?.message || "Unexpected UI error.");
  const humanized = /failed to fetch|networkerror/i.test(message)
    ? "UI could not reach the API. Refresh the page or confirm the service is still running."
    : message;
  pushStatus(humanized, "error");
}
