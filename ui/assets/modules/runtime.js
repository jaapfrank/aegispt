import { DEFAULT_MODULE_STATE, DEFAULT_SAFETY } from "./constants.js";

export function buildEmptyAccount() {
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

export function buildEmptyWizardState() {
  return {
    step: 0,
    advancedStep: 0,
    errors: [],
    useExistingEngagement: false,
    lastCreated: null,
    submitting: false,
    intake: {
      activeQuestionId: "intent",
      reviewQuestionId: null,
      draftAnswer: "",
      customAnswerOpen: false,
      flowMode: "tile",
      flowStep: 1,
      flowDepthChoice: "active",
      selectedAssessmentTileKey: "",
      selectedAssessmentTileKeys: [],
      advancedOpen: false,
      history: [],
      sources: {
        intent: "still-needed",
        target_type: "still-needed",
        goal: "still-needed",
        scope: "still-needed",
        auth: "still-needed",
        safety: "still-needed",
        boundaries: "still-needed",
        output: "still-needed",
      },
      overrides: {
        mission: false,
        assessment_type: false,
        scope: false,
        access: false,
        profile: false,
        modules: false,
        safety: false,
        boundaries: false,
      },
    },
    data: {
      engagement_name: "",
      client: "",
      roe_ref: "",
      authorization_confirmed: false,
      assessment_type: "Website / Web App",
      targets: {
        domains: [],
        subdomains: [],
        urls: [],
        ip_addresses: [],
        cidr_ranges: [],
        api_base_urls: [],
        wireless_sites: [],
        ssids: [],
        bssids: [],
      },
      access: {
        accounts: [buildEmptyAccount()],
        manual_auth_steps: "",
        cookie_notes: "",
      },
      exclusions: {
        domains: [],
        urls: [],
        ip_addresses: [],
        cidr_ranges: [],
        api_base_urls: [],
        ssids: [],
        bssids: [],
        notes: "",
      },
      wireless: {
        site: "",
        adapter: "",
        approved_ssids: [],
        approved_bssids: [],
        excluded_ssids: [],
        excluded_bssids: [],
        roe_acknowledged: false,
        passive_only: true,
        rf_disruptive_actions: false,
        handshake_capture: false,
        credential_harvesting: false,
        wps_pin_testing: false,
        evil_twin: false,
        jamming: false,
      },
      intake_preferences: {
        mission_intent: "",
        primary_goal: "",
        output_style: "",
        auth_strategy: "",
        safety_posture: "",
        boundary_handling: "",
        lateral_discovery: "not-requested",
      },
      assessment_mode: {
        mode: "",
        auto_advance_on_phase_complete: true,
        authorization_level: "passive",
        typed_scope_confirmation: "",
      },
      test_profile: "Standard",
      modules: { ...DEFAULT_MODULE_STATE },
      safety: { ...DEFAULT_SAFETY },
    },
  };
}

export function buildEmptyOnboardingState() {
  return {
    initialized: false,
    visible: false,
    forced: false,
    step: 0,
    saving: false,
    error: null,
    values: {
      provider: "disabled",
      defaultScope: "",
      actorName: "",
    },
  };
}

export const state = {
  actor: window.localStorage.getItem("aegispt-actor") || "operator-ui",
  currentActor: null,
  tenantId: window.localStorage.getItem("aegispt-tenant-id") || "",
  activeScreen: "wizard",
  activePhase: "intake",
  dashboard: null,
  dashboardLoading: false,
  dashboardError: null,
  dashboardHomeAutoRouted: false,
  problems: null,
  problemsLoading: false,
  problemsError: null,
  problemsUi: {
    selectedIds: [],
    expandedId: null,
    recentlyResolvedOpen: true,
    filters: {
      severity: "critical,high",
      status: "open",
      engagementId: "all",
      assignee: "all",
      age: "all",
      methodology: "all",
    },
  },
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
  reportComplianceFramework: "nis2",
  reportCenterView: "reports",
  reportFormat: "markdown",
  reportPreview: "",
  reportHtml: "",
  reportDraft: null,
  reportCatalog: [],
  remediationPortfolio: null,
  selectedRun: null,
  selectedAiInsights: null,
  selectedAiSignalStream: null,
  selectedCveIntelligence: null,
  exposureScore: null,
  chatgptOAuthStatus: null,
  operatorSettings: null,
  settingsReadiness: null,
  settingsReadinessLoading: false,
  settingsReadinessError: null,
  apiKeys: [],
  apiKeysLoading: false,
  apiKeysError: null,
  apiKeyCreateResult: null,
  scheduledRuns: [],
  scheduledRunsLoading: false,
  scheduledRunsError: null,
  settingsSaving: false,
  settingsError: null,
  settingsUi: {
    openPanels: {},
  },
  deleteUi: {
    selectedRunIds: [],
    selectedEngagementIds: [],
    modal: null,
  },
  onboarding: buildEmptyOnboardingState(),
  cicdTriggerSettings: null,
  cicdTriggerLoading: false,
  cicdTriggerSavingSource: null,
  cicdTriggerError: null,
  siemIntegrationSettings: null,
  siemIntegrationLoading: false,
  siemIntegrationSavingProvider: null,
  siemIntegrationError: null,
  jiraIntegrationConfiguration: null,
  jiraIntegrationLoadedEngagementId: null,
  jiraIntegrationLoading: false,
  jiraIntegrationSaving: false,
  jiraIntegrationTesting: false,
  jiraIntegrationTestResult: null,
  jiraIntegrationError: null,
  jiraPushFindingId: null,
  jiraBulkPushing: false,
  jiraFindingLinks: {},
  threatIntelStatus: null,
  threatIntelWatchlist: [],
  threatIntelRecords: [],
  threatIntelTemplateGeneratingId: null,
  threatIntelTemplateResult: null,
  threatIntelLoading: false,
  threatIntelSyncing: false,
  threatIntelError: null,
  customVulnerabilities: [],
  customVulnerabilityScanOptions: [],
  customVulnLoading: false,
  customVulnSaving: false,
  customVulnError: null,
  customVulnImportResult: null,
  customVulnExport: "",
  customVulnSelectedId: null,
  customVulnFilters: {
    q: "",
    product: "",
    severity: "all",
    status: "all",
  },
  selectedTask: null,
  selectedPackBundle: null,
  selectedFindingTheater: null,
  selectedFindingEvidence: null,
  selectedAttackPathSummary: null,
  selectedCodexResult: null,
  selectedCodexContext: null,
  selectedSurfaceAssetKey: null,
  surfaceAssetFilter: "",
  surfaceAssetQuery: "",
  surfaceView: "hotspots",
  historyQuery: "",
  surfaceOverlays: {
    hotspots: true,
    packZones: true,
    futureAttackPaths: false,
    futureIdentityGraph: false,
    futureRiskOverlay: false,
  },
  findingsUi: {
    filtersOpen: false,
    remediationOpen: false,
    view: "list",
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
  loading: {
    reportPreview: false,
    reportDraft: false,
    findingDetail: false,
    evidenceDetail: false,
    packAction: null,
    dispatchRunId: null,
    approvalRunId: null,
    approvalDecision: null,
  },
  runStream: {
    source: null,
    runId: null,
    status: "idle",
    fallbackReason: null,
    lastEventAt: null,
  },
  missionLaunch: {
    runId: null,
    createdAt: null,
  },
  taskStdoutStream: {
    source: null,
    taskId: null,
    status: "idle",
    sourceLabel: null,
    fallbackReason: null,
    lines: [],
    lineCount: 0,
    truncated: false,
    terminal: false,
    lastEventAt: null,
  },
  dispatchHintsByRunId: {},
  wizard: buildEmptyWizardState(),
};

export const dom = {};
export const statusFeed = [];
export const runtime = {
  state,
  dom,
  statusFeed,
  refreshTimer: null,
  taskStdoutPollTimer: null,
  taskStdoutPollTaskId: null,
  taskStdoutPollInFlight: false,
  actions: {},
};

const stateSubscribers = new Set();

export function getState() {
  return state;
}

export function patchState(patch, reason = "runtime.patch") {
  const updates = typeof patch === "function" ? patch(state) : patch;
  if (!updates || typeof updates !== "object" || Array.isArray(updates)) {
    return state;
  }
  Object.entries(updates).forEach(([key, value]) => {
    state[key] = value;
  });
  stateSubscribers.forEach((subscriber) => {
    subscriber({ state, patch: updates, reason });
  });
  return state;
}

export function subscribe(subscriber) {
  if (typeof subscriber !== "function") {
    return () => {};
  }
  stateSubscribers.add(subscriber);
  return () => {
    stateSubscribers.delete(subscriber);
  };
}

export function setRefreshTimer(timer) {
  runtime.refreshTimer = timer;
}
