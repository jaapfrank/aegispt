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

export const state = {
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
  loading: {
    reportPreview: false,
    findingDetail: false,
    evidenceDetail: false,
    packAction: null,
  },
  wizard: buildEmptyWizardState(),
};

export const dom = {};
export const statusFeed = [];
export const runtime = {
  state,
  dom,
  statusFeed,
  refreshTimer: null,
  actions: {},
};

export function setRefreshTimer(timer) {
  runtime.refreshTimer = timer;
}
