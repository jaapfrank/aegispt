import { api, apiOrNull } from "./api.js";
import { dom, patchState, runtime, state } from "./runtime.js";
import { escapeHtml } from "./shared.js";

const CICD_TRIGGER_SOURCES = [
  { id: "github", label: "GitHub Actions", defaultProfiles: ["passive-web-baseline"] },
  { id: "gitlab", label: "GitLab CI", defaultProfiles: ["passive-web-baseline"] },
  { id: "generic", label: "Generic Push", defaultProfiles: ["passive-web-baseline"] },
];

const SIEM_PROVIDERS = [
  {
    id: "splunk",
    label: "Splunk HEC",
    baseLabel: "HEC endpoint",
    basePlaceholder: "https://splunk.example.test/services/collector/event",
    routeLabel: "Index",
    routeField: "index_name",
    routePlaceholder: "aegispt_pentest",
    extraLabel: "Sourcetype",
    extraField: "sourcetype",
    extraPlaceholder: "aegispt:pentest:finding",
    credentialLabel: "HEC token",
  },
  {
    id: "elastic",
    label: "Elastic",
    baseLabel: "Cluster endpoint",
    basePlaceholder: "https://elastic.example.test",
    routeLabel: "Index",
    routeField: "index_name",
    routePlaceholder: "aegispt-findings",
    extraLabel: null,
    extraField: null,
    extraPlaceholder: null,
    credentialLabel: "API key",
  },
  {
    id: "sentinel",
    label: "Azure Sentinel",
    baseLabel: "Log ingestion endpoint",
    basePlaceholder: "https://sentinel.example.test/data-collection-endpoint",
    routeLabel: "Custom log table",
    routeField: "custom_log_table",
    routePlaceholder: "AegisPTFindings_CL",
    extraLabel: "Stream name",
    extraField: "stream_name",
    extraPlaceholder: "Custom-AegisPTFindings",
    credentialLabel: "Bearer token",
  },
];

const DEFAULT_SETTINGS_PANELS = Object.freeze({
  chatgpt_oauth: true,
  runtime_readiness: true,
  users: true,
  ai_provider: false,
  default_network_scope: false,
  default_scan_profile: false,
  runtime_execution: true,
  integrations: false,
  notifications: false,
  threat_intel: false,
  threat_intel_controls: true,
  scheduled_scans: true,
  data_retention: true,
  instance: false,
  engagement_siem: false,
  engagement_jira: false,
  engagement_cicd: false,
  siem_splunk: false,
  siem_elastic: false,
  siem_sentinel: false,
  cicd_github: false,
  cicd_gitlab: false,
  cicd_generic: false,
  cicd_history: false,
});

const AI_PROVIDER_PRIMARY_KEYS = new Set([
  "ai.provider",
  "ai.chatgpt_model",
  "ai.http_endpoint",
  "ai.http_api_key",
]);

const AI_FEATURE_SETTING_KEYS = new Set([
  "ai.finding_enrichment_enabled",
  "ai.post_task_analysis_enabled",
  "ai.intake_intelligence_enabled",
  "ai.autofix_enabled",
  "ai.report_drafting_enabled",
]);

export function createSettingsModule() {
  async function loadSettings() {
    const settings = await api("/api/v1/settings");
    patchState({ operatorSettings: settings, settingsError: null }, "settings.load");
    if (state.selectedEngagementId) {
      loadDataRetentionStatus().catch(runtime.actions.handleError || (() => {}));
    }
    if (state.activeScreen === "settings") renderSettingsScreen();
    return settings;
  }

  async function loadSettingsReadiness() {
    patchState(
      { settingsReadinessLoading: true, settingsReadinessError: null },
      "settings.readiness.load.start"
    );
    try {
      const readiness = await api("/api/v1/settings/readiness");
      patchState(
        {
          settingsReadiness: readiness,
          settingsReadinessLoading: false,
          settingsReadinessError: null,
        },
        "settings.readiness.load.complete"
      );
      if (state.activeScreen === "settings") renderSettingsScreen();
      return readiness;
    } catch (error) {
      patchState(
        {
          settingsReadinessLoading: false,
          settingsReadinessError: String(error?.message || error),
        },
        "settings.readiness.load.error"
      );
      if (state.activeScreen === "settings") renderSettingsScreen();
      throw error;
    }
  }

  async function loadDataRetentionStatus() {
    if (!state.selectedEngagementId) {
      patchState({ dataRetentionStatus: null, dataRetentionError: null }, "settings.retention.noEngagement");
      return null;
    }
    patchState({ dataRetentionLoading: true, dataRetentionError: null }, "settings.retention.load.start");
    try {
      const payload = await api(`/api/v1/engagements/${state.selectedEngagementId}/data-retention`);
      patchState(
        { dataRetentionStatus: payload, dataRetentionLoading: false, dataRetentionError: null },
        "settings.retention.load.complete"
      );
      if (state.activeScreen === "settings") renderSettingsScreen();
      return payload;
    } catch (error) {
      patchState(
        { dataRetentionLoading: false, dataRetentionError: String(error?.message || error) },
        "settings.retention.load.error"
      );
      if (state.activeScreen === "settings") renderSettingsScreen();
      throw error;
    }
  }

  async function loadApiKeys() {
    patchState({ apiKeysLoading: true, apiKeysError: null }, "settings.apiKeys.load.start");
    try {
      const keys = await api("/api/v1/auth/keys");
      patchState(
        {
          apiKeys: Array.isArray(keys) ? keys : [],
          apiKeysLoading: false,
          apiKeysError: null,
        },
        "settings.apiKeys.load.complete"
      );
      if (state.activeScreen === "settings") renderSettingsScreen();
      return keys;
    } catch (error) {
      patchState(
        {
          apiKeysLoading: false,
          apiKeysError: String(error?.message || error),
        },
        "settings.apiKeys.load.error"
      );
      if (state.activeScreen === "settings") renderSettingsScreen();
      throw error;
    }
  }

  async function createApiKey(form) {
    if (!form) return;
    const actorName = String(form.querySelector('[data-api-key-field="actor_name"]')?.value || "").trim();
    const role = String(form.querySelector('[data-api-key-field="role"]')?.value || "operator").trim();
    if (!actorName) {
      patchState({ apiKeysError: "Enter a user or integration name before creating a key." }, "settings.apiKeys.create.validation");
      renderSettingsScreen();
      return;
    }
    patchState({ apiKeysLoading: true, apiKeysError: null, apiKeyCreateResult: null }, "settings.apiKeys.create.start");
    renderSettingsScreen();
    try {
      const result = await api("/api/v1/auth/keys", {
        method: "POST",
        body: { actor_name: actorName, role },
      });
      patchState({ apiKeyCreateResult: result, apiKeysLoading: false, apiKeysError: null }, "settings.apiKeys.create.complete");
      await loadApiKeys();
      runtime.actions.pushStatus?.(`API key created for ${result.actor_name}. Copy it from the one-time result before leaving Settings.`, "success");
    } catch (error) {
      patchState(
        {
          apiKeysLoading: false,
          apiKeysError: String(error?.message || error),
          apiKeyCreateResult: null,
        },
        "settings.apiKeys.create.error"
      );
      runtime.actions.handleError?.(error);
      renderSettingsScreen();
    }
  }

  async function revokeApiKey(keyId) {
    if (!keyId) return;
    patchState({ apiKeysLoading: true, apiKeysError: null }, "settings.apiKeys.revoke.start");
    renderSettingsScreen();
    try {
      await api(`/api/v1/auth/keys/${encodeURIComponent(keyId)}/revoke`, {
        method: "POST",
        body: {},
      });
      patchState({ apiKeyCreateResult: null }, "settings.apiKeys.revoke.clearToken");
      await loadApiKeys();
      runtime.actions.pushStatus?.("API key revoked.", "warning");
    } catch (error) {
      patchState(
        {
          apiKeysLoading: false,
          apiKeysError: String(error?.message || error),
        },
        "settings.apiKeys.revoke.error"
      );
      runtime.actions.handleError?.(error);
      renderSettingsScreen();
    }
  }

  async function loadScheduledRuns(engagementId = state.selectedEngagementId) {
    if (!engagementId) {
      patchState({ scheduledRuns: [], scheduledRunsLoading: false, scheduledRunsError: null }, "settings.schedules.noEngagement");
      return [];
    }
    patchState({ scheduledRunsLoading: true, scheduledRunsError: null }, "settings.schedules.load.start");
    try {
      const payload = await api(`/api/v1/engagements/${engagementId}/schedules`);
      patchState(
        {
          scheduledRuns: Array.isArray(payload) ? payload : [],
          scheduledRunsLoading: false,
          scheduledRunsError: null,
        },
        "settings.schedules.load.complete"
      );
      if (state.activeScreen === "settings") renderSettingsScreen();
      return payload;
    } catch (error) {
      patchState(
        {
          scheduledRunsLoading: false,
          scheduledRunsError: String(error?.message || error),
        },
        "settings.schedules.load.error"
      );
      if (state.activeScreen === "settings") renderSettingsScreen();
      throw error;
    }
  }

  async function saveScheduledScan(form) {
    if (!form) return;
    const engagementId = String(form.querySelector('[data-schedule-field="engagement"]')?.value || "").trim();
    const frequency = String(form.querySelector('[data-schedule-field="frequency"]')?.value || "daily").trim();
    const enabled = Boolean(form.querySelector('[data-schedule-field="enabled"]')?.checked);
    if (!engagementId) return;
    if (!enabled || frequency === "never") {
      runtime.actions.pushStatus?.("No scheduled scan was created because the frequency is set to never or disabled.", "info");
      return;
    }
    const profileName = String(form.querySelector('[data-schedule-field="profile"]')?.value || "passive-web-baseline").trim();
    const target = String(form.querySelector('[data-schedule-field="target"]')?.value || "").trim();
    const timeOfDay = String(form.querySelector('[data-schedule-field="time"]')?.value || "09:00").trim();
    if (!target) {
      patchState({ scheduledRunsError: "Enter one saved target for the scheduled baseline." }, "settings.schedules.save.validation");
      renderSettingsScreen();
      return;
    }
    const startsAt = nextScheduleStartIso(timeOfDay);
    patchState({ scheduledRunsLoading: true, scheduledRunsError: null }, "settings.schedules.save.start");
    renderSettingsScreen();
    try {
      await api(`/api/v1/engagements/${engagementId}/schedules`, {
        method: "POST",
        body: {
          profile_name: profileName,
          cadence: frequency,
          timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC",
          starts_at: startsAt,
          configuration_json: {
            assessment_type: "Scheduled Baseline",
            targets: targetConfigurationForSchedule(target),
            intake: {
              confirmation_summary: "Scheduled passive baseline configured from Settings.",
            },
          },
        },
      });
      runtime.actions.pushStatus?.("Scheduled passive baseline saved.", "success");
      await loadScheduledRuns(engagementId);
    } catch (error) {
      patchState(
        { scheduledRunsLoading: false, scheduledRunsError: String(error?.message || error) },
        "settings.schedules.save.error"
      );
      runtime.actions.handleError?.(error);
      renderSettingsScreen();
    }
  }

  async function saveDataRetention(form) {
    if (!state.selectedEngagementId) return;
    const retentionDays = Number(form.querySelector("[name='retention_days']")?.value || 90);
    patchState({ dataRetentionLoading: true, dataRetentionError: null }, "settings.retention.save.start");
    try {
      const payload = await api(`/api/v1/engagements/${state.selectedEngagementId}/data-retention`, {
        method: "PATCH",
        body: { retention_days: retentionDays },
      });
      patchState(
        { dataRetentionStatus: payload, dataRetentionLoading: false, dataRetentionError: null },
        "settings.retention.save.complete"
      );
      runtime.actions.pushStatus?.("Data retention policy saved for this engagement.", "success");
    } catch (error) {
      patchState(
        { dataRetentionLoading: false, dataRetentionError: String(error?.message || error) },
        "settings.retention.save.error"
      );
      runtime.actions.handleError?.(error);
    }
    renderSettingsScreen();
  }

  async function cleanupDataRetention() {
    if (!state.selectedEngagementId) return;
    patchState({ dataRetentionLoading: true, dataRetentionError: null }, "settings.retention.cleanup.start");
    try {
      const result = await api(`/api/v1/engagements/${state.selectedEngagementId}/data-retention/cleanup`, {
        method: "POST",
      });
      runtime.actions.pushStatus?.(`Retention cleanup soft-deleted ${result.soft_deleted_runs || 0} run(s).`, "info");
      await loadDataRetentionStatus();
    } catch (error) {
      patchState(
        { dataRetentionLoading: false, dataRetentionError: String(error?.message || error) },
        "settings.retention.cleanup.error"
      );
      runtime.actions.handleError?.(error);
      renderSettingsScreen();
    }
  }

  async function purgeAssessmentData(form) {
    if (!state.selectedEngagementId) return;
    const confirmation = form.querySelector("[name='purge_confirmation']")?.value || "";
    patchState({ dataRetentionLoading: true, dataRetentionError: null }, "settings.retention.purge.start");
    try {
      const result = await api(`/api/v1/engagements/${state.selectedEngagementId}/purge`, {
        method: "DELETE",
        body: { confirmation },
      });
      runtime.actions.pushStatus?.(
        `Assessment data purge completed; ${Object.values(result.counts || {}).reduce((sum, value) => sum + Number(value || 0), 0)} records removed.`,
        "warning"
      );
      await loadDataRetentionStatus();
    } catch (error) {
      patchState(
        { dataRetentionLoading: false, dataRetentionError: String(error?.message || error) },
        "settings.retention.purge.error"
      );
      runtime.actions.handleError?.(error);
      renderSettingsScreen();
    }
  }

  async function loadChatGPTStatus() {
    if (!state.selectedEngagementId) {
      patchState({ chatgptOAuthStatus: null }, "settings.chatgptStatus.noEngagement");
      return null;
    }
    const status = await apiOrNull(
      `/api/v1/auth/chatgpt/status?engagement_id=${encodeURIComponent(state.selectedEngagementId)}`
    );
    patchState({ chatgptOAuthStatus: status }, "settings.chatgptStatus");
    if (state.activeScreen === "settings") renderSettingsScreen();
    return status;
  }

  async function connectChatGPT() {
    if (!state.selectedEngagementId) return;
    let authWindow = null;
    const canReuse = Boolean(state.chatgptOAuthStatus?.reusable_session_available && !state.chatgptOAuthStatus?.connected);
    if (!canReuse) {
      authWindow = window.open("about:blank", "_blank");
    }
    patchState(
      {
        chatgptOAuthStatus: {
          ...(state.chatgptOAuthStatus || {}),
          loading: true,
          pendingAuthorization: false,
          error: null,
          token_exposed: false,
        },
      },
      "settings.chatgpt.connect.start"
    );
    renderSettingsScreen();
    try {
      const response = await api(
        `/api/v1/auth/chatgpt/authorize?engagement_id=${encodeURIComponent(state.selectedEngagementId)}`
      );
      if (response.reused && response.status) {
        authWindow?.close?.();
        patchState(
          {
            chatgptOAuthStatus: {
              ...response.status,
              loading: false,
              pendingAuthorization: false,
              error: null,
              token_exposed: false,
            },
          },
          "settings.chatgpt.connect.reused"
        );
        runtime.actions.pushStatus?.(
          "Existing encrypted ChatGPT OAuth session was reused for this engagement.",
          "success"
        );
        renderSettingsScreen();
        return;
      }
      if (!response.authorization_url) {
        authWindow?.close?.();
        throw new Error("ChatGPT OAuth authorization did not return a login URL.");
      }
      if (authWindow) {
        authWindow.location.href = response.authorization_url;
      } else {
        window.open(response.authorization_url, "_blank", "noopener,noreferrer");
      }
      patchState(
        {
          chatgptOAuthStatus: {
            ...(state.chatgptOAuthStatus || {}),
            connected: false,
            loading: false,
            pendingAuthorization: true,
            authorization_url: response.authorization_url,
            local_callback_listener: response.local_callback_listener || null,
            error: null,
            token_exposed: false,
          },
        },
        "settings.chatgpt.connect.opened"
      );
      runtime.actions.pushStatus?.(
        "ChatGPT OAuth authorization opened. Complete the browser login, then refresh status.",
        "info"
      );
      scheduleChatGPTStatusPolling();
    } catch (error) {
      authWindow?.close?.();
      patchState(
        {
          chatgptOAuthStatus: {
            ...(state.chatgptOAuthStatus || {}),
            loading: false,
            pendingAuthorization: false,
            error: String(error?.message || error),
            token_exposed: false,
          },
        },
        "settings.chatgpt.connect.error"
      );
      runtime.actions.handleError?.(error);
    }
    renderSettingsScreen();
  }

  function scheduleChatGPTStatusPolling() {
    let attempts = 0;
    const poll = async () => {
      attempts += 1;
      const status = await loadChatGPTStatus().catch(() => null);
      if (status?.connected || attempts >= 12) return;
      window.setTimeout(poll, 5000);
    };
    window.setTimeout(poll, 5000);
  }

  async function loadSiemIntegrationSettings() {
    if (!state.selectedEngagementId) {
      patchState(
        {
          siemIntegrationSettings: null,
          siemIntegrationLoading: false,
          siemIntegrationSavingProvider: null,
          siemIntegrationError: null,
        },
        "settings.siem.noEngagement"
      );
      return null;
    }
    patchState({ siemIntegrationLoading: true, siemIntegrationError: null }, "settings.siem.load.start");
    try {
      const payload = await api(`/api/v1/engagements/${state.selectedEngagementId}/integrations/siem`);
      patchState(
        {
          siemIntegrationSettings: payload,
          siemIntegrationLoading: false,
          siemIntegrationSavingProvider: null,
          siemIntegrationError: null,
        },
        "settings.siem.load.complete"
      );
      if (state.activeScreen === "settings") renderSettingsScreen();
      return payload;
    } catch (error) {
      patchState(
        {
          siemIntegrationLoading: false,
          siemIntegrationSavingProvider: null,
          siemIntegrationError: String(error?.message || error),
        },
        "settings.siem.load.error"
      );
      if (state.activeScreen === "settings") renderSettingsScreen();
      throw error;
    }
  }

  async function loadJiraIntegrationSettings() {
    if (!state.selectedEngagementId) {
      patchState(
        {
          jiraIntegrationConfiguration: null,
          jiraIntegrationLoadedEngagementId: null,
          jiraIntegrationLoading: false,
          jiraIntegrationError: null,
        },
        "settings.jira.noEngagement"
      );
      return null;
    }
    patchState({ jiraIntegrationLoading: true, jiraIntegrationError: null }, "settings.jira.load.start");
    try {
      const payload = await apiOrNull(`/api/v1/engagements/${state.selectedEngagementId}/integrations/jira`);
      patchState(
        {
          jiraIntegrationConfiguration: payload,
          jiraIntegrationLoadedEngagementId: state.selectedEngagementId,
          jiraIntegrationLoading: false,
          jiraIntegrationError: null,
        },
        "settings.jira.load.complete"
      );
      if (state.activeScreen === "settings") renderSettingsScreen();
      return payload;
    } catch (error) {
      patchState(
        {
          jiraIntegrationConfiguration: null,
          jiraIntegrationLoadedEngagementId: state.selectedEngagementId,
          jiraIntegrationLoading: false,
          jiraIntegrationError: String(error?.message || error),
        },
        "settings.jira.load.error"
      );
      if (state.activeScreen === "settings") renderSettingsScreen();
      throw error;
    }
  }

  async function loadCicdTriggerSettings() {
    if (!state.selectedEngagementId) {
      patchState(
        { cicdTriggerSettings: null, cicdTriggerLoading: false, cicdTriggerError: null },
        "settings.cicd.noEngagement"
      );
      return null;
    }
    patchState({ cicdTriggerLoading: true, cicdTriggerError: null }, "settings.cicd.load.start");
    try {
      const payload = await api(`/api/v1/engagements/${state.selectedEngagementId}/triggers/cicd`);
      patchState(
        { cicdTriggerSettings: payload, cicdTriggerLoading: false, cicdTriggerError: null },
        "settings.cicd.load.complete"
      );
      if (state.activeScreen === "settings") renderSettingsScreen();
      return payload;
    } catch (error) {
      patchState(
        {
          cicdTriggerLoading: false,
          cicdTriggerError: String(error?.message || error),
        },
        "settings.cicd.load.error"
      );
      if (state.activeScreen === "settings") renderSettingsScreen();
      throw error;
    }
  }

  async function loadThreatIntelControls() {
    patchState({ threatIntelLoading: true, threatIntelError: null }, "settings.threatIntel.load.start");
    try {
      const [status, watchlist, records] = await Promise.all([
        api("/api/v1/threat-intel/feed-sync/status"),
        api("/api/v1/threat-intel/product-watchlist"),
        api("/api/v1/threat-intel/search"),
      ]);
      patchState(
        {
          threatIntelStatus: status,
          threatIntelWatchlist: Array.isArray(watchlist) ? watchlist : [],
          threatIntelRecords: Array.isArray(records) ? records : [],
          threatIntelLoading: false,
          threatIntelError: null,
        },
        "settings.threatIntel.load.complete"
      );
      if (state.activeScreen === "settings") renderSettingsScreen();
      return { status, watchlist, records };
    } catch (error) {
      patchState(
        {
          threatIntelLoading: false,
          threatIntelError: String(error?.message || error),
        },
        "settings.threatIntel.load.error"
      );
      if (state.activeScreen === "settings") renderSettingsScreen();
      throw error;
    }
  }

  async function generateThreatIntelTemplate(recordId) {
    if (!recordId || !state.selectedEngagementId) return;
    patchState(
      {
        threatIntelTemplateGeneratingId: recordId,
        threatIntelTemplateResult: null,
        threatIntelError: null,
      },
      "settings.threatIntel.template.generate.start"
    );
    renderSettingsScreen();
    try {
      const result = await api(`/api/v1/threat-intel/${encodeURIComponent(recordId)}/generate-template`, {
        method: "POST",
        body: { engagement_id: state.selectedEngagementId },
      });
      patchState(
        {
          threatIntelTemplateGeneratingId: null,
          threatIntelTemplateResult: result,
        },
        "settings.threatIntel.template.generate.complete"
      );
      await loadThreatIntelControls();
      runtime.actions.pushStatus?.(
        result.status === "generated"
          ? "Generated Nuclei template staged in Pack Forge for review."
          : result.message || "Template generation did not create a pack.",
        result.status === "generated" ? "info" : "warning"
      );
    } catch (error) {
      patchState(
        {
          threatIntelTemplateGeneratingId: null,
          threatIntelError: String(error?.message || error),
        },
        "settings.threatIntel.template.generate.error"
      );
      runtime.actions.handleError?.(error);
    }
    renderSettingsScreen();
  }

  async function syncThreatIntelFeeds() {
    patchState({ threatIntelSyncing: true, threatIntelError: null }, "settings.threatIntel.sync.start");
    renderSettingsScreen();
    try {
      await api("/api/v1/threat-intel/feed-sync/run", {
        method: "POST",
        body: { sources: [] },
      });
      await loadThreatIntelControls();
      runtime.actions.pushStatus?.("Threat intel cache sync finished. Finding lookups remain local-cache only.", "info");
    } catch (error) {
      patchState(
        {
          threatIntelSyncing: false,
          threatIntelError: String(error?.message || error),
        },
        "settings.threatIntel.sync.error"
      );
      runtime.actions.handleError?.(error);
    }
    patchState({ threatIntelSyncing: false }, "settings.threatIntel.sync.complete");
    renderSettingsScreen();
  }

  async function addThreatIntelWatchlistEntry(form) {
    const query = String(form?.querySelector("[data-threat-intel-watchlist-query]")?.value || "").trim();
    if (!query) return;
    patchState({ threatIntelLoading: true, threatIntelError: null }, "settings.threatIntel.watchlist.add.start");
    renderSettingsScreen();
    try {
      await api("/api/v1/threat-intel/product-watchlist", {
        method: "POST",
        body: { query },
      });
      await loadThreatIntelControls();
    } catch (error) {
      patchState(
        { threatIntelLoading: false, threatIntelError: String(error?.message || error) },
        "settings.threatIntel.watchlist.add.error"
      );
      runtime.actions.handleError?.(error);
      renderSettingsScreen();
    }
  }

  async function approveThreatIntelWatchlistEntry(entryId) {
    patchState({ threatIntelLoading: true, threatIntelError: null }, "settings.threatIntel.watchlist.approve.start");
    renderSettingsScreen();
    try {
      await api(`/api/v1/threat-intel/product-watchlist/${encodeURIComponent(entryId)}/approve`, {
        method: "POST",
        body: {},
      });
      await loadThreatIntelControls();
    } catch (error) {
      patchState(
        { threatIntelLoading: false, threatIntelError: String(error?.message || error) },
        "settings.threatIntel.watchlist.approve.error"
      );
      runtime.actions.handleError?.(error);
      renderSettingsScreen();
    }
  }

  async function removeThreatIntelWatchlistEntry(entryId) {
    patchState({ threatIntelLoading: true, threatIntelError: null }, "settings.threatIntel.watchlist.remove.start");
    renderSettingsScreen();
    try {
      await api(`/api/v1/threat-intel/product-watchlist/${encodeURIComponent(entryId)}`, { method: "DELETE" });
      await loadThreatIntelControls();
    } catch (error) {
      patchState(
        { threatIntelLoading: false, threatIntelError: String(error?.message || error) },
        "settings.threatIntel.watchlist.remove.error"
      );
      runtime.actions.handleError?.(error);
      renderSettingsScreen();
    }
  }

  async function suggestThreatIntelFromInventory() {
    if (!state.selectedEngagementId) return;
    patchState({ threatIntelLoading: true, threatIntelError: null }, "settings.threatIntel.suggest.start");
    renderSettingsScreen();
    try {
      const snapshots = await api(`/api/v1/engagements/${encodeURIComponent(state.selectedEngagementId)}/inventory`);
      const snapshot = Array.isArray(snapshots) ? snapshots[0] : null;
      if (!snapshot?.id) {
        throw new Error("No inventory snapshot is available for suggestions.");
      }
      await api("/api/v1/threat-intel/product-watchlist/suggest-from-inventory", {
        method: "POST",
        body: { inventory_snapshot_id: snapshot.id },
      });
      await loadThreatIntelControls();
    } catch (error) {
      patchState(
        { threatIntelLoading: false, threatIntelError: String(error?.message || error) },
        "settings.threatIntel.suggest.error"
      );
      runtime.actions.handleError?.(error);
      renderSettingsScreen();
    }
  }

  async function saveSettings(form) {
    const payload = state.operatorSettings;
    const settingsForm = form?.querySelectorAll ? form : dom.settingsContent?.querySelector("#settings-form");
    if (!payload || !settingsForm) return;

    const patch = {};
    flattenSettings(payload).forEach((setting) => {
      if (setting.read_only) return;
      const input = findSettingInput(settingsForm, setting.key);
      if (!input) return;
      if (setting.sensitive) {
        const secretValue = String(input.value || "").trim();
        if (secretValue) patch[setting.key] = secretValue;
        return;
      }
      if (setting.input_type === "checkbox") {
        const value = Boolean(input.checked);
        if (String(value) !== String(input.dataset.originalValue || "false")) {
          patch[setting.key] = value;
        }
        return;
      }
      if (setting.input_type === "list") {
        const value = String(input.value || "")
          .split(",")
          .map((item) => item.trim())
          .filter(Boolean);
        if (value.join(", ") !== String(input.dataset.originalValue || "")) {
          patch[setting.key] = value;
        }
        return;
      }
      const value = String(input.value || "").trim();
      if (value !== String(input.dataset.originalValue || "")) {
        patch[setting.key] = value;
      }
    });
    collectChangedSettingInputs(settingsForm).forEach(({ key, value }) => {
      if (!Object.prototype.hasOwnProperty.call(patch, key)) {
        patch[key] = value;
      }
    });
    collectChangedSettingInputs(document.querySelector("#settings-form")).forEach(({ key, value }) => {
      if (!Object.prototype.hasOwnProperty.call(patch, key)) {
        patch[key] = value;
      }
    });
    const runtimeWorkersInput = document.querySelector('[data-setting-key="runtime.inline_task_workers"]');
    if (
      runtimeWorkersInput &&
      String(runtimeWorkersInput.value || "").trim() !== String(runtimeWorkersInput.dataset.originalValue || "")
    ) {
      patch["runtime.inline_task_workers"] = String(runtimeWorkersInput.value || "").trim();
    }

    patchState({ settingsSaving: true, settingsError: null }, "settings.save.start");
    renderSettingsScreen();
    try {
      const updated = await api("/api/v1/settings", {
        method: "PATCH",
        body: { settings: patch },
      });
      patchState({ operatorSettings: updated, settingsSaving: false, settingsError: null }, "settings.save.complete");
      await loadSettingsReadiness().catch(runtime.actions.handleError || (() => {}));
      runtime.actions.pushStatus?.("Settings saved. Sensitive values remain encrypted and masked.", "info");
    } catch (error) {
      patchState({ settingsSaving: false, settingsError: String(error?.message || error) }, "settings.save.error");
      runtime.actions.handleError?.(error);
    }
    renderSettingsScreen();
  }

  async function saveCicdTrigger(source, form) {
    if (!state.selectedEngagementId || !form) return;
    const payload = {
      enabled: Boolean(form.querySelector('[data-cicd-field="enabled"]')?.checked),
      enabled_profiles: String(form.querySelector('[data-cicd-field="profiles"]')?.value || "")
        .split(",")
        .map((item) => item.trim())
        .filter(Boolean),
      branch_filters: String(form.querySelector('[data-cicd-field="branches"]')?.value || "")
        .split(",")
        .map((item) => item.trim())
        .filter(Boolean),
      scope_override_allowed: Boolean(form.querySelector('[data-cicd-field="scope-override"]')?.checked),
    };
    const webhookSecret = String(form.querySelector('[data-cicd-field="webhook-secret"]')?.value || "").trim();
    if (webhookSecret) {
      payload.webhook_secret = webhookSecret;
    }

    patchState(
      { cicdTriggerSavingSource: source, cicdTriggerError: null },
      "settings.cicd.save.start"
    );
    renderSettingsScreen();
    try {
      await api(`/api/v1/engagements/${state.selectedEngagementId}/triggers/cicd/${encodeURIComponent(source)}`, {
        method: "PUT",
        body: payload,
      });
      await loadCicdTriggerSettings();
      runtime.actions.pushStatus?.(`${triggerSourceLabel(source)} trigger saved. Secret remains encrypted.`, "info");
    } catch (error) {
      patchState(
        {
          cicdTriggerSavingSource: null,
          cicdTriggerError: String(error?.message || error),
        },
        "settings.cicd.save.error"
      );
      runtime.actions.handleError?.(error);
      renderSettingsScreen();
      return;
    }
    patchState({ cicdTriggerSavingSource: null, cicdTriggerError: null }, "settings.cicd.save.complete");
    renderSettingsScreen();
  }

  async function saveSiemIntegration(provider, form) {
    if (!state.selectedEngagementId || !form) return;
    const payload = {
      integration_type: provider,
      display_name: String(form.querySelector('[data-siem-field="display-name"]')?.value || "").trim() || null,
      base_url: String(form.querySelector('[data-siem-field="base-url"]')?.value || "").trim(),
      enabled: Boolean(form.querySelector('[data-siem-field="enabled"]')?.checked),
      push_on_run_completion: Boolean(form.querySelector('[data-siem-field="push-run-completion"]')?.checked),
      push_on_critical_finding: Boolean(form.querySelector('[data-siem-field="push-critical-finding"]')?.checked),
      include_sigma: Boolean(form.querySelector('[data-siem-field="include-sigma"]')?.checked),
    };
    const indexName = String(form.querySelector('[data-siem-field="index-name"]')?.value || "").trim();
    const sourcetype = String(form.querySelector('[data-siem-field="sourcetype"]')?.value || "").trim();
    const customLogTable = String(form.querySelector('[data-siem-field="custom-log-table"]')?.value || "").trim();
    const streamName = String(form.querySelector('[data-siem-field="stream-name"]')?.value || "").trim();
    const timeoutSeconds = String(form.querySelector('[data-siem-field="timeout-seconds"]')?.value || "").trim();
    const credential = String(form.querySelector('[data-siem-field="credential"]')?.value || "").trim();

    if (indexName) payload.index_name = indexName;
    if (sourcetype) payload.sourcetype = sourcetype;
    if (customLogTable) payload.custom_log_table = customLogTable;
    if (streamName) payload.stream_name = streamName;
    if (timeoutSeconds) payload.timeout_seconds = Number(timeoutSeconds);
    if (credential) payload.credential = credential;

    patchState(
      { siemIntegrationSavingProvider: provider, siemIntegrationError: null },
      "settings.siem.save.start"
    );
    renderSettingsScreen();
    try {
      await api(`/api/v1/engagements/${state.selectedEngagementId}/integrations/siem/${encodeURIComponent(provider)}`, {
        method: "PUT",
        body: payload,
      });
      await loadSiemIntegrationSettings();
      runtime.actions.pushStatus?.(
        `${siemProviderLabel(provider)} integration saved. Credentials remain encrypted.`,
        "info"
      );
    } catch (error) {
      patchState(
        {
          siemIntegrationSavingProvider: null,
          siemIntegrationError: String(error?.message || error),
        },
        "settings.siem.save.error"
      );
      runtime.actions.handleError?.(error);
      renderSettingsScreen();
      return;
    }
    patchState({ siemIntegrationSavingProvider: null, siemIntegrationError: null }, "settings.siem.save.complete");
    renderSettingsScreen();
  }

  async function saveJiraIntegration(form) {
    if (!state.selectedEngagementId || !form) return;
    const authMethod = String(form.querySelector('[data-jira-field="auth-method"]')?.value || "api_token").trim();
    const payload = {
      integration_type: "jira",
      display_name: String(form.querySelector('[data-jira-field="display-name"]')?.value || "").trim() || null,
      base_url: String(form.querySelector('[data-jira-field="base-url"]')?.value || "").trim(),
      project_key: String(form.querySelector('[data-jira-field="project-key"]')?.value || "").trim() || null,
      auth_ref: String(form.querySelector('[data-jira-field="auth-ref"]')?.value || "").trim() || null,
      settings_json: {
        auth_method: authMethod,
        issue_type: String(form.querySelector('[data-jira-field="issue-type"]')?.value || "Bug").trim() || "Bug",
      },
    };
    patchState(
      { jiraIntegrationSaving: true, jiraIntegrationError: null, jiraIntegrationTestResult: null },
      "settings.jira.save.start"
    );
    renderSettingsScreen();
    try {
      await api(`/api/v1/engagements/${state.selectedEngagementId}/integrations/jira`, {
        method: "PUT",
        body: payload,
      });
      await loadJiraIntegrationSettings();
      runtime.actions.pushStatus?.("Jira integration saved. Credential references stay protected.", "info");
    } catch (error) {
      patchState(
        {
          jiraIntegrationSaving: false,
          jiraIntegrationError: String(error?.message || error),
        },
        "settings.jira.save.error"
      );
      runtime.actions.handleError?.(error);
      renderSettingsScreen();
      return;
    }
    patchState({ jiraIntegrationSaving: false }, "settings.jira.save.complete");
    renderSettingsScreen();
  }

  async function testJiraIntegration() {
    if (!state.selectedEngagementId) return;
    patchState({ jiraIntegrationTesting: true, jiraIntegrationTestResult: null, jiraIntegrationError: null }, "settings.jira.test.start");
    renderSettingsScreen();
    try {
      const payload = await api(`/api/v1/engagements/${state.selectedEngagementId}/integrations/jira`);
      patchState(
        {
          jiraIntegrationConfiguration: payload,
          jiraIntegrationTesting: false,
          jiraIntegrationTestResult: "Jira configuration is available. Per-finding sync validates remote issue status after a Jira key exists.",
        },
        "settings.jira.test.complete"
      );
    } catch (error) {
      patchState(
        {
          jiraIntegrationTesting: false,
          jiraIntegrationError: String(error?.message || error),
        },
        "settings.jira.test.error"
      );
      runtime.actions.handleError?.(error);
    }
    renderSettingsScreen();
  }

  function renderSettingsScreen() {
    if (!dom.settingsContent) return;
    const payload = state.operatorSettings;
    if (!payload) {
      dom.settingsContent.innerHTML = `<div class="panel settings-loading" data-testid="settings-loading">Loading settings...</div>`;
      return;
    }
    const pendingValues = capturePendingSettingValues();

    dom.settingsContent.innerHTML = `
      ${renderSettingsOverview(payload)}
      ${renderSettingsReadinessPanel()}
      ${renderUsersPanel()}
      ${renderChatGPTOAuthPanel()}
      ${renderThreatIntelPanel()}
      ${renderScheduledScansPanel()}
      ${renderDataRetentionPanel()}
      <form id="settings-form" class="settings-grid" data-testid="settings-form">
        <div class="settings-stack">
          ${payload.sections.map(renderSection).join("")}
        </div>
        <div class="settings-save-bar">
          <span>${escapeHtml(state.settingsError || "Changes update defaults only; they do not mutate active runs.")}</span>
          <button class="action primary" type="button" data-testid="settings-save" ${state.settingsSaving ? "disabled" : ""}>
            ${state.settingsSaving ? "Saving..." : "Save Settings"}
          </button>
        </div>
      </form>
      <div class="settings-stack">
        ${renderJiraPanel()}
        ${renderSiemPanel()}
        ${renderCicdPanel()}
      </div>
    `;
    restorePendingSettingValues(pendingValues);

    dom.settingsContent.querySelector("#settings-form")?.addEventListener("submit", (event) => {
      event.preventDefault();
      saveSettings(event.currentTarget).catch(runtime.actions.handleError || (() => {}));
    });
    dom.settingsContent.querySelector("[data-testid='settings-save']")?.addEventListener("click", () => {
      saveSettings(dom.settingsContent.querySelector("#settings-form")).catch(runtime.actions.handleError || (() => {}));
    });
    dom.settingsContent.querySelector("#settings-form")?.addEventListener("change", (event) => {
      const target = event.target;
      if (
        !target?.matches?.(
          '[data-ai-provider-control="provider"], [data-ai-provider-control="feature-toggle"]'
        )
      ) {
        return;
      }
      syncAiProviderWarning(event.currentTarget);
    });
    dom.settingsContent.querySelectorAll("details[data-settings-panel]").forEach((panel) => {
      panel.addEventListener("toggle", () => {
        setSettingsPanelOpen(panel.dataset.settingsPanel, panel.open);
      });
    });
    dom.settingsContent.querySelector("[data-settings-chatgpt-connect]")?.addEventListener("click", () => {
      connectChatGPT().catch(runtime.actions.handleError || (() => {}));
    });
    dom.settingsContent.querySelector("[data-settings-refresh-api-keys]")?.addEventListener("click", () => {
      loadApiKeys().catch(runtime.actions.handleError || (() => {}));
    });
    dom.settingsContent.querySelector("[data-api-key-create-form]")?.addEventListener("submit", (event) => {
      event.preventDefault();
      createApiKey(event.currentTarget).catch(runtime.actions.handleError || (() => {}));
    });
    dom.settingsContent.querySelectorAll("[data-api-key-revoke]").forEach((button) => {
      button.addEventListener("click", () => {
        revokeApiKey(button.dataset.apiKeyRevoke).catch(runtime.actions.handleError || (() => {}));
      });
    });
    dom.settingsContent.querySelector("[data-settings-refresh-chatgpt]")?.addEventListener("click", () => {
      loadChatGPTStatus().catch(runtime.actions.handleError || (() => {}));
    });
    dom.settingsContent.querySelector("[data-settings-refresh-readiness]")?.addEventListener("click", () => {
      loadSettingsReadiness().catch(runtime.actions.handleError || (() => {}));
    });
    dom.settingsContent.querySelector("[data-settings-export-readiness]")?.addEventListener("click", () => {
      exportSettingsReadiness();
    });
    dom.settingsContent.querySelector("[data-settings-refresh-siem]")?.addEventListener("click", () => {
      loadSiemIntegrationSettings().catch(runtime.actions.handleError || (() => {}));
    });
    dom.settingsContent.querySelector("[data-settings-refresh-jira]")?.addEventListener("click", () => {
      loadJiraIntegrationSettings().catch(runtime.actions.handleError || (() => {}));
    });
    dom.settingsContent.querySelector("[data-settings-test-jira]")?.addEventListener("click", () => {
      testJiraIntegration().catch(runtime.actions.handleError || (() => {}));
    });
    dom.settingsContent.querySelector("[data-settings-refresh-cicd]")?.addEventListener("click", () => {
      loadCicdTriggerSettings().catch(runtime.actions.handleError || (() => {}));
    });
    dom.settingsContent.querySelector("[data-settings-refresh-threat-intel]")?.addEventListener("click", () => {
      loadThreatIntelControls().catch(runtime.actions.handleError || (() => {}));
    });
    dom.settingsContent.querySelector("[data-settings-sync-threat-intel]")?.addEventListener("click", () => {
      syncThreatIntelFeeds().catch(runtime.actions.handleError || (() => {}));
    });
    dom.settingsContent.querySelector("[data-settings-refresh-retention]")?.addEventListener("click", () => {
      loadDataRetentionStatus().catch(runtime.actions.handleError || (() => {}));
    });
    dom.settingsContent.querySelector("[data-settings-refresh-schedules]")?.addEventListener("click", () => {
      const engagementId = dom.settingsContent.querySelector('[data-schedule-field="engagement"]')?.value || state.selectedEngagementId;
      loadScheduledRuns(engagementId).catch(runtime.actions.handleError || (() => {}));
    });
    dom.settingsContent.querySelector("[data-schedule-form]")?.addEventListener("submit", (event) => {
      event.preventDefault();
      saveScheduledScan(event.currentTarget).catch(runtime.actions.handleError || (() => {}));
    });
    dom.settingsContent.querySelector("[data-retention-policy-form]")?.addEventListener("submit", (event) => {
      event.preventDefault();
      saveDataRetention(event.currentTarget).catch(runtime.actions.handleError || (() => {}));
    });
    dom.settingsContent.querySelector("[data-retention-cleanup]")?.addEventListener("click", () => {
      cleanupDataRetention().catch(runtime.actions.handleError || (() => {}));
    });
    dom.settingsContent.querySelector("[data-retention-purge-form]")?.addEventListener("submit", (event) => {
      event.preventDefault();
      purgeAssessmentData(event.currentTarget).catch(runtime.actions.handleError || (() => {}));
    });
    dom.settingsContent.querySelector("[data-settings-threat-intel-suggest]")?.addEventListener("click", () => {
      suggestThreatIntelFromInventory().catch(runtime.actions.handleError || (() => {}));
    });
    dom.settingsContent.querySelector("[data-threat-intel-watchlist-form]")?.addEventListener("submit", (event) => {
      event.preventDefault();
      addThreatIntelWatchlistEntry(event.currentTarget).catch(runtime.actions.handleError || (() => {}));
    });
    dom.settingsContent.querySelectorAll("[data-threat-intel-approve]").forEach((button) => {
      button.addEventListener("click", () => {
        approveThreatIntelWatchlistEntry(button.dataset.threatIntelApprove).catch(
          runtime.actions.handleError || (() => {})
        );
      });
    });
    dom.settingsContent.querySelectorAll("[data-threat-intel-remove]").forEach((button) => {
      button.addEventListener("click", () => {
        removeThreatIntelWatchlistEntry(button.dataset.threatIntelRemove).catch(
          runtime.actions.handleError || (() => {})
        );
      });
    });
    dom.settingsContent.querySelectorAll("[data-threat-intel-generate-template]").forEach((button) => {
      button.addEventListener("click", () => {
        generateThreatIntelTemplate(button.dataset.threatIntelGenerateTemplate).catch(
          runtime.actions.handleError || (() => {})
        );
      });
    });
    dom.settingsContent.querySelectorAll("[data-siem-provider-form]").forEach((form) => {
      form.addEventListener("submit", (event) => {
        event.preventDefault();
        saveSiemIntegration(form.dataset.siemProviderForm, event.currentTarget).catch(
          runtime.actions.handleError || (() => {})
        );
      });
    });
    dom.settingsContent.querySelector("[data-jira-integration-form]")?.addEventListener("submit", (event) => {
      event.preventDefault();
      saveJiraIntegration(event.currentTarget).catch(runtime.actions.handleError || (() => {}));
    });
    dom.settingsContent.querySelectorAll("[data-cicd-trigger-form]").forEach((form) => {
      form.addEventListener("submit", (event) => {
        event.preventDefault();
        saveCicdTrigger(form.dataset.cicdTriggerForm, event.currentTarget).catch(
          runtime.actions.handleError || (() => {})
        );
      });
    });
    syncAiProviderWarning(dom.settingsContent.querySelector("#settings-form"));
  }

  return {
    loadApiKeys,
    loadChatGPTStatus,
    loadCicdTriggerSettings,
    loadJiraIntegrationSettings,
    loadSiemIntegrationSettings,
    loadSettings,
    loadSettingsReadiness,
    loadScheduledRuns,
    loadDataRetentionStatus,
    loadThreatIntelControls,
    renderSettingsScreen,
    saveCicdTrigger,
    connectChatGPT,
    saveJiraIntegration,
    saveSiemIntegration,
    saveSettings,
    syncThreatIntelFeeds,
  };
}

function flattenSettings(payload) {
  return (payload.sections || []).flatMap((section) => section.settings || []);
}

function capturePendingSettingValues() {
  const form = dom.settingsContent?.querySelector("#settings-form");
  if (!form) return {};
  const values = {};
  form.querySelectorAll("[data-setting-key]").forEach((input) => {
    const key = input.dataset.settingKey;
    if (!key || input.readOnly || input.disabled) return;
    const original = String(input.dataset.originalValue || "");
    if (input.type === "checkbox") {
      const value = Boolean(input.checked);
      if (String(value) !== original) values[key] = value;
      return;
    }
    const value = String(input.value || "");
    if (value !== original) values[key] = value;
  });
  return values;
}

function restorePendingSettingValues(values) {
  if (!values || !Object.keys(values).length) return;
  const form = dom.settingsContent?.querySelector("#settings-form");
  if (!form) return;
  Object.entries(values).forEach(([key, value]) => {
    const input = findSettingInput(form, key);
    if (!input || input.readOnly || input.disabled) return;
    if (input.type === "checkbox") {
      input.checked = Boolean(value);
    } else {
      input.value = String(value);
    }
  });
}

function renderSettingsOverview(payload) {
  const engagement = runtime.actions.selectedEngagement?.();
  const model = findSettingValue("ai.chatgpt_model") || "gpt-5.4";
  const role = String(state.currentActor?.role || "admin").toLowerCase();
  return `
    <div class="settings-overview-strip" data-testid="settings-overview-strip">
      <span class="settings-overview-pill">Tenant ${escapeHtml(payload.tenant_id || "default")}</span>
      <span class="settings-overview-pill">${escapeHtml(engagement?.name ? `Engagement ${engagement.name}` : "No engagement selected")}</span>
      <span class="settings-overview-pill">Model ${escapeHtml(model)}</span>
      <span class="settings-overview-pill">Role ${escapeHtml(role)}</span>
      <span class="settings-overview-pill">Secrets masked by API</span>
    </div>
  `;
}

function renderSettingsReadinessPanel() {
  const readiness = state.settingsReadiness;
  const loading = Boolean(state.settingsReadinessLoading);
  const error = state.settingsReadinessError;
  const summary = readiness
    ? `${readiness.overall_status || "unknown"} · ${(readiness.tools || []).filter((tool) => tool.installed).length}/${(readiness.tools || []).length} tool groups ready`
    : loading
      ? "checking runtime"
      : "not loaded";
  if (!readiness) {
    return renderSettingsDisclosure({
      panelId: "runtime_readiness",
      title: "Runtime Readiness",
      summary,
      open: isSettingsPanelOpen("runtime_readiness"),
      testId: "settings-readiness-panel",
      className: "settings-readiness-disclosure",
      body: `
        <div class="settings-engagement-actions">
          <p class="settings-section-copy">Check local runtime readiness, installed pentest binaries, AI provider state, storage, scheduler, and integrations before trusting a run.</p>
          <button class="action ghost compact-action" type="button" data-settings-refresh-readiness ${loading ? "disabled" : ""}>
            ${loading ? "Checking..." : "Refresh readiness"}
          </button>
        </div>
        ${error ? `<p class="settings-inline-error" data-testid="settings-readiness-error">${escapeHtml(error)}</p>` : ""}
        <div class="detail-surface empty-detail-surface">Readiness has not loaded yet.</div>
      `,
    });
  }
  const capabilities = Array.isArray(readiness.capabilities) ? readiness.capabilities : [];
  const tools = Array.isArray(readiness.tools) ? readiness.tools : [];
  return renderSettingsDisclosure({
    panelId: "runtime_readiness",
    title: "Runtime Readiness",
    summary,
    open: isSettingsPanelOpen("runtime_readiness"),
    testId: "settings-readiness-panel",
    className: "settings-readiness-disclosure",
    body: `
      <div class="settings-engagement-actions">
        <p class="settings-section-copy">
          Authoritative readiness for this host and tenant. This does not install tools or mutate active runs; it shows what the current runtime can actually support.
        </p>
        <div class="chip-row compact">
          ${readinessStatusChip(readiness.overall_status)}
          <button class="action ghost compact-action" type="button" data-settings-refresh-readiness ${loading ? "disabled" : ""}>
            ${loading ? "Checking..." : "Refresh readiness"}
          </button>
          <button class="action primary compact-action" type="button" data-settings-export-readiness data-testid="settings-readiness-export">
            Export readiness JSON
          </button>
        </div>
      </div>
      ${error ? `<p class="settings-inline-error" data-testid="settings-readiness-error">${escapeHtml(error)}</p>` : ""}
      <div class="settings-readiness-grid" data-testid="settings-readiness-cards">
        ${capabilities.map(renderReadinessCapabilityCard).join("")}
      </div>
      <section class="settings-subsection" data-testid="settings-tool-readiness">
        <div class="settings-subsection-head">
          <strong>Pentest Tool Readiness</strong>
          <span>Missing tools list the affected assessment families instead of failing silently during intake or Mission Control.</span>
        </div>
        <div class="settings-tool-list">
          ${tools.map(renderToolReadinessRow).join("")}
        </div>
      </section>
    `,
  });
}

function renderReadinessCapabilityCard(capability) {
  const details = Array.isArray(capability.details) ? capability.details : [];
  const affected = Array.isArray(capability.affected_assessment_families) ? capability.affected_assessment_families : [];
  return `
    <article class="detail-surface settings-readiness-card" data-testid="settings-readiness-card" data-readiness-id="${escapeHtml(capability.id || "")}">
      <div class="settings-label-row">
        <strong>${escapeHtml(capability.title || "Readiness item")}</strong>
        ${readinessStatusChip(capability.status)}
      </div>
      <p>${escapeHtml(capability.summary || "")}</p>
      ${details.length ? `<ul>${details.slice(0, 3).map((detail) => `<li>${escapeHtml(detail)}</li>`).join("")}</ul>` : ""}
      ${affected.length ? `<p class="settings-help">Affected: ${escapeHtml(affected.join(", "))}</p>` : ""}
      <p class="settings-help">${escapeHtml(capability.operator_next_step || "No action required.")}</p>
    </article>
  `;
}

function renderToolReadinessRow(tool) {
  const families = Array.isArray(tool.affected_assessment_families) ? tool.affected_assessment_families : [];
  const binaries = Array.isArray(tool.binary_names) ? tool.binary_names : [];
  return `
    <article class="threat-watchlist-row settings-tool-readiness-row" data-testid="settings-tool-readiness-row">
      <span class="status-dot status-${escapeHtml(statusDotForReadiness(tool.status))}"></span>
      <div>
        <strong>${escapeHtml(tool.title || tool.id || "Tool")}</strong>
        <p>${escapeHtml(binaries.join(" / "))} · ${escapeHtml(tool.detected_path || "not detected")}</p>
        <p class="settings-help">${escapeHtml(families.join(", "))}</p>
      </div>
      <div class="chip-row compact">
        ${readinessStatusChip(tool.status)}
        <span class="status-chip ${tool.required ? "warning" : "info"}">${escapeHtml(tool.required ? "required" : "optional")}</span>
      </div>
    </article>
  `;
}

function readinessStatusChip(status) {
  const normalized = String(status || "unknown").toLowerCase();
  const theme =
    normalized === "ready"
      ? "success"
      : normalized === "blocked" || normalized === "missing"
        ? "danger"
        : normalized === "degraded"
          ? "warning"
          : "info";
  return `<span class="status-chip ${theme}">${escapeHtml(normalized)}</span>`;
}

function statusDotForReadiness(status) {
  const normalized = String(status || "").toLowerCase();
  if (normalized === "ready") return "completed";
  if (normalized === "blocked" || normalized === "missing") return "failed";
  return "queued";
}

function exportSettingsReadiness() {
  const artifact = state.settingsReadiness?.artifact || state.settingsReadiness;
  if (!artifact) return;
  const blob = new Blob([JSON.stringify(artifact, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `aegispt-settings-readiness-${new Date().toISOString().replace(/[:.]/g, "-")}.json`;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
  runtime.actions.pushStatus?.("Settings readiness artifact exported.", "success");
}

function renderUsersPanel() {
  const role = String(state.currentActor?.role || "admin").toLowerCase();
  const keys = Array.isArray(state.apiKeys) ? state.apiKeys : [];
  const loading = Boolean(state.apiKeysLoading);
  const result = state.apiKeyCreateResult || null;
  const canManage = role === "admin";
  const summary = canManage
    ? `${keys.filter((key) => !key.revoked_at).length} active · ${keys.length} total`
    : `${role} role · admin required`;
  return renderSettingsDisclosure({
    panelId: "users",
    title: "Users & API Keys",
    summary,
    open: isSettingsPanelOpen("users"),
    testId: "settings-users-panel",
    className: "settings-users-disclosure",
    body: `
      <div class="settings-engagement-actions">
        <p class="settings-section-copy">Create scoped API keys for admins, operators, and reviewers. The full token is shown only once after creation.</p>
        <button class="action ghost compact-action" type="button" data-settings-refresh-api-keys ${loading ? "disabled" : ""}>
          ${loading ? "Refreshing..." : "Refresh keys"}
        </button>
      </div>
      ${state.apiKeysError ? `<p class="settings-inline-error" data-testid="settings-api-keys-error">${escapeHtml(state.apiKeysError)}</p>` : ""}
      ${result ? renderApiKeyCreateResult(result) : ""}
      <form class="settings-inline-form settings-api-key-form" data-api-key-create-form data-testid="settings-api-key-create-form">
        <input type="text" data-api-key-field="actor_name" placeholder="User or integration name" aria-label="API key user or integration name" ${canManage ? "" : "disabled"} />
        <select data-api-key-field="role" ${canManage ? "" : "disabled"} aria-label="API key role">
          <option value="operator">Operator</option>
          <option value="reviewer">Reviewer</option>
          <option value="admin">Admin</option>
        </select>
        <button class="action primary compact-action" type="submit" ${canManage && !loading ? "" : "disabled"}>
          ${loading ? "Working..." : "Create Key"}
        </button>
      </form>
      <div class="settings-api-key-list" data-testid="settings-api-key-list">
        ${
          keys.length
            ? keys.map(renderApiKeyRow).join("")
            : `<div class="cicd-history-empty">No API keys have been created yet. Local X-Actor fallback is still available for development only.</div>`
        }
      </div>
    `,
  });
}

function renderApiKeyCreateResult(result) {
  return `
    <article class="settings-result-card settings-api-key-result" data-testid="settings-api-key-create-result">
      <div class="settings-label-row">
        <strong>API key created for ${escapeHtml(result.actor_name || "actor")}</strong>
        <span class="status-chip warning">shown once</span>
      </div>
      <p class="settings-section-copy">Store this token now. AegisPT only keeps its hash and cannot show it again.</p>
      <pre class="settings-yaml-diff">${escapeHtml(result.api_key || "")}</pre>
    </article>
  `;
}

function renderApiKeyRow(key) {
  const revoked = Boolean(key.revoked_at);
  const canRevoke = String(state.currentActor?.role || "admin").toLowerCase() === "admin" && !revoked;
  return `
    <article class="threat-watchlist-row settings-api-key-row" data-testid="settings-api-key-row">
      <span class="status-dot status-${revoked ? "failed" : "completed"}"></span>
      <div>
        <strong>${escapeHtml(key.actor_name || "API actor")}</strong>
        <p>${escapeHtml(String(key.role || "operator"))} · created ${escapeHtml(formatTimestamp(key.created_at))} · last used ${escapeHtml(formatTimestamp(key.last_used_at) || "never")}</p>
      </div>
      <div class="chip-row compact">
        <span class="status-chip ${revoked ? "danger" : "success"}">${escapeHtml(revoked ? "revoked" : "active")}</span>
        <button class="action ghost compact-action" type="button" data-api-key-revoke="${escapeHtml(key.id)}" ${canRevoke ? "" : "disabled"}>Revoke</button>
      </div>
    </article>
  `;
}

function renderSettingsDisclosure({ panelId, title, summary = "", body = "", open = false, testId = "", className = "" }) {
  return `
    <details
      class="disclosure-card settings-disclosure ${escapeHtml(className)}"
      data-settings-panel="${escapeHtml(panelId)}"
      ${open ? "open" : ""}
      ${testId ? `data-testid="${escapeHtml(testId)}"` : ""}
    >
      <summary class="disclosure-summary">
        <span class="disclosure-copy">
          <strong>${escapeHtml(title)}</strong>
          ${summary ? `<small>${escapeHtml(summary)}</small>` : ""}
        </span>
        <span class="disclosure-caret" aria-hidden="true">Expand</span>
      </summary>
      <div class="disclosure-body">
        ${body}
      </div>
    </details>
  `;
}

function settingsPanelState() {
  return state.settingsUi?.openPanels || {};
}

function isSettingsPanelOpen(panelId) {
  if (!panelId) return false;
  const persisted = settingsPanelState()[panelId];
  if (typeof persisted === "boolean") return persisted;
  return DEFAULT_SETTINGS_PANELS[panelId] ?? false;
}

function setSettingsPanelOpen(panelId, open) {
  if (!panelId) return;
  patchState(
    {
      settingsUi: {
        ...(state.settingsUi || {}),
        openPanels: {
          ...settingsPanelState(),
          [panelId]: Boolean(open),
        },
      },
    },
    "settings.ui.panel"
  );
}

function defaultScheduleTarget() {
  const allowlist = state.mission?.scope?.allowlist_json || {};
  const groups = ["urls", "cidr_ranges", "ip_addresses", "domains", "api_base_urls"];
  for (const group of groups) {
    const values = allowlist[group];
    if (Array.isArray(values) && values.length) {
      return String(values[0] || "");
    }
  }
  return "";
}

function targetConfigurationForSchedule(target) {
  const normalized = String(target || "").trim();
  if (!normalized) return {};
  if (/^https?:\/\//i.test(normalized)) return { urls: [normalized] };
  if (/^\d{1,3}(?:\.\d{1,3}){3}\/\d{1,2}$/.test(normalized)) return { cidr_ranges: [normalized] };
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(normalized)) return { ip_addresses: [normalized] };
  return { domains: [normalized] };
}

function nextScheduleStartIso(timeOfDay) {
  const [hours, minutes] = String(timeOfDay || "09:00")
    .split(":")
    .map((part) => Number(part));
  const next = new Date();
  next.setSeconds(0, 0);
  next.setHours(Number.isFinite(hours) ? hours : 9, Number.isFinite(minutes) ? minutes : 0, 0, 0);
  if (next.getTime() <= Date.now()) {
    next.setDate(next.getDate() + 1);
  }
  return next.toISOString();
}

function formatScheduleDate(value) {
  if (!value) return "not scheduled";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return date.toLocaleString();
}

function summarizeSection(section) {
  const settings = (section.settings || []).filter((setting) => !setting.ui_hidden);
  const count = settings.length;
  const sensitiveCount = settings.filter((setting) => setting.sensitive).length;
  const readOnlyCount = settings.filter((setting) => setting.read_only).length;
  const parts = [`${count} setting${count === 1 ? "" : "s"}`];
  if (sensitiveCount) parts.push(`${sensitiveCount} encrypted`);
  if (readOnlyCount) parts.push(`${readOnlyCount} read-only`);
  return parts.join(" · ");
}

function renderSection(section) {
  if (section.id === "ai_provider") {
    return renderAiProviderSection(section);
  }
  if (section.id === "instance") {
    return renderInstanceSection(section);
  }
  return renderSettingsDisclosure({
    panelId: section.id,
    title: section.title,
    summary: summarizeSection(section),
    open: isSettingsPanelOpen(section.id),
    testId: sectionTestId(section.id),
    className: "settings-panel-disclosure",
    body: `
      <p class="settings-section-copy">${escapeHtml(section.description || "")}</p>
      <div class="settings-fields">
        ${(section.settings || []).filter((setting) => !setting.ui_hidden).map(renderSetting).join("")}
      </div>
    `,
  });
}

function renderAiProviderSection(section) {
  const settings = (section.settings || []).filter((setting) => !setting.ui_hidden);
  const providerSettings = settings.filter((setting) => AI_PROVIDER_PRIMARY_KEYS.has(setting.key));
  const featureSettings = settings.filter((setting) => AI_FEATURE_SETTING_KEYS.has(setting.key));
  const providerValue = valueForSetting(providerSettings, "ai.provider");
  const warning = renderAiProviderWarning({
    providerValue,
    enabledFeatureCount: featureSettings.filter((setting) => Boolean(setting.value)).length,
  });
  return renderSettingsDisclosure({
    panelId: section.id,
    title: section.title,
    summary: summarizeSection(section),
    open: isSettingsPanelOpen(section.id),
    testId: sectionTestId(section.id),
    className: "settings-panel-disclosure",
    body: `
      <p class="settings-section-copy">${escapeHtml(section.description || "")}</p>
      <div class="settings-fields">
        ${providerSettings.map(renderSetting).join("")}
      </div>
      <section class="settings-subsection" data-testid="settings-ai-features">
        <div class="settings-subsection-head">
          <strong>AI Features</strong>
          <span>Save operator-facing AI defaults here instead of relying on environment edits.</span>
        </div>
        <div data-ai-provider-warning-slot>
          ${warning}
        </div>
        <div class="settings-fields settings-feature-fields">
          ${featureSettings.map(renderSetting).join("")}
        </div>
      </section>
    `,
  });
}

function renderInstanceSection(section) {
  const visibleSettings = (section.settings || []).filter((setting) => !setting.ui_hidden);
  return renderSettingsDisclosure({
    panelId: section.id,
    title: section.title,
    summary: summarizeSection(section),
    open: isSettingsPanelOpen(section.id),
    testId: sectionTestId(section.id),
    className: "settings-panel-disclosure",
    body: `
      <p class="settings-section-copy">${escapeHtml(section.description || "")}</p>
      <div class="settings-fields">
        ${visibleSettings.map(renderSetting).join("")}
      </div>
      <section class="settings-subsection" data-testid="settings-onboarding-controls">
        <div class="settings-subsection-head">
          <strong>First-run onboarding</strong>
          <span>Re-open the guided setup when you want to recheck AI, scope, and operator defaults.</span>
        </div>
        <div class="settings-oauth-actions">
          <button class="action ghost compact-action" type="button" data-onboarding-rerun data-testid="settings-rerun-onboarding">
            Re-run onboarding
          </button>
        </div>
      </section>
    `,
  });
}

function renderSetting(setting) {
  const value = setting.value;
  const fieldId = `setting-${setting.key.replace(/[^a-z0-9]+/gi, "-").toLowerCase()}`;
  return `
    <label class="settings-field ${setting.sensitive ? "is-sensitive" : ""}" data-testid="${escapeHtml(fieldId)}">
      <span class="settings-label-row">
        <strong>${escapeHtml(setting.label)}</strong>
        <span class="settings-source">${escapeHtml(setting.source)}${setting.read_only ? " / read-only" : ""}</span>
      </span>
      ${renderInput(setting, value)}
      <span class="settings-help">
        ${escapeHtml(setting.description || "")}
        ${setting.sensitive && setting.configured ? ` Current value: ${escapeHtml(setting.masked_value || "stored securely")}.` : ""}
      </span>
    </label>
  `;
}

function findSettingInput(form, key) {
  if (!form) return null;
  return Array.from(form.querySelectorAll("[data-setting-key]")).find(
    (input) => input.dataset.settingKey === key
  );
}

function collectChangedSettingInputs(form) {
  if (!form) return [];
  return Array.from(form.querySelectorAll("[data-setting-key]"))
    .filter((input) => !input.disabled)
    .map((input) => {
      const key = input.dataset.settingKey || "";
      const original = String(input.dataset.originalValue || "");
      const isCheckbox = String(input.type || "").toLowerCase() === "checkbox";
      const current = isCheckbox ? String(Boolean(input.checked)) : String(input.value || "").trim();
      return {
        key,
        changed: current !== original,
        value: isCheckbox ? Boolean(input.checked) : current,
      };
    })
    .filter((item) => item.key && item.changed);
}

function renderInput(setting, value) {
  const originalValue = setting.input_type === "list" && Array.isArray(value) ? value.join(", ") : String(value ?? "");
  const inputLabel = setting.label || setting.key;
  const common = `data-setting-key="${escapeHtml(setting.key)}" data-original-value="${escapeHtml(originalValue)}" aria-label="${escapeHtml(inputLabel)}" ${setting.read_only ? "disabled" : ""}`;
  const aiProviderControl = setting.key === "ai.provider" ? 'data-ai-provider-control="provider"' : "";
  const aiFeatureControl = AI_FEATURE_SETTING_KEYS.has(setting.key)
    ? 'data-ai-provider-control="feature-toggle"'
    : "";
  if (setting.input_type === "select") {
    const options = setting.options || [];
    return `
      <select ${common} ${aiProviderControl}>
        ${options
          .map(
            (option) =>
              `<option value="${escapeHtml(option.value)}" ${String(value ?? "") === String(option.value) ? "selected" : ""}>${escapeHtml(option.label)}</option>`
          )
          .join("")}
      </select>
    `;
  }
  if (setting.input_type === "checkbox") {
    return `
      <span class="settings-checkline">
        <input type="checkbox" data-setting-key="${escapeHtml(setting.key)}" data-original-value="${value ? "true" : "false"}" aria-label="${escapeHtml(inputLabel)}" ${aiFeatureControl} ${setting.read_only ? "disabled" : ""} ${value ? "checked" : ""} />
        <span>${value ? "Enabled" : "Disabled"}</span>
      </span>
    `;
  }
  const displayValue = setting.input_type === "list" && Array.isArray(value) ? value.join(", ") : String(value ?? "");
  if (setting.input_type === "number") {
    return `
      <input
        type="number"
        ${common}
        value="${escapeHtml(displayValue)}"
        ${setting.min_value !== null && setting.min_value !== undefined ? `min="${escapeHtml(setting.min_value)}"` : ""}
        ${setting.max_value !== null && setting.max_value !== undefined ? `max="${escapeHtml(setting.max_value)}"` : ""}
        ${setting.step !== null && setting.step !== undefined ? `step="${escapeHtml(setting.step)}"` : ""}
        placeholder="${escapeHtml(setting.placeholder || "Enter number")}"
      />
    `;
  }
  if (setting.sensitive) {
    return `
      <input
        type="password"
        ${common}
        value=""
        autocomplete="new-password"
        placeholder="${escapeHtml(setting.configured ? "Stored securely. Enter a new value to replace." : "Enter value to encrypt at rest")}"
      />
    `;
  }
  return `
    <input
      type="${escapeHtml(setting.input_type === "url" ? "url" : "text")}"
      ${common}
      value="${escapeHtml(displayValue)}"
      placeholder="Not set"
    />
  `;
}

function renderChatGPTStatus() {
  const status = state.chatgptOAuthStatus;
  const model = findSettingValue("ai.chatgpt_model") || "gpt-5.4";
  const selectedEngagement = runtime.actions.selectedEngagement?.();
  const connected = Boolean(status?.connected);
  const loading = Boolean(status?.loading);
  const reusable = Boolean(status?.reusable_session_available && !connected);
  const accountId = String(status?.account_id || "").trim();
  const listener = status?.local_callback_listener;
  const statusLabel = loading
    ? "Starting authorization"
    : connected
      ? "Connected"
      : status?.pendingAuthorization
        ? "Authorization window opened"
        : !state.selectedEngagementId
          ? "Engagement required"
          : status?.error
            ? "Needs attention"
            : "Not connected";
  const message = !state.selectedEngagementId
    ? "Select or create an engagement first. ChatGPT OAuth is stored per engagement so customer contexts stay separated."
    : status?.error
      ? String(status.error)
      : connected
        ? "AegisPT can use this encrypted ChatGPT OAuth session for enabled AI provider features."
        : reusable
          ? `An encrypted ChatGPT session for ${status.reusable_account_id || "another engagement"} is available. Use it here without logging in again.`
        : status?.pendingAuthorization
          ? "Complete the browser login in the opened window, then refresh status here."
          : "Connect a ChatGPT Plus/Pro account using PKCE. Tokens are encrypted through SecretRef and never rendered in this screen.";
  const callbackCopy =
    listener?.active && listener?.url
      ? `Local callback listener ready at ${listener.url}.`
      : "No token material is ever displayed in the UI.";
  const connectLabel = connected ? "Reconnect ChatGPT" : reusable ? "Use Existing ChatGPT Session" : "Connect ChatGPT";
  if (!state.selectedEngagementId) {
    return `
      <div class="settings-oauth-status" data-testid="settings-chatgpt-status">
        <div class="chip-row compact">
          <span class="status-chip neutral">${escapeHtml(statusLabel)}</span>
          <span class="status-chip neutral">model ${escapeHtml(model)}</span>
          <span class="status-chip neutral">token exposed: no</span>
        </div>
        <p class="settings-section-copy">${escapeHtml(message)}</p>
        <p class="micro-copy">Connection scope: ${escapeHtml(selectedEngagement?.name || "selected engagement")}</p>
        <div class="settings-oauth-actions">
          <button class="action secondary" type="button" data-settings-chatgpt-connect disabled>${escapeHtml(connectLabel)}</button>
          <button class="action ghost compact-action" type="button" data-settings-refresh-chatgpt disabled>Refresh status</button>
        </div>
      </div>
    `;
  }
  if (!status) {
    return `
      <div class="settings-oauth-status" data-testid="settings-chatgpt-status">
        <div class="chip-row compact">
          <span class="status-chip neutral">Status not checked</span>
          <span class="status-chip neutral">model ${escapeHtml(model)}</span>
          <span class="status-chip neutral">token exposed: no</span>
        </div>
        <p class="settings-section-copy">Refresh to read the engagement-scoped ChatGPT connection before reconnecting.</p>
        <p class="micro-copy">Connection scope: ${escapeHtml(selectedEngagement?.name || "selected engagement")}</p>
        <div class="settings-oauth-actions">
          <button class="action secondary" type="button" data-settings-chatgpt-connect>${escapeHtml(connectLabel)}</button>
          <button class="action ghost compact-action" type="button" data-settings-refresh-chatgpt>Refresh status</button>
        </div>
      </div>
    `;
  }
  return `
    <div class="settings-oauth-status" data-testid="settings-chatgpt-status">
      <div class="chip-row compact">
        <span class="status-chip ${connected ? "success" : status?.error ? "danger" : status?.pendingAuthorization ? "warning" : "neutral"}">${escapeHtml(statusLabel)}</span>
        ${accountId ? `<span class="status-chip neutral">${escapeHtml(accountId)}</span>` : ""}
        <span class="status-chip neutral">model ${escapeHtml(model)}</span>
        <span class="status-chip neutral">token exposed: no</span>
      </div>
      <p class="settings-section-copy">${escapeHtml(message)}</p>
      <p class="micro-copy">Connection scope: ${escapeHtml(selectedEngagement?.name || "selected engagement")} · ${escapeHtml(callbackCopy)}</p>
      <div class="settings-oauth-actions">
        <button class="action secondary" type="button" data-settings-chatgpt-connect ${loading ? "disabled" : ""}>${escapeHtml(loading ? "Starting OAuth..." : connectLabel)}</button>
        <button class="action ghost compact-action" type="button" data-settings-refresh-chatgpt ${loading ? "disabled" : ""}>Refresh status</button>
      </div>
    </div>
  `;
}

function renderChatGPTOAuthPanel() {
  const status = state.chatgptOAuthStatus;
  const model = findSettingValue("ai.chatgpt_model") || "gpt-5.4";
  const summary = !state.selectedEngagementId
    ? `Engagement required · ${model}`
    : status?.connected
      ? `${status.account_id || "Connected"} · ${model}`
      : status?.pendingAuthorization
        ? `Authorization opened · ${model}`
        : `${status?.error ? "Needs attention" : "Not connected"} · ${model}`;
  return renderSettingsDisclosure({
    panelId: "chatgpt_oauth",
    title: "ChatGPT OAuth",
    summary,
    open: isSettingsPanelOpen("chatgpt_oauth"),
    testId: "settings-chatgpt-oauth-panel",
    className: "settings-oauth-disclosure",
    body: renderChatGPTStatus(),
  });
}

function renderScheduledScansPanel() {
  const engagements = Array.isArray(state.engagements) ? state.engagements : [];
  const passiveProfiles = (state.runProfiles || []).filter((profile) => String(profile.run_class || "") === "passive");
  const selectedEngagementId = state.selectedEngagementId || engagements[0]?.id || "";
  const schedules = Array.isArray(state.scheduledRuns) ? state.scheduledRuns : [];
  const target = defaultScheduleTarget();
  const summary = schedules.length
    ? `${schedules.filter((item) => item.status === "enabled").length} enabled · ${schedules.length} total`
    : "No enabled schedules yet";
  return renderSettingsDisclosure({
    panelId: "scheduled_scans",
    title: "Scheduled Scans",
    summary,
    open: isSettingsPanelOpen("scheduled_scans"),
    testId: "settings-scheduled-scans-panel",
    className: "settings-schedule-disclosure",
    body: `
      <p class="settings-section-copy">Configure recurring passive baselines. Intrusive or approval-gated profiles cannot be scheduled.</p>
      ${state.scheduledRunsError ? `<p class="settings-error">${escapeHtml(state.scheduledRunsError)}</p>` : ""}
      <form class="settings-schedule-form" data-schedule-form data-testid="settings-schedule-form">
        <div class="settings-fields">
          <label class="settings-field">
            <span class="settings-label-row"><strong>Engagement</strong><span class="settings-source">required</span></span>
            <select data-schedule-field="engagement" aria-label="Scheduled scan engagement" ${engagements.length ? "" : "disabled"}>
              ${
                engagements.length
                  ? engagements
                      .map(
                        (engagement) =>
                          `<option value="${escapeHtml(engagement.id)}" ${String(engagement.id) === String(selectedEngagementId) ? "selected" : ""}>${escapeHtml(engagement.name || "Engagement")}</option>`
                      )
                      .join("")
                  : `<option value="">No engagement yet</option>`
              }
            </select>
            <span class="settings-help">The schedule is stored on the selected engagement and uses its approved scope.</span>
          </label>
          <label class="settings-field">
            <span class="settings-label-row"><strong>Passive profile</strong><span class="settings-source">passive only</span></span>
            <select data-schedule-field="profile" aria-label="Scheduled scan passive profile">
              ${
                passiveProfiles.length
                  ? passiveProfiles
                      .map(
                        (profile) =>
                          `<option value="${escapeHtml(profile.name)}" ${profile.name === "passive-web-baseline" ? "selected" : ""}>${escapeHtml(profile.name)}</option>`
                      )
                      .join("")
                  : `<option value="passive-web-baseline">passive-web-baseline</option>`
              }
            </select>
            <span class="settings-help">Scheduled scans intentionally exclude intrusive profiles.</span>
          </label>
          <label class="settings-field">
            <span class="settings-label-row"><strong>Target</strong><span class="settings-source">scope checked</span></span>
            <input data-schedule-field="target" type="text" value="${escapeHtml(target)}" placeholder="https://example.com or 10.0.20.0/24" aria-label="Scheduled scan target" />
            <span class="settings-help">Use a saved target already present in the engagement allowlist.</span>
          </label>
          <label class="settings-field">
            <span class="settings-label-row"><strong>Frequency</strong><span class="settings-source">daily / weekly / never</span></span>
            <select data-schedule-field="frequency" aria-label="Scheduled scan frequency">
              <option value="daily">Daily</option>
              <option value="weekly">Weekly</option>
              <option value="never">Never</option>
            </select>
            <span class="settings-help">Never leaves the system unchanged and does not create a schedule.</span>
          </label>
          <label class="settings-field">
            <span class="settings-label-row"><strong>Time of day</strong><span class="settings-source">local</span></span>
            <input data-schedule-field="time" type="time" value="09:00" aria-label="Scheduled scan time of day" />
            <span class="settings-help">The backend stores the next run timestamp; Dashboard shows the upcoming scan.</span>
          </label>
          <label class="settings-field">
            <span class="settings-label-row"><strong>Enabled</strong><span class="settings-source">toggle</span></span>
            <input data-schedule-field="enabled" type="checkbox" checked aria-label="Enable scheduled scan" />
            <span class="settings-help">Disable this before saving if you only wanted to review the fields.</span>
          </label>
        </div>
        <div class="settings-oauth-actions">
          <button class="action primary" type="submit" ${engagements.length ? "" : "disabled"}>${escapeHtml(state.scheduledRunsLoading ? "Saving..." : "Save Schedule")}</button>
          <button class="action ghost compact-action" type="button" data-settings-refresh-schedules ${selectedEngagementId ? "" : "disabled"}>Refresh schedules</button>
        </div>
      </form>
      <div class="settings-schedule-list" data-testid="settings-schedule-list">
        ${
          schedules.length
            ? schedules
                .map(
                  (schedule) => `
                    <div class="settings-schedule-row">
                      <strong>${escapeHtml(schedule.profile_name || "Scheduled scan")}</strong>
                      <span>${escapeHtml(schedule.cadence || "daily")} · ${escapeHtml(schedule.status || "enabled")} · next ${escapeHtml(formatScheduleDate(schedule.next_run_at))}</span>
                    </div>
                  `
                )
                .join("")
            : `<p class="settings-section-copy">No recurring baseline is configured for the selected engagement yet.</p>`
        }
      </div>
    `,
  });
}

function renderThreatIntelPanel() {
  const status = state.threatIntelStatus || null;
  const watchlist = Array.isArray(state.threatIntelWatchlist) ? state.threatIntelWatchlist : [];
  const records = Array.isArray(state.threatIntelRecords) ? state.threatIntelRecords : [];
  const approved = watchlist.filter((entry) => entry.status === "approved");
  const suggested = watchlist.filter((entry) => entry.status === "suggested");
  const summary = status
    ? `${approved.length} approved · ${suggested.length} suggested · local-cache only`
    : "Status not checked";
  return renderSettingsDisclosure({
    panelId: "threat_intel_controls",
    title: "Threat Intel Cache",
    summary,
    open: isSettingsPanelOpen("threat_intel_controls"),
    testId: "settings-threat-intel-panel",
    className: "settings-engagement-disclosure",
    body: `
      <div class="settings-engagement-actions">
        <p class="settings-section-copy">CISA KEV and NCSC NL sync in full. NVD and OpenCVE only use the approved product watchlist; findings never call external feeds.</p>
        <div class="settings-oauth-actions">
          <button class="action ghost compact-action" type="button" data-settings-refresh-threat-intel ${state.threatIntelLoading ? "disabled" : ""}>
            ${state.threatIntelLoading ? "Refreshing..." : "Refresh"}
          </button>
          <button class="action secondary compact-action" type="button" data-settings-sync-threat-intel ${state.threatIntelSyncing ? "disabled" : ""} data-testid="threat-intel-sync-now">
            ${state.threatIntelSyncing ? "Syncing..." : "Sync Now"}
          </button>
        </div>
      </div>
      ${state.threatIntelError ? `<p class="settings-inline-error" data-testid="threat-intel-error">${escapeHtml(state.threatIntelError)}</p>` : ""}
      <div class="settings-threat-grid">
        ${renderThreatIntelSourceStatus(status?.sources || [])}
      </div>
      <section class="settings-subsection" data-testid="threat-intel-watchlist">
        <div class="settings-subsection-head">
          <strong>Product Watchlist</strong>
          <span>${approved.length} approved source${approved.length === 1 ? "" : "s"} for NVD/OpenCVE filtering</span>
        </div>
        <form class="settings-inline-form" data-threat-intel-watchlist-form>
          <input type="text" data-threat-intel-watchlist-query placeholder="Add product, vendor product, or CPE keyword" aria-label="Threat intel product watchlist keyword" />
          <button class="action primary compact-action" type="submit" data-testid="threat-intel-watchlist-add" ${state.threatIntelLoading ? "disabled" : ""}>Add</button>
          <button class="action ghost compact-action" type="button" data-settings-threat-intel-suggest ${!state.selectedEngagementId || state.threatIntelLoading ? "disabled" : ""}>Suggest from Inventory</button>
        </form>
        ${renderThreatIntelWatchlist(watchlist)}
      </section>
      <section class="settings-subsection" data-testid="threat-intel-template-candidates">
        <div class="settings-subsection-head">
          <strong>CVE Test Templates</strong>
          <span>${records.filter(isCveThreatIntelRecord).length} local CVE candidate${records.filter(isCveThreatIntelRecord).length === 1 ? "" : "s"}</span>
        </div>
        ${renderThreatIntelTemplateCandidates(records)}
      </section>
    `,
  });
}

function renderDataRetentionPanel() {
  const engagement = runtime.actions.selectedEngagement?.();
  const status = state.dataRetentionStatus || null;
  const loading = Boolean(state.dataRetentionLoading);
  const summary = status
    ? `${status.retention_days} days · ${status.eligible_run_count} eligible · next ${formatTimestamp(status.next_cleanup_at)}`
    : engagement
      ? "Policy not loaded"
      : "Select an engagement";
  const purgePhrase = engagement?.name ? `PURGE ${engagement.name}` : "PURGE <engagement name>";
  return renderSettingsDisclosure({
    panelId: "data_retention",
    title: "Data Retention",
    summary,
    open: isSettingsPanelOpen("data_retention"),
    testId: "settings-data-retention-panel",
    className: "settings-engagement-disclosure",
    body: `
      <div class="settings-engagement-actions">
        <p class="settings-section-copy">AVG/GDPR data handling is engagement-scoped. Exports exclude credential material; irreversible purge requires typed confirmation.</p>
        <div class="settings-oauth-actions">
          <button class="action ghost compact-action" type="button" data-settings-refresh-retention ${!engagement || loading ? "disabled" : ""}>
            ${loading ? "Refreshing..." : "Refresh"}
          </button>
        </div>
      </div>
      ${state.dataRetentionError ? `<p class="settings-inline-error" data-testid="data-retention-error">${escapeHtml(state.dataRetentionError)}</p>` : ""}
      ${
        engagement
          ? `
            <div class="settings-threat-grid">
              <article class="threat-source-card status-completed">
                <strong>Retention Window</strong>
                <p>${escapeHtml(String(status?.retention_days ?? engagement.retention_days ?? 90))} days</p>
              </article>
              <article class="threat-source-card">
                <strong>Next Cleanup</strong>
                <p>${escapeHtml(status?.next_cleanup_at ? formatTimestamp(status.next_cleanup_at) : "Not loaded")}</p>
              </article>
              <article class="threat-source-card">
                <strong>Eligible Runs</strong>
                <p>${escapeHtml(String(status?.eligible_run_count ?? 0))} eligible · ${escapeHtml(String(status?.active_run_count ?? 0))} active</p>
              </article>
            </div>
            <form class="settings-inline-form" data-retention-policy-form data-testid="data-retention-policy-form">
              <input type="number" min="1" max="3650" name="retention_days" value="${escapeHtml(String(status?.retention_days ?? engagement.retention_days ?? 90))}" aria-label="Retention days" />
              <button class="action primary compact-action" type="submit" ${loading ? "disabled" : ""}>Save Policy</button>
              <button class="action ghost compact-action" type="button" data-retention-cleanup ${loading ? "disabled" : ""}>Run Cleanup</button>
            </form>
            <form class="settings-inline-form danger" data-retention-purge-form data-testid="data-retention-purge-form">
              <input type="text" name="purge_confirmation" placeholder="${escapeHtml(purgePhrase)}" aria-label="Purge confirmation" />
              <button class="action secondary compact-action" type="submit" ${loading ? "disabled" : ""}>Delete All Assessment Data</button>
            </form>
            <p class="settings-section-copy">Type <code>${escapeHtml(purgePhrase)}</code> to hard-delete assessment data while keeping the engagement shell and audit trail.</p>
          `
          : `<p class="settings-section-copy">Select an engagement before changing retention, exporting data, or purging assessment records.</p>`
      }
    `,
  });
}

function renderThreatIntelSourceStatus(sources) {
  const items = sources.length
    ? sources
    : ["cisa_kev", "ncsc_nl", "nvd", "opencve"].map((source) => ({
        source,
        label: sourceLabel(source),
        status: "never_synced",
        imported_count: 0,
        updated_count: 0,
        skipped_count: 0,
      }));
  return items
    .map(
      (source) => `
        <article class="threat-source-card status-${escapeHtml(source.status || "unknown")}" data-testid="threat-intel-source-${escapeHtml(source.source)}">
          <div class="settings-label-row">
            <strong>${escapeHtml(source.label || sourceLabel(source.source))}</strong>
            <span class="status-chip ${statusChipClass(source.status)}">${escapeHtml(formatStatus(source.status))}</span>
          </div>
          <p>${escapeHtml(source.completed_at ? formatTimestamp(source.completed_at) : source.metadata?.reason || "No sync recorded yet")}</p>
          <div class="chip-row compact">
            <span class="status-chip neutral">${Number(source.imported_count || 0)} imported</span>
            <span class="status-chip neutral">${Number(source.updated_count || 0)} updated</span>
            <span class="status-chip neutral">${Number(source.skipped_count || 0)} skipped</span>
          </div>
          ${sourceStatusExplanation(source) ? `<p class="settings-section-copy">${escapeHtml(sourceStatusExplanation(source))}</p>` : ""}
          ${source.error ? `<p class="settings-inline-warning">${escapeHtml(source.error)}</p>` : ""}
        </article>
      `
    )
    .join("");
}

function sourceStatusExplanation(source) {
  const status = String(source?.status || "").toLowerCase();
  const reason = String(source?.metadata?.reason || "").toLowerCase();
  if (status === "skipped" && reason === "missing_optional_token") {
    return `${source.label || sourceLabel(source.source)} was skipped because no optional API token is configured. Local finding lookups still use the other completed cache sources.`;
  }
  if (status === "skipped" && reason === "empty_watchlist") {
    return `${source.label || sourceLabel(source.source)} is watchlist-only and was skipped because no approved product watchlist exists yet.`;
  }
  if (status === "failed" && reason === "rate_limited") {
    return `${source.label || sourceLabel(source.source)} was rate limited by the provider. Try again later or configure the optional API key; the existing local cache remains available.`;
  }
  if (status === "failed" && reason === "credential_rejected") {
    return `${source.label || sourceLabel(source.source)} rejected the configured credential. Check the feed credential before syncing again.`;
  }
  if (status === "failed") {
    return `${source.label || sourceLabel(source.source)} failed non-blocking; the existing local cache remains available.`;
  }
  return "";
}

function renderThreatIntelWatchlist(entries) {
  if (!entries.length) {
    return `<div class="cicd-history-empty">No products are approved yet. Add the products you actually run, or derive suggestions from the latest inventory snapshot.</div>`;
  }
  return `
    <div class="threat-watchlist-list">
      ${entries
        .map(
          (entry) => `
            <article class="threat-watchlist-row" data-testid="threat-intel-watchlist-row">
              <span class="status-dot status-${escapeHtml(entry.status || "unknown")}"></span>
              <div>
                <strong>${escapeHtml(entry.query)}</strong>
                <p>${escapeHtml(`${entry.status || "unknown"} · ${entry.source || "operator"}${entry.source_inventory_snapshot_id ? " · inventory suggestion" : ""}`)}</p>
              </div>
              <div class="settings-oauth-actions">
                ${
                  entry.status === "suggested"
                    ? `<button class="action secondary compact-action" type="button" data-threat-intel-approve="${escapeHtml(entry.id)}">Approve</button>`
                    : ""
                }
                <button class="action ghost compact-action" type="button" data-threat-intel-remove="${escapeHtml(entry.id)}">Remove</button>
              </div>
            </article>
          `
        )
        .join("")}
    </div>
  `;
}

function renderThreatIntelTemplateCandidates(records) {
  const cveRecords = records.filter(isCveThreatIntelRecord).slice(0, 8);
  if (!cveRecords.length) {
    return `<div class="cicd-history-empty">No local CVE records are available yet. Sync or ingest threat intel before generating review-gated Nuclei templates.</div>`;
  }
  const result = state.threatIntelTemplateResult || null;
  return `
    <div class="threat-watchlist-list">
      ${cveRecords
        .map((record) => {
          const generated = generatedTemplateForRecord(record);
          const isGenerating = state.threatIntelTemplateGeneratingId === record.id;
          const canGenerate = state.selectedEngagementId && !generated?.pack_id && !isGenerating;
          return `
            <article class="threat-watchlist-row threat-template-row" data-testid="threat-intel-template-row">
              <span class="status-dot status-${escapeHtml(generated?.status || "suggested")}"></span>
              <div>
                <strong>${escapeHtml(record.advisory_id || "CVE record")}</strong>
                <p>${escapeHtml(record.title || "No title recorded.")}</p>
                <div class="chip-row compact">
                  <span class="status-chip neutral">${escapeHtml(record.severity || "severity n/a")}</span>
                  <span class="status-chip neutral">${escapeHtml((record.affected_products_json || []).slice(0, 2).join(", ") || "product n/a")}</span>
                  <span class="status-chip ${generated?.pack_id ? "warning" : "neutral"}">${escapeHtml(generated?.status || "not generated")}</span>
                </div>
              </div>
              <div class="settings-oauth-actions">
                ${
                  generated?.pack_id
                    ? `<button class="action secondary compact-action" type="button" data-nav-screen="pack-forge">Review in Pack Forge</button>`
                    : `<button class="action primary compact-action" type="button" data-threat-intel-generate-template="${escapeHtml(record.id)}" ${canGenerate ? "" : "disabled"}>${escapeHtml(isGenerating ? "Generating..." : "Generate Test Template")}</button>`
                }
              </div>
            </article>
          `;
        })
        .join("")}
    </div>
    ${result ? renderThreatIntelTemplateResult(result) : ""}
  `;
}

function renderThreatIntelTemplateResult(result) {
  const generated = result.generated_template || {};
  return `
    <article class="settings-result-card" data-testid="threat-intel-template-result">
      <div class="settings-label-row">
        <strong>${escapeHtml(result.status === "generated" ? "Generated template review" : "Template generation status")}</strong>
        <span class="status-chip ${result.status === "generated" ? "warning" : result.status === "unavailable" ? "danger" : "neutral"}">${escapeHtml(result.status || "unknown")}</span>
      </div>
      <p>${escapeHtml(result.message || result.lifecycle_note || "Review required before runtime use.")}</p>
      ${result.review_url || generated.review_url ? `<button class="action secondary compact-action" type="button" data-nav-screen="pack-forge">Review in Pack Forge</button>` : ""}
      ${result.yaml_diff ? `<pre class="settings-yaml-diff">${escapeHtml(result.yaml_diff).slice(0, 2400)}</pre>` : ""}
    </article>
  `;
}

function isCveThreatIntelRecord(record) {
  const values = [
    record?.advisory_id,
    record?.title,
    record?.summary,
    ...(record?.product_match_hints_json || []),
    ...(record?.suggested_test_patterns_json || []),
    record?.metadata_json?.cve_id,
  ];
  return values.some((value) => /\bCVE-\d{4}-\d{4,}\b/i.test(String(value || "")));
}

function generatedTemplateForRecord(record) {
  const generated = record?.metadata_json?.generated_nuclei_template;
  return generated && typeof generated === "object" ? generated : null;
}

function renderSiemPanel() {
  const configuredCount = (state.siemIntegrationSettings?.providers || []).length;
  const summary = !state.selectedEngagementId
    ? "Select an engagement to configure push-only delivery"
    : `${configuredCount} configured provider${configuredCount === 1 ? "" : "s"} · ${SIEM_PROVIDERS.length} available`;
  if (!state.selectedEngagementId) {
    return renderSettingsDisclosure({
      panelId: "engagement_siem",
      title: "Delivery Integrations",
      summary,
      open: isSettingsPanelOpen("engagement_siem"),
      testId: "settings-siem-panel",
      className: "settings-engagement-disclosure",
      body: `<p class="settings-section-copy">Select an engagement to configure encrypted SIEM delivery credentials and push rules.</p>`,
    });
  }

  return renderSettingsDisclosure({
    panelId: "engagement_siem",
    title: "Delivery Integrations",
    summary,
    open: isSettingsPanelOpen("engagement_siem"),
    testId: "settings-siem-panel",
    className: "settings-engagement-disclosure",
    body: `
      <div class="settings-engagement-actions">
        <p class="settings-section-copy">Push-only delivery only. Findings and run-completion events are labeled as <code>aegispt-pentest-finding</code>, and credentials stay encrypted at rest.</p>
        <button class="action ghost compact-action" type="button" data-settings-refresh-siem ${state.siemIntegrationLoading ? "disabled" : ""}>
          ${state.siemIntegrationLoading ? "Refreshing..." : "Refresh"}
        </button>
      </div>
      ${state.siemIntegrationError ? `<p class="settings-inline-error">${escapeHtml(state.siemIntegrationError)}</p>` : ""}
      <div class="settings-substack">
        ${SIEM_PROVIDERS.map((provider) => renderSiemProviderCard(resolveSiemProvider(provider.id), provider)).join("")}
      </div>
    `,
  });
}

function renderJiraPanel() {
  const configuration = state.jiraIntegrationConfiguration || {};
  const configured = Boolean(configuration.id);
  const authMethod = String(configuration.settings_json?.auth_method || "api_token");
  const summary = !state.selectedEngagementId
    ? "Select an engagement to configure Jira handoff"
    : configured
      ? `${configuration.project_key || "No project"} · ${configuration.base_url || "base URL missing"}`
      : "Not configured";
  if (!state.selectedEngagementId) {
    return renderSettingsDisclosure({
      panelId: "engagement_jira",
      title: "Jira Handoff",
      summary,
      open: isSettingsPanelOpen("engagement_jira"),
      testId: "settings-jira-panel",
      className: "settings-engagement-disclosure",
      body: `<p class="settings-section-copy">Select an engagement to configure Jira tickets for finding triage.</p>`,
    });
  }
  return renderSettingsDisclosure({
    panelId: "engagement_jira",
    title: "Jira Handoff",
    summary,
    open: isSettingsPanelOpen("engagement_jira"),
    testId: "settings-jira-panel",
    className: "settings-engagement-disclosure",
    body: `
      <div class="settings-engagement-actions">
        <p class="settings-section-copy">Store the engagement-scoped Jira target used by Finding and Problems handoff buttons. Credentials are protected references, not raw tokens.</p>
        <div class="settings-oauth-actions">
          <button class="action ghost compact-action" type="button" data-settings-refresh-jira ${state.jiraIntegrationLoading ? "disabled" : ""}>
            ${state.jiraIntegrationLoading ? "Refreshing..." : "Refresh"}
          </button>
          <button class="action ghost compact-action" type="button" data-settings-test-jira ${configured && !state.jiraIntegrationTesting ? "" : "disabled"} data-testid="settings-jira-test">
            ${state.jiraIntegrationTesting ? "Testing..." : "Test Connection"}
          </button>
        </div>
      </div>
      ${state.jiraIntegrationError ? `<p class="settings-inline-error" data-testid="settings-jira-error">${escapeHtml(state.jiraIntegrationError)}</p>` : ""}
      ${state.jiraIntegrationTestResult ? `<p class="settings-subtle-note" data-testid="settings-jira-test-result">${escapeHtml(state.jiraIntegrationTestResult)}</p>` : ""}
      <form class="cicd-trigger-card cicd-trigger-card-form" data-jira-integration-form data-testid="settings-jira-form">
        <div class="cicd-trigger-head">
          <div>
            <strong>${escapeHtml(configuration.display_name || "Jira")}</strong>
            <span>${escapeHtml(configured ? "configured" : "unconfigured")} · ${escapeHtml(configuration.auth_ref ? "auth ref stored" : "auth ref missing")}</span>
          </div>
          <span class="status-chip ${configured ? "success" : "neutral"}">${escapeHtml(configured ? "active" : "setup required")}</span>
        </div>
        <label class="settings-field">
          <span class="settings-label-row"><strong>Display name</strong><span class="settings-source">engagement</span></span>
          <input type="text" data-jira-field="display-name" value="${escapeHtml(configuration.display_name || "")}" placeholder="Security Jira" />
          <span class="settings-help">Operator-facing label shown near Jira handoff controls.</span>
        </label>
        <label class="settings-field">
          <span class="settings-label-row"><strong>Base URL</strong><span class="settings-source">required</span></span>
          <input type="url" data-jira-field="base-url" value="${escapeHtml(configuration.base_url || "")}" placeholder="https://jira.example.com" required />
          <span class="settings-help">AegisPT builds issue links as base URL plus /browse/PROJECT-key.</span>
        </label>
        <label class="settings-field">
          <span class="settings-label-row"><strong>Project key</strong><span class="settings-source">routing</span></span>
          <input type="text" data-jira-field="project-key" value="${escapeHtml(configuration.project_key || "")}" placeholder="AEGIS" />
          <span class="settings-help">Used for generated finding handoff keys when no Jira key exists yet.</span>
        </label>
        <label class="settings-field">
          <span class="settings-label-row"><strong>Auth method</strong><span class="settings-source">API token / OAuth</span></span>
          <select data-jira-field="auth-method">
            <option value="api_token" ${authMethod === "api_token" ? "selected" : ""}>API token</option>
            <option value="oauth" ${authMethod === "oauth" ? "selected" : ""}>OAuth</option>
          </select>
          <span class="settings-help">This records the expected credential mode for operators and backend sync.</span>
        </label>
        <label class="settings-field">
          <span class="settings-label-row"><strong>Credential reference</strong><span class="settings-source">protected</span></span>
          <input type="text" data-jira-field="auth-ref" value="${escapeHtml(configuration.auth_ref || "")}" placeholder="secret://engagements/acme/jira-token" />
          <span class="settings-help">Use a vault/env/secret reference. Do not paste raw Jira tokens here.</span>
        </label>
        <label class="settings-field">
          <span class="settings-label-row"><strong>Issue type</strong><span class="settings-source">default</span></span>
          <input type="text" data-jira-field="issue-type" value="${escapeHtml(configuration.settings_json?.issue_type || "Bug")}" placeholder="Bug" />
          <span class="settings-help">Stored with the integration for future remote issue creation or handoff policies.</span>
        </label>
        <div class="cicd-trigger-foot">
          <span>${escapeHtml(configured ? "Findings can now be handed off to Jira from the drawer and Problems Center." : "Save this configuration before pushing findings to Jira.")}</span>
          <button class="action primary compact-action" type="submit" ${state.jiraIntegrationSaving ? "disabled" : ""}>
            ${state.jiraIntegrationSaving ? "Saving..." : "Save Jira"}
          </button>
        </div>
      </form>
    `,
  });
}

function renderSiemProviderCard(configuration, provider) {
  const saving = state.siemIntegrationSavingProvider === provider.id;
  const credentialLabel = configuration.credential_configured ? "stored" : "missing";
  const statusLabel = configuration.id ? "configured" : "unconfigured";
  const routeValue = String(configuration[provider.routeField] || "").trim();
  const extraValue = provider.extraField ? String(configuration[provider.extraField] || "").trim() : "";
  return renderSettingsDisclosure({
    panelId: `siem_${provider.id}`,
    title: provider.label,
    summary: `${statusLabel} · credential ${credentialLabel}`,
    open: isSettingsPanelOpen(`siem_${provider.id}`) || saving,
    testId: `siem-integration-${provider.id}`,
    className: "settings-nested-disclosure",
    body: `
    <form class="cicd-trigger-card cicd-trigger-card-form" data-siem-provider-form="${escapeHtml(provider.id)}">
      <div class="cicd-trigger-head">
        <div>
          <strong>${escapeHtml(provider.label)}</strong>
          <span>${escapeHtml(statusLabel)} - credential ${escapeHtml(credentialLabel)}</span>
        </div>
        <label class="settings-checkline">
          <input type="checkbox" data-siem-field="enabled" ${configuration.enabled ? "checked" : ""} />
          <span>Enabled</span>
        </label>
      </div>
      <label class="settings-field">
        <span class="settings-label-row">
          <strong>Display name</strong>
          <span class="settings-source">engagement</span>
        </span>
        <input type="text" data-siem-field="display-name" value="${escapeHtml(configuration.display_name || "")}" placeholder="${escapeHtml(provider.label)}" />
        <span class="settings-help">Operator-facing label for this engagement-scoped SIEM target.</span>
      </label>
      <label class="settings-field">
        <span class="settings-label-row">
          <strong>${escapeHtml(provider.baseLabel)}</strong>
          <span class="settings-source">push only</span>
        </span>
        <input type="url" data-siem-field="base-url" value="${escapeHtml(configuration.base_url || "")}" placeholder="${escapeHtml(provider.basePlaceholder)}" />
        <span class="settings-help">AegisPT posts findings and run-completion events here without reading back from the SIEM.</span>
      </label>
      <label class="settings-field">
        <span class="settings-label-row">
          <strong>${escapeHtml(provider.routeLabel)}</strong>
          <span class="settings-source">routing</span>
        </span>
        <input type="text" data-siem-field="${escapeHtml(provider.routeField.replaceAll("_", "-"))}" value="${escapeHtml(routeValue)}" placeholder="${escapeHtml(provider.routePlaceholder)}" />
        <span class="settings-help">Destination routing for this provider.</span>
      </label>
      ${
        provider.extraField
          ? `
            <label class="settings-field">
              <span class="settings-label-row">
                <strong>${escapeHtml(provider.extraLabel || "Additional routing")}</strong>
                <span class="settings-source">provider</span>
              </span>
              <input type="text" data-siem-field="${escapeHtml(provider.extraField.replaceAll("_", "-"))}" value="${escapeHtml(extraValue)}" placeholder="${escapeHtml(provider.extraPlaceholder || "")}" />
              <span class="settings-help">Optional provider-specific routing hint.</span>
            </label>
          `
          : ""
      }
      <label class="settings-field">
        <span class="settings-label-row">
          <strong>${escapeHtml(provider.credentialLabel)}</strong>
          <span class="settings-source">${escapeHtml(configuration.credential_display_label || "encrypted")}</span>
        </span>
        <input type="password" data-siem-field="credential" value="" autocomplete="new-password" placeholder="${escapeHtml(configuration.credential_configured ? "Stored securely. Enter a new value to rotate." : `Enter ${provider.credentialLabel.toLowerCase()}`)}" />
        <span class="settings-help">The credential is encrypted at rest and never returned in plaintext.</span>
      </label>
      <label class="settings-field">
        <span class="settings-label-row">
          <strong>Timeout seconds</strong>
          <span class="settings-source">delivery</span>
        </span>
        <input type="text" data-siem-field="timeout-seconds" value="${escapeHtml(configuration.timeout_seconds || "")}" placeholder="10" />
        <span class="settings-help">Network timeout for outbound SIEM delivery attempts.</span>
      </label>
      <label class="settings-checkline cicd-trigger-checkline">
        <input type="checkbox" data-siem-field="push-run-completion" ${configuration.push_on_run_completion ? "checked" : ""} />
        <span>Push on run completion</span>
      </label>
      <label class="settings-checkline cicd-trigger-checkline">
        <input type="checkbox" data-siem-field="push-critical-finding" ${configuration.push_on_critical_finding ? "checked" : ""} />
        <span>Push immediately on new critical finding</span>
      </label>
      <label class="settings-checkline cicd-trigger-checkline">
        <input type="checkbox" data-siem-field="include-sigma" ${configuration.include_sigma ? "checked" : ""} />
        <span>Include advisory Sigma export when detection guidance exists</span>
      </label>
      <div class="cicd-trigger-foot">
        <span>${renderSiemProviderMeta(provider.id, configuration)}</span>
        <button class="action primary compact-action" type="submit" ${saving ? "disabled" : ""}>
          ${saving ? "Saving..." : "Save Integration"}
        </button>
      </div>
    </form>
    `,
  });
}

function renderSiemProviderMeta(providerId, configuration) {
  const routing = configuration.index_name || configuration.custom_log_table || configuration.stream_name || "default routing";
  const sigma = configuration.include_sigma ? "Sigma advisory export enabled" : "Sigma export disabled";
  return `${siemProviderLabel(providerId)} - ${routing} - ${sigma}`;
}

function renderCicdPanel() {
  if (!state.selectedEngagementId) {
    return renderSettingsDisclosure({
      panelId: "engagement_cicd",
      title: "Trigger Automation",
      summary: "Select an engagement to configure signed deploy triggers",
      open: isSettingsPanelOpen("engagement_cicd"),
      testId: "settings-cicd-panel",
      className: "settings-engagement-disclosure",
      body: `<p class="settings-section-copy">Select an engagement to configure encrypted webhook secrets and recent trigger history.</p>`,
    });
  }

  const payload = state.cicdTriggerSettings || { triggers: [], history: [] };
  const historyCount = (payload.history || []).length;
  return renderSettingsDisclosure({
    panelId: "engagement_cicd",
    title: "Trigger Automation",
    summary: `${CICD_TRIGGER_SOURCES.length} sources · ${historyCount} recent event${historyCount === 1 ? "" : "s"}`,
    open: isSettingsPanelOpen("engagement_cicd"),
    testId: "settings-cicd-panel",
    className: "settings-engagement-disclosure",
    body: `
      <div class="settings-engagement-actions">
        <p class="settings-section-copy">Configure one encrypted webhook secret per source. Matching deploy events launch runs through the existing approval-aware path only.</p>
        <button class="action ghost compact-action" type="button" data-settings-refresh-cicd ${state.cicdTriggerLoading ? "disabled" : ""}>
          ${state.cicdTriggerLoading ? "Refreshing..." : "Refresh"}
        </button>
      </div>
      ${state.cicdTriggerError ? `<p class="settings-inline-error">${escapeHtml(state.cicdTriggerError)}</p>` : ""}
      <div class="settings-substack">
        ${CICD_TRIGGER_SOURCES.map((source) => renderCicdTriggerCard(resolveTrigger(source.id), source.label)).join("")}
        ${renderSettingsDisclosure({
          panelId: "cicd_history",
          title: "Recent Trigger History",
          summary: historyCount ? `${historyCount} recorded event${historyCount === 1 ? "" : "s"}` : "No events recorded yet",
          open: isSettingsPanelOpen("cicd_history"),
          testId: "settings-cicd-history",
          className: "settings-nested-disclosure",
          body: `
        <aside class="cicd-history-card">
          <div class="cicd-history-head">
            <strong>Recent Trigger History</strong>
            <span>Last 10 events</span>
          </div>
          ${renderCicdHistory(payload.history || [])}
        </aside>
          `,
        })}
      </div>
    `,
  });
}

function renderCicdTriggerCard(trigger, label) {
  const source = trigger.trigger_source;
  const saving = state.cicdTriggerSavingSource === source;
  const profiles = (trigger.enabled_profiles || []).join(", ") || defaultTriggerProfiles(source).join(", ");
  const branches = (trigger.branch_filters || []).join(", ") || "main";
  return renderSettingsDisclosure({
    panelId: `cicd_${source}`,
    title: label,
    summary: `${trigger.configured ? trigger.status : "unconfigured"} · secret ${trigger.webhook_secret_configured ? "stored" : "missing"}`,
    open: isSettingsPanelOpen(`cicd_${source}`) || saving,
    testId: `cicd-trigger-${source}`,
    className: "settings-nested-disclosure",
    body: `
    <form class="cicd-trigger-card cicd-trigger-card-form" data-cicd-trigger-form="${escapeHtml(source)}">
      <div class="cicd-trigger-head">
        <div>
          <strong>${escapeHtml(label)}</strong>
          <span>${escapeHtml(trigger.configured ? trigger.status : "unconfigured")} - secret ${trigger.webhook_secret_configured ? "stored" : "missing"}</span>
        </div>
        <label class="settings-checkline">
          <input type="checkbox" data-cicd-field="enabled" ${trigger.status !== "disabled" ? "checked" : ""} />
          <span>Enabled</span>
        </label>
      </div>
      <label class="settings-field">
        <span class="settings-label-row">
          <strong>Run profiles</strong>
          <span class="settings-source">engagement</span>
        </span>
        <input type="text" data-cicd-field="profiles" value="${escapeHtml(profiles)}" placeholder="passive-web-baseline" />
        <span class="settings-help">Comma-separated run profiles launched when the signed trigger matches.</span>
      </label>
      <label class="settings-field">
        <span class="settings-label-row">
          <strong>Branch filters</strong>
          <span class="settings-source">glob</span>
        </span>
        <input type="text" data-cicd-field="branches" value="${escapeHtml(branches)}" placeholder="main, release/*" />
        <span class="settings-help">Matches branch names like <code>main</code> or <code>release/*</code>.</span>
      </label>
      <label class="settings-field">
        <span class="settings-label-row">
          <strong>Webhook secret</strong>
          <span class="settings-source">${escapeHtml(trigger.webhook_display_label || "encrypted")}</span>
        </span>
        <input type="password" data-cicd-field="webhook-secret" value="" autocomplete="new-password" placeholder="${escapeHtml(trigger.webhook_secret_configured ? "Stored securely. Enter a new value to rotate." : "Enter webhook secret")}" />
        <span class="settings-help">Used to verify the HMAC signature header. The secret is never returned by the API.</span>
      </label>
      <label class="settings-checkline cicd-trigger-checkline">
        <input type="checkbox" data-cicd-field="scope-override" ${trigger.scope_override_allowed ? "checked" : ""} />
        <span>Allow in-scope target URL override</span>
      </label>
      <div class="cicd-trigger-foot">
        <span>${renderCicdTriggerMeta(trigger)}</span>
        <button class="action primary compact-action" type="submit" ${saving ? "disabled" : ""}>
          ${saving ? "Saving..." : "Save Trigger"}
        </button>
      </div>
    </form>
    `,
  });
}

function renderCicdTriggerMeta(trigger) {
  const endpoint = "/api/v1/triggers/cicd";
  const lastRun = trigger.last_run_id ? ` - last run ${escapeHtml(trigger.last_run_status || "created")}` : "";
  const lastTriggered = trigger.last_triggered_at ? `Last event ${escapeHtml(formatTimestamp(trigger.last_triggered_at))}${lastRun}` : "No events yet";
  return `${lastTriggered} - POST ${escapeHtml(endpoint)}`;
}

function renderCicdHistory(history) {
  if (!history.length) {
    return `<div class="cicd-history-empty">No CI/CD trigger events have been recorded for this engagement yet.</div>`;
  }
  return `
    <div class="cicd-history-list">
      ${history
        .map(
          (item) => `
            <article class="cicd-history-item">
              <div class="cicd-history-item-top">
                <strong>${escapeHtml(triggerSourceLabel(item.trigger_source))}</strong>
                <span class="cicd-history-status is-${escapeHtml(item.status)}">${escapeHtml(item.status.replaceAll("_", " "))}</span>
              </div>
              <p>${escapeHtml(item.profile_name || "trigger evaluation")} - ${escapeHtml(item.branch || item.ref || "no ref")} - ${escapeHtml(shortCommit(item.commit_sha))}</p>
              <p>${escapeHtml(item.status_detail || "Processed through the CI/CD trigger receiver.")}</p>
              <p>${item.run_id ? `Run ${escapeHtml(item.run_status || "created")}` : "No run linked"} - ${escapeHtml(formatTimestamp(item.created_at))}</p>
            </article>
          `
        )
        .join("")}
    </div>
  `;
}

function resolveTrigger(source) {
  const configured = (state.cicdTriggerSettings?.triggers || []).find((item) => item.trigger_source === source);
  if (configured) return configured;
  return {
    trigger_source: source,
    configured: false,
    status: "unconfigured",
    enabled_profiles: defaultTriggerProfiles(source),
    branch_filters: ["main"],
    scope_override_allowed: false,
    webhook_secret_configured: false,
    webhook_display_label: "encrypted",
    last_triggered_at: null,
    last_run_id: null,
    last_run_status: null,
  };
}

function resolveSiemProvider(providerId) {
  const configured = (state.siemIntegrationSettings?.providers || []).find(
    (item) => item.integration_type === providerId
  );
  if (configured) return configured;
  return {
    id: null,
    integration_type: providerId,
    provider_label: siemProviderLabel(providerId),
    display_name: "",
    base_url: "",
    enabled: true,
    push_on_run_completion: true,
    push_on_critical_finding: true,
    include_sigma: false,
    index_name: "",
    sourcetype: "",
    custom_log_table: "",
    stream_name: "",
    timeout_seconds: "",
    credential_configured: false,
    credential_display_label: "encrypted",
  };
}

function defaultTriggerProfiles(source) {
  return CICD_TRIGGER_SOURCES.find((item) => item.id === source)?.defaultProfiles || ["passive-web-baseline"];
}

function triggerSourceLabel(source) {
  return CICD_TRIGGER_SOURCES.find((item) => item.id === source)?.label || source;
}

function siemProviderLabel(providerId) {
  return SIEM_PROVIDERS.find((item) => item.id === providerId)?.label || providerId;
}

function findSettingValue(key) {
  const found = flattenSettings(state.operatorSettings || {}).find((setting) => setting.key === key);
  return found?.value ?? null;
}

function valueForSetting(settings, key) {
  return settings.find((setting) => setting.key === key)?.value ?? null;
}

function renderAiProviderWarning({ providerValue, enabledFeatureCount }) {
  const normalizedProvider = String(providerValue || "disabled").trim().toLowerCase();
  if (normalizedProvider === "chatgpt_oauth") {
    if (!enabledFeatureCount) {
      return `<p class="settings-subtle-note">AI helpers are currently off. Enable the toggles below to let connected engagements use ChatGPT OAuth where supported.</p>`;
    }
    return `<p class="settings-subtle-note">Saved AI feature defaults will use the engagement-scoped ChatGPT OAuth connection when one is present.</p>`;
  }
  if (!enabledFeatureCount) {
    return `<p class="settings-subtle-note">AI helpers are currently off. Select ChatGPT OAuth before turning any of them on.</p>`;
  }
  const featureCopy = enabledFeatureCount === 1 ? "feature is" : "features are";
  return `
    <p class="settings-inline-warning" data-testid="settings-ai-provider-warning">
      ${enabledFeatureCount} AI ${featureCopy} enabled, but the provider is ${escapeHtml(normalizedProvider || "disabled")}. Select ChatGPT OAuth before expecting live provider calls.
    </p>
  `;
}

function syncAiProviderWarning(form) {
  if (!form) return;
  const slot = form.querySelector("[data-ai-provider-warning-slot]");
  if (!slot) return;
  const providerValue = form.querySelector('[data-setting-key="ai.provider"]')?.value || "disabled";
  const enabledFeatureCount = [...form.querySelectorAll('[data-ai-provider-control="feature-toggle"]')].filter(
    (input) => input.checked
  ).length;
  slot.innerHTML = renderAiProviderWarning({ providerValue, enabledFeatureCount });
}

function sectionTestId(sectionId) {
  return `settings-${String(sectionId || "").replaceAll("_", "-")}`;
}

function cssEscape(value) {
  if (window.CSS?.escape) return window.CSS.escape(value);
  return String(value).replace(/"/g, '\\"');
}

function formatTimestamp(value) {
  if (!value) return "unknown time";
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return String(value);
  return parsed.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function sourceLabel(source) {
  const labels = {
    cisa_kev: "CISA KEV",
    ncsc_nl: "NCSC NL",
    nvd: "NVD",
    opencve: "OpenCVE",
  };
  return labels[source] || source || "Source";
}

function formatStatus(value) {
  return String(value || "unknown").replaceAll("_", " ");
}

function statusChipClass(value) {
  const normalized = String(value || "").toLowerCase();
  if (["completed", "scheduled"].includes(normalized)) return "success";
  if (["failed", "error"].includes(normalized)) return "danger";
  if (["skipped", "never_synced", "missing_dependency"].includes(normalized)) return "warning";
  return "neutral";
}

function shortCommit(value) {
  const candidate = String(value || "").trim();
  if (!candidate) return "no commit";
  return candidate.slice(0, 12);
}
