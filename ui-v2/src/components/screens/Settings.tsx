import { useEffect, useMemo, useState } from 'react';
import type { ReactNode } from 'react';
import {
  Bot,
  ChevronDown,
  Circle,
  Database,
  Download,
  KeyRound,
  Loader2,
  Lock,
  PlugZap,
  RefreshCw,
  Save,
  ServerCog,
  Shield,
  Trash2,
  UserRound,
  X,
} from 'lucide-react';
import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';
import {
  ApiError,
  authorizeChatGptOAuth,
  createApiKey,
  createDeceptionTrap,
  exportEngagementData,
  getApiKeys,
  getChatGptOAuthStatus,
  getDeceptionAlerts,
  getDeceptionTraps,
  getEnterpriseIdentityStatus,
  getScheduledRuns,
  getSettings,
  patchSettings,
  pauseScheduledRun,
  resumeScheduledRun,
  revokeApiKey,
} from '../../api/client';
import type {
  ApiKeyRead,
  ChatGptOAuthAuthorize,
  ChatGptOAuthStatus,
  DeceptionAlert,
  DeceptionTrap,
  DeceptionTrapKind,
  EnterpriseIdentityStatus,
  ScheduledRun,
  Setting,
  SettingsEnvelope,
  UUID,
} from '../../api/types';
import { ACTOR_STORAGE_KEY, V2_ACTOR_STORAGE_KEY, useAegisStore } from '../../store';

type SettingsTab = 'ai' | 'runtime' | 'integrations' | 'data' | 'identity' | 'deception';
type SaveScope = 'ai' | 'runtime' | 'integrations' | 'data' | 'identity' | 'deception';
type PendingAction =
  | SaveScope
  | 'chatgpt-status'
  | 'chatgpt-connect'
  | 'api-key-create'
  | 'data-export'
  | 'schedule'
  | 'deception-create'
  | 'deception-refresh'
  | null;

const tabs: Array<{ id: SettingsTab; label: string; icon: typeof Bot }> = [
  { id: 'ai', label: 'AI & Provider', icon: Bot },
  { id: 'runtime', label: 'Tools & Runtime', icon: ServerCog },
  { id: 'integrations', label: 'Integrations', icon: PlugZap },
  { id: 'data', label: 'Data & Security', icon: Lock },
  { id: 'deception', label: 'Deception', icon: Shield },
  { id: 'identity', label: 'Identity & Users', icon: UserRound },
];

const tabSettingKeys: Record<SaveScope, string[]> = {
  ai: [
    'ai.provider',
    'ai.http_endpoint',
    'ai.http_api_key',
    'ai.finding_enrichment_enabled',
    'ai.post_task_analysis_enabled',
    'ai.intake_intelligence_enabled',
    'ai.autofix_enabled',
    'ai.report_drafting_enabled',
  ],
  runtime: ['runtime.inline_task_workers'],
  integrations: [
    'integrations.jira_base_url',
    'integrations.jira_project_key',
    'integrations.jira_token',
    'integrations.slack_webhook_url',
    'integrations.teams_webhook_url',
    'integrations.servicenow_instance_url',
    'notifications.email_enabled',
    'notifications.smtp_host',
    'notifications.smtp_port',
    'notifications.smtp_username',
    'notifications.smtp_password',
    'notifications.smtp_use_tls',
    'notifications.smtp_from',
    'notifications.smtp_to',
    'notifications.run_completion',
    'notifications.phase_approval_needed',
  ],
  data: [
    'evidence.timestamping_enabled',
    'evidence.timestamp_authority_url',
    'evidence.timestamp_timeout_seconds',
    'instance.app_public_base_url',
    'instance.build_lane_mode',
    'instance.onboarding_completed',
  ],
  deception: [],
  identity: [
    'identity.enterprise_sso_provider',
    'identity.session_timeout_minutes',
    'identity.logout_redirect_url',
    'identity.oidc_issuer_url',
    'identity.oidc_client_id',
    'identity.oidc_client_secret',
    'identity.saml_entity_id',
    'identity.saml_sso_url',
    'identity.saml_certificate',
  ],
};

function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export default function SettingsScreen() {
  const selectedEngagement = useAegisStore((state) => state.selectedEngagement);
  const selectedEngagementId = useAegisStore((state) => state.selectedEngagementId);
  const actor = useAegisStore((state) => state.actor);
  const settingsEnvelope = useAegisStore((state) => state.settings);
  const setActor = useAegisStore((state) => state.setActor);
  const setSettings = useAegisStore((state) => state.setSettings);
  const setError = useAegisStore((state) => state.setError);

  const [activeTab, setActiveTab] = useState<SettingsTab>('ai');
  const [draftValues, setDraftValues] = useState<Record<string, unknown>>({});
  const [dirtyKeys, setDirtyKeys] = useState<Set<string>>(() => new Set());
  const [openSections, setOpenSections] = useState<Set<string>>(
    () => new Set(['chatgpt', 'ai-provider', 'readiness', 'jira', 'actor']),
  );
  const [chatgptStatus, setChatgptStatus] = useState<ChatGptOAuthStatus | null>(null);
  const [identityStatus, setIdentityStatus] = useState<EnterpriseIdentityStatus | null>(null);
  const [apiKeys, setApiKeys] = useState<ApiKeyRead[]>([]);
  const [scheduledRuns, setScheduledRuns] = useState<ScheduledRun[]>([]);
  const [deceptionTraps, setDeceptionTraps] = useState<DeceptionTrap[]>([]);
  const [deceptionAlerts, setDeceptionAlerts] = useState<DeceptionAlert[]>([]);
  const [newTrapName, setNewTrapName] = useState('Local recursive API fixture');
  const [newTrapKind, setNewTrapKind] = useState<DeceptionTrapKind>('hallucination_api');
  const [newKey, setNewKey] = useState('');
  const [newKeyRole, setNewKeyRole] = useState<'admin' | 'operator' | 'reviewer'>('operator');
  const [actorName, setActorName] = useState(actor.name);
  const [toast, setToast] = useState<string | null>(null);
  const [pending, setPending] = useState<PendingAction>(null);

  const settings = settingsEnvelope.settings;
  const settingByKey = useMemo(() => indexSettings(settingsEnvelope), [settingsEnvelope]);
  const modelSetting = settingByKey.get('ai.chatgpt_model');
  const providerSetting = settingByKey.get('ai.provider');
  const tenantLabel = settings?.tenant_id ?? selectedEngagement?.tenant_id ?? 'default';
  const modelLabel = String(readSettingValue(modelSetting, draftValues) || 'not configured');

  useEffect(() => {
    const storedActor =
      window.localStorage.getItem(ACTOR_STORAGE_KEY) ?? window.localStorage.getItem(V2_ACTOR_STORAGE_KEY);
    if (storedActor && storedActor !== actor.name) {
      setActorName(storedActor);
      setActor({ name: storedActor });
    }
  }, [actor.name, setActor]);

  useEffect(() => {
    setDraftValues({});
    setDirtyKeys(new Set());
  }, [settingsEnvelope.settings]);

  useEffect(() => {
    void refreshSupplementalData();
  }, [selectedEngagementId]);

  function toggleSection(id: string) {
    setOpenSections((current) => {
      const next = new Set(current);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  function updateDraft(setting: Setting, value: unknown) {
    setDraftValues((current) => ({ ...current, [setting.key]: value }));
    setDirtyKeys((current) => new Set(current).add(setting.key));
  }

  async function refreshAll() {
    setPending('runtime');
    setError(null);
    try {
      const payload = await getSettings();
      setSettings(payload);
      await refreshSupplementalData();
      setToast('Settings refreshed from backend.');
    } catch (error) {
      setToast(errorMessage(error));
      setError(errorMessage(error));
    } finally {
      setPending(null);
    }
  }

  async function refreshSupplementalData() {
    const promises: Array<Promise<void>> = [];
    if (selectedEngagementId) {
      promises.push(loadChatGptStatus(selectedEngagementId, false));
      promises.push(loadSchedules(selectedEngagementId));
    } else {
      setChatgptStatus(null);
      setScheduledRuns([]);
    }
    promises.push(loadApiKeys());
    promises.push(loadIdentityStatus());
    promises.push(loadDeceptionData(false));
    await Promise.all(promises);
  }

  async function loadChatGptStatus(engagementId: UUID, notify = true) {
    if (notify) setPending('chatgpt-status');
    try {
      const payload = await getChatGptOAuthStatus(engagementId);
      setChatgptStatus(payload);
      if (notify) setToast('ChatGPT OAuth status refreshed.');
    } catch (error) {
      setChatgptStatus({ status: 'unavailable', failure_reason: errorMessage(error) });
      if (notify) setToast(errorMessage(error));
    } finally {
      if (notify) setPending(null);
    }
  }

  async function handleConnectChatGpt() {
    if (!selectedEngagementId) {
      setToast('Select an engagement before connecting ChatGPT.');
      return;
    }
    setPending('chatgpt-connect');
    try {
      const payload = await authorizeChatGptOAuth(selectedEngagementId);
      handleAuthorizationPayload(payload);
      await loadChatGptStatus(selectedEngagementId, false);
    } catch (error) {
      setToast(errorMessage(error));
    } finally {
      setPending(null);
    }
  }

  function handleAuthorizationPayload(payload: ChatGptOAuthAuthorize) {
    if (payload.authorization_url) {
      window.open(payload.authorization_url, '_blank', 'noopener,noreferrer');
      setToast('ChatGPT authorization opened in a new tab.');
      return;
    }
    setToast(payload.message || 'ChatGPT OAuth session is already reusable for this engagement.');
  }

  async function saveScope(scope: SaveScope) {
    const allowed = new Set(tabSettingKeys[scope]);
    const patch = Object.fromEntries(
      [...dirtyKeys]
        .filter((key) => allowed.has(key))
        .map((key) => [key, draftValues[key]]),
    );
    if (Object.keys(patch).length === 0) {
      setToast('No settings changes to save.');
      return;
    }

    setPending(scope);
    setError(null);
    try {
      const payload = await patchSettings({ settings: patch });
      const refreshed = await getSettings();
      setSettings({ ...refreshed, settings: payload });
      setDirtyKeys((current) => {
        const next = new Set(current);
        Object.keys(patch).forEach((key) => next.delete(key));
        return next;
      });
      setToast('Settings saved.');
    } catch (error) {
      setToast(errorMessage(error));
      setError(errorMessage(error));
    } finally {
      setPending(null);
    }
  }

  function saveActorName() {
    const nextActor = actorName.trim() || 'operator-ui';
    window.localStorage.setItem(ACTOR_STORAGE_KEY, nextActor);
    window.localStorage.setItem(V2_ACTOR_STORAGE_KEY, nextActor);
    setActor({ name: nextActor });
    setToast('Actor name saved for future API requests.');
  }

  async function loadApiKeys() {
    try {
      setApiKeys(await getApiKeys());
    } catch (error) {
      setApiKeys([]);
      setToast((current) => current ?? errorMessage(error));
    }
  }

  async function createKey() {
    setPending('api-key-create');
    try {
      const payload = await createApiKey({ actor_name: actorName.trim() || actor.name, role: newKeyRole });
      setNewKey(payload.api_key);
      await loadApiKeys();
      setToast('API key created. The token is shown once.');
    } catch (error) {
      setToast(errorMessage(error));
    } finally {
      setPending(null);
    }
  }

  async function revokeKey(keyId: UUID) {
    setPending('api-key-create');
    try {
      await revokeApiKey(keyId);
      await loadApiKeys();
      setToast('API key revoked.');
    } catch (error) {
      setToast(errorMessage(error));
    } finally {
      setPending(null);
    }
  }

  async function loadIdentityStatus() {
    try {
      setIdentityStatus(await getEnterpriseIdentityStatus());
    } catch {
      setIdentityStatus(null);
    }
  }

  async function loadSchedules(engagementId: UUID) {
    try {
      setScheduledRuns(await getScheduledRuns(engagementId));
    } catch {
      setScheduledRuns([]);
    }
  }

  async function toggleSchedule(schedule: ScheduledRun) {
    if (!selectedEngagementId) return;
    setPending('schedule');
    try {
      if (schedule.status === 'enabled') {
        await pauseScheduledRun(selectedEngagementId, schedule.id);
      } else {
        await resumeScheduledRun(selectedEngagementId, schedule.id);
      }
      await loadSchedules(selectedEngagementId);
      setToast('Scheduled scan state updated.');
    } catch (error) {
      setToast(errorMessage(error));
    } finally {
      setPending(null);
    }
  }

  async function loadDeceptionData(notify = true) {
    if (notify) setPending('deception-refresh');
    try {
      const [traps, alerts] = await Promise.all([getDeceptionTraps(), getDeceptionAlerts()]);
      setDeceptionTraps(traps.traps);
      setDeceptionAlerts(alerts.alerts);
      if (notify) setToast('Deception fixtures refreshed.');
    } catch (error) {
      setDeceptionTraps([]);
      setDeceptionAlerts([]);
      if (notify) setToast(errorMessage(error));
    } finally {
      if (notify) setPending(null);
    }
  }

  async function handleCreateDeceptionTrap() {
    const name = newTrapName.trim();
    if (!name) {
      setToast('Name the local deception fixture before creating it.');
      return;
    }
    setPending('deception-create');
    try {
      await createDeceptionTrap({
        name,
        trap_kind: newTrapKind,
        local_only: true,
        enabled: true,
        max_depth: 4,
      });
      await loadDeceptionData(false);
      setToast('Local deception fixture created.');
    } catch (error) {
      setToast(errorMessage(error));
    } finally {
      setPending(null);
    }
  }

  async function handleDataExport() {
    if (!selectedEngagementId) {
      setToast('Select an engagement before exporting data.');
      return;
    }
    setPending('data-export');
    try {
      const payload = await exportEngagementData(selectedEngagementId);
      const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement('a');
      anchor.href = url;
      anchor.download = `aegispt-engagement-${selectedEngagementId}-data-export.json`;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(url);
      setToast('Engagement data export prepared.');
    } catch (error) {
      setToast(errorMessage(error));
    } finally {
      setPending(null);
    }
  }

  const activeSaveScope = activeTabToSaveScope(activeTab);

  return (
    <section className="flex h-full min-h-0 flex-col">
      <header className="mb-5 flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold text-text">Settings</h1>
          <p className="mt-1 text-[1rem] text-muted">
            Governed configuration. Saving settings does not install tools, run checks, or bypass approval gates.
          </p>
        </div>
        <button
          type="button"
          onClick={() => void refreshAll()}
          disabled={pending === 'runtime'}
          className="inline-flex items-center gap-2 rounded-md border border-cyan/30 bg-cyan/10 px-3 py-2 text-[1rem] font-semibold text-cyan disabled:opacity-50"
        >
          {pending === 'runtime' ? <Loader2 size={14} className="animate-spin" /> : <RefreshCw size={14} />}
          Refresh
        </button>
      </header>

      <div className="mb-5 grid gap-3 md:grid-cols-4">
        <SummaryChip label="Tenant" value={tenantLabel} icon={<Shield size={14} />} />
        <SummaryChip label="Engagement" value={selectedEngagement?.name ?? 'No engagement selected'} icon={<Database size={14} />} />
        <SummaryChip label="Model" value={modelLabel} icon={<Bot size={14} />} />
        <SummaryChip label="Role" value={actor.role} icon={<UserRound size={14} />} />
      </div>

      <div className="mb-5 flex gap-1 overflow-x-auto rounded-lg border border-border bg-surface/55 p-1">
        {tabs.map((tab) => (
          <TabButton
            key={tab.id}
            active={activeTab === tab.id}
            icon={<tab.icon size={14} />}
            onClick={() => setActiveTab(tab.id)}
          >
            {tab.label}
          </TabButton>
        ))}
      </div>

      <div className="min-h-0 flex-1 overflow-y-auto rounded-xl border border-border bg-surface/55 p-4 backdrop-blur-md">
        {activeTab === 'ai' && (
          <AiProviderTab
            selectedEngagementId={selectedEngagementId}
            chatgptStatus={chatgptStatus}
            providerSetting={providerSetting}
            settings={settings}
            draftValues={draftValues}
            dirtyKeys={dirtyKeys}
            pending={pending}
            openSections={openSections}
            toggleSection={toggleSection}
            updateDraft={updateDraft}
            refreshStatus={loadChatGptStatus}
            connectChatGpt={handleConnectChatGpt}
          />
        )}
        {activeTab === 'runtime' && (
          <RuntimeTab
            envelope={settingsEnvelope}
            settingByKey={settingByKey}
            draftValues={draftValues}
            dirtyKeys={dirtyKeys}
            scheduledRuns={scheduledRuns}
            pending={pending}
            openSections={openSections}
            toggleSection={toggleSection}
            updateDraft={updateDraft}
            toggleSchedule={toggleSchedule}
          />
        )}
        {activeTab === 'integrations' && (
          <IntegrationsTab
            settingByKey={settingByKey}
            draftValues={draftValues}
            dirtyKeys={dirtyKeys}
            openSections={openSections}
            toggleSection={toggleSection}
            updateDraft={updateDraft}
          />
        )}
        {activeTab === 'data' && (
          <DataSecurityTab
            selectedEngagementName={selectedEngagement?.name ?? null}
            retentionDays={selectedEngagement?.retention_days ?? null}
            settingByKey={settingByKey}
            draftValues={draftValues}
            dirtyKeys={dirtyKeys}
            pending={pending}
            openSections={openSections}
            toggleSection={toggleSection}
            updateDraft={updateDraft}
            exportData={handleDataExport}
          />
        )}
        {activeTab === 'deception' && (
          <DeceptionTab
            traps={deceptionTraps}
            alerts={deceptionAlerts}
            newTrapName={newTrapName}
            newTrapKind={newTrapKind}
            setNewTrapName={setNewTrapName}
            setNewTrapKind={setNewTrapKind}
            pending={pending}
            openSections={openSections}
            toggleSection={toggleSection}
            createTrap={handleCreateDeceptionTrap}
            refreshTraps={loadDeceptionData}
          />
        )}
        {activeTab === 'identity' && (
          <IdentityTab
            actor={actor}
            actorName={actorName}
            setActorName={setActorName}
            saveActorName={saveActorName}
            identityStatus={identityStatus}
            apiKeys={apiKeys}
            newKey={newKey}
            newKeyRole={newKeyRole}
            setNewKeyRole={setNewKeyRole}
            pending={pending}
            settingByKey={settingByKey}
            draftValues={draftValues}
            dirtyKeys={dirtyKeys}
            openSections={openSections}
            toggleSection={toggleSection}
            updateDraft={updateDraft}
            createKey={createKey}
            revokeKey={revokeKey}
          />
        )}
      </div>

      <footer className="mt-4 flex flex-wrap items-center justify-between gap-3">
        {toast && (
          <div className="rounded-md border border-cyan/20 bg-cyan/10 px-3 py-2 text-[0.925rem] text-cyan">
            {toast}
          </div>
        )}
        <button
          type="button"
          onClick={() => void saveScope(activeSaveScope)}
          disabled={pending === activeSaveScope}
          className="ml-auto inline-flex items-center gap-2 rounded-md border border-green/30 bg-green/10 px-4 py-2 text-[1rem] font-semibold text-green disabled:opacity-50"
        >
          {pending === activeSaveScope ? <Loader2 size={14} className="animate-spin" /> : <Save size={14} />}
          Save Settings
        </button>
      </footer>
    </section>
  );
}

function AiProviderTab({
  selectedEngagementId,
  chatgptStatus,
  providerSetting,
  settings,
  draftValues,
  dirtyKeys,
  pending,
  openSections,
  toggleSection,
  updateDraft,
  refreshStatus,
  connectChatGpt,
}: {
  selectedEngagementId: UUID | null;
  chatgptStatus: ChatGptOAuthStatus | null;
  providerSetting: Setting | undefined;
  settings: SettingsEnvelope['settings'];
  draftValues: Record<string, unknown>;
  dirtyKeys: Set<string>;
  pending: PendingAction;
  openSections: Set<string>;
  toggleSection: (id: string) => void;
  updateDraft: (setting: Setting, value: unknown) => void;
  refreshStatus: (engagementId: UUID, notify?: boolean) => Promise<void>;
  connectChatGpt: () => Promise<void>;
}) {
  const status = normalizeStatus(String(chatgptStatus?.status ?? (chatgptStatus?.connected ? 'connected' : 'unavailable')));
  const providerSummary = providerSetting ? `${providerSetting.label}: ${readSettingValue(providerSetting, draftValues)}` : 'Provider setting unavailable';

  return (
    <div className="space-y-3">
      <SettingsDisclosure
        id="chatgpt"
        title="ChatGPT OAuth"
        summary={chatgptSummary(chatgptStatus, selectedEngagementId)}
        openSections={openSections}
        toggleSection={toggleSection}
      >
        <div className="grid gap-4 lg:grid-cols-[1fr_auto]">
          <div>
            <StatusLine status={status} title="Connection" detail={chatgptDetail(chatgptStatus, selectedEngagementId)} />
            <div className="mt-3 grid gap-2 sm:grid-cols-3">
              <MiniMetric label="Provider" value={String(chatgptStatus?.provider ?? 'chatgpt_oauth')} />
              <MiniMetric label="Model" value={String(chatgptStatus?.model ?? readSettingValue(findSetting(settings, 'ai.chatgpt_model'), draftValues) ?? 'not configured')} />
              <MiniMetric label="Tokens" value={String(chatgptStatus?.token_count ?? 'n/a')} />
            </div>
          </div>
          <div className="flex flex-wrap items-start gap-2">
            <button
              type="button"
              disabled={!selectedEngagementId || pending === 'chatgpt-status'}
              onClick={() => selectedEngagementId && void refreshStatus(selectedEngagementId)}
              className="inline-flex items-center gap-2 rounded-md border border-cyan/30 bg-cyan/10 px-3 py-2 text-[1rem] font-semibold text-cyan disabled:opacity-50"
            >
              {pending === 'chatgpt-status' ? <Loader2 size={14} className="animate-spin" /> : <RefreshCw size={14} />}
              Refresh Status
            </button>
            <button
              type="button"
              disabled={!selectedEngagementId || pending === 'chatgpt-connect'}
              onClick={() => void connectChatGpt()}
              className="inline-flex items-center gap-2 rounded-md border border-green/30 bg-green/10 px-3 py-2 text-[1rem] font-semibold text-green disabled:opacity-50"
            >
              {pending === 'chatgpt-connect' ? <Loader2 size={14} className="animate-spin" /> : <Bot size={14} />}
              Connect ChatGPT
            </button>
          </div>
        </div>
      </SettingsDisclosure>

      <SettingsDisclosure
        id="ai-provider"
        title="AI Provider Settings"
        summary={providerSummary}
        openSections={openSections}
        toggleSection={toggleSection}
      >
        <SettingGrid
          settings={settingsForKeys(settings, tabSettingKeys.ai)}
          draftValues={draftValues}
          dirtyKeys={dirtyKeys}
          updateDraft={updateDraft}
        />
      </SettingsDisclosure>
    </div>
  );
}

function RuntimeTab({
  envelope,
  settingByKey,
  draftValues,
  dirtyKeys,
  scheduledRuns,
  pending,
  openSections,
  toggleSection,
  updateDraft,
  toggleSchedule,
}: {
  envelope: SettingsEnvelope;
  settingByKey: Map<string, Setting>;
  draftValues: Record<string, unknown>;
  dirtyKeys: Set<string>;
  scheduledRuns: ScheduledRun[];
  pending: PendingAction;
  openSections: Set<string>;
  toggleSection: (id: string) => void;
  updateDraft: (setting: Setting, value: unknown) => void;
  toggleSchedule: (schedule: ScheduledRun) => Promise<void>;
}) {
  const readiness = envelope.readiness;
  const workerSetting = settingByKey.get('runtime.inline_task_workers');

  return (
    <div className="space-y-3">
      <SettingsDisclosure
        id="readiness"
        title="Runtime Readiness"
        summary={readiness ? `Overall: ${readiness.overall_status}` : 'Readiness endpoint unavailable'}
        openSections={openSections}
        toggleSection={toggleSection}
      >
        {readiness ? (
          <div className="space-y-4">
            <StatusLine status={readiness.overall_status} title="Overall readiness" detail={`Generated ${formatDate(readiness.generated_at)}.`} />
            <div className="grid gap-3 lg:grid-cols-2">
              {readiness.capabilities.map((capability) => (
                <ReadinessCard key={capability.id} title={capability.title} status={capability.status} summary={capability.summary} details={capability.details} nextStep={capability.operator_next_step} />
              ))}
            </div>
            <div className="grid gap-3 lg:grid-cols-2">
              {readiness.tools.slice(0, 12).map((tool) => (
                <ReadinessCard key={tool.id} title={tool.title} status={tool.status} summary={tool.installed ? 'Installed' : `Missing: ${tool.missing_binaries.join(', ') || 'none reported'}`} details={tool.detected_path ? [`Detected at ${tool.detected_path}`] : tool.missing_binaries} nextStep={tool.operator_next_step} />
              ))}
            </div>
          </div>
        ) : (
          <EmptyInline title="Readiness unavailable" detail="GET /api/v1/settings/readiness did not return data during bootstrap." />
        )}
      </SettingsDisclosure>

      <SettingsDisclosure
        id="execution"
        title="Execution"
        summary={`Parallel workers: ${workerSetting ? readSettingValue(workerSetting, draftValues) : 'unavailable'}`}
        openSections={openSections}
        toggleSection={toggleSection}
      >
        <SettingGrid
          settings={workerSetting ? [workerSetting] : []}
          draftValues={draftValues}
          dirtyKeys={dirtyKeys}
          updateDraft={updateDraft}
        />
        <div className="mt-3 rounded-md border border-border bg-bg/30 p-3 text-[0.925rem] text-muted">
          Dispatch mode is controlled by the backend runtime configuration. This screen records settings only; it does not dispatch work.
        </div>
      </SettingsDisclosure>

      <SettingsDisclosure
        id="scheduled-scans"
        title="Scheduled Scans"
        summary={`${scheduledRuns.filter((run) => run.status === 'enabled').length} enabled · ${scheduledRuns.length} total`}
        openSections={openSections}
        toggleSection={toggleSection}
      >
        {scheduledRuns.length ? (
          <div className="space-y-2">
            {scheduledRuns.map((schedule) => (
              <div key={schedule.id} className="grid gap-3 rounded-lg border border-border bg-bg/30 p-3 md:grid-cols-[1fr_auto]">
                <div className="min-w-0">
                  <div className="text-[1rem] font-semibold text-text">{schedule.profile_name}</div>
                  <div className="mt-1 text-[0.925rem] text-muted">
                    {schedule.cadence} · next {formatDate(schedule.next_run_at)} · {schedule.status}
                  </div>
                </div>
                <button
                  type="button"
                  disabled={pending === 'schedule'}
                  onClick={() => void toggleSchedule(schedule)}
                  className="rounded-md border border-cyan/30 bg-cyan/10 px-3 py-2 text-[0.925rem] font-semibold text-cyan disabled:opacity-50"
                >
                  {schedule.status === 'enabled' ? 'Pause' : 'Enable'}
                </button>
              </div>
            ))}
          </div>
        ) : (
          <EmptyInline title="No scheduled scans" detail="Recurring validation can be added after an engagement has governed scope." />
        )}
      </SettingsDisclosure>
    </div>
  );
}

function IntegrationsTab(props: SettingsPanelProps) {
  const { settingByKey, draftValues, dirtyKeys, openSections, toggleSection, updateDraft } = props;
  return (
    <div className="space-y-3">
      <SettingsDisclosure id="jira" title="Jira" summary={integrationSummary(settingByKey, 'integrations.jira_base_url', 'Jira')} openSections={openSections} toggleSection={toggleSection}>
        <SettingGrid settings={pickSettings(settingByKey, ['integrations.jira_base_url', 'integrations.jira_project_key', 'integrations.jira_token'])} draftValues={draftValues} dirtyKeys={dirtyKeys} updateDraft={updateDraft} />
        <UnavailableNote label="Test Jira Connection" detail="No dedicated React v2 test endpoint exists in repo truth; saving configuration is supported through PATCH /api/v1/settings." />
      </SettingsDisclosure>
      <SettingsDisclosure id="siem" title="SIEM" summary="Splunk, Elastic, and Sentinel configuration states from settings" openSections={openSections} toggleSection={toggleSection}>
        <SettingGrid settings={pickSettings(settingByKey, ['integrations.servicenow_instance_url', 'integrations.slack_webhook_url', 'integrations.teams_webhook_url', 'notifications.critical_destination'])} draftValues={draftValues} dirtyKeys={dirtyKeys} updateDraft={updateDraft} />
      </SettingsDisclosure>
      <SettingsDisclosure id="cicd" title="CI/CD" summary="Webhook controls are not exposed by current Settings definitions" openSections={openSections} toggleSection={toggleSection}>
        <UnavailableNote label="GitHub / GitLab Webhook URL" detail="The current backend does not expose CI/CD webhook settings in /api/v1/settings. This panel is intentionally read-only until that contract exists." />
      </SettingsDisclosure>
      <SettingsDisclosure id="email" title="Notifications" summary={integrationSummary(settingByKey, 'notifications.email_enabled', 'Email')} openSections={openSections} toggleSection={toggleSection}>
        <SettingGrid settings={pickSettings(settingByKey, ['notifications.email_enabled', 'notifications.smtp_host', 'notifications.smtp_port', 'notifications.smtp_username', 'notifications.smtp_password', 'notifications.smtp_use_tls', 'notifications.smtp_from', 'notifications.smtp_to', 'notifications.run_completion', 'notifications.phase_approval_needed'])} draftValues={draftValues} dirtyKeys={dirtyKeys} updateDraft={updateDraft} />
      </SettingsDisclosure>
    </div>
  );
}

function DataSecurityTab({
  selectedEngagementName,
  retentionDays,
  settingByKey,
  draftValues,
  dirtyKeys,
  pending,
  openSections,
  toggleSection,
  updateDraft,
  exportData,
}: SettingsPanelProps & {
  selectedEngagementName: string | null;
  retentionDays: number | null;
  pending: PendingAction;
  exportData: () => Promise<void>;
}) {
  return (
    <div className="space-y-3">
      <SettingsDisclosure id="retention" title="Data Retention" summary={retentionDays ? `${retentionDays} days for selected engagement` : 'No engagement selected'} openSections={openSections} toggleSection={toggleSection}>
        <div className="grid gap-3 md:grid-cols-3">
          <MiniMetric label="Engagement" value={selectedEngagementName ?? 'No engagement'} />
          <MiniMetric label="Retention" value={retentionDays ? `${retentionDays} days` : 'unavailable'} />
          <MiniMetric label="Per-type policy" value="not implemented" />
        </div>
        <UnavailableNote label="Per-type retention days" detail="Repo truth supports engagement-level retention through engagement data-retention APIs; per-type findings/runs/evidence retention fields are not exposed by current Settings definitions." />
      </SettingsDisclosure>
      <SettingsDisclosure id="evidence" title="Evidence Integrity" summary={integrationSummary(settingByKey, 'evidence.timestamping_enabled', 'Timestamping')} openSections={openSections} toggleSection={toggleSection}>
        <SettingGrid settings={pickSettings(settingByKey, ['evidence.timestamping_enabled', 'evidence.timestamp_authority_url', 'evidence.timestamp_timeout_seconds'])} draftValues={draftValues} dirtyKeys={dirtyKeys} updateDraft={updateDraft} />
      </SettingsDisclosure>
      <SettingsDisclosure id="deployment" title="DB Encryption & Deployment" summary="Read-only deployment posture from backend settings" openSections={openSections} toggleSection={toggleSection}>
        <SettingGrid settings={pickSettings(settingByKey, ['deployment.database_encryption_confirmed', 'deployment.artifact_storage_encryption_confirmed', 'deployment.tls_terminated_by_proxy', 'deployment.secure_cookies', 'deployment.no_internet_mode'])} draftValues={draftValues} dirtyKeys={dirtyKeys} updateDraft={updateDraft} />
      </SettingsDisclosure>
      <SettingsDisclosure id="gdpr" title="GDPR Controls" summary="Export is available; purge requires existing backend confirmation flow" openSections={openSections} toggleSection={toggleSection}>
        <div className="flex flex-wrap gap-2">
          <button type="button" onClick={() => void exportData()} disabled={pending === 'data-export'} className="inline-flex items-center gap-2 rounded-md border border-cyan/30 bg-cyan/10 px-3 py-2 text-[1rem] font-semibold text-cyan disabled:opacity-50">
            {pending === 'data-export' ? <Loader2 size={14} className="animate-spin" /> : <Download size={14} />}
            Export my data
          </button>
          <button type="button" disabled className="inline-flex items-center gap-2 rounded-md border border-border bg-bg/40 px-3 py-2 text-[1rem] font-semibold text-muted opacity-70">
            <Trash2 size={14} />
            Request purge
          </button>
        </div>
        <p className="mt-3 text-[0.925rem] leading-5 text-muted">
          Purge is intentionally disabled here because the backend requires typed confirmation through its governed purge endpoint.
        </p>
      </SettingsDisclosure>
    </div>
  );
}

function DeceptionTab({
  traps,
  alerts,
  newTrapName,
  newTrapKind,
  setNewTrapName,
  setNewTrapKind,
  pending,
  openSections,
  toggleSection,
  createTrap,
  refreshTraps,
}: {
  traps: DeceptionTrap[];
  alerts: DeceptionAlert[];
  newTrapName: string;
  newTrapKind: DeceptionTrapKind;
  setNewTrapName: (value: string) => void;
  setNewTrapKind: (value: DeceptionTrapKind) => void;
  pending: PendingAction;
  openSections: Set<string>;
  toggleSection: (id: string) => void;
  createTrap: () => Promise<void>;
  refreshTraps: (notify?: boolean) => Promise<void>;
}) {
  return (
    <div className="space-y-3">
      <SettingsDisclosure id="deception-create" title="Local Trap Fixtures" summary={`${traps.length} configured local fixtures`} openSections={openSections} toggleSection={toggleSection}>
        <div className="grid gap-3 lg:grid-cols-[1fr_220px_auto]">
          <label className="block">
            <span className="mb-1 block text-[0.85rem] font-bold uppercase text-muted">Fixture name</span>
            <input value={newTrapName} onChange={(event) => setNewTrapName(event.target.value)} className="h-10 w-full rounded-lg border border-border bg-surface px-3 text-[1rem] text-text outline-none focus:border-cyan/50" />
          </label>
          <label className="block">
            <span className="mb-1 block text-[0.85rem] font-bold uppercase text-muted">Kind</span>
            <select value={newTrapKind} onChange={(event) => setNewTrapKind(event.target.value as DeceptionTrapKind)} className="h-10 w-full rounded-lg border border-border bg-surface px-3 text-[1rem] text-text outline-none focus:border-cyan/50">
              <option value="hallucination_api" className="bg-surface text-text">Recursive API</option>
              <option value="fake_admin_api" className="bg-surface text-text">Admin API</option>
              <option value="canary_document" className="bg-surface text-text">Canary document</option>
            </select>
          </label>
          <button type="button" disabled={pending === 'deception-create'} onClick={() => void createTrap()} className="self-end inline-flex items-center justify-center gap-2 rounded-md border border-green/30 bg-green/10 px-3 py-2 text-[1rem] font-semibold text-green disabled:opacity-50">
            {pending === 'deception-create' ? <Loader2 size={14} className="animate-spin" /> : <Shield size={14} />}
            Create Fixture
          </button>
        </div>
        <p className="mt-3 text-[0.925rem] leading-5 text-muted">
          Fixtures are local controlled endpoints only. Creating one does not deploy to live systems, dispatch tools, materialize credentials, or approve runtime work.
        </p>
      </SettingsDisclosure>

      <SettingsDisclosure id="deception-traps" title="Configured Fixtures" summary={`${traps.filter((trap) => trap.enabled).length} enabled`} openSections={openSections} toggleSection={toggleSection}>
        <div className="mb-3 flex justify-end">
          <button type="button" disabled={pending === 'deception-refresh'} onClick={() => void refreshTraps()} className="inline-flex items-center gap-2 rounded-md border border-cyan/30 bg-cyan/10 px-3 py-2 text-[0.925rem] font-semibold text-cyan disabled:opacity-50">
            {pending === 'deception-refresh' ? <Loader2 size={14} className="animate-spin" /> : <RefreshCw size={14} />}
            Refresh
          </button>
        </div>
        {traps.length ? (
          <div className="space-y-2">
            {traps.map((trap) => (
              <div key={trap.id} className="rounded-lg border border-border bg-bg/30 p-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="min-w-0">
                    <div className="truncate text-[1rem] font-semibold text-text">{trap.name}</div>
                    <div className="mt-1 break-all font-mono text-[0.85rem] text-muted">{trap.endpoint_path}</div>
                  </div>
                  <span className={cn('rounded-full border px-2 py-0.5 text-[0.77rem] font-bold uppercase', trap.enabled ? 'border-green/30 bg-green/10 text-green' : 'border-amber/30 bg-amber/10 text-amber')}>
                    {trap.enabled ? 'enabled' : 'disabled'}
                  </span>
                </div>
                <div className="mt-3 grid gap-2 sm:grid-cols-3">
                  <MiniMetric label="Kind" value={trap.trap_kind.replace(/_/g, ' ')} />
                  <MiniMetric label="Max depth" value={String(trap.max_depth)} />
                  <MiniMetric label="Boundary" value={trap.boundary.automatic_live_deployment ? 'review needed' : 'local only'} />
                </div>
              </div>
            ))}
          </div>
        ) : (
          <EmptyInline title="No local fixtures" detail="Create a controlled trap endpoint before monitoring deception alerts." />
        )}
      </SettingsDisclosure>

      <SettingsDisclosure id="deception-alerts" title="Probe Alerts" summary={`${alerts.length} recorded probes`} openSections={openSections} toggleSection={toggleSection}>
        {alerts.length ? (
          <div className="space-y-2">
            {alerts.slice(0, 12).map((alert) => (
              <div key={alert.id} className="grid gap-3 rounded-lg border border-border bg-bg/30 p-3 md:grid-cols-[1fr_auto]">
                <div className="min-w-0">
                  <div className="truncate text-[1rem] font-semibold text-text">{alert.trap_name}</div>
                  <div className="mt-1 break-all text-[0.925rem] text-muted">{alert.probed_path}</div>
                  <div className="mt-1 text-[0.85rem] text-muted">{alert.actor} · {alert.evidence_ref}</div>
                </div>
                <span className="self-start rounded-full border border-amber/30 bg-amber/10 px-2 py-0.5 text-[0.77rem] font-bold uppercase text-amber">
                  {formatDate(alert.created_at)}
                </span>
              </div>
            ))}
          </div>
        ) : (
          <EmptyInline title="No probe alerts" detail="Configured trap endpoint probes will appear here as evidence-backed local alerts." />
        )}
      </SettingsDisclosure>
    </div>
  );
}

function IdentityTab({
  actor,
  actorName,
  setActorName,
  saveActorName,
  identityStatus,
  apiKeys,
  newKey,
  newKeyRole,
  setNewKeyRole,
  pending,
  settingByKey,
  draftValues,
  dirtyKeys,
  openSections,
  toggleSection,
  updateDraft,
  createKey,
  revokeKey,
}: SettingsPanelProps & {
  actor: { name: string; role: string };
  actorName: string;
  setActorName: (value: string) => void;
  saveActorName: () => void;
  identityStatus: EnterpriseIdentityStatus | null;
  apiKeys: ApiKeyRead[];
  newKey: string;
  newKeyRole: 'admin' | 'operator' | 'reviewer';
  setNewKeyRole: (role: 'admin' | 'operator' | 'reviewer') => void;
  pending: PendingAction;
  createKey: () => Promise<void>;
  revokeKey: (keyId: UUID) => Promise<void>;
}) {
  return (
    <div className="space-y-3">
      <SettingsDisclosure id="actor" title="Actor" summary={`${actor.name} · ${actor.role}`} openSections={openSections} toggleSection={toggleSection}>
        <div className="grid gap-3 md:grid-cols-[1fr_auto]">
          <label className="block">
            <span className="mb-1 block text-[0.85rem] font-bold uppercase text-muted">Actor name</span>
            <input value={actorName} onChange={(event) => setActorName(event.target.value)} className="h-10 w-full rounded-lg border border-border bg-surface px-3 text-[1rem] text-text outline-none focus:border-cyan/50" />
          </label>
          <button type="button" onClick={saveActorName} className="self-end rounded-md border border-green/30 bg-green/10 px-3 py-2 text-[1rem] font-semibold text-green">
            Save Actor
          </button>
        </div>
        <div className="mt-3 rounded-md border border-border bg-bg/30 p-3 text-[0.925rem] text-muted">
          Saved actor names are stored in localStorage and injected into the v2 API client as `X-Actor`.
        </div>
      </SettingsDisclosure>
      <SettingsDisclosure id="enterprise-identity" title="Enterprise Identity" summary={identityStatus?.summary ?? 'Identity status unavailable'} openSections={openSections} toggleSection={toggleSection}>
        {identityStatus ? (
          <div className="space-y-3">
            <StatusLine status={identityStatus.status} title={identityStatus.provider} detail={identityStatus.operator_next_step} />
            <SettingGrid settings={pickSettings(settingByKey, tabSettingKeys.identity)} draftValues={draftValues} dirtyKeys={dirtyKeys} updateDraft={updateDraft} />
          </div>
        ) : (
          <EmptyInline title="Identity status unavailable" detail="The current backend did not return enterprise identity status." />
        )}
      </SettingsDisclosure>
      <SettingsDisclosure id="api-keys" title="API Keys" summary={`${apiKeys.filter((key) => !key.revoked_at).length} active keys`} openSections={openSections} toggleSection={toggleSection}>
        <div className="mb-4 grid gap-3 md:grid-cols-[1fr_160px_auto]">
          <input value={actorName} readOnly className="h-10 rounded-lg border border-border bg-bg/30 px-3 text-[1rem] text-muted" />
          <select value={newKeyRole} onChange={(event) => setNewKeyRole(event.target.value as 'admin' | 'operator' | 'reviewer')} className="h-10 rounded-lg border border-border bg-surface px-3 text-[1rem] text-text outline-none focus:border-cyan/50">
            <option value="operator" className="bg-surface text-text">Operator</option>
            <option value="reviewer" className="bg-surface text-text">Reviewer</option>
            <option value="admin" className="bg-surface text-text">Admin</option>
          </select>
          <button type="button" disabled={pending === 'api-key-create'} onClick={() => void createKey()} className="inline-flex items-center justify-center gap-2 rounded-md border border-cyan/30 bg-cyan/10 px-3 py-2 text-[1rem] font-semibold text-cyan disabled:opacity-50">
            {pending === 'api-key-create' ? <Loader2 size={14} className="animate-spin" /> : <KeyRound size={14} />}
            Create Key
          </button>
        </div>
        {newKey && (
          <div className="mb-4 rounded-md border border-amber/30 bg-amber/10 p-3 text-[0.925rem] text-amber">
            <div className="font-semibold text-text">New key, shown once</div>
            <div className="mt-2 break-all font-mono">{newKey}</div>
          </div>
        )}
        <div className="space-y-2">
          {apiKeys.length ? apiKeys.map((key) => (
            <div key={key.id} className="grid gap-3 rounded-md border border-border bg-bg/30 p-3 md:grid-cols-[1fr_auto]">
              <div className="min-w-0">
                <div className="truncate text-[1rem] font-semibold text-text">{key.actor_name}</div>
                <div className="mt-1 text-[0.925rem] text-muted">{key.role} · {key.revoked_at ? 'revoked' : 'active'} · created {formatDate(key.created_at)}</div>
              </div>
              <button type="button" disabled={Boolean(key.revoked_at) || pending === 'api-key-create'} onClick={() => void revokeKey(key.id)} className="rounded-md border border-red/30 bg-red/10 px-3 py-2 text-[0.925rem] font-semibold text-red disabled:opacity-50">
                Revoke
              </button>
            </div>
          )) : <EmptyInline title="No API keys" detail="Create a key to use Authorization: Bearer instead of local X-Actor fallback." />}
        </div>
      </SettingsDisclosure>
    </div>
  );
}

type SettingsPanelProps = {
  settingByKey: Map<string, Setting>;
  draftValues: Record<string, unknown>;
  dirtyKeys: Set<string>;
  openSections: Set<string>;
  toggleSection: (id: string) => void;
  updateDraft: (setting: Setting, value: unknown) => void;
};

function SettingGrid({
  settings,
  draftValues,
  dirtyKeys,
  updateDraft,
}: {
  settings: Setting[];
  draftValues: Record<string, unknown>;
  dirtyKeys: Set<string>;
  updateDraft: (setting: Setting, value: unknown) => void;
}) {
  if (!settings.length) {
    return <EmptyInline title="No backend settings" detail="The current settings endpoint does not expose fields for this section." />;
  }

  return (
    <div className="grid gap-3 md:grid-cols-2">
      {settings.map((setting) => (
        <SettingField
          key={setting.key}
          setting={setting}
          value={readSettingValue(setting, draftValues)}
          dirty={dirtyKeys.has(setting.key)}
          updateDraft={updateDraft}
        />
      ))}
    </div>
  );
}

function SettingField({
  setting,
  value,
  dirty,
  updateDraft,
}: {
  setting: Setting;
  value: unknown;
  dirty: boolean;
  updateDraft: (setting: Setting, value: unknown) => void;
}) {
  const label = (
    <span className="mb-1 flex items-center gap-2 text-[0.85rem] font-bold uppercase text-muted">
      {setting.label}
      {dirty && <span className="rounded-full bg-cyan/10 px-1.5 py-0.5 text-[0.7rem] text-cyan">dirty</span>}
      {setting.read_only && <span className="rounded-full bg-bg/50 px-1.5 py-0.5 text-[0.7rem] text-muted">read-only</span>}
    </span>
  );
  const commonClass = 'h-10 w-full rounded-lg border border-border bg-surface px-3 text-[1rem] text-text outline-none transition-colors focus:border-cyan/50 disabled:opacity-70';

  if (setting.input_type === 'checkbox') {
    return (
      <label className="flex min-h-[74px] items-center justify-between gap-3 rounded-lg border border-border bg-bg/25 p-3">
        <span>
          {label}
          <span className="block text-[0.925rem] leading-5 text-muted">{setting.description || setting.key}</span>
        </span>
        <input
          type="checkbox"
          checked={Boolean(value)}
          disabled={setting.read_only}
          onChange={(event) => updateDraft(setting, event.target.checked)}
          className="h-5 w-5 accent-cyan"
        />
      </label>
    );
  }

  return (
    <label className="block rounded-lg border border-border bg-bg/25 p-3">
      {label}
      {setting.input_type === 'select' ? (
        <select
          value={String(value ?? '')}
          disabled={setting.read_only}
          onChange={(event) => updateDraft(setting, event.target.value)}
          className={commonClass}
        >
          {setting.options.map((option) => (
            <option key={option.value} value={option.value} className="bg-surface text-text">
              {option.label}
            </option>
          ))}
        </select>
      ) : setting.input_type === 'number' ? (
        <input
          type="number"
          value={typeof value === 'number' || typeof value === 'string' ? value : ''}
          disabled={setting.read_only}
          min={setting.min_value ?? undefined}
          max={setting.max_value ?? undefined}
          step={setting.step ?? undefined}
          onChange={(event) => updateDraft(setting, event.target.value === '' ? null : Number(event.target.value))}
          className={commonClass}
        />
      ) : (
        <input
          type={setting.input_type === 'password' ? 'password' : 'text'}
          value={setting.sensitive && !dirty ? '' : String(value ?? '')}
          placeholder={setting.sensitive ? setting.masked_value || setting.placeholder || 'Stored securely' : setting.placeholder || ''}
          disabled={setting.read_only}
          onChange={(event) => updateDraft(setting, event.target.value)}
          className={commonClass}
        />
      )}
      {setting.description && <span className="mt-2 block text-[0.85rem] leading-4 text-muted">{setting.description}</span>}
    </label>
  );
}

function SettingsDisclosure({
  id,
  title,
  summary,
  openSections,
  toggleSection,
  children,
}: {
  id: string;
  title: string;
  summary: string;
  openSections: Set<string>;
  toggleSection: (id: string) => void;
  children: ReactNode;
}) {
  const open = openSections.has(id);
  return (
    <section className="overflow-hidden rounded-lg border border-border bg-bg/25">
      <button type="button" onClick={() => toggleSection(id)} className="flex w-full items-center justify-between gap-4 px-4 py-3 text-left">
        <span className="min-w-0">
          <span className="block text-[1rem] font-semibold text-text">{title}</span>
          <span className="mt-1 block truncate text-[0.925rem] text-muted">{summary}</span>
        </span>
        {open ? <ChevronDown size={16} className="shrink-0 text-muted" /> : <Circle size={12} className="shrink-0 text-muted" />}
      </button>
      {open && <div className="border-t border-border p-4">{children}</div>}
    </section>
  );
}

function SummaryChip({ label, value, icon }: { label: string; value: string; icon: ReactNode }) {
  return (
    <div className="rounded-lg border border-border bg-surface/55 p-3">
      <div className="mb-2 flex items-center gap-2 text-[0.77rem] font-bold uppercase text-muted">
        {icon}
        {label}
      </div>
      <div className="truncate text-[1rem] font-semibold text-text">{value}</div>
    </div>
  );
}

function TabButton({ active, onClick, icon, children }: { active: boolean; onClick: () => void; icon: ReactNode; children: ReactNode }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={cn(
        'inline-flex shrink-0 items-center gap-2 rounded-md px-3 py-2 text-[1rem] font-semibold transition-colors',
        active ? 'bg-cyan/10 text-cyan' : 'text-muted hover:bg-bg/40 hover:text-text',
      )}
    >
      {icon}
      {children}
    </button>
  );
}

function StatusLine({ status, title, detail }: { status: string; title: string; detail: string }) {
  return (
    <div className="rounded-lg border border-border bg-bg/30 p-3">
      <div className="flex items-center gap-2">
        <span className={cn('h-2.5 w-2.5 rounded-full', statusDot(status))} />
        <span className="text-[1rem] font-semibold text-text">{title}</span>
        <span className={cn('rounded-full border px-2 py-0.5 text-[0.77rem] font-bold uppercase', statusBadge(status))}>{status}</span>
      </div>
      <p className="mt-2 text-[0.925rem] leading-5 text-muted">{detail}</p>
    </div>
  );
}

function ReadinessCard({ title, status, summary, details, nextStep }: { title: string; status: string; summary: string; details: string[]; nextStep: string }) {
  return (
    <details className="rounded-lg border border-border bg-bg/30 p-3">
      <summary className="cursor-pointer list-none">
        <div className="flex items-center justify-between gap-3">
          <div className="min-w-0">
            <div className="truncate text-[1rem] font-semibold text-text">{title}</div>
            <div className="mt-1 truncate text-[0.925rem] text-muted">{summary}</div>
          </div>
          <span className={cn('rounded-full border px-2 py-0.5 text-[0.77rem] font-bold uppercase', statusBadge(status))}>{status}</span>
        </div>
      </summary>
      <div className="mt-3 space-y-2 border-t border-border pt-3 text-[0.925rem] leading-5 text-muted">
        {details.map((detail) => <div key={detail}>{detail}</div>)}
        <div className="text-cyan">{nextStep}</div>
      </div>
    </details>
  );
}

function MiniMetric({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-md border border-border bg-bg/30 px-3 py-2">
      <div className="text-[0.77rem] font-bold uppercase text-muted">{label}</div>
      <div className="truncate text-[0.925rem] font-semibold text-text">{value}</div>
    </div>
  );
}

function EmptyInline({ title, detail }: { title: string; detail: string }) {
  return (
    <div className="rounded-lg border border-border bg-bg/25 p-5 text-center">
      <h2 className="text-[1.08rem] font-semibold text-text">{title}</h2>
      <p className="mt-2 text-[0.925rem] leading-5 text-muted">{detail}</p>
    </div>
  );
}

function UnavailableNote({ label, detail }: { label: string; detail: string }) {
  return (
    <div className="mt-3 rounded-md border border-amber/30 bg-amber/10 p-3 text-[0.925rem] leading-5 text-amber">
      <div className="mb-1 flex items-center gap-2 font-semibold text-text">
        <X size={13} />
        {label}
      </div>
      {detail}
    </div>
  );
}

function indexSettings(envelope: SettingsEnvelope): Map<string, Setting> {
  const entries = envelope.settings?.sections.flatMap((section) => section.settings.map((setting) => [setting.key, setting] as const)) ?? [];
  return new Map(entries);
}

function findSetting(settings: SettingsEnvelope['settings'], key: string): Setting | undefined {
  return settings?.sections.flatMap((section) => section.settings).find((setting) => setting.key === key);
}

function settingsForKeys(settings: SettingsEnvelope['settings'], keys: string[]): Setting[] {
  const lookup = new Map(settings?.sections.flatMap((section) => section.settings.map((setting) => [setting.key, setting] as const)) ?? []);
  return keys.map((key) => lookup.get(key)).filter((setting): setting is Setting => Boolean(setting));
}

function pickSettings(settingByKey: Map<string, Setting>, keys: string[]): Setting[] {
  return keys.map((key) => settingByKey.get(key)).filter((setting): setting is Setting => Boolean(setting));
}

function readSettingValue(setting: Setting | undefined, draftValues: Record<string, unknown>): unknown {
  if (!setting) return undefined;
  if (Object.prototype.hasOwnProperty.call(draftValues, setting.key)) return draftValues[setting.key];
  return setting.value;
}

function integrationSummary(settingByKey: Map<string, Setting>, key: string, label: string): string {
  const setting = settingByKey.get(key);
  if (!setting) return `${label}: unavailable`;
  const value = setting.value;
  if (setting.input_type === 'checkbox') return `${label}: ${value ? 'enabled' : 'disabled'}`;
  return `${label}: ${setting.configured || Boolean(value) ? 'configured' : 'not configured'}`;
}

function chatgptSummary(status: ChatGptOAuthStatus | null, engagementId: UUID | null): string {
  if (!engagementId) return 'Select an engagement to check ChatGPT status';
  if (!status) return 'Status not loaded';
  return `ChatGPT: ${status.status ?? (status.connected ? 'connected' : 'unavailable')}`;
}

function chatgptDetail(status: ChatGptOAuthStatus | null, engagementId: UUID | null): string {
  if (!engagementId) return 'ChatGPT OAuth status is engagement-scoped, so no status request is made without an engagement.';
  if (!status) return 'Status not loaded yet.';
  if (status.failure_reason) return String(status.failure_reason);
  return String(status.message || status.account_id || 'Backend status loaded without exposing token material.');
}

function normalizeStatus(status: string): string {
  const normalized = status.toLowerCase();
  if (normalized === 'connected' || normalized === 'ready' || normalized === 'enabled') return 'ready';
  if (normalized === 'blocked' || normalized === 'missing' || normalized === 'error') return 'blocked';
  if (normalized === 'unavailable' || normalized === 'disabled') return 'degraded';
  return normalized || 'degraded';
}

function statusDot(status: string): string {
  const normalized = normalizeStatus(status);
  if (normalized === 'ready') return 'bg-green shadow-[0_0_8px_rgba(84,211,122,0.7)]';
  if (normalized === 'blocked') return 'bg-red shadow-[0_0_8px_rgba(255,91,91,0.7)]';
  return 'bg-amber shadow-[0_0_8px_rgba(255,191,71,0.7)]';
}

function statusBadge(status: string): string {
  const normalized = normalizeStatus(status);
  if (normalized === 'ready') return 'border-green/30 bg-green/10 text-green';
  if (normalized === 'blocked') return 'border-red/30 bg-red/10 text-red';
  return 'border-amber/30 bg-amber/10 text-amber';
}

function activeTabToSaveScope(tab: SettingsTab): SaveScope {
  if (tab === 'ai') return 'ai';
  if (tab === 'runtime') return 'runtime';
  if (tab === 'integrations') return 'integrations';
  if (tab === 'data') return 'data';
  if (tab === 'deception') return 'deception';
  return 'identity';
}

function formatDate(value: string): string {
  return new Intl.DateTimeFormat(undefined, {
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  }).format(new Date(value));
}

function errorMessage(error: unknown): string {
  if (error instanceof ApiError) {
    if (typeof error.detail === 'string' && error.detail.trim()) return error.detail;
    return error.message;
  }
  if (error instanceof Error) return error.message;
  return 'AegisPT API request failed.';
}
