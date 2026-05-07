import { useAegisStore } from '../store';
import type {
  AgentProposal,
  Engagement,
  EngagementCreateInput,
  Finding,
  InventoryRunCreateInput,
  InventorySnapshot,
  JsonMap,
  Run,
  RunAiInsights,
  RunCreateInput,
  RunDispatch,
  RunIntakeInterpretation,
  RunIntakeInterpretationInput,
  ScopeInput,
  Settings,
  SettingsEnvelope,
  SettingsReadiness,
  Task,
  TaskDetail,
  UUID,
  AgentProposalReviewInput,
} from './types';

type ApiOptions = RequestInit & {
  json?: unknown;
};

export class ApiError extends Error {
  status: number;
  detail: unknown;

  constructor(message: string, status: number, detail: unknown) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.detail = detail;
  }
}

const configuredBaseUrl = import.meta.env.VITE_API_BASE_URL as string | undefined;
const apiBaseUrl = configuredBaseUrl?.replace(/\/$/, '') ?? '';

function requestUrl(path: string): string {
  if (/^https?:\/\//i.test(path)) {
    return path;
  }
  const normalizedPath = path.startsWith('/') ? path : `/${path}`;
  return `${apiBaseUrl}${normalizedPath}`;
}

function selectedTenantId(): string | null {
  const state = useAegisStore.getState();
  return state.selectedEngagement?.tenant_id ?? null;
}

export async function api<T>(path: string, options: ApiOptions = {}): Promise<T> {
  const { json, headers: optionHeaders, ...requestOptions } = options;
  const state = useAegisStore.getState();
  const headers = new Headers(optionHeaders);
  headers.set('Accept', 'application/json');
  headers.set('X-Actor', state.actor.name || 'operator-ui');

  const tenantId = selectedTenantId();
  if (tenantId) {
    headers.set('X-Tenant-ID', tenantId);
  }

  let body = requestOptions.body;
  if (json !== undefined) {
    headers.set('Content-Type', 'application/json');
    body = JSON.stringify(json);
  }

  const response = await fetch(requestUrl(path), {
    ...requestOptions,
    headers,
    body,
  });

  if (response.status === 204) {
    return undefined as T;
  }

  const contentType = response.headers.get('Content-Type') ?? '';
  const payload = contentType.includes('application/json') ? await response.json() : await response.text();

  if (!response.ok) {
    const detail =
      typeof payload === 'object' && payload !== null && 'detail' in payload
        ? (payload as { detail: unknown }).detail
        : payload;
    throw new ApiError(`AegisPT API request failed: ${response.status}`, response.status, detail);
  }

  return payload as T;
}

export async function getEngagements(): Promise<Engagement[]> {
  return api<Engagement[]>('/api/v1/engagements');
}

export async function getRunsForEngagement(engagementId: UUID): Promise<Run[]> {
  return api<Run[]>(`/api/v1/engagements/${engagementId}/runs`);
}

export async function getRun(runId: UUID): Promise<Run> {
  return api<Run>(`/api/v1/runs/${runId}`);
}

export async function getRunTasks(runId: UUID): Promise<Task[]> {
  const run = await getRun(runId);
  return run.tasks;
}

export async function getRunFindings(runId: UUID): Promise<Finding[]> {
  return api<Finding[]>(`/api/v1/runs/${runId}/findings`);
}

export async function getRunInventory(runId: UUID): Promise<InventorySnapshot | null> {
  const run = await getRun(runId);
  if (run.source_inventory_snapshot_id) {
    return api<InventorySnapshot>(`/api/v1/inventory/${run.source_inventory_snapshot_id}`);
  }

  const snapshots = await api<InventorySnapshot[]>(`/api/v1/engagements/${run.engagement_id}/inventory`);
  return snapshots[0] ?? null;
}

export async function getRunAiInsights(runId: UUID): Promise<RunAiInsights> {
  return api<RunAiInsights>(`/api/v1/runs/${runId}/ai-insights`);
}

function settingsToMap(settings: Settings | null): Record<string, unknown> {
  if (!settings) {
    return {};
  }
  return Object.fromEntries(
    settings.sections.flatMap((section) => section.settings.map((setting) => [setting.key, setting.value])),
  );
}

export async function getSettings(): Promise<SettingsEnvelope> {
  const [settingsResult, readinessResult] = await Promise.allSettled([
    api<Settings>('/api/v1/settings'),
    api<SettingsReadiness>('/api/v1/settings/readiness'),
  ]);
  const settings = settingsResult.status === 'fulfilled' ? settingsResult.value : null;
  const readiness = readinessResult.status === 'fulfilled' ? readinessResult.value : null;
  const settingsMap = settingsToMap(settings);
  const chatgptValue = settingsMap['ai.chatgpt_oauth.connected'] ?? settingsMap['ai.provider.chatgpt_connected'];

  return {
    settings,
    readiness,
    chatgpt_connected: chatgptValue === true || chatgptValue === 'true',
    tool_readiness: Object.fromEntries((readiness?.tools ?? []).map((tool) => [tool.id, tool])),
  };
}

export async function postEngagement(data: EngagementCreateInput): Promise<Engagement> {
  return api<Engagement>('/api/v1/engagements', {
    method: 'POST',
    json: data,
  });
}

export async function postRun(engagementId: UUID, data: RunCreateInput): Promise<Run> {
  return api<Run>(`/api/v1/engagements/${engagementId}/runs`, {
    method: 'POST',
    json: data,
  });
}

export async function patchConfirmAuthorization(engagementId: UUID): Promise<JsonMap> {
  return api<JsonMap>(`/api/v1/engagements/${engagementId}/confirm-authorization`, {
    method: 'PATCH',
  });
}

export async function postScope(engagementId: UUID, data: ScopeInput): Promise<JsonMap> {
  return api<JsonMap>(`/api/v1/engagements/${engagementId}/scope`, {
    method: 'POST',
    json: data,
  });
}

export async function postInventoryRun(data: InventoryRunCreateInput): Promise<InventorySnapshot> {
  return api<InventorySnapshot>('/api/v1/inventory/runs', {
    method: 'POST',
    json: data,
  });
}

export async function cancelRun(runId: UUID): Promise<Run> {
  return api<Run>(`/api/v1/runs/${runId}/cancel`, {
    method: 'POST',
  });
}

export async function dispatchRun(runId: UUID): Promise<RunDispatch> {
  return api<RunDispatch>(`/api/v1/runs/${runId}/dispatch`, {
    method: 'POST',
  });
}

export async function postRunIntakeInterpretation(
  data: RunIntakeInterpretationInput,
): Promise<RunIntakeInterpretation> {
  return api<RunIntakeInterpretation>('/api/v1/intake/interpretation', {
    method: 'POST',
    json: data,
  });
}

export async function getRunProposals(runId: UUID): Promise<AgentProposal[]> {
  const insights = await getRunAiInsights(runId);
  return insights.proposals;
}

export async function reviewAgentProposal(
  runId: UUID,
  proposalId: UUID,
  data: AgentProposalReviewInput,
): Promise<AgentProposal> {
  return api<AgentProposal>(`/api/v1/runs/${runId}/ai-proposals/${proposalId}/review`, {
    method: 'POST',
    json: data,
  });
}

export async function getTaskDetail(taskId: UUID): Promise<TaskDetail> {
  return api<TaskDetail>(`/api/v1/tasks/${taskId}`);
}

export async function getAssessmentChain(chainId: UUID): Promise<JsonMap> {
  return api<JsonMap>(`/api/v1/assessment-chains/${chainId}`);
}

export async function decideAssessmentChainPhase(
  chainId: UUID,
  phaseKey: string,
  decision: 'approved' | 'rejected' = 'approved',
): Promise<JsonMap> {
  return api<JsonMap>(`/api/v1/assessment-chains/${chainId}/phases/${phaseKey}/decision`, {
    method: 'POST',
    json: { decision },
  });
}
