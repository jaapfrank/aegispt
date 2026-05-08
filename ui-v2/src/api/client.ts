import { useAegisStore } from '../store';
import type {
  AgentProposal,
  AiResearchGeneration,
  AiResearchGenerationInput,
  AiResearchLab,
  CapabilityPack,
  CapabilityPackArtifact,
  CapabilityPackDeployment,
  CapabilityPackValidation,
  CustomVulnerability,
  CustomVulnerabilityExport,
  CustomVulnerabilityInput,
  CustomVulnerabilityList,
  DashboardRead,
  Engagement,
  EngagementCreateInput,
  ApiKeyCreateInput,
  ApiKeyCreateRead,
  ApiKeyRead,
  ChatGptOAuthAuthorize,
  ChatGptOAuthStatus,
  EnterpriseIdentityStatus,
  Finding,
  FindingEvidenceReplay,
  FindingStatusUpdateInput,
  FindingTheater,
  InventoryRunCreateInput,
  InventorySnapshot,
  JsonMap,
  PortfolioRun,
  ProblemBulkUpdateInput,
  ProblemBulkUpdateRead,
  ProblemsQuery,
  ProblemsRead,
  RunReportCatalogItem,
  Run,
  RunAiInsights,
  RunCreateInput,
  RunDispatch,
  RunIntakeInterpretation,
  RunIntakeInterpretationInput,
  ScopeInput,
  ScheduledRun,
  Settings,
  SettingsEnvelope,
  SettingsPatchInput,
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

export async function apiBlob(path: string, options: ApiOptions = {}): Promise<Blob> {
  const { json, headers: optionHeaders, ...requestOptions } = options;
  const state = useAegisStore.getState();
  const headers = new Headers(optionHeaders);
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

  if (!response.ok) {
    const contentType = response.headers.get('Content-Type') ?? '';
    const detail = contentType.includes('application/json') ? await response.json() : await response.text();
    throw new ApiError(`AegisPT API request failed: ${response.status}`, response.status, detail);
  }

  return response.blob();
}

export async function getEngagements(): Promise<Engagement[]> {
  return api<Engagement[]>('/api/v1/engagements');
}

export async function getDashboard(engagementId?: UUID | null): Promise<DashboardRead> {
  const query = engagementId ? `?engagement_id=${encodeURIComponent(engagementId)}` : '';
  return api<DashboardRead>(`/api/v1/dashboard${query}`);
}

export async function getRunsForEngagement(engagementId: UUID): Promise<Run[]> {
  return api<Run[]>(`/api/v1/engagements/${engagementId}/runs`);
}

export async function getPortfolioRuns(): Promise<PortfolioRun[]> {
  const engagements = await getEngagements();
  const runGroups = await Promise.all(
    engagements.map(async (engagement) => {
      const runs = await getRunsForEngagement(engagement.id);
      return runs.map((run) => ({
        ...run,
        engagement_name: engagement.name,
        engagement_client: engagement.client,
      }));
    }),
  );
  return runGroups.flat().sort((left, right) => Date.parse(right.created_at) - Date.parse(left.created_at));
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

export async function getAssessmentChainFindings(chainId: UUID): Promise<Finding[]> {
  return api<Finding[]>(`/api/v1/assessment-chains/${chainId}/findings`);
}

export async function getFindingsForRunContext(run: Run): Promise<Finding[]> {
  const chainId = typeof run.assessment_chain?.id === 'string' ? run.assessment_chain.id : null;
  return chainId ? getAssessmentChainFindings(chainId) : getRunFindings(run.id);
}

export async function getRunTheaterFindings(runId: UUID): Promise<Finding[]> {
  return api<Finding[]>(`/api/v1/runs/${runId}/findings?theater=true`);
}

export async function getRunReports(runId: UUID): Promise<RunReportCatalogItem[]> {
  return api<RunReportCatalogItem[]>(`/api/v1/runs/${runId}/reports`);
}

export async function getRunReportMarkdown(runId: UUID, variant: string): Promise<string> {
  return api<string>(`/api/v1/runs/${runId}/report?format=markdown&variant=${encodeURIComponent(variant)}`);
}

export async function downloadRunReport(runId: UUID, variant: string, format: 'html' | 'pdf'): Promise<Blob> {
  return apiBlob(`/api/v1/runs/${runId}/report?format=${format}&variant=${encodeURIComponent(variant)}`);
}

export async function getFindingTheater(findingId: UUID): Promise<FindingTheater> {
  return api<FindingTheater>(`/api/v1/findings/${findingId}/theater`);
}

export async function getFindingEvidence(findingId: UUID): Promise<FindingEvidenceReplay> {
  return api<FindingEvidenceReplay>(`/api/v1/findings/${findingId}/evidence`);
}

export async function updateFindingStatus(findingId: UUID, data: FindingStatusUpdateInput): Promise<Finding> {
  return api<Finding>(`/api/v1/findings/${findingId}`, {
    method: 'PATCH',
    json: data,
  });
}

export async function enrichFinding(findingId: UUID): Promise<JsonMap> {
  return api<JsonMap>(`/api/v1/findings/${findingId}/ai-enrich`, {
    method: 'POST',
  });
}

export async function handoffFindingToJira(findingId: UUID): Promise<JsonMap> {
  return api<JsonMap>(`/api/v1/findings/${findingId}/handoff-jira`, {
    method: 'POST',
  });
}

export async function getRunInventory(runId: UUID): Promise<InventorySnapshot | null> {
  const run = await getRun(runId);
  return getInventoryForRun(run);
}

export async function getInventoryForRun(run: Run): Promise<InventorySnapshot | null> {
  if (run.source_inventory_snapshot_id) {
    return api<InventorySnapshot>(`/api/v1/inventory/${run.source_inventory_snapshot_id}`);
  }

  const snapshots = await api<InventorySnapshot[]>(`/api/v1/engagements/${run.engagement_id}/inventory`);
  return snapshots[0] ?? null;
}

export async function getEngagementInventory(engagementId: UUID): Promise<InventorySnapshot[]> {
  return api<InventorySnapshot[]>(`/api/v1/engagements/${engagementId}/inventory`);
}

export async function getLatestEngagementInventory(engagementId: UUID): Promise<InventorySnapshot | null> {
  const snapshots = await getEngagementInventory(engagementId);
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

export async function patchSettings(data: SettingsPatchInput): Promise<Settings> {
  return api<Settings>('/api/v1/settings', {
    method: 'PATCH',
    json: data,
  });
}

export async function getChatGptOAuthStatus(engagementId: UUID): Promise<ChatGptOAuthStatus> {
  return api<ChatGptOAuthStatus>(`/api/v1/auth/chatgpt/status?engagement_id=${engagementId}`);
}

export async function authorizeChatGptOAuth(engagementId: UUID): Promise<ChatGptOAuthAuthorize> {
  return api<ChatGptOAuthAuthorize>(`/api/v1/auth/chatgpt/authorize?engagement_id=${engagementId}`);
}

export async function getApiKeys(): Promise<ApiKeyRead[]> {
  return api<ApiKeyRead[]>('/api/v1/auth/keys');
}

export async function createApiKey(data: ApiKeyCreateInput): Promise<ApiKeyCreateRead> {
  return api<ApiKeyCreateRead>('/api/v1/auth/keys', {
    method: 'POST',
    json: data,
  });
}

export async function revokeApiKey(keyId: UUID): Promise<ApiKeyRead> {
  return api<ApiKeyRead>(`/api/v1/auth/keys/${keyId}/revoke`, {
    method: 'POST',
  });
}

export async function getEnterpriseIdentityStatus(): Promise<EnterpriseIdentityStatus> {
  return api<EnterpriseIdentityStatus>('/api/v1/auth/identity/status');
}

export async function getScheduledRuns(engagementId: UUID): Promise<ScheduledRun[]> {
  return api<ScheduledRun[]>(`/api/v1/engagements/${engagementId}/schedules`);
}

export async function pauseScheduledRun(engagementId: UUID, scheduleId: UUID): Promise<ScheduledRun> {
  return api<ScheduledRun>(`/api/v1/engagements/${engagementId}/schedules/${scheduleId}/pause`, {
    method: 'POST',
  });
}

export async function resumeScheduledRun(engagementId: UUID, scheduleId: UUID): Promise<ScheduledRun> {
  return api<ScheduledRun>(`/api/v1/engagements/${engagementId}/schedules/${scheduleId}/resume`, {
    method: 'POST',
  });
}

export async function exportEngagementData(engagementId: UUID): Promise<JsonMap> {
  return api<JsonMap>(`/api/v1/engagements/${engagementId}/data-export`);
}

export async function getProblems(query: ProblemsQuery = {}): Promise<ProblemsRead> {
  const params = new URLSearchParams();
  Object.entries(query).forEach(([key, value]) => {
    if (value !== undefined && value !== null && value !== '') {
      params.set(key, String(value));
    }
  });
  const suffix = params.toString() ? `?${params.toString()}` : '';
  return api<ProblemsRead>(`/api/v1/problems${suffix}`);
}

export async function bulkUpdateProblems(data: ProblemBulkUpdateInput): Promise<ProblemBulkUpdateRead> {
  return api<ProblemBulkUpdateRead>('/api/v1/problems/bulk', {
    method: 'PATCH',
    json: data,
  });
}

export async function getEngagementPacks(engagementId: UUID): Promise<CapabilityPack[]> {
  return api<CapabilityPack[]>(`/api/v1/engagements/${engagementId}/packs`);
}

export async function getPackArtifacts(packId: UUID): Promise<CapabilityPackArtifact[]> {
  return api<CapabilityPackArtifact[]>(`/api/v1/packs/${packId}/artifacts`);
}

export async function validatePack(packId: UUID): Promise<CapabilityPackValidation> {
  return api<CapabilityPackValidation>(`/api/v1/packs/${packId}/validate`, {
    method: 'POST',
  });
}

export async function approvePack(packId: UUID): Promise<CapabilityPack> {
  return api<CapabilityPack>(`/api/v1/packs/${packId}/approve?notes=${encodeURIComponent('React v2 operator approval')}`, {
    method: 'POST',
  });
}

export async function deployPack(packId: UUID, engagementId: UUID): Promise<CapabilityPackDeployment> {
  return api<CapabilityPackDeployment>(`/api/v1/packs/${packId}/deploy`, {
    method: 'POST',
    json: {
      engagement_id: engagementId,
      deployment_target: 'engagement-runtime',
      notes: 'React v2 operator deployment request',
    },
  });
}

export async function downloadArtifactContent(artifactId: UUID): Promise<Blob> {
  return apiBlob(`/api/v1/artifacts/${artifactId}/content`);
}

export async function getCustomVulnerabilities(): Promise<CustomVulnerabilityList> {
  return api<CustomVulnerabilityList>('/api/v1/custom-vulnerabilities');
}

export async function createCustomVulnerability(data: CustomVulnerabilityInput): Promise<CustomVulnerability> {
  return api<CustomVulnerability>('/api/v1/custom-vulnerabilities', {
    method: 'POST',
    json: data,
  });
}

export async function updateCustomVulnerability(id: UUID, data: Partial<CustomVulnerabilityInput>): Promise<CustomVulnerability> {
  return api<CustomVulnerability>(`/api/v1/custom-vulnerabilities/${id}`, {
    method: 'PATCH',
    json: data,
  });
}

export async function deleteCustomVulnerability(id: UUID): Promise<CustomVulnerability> {
  return api<CustomVulnerability>(`/api/v1/custom-vulnerabilities/${id}`, {
    method: 'DELETE',
  });
}

export async function importCustomVulnerabilities(payload: string): Promise<JsonMap> {
  return api<JsonMap>('/api/v1/custom-vulnerabilities/import', {
    method: 'POST',
    json: {
      format: 'plain_text',
      payload,
      use_ai: false,
      default_status: 'draft',
    },
  });
}

export async function exportCustomVulnerabilities(): Promise<CustomVulnerabilityExport> {
  return api<CustomVulnerabilityExport>('/api/v1/custom-vulnerabilities/export');
}

export async function getAiResearchLab(engagementId: UUID): Promise<AiResearchLab> {
  return api<AiResearchLab>(`/api/v1/ai/research?engagement_id=${engagementId}`);
}

export async function generateAiResearchScript(data: AiResearchGenerationInput): Promise<AiResearchGeneration> {
  return api<AiResearchGeneration>('/api/v1/ai/research/generate-script', {
    method: 'POST',
    json: data,
  });
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
