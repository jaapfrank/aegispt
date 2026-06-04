import { api } from './transport';
import type {
  DashboardRead,
  Engagement,
  EngagementCreateInput,
  JsonMap,
  ScopeInput,
  UUID,
  ZeroDayScanNowResponse,
} from './types';

export async function getEngagements(): Promise<Engagement[]> {
  return api<Engagement[]>('/api/v1/engagements');
}

export async function getDashboard(engagementId?: UUID | null): Promise<DashboardRead> {
  const query = engagementId ? `?engagement_id=${encodeURIComponent(engagementId)}` : '';
  return api<DashboardRead>(`/api/v1/dashboard${query}`);
}

export async function launchZeroDayRapidResponseScan(
  engagementId: UUID,
  recordId: UUID,
  target?: string | null,
): Promise<ZeroDayScanNowResponse> {
  return api<ZeroDayScanNowResponse>(
    `/api/v1/engagements/${engagementId}/threat-intel/zero-day-response/${recordId}/scan-now`,
    {
      method: 'POST',
      json: { target: target ?? null },
    },
  );
}

export async function postEngagement(data: EngagementCreateInput): Promise<Engagement> {
  return api<Engagement>('/api/v1/engagements', {
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

export async function exportEngagementData(engagementId: UUID): Promise<JsonMap> {
  return api<JsonMap>(`/api/v1/engagements/${engagementId}/data-export`);
}

export async function deleteEngagement(engagementId: UUID, confirmationName: string): Promise<void> {
  await api<JsonMap>(`/api/v1/engagements/${engagementId}`, {
    method: 'DELETE',
    body: JSON.stringify({ confirmation: confirmationName }),
  });
}
