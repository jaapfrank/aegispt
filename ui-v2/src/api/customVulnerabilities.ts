import { api } from './transport';
import type {
  CustomVulnerability,
  CustomVulnerabilityExport,
  CustomVulnerabilityInput,
  CustomVulnerabilityList,
  JsonMap,
  UUID,
} from './types';

export async function getCustomVulnerabilities(): Promise<CustomVulnerabilityList> {
  return api<CustomVulnerabilityList>('/api/v1/custom-vulnerabilities');
}

export async function createCustomVulnerability(data: CustomVulnerabilityInput): Promise<CustomVulnerability> {
  return api<CustomVulnerability>('/api/v1/custom-vulnerabilities', {
    method: 'POST',
    json: data,
  });
}

export async function updateCustomVulnerability(
  id: UUID,
  data: Partial<CustomVulnerabilityInput>,
): Promise<CustomVulnerability> {
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
