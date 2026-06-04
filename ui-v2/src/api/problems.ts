import { api } from './transport';
import type { ProblemBulkUpdateInput, ProblemBulkUpdateRead, ProblemsQuery, ProblemsRead } from './types';

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
