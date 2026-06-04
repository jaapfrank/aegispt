import { api, apiBlob } from './transport';
import type { RunReportCatalogItem, UUID } from './types';

export async function getRunReports(runId: UUID): Promise<RunReportCatalogItem[]> {
  return api<RunReportCatalogItem[]>(`/api/v1/runs/${runId}/reports`);
}

export async function getRunReportMarkdown(runId: UUID, variant: string): Promise<string> {
  return api<string>(`/api/v1/runs/${runId}/report?format=markdown&variant=${encodeURIComponent(variant)}`);
}

export async function downloadRunReport(runId: UUID, variant: string, format: 'html' | 'pdf'): Promise<Blob> {
  return apiBlob(`/api/v1/runs/${runId}/report?format=${format}&variant=${encodeURIComponent(variant)}`);
}
