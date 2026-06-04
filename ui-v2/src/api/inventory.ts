import { getRun } from './runs';
import { api } from './transport';
import type { InventoryRunCreateInput, InventorySnapshot, Run, UUID } from './types';

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

export async function postInventoryRun(data: InventoryRunCreateInput): Promise<InventorySnapshot> {
  return api<InventorySnapshot>('/api/v1/inventory/runs', {
    method: 'POST',
    json: data,
  });
}
