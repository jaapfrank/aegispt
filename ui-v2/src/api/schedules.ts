import { api } from './transport';
import type { ScheduledRun, UUID } from './types';

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
