import { getEngagements } from './engagements';
import { api } from './transport';
import type {
  AgentProposal,
  AgentProposalReviewInput,
  AttackPathSimulation,
  JsonMap,
  PortfolioRun,
  Run,
  RunAiInsights,
  RunCreateInput,
  RunDispatch,
  RunIntakeInterpretation,
  RunIntakeInterpretationInput,
  Task,
  TaskDetail,
  UUID,
} from './types';

export async function getRunsForEngagement(engagementId: UUID): Promise<Run[]> {
  return api<Run[]>(`/api/v1/engagements/${engagementId}/runs`);
}

export async function getPortfolioRuns(): Promise<PortfolioRun[]> {
  try {
    return await api<PortfolioRun[]>('/api/v1/portfolio/runs');
  } catch {
    // Legacy fan-out kept for older deployments that do not expose portfolio/runs yet.
  }
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

export async function simulateAttackPaths(
  runId: UUID,
  startingPointLabel: string,
  startingPointType = 'hypothetical_start',
): Promise<AttackPathSimulation> {
  return api<AttackPathSimulation>(`/api/v1/runs/${runId}/attack-paths/simulate`, {
    method: 'POST',
    json: {
      starting_point_label: startingPointLabel,
      starting_point_type: startingPointType,
      max_paths: 5,
    },
  });
}

export async function getRunTasks(runId: UUID): Promise<Task[]> {
  const run = await getRun(runId);
  return run.tasks;
}

export async function getAssessmentChainTasks(chainId: UUID): Promise<Task[]> {
  return api<Task[]>(`/api/v1/assessment-chains/${chainId}/tasks`);
}

export async function getTasksForRunContext(run: Run): Promise<Task[]> {
  const chainId = typeof run.assessment_chain?.id === 'string' ? run.assessment_chain.id : null;
  return chainId ? getAssessmentChainTasks(chainId) : run.tasks;
}

export async function getRunBriefing(runId: UUID): Promise<{ briefing?: string }> {
  return api<{ briefing?: string }>(`/api/v1/runs/${runId}/briefing`);
}

export async function getRunAiInsights(runId: UUID): Promise<RunAiInsights> {
  return api<RunAiInsights>(`/api/v1/runs/${runId}/ai-insights`);
}

export async function getAiInsightsForRunContext(run: Run, runs: Run[] = []): Promise<RunAiInsights> {
  const chainId = typeof run.assessment_chain?.id === 'string' ? run.assessment_chain.id : null;
  if (!chainId) {
    return getRunAiInsights(run.id);
  }

  const candidateRuns = [run, ...runs]
    .filter((candidate) => candidate.assessment_chain?.id === chainId)
    .sort((left, right) => Date.parse(left.created_at) - Date.parse(right.created_at));
  const uniqueRuns = Array.from(new Map(candidateRuns.map((candidate) => [candidate.id, candidate])).values());
  const insightResults = await Promise.allSettled(uniqueRuns.map((candidate) => getRunAiInsights(candidate.id)));
  const insights = insightResults
    .filter((result): result is PromiseFulfilledResult<RunAiInsights> => result.status === 'fulfilled')
    .map((result) => result.value);

  if (insights.length === 0) {
    return getRunAiInsights(run.id);
  }

  const base = insights.find((insight) => insight.run_id === run.id) ?? insights[insights.length - 1];
  const reasoningRecords = uniqueById(insights.flatMap((insight) => insight.reasoning_records)).sort(
    (left, right) => Date.parse(left.created_at) - Date.parse(right.created_at),
  );
  const proposals = uniqueById(insights.flatMap((insight) => insight.proposals)).sort(
    (left, right) => Date.parse(left.created_at) - Date.parse(right.created_at),
  );
  const workbench = plainObject(base.operator_workbench);
  const summary = plainObject(workbench.summary);

  return {
    ...base,
    reasoning_records: reasoningRecords,
    proposals,
    operator_workbench: {
      ...workbench,
      summary: {
        ...summary,
        signals: reasoningRecords.length,
        pending_repair_proposals: proposals.filter((proposal) => ['pending', 'pending_review'].includes(proposal.status)).length,
      },
      chain_context: {
        aggregated: true,
        chain_id: chainId,
        source_run_count: uniqueRuns.length,
        source_insight_count: insights.length,
      },
    },
  };
}

export async function postRun(engagementId: UUID, data: RunCreateInput): Promise<Run> {
  return api<Run>(`/api/v1/engagements/${engagementId}/runs`, {
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

export async function advanceAssessmentLoop(runId: UUID, operatorNote?: string | null): Promise<JsonMap> {
  return api<JsonMap>(`/api/v1/runs/${runId}/assessment-loop/iterate`, {
    method: 'POST',
    json: { operator_note: operatorNote ?? null },
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

function uniqueById<T extends { id: UUID }>(items: T[]): T[] {
  return Array.from(new Map(items.map((item) => [item.id, item])).values());
}

function plainObject(value: unknown): JsonMap {
  return value && typeof value === 'object' && !Array.isArray(value) ? (value as JsonMap) : {};
}
