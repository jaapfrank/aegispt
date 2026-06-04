import { api } from './transport';
import type {
  Finding,
  FindingEvidenceReplay,
  FindingStatusUpdateInput,
  FindingTheater,
  JsonMap,
  RepositoryFixPullRequest,
  Run,
  UUID,
} from './types';

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

export async function createFindingFixPullRequest(findingId: UUID): Promise<RepositoryFixPullRequest> {
  return api<RepositoryFixPullRequest>(`/api/v1/findings/${findingId}/repository/fix-pr`, {
    method: 'POST',
  });
}
