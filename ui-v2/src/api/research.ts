import { api } from './transport';
import type { AiResearchGeneration, AiResearchGenerationInput, AiResearchLab, UUID } from './types';

export async function getAiResearchLab(engagementId: UUID): Promise<AiResearchLab> {
  return api<AiResearchLab>(`/api/v1/ai/research?engagement_id=${engagementId}`);
}

export async function generateAiResearchScript(data: AiResearchGenerationInput): Promise<AiResearchGeneration> {
  return api<AiResearchGeneration>('/api/v1/ai/research/generate-script', {
    method: 'POST',
    json: data,
  });
}
