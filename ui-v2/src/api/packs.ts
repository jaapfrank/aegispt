import { api, apiBlob } from './transport';
import type {
  CapabilityPack,
  CapabilityPackArtifact,
  CapabilityPackDeployment,
  CapabilityPackValidation,
  UUID,
} from './types';

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
