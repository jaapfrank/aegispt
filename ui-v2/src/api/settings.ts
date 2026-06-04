import { api } from './transport';
import type {
  ApiKeyCreateInput,
  ApiKeyCreateRead,
  ApiKeyRead,
  ChatGptOAuthAuthorize,
  ChatGptOAuthStatus,
  EnterpriseIdentityStatus,
  Settings,
  SettingsEnvelope,
  SettingsPatchInput,
  SettingsReadiness,
  UUID,
} from './types';

function settingsToMap(settings: Settings | null): Record<string, unknown> {
  if (!settings) {
    return {};
  }
  return Object.fromEntries(
    settings.sections.flatMap((section) => section.settings.map((setting) => [setting.key, setting.value])),
  );
}

export async function getSettings(): Promise<SettingsEnvelope> {
  const [settingsResult, readinessResult] = await Promise.allSettled([
    api<Settings>('/api/v1/settings'),
    api<SettingsReadiness>('/api/v1/settings/readiness'),
  ]);
  const settings = settingsResult.status === 'fulfilled' ? settingsResult.value : null;
  const readiness = readinessResult.status === 'fulfilled' ? readinessResult.value : null;
  const settingsMap = settingsToMap(settings);
  const chatgptValue = settingsMap['ai.chatgpt_oauth.connected'] ?? settingsMap['ai.provider.chatgpt_connected'];

  return {
    settings,
    readiness,
    chatgpt_connected: chatgptValue === true || chatgptValue === 'true',
    tool_readiness: Object.fromEntries((readiness?.tools ?? []).map((tool) => [tool.id, tool])),
  };
}

export async function patchSettings(data: SettingsPatchInput): Promise<Settings> {
  return api<Settings>('/api/v1/settings', {
    method: 'PATCH',
    json: data,
  });
}

export async function getChatGptOAuthStatus(engagementId: UUID): Promise<ChatGptOAuthStatus> {
  return api<ChatGptOAuthStatus>(`/api/v1/auth/chatgpt/status?engagement_id=${engagementId}`);
}

export async function authorizeChatGptOAuth(engagementId: UUID): Promise<ChatGptOAuthAuthorize> {
  return api<ChatGptOAuthAuthorize>(`/api/v1/auth/chatgpt/authorize?engagement_id=${engagementId}`);
}

export async function getApiKeys(): Promise<ApiKeyRead[]> {
  return api<ApiKeyRead[]>('/api/v1/auth/keys');
}

export async function createApiKey(data: ApiKeyCreateInput): Promise<ApiKeyCreateRead> {
  return api<ApiKeyCreateRead>('/api/v1/auth/keys', {
    method: 'POST',
    json: data,
  });
}

export async function revokeApiKey(keyId: UUID): Promise<ApiKeyRead> {
  return api<ApiKeyRead>(`/api/v1/auth/keys/${keyId}/revoke`, {
    method: 'POST',
  });
}

export async function getEnterpriseIdentityStatus(): Promise<EnterpriseIdentityStatus> {
  return api<EnterpriseIdentityStatus>('/api/v1/auth/identity/status');
}
