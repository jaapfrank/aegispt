import { useAegisStore } from '../store';

export type ApiOptions = RequestInit & {
  json?: unknown;
};

export class ApiError extends Error {
  status: number;
  detail: unknown;

  constructor(message: string, status: number, detail: unknown) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.detail = detail;
  }
}

const configuredBaseUrl = import.meta.env.VITE_API_BASE_URL as string | undefined;
const apiBaseUrl = configuredBaseUrl?.replace(/\/$/, '') ?? '';

function requestUrl(path: string): string {
  if (/^https?:\/\//i.test(path)) {
    return path;
  }
  const normalizedPath = path.startsWith('/') ? path : `/${path}`;
  return `${apiBaseUrl}${normalizedPath}`;
}

function selectedTenantId(): string | null {
  const state = useAegisStore.getState();
  return state.selectedEngagement?.tenant_id ?? null;
}

export async function api<T>(path: string, options: ApiOptions = {}): Promise<T> {
  const { json, headers: optionHeaders, ...requestOptions } = options;
  const state = useAegisStore.getState();
  const headers = new Headers(optionHeaders);
  headers.set('Accept', 'application/json');
  headers.set('X-Actor', state.actor.name || 'operator-ui');

  const tenantId = selectedTenantId();
  if (tenantId) {
    headers.set('X-Tenant-ID', tenantId);
  }

  let body = requestOptions.body;
  if (json !== undefined) {
    headers.set('Content-Type', 'application/json');
    body = JSON.stringify(json);
  }

  const response = await fetch(requestUrl(path), {
    ...requestOptions,
    headers,
    body,
  });

  if (response.status === 204) {
    return undefined as T;
  }

  const contentType = response.headers.get('Content-Type') ?? '';
  const payload = contentType.includes('application/json') ? await response.json() : await response.text();

  if (!response.ok) {
    const detail =
      typeof payload === 'object' && payload !== null && 'detail' in payload
        ? (payload as { detail: unknown }).detail
        : payload;
    throw new ApiError(`AegisPT API request failed: ${response.status}`, response.status, detail);
  }

  return payload as T;
}

export async function apiBlob(path: string, options: ApiOptions = {}): Promise<Blob> {
  const { json, headers: optionHeaders, ...requestOptions } = options;
  const state = useAegisStore.getState();
  const headers = new Headers(optionHeaders);
  headers.set('X-Actor', state.actor.name || 'operator-ui');

  const tenantId = selectedTenantId();
  if (tenantId) {
    headers.set('X-Tenant-ID', tenantId);
  }

  let body = requestOptions.body;
  if (json !== undefined) {
    headers.set('Content-Type', 'application/json');
    body = JSON.stringify(json);
  }

  const response = await fetch(requestUrl(path), {
    ...requestOptions,
    headers,
    body,
  });

  if (!response.ok) {
    const contentType = response.headers.get('Content-Type') ?? '';
    const detail = contentType.includes('application/json') ? await response.json() : await response.text();
    throw new ApiError(`AegisPT API request failed: ${response.status}`, response.status, detail);
  }

  return response.blob();
}
