import { ApiError } from '../api/client';

type SafeErrorOptions = {
  fallback?: string;
  unavailable?: string;
  notFound?: string;
  denied?: string;
};

const UNSAFE_DIAGNOSTIC_PATTERNS = [
  /aegispt api request failed/i,
  /anthropic api/i,
  /openai api/i,
  /invalid_request_error/i,
  /request[_-]?id/i,
  /credit balance/i,
  /plans? & billing/i,
  /api key/i,
  /traceback/i,
  /stack trace/i,
  /exception/i,
  /\{['"]?type['"]?\s*:/i,
];

export function safeErrorMessage(error: unknown, options: SafeErrorOptions = {}): string {
  const fallback = options.fallback ?? 'This data could not be loaded. Refresh the page or select a different run.';
  const unavailable = options.unavailable ?? fallback;
  const notFound = options.notFound ?? 'The selected data is no longer available. Refresh or choose another item.';
  const denied = options.denied ?? 'Your current operator role cannot access this data.';

  if (error instanceof ApiError) {
    if (error.status === 401 || error.status === 403) return denied;
    if (error.status === 404) return notFound;
    if (error.status >= 500) return unavailable;
    return safeDiagnosticText(error.detail, fallback);
  }

  if (error instanceof Error) return safeDiagnosticText(error.message, fallback);
  return fallback;
}

export function safeProviderText(value: string | null | undefined, fallback: string): string | null {
  if (!value) return null;
  return isUnsafeDiagnosticText(value) ? fallback : value;
}

export function isUnsafeDiagnosticText(value: unknown): boolean {
  if (typeof value !== 'string') return false;
  const text = value.trim();
  if (!text) return false;
  return UNSAFE_DIAGNOSTIC_PATTERNS.some((pattern) => pattern.test(text));
}

function safeDiagnosticText(value: unknown, fallback: string): string {
  if (typeof value !== 'string') return fallback;
  const text = value.trim();
  if (!text || isUnsafeDiagnosticText(text)) return fallback;
  return text.length > 220 ? `${text.slice(0, 217)}...` : text;
}
