import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export const inputClass =
  'h-10 w-full rounded-lg border border-border bg-surface px-3 text-[1rem] text-text outline-none transition-colors placeholder:text-muted/70 focus:border-cyan/50';

export function formatDate(value?: string | null): string {
  if (!value) return 'n/a';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return 'n/a';
  return new Intl.DateTimeFormat(undefined, {
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  }).format(date);
}

export function jsonNumber(value: unknown, fallback = 0): number {
  return typeof value === 'number' && Number.isFinite(value) ? value : fallback;
}

export function jsonString(value: unknown, fallback = 'n/a'): string {
  return typeof value === 'string' && value.trim() ? value : fallback;
}

export function triggerJsonDownload(payload: unknown, filename: string) {
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}