import type { ReactNode } from 'react';
import { Loader2 } from 'lucide-react';
import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function PageHeader({
  title,
  eyebrow,
  detail,
  actions,
}: {
  title: string;
  eyebrow?: string;
  detail?: string;
  actions?: ReactNode;
}) {
  return (
    <header className="mb-5 flex flex-wrap items-end justify-between gap-4">
      <div className="min-w-0">
        {eyebrow && <div className="mb-1 text-[10px] font-bold uppercase tracking-[0.24em] text-cyan">{eyebrow}</div>}
        <h1 className="text-2xl font-semibold text-text">{title}</h1>
        {detail && <p className="mt-1 max-w-3xl text-[13px] leading-5 text-muted">{detail}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </header>
  );
}

export function MetricCard({ icon, label, value, detail }: { icon: ReactNode; label: string; value: ReactNode; detail?: string }) {
  return (
    <div className="rounded-lg border border-border bg-surface/55 p-4 backdrop-blur-md">
      <div className="mb-3 flex items-center gap-2 text-cyan">
        {icon}
        <span className="text-[10px] font-bold uppercase tracking-wider">{label}</span>
      </div>
      <div className="truncate text-2xl font-semibold text-text">{value}</div>
      {detail && <div className="mt-2 line-clamp-2 text-[12px] leading-5 text-muted">{detail}</div>}
    </div>
  );
}

export function Panel({ title, detail, children, action }: { title: string; detail?: string; children: ReactNode; action?: ReactNode }) {
  return (
    <section className="rounded-xl border border-border bg-surface/55 p-4 backdrop-blur-md">
      <div className="mb-4 flex items-start justify-between gap-3">
        <div className="min-w-0">
          <h2 className="text-[14px] font-semibold text-text">{title}</h2>
          {detail && <p className="mt-1 text-[12px] leading-5 text-muted">{detail}</p>}
        </div>
        {action}
      </div>
      {children}
    </section>
  );
}

export function EmptyState({ title, detail, action }: { title: string; detail: string; action?: ReactNode }) {
  return (
    <div className="rounded-xl border border-border bg-surface/50 p-8 text-center">
      <h2 className="text-[16px] font-semibold text-text">{title}</h2>
      <p className="mx-auto mt-2 max-w-xl text-[13px] leading-5 text-muted">{detail}</p>
      {action && <div className="mt-4 flex justify-center">{action}</div>}
    </div>
  );
}

export function StatusBadge({ value }: { value: string }) {
  const normalized = value.toLowerCase().replace(/-/g, '_');
  const tone =
    normalized.includes('critical') || normalized.includes('blocked') || normalized.includes('failed')
      ? 'border-red/30 bg-red/10 text-red'
      : normalized.includes('high') || normalized.includes('warning') || normalized.includes('degraded') || normalized.includes('queued')
        ? 'border-amber/30 bg-amber/10 text-amber'
        : normalized.includes('ready') || normalized.includes('active') || normalized.includes('completed') || normalized.includes('deployed') || normalized.includes('resolved')
          ? 'border-green/30 bg-green/10 text-green'
          : 'border-cyan/25 bg-cyan/10 text-cyan';
  return <span className={cn('inline-flex rounded-full border px-2 py-0.5 text-[10px] font-bold uppercase', tone)}>{value}</span>;
}

export function ActionButton({
  children,
  onClick,
  disabled,
  loading,
  tone = 'cyan',
  type = 'button',
}: {
  children: ReactNode;
  onClick?: () => void;
  disabled?: boolean;
  loading?: boolean;
  tone?: 'cyan' | 'green' | 'amber' | 'red' | 'muted';
  type?: 'button' | 'submit';
}) {
  const toneClass = {
    cyan: 'border-cyan/30 bg-cyan/10 text-cyan hover:bg-cyan/15',
    green: 'border-green/30 bg-green/10 text-green hover:bg-green/15',
    amber: 'border-amber/30 bg-amber/10 text-amber hover:bg-amber/15',
    red: 'border-red/30 bg-red/10 text-red hover:bg-red/15',
    muted: 'border-border bg-bg/40 text-muted hover:text-text',
  }[tone];
  return (
    <button
      type={type}
      onClick={onClick}
      disabled={disabled || loading}
      className={cn('inline-flex items-center justify-center gap-2 rounded-md border px-3 py-2 text-[13px] font-semibold transition-colors disabled:cursor-not-allowed disabled:opacity-55', toneClass)}
    >
      {loading && <Loader2 size={14} className="animate-spin" />}
      {children}
    </button>
  );
}

export function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <label className="block">
      <span className="mb-1 block text-[10px] font-bold uppercase tracking-wider text-muted">{label}</span>
      {children}
    </label>
  );
}

export const inputClass =
  'h-10 w-full rounded-lg border border-border bg-surface px-3 text-[13px] text-text outline-none transition-colors placeholder:text-muted/70 focus:border-cyan/50';

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
