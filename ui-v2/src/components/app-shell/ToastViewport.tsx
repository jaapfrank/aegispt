import type { ReactNode } from 'react';
import { AlertTriangle, CheckCircle2, Info, X, XCircle } from 'lucide-react';
import { useI18n } from '../../i18n';
import type { ToastNotice, ToastTone } from './types';
import { cn } from './utils';

export default function ToastViewport({
  toasts,
  onDismiss,
}: {
  toasts: ToastNotice[];
  onDismiss: (toastId: number) => void;
}) {
  const { t } = useI18n();
  if (toasts.length === 0) return null;
  return (
    <div className="toast-viewport" aria-live="polite" aria-atomic="false">
      {toasts.map((toast) => (
        <div key={toast.id} className={cn('toast-notice', toastToneClass(toast.tone))}>
          <div className="mt-0.5 shrink-0">{toastIcon(toast.tone)}</div>
          <div className="min-w-0 flex-1">
            <p className="truncate text-[1rem] font-semibold text-text">{toast.title}</p>
            <p className="mt-1 line-clamp-2 text-[0.925rem] leading-5 text-muted">{toast.detail}</p>
          </div>
          <button
            type="button"
            onClick={() => onDismiss(toast.id)}
            className="shrink-0 rounded-md p-1 text-muted transition-colors hover:bg-surface hover:text-text"
            aria-label={t('shell.dismissToast', { title: toast.title })}
          >
            <X size={14} />
          </button>
        </div>
      ))}
    </div>
  );
}

function toastToneClass(tone: ToastTone): string {
  if (tone === 'success') return 'toast-success';
  if (tone === 'warning') return 'toast-warning';
  if (tone === 'error') return 'toast-error';
  return 'toast-info';
}

function toastIcon(tone: ToastTone): ReactNode {
  if (tone === 'success') return <CheckCircle2 size={17} />;
  if (tone === 'warning') return <AlertTriangle size={17} />;
  if (tone === 'error') return <XCircle size={17} />;
  return <Info size={17} />;
}
