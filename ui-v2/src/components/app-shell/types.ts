import type { LucideIcon } from 'lucide-react';
import type { TFunction } from '../../i18n';

export type ShellLabelKey = Parameters<TFunction>[0];

export type NavEntry = {
  to: string;
  labelKey: ShellLabelKey;
  icon: LucideIcon;
  pulse?: boolean;
  badgeKey?: 'findings';
};

export type NavSection = {
  labelKey: ShellLabelKey;
  items: NavEntry[];
};

export type CommandPaletteItem = {
  id: string;
  group: string;
  label: string;
  detail: string;
  keywords: string;
  to?: string;
  action?: () => void;
};

export type ToastTone = 'success' | 'warning' | 'error' | 'info';

export type ToastNotice = {
  id: number;
  tone: ToastTone;
  title: string;
  detail: string;
};
