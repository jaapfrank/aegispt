import type { Engagement, Finding, Run, UUID } from '../../api/types';
import type { TFunction } from '../../i18n';
import type { CommandPaletteItem } from './types';
import { navSections } from './navConfig';

export function buildCommandPaletteItems({
  engagements,
  runs,
  findings,
  selectEngagement,
  selectRun,
  selectFinding,
  t,
}: {
  engagements: Engagement[];
  runs: Run[];
  findings: Finding[];
  selectEngagement: (engagementId: UUID | null) => void;
  selectRun: (runId: UUID | null) => void;
  selectFinding: (findingId: UUID | null) => void;
  t: TFunction;
}): CommandPaletteItem[] {
  const navigationItems = [
    ...navSections.flatMap((section) =>
      section.items.map((item) => ({
        id: `nav-${item.to}`,
        group: t(section.labelKey),
        label: t(item.labelKey),
        detail: t('command.openScreen', { label: t(item.labelKey) }),
        keywords: `${t(section.labelKey)} ${t(item.labelKey)} ${item.to}`,
        to: item.to,
      })),
    ),
    {
      id: 'nav-settings',
      group: t('nav.operate'),
      label: t('nav.settings'),
      detail: t('command.openSettings'),
      keywords: 'settings operator tools identity integrations',
      to: '/settings',
    },
    {
      id: 'quick-new-mission',
      group: t('command.group.quick'),
      label: t('shell.newMission'),
      detail: t('command.newMissionDetail'),
      keywords: 'new mission intake create launch scope',
      to: '/intake',
    },
  ];

  const engagementItems = engagements.map((engagement) => ({
    id: `engagement-${engagement.id}`,
    group: t('command.group.engagement'),
    label: engagement.name,
    detail: engagement.client ? `${engagement.client} · ${engagement.status}` : engagement.status,
    keywords: `${engagement.name} ${engagement.client ?? ''} ${engagement.status}`,
    to: '/',
    action: () => selectEngagement(engagement.id),
  }));

  const runItems = runs.slice(0, 8).map((run) => ({
    id: `run-${run.id}`,
    group: t('command.group.run'),
    label: run.profile.name,
    detail: `${run.status} · ${compactId(run.id)}`,
    keywords: `${run.profile.name} ${run.status} ${run.id}`,
    to: '/mission-control',
    action: () => selectRun(run.id),
  }));

  const findingItems = findings.slice(0, 12).map((finding) => ({
    id: `finding-${finding.id}`,
    group: t('command.group.finding'),
    label: finding.title,
    detail: `${finding.severity} · ${finding.status} · ${finding.target_id}`,
    keywords: `${finding.title} ${finding.severity} ${finding.status} ${finding.target_id} ${finding.evidence_ref}`,
    to: '/findings',
    action: () => selectFinding(finding.id),
  }));

  return [...navigationItems, ...engagementItems, ...runItems, ...findingItems];
}

function compactId(value: string): string {
  return value.length > 12 ? `${value.slice(0, 8)}...${value.slice(-4)}` : value;
}
