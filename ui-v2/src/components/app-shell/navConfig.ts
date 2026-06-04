import {
  Activity,
  Archive,
  BadgeAlert,
  Box,
  Command,
  Crosshair,
  Database,
  FileText,
  FlaskConical,
  History,
  LayoutDashboard,
  Map,
  ShieldAlert,
} from 'lucide-react';
import type { NavSection } from './types';

export const navSections: NavSection[] = [
  {
    labelKey: 'nav.operate',
    items: [
      { to: '/', labelKey: 'nav.dashboard', icon: LayoutDashboard },
      { to: '/intake', labelKey: 'nav.intake', icon: Crosshair },
      { to: '/mission-control', labelKey: 'nav.missionControl', icon: Activity, pulse: true },
      { to: '/live-cli', labelKey: 'nav.liveCli', icon: Command },
    ],
  },
  {
    labelKey: 'nav.analyze',
    items: [
      { to: '/surface-map', labelKey: 'nav.surfaceMap', icon: Map },
      { to: '/evidence', labelKey: 'nav.evidenceReplay', icon: Archive },
      { to: '/findings', labelKey: 'nav.findings', icon: ShieldAlert, badgeKey: 'findings' },
      { to: '/reports', labelKey: 'nav.reports', icon: FileText },
      { to: '/history', labelKey: 'nav.history', icon: History },
      { to: '/problems', labelKey: 'nav.problems', icon: BadgeAlert },
    ],
  },
  {
    labelKey: 'nav.build',
    items: [
      { to: '/packs', labelKey: 'nav.packs', icon: Box },
      { to: '/cve-library', labelKey: 'nav.cveLibrary', icon: Database },
      { to: '/research', labelKey: 'nav.research', icon: FlaskConical },
    ],
  },
];
