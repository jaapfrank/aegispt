import { useEffect } from 'react';
import type { ReactNode } from 'react';
import {
  Activity,
  Archive,
  BadgeAlert,
  Box,
  ChevronDown,
  Crosshair,
  Database,
  ExternalLink,
  FileText,
  FlaskConical,
  History,
  LayoutDashboard,
  Map,
  Plus,
  Settings,
  Shield,
  ShieldAlert,
} from 'lucide-react';
import { Link, Navigate, NavLink, Outlet, Route, Routes } from 'react-router-dom';
import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';
import Intake from './components/Intake';
import CustomCVELibrary from './components/screens/CustomCVELibrary';
import DashboardScreen from './components/screens/Dashboard';
import EvidenceReplay from './components/screens/EvidenceReplay';
import FindingsTheater from './components/screens/FindingsTheater';
import HistoryScreen from './components/screens/History';
import MissionControl from './components/screens/MissionControl';
import PacksScreen from './components/screens/Packs';
import ProblemsCenter from './components/screens/ProblemsCenter';
import ResearchScreen from './components/screens/Research';
import ReportCenter from './components/screens/ReportCenter';
import SettingsScreen from './components/screens/Settings';
import SurfaceMap from './components/screens/SurfaceMap';
import {
  getEngagements,
  getInventoryForRun,
  getRun,
  getRunAiInsights,
  getRunFindings,
  getRunsForEngagement,
  getSettings,
} from './api/client';
import { useAegisStore } from './store';

function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

type NavEntry = {
  to: string;
  label: string;
  icon: typeof Activity;
  pulse?: boolean;
  badgeKey?: 'findings';
};

type NavSection = {
  label: string;
  items: NavEntry[];
};

const navSections: NavSection[] = [
  {
    label: 'Operate',
    items: [
      { to: '/', label: 'Dashboard', icon: LayoutDashboard },
      { to: '/intake', label: 'Intake', icon: Crosshair },
      { to: '/mission-control', label: 'Mission Control', icon: Activity, pulse: true },
    ],
  },
  {
    label: 'Analyze',
    items: [
      { to: '/surface-map', label: 'Surface Map', icon: Map },
      { to: '/evidence', label: 'Evidence Replay', icon: Archive },
      { to: '/findings', label: 'Findings', icon: ShieldAlert, badgeKey: 'findings' },
      { to: '/reports', label: 'Reports', icon: FileText },
      { to: '/history', label: 'History', icon: History },
      { to: '/problems', label: 'Problems', icon: BadgeAlert },
    ],
  },
  {
    label: 'Build',
    items: [
      { to: '/packs', label: 'Packs', icon: Box },
      { to: '/cve-library', label: 'CVE Library', icon: Database },
      { to: '/research', label: 'Research', icon: FlaskConical },
    ],
  },
];

export default function App() {
  return (
    <Routes>
      <Route element={<AppShell />}>
        <Route index element={<DashboardScreen />} />
        <Route path="intake" element={<IntakeScreen />} />
        <Route path="mission-control" element={<MissionControl />} />
        <Route path="surface-map" element={<SurfaceMap />} />
        <Route path="evidence" element={<EvidenceReplay />} />
        <Route path="findings" element={<FindingsTheater />} />
        <Route path="reports" element={<ReportCenter />} />
        <Route path="history" element={<HistoryScreen />} />
        <Route path="problems" element={<ProblemsCenter />} />
        <Route path="packs" element={<PacksScreen />} />
        <Route path="cve-library" element={<CustomCVELibrary />} />
        <Route path="research" element={<ResearchScreen />} />
        <Route path="settings" element={<SettingsScreen />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  );
}

function AppShell() {
  const engagements = useAegisStore((state) => state.engagements);
  const selectedEngagementId = useAegisStore((state) => state.selectedEngagementId);
  const selectedEngagement = useAegisStore((state) => state.selectedEngagement);
  const selectedRunId = useAegisStore((state) => state.selectedRunId);
  const runs = useAegisStore((state) => state.runs);
  const findings = useAegisStore((state) => state.findings);
  const actor = useAegisStore((state) => state.actor);
  const loading = useAegisStore((state) => state.loading);
  const error = useAegisStore((state) => state.error);
  const setEngagements = useAegisStore((state) => state.setEngagements);
  const selectEngagement = useAegisStore((state) => state.selectEngagement);
  const setRuns = useAegisStore((state) => state.setRuns);
  const setSelectedRun = useAegisStore((state) => state.setSelectedRun);
  const setFindings = useAegisStore((state) => state.setFindings);
  const setInventory = useAegisStore((state) => state.setInventory);
  const setAiInsights = useAegisStore((state) => state.setAiInsights);
  const setSettings = useAegisStore((state) => state.setSettings);
  const setLoading = useAegisStore((state) => state.setLoading);
  const setError = useAegisStore((state) => state.setError);

  useEffect(() => {
    let cancelled = false;

    async function bootstrap() {
      setLoading('bootstrap', true);
      setError(null);
      try {
        const [engagementPayload, settingsPayload] = await Promise.all([getEngagements(), getSettings()]);
        if (cancelled) return;
        setEngagements(engagementPayload);
        setSettings(settingsPayload);
      } catch (bootstrapError) {
        if (cancelled) return;
        setError(errorMessage(bootstrapError));
        setEngagements([]);
      } finally {
        if (!cancelled) {
          setLoading('bootstrap', false);
        }
      }
    }

    void bootstrap();
    return () => {
      cancelled = true;
    };
  }, [setEngagements, setError, setLoading, setSettings]);

  useEffect(() => {
    if (!selectedEngagementId) {
      setRuns([]);
      return;
    }

    const engagementId = selectedEngagementId;
    let cancelled = false;
    async function loadRuns() {
      setLoading('runs', true);
      setError(null);
      try {
        const runPayload = await getRunsForEngagement(engagementId);
        if (!cancelled) {
          setRuns(runPayload);
        }
      } catch (runError) {
        if (!cancelled) {
          setError(errorMessage(runError));
          setRuns([]);
        }
      } finally {
        if (!cancelled) {
          setLoading('runs', false);
        }
      }
    }

    void loadRuns();
    return () => {
      cancelled = true;
    };
  }, [selectedEngagementId, setError, setLoading, setRuns]);

  useEffect(() => {
    if (!selectedRunId) {
      setSelectedRun(null);
      setFindings([]);
      setInventory(null);
      setAiInsights(null);
      return;
    }

    const runId = selectedRunId;
    let cancelled = false;
    async function loadRunScopedData() {
      setLoading('runScoped', true);
      setError(null);
      try {
        const runPayload = await getRun(runId);
        const [findingsPayload, inventoryPayload, aiInsightsPayload] = await Promise.all([
          getRunFindings(runId),
          getInventoryForRun(runPayload),
          getRunAiInsights(runId),
        ]);
        if (cancelled) return;
        setSelectedRun(runPayload);
        setFindings(findingsPayload);
        setInventory(inventoryPayload);
        setAiInsights(aiInsightsPayload);
      } catch (runScopedError) {
        if (!cancelled) {
          setError(errorMessage(runScopedError));
          setFindings([]);
          setInventory(null);
          setAiInsights(null);
        }
      } finally {
        if (!cancelled) {
          setLoading('runScoped', false);
        }
      }
    }

    void loadRunScopedData();
    return () => {
      cancelled = true;
    };
  }, [selectedRunId, setAiInsights, setError, setFindings, setInventory, setLoading, setSelectedRun]);

  const runningRunCount = runs.filter((run) => ['dispatching', 'running'].includes(run.status)).length;
  const runActivityLabel = `${runningRunCount} running`;
  const engagementLabel = selectedEngagement?.name ?? (loading.bootstrap ? 'Loading engagements' : 'No engagement selected');

  return (
    <div className="flex h-screen w-full flex-col overflow-hidden bg-bg text-text font-sans">
        <header className="flex h-[48px] shrink-0 items-center justify-between border-b border-border bg-[rgba(5,9,18,0.97)] px-4 z-50">
          <div className="flex h-full items-center gap-4 min-w-0">
            <Link to="/" className="flex items-center gap-2 pr-4 border-r border-border h-full">
              <div className="flex h-[22px] w-[22px] items-center justify-center rounded-[5px] bg-cyan text-[#04080f]">
                <Shield size={14} strokeWidth={2.5} />
              </div>
              <span className="text-[1rem] font-bold text-cyan tracking-wide">AegisPT</span>
            </Link>

            <select
              aria-label="Selected engagement"
              value={selectedEngagementId ?? ''}
              onChange={(event) => selectEngagement(event.target.value || null)}
              className="max-w-[280px] truncate bg-transparent text-[1rem] font-medium text-text outline-none hover:text-cyan transition-colors"
            >
              {engagements.length === 0 ? (
                <option value="">{engagementLabel}</option>
              ) : (
                engagements.map((engagement) => (
                  <option key={engagement.id} value={engagement.id} className="bg-surface text-text">
                    {engagement.name}
                  </option>
                ))
              )}
            </select>
            <ChevronDown size={14} className="text-muted -ml-3 pointer-events-none" />
          </div>

          <div className="flex h-full items-center gap-4">
            {runningRunCount > 0 && (
              <div className="flex items-center gap-2 rounded-full bg-cyan/10 px-3 py-1 border border-cyan/20">
                <div className={cn(
                  'h-[7px] w-[7px] rounded-full bg-cyan shadow-[0_0_8px_rgba(94,207,255,0.8)]',
                  'animate-pulse-fast',
                )} />
                <span className="text-[0.925rem] font-medium text-cyan">{runActivityLabel}</span>
              </div>
            )}

            <div className="flex h-full items-center gap-4 pl-4 border-l border-border">
              <a
                href="/app/"
                className="inline-flex shrink-0 items-center gap-1 rounded-md border border-border bg-surface/60 px-2 py-1 text-[0.925rem] font-medium text-muted transition-colors hover:border-cyan/40 hover:text-cyan"
                data-testid="switch-to-classic-ui"
              >
                <ExternalLink size={13} />
                Classic UI
              </a>
              <NavLink to="/settings" className="text-muted hover:text-text transition-colors" aria-label="Settings">
                <Settings size={16} />
              </NavLink>
              <button className="flex items-center gap-2 text-[1rem] font-medium text-text hover:text-cyan transition-colors">
                <span>{actor.name}</span>
                <ChevronDown size={14} className="text-muted" />
              </button>
            </div>
          </div>
        </header>

        <div className="flex flex-1 overflow-hidden">
          <aside className="w-[180px] shrink-0 border-r border-border bg-bg flex flex-col pt-4 overflow-y-auto">
            <div className="px-3 mb-6">
              <Link className="w-full flex items-center justify-center gap-2 rounded-md border border-cyan/30 bg-cyan/5 py-2 text-[1rem] font-medium text-cyan hover:bg-cyan/10 hover:border-cyan/50 transition-all shadow-[0_0_15px_rgba(94,207,255,0.05)]" to="/intake">
                <Plus size={16} />
                New Mission
              </Link>
            </div>

            <nav className="flex flex-col gap-6 px-3">
              {navSections.map((section) => (
                <div key={section.label} className="flex flex-col gap-1">
                  <span className="px-2 text-[0.77rem] font-bold uppercase tracking-wider text-muted mb-1">
                    {section.label}
                  </span>
                  {section.items.map((item) => (
                    <NavItem
                      key={item.to}
                      to={item.to}
                      icon={<item.icon size={15} />}
                      label={item.label}
                      badge={item.badgeKey === 'findings' && findings.length > 0 ? String(findings.length) : undefined}
                      showLivingPulse={Boolean(item.pulse && runningRunCount > 0)}
                    />
                  ))}
                </div>
              ))}
            </nav>
          </aside>

          <main className="flex-1 relative overflow-hidden bg-[#04080f]">
            <div className="absolute inset-0 pointer-events-none opacity-20">
              <svg width="100%" height="100%" xmlns="http://www.w3.org/2000/svg">
                <defs>
                  <pattern id="grid" width="40" height="40" patternUnits="userSpaceOnUse">
                    <path d="M 40 0 L 0 0 0 40" fill="none" stroke="rgba(120,177,212,0.15)" strokeWidth="1" />
                  </pattern>
                </defs>
                <rect width="100%" height="100%" fill="url(#grid)" />
              </svg>
            </div>

            <div className="relative z-10 h-full p-8 overflow-y-auto">
              {error && (
                <div className="mb-4 rounded-md border border-amber/30 bg-amber/10 px-4 py-3 text-sm text-amber">
                  {error}
                </div>
              )}
              <Outlet />
            </div>
          </main>
        </div>
      </div>
  );
}

function NavItem({
  icon,
  label,
  to,
  badge,
  showLivingPulse,
}: {
  icon: ReactNode;
  label: string;
  to: string;
  badge?: string;
  showLivingPulse?: boolean;
}) {
  return (
    <NavLink
      to={to}
      className={({ isActive }) =>
        cn(
          'group relative flex items-center justify-between w-full rounded-md px-2 py-1.5 text-[1rem] font-medium transition-all duration-200',
          isActive ? 'bg-cyan/10 text-cyan' : 'text-muted hover:bg-surface hover:text-text',
        )
      }
    >
      {({ isActive }) => (
        <>
          <div className="flex items-center gap-2">
            <span className={cn('transition-colors', isActive ? 'text-cyan' : 'text-muted group-hover:text-text')}>
              {icon}
            </span>
            {label}
          </div>
          <div className="flex items-center gap-2">
            {badge && (
              <span className="flex h-4 min-w-[16px] items-center justify-center rounded-full bg-red/20 px-1 text-[0.77rem] font-bold text-red">
                {badge}
              </span>
            )}
            {showLivingPulse && isActive && (
              <div className="h-1.5 w-1.5 rounded-full bg-cyan animate-pulse shadow-[0_0_5px_rgba(94,207,255,0.8)]" />
            )}
          </div>
          {isActive && (
            <div className="absolute left-0 top-[10%] h-[80%] w-[3px] rounded-r bg-cyan shadow-[0_0_8px_rgba(94,207,255,0.8)]" />
          )}
        </>
      )}
    </NavLink>
  );
}

function IntakeScreen() {
  return (
    <div className="h-full w-full flex flex-col">
      <div className="shrink-0 mb-4">
        <h1 className="text-2xl font-semibold">New Mission</h1>
        <p className="text-muted text-[1rem] mt-1">Configure target, scope, and execution depth before launching.</p>
      </div>
      <div className="flex-1 min-h-0">
        <Intake />
      </div>
    </div>
  );
}

function errorMessage(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }
  return 'AegisPT API request failed.';
}
