import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { KeyboardEvent as ReactKeyboardEvent, ReactNode } from 'react';
import {
  Activity,
  Archive,
  AlertTriangle,
  BadgeAlert,
  Box,
  ChevronDown,
  CheckCircle2,
  Command,
  CornerDownLeft,
  Crosshair,
  Database,
  ExternalLink,
  FileText,
  FlaskConical,
  History,
  Info,
  LayoutDashboard,
  Map,
  Plus,
  Settings,
  Shield,
  ShieldAlert,
  X,
  XCircle,
} from 'lucide-react';
import { Link, Navigate, NavLink, Outlet, Route, Routes, useLocation, useNavigate } from 'react-router-dom';
import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';
import { AnimatePresence, motion } from 'framer-motion';
import Intake from './components/Intake';
import CustomCVELibrary from './components/screens/CustomCVELibrary';
import DashboardScreen from './components/screens/Dashboard';
import EvidenceReplay from './components/screens/EvidenceReplay';
import FindingsTheater from './components/screens/FindingsTheater';
import HistoryScreen from './components/screens/History';
import LiveCLIScreen from './components/screens/LiveCLI';
import MissionControl from './components/screens/MissionControl';
import PacksScreen from './components/screens/Packs';
import ProblemsCenter from './components/screens/ProblemsCenter';
import ResearchScreen from './components/screens/Research';
import ReportCenter from './components/screens/ReportCenter';
import SettingsScreen from './components/screens/Settings';
import SurfaceMap from './components/screens/SurfaceMap';
import {
  ApiError,
  getAiInsightsForRunContext,
  getEngagements,
  getFindingsForRunContext,
  getInventoryForRun,
  getRun,
  getRunsForEngagement,
  getSettings,
  getTasksForRunContext,
} from './api/client';
import type { Run } from './api/types';
import { useAegisStore } from './store';
import ErrorBoundary from './components/ErrorBoundary';
import { I18nProvider, useI18n, type TFunction } from './i18n';
import LanguageSelector from './i18n/LanguageSelector';

function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

type NavEntry = {
  to: string;
  labelKey: Parameters<TFunction>[0];
  icon: typeof Activity;
  pulse?: boolean;
  badgeKey?: 'findings';
};

type NavSection = {
  labelKey: Parameters<TFunction>[0];
  items: NavEntry[];
};

type CommandPaletteItem = {
  id: string;
  group: string;
  label: string;
  detail: string;
  keywords: string;
  to?: string;
  action?: () => void;
};

type ToastTone = 'success' | 'warning' | 'error' | 'info';

type ToastNotice = {
  id: number;
  tone: ToastTone;
  title: string;
  detail: string;
};

const navSections: NavSection[] = [
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

export default function App() {
  return (
    <I18nProvider>
      <Routes>
        <Route element={<AppShell />}>
          <Route index element={<DashboardScreen />} />
          <Route path="intake" element={<IntakeScreen />} />
          <Route path="mission-control" element={<MissionControl />} />
          <Route path="live-cli" element={<LiveCLIScreen />} />
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
    </I18nProvider>
  );
}

function AppShell() {
  const { t } = useI18n();
  const location = useLocation();
  const navigate = useNavigate();
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
  const selectRun = useAegisStore((state) => state.selectRun);
  const setRuns = useAegisStore((state) => state.setRuns);
  const setSelectedRun = useAegisStore((state) => state.setSelectedRun);
  const setTasks = useAegisStore((state) => state.setTasks);
  const setFindings = useAegisStore((state) => state.setFindings);
  const selectFinding = useAegisStore((state) => state.selectFinding);
  const setInventory = useAegisStore((state) => state.setInventory);
  const setAiInsights = useAegisStore((state) => state.setAiInsights);
  const setSettings = useAegisStore((state) => state.setSettings);
  const setLoading = useAegisStore((state) => state.setLoading);
  const setError = useAegisStore((state) => state.setError);
  const [commandOpen, setCommandOpen] = useState(false);
  const [toasts, setToasts] = useState<ToastNotice[]>([]);
  const toastIdRef = useRef(0);
  const lastErrorToastRef = useRef<string | null>(null);

  const removeToast = useCallback((toastId: number) => {
    setToasts((current) => current.filter((toast) => toast.id !== toastId));
  }, []);

  const pushToast = useCallback((tone: ToastTone, title: string, detail: string) => {
    const id = toastIdRef.current + 1;
    toastIdRef.current = id;
    setToasts((current) => [...current.slice(-3), { id, tone, title, detail }]);
    window.setTimeout(() => removeToast(id), 5200);
  }, [removeToast]);

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
        const [tasksPayload, findingsPayload, inventoryPayload, aiInsightsPayload] = await Promise.all([
          getTasksForRunContext(runPayload),
          getFindingsForRunContext(runPayload),
          getInventoryForRun(runPayload),
          getAiInsightsForRunContext(runPayload, runs),
        ]);
        if (cancelled) return;
        setSelectedRun(runPayload);
        setTasks(tasksPayload);
        setFindings(findingsPayload);
        setInventory(inventoryPayload);
        setAiInsights(aiInsightsPayload);
      } catch (runScopedError) {
        if (!cancelled) {
          if (runScopedError instanceof ApiError && runScopedError.status === 404) {
            const fallbackRun = fallbackRunForMissingRun(runs, useAegisStore.getState().selectedRun, runId);
            setSelectedRun(fallbackRun);
            setTasks(fallbackRun?.tasks ?? []);
            setError(null);
          } else {
            setError(errorMessage(runScopedError));
            setTasks([]);
          }
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
  }, [runs, selectedRunId, setAiInsights, setError, setFindings, setInventory, setLoading, setSelectedRun, setTasks]);

  const runningRunCount = runs.filter((run) => ['dispatching', 'running'].includes(run.status)).length;
  const criticalFindingCount = findings.filter((finding) => finding.severity.toLowerCase() === 'critical').length;
  const previousCriticalCountRef = useRef(criticalFindingCount);
  const [criticalPulseVisible, setCriticalPulseVisible] = useState(false);
  const runActivityLabel = t('shell.runningRuns', { count: runningRunCount });
  const engagementLabel = selectedEngagement?.name ?? (loading.bootstrap ? t('shell.loadingEngagements') : t('shell.noEngagement'));
  const commandItems = useMemo(
    () =>
      buildCommandPaletteItems({
        engagements,
        runs,
        findings,
        selectEngagement,
        selectRun,
        selectFinding,
        t,
      }),
    [engagements, findings, runs, selectEngagement, selectFinding, selectRun, t],
  );

  useEffect(() => {
    const previousCriticalCount = previousCriticalCountRef.current;
    previousCriticalCountRef.current = criticalFindingCount;
    if (criticalFindingCount > previousCriticalCount) {
      setCriticalPulseVisible(true);
      const timer = window.setTimeout(() => setCriticalPulseVisible(false), 1500);
      return () => window.clearTimeout(timer);
    }
    return undefined;
  }, [criticalFindingCount]);

  useEffect(() => {
    if (!error || lastErrorToastRef.current === error) return;
    lastErrorToastRef.current = error;
    pushToast('error', t('shell.requestFailed'), error);
  }, [error, pushToast, t]);

  useEffect(() => {
    function handleGlobalKeyDown(event: KeyboardEvent) {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault();
        setCommandOpen((current) => !current);
      }
    }
    window.addEventListener('keydown', handleGlobalKeyDown);
    return () => window.removeEventListener('keydown', handleGlobalKeyDown);
  }, []);

  return (
    <div className="aegis-shell flex h-screen w-full flex-col overflow-hidden bg-bg text-text font-sans">
        {criticalPulseVisible && <div className="living-critical-vignette" aria-hidden="true" />}
        <header className="aegis-topbar z-50 flex h-[48px] shrink-0 items-center justify-between border-b border-border px-4">
          <div className="flex h-full items-center gap-4 min-w-0">
            <Link to="/" className="flex items-center gap-2 pr-4 border-r border-border h-full">
              <div className="flex h-[22px] w-[22px] items-center justify-center rounded-[5px] bg-cyan text-[#04080f]">
                <Shield size={14} strokeWidth={2.5} />
              </div>
              <span className="text-[1rem] font-bold text-cyan tracking-wide">AegisPT</span>
            </Link>

            <select
              aria-label={t('shell.selectedEngagement')}
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
              <LanguageSelector />
              <button
                type="button"
                onClick={() => setCommandOpen(true)}
                className="inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-md border border-border bg-surface/60 text-muted transition-colors hover:border-cyan/40 hover:text-cyan hover:shadow-[0_0_1rem_rgba(94,207,255,0.12)]"
                aria-label={t('shell.openCommandPalette')}
              >
                <Command size={15} />
              </button>
              <a
                href="/app/"
                className="inline-flex shrink-0 items-center gap-1 rounded-md border border-border bg-surface/60 px-2 py-1 text-[0.925rem] font-medium text-muted transition-colors hover:border-cyan/40 hover:text-cyan hover:shadow-[0_0_1rem_rgba(94,207,255,0.12)]"
                data-testid="switch-to-classic-ui"
              >
                <ExternalLink size={13} />
                {t('shell.classicUi')}
              </a>
              <NavLink to="/settings" className="text-muted hover:text-text transition-colors" aria-label={t('nav.settings')}>
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
          <aside className="aegis-sidebar flex w-[180px] shrink-0 flex-col overflow-y-auto border-r border-border pt-4">
            <div className="px-3 mb-6">
              <Link className="flex w-full items-center justify-center gap-2 rounded-md border border-cyan/30 bg-cyan/5 py-2 text-[1rem] font-semibold text-cyan shadow-[0_0_1rem_rgba(94,207,255,0.08)] transition-all hover:border-cyan/50 hover:bg-cyan/10 hover:shadow-[0_0_1.25rem_rgba(94,207,255,0.18)]" to="/intake">
                <Plus size={16} />
                {t('shell.newMission')}
              </Link>
            </div>

            <nav className="flex flex-col gap-6 px-3">
              {navSections.map((section) => (
                <div key={section.labelKey} className="flex flex-col gap-1">
                  <span className="px-2 text-[0.77rem] font-bold uppercase tracking-wider text-muted mb-1">
                    {t(section.labelKey)}
                  </span>
                  {section.items.map((item) => (
                    <NavItem
                      key={item.to}
                      to={item.to}
                      icon={<item.icon size={15} />}
                      label={t(item.labelKey)}
                      badge={item.badgeKey === 'findings' && findings.length > 0 ? String(findings.length) : undefined}
                      criticalBadge={item.badgeKey === 'findings' && criticalPulseVisible}
                      showLivingPulse={Boolean(item.pulse && runningRunCount > 0)}
                    />
                  ))}
                </div>
              ))}
            </nav>
          </aside>

          <main className="aegis-workspace relative flex-1 overflow-hidden">
            <div className="aegis-background" aria-hidden="true" />
            <div className="aegis-scanline" aria-hidden="true" />

            <div className="aegis-content relative z-10 h-full overflow-y-auto p-8">
              {error && (
                <div className="mb-4 rounded-md border border-amber/30 bg-amber/10 px-4 py-3 text-sm text-amber">
                  {error}
                </div>
              )}
              {loading.bootstrap && engagements.length === 0 ? (
                <WorkspaceSkeleton />
              ) : (
                <AnimatePresence mode="wait" initial={false}>
                  <motion.div
                    key={location.pathname}
                    className="route-transition-shell"
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: -8 }}
                    transition={{ duration: 0.18, ease: 'easeOut' }}
                  >
                    <ErrorBoundary resetKey={location.pathname}>
                      <Outlet />
                    </ErrorBoundary>
                  </motion.div>
                </AnimatePresence>
              )}
            </div>
          </main>
        </div>
        {commandOpen && (
          <CommandPalette
            items={commandItems}
            onClose={() => setCommandOpen(false)}
            onNavigate={(target) => navigate(target)}
            onNotify={pushToast}
          />
        )}
        <ToastViewport toasts={toasts} onDismiss={removeToast} />
      </div>
  );
}

function NavItem({
  icon,
  label,
  to,
  badge,
  criticalBadge,
  showLivingPulse,
}: {
  icon: ReactNode;
  label: string;
  to: string;
  badge?: string;
  criticalBadge?: boolean;
  showLivingPulse?: boolean;
}) {
  return (
    <NavLink
      to={to}
      className={({ isActive }) =>
        cn(
          'group relative flex w-full items-center justify-between rounded-md px-2 py-1.5 text-[1rem] font-medium transition-all duration-200',
          isActive
            ? 'bg-cyan/10 text-cyan shadow-[inset_0_0_0_1px_rgba(94,207,255,0.08),0_0_1rem_rgba(94,207,255,0.08)]'
            : 'text-muted hover:bg-surface hover:text-text hover:shadow-[0_0_1rem_rgba(94,207,255,0.07)]',
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
              <span className={cn(
                'living-badge-pop flex h-4 min-w-[16px] items-center justify-center rounded-full bg-red/20 px-1 text-[0.77rem] font-bold text-red',
                criticalBadge && 'living-critical-pulse',
              )}>
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

function WorkspaceSkeleton() {
  const { t } = useI18n();
  return (
    <section className="flex h-full min-h-0 flex-col" aria-label={t('shell.loadingWorkspace')}>
      <div className="mb-5 flex flex-wrap items-end justify-between gap-4">
        <div className="min-w-[18rem] flex-1">
          <div className="skeleton-glow mb-3 h-4 w-28 rounded-full" />
          <div className="skeleton-glow mb-3 h-8 w-64 max-w-full rounded-md" />
          <div className="skeleton-glow h-4 w-[30rem] max-w-full rounded-full" />
        </div>
        <div className="skeleton-glow h-10 w-28 rounded-md" />
      </div>

      <div className="mb-5 grid gap-3 md:grid-cols-2 xl:grid-cols-5">
        {Array.from({ length: 5 }).map((_, index) => (
          <div key={`metric-skeleton-${index}`} className="neon-panel rounded-lg p-4">
            <div className="skeleton-glow mb-4 h-4 w-24 rounded-full" />
            <div className="skeleton-glow mb-3 h-8 w-16 rounded-md" />
            <div className="skeleton-glow h-3 w-32 rounded-full" />
          </div>
        ))}
      </div>

      <div className="grid min-h-0 flex-1 gap-5 xl:grid-cols-2">
        {Array.from({ length: 2 }).map((_, panelIndex) => (
          <div key={`panel-skeleton-${panelIndex}`} className="neon-panel rounded-lg p-5">
            <div className="skeleton-glow mb-5 h-5 w-40 rounded-md" />
            <div className="space-y-3">
              {Array.from({ length: 5 }).map((__, rowIndex) => (
                <div key={`row-skeleton-${panelIndex}-${rowIndex}`} className="rounded-lg border border-border bg-bg/25 p-3">
                  <div className="skeleton-glow mb-3 h-4 w-3/4 rounded-full" />
                  <div className="skeleton-glow h-3 w-1/2 rounded-full" />
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}

function CommandPalette({
  items,
  onClose,
  onNavigate,
  onNotify,
}: {
  items: CommandPaletteItem[];
  onClose: () => void;
  onNavigate: (target: string) => void;
  onNotify: (tone: ToastTone, title: string, detail: string) => void;
}) {
  const { t } = useI18n();
  const inputRef = useRef<HTMLInputElement | null>(null);
  const [query, setQuery] = useState('');
  const [activeIndex, setActiveIndex] = useState(0);
  const filteredItems = useMemo(() => filterCommandItems(items, query), [items, query]);
  const activeItem = filteredItems[activeIndex] ?? filteredItems[0] ?? null;

  useEffect(() => {
    inputRef.current?.focus();
  }, []);

  useEffect(() => {
    setActiveIndex(0);
  }, [query]);

  function selectItem(item: CommandPaletteItem | null) {
    if (!item) return;
    item.action?.();
    if (item.to) {
      onNavigate(item.to);
    }
    onNotify('info', item.label, item.detail);
    onClose();
  }

  function handleKeyDown(event: ReactKeyboardEvent<HTMLInputElement>) {
    if (event.key === 'Escape') {
      event.preventDefault();
      onClose();
      return;
    }
    if (event.key === 'ArrowDown') {
      event.preventDefault();
      setActiveIndex((current) => Math.min(filteredItems.length - 1, current + 1));
      return;
    }
    if (event.key === 'ArrowUp') {
      event.preventDefault();
      setActiveIndex((current) => Math.max(0, current - 1));
      return;
    }
    if (event.key === 'Enter') {
      event.preventDefault();
      selectItem(activeItem);
    }
  }

  return (
    <div className="command-palette-overlay" role="presentation" onMouseDown={onClose}>
      <section
        className="command-palette"
        role="dialog"
        aria-modal="true"
        aria-label={t('command.palette')}
        onMouseDown={(event) => event.stopPropagation()}
      >
        <div className="flex items-center gap-3 border-b border-border px-4 py-3">
          <Command size={16} className="text-cyan" />
          <input
            ref={inputRef}
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            onKeyDown={handleKeyDown}
            className="h-10 min-w-0 flex-1 bg-transparent text-[1rem] text-text outline-none placeholder:text-muted"
            placeholder={t('command.searchPlaceholder')}
            aria-label={t('command.searchLabel')}
          />
          <button
            type="button"
            onClick={onClose}
            className="rounded-md border border-border bg-surface/60 px-2 py-1 text-[0.85rem] font-semibold text-muted transition-colors hover:text-text"
          >
            Esc
          </button>
        </div>

        <div className="max-h-[min(34rem,70vh)] overflow-y-auto p-2">
          {filteredItems.length === 0 ? (
            <div className="rounded-lg border border-dashed border-border bg-bg/35 p-6 text-center">
              <p className="text-[1rem] font-semibold text-text">{t('command.noCommand')}</p>
              <p className="mt-1 text-[0.925rem] text-muted">{t('command.noCommandHint')}</p>
            </div>
          ) : (
            <div className="space-y-1">
              {filteredItems.map((item, index) => (
                <button
                  key={item.id}
                  type="button"
                  onMouseEnter={() => setActiveIndex(index)}
                  onClick={() => selectItem(item)}
                  className={cn(
                    'command-palette-item flex w-full items-center justify-between gap-3 rounded-lg px-3 py-2 text-left transition-all',
                    index === activeIndex ? 'border-cyan/35 bg-cyan/10 text-text' : 'border-transparent text-muted hover:bg-surface/70 hover:text-text',
                  )}
                >
                  <span className="min-w-0">
                    <span className="block truncate text-[1rem] font-semibold">{item.label}</span>
                    <span className="mt-0.5 block truncate text-[0.85rem] text-muted">{item.detail}</span>
                  </span>
                  <span className="flex shrink-0 items-center gap-2">
                    <span className="rounded-full border border-border bg-bg/50 px-2 py-0.5 text-[0.7rem] font-bold uppercase text-muted">
                      {item.group}
                    </span>
                    {index === activeIndex && <CornerDownLeft size={14} className="text-cyan" aria-hidden="true" />}
                  </span>
                </button>
              ))}
            </div>
          )}
        </div>
      </section>
    </div>
  );
}

function ToastViewport({ toasts, onDismiss }: { toasts: ToastNotice[]; onDismiss: (toastId: number) => void }) {
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

function buildCommandPaletteItems({
  engagements,
  runs,
  findings,
  selectEngagement,
  selectRun,
  selectFinding,
  t,
}: {
  engagements: ReturnType<typeof useAegisStore.getState>['engagements'];
  runs: ReturnType<typeof useAegisStore.getState>['runs'];
  findings: ReturnType<typeof useAegisStore.getState>['findings'];
  selectEngagement: ReturnType<typeof useAegisStore.getState>['selectEngagement'];
  selectRun: ReturnType<typeof useAegisStore.getState>['selectRun'];
  selectFinding: ReturnType<typeof useAegisStore.getState>['selectFinding'];
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

function filterCommandItems(items: CommandPaletteItem[], query: string): CommandPaletteItem[] {
  const normalized = query.trim().toLowerCase();
  if (!normalized) return items.slice(0, 14);
  const tokens = normalized.split(/\s+/).filter(Boolean);
  return items
    .map((item) => {
      const haystack = `${item.group} ${item.label} ${item.detail} ${item.keywords}`.toLowerCase();
      const score = tokens.reduce((total, token) => total + (haystack.includes(token) ? 1 : -2), 0);
      return { item, score };
    })
    .filter(({ score }) => score > 0)
    .sort((left, right) => right.score - left.score || left.item.label.localeCompare(right.item.label))
    .slice(0, 14)
    .map(({ item }) => item);
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

function IntakeScreen() {
  const { t } = useI18n();
  return (
    <div className="h-full w-full flex flex-col">
      <div className="shrink-0 mb-4">
        <h1 className="text-2xl font-semibold">{t('intake.title')}</h1>
        <p className="text-muted text-[1rem] mt-1">{t('intake.subtitle')}</p>
      </div>
      <div className="flex-1 min-h-0">
        <Intake />
      </div>
    </div>
  );
}

function assessmentChainId(run: Run | null): string | null {
  const chainId = run?.assessment_chain?.id;
  return typeof chainId === 'string' && chainId.trim() ? chainId : null;
}

function compactId(value: string): string {
  return value.length > 12 ? `${value.slice(0, 8)}...${value.slice(-4)}` : value;
}

function fallbackRunForMissingRun(runs: Run[], missingRun: Run | null, missingRunId: string): Run | null {
  const chainId = assessmentChainId(missingRun);
  if (chainId) {
    const sameChain = runs
      .filter((run) => run.id !== missingRunId && assessmentChainId(run) === chainId)
      .sort((left, right) => Date.parse(right.created_at) - Date.parse(left.created_at))[0];
    if (sameChain) return sameChain;
  }
  return runs.find((candidate) => candidate.id !== missingRunId) ?? null;
}

function errorMessage(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }
  return 'AegisPT API request failed.';
}
