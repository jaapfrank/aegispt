import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { AnimatePresence, motion } from 'framer-motion';
import { ChevronDown, Command, ExternalLink, Moon, Settings, Shield, Sun } from 'lucide-react';
import { Link, NavLink, Outlet, useLocation, useNavigate } from 'react-router-dom';
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
} from '../../api/client';
import type { Run } from '../../api/types';
import ErrorBoundary from '../ErrorBoundary';
import MissionExperienceSpine from '../MissionExperienceSpine';
import { useAegisStore } from '../../store';
import { useI18n } from '../../i18n';
import { safeErrorMessage } from '../../viewModels/safeMessaging';
import LanguageSelector from '../../i18n/LanguageSelector';
import CommandPalette from './CommandPalette';
import { buildCommandPaletteItems } from './commandItems';
import { ShellNavigation } from './navigation';
import ToastViewport from './ToastViewport';
import type { ToastNotice, ToastTone } from './types';
import { cn } from './utils';
import WorkspaceSkeleton from './WorkspaceSkeleton';

type ThemePreference = 'dark' | 'light';

const THEME_STORAGE_KEY = 'aegispt.ui.theme';

export default function AppShell() {
  const { t } = useI18n();
  const location = useLocation();
  const navigate = useNavigate();
  const engagements = useAegisStore((state) => state.engagements);
  const selectedEngagementId = useAegisStore((state) => state.selectedEngagementId);
  const selectedEngagement = useAegisStore((state) => state.selectedEngagement);
  const selectedRunId = useAegisStore((state) => state.selectedRunId);
  const selectedRun = useAegisStore((state) => state.selectedRun);
  const runs = useAegisStore((state) => state.runs);
  const tasks = useAegisStore((state) => state.tasks);
  const findings = useAegisStore((state) => state.findings);
  const inventory = useAegisStore((state) => state.inventory);
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
  const [themePreference, setThemePreference] = useState<ThemePreference>(() => initialThemePreference());
  const toastIdRef = useRef(0);
  const lastErrorToastRef = useRef<string | null>(null);
  const showMissionExperienceSpine = !location.pathname.startsWith('/mission-control');

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
    applyThemePreference(themePreference);
    persistThemePreference(themePreference);
  }, [themePreference]);

  useEffect(() => {
    if (storedThemePreference()) return undefined;
    const media = window.matchMedia?.('(prefers-color-scheme: light)');
    if (!media) return undefined;
    const handleChange = (event: MediaQueryListEvent) => {
      setThemePreference(event.matches ? 'light' : 'dark');
    };
    media.addEventListener('change', handleChange);
    return () => media.removeEventListener('change', handleChange);
  }, []);

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

  const toggleTheme = useCallback(() => {
    setThemePreference((current) => (current === 'dark' ? 'light' : 'dark'));
  }, []);

  const themeLabel = themePreference === 'dark' ? t('shell.switchToLightTheme') : t('shell.switchToDarkTheme');

  return (
    <div className="aegis-shell flex h-screen w-full flex-col overflow-hidden bg-bg text-text font-sans">
      <a
        className="skip-link"
        href="#main-content"
        onClick={(event) => {
          event.preventDefault();
          document.getElementById('main-content')?.focus();
        }}
      >
        {t('shell.skipToWorkspace')}
      </a>
      {criticalPulseVisible && <div className="living-critical-vignette" aria-hidden="true" />}
      <header className="aegis-topbar z-50 flex h-[48px] shrink-0 items-center justify-between border-b border-border px-4">
        <div className="flex h-full items-center gap-4 min-w-0">
          <Link to="/" className="flex items-center gap-2 pr-4 border-r border-border h-full">
            <div className="flex h-[22px] w-[22px] items-center justify-center rounded-[5px] bg-cyan text-[var(--brand-contrast)]">
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
              <div
                className={cn(
                  'h-[7px] w-[7px] rounded-full bg-cyan shadow-[0_0_8px_rgba(94,207,255,0.8)]',
                  'animate-pulse-fast',
                )}
              />
              <span className="text-[0.925rem] font-medium text-cyan">{runActivityLabel}</span>
            </div>
          )}

          <div className="flex h-full items-center gap-4 pl-4 border-l border-border">
            <LanguageSelector />
            <button
              type="button"
              onClick={toggleTheme}
              data-testid="theme-toggle"
              className="inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-md border border-border bg-surface/60 text-muted transition-colors hover:border-cyan/40 hover:text-cyan hover:shadow-[0_0_1rem_rgba(94,207,255,0.12)]"
              aria-label={themeLabel}
              title={themeLabel}
            >
              {themePreference === 'dark' ? <Sun size={15} /> : <Moon size={15} />}
            </button>
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
            <button
              type="button"
              className="flex items-center gap-2 text-[1rem] font-medium text-text hover:text-cyan transition-colors"
              aria-label={t('shell.operatorMenu', { name: actor.name })}
            >
              <span>{actor.name}</span>
              <ChevronDown size={14} className="text-muted" />
            </button>
          </div>
        </div>
      </header>

      <div className="flex flex-1 overflow-hidden">
        <ShellNavigation
          criticalBadge={criticalPulseVisible}
          findingsCount={findings.length}
          runningRunCount={runningRunCount}
          t={t}
        />

        <main id="main-content" tabIndex={-1} aria-label={t('shell.workspace')} className="aegis-workspace relative flex-1 overflow-hidden">
          <div className="aegis-background" aria-hidden="true" />
          <div className="aegis-scanline" aria-hidden="true" />

          <div className="aegis-content relative z-10 h-full overflow-y-auto p-8">
            {showMissionExperienceSpine && (
              <MissionExperienceSpine
                run={selectedRun}
                tasks={tasks}
                findings={findings}
                inventory={inventory}
                currentPath={location.pathname}
                onNavigate={(target) => navigate(target)}
              />
            )}
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

function assessmentChainId(run: Run | null): string | null {
  const chainId = run?.assessment_chain?.id;
  return typeof chainId === 'string' && chainId.trim() ? chainId : null;
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
  return safeErrorMessage(error, {
    fallback: 'AegisPT could not refresh this workspace data. Refresh or select another engagement/run.',
    unavailable: 'AegisPT API is temporarily unavailable. Existing loaded data remains visible where possible.',
  });
}

function initialThemePreference(): ThemePreference {
  const stored = storedThemePreference();
  if (stored) return stored;
  if (typeof window !== 'undefined' && window.matchMedia?.('(prefers-color-scheme: light)').matches) return 'light';
  return 'dark';
}

function storedThemePreference(): ThemePreference | null {
  if (typeof window === 'undefined') return null;
  const stored = window.localStorage.getItem(THEME_STORAGE_KEY);
  return stored === 'light' || stored === 'dark' ? stored : null;
}

function applyThemePreference(theme: ThemePreference) {
  if (typeof document === 'undefined') return;
  document.documentElement.dataset.theme = theme;
  document.documentElement.style.colorScheme = theme;
}

function persistThemePreference(theme: ThemePreference) {
  if (typeof window === 'undefined') return;
  window.localStorage.setItem(THEME_STORAGE_KEY, theme);
}
