import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  Check,
  CircleStop,
  Loader2,
  MonitorPlay,
  Play,
  RefreshCw,
  ShieldAlert,
  TerminalSquare,
  BrainCircuit,
  ChevronRight,
  Workflow,
  X,
} from 'lucide-react';
import { Link, useLocation } from 'react-router-dom';
import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';
import {
  ApiError,
  cancelRun,
  decideAssessmentChainPhase,
  dispatchRun,
  getAiInsightsForRunContext,
  getFindingsForRunContext,
  getInventoryForRun,
  getRun,
  getTaskDetail,
  getTasksForRunContext,
  reviewAgentProposal,
} from '../../api/client';
import type {
  AgentProposal,
  AssessmentChain,
  Finding,
  JsonMap,
  Run,
  Task,
  TaskDetail,
  UUID,
} from '../../api/types';
import { useAegisStore } from '../../store';
import CinemaMode from '../CinemaMode';
import MissionControlV3 from './MissionControlV3';

const POLL_MS = 3000;
const ACTIVE_STATUSES = new Set(['queued', 'requested', 'dispatching', 'running']);
const QUEUED_STATUSES = new Set(['queued', 'requested']);
const RUNNING_STATUSES = new Set(['dispatching', 'running']);
const TERMINAL_STATUSES = new Set(['completed', 'failed', 'cancelled', 'canceled']);
const OUTPUT_LIMIT = 5000;
function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

type BusyAction = 'refresh' | 'cancel' | 'dispatch' | 'phase' | 'autopilot-continue' | `proposal-${UUID}` | null;

type PhaseView = {
  key: string;
  label: string;
  status: string;
  current: boolean;
  requiresApproval: boolean;
  approved_by?: string | null;
};

type IntakeLaunchState = {
  runId: UUID;
  target: string | null;
  assessmentType: string | null;
  depth: string | null;
};

const lowerValue = (value: unknown): string => (typeof value === 'string' ? value.toLowerCase() : '');
const runStatus = (run: Partial<Run> | null | undefined): string => lowerValue(run?.status);
const taskStatus = (task: Partial<Task> | null | undefined): string => lowerValue(task?.status);
const isRunTerminal = (run: Run): boolean => {
  const status = runStatus(run);
  return TERMINAL_STATUSES.has(status) || chainStatus(run.assessment_chain).toLowerCase() === 'completed_with_gaps';
};

const isTaskActiveForRun = (task: Task, run: Run): boolean => !isRunTerminal(run) && RUNNING_STATUSES.has(taskStatus(task));
const isTaskQueuedForRun = (task: Task, run: Run): boolean => !isRunTerminal(run) && QUEUED_STATUSES.has(taskStatus(task));

export default function MissionControl() {
  const location = useLocation();
  const selectedRun = useAegisStore((state) => state.selectedRun);
  const selectedRunId = useAegisStore((state) => state.selectedRunId);
  const runs = useAegisStore((state) => state.runs);
  const tasks = useAegisStore((state) => state.tasks);
  const findings = useAegisStore((state) => state.findings);
  const aiInsights = useAegisStore((state) => state.aiInsights);
  const loading = useAegisStore((state) => state.loading);
  const setSelectedRun = useAegisStore((state) => state.setSelectedRun);
  const setTasks = useAegisStore((state) => state.setTasks);
  const setFindings = useAegisStore((state) => state.setFindings);
  const setInventory = useAegisStore((state) => state.setInventory);
  const setAiInsights = useAegisStore((state) => state.setAiInsights);
  const setLoading = useAegisStore((state) => state.setLoading);
  const setError = useAegisStore((state) => state.setError);

  const [selectedTaskId, setSelectedTaskId] = useState<UUID | null>(null);
  const [taskDetails, setTaskDetails] = useState<Record<UUID, TaskDetail>>({});
  const [busyAction, setBusyAction] = useState<BusyAction>(null);
  const [_actionMessage, setActionMessage] = useState<string | null>(null);
  const [cinemaOpen, setCinemaOpen] = useState(false);
  const [briefing, setBriefing] = useState<string | null>(null);
  const [_launchArrival, setLaunchArrival] = useState(() => readIntakeLaunchState(location.state));
  const refreshInFlightRef = useRef(false);

  const proposals = useMemo(() => aiInsights?.proposals ?? [], [aiInsights?.proposals]);
  const chain = selectedRun?.assessment_chain ?? null;
  const phases = useMemo(() => buildPhaseViews(chain), [chain]);
  const currentPhase = phases.find((phase) => phase.current) ?? phases[0] ?? null;
  const canCancel = Boolean(selectedRun && !TERMINAL_STATUSES.has(runStatus(selectedRun)));
  const selectedRunIsAutomatic = Boolean(selectedRun && isAutomaticRun(selectedRun));
  const selectedRunIsWargaming = Boolean(selectedRun && isWargamingRun(selectedRun));
  const canDispatch = Boolean(selectedRun && ['queued', 'requested'].includes(runStatus(selectedRun)));
  const consoleTask = useMemo(
    () => (selectedRun ? selectConsoleTask(tasks, selectedRun, selectedTaskId) : null),
    [selectedRun, selectedTaskId, tasks],
  );
  const canApprovePhase = Boolean(
    selectedRun &&
      chainId(chain) &&
      currentPhase?.key &&
      (chainStatus(chain) === 'pending_phase_approval' || (currentPhase.requiresApproval && !currentPhase.approved_by))
  );
  const isPolling = Boolean(selectedRun && ACTIVE_STATUSES.has(runStatus(selectedRun)));

  useEffect(() => {
    const intakeLaunch = readIntakeLaunchState(location.state);
    if (!intakeLaunch) return;
    setLaunchArrival(intakeLaunch);
    const timer = window.setTimeout(() => setLaunchArrival(null), 3200);
    return () => window.clearTimeout(timer);
  }, [location.state]);

  const refreshRun = useCallback(async (runId = selectedRunId, options: { quiet?: boolean } = {}) => {
    if (!runId) return;
    if (refreshInFlightRef.current) return;
    refreshInFlightRef.current = true;
    if (!options.quiet) {
      setBusyAction('refresh');
    }
    setLoading('missionControl', true);
    setError(null);
    try {
      const run = await getRun(runId);
      const [tasksResult, findingsResult, inventoryResult, insightsResult] = await Promise.allSettled([
        getTasksForRunContext(run),
        getFindingsForRunContext(run),
        getInventoryForRun(run),
        getAiInsightsForRunContext(run, runs),
      ]);

      if (useAegisStore.getState().selectedRunId !== runId) {
        return;
      }

      setSelectedRun(run);
      setTasks(tasksResult.status === 'fulfilled' ? tasksResult.value : run.tasks ?? []);
      if (findingsResult.status === 'fulfilled') {
        setFindings(findingsResult.value);
      }
      if (inventoryResult.status === 'fulfilled') {
        setInventory(inventoryResult.value);
      }
      if (insightsResult.status === 'fulfilled') {
        setAiInsights(insightsResult.value);
      }
      if (!options.quiet) {
        setActionMessage('Run data refreshed from backend.');
      }
    } catch (error) {
      if (useAegisStore.getState().selectedRunId !== runId) {
        return;
      }
      if (error instanceof ApiError && error.status === 404) {
        const fallbackRun = fallbackRunForMissingRun(runs, useAegisStore.getState().selectedRun, runId);
        setSelectedRun(fallbackRun);
        setTasks(fallbackRun?.tasks ?? []);
        setError(null);
      } else {
        setError(errorMessage(error));
      }
      if (!options.quiet) {
        setActionMessage('Refresh failed.');
      }
    } finally {
      refreshInFlightRef.current = false;
      setLoading('missionControl', false);
      if (!options.quiet) {
        setBusyAction(null);
      }
    }
  }, [
    selectedRunId,
    runs,
    setAiInsights,
    setError,
    setFindings,
    setInventory,
    setLoading,
    setSelectedRun,
    setTasks,
  ]);

  useEffect(() => {
    if (!selectedRunId) return;
    void refreshRun(selectedRunId, { quiet: true });
  }, [refreshRun, selectedRunId]);

  useEffect(() => {
    if (!selectedRunId || !isPolling) return;
    const timer = window.setInterval(() => {
      void refreshRun(selectedRunId, { quiet: true });
    }, POLL_MS);
    return () => window.clearInterval(timer);
  }, [isPolling, refreshRun, selectedRunId]);

  // Fetch briefing when run completes and has findings
  useEffect(() => {
    if (!selectedRunId || !selectedRun) return;
    const isComplete = TERMINAL_STATUSES.has(runStatus(selectedRun));
    if (!isComplete || briefing || findings.length === 0) return;
    fetch(`/api/v1/runs/${selectedRunId}/briefing`)
      .then((r) => r.json())
      .then((d: Record<string, unknown>) => {
        if (typeof d.briefing === 'string' && d.briefing) setBriefing(d.briefing);
      })
      .catch(() => undefined);
  }, [selectedRunId, selectedRun, briefing, findings.length]);

  useEffect(() => {
    if (!consoleTask) return;
    const taskId = consoleTask.id;
    const shouldPollDetail = selectedRun ? !TERMINAL_STATUSES.has(runStatus(selectedRun)) || !TERMINAL_STATUSES.has(taskStatus(consoleTask)) : false;
    let cancelled = false;
    async function loadTaskDetail() {
      try {
        const detail = await getTaskDetail(taskId);
        if (!cancelled) {
          setTaskDetails((current) => ({ ...current, [taskId]: detail }));
        }
      } catch (error) {
        if (!cancelled) {
          setError(errorMessage(error));
        }
      }
    }
    void loadTaskDetail();
    const timer = shouldPollDetail ? window.setInterval(() => void loadTaskDetail(), POLL_MS) : null;
    return () => {
      cancelled = true;
      if (timer) window.clearInterval(timer);
    };
  }, [consoleTask, selectedRun, setError]);

  async function handleCancel() {
    if (!selectedRun) return;
    setBusyAction('cancel');
    setActionMessage(null);
    try {
      const run = await cancelRun(selectedRun.id);
      setSelectedRun(run);
      setTasks(run.tasks ?? []);
      setActionMessage('Kill switch accepted for this run.');
    } catch (error) {
      setError(errorMessage(error));
      setActionMessage('Kill Run failed.');
    } finally {
      setBusyAction(null);
    }
  }

  async function handleDispatch() {
    if (!selectedRun) return;
    setBusyAction('dispatch');
    setActionMessage(null);
    try {
      const payload = await dispatchRun(selectedRun.id);
      setSelectedRun(payload.run);
      setTasks(payload.run.tasks ?? []);
      setActionMessage(
        payload.dispatch_mode === 'manual'
          ? 'Dispatch accepted, but backend is in manual dispatch mode; no runner was started.'
          : `Dispatch accepted: ${payload.dispatched_task_ids.length} queued check(s) via ${payload.dispatch_mode}.`,
      );
    } catch (error) {
      setError(errorMessage(error));
      setActionMessage('Start Queued Checks failed.');
    } finally {
      setBusyAction(null);
    }
  }

  async function handleProposalReview(proposal: AgentProposal, decision: 'approved' | 'rejected') {
    if (!selectedRun) return;
    const busyKey = `proposal-${proposal.id}` as const;
    setBusyAction(busyKey);
    setActionMessage(null);
    try {
      await reviewAgentProposal(proposal.run_id || selectedRun.id, proposal.id, {
        decision,
        note: decision === 'approved' ? 'Approved from v2 Mission Control.' : 'Rejected from v2 Mission Control.',
      });
      await refreshRun(selectedRun.id, { quiet: true });
      setActionMessage(decision === 'approved' ? 'AI proposal approved.' : 'AI proposal rejected.');
    } catch (error) {
      setError(errorMessage(error));
      setActionMessage('AI proposal review failed.');
    } finally {
      setBusyAction(null);
    }
  }



  async function handleApprovePhase() {
    const id = chainId(chain);
    if (!id || !currentPhase) return;
    setBusyAction('phase');
    setActionMessage(null);
    try {
      await decideAssessmentChainPhase(id, currentPhase.key, 'approved');
      await refreshRun(selectedRunId, { quiet: true });
      setActionMessage('Assessment phase approved.');
    } catch (error) {
      setError(errorMessage(error));
      setActionMessage('Phase approval failed.');
    } finally {
      setBusyAction(null);
    }
  }

  if (!selectedRun) {
    return (
      <section className="max-w-4xl">
        <div className="glass-panel rounded-lg p-6">
          <div className="flex items-start gap-4">
            <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-md border border-cyan/30 bg-cyan/10 text-cyan">
              <Activity size={18} />
            </div>
            <div className="min-w-0">
              <h1 className="text-2xl font-semibold">Mission Control</h1>
              <p className="mt-2 max-w-2xl text-[1rem] leading-6 text-muted">
                {loading.runs
                  ? 'Loading runs from the selected engagement.'
                  : 'No run is selected. Create or select a mission to view live operations.'}
              </p>
              <Link
                to="/intake"
                className="mt-5 inline-flex items-center gap-2 rounded-md border border-cyan/30 bg-cyan/10 px-4 py-2 text-[1rem] font-semibold text-cyan transition-colors hover:bg-cyan/15"
              >
                <Play size={15} />
                Start Mission Intake
              </Link>
            </div>
          </div>
        </div>
      </section>
    );
  }

  return (
    <section className="flex h-full flex-col min-h-0">
      <MissionControlV3
        run={selectedRun}
        tasks={tasks}
        findings={findings}
        proposals={proposals}
        onKill={() => void handleCancel()}
        onCinema={() => setCinemaOpen(true)}
        canKill={canCancel && busyAction === null}
        cinemaDisabled={busyAction !== null}
      />
      {cinemaOpen && <CinemaMode onClose={() => setCinemaOpen(false)} />}
    </section>
  );
}


function readIntakeLaunchState(state: unknown): IntakeLaunchState | null {
  if (!isJsonMap(state)) return null;
  const value = state.intakeLaunch;
  if (!isJsonMap(value)) return null;
  const runId = value.runId;
  if (typeof runId !== 'string' || !runId.trim()) return null;
  return {
    runId,
    target: typeof value.target === 'string' ? value.target : null,
    assessmentType: typeof value.assessmentType === 'string' ? value.assessmentType : null,
    depth: typeof value.depth === 'string' ? value.depth : null,
  };
}

function LiveCommandConsole({
  run,
  task,
  detail,
}: {
  run: Run;
  task: Task | null;
  detail: TaskDetail | undefined;
}) {
  if (!task) {
    return (
      <section className="rounded-lg border border-border bg-[#02060c]/90 p-4 shadow-[0_0_30px_rgba(94,207,255,0.08)]">
        <div className="flex items-center gap-2 text-[1rem] font-semibold text-cyan">
          <TerminalSquare size={16} />
          Live Command Console
        </div>
        <pre className="mt-4 min-h-[10rem] overflow-auto rounded-md border border-border bg-black/70 p-4 font-mono text-[0.9rem] leading-6 text-[#c8d6e5]">
{`aegispt> no backend task is selected
status > ${statusLabel(runStatus(run))}
hint   > create or dispatch a mission to see command input and stdout here`}
        </pre>
      </section>
    );
  }

  const displayStatus = taskDisplayStatus(task, run);
  const execution = latestExecution(detail);
  const output = detail ? boundedOutput(detail) : pendingOutputForTask(task, run);
  const command = commandPreview(task);
  const displayStatusLower = displayStatus.toLowerCase();
  const live = RUNNING_STATUSES.has(taskStatus(task)) && !isRunTerminal(run);

  return (
    <section className="flex flex-1 flex-col rounded-lg border border-cyan/25 bg-[#02060c]/95 p-4 shadow-[0_0_34px_rgba(94,207,255,0.12)]">
      <div className="mb-3 flex flex-wrap items-center justify-between gap-3 shrink-0">
        <div>
          <h2 className="flex items-center gap-2 text-[1rem] font-semibold text-cyan">
            <TerminalSquare size={16} />
            Live Command Console
          </h2>
          <p className="mt-1 text-[0.875rem] text-muted">
            Single source for selected task command, sanitized input, stdout, stderr, and exit code.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {live && <span className="h-2 w-2 rounded-full bg-cyan shadow-[0_0_12px_rgba(94,207,255,0.9)] animate-pulse" />}
          <span className={cn('rounded-full px-2.5 py-1 text-[0.77rem] font-bold uppercase', statusTone(displayStatus))}>
            {statusLabel(displayStatus)}
          </span>
          <span className="rounded-full border border-border bg-bg/60 px-2.5 py-1 font-mono text-[0.77rem] uppercase text-muted">
            {compactId(task.id)}
          </span>
        </div>
      </div>

      <div className="flex min-h-0 flex-1 flex-col gap-3">
        <div className="min-w-0 shrink-0 rounded-md border border-border bg-black/60 p-3">
          <p className="text-[0.75rem] font-bold uppercase tracking-widest text-cyan/75">Command</p>
          <pre className="mt-2 overflow-auto whitespace-pre-wrap break-words font-mono text-[0.88rem] leading-5 text-[#d8f3ff]">
            {command}
          </pre>
          <div className="mt-3 grid grid-cols-2 gap-2 text-[0.85rem] text-muted">
            <KeyValue label="Tool" value={task.tool} />
            <KeyValue label="Exit code" value={execution?.exit_code === null || execution?.exit_code === undefined ? 'pending' : String(execution.exit_code)} />
          </div>
        </div>

        <div className="flex min-h-0 flex-1 flex-col rounded-md border border-border bg-black/70 p-3">
          <div className="mb-2 flex shrink-0 flex-wrap items-center justify-between gap-2">
            <p className="text-[0.75rem] font-bold uppercase tracking-widest text-cyan/75">
              {displayStatusLower === 'failed' ? 'Stdout / Stderr' : 'Stdout'}
            </p>
            <span className="font-mono text-[0.75rem] text-muted">
              {detail?.stdout_snapshot?.source || 'task-detail'} {detail?.stdout_snapshot?.stream_terminal === false ? '// streaming' : '// snapshot'}
            </span>
          </div>
          <pre className="min-h-0 flex-1 overflow-auto whitespace-pre-wrap break-words rounded border border-border bg-[#010409] p-4 font-mono text-[0.9rem] leading-6 text-[#c8d6e5]">
            {output}
          </pre>
        </div>
      </div>
    </section>
  );
}

// ─────────────────────────────────────────────
// Findings summary card: severity badges + top findings
// ─────────────────────────────────────────────
// ─────────────────────────────────────────────
// Status banner: big one-line summary + severity row
// ─────────────────────────────────────────────
function MissionStatusBanner({ run, tasks, findings, proposals }: { run: Run; tasks: Task[]; findings: Finding[]; proposals: AgentProposal[] }) {
  const sev = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) { const s = (f.severity ?? 'info').toLowerCase() as keyof typeof sev; if (s in sev) sev[s]++; }
  const running = tasks.find((t) => ['running', 'dispatching', 'in_progress'].includes(t.status));
  const queued = tasks.filter((t) => ['queued', 'pending'].includes(t.status));
  const done = tasks.filter((t) => t.status === 'completed').length;
  const loop = run.configuration_json?.ai_assessment_loop as Record<string, unknown> | undefined;
  const iters = loop?.iteration_count ? Number(loop.iteration_count) : 0;
  const stopReason = loop?.stop_reason ? String(loop.stop_reason) : null;
  const isAiLoop = run.configuration_json?.run_mode === 'ai_loop' || loop?.run_mode === 'ai_loop';
  const pending = proposals.filter((p) => p.status === 'pending').length;

  let bannerText = '';
  let bannerColor = 'border-cyan/20 bg-cyan/5 text-cyan';
  if (stopReason === 'stuck_no_new_signals') {
    bannerColor = 'border-amber/20 bg-amber/5 text-amber';
    bannerText = `AI-scan gestopt na ${iters} iteraties: geen nieuwe signalen meer. ${findings.length} bevindingen opgeslagen.`;
  } else if (stopReason) {
    bannerColor = 'border-muted/20 bg-surface/40 text-muted';
    bannerText = `Scan gestopt (${stopReason.replace(/_/g, ' ')}). ${done} tools uitgevoerd.`;
  } else if (running) {
    bannerColor = 'border-cyan/20 bg-cyan/5 text-cyan';
    bannerText = `🔍 ${running.tool} is nu aan het scannen…`;
  } else if (pending > 0) {
    bannerColor = 'border-amber/20 bg-amber/5 text-amber';
    bannerText = `${pending} actie${pending > 1 ? 's' : ''} wacht${pending > 1 ? 'en' : ''} op jouw goedkeuring.`;
  } else if (queued.length > 0) {
    bannerColor = 'border-cyan/20 bg-cyan/5 text-cyan';
    bannerText = isAiLoop
      ? `${queued.length} tool${queued.length > 1 ? 's' : ''} in de wachtrij — AI loop dispatcht binnen enkele seconden automatisch…`
      : `${queued.length} tool${queued.length > 1 ? 's' : ''} staat in de wachtrij. Klik 'Start wachtrij' om door te gaan.`;
  } else if (done > 0) {
    bannerColor = 'border-emerald-400/20 bg-emerald-400/5 text-emerald-300';
    bannerText = `✓ ${done} tools uitgevoerd${iters > 0 ? ` in ${iters} iteraties` : ''}. ${findings.length} bevindingen gevonden.`;
  }

  const sevRow = (
    <div className="flex flex-wrap gap-2 mt-2">
      {[
        { key: 'critical', label: 'Kritiek', cls: 'bg-red/15 text-red border-red/25' },
        { key: 'high', label: 'Hoog', cls: 'bg-orange-500/15 text-orange-400 border-orange-500/25' },
        { key: 'medium', label: 'Gemiddeld', cls: 'bg-yellow-400/15 text-yellow-300 border-yellow-400/25' },
        { key: 'low', label: 'Laag', cls: 'bg-blue-500/15 text-blue-300 border-blue-500/25' },
        { key: 'info', label: 'Info', cls: 'bg-surface/60 text-muted border-border' },
      ].filter(({ key }) => sev[key as keyof typeof sev] > 0).map(({ key, label, cls }) => (
        <span key={key} className={cn('inline-flex items-center gap-1.5 rounded-full border px-3 py-0.5 text-[0.8rem] font-bold', cls)}>
          {sev[key as keyof typeof sev]} {label}
        </span>
      ))}
      {findings.length === 0 && <span className="text-[0.82rem] text-muted">Nog geen bevindingen</span>}
    </div>
  );

  return (
    <div className={cn('shrink-0 rounded-lg border px-4 py-3', bannerColor.split(' ')[0], bannerColor.split(' ')[1])}>
      <p className={cn('text-[0.9rem] font-semibold', bannerColor.split(' ')[2])}>{bannerText || 'Gereed.'}</p>
      {sevRow}
    </div>
  );
}

// ─────────────────────────────────────────────
// Activity feed: each tool + what it did in plain Dutch
// ─────────────────────────────────────────────
function ActivityFeed({ run: _run, tasks, findings, selectedTaskId, onSelect }: {
  run: Run; tasks: Task[]; findings: Finding[];
  selectedTaskId: UUID | null; onSelect: (id: UUID) => void;
}) {
  const ordered = [...tasks].sort((a, b) => (a.created_at ?? '') < (b.created_at ?? '') ? -1 : 1);
  const [openId, setOpenId] = useState<string | null>(null);
  const [showEmpty, setShowEmpty] = useState(false);

  const findingsForTool = (tool: string) =>
    findings.filter((f) => f.methodology_tags?.some((t: string) => t === tool) || (f as unknown as Record<string, unknown>).tool === tool).length;

  const statusBadge = (status: string) => {
    if (['running', 'dispatching', 'in_progress'].includes(status))
      return <span className="inline-flex items-center gap-1 rounded-full bg-cyan/15 px-2 py-0.5 text-[0.72rem] font-bold text-cyan"><span className="h-1.5 w-1.5 rounded-full bg-cyan animate-pulse" />Loopt</span>;
    if (status === 'completed')
      return <span className="rounded-full bg-emerald-400/15 px-2 py-0.5 text-[0.72rem] font-bold text-emerald-400">Klaar</span>;
    if (status === 'failed')
      return <span className="rounded-full bg-red/15 px-2 py-0.5 text-[0.72rem] font-bold text-red">Fout</span>;
    if (status === 'completed_with_errors')
      return <span className="rounded-full bg-amber/15 px-2 py-0.5 text-[0.72rem] font-bold text-amber">Overgeslagen</span>;
    return <span className="rounded-full bg-surface/60 px-2 py-0.5 text-[0.72rem] text-muted">Wacht</span>;
  };

  // Split: tasks with findings or active/failed always shown; empty completed tasks hidden
  const withFindings = ordered.filter((t) => {
    const count = findingsForTool(t.tool ?? '');
    return count > 0 || ['running', 'dispatching', 'in_progress', 'failed', 'completed_with_errors'].includes(t.status ?? '');
  });
  const withoutFindings = ordered.filter((t) => {
    const count = findingsForTool(t.tool ?? '');
    return count === 0 && !['running', 'dispatching', 'in_progress', 'failed', 'completed_with_errors'].includes(t.status ?? '');
  });

  const renderTask = (task: Task) => {
    const info = TOOL_INFO[task.tool ?? ''];
    const count = findingsForTool(task.tool ?? '');
    const isOpen = openId === task.id;
    const isSelected = selectedTaskId === task.id;
    return (
      <div key={task.id} className={cn('rounded-lg border transition-colors', isSelected ? 'border-cyan/30 bg-cyan/5' : 'border-border bg-surface/25 hover:bg-surface/40')}>
        <button type="button" className="flex w-full items-center gap-3 px-3 py-2.5 text-left"
          onClick={() => { onSelect(task.id); setOpenId(isOpen ? null : task.id); }}>
          <span className="shrink-0">{statusBadge(task.status ?? '')}</span>
          <span className="flex-1 font-mono text-[0.88rem] font-semibold text-text">{task.tool}</span>
          {count > 0 && (
            <span className="shrink-0 rounded-full border border-amber/30 bg-amber/10 px-2 py-0.5 text-[0.72rem] font-bold text-amber">
              {count} gevonden
            </span>
          )}
          <ChevronRight size={12} className={cn('shrink-0 text-muted/50 transition-transform', isOpen && 'rotate-90')} />
        </button>
        {isOpen && (
          <div className="border-t border-border/60 px-3 py-2.5 space-y-2">
            {info ? (
              <>
                <p className="text-[0.82rem] text-text"><span className="font-semibold text-cyan/80">Doel:</span> {info.why}</p>
                <p className="text-[0.82rem] text-muted"><span className="font-semibold">Methode:</span> {info.what}</p>
                <p className="text-[0.82rem] text-muted"><span className="font-semibold">Risico bij vondst:</span> {info.impact}</p>
              </>
            ) : (
              <p className="text-[0.78rem] text-muted truncate">{task.target_id}</p>
            )}
          </div>
        )}
      </div>
    );
  };

  return (
    <div className="glass-panel flex flex-col rounded-lg p-4 min-h-0">
      <h2 className="mb-3 shrink-0 flex items-center gap-2 text-[1rem] font-semibold text-cyan">
        <Activity size={15} /> Activiteiten
        <span className="ml-auto text-[0.8rem] text-muted font-normal">{ordered.length} tools</span>
      </h2>
      <div className="flex-1 min-h-0 overflow-y-auto space-y-2 pr-1">
        {withFindings.length === 0 && ordered.length === 0 && (
          <p className="py-6 text-center text-[0.88rem] text-muted">Nog geen activiteit.</p>
        )}
        {withFindings.map(renderTask)}
        {withoutFindings.length > 0 && (
          <button type="button"
            className="flex w-full items-center gap-2 rounded-lg border border-border/50 px-3 py-2 text-[0.8rem] text-muted hover:text-text hover:bg-surface/30 transition-colors"
            onClick={() => setShowEmpty((s) => !s)}>
            <ChevronRight size={12} className={cn('transition-transform', showEmpty && 'rotate-90')} />
            {showEmpty ? 'Verberg' : 'Toon'} {withoutFindings.length} tool{withoutFindings.length !== 1 ? 's' : ''} zonder vondsten
          </button>
        )}
        {showEmpty && withoutFindings.map(renderTask)}
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────
// Findings explained: each unique finding with plain Dutch explanation
// ─────────────────────────────────────────────
const FINDING_EXPLANATIONS: Record<string, { short: string; impact: string; action: string }> = {
  'reflected xss': {
    short: 'Een aanvaller kan code in een URL stoppen die wordt uitgevoerd als iemand erop klikt.',
    impact: 'Sessiecookies kunnen worden gestolen waarmee een aanvaller inlogt als de slachtoffer.',
    action: 'Zorg dat alle URL-parameters worden gesanitiseerd voordat ze op de pagina worden getoond.',
  },
  'stored xss': {
    short: 'Kwaadaardige code is opgeslagen en wordt bij iedere bezoeker uitgevoerd.',
    impact: 'Alle bezoekers van de pagina zijn potentieel slachtoffer — niet alleen degene die de link aanklikt.',
    action: 'Sanitiseer alle gebruikersinvoer bij opslag en bij weergave.',
  },
  'csrf': {
    short: 'Formulieren hebben geen bescherming tegen ongewenste acties van andere websites.',
    impact: 'Een aanvaller kan een ingelogde gebruiker ongemerkt acties laten uitvoeren (bijv. gegevens wijzigen).',
    action: 'Voeg een CSRF-token toe aan alle formulieren die gegevens wijzigen.',
  },
  'csp': {
    short: 'De website heeft geen beleid ingesteld dat scripts van onbekende bronnen blokkeert.',
    impact: 'Dit maakt het eenvoudiger voor aanvallers om via XSS kwaadaardige scripts te laden.',
    action: 'Stel een Content-Security-Policy header in die alleen vertrouwde bronnen toestaat.',
  },
  'hsts': {
    short: 'De website dwingt geen HTTPS-verbinding af.',
    impact: 'Op onveilige netwerken kan communicatie worden onderschept (man-in-the-middle).',
    action: 'Voeg de Strict-Transport-Security header toe met een lange max-age.',
  },
  'clickjacking': {
    short: 'De website kan verborgen in een frame worden geladen op een andere site.',
    impact: 'Bezoekers kunnen ongemerkt klikken op knoppen van jouw site die verborgen zijn.',
    action: 'Voeg X-Frame-Options: DENY of een frame-ancestors CSP-richtlijn toe.',
  },
  'cookie': {
    short: 'Sessiecookies zijn niet volledig beveiligd.',
    impact: 'Cookies kunnen worden gestolen via XSS (ontbrekend HttpOnly) of via onveilige verbindingen (ontbrekend Secure).',
    action: 'Zet de HttpOnly, Secure en SameSite-attributen op alle sessiecookies.',
  },
  'hidden endpoint': {
    short: 'Er zijn pagina\'s gevonden die niet via de normale navigatie bereikbaar zijn.',
    impact: 'Verborgen beheer- of testpagina\'s kunnen toegankelijk zijn zonder authenticatie.',
    action: 'Verwijder niet-gebruikte endpoints of beveilig ze met authenticatie.',
  },
  'sql injection': {
    short: 'Invoervelden geven direct door aan de database zonder filtering.',
    impact: 'Een aanvaller kan data lezen, wijzigen of verwijderen — inclusief gebruikerswachtwoorden.',
    action: 'Gebruik parameterized queries of een ORM in plaats van string-concatenatie.',
  },
  'path traversal': {
    short: 'De server geeft bestanden terug buiten de bedoelde map.',
    impact: 'Aanvallers kunnen configuratiebestanden of private sleutels lezen.',
    action: 'Valideer bestandspaden en beperk toegang tot een specifieke map.',
  },
};

function findingExplanation(title: string): { short: string; impact: string; action: string } | null {
  const lower = title.toLowerCase();
  for (const [key, val] of Object.entries(FINDING_EXPLANATIONS)) {
    if (lower.includes(key)) return val;
  }
  return null;
}

type SevGroup = { finding: Finding; count: number }[];

function dedupeFindings(findings: Finding[], sev: string): SevGroup {
  const group = findings.filter((f) => (f.severity ?? 'info').toLowerCase() === sev);
  const seen = new Map<string, { finding: Finding; count: number }>();
  for (const f of group) {
    const t = f.title ?? 'Onbekend';
    const existing = seen.get(t);
    if (existing) existing.count++;
    else seen.set(t, { finding: f, count: 1 });
  }
  return Array.from(seen.values());
}

function FindingsExplained({ findings }: { findings: Finding[] }) {
  const [openSev, setOpenSev] = useState<Record<string, boolean>>({ critical: true, high: true, medium: false, low: false, info: false });
  const [openFinding, setOpenFinding] = useState<string | null>(null);

  const sevConfig = [
    { key: 'critical', label: 'Kritiek',    hdr: 'bg-red/10 border-red/30',               txt: 'text-red',          row: 'bg-red/4' },
    { key: 'high',     label: 'Hoog',       hdr: 'bg-orange-500/10 border-orange-500/25', txt: 'text-orange-400',   row: 'bg-orange-500/4' },
    { key: 'medium',   label: 'Gemiddeld',  hdr: 'bg-yellow-400/8 border-yellow-400/20',  txt: 'text-yellow-300',   row: 'bg-yellow-400/3' },
    { key: 'low',      label: 'Laag',       hdr: 'bg-blue-500/8 border-blue-500/20',      txt: 'text-blue-300',     row: 'bg-blue-500/3' },
    { key: 'info',     label: 'Info',       hdr: 'bg-surface/40 border-border',           txt: 'text-muted',        row: 'bg-surface/20' },
  ];

  return (
    <div className="glass-panel flex flex-col rounded-lg p-4 min-h-0">
      <h2 className="mb-3 shrink-0 flex items-center gap-2 text-[1rem] font-semibold text-cyan">
        <AlertTriangle size={15} /> Bevindingen ({findings.length})
      </h2>
      <div className="flex-1 min-h-0 overflow-y-auto space-y-2 pr-1">
        {sevConfig.map(({ key, label, hdr, txt, row }) => {
          const items = dedupeFindings(findings, key);
          if (items.length === 0) return null;
          const total = items.reduce((s, i) => s + i.count, 0);
          const isOpen = Boolean(openSev[key]);
          return (
            <div key={key} className="rounded-lg border border-border overflow-hidden">
              <button type="button"
                className={cn('flex w-full items-center gap-3 px-3 py-2.5 text-left', hdr)}
                onClick={() => setOpenSev((s) => ({ ...s, [key]: !s[key] }))}>
                <span className={cn('text-[0.77rem] font-bold uppercase', txt)}>{label}</span>
                <span className="text-[0.77rem] text-muted/70">{items.length} uniek · {total} totaal</span>
                <ChevronRight size={13} className={cn('ml-auto text-muted/50 transition-transform', isOpen && 'rotate-90')} />
              </button>
              {isOpen && (
                <div className="divide-y divide-border/40">
                  {items.map(({ finding, count }) => {
                    const expl = findingExplanation(finding.title ?? '');
                    const isExpanded = openFinding === finding.id;
                    return (
                      <div key={finding.id} className={row}>
                        <button type="button" className="flex w-full items-center gap-2 px-3 py-2 text-left"
                          onClick={() => setOpenFinding(isExpanded ? null : finding.id)}>
                          <span className="flex-1 text-[0.83rem] text-text leading-5">{finding.title}</span>
                          {count > 1 && <span className="shrink-0 text-[0.72rem] text-muted">×{count}</span>}
                          <ChevronRight size={11} className={cn('shrink-0 text-muted/40 transition-transform', isExpanded && 'rotate-90')} />
                        </button>
                        {isExpanded && (
                          <div className="px-3 pb-3 border-t border-border/30 space-y-1.5">
                            {expl ? (
                              <>
                                <p className="pt-2 text-[0.8rem] text-text/85">{expl.short}</p>
                                <p className="text-[0.76rem] text-muted"><span className="font-semibold text-amber/75">Risico:</span> {expl.impact}</p>
                                <p className="text-[0.76rem] text-muted"><span className="font-semibold text-emerald-400/75">Oplossing:</span> {expl.action}</p>
                              </>
                            ) : (
                              <p className="pt-2 text-[0.76rem] text-muted truncate">{finding.target_id}</p>
                            )}
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          );
        })}
        {findings.length === 0 && <p className="py-6 text-center text-[0.88rem] text-muted">Nog geen bevindingen.</p>}
      </div>
    </div>
  );
}


// ─────────────────────────────────────────────
// Task results panel: each tool with status + finding count + Dutch explanation
// ─────────────────────────────────────────────
const TOOL_INFO: Record<string, { why: string; what: string; impact: string }> = {
  httpx: {
    why: 'Eerste verkenning van het systeem.',
    what: 'Haalt de pagina op, leest headers, links en formulieren.',
    impact: 'Geeft een overzicht van het aanvalsoppervlak.',
  },
  'xss-extended': {
    why: 'Testen of gebruikersinvoer als code uitgevoerd kan worden.',
    what: 'Injecteert testpayloads in URL-parameters en formulieren.',
    impact: 'XSS kan sessies stelen of gebruikers misleiden.',
  },
  zap: {
    why: 'Actieve scan op bekende kwetsbaarheden.',
    what: 'Test alle pagina\'s op injection, headers en sessiefouten.',
    impact: 'Vindt CSRF, clickjacking, missing security headers en meer.',
  },
  nikto: {
    why: 'Controle op bekende webserver-kwetsbaarheden.',
    what: 'Vergelijkt de server met een database van bekende problemen.',
    impact: 'Vindt verouderde software, verkeerde configuraties.',
  },
  'session-security': {
    why: 'Controleren of sessies veilig beheerd worden.',
    what: 'Analyseert cookies, tokens en authenticatiegedrag.',
    impact: 'Sessiediefstal kan leiden tot accountovername.',
  },
  'content-discovery': {
    why: 'Zoeken naar verborgen pagina\'s en endpoints.',
    what: 'Probeert bekende padnamen op de server.',
    impact: 'Verborgen beheerinterfaces of backup-bestanden.',
  },
  'headers-security': {
    why: 'Controleren of beveiligingsheaders aanwezig zijn.',
    what: 'Leest alle HTTP-responsheaders en vergelijkt met best practices.',
    impact: 'Ontbrekende headers maken XSS en clickjacking eenvoudiger.',
  },
  'logging-probe': {
    why: 'Testen of fouten onbedoeld informatie lekken.',
    what: 'Stuurt foute verzoeken en kijkt wat de server teruggeeft.',
    impact: 'Stack traces en paden helpen aanvallers.',
  },
  'crypto-audit': {
    why: 'Beoordelen van de TLS/SSL-configuratie.',
    what: 'Controleert certificaat, cipher suites en protocol.',
    impact: 'Zwakke TLS maakt man-in-the-middle aanvallen mogelijk.',
  },
  'ssrf-probe': {
    why: 'Testen of de server interne diensten kan benaderen.',
    what: 'Stuurt verzoeken naar interne adressen via het systeem.',
    impact: 'SSRF geeft toegang tot cloud metadata of interne API\'s.',
  },
  'ssti-probe': {
    why: 'Testen op server-side template injectie.',
    what: 'Injecteert template-expressies en kijkt of die worden uitgevoerd.',
    impact: 'SSTI kan leiden tot volledige code-executie.',
  },
  'auth-flow': {
    why: 'Analyseren van het inlogsysteem.',
    what: 'Test authenticatiegedrag, wachtwoordbeleid en sessieafhandeling.',
    impact: 'Zwakke auth leidt tot accountovername.',
  },
  'client-state': {
    why: 'Testen op client-side privileges manipulatie.',
    what: 'Past cookies en lokale opslag aan en kijkt of de server dat accepteert.',
    impact: 'Privilege escalatie zonder server-side check.',
  },
  'idor-bac': {
    why: 'Testen of je objecten van andere gebruikers kunt benaderen.',
    what: 'Past ID\'s aan in verzoeken en kijkt of de server reageert.',
    impact: 'IDOR/BAC lekt data van andere gebruikers.',
  },
  'http-smuggling': {
    why: 'Testen op HTTP request smuggling.',
    what: 'Stuurt ambigue HTTP-verzoeken die tussenliggende proxies verwarren.',
    impact: 'Kan sessies kapen of beveiligingscontroles omzeilen.',
  },
};



function AiLoopPanel({
  run,
  proposals,
  tasks,
}: {
  run: Run;
  proposals: AgentProposal[];
  tasks: Task[];
}) {
  const loop = run.configuration_json?.ai_assessment_loop as Record<string, unknown> | undefined;
  const stepCount = Number(loop?.iteration_count ?? 0);
  const depthLevel = Number(loop?.depth_level ?? 1);
  const depthLabel = String(loop?.depth_label ?? 'Verkenning');
  const loopStatus = String(loop?.status ?? 'ready');
  const stopReason = loop?.stop_reason ? String(loop.stop_reason) : null;
  const iterations = Array.isArray(loop?.iterations) ? (loop.iterations as Record<string, unknown>[]) : [];

  const isRunning = loopStatus === 'running' || loopStatus === 'waiting_for_execution';
  const isStopped = loopStatus === 'stopped' || Boolean(stopReason);

  // Latest iteration for hypothesis
  const latestIter = iterations[iterations.length - 1] as Record<string, unknown> | undefined;
  const latestAction = latestIter?.next_action as Record<string, unknown> | undefined;
  const latestParams = (latestAction?.params ?? {}) as Record<string, unknown>;
  const nba = (latestParams.next_best_action_selector ?? {}) as Record<string, unknown>;
  const triggers = Array.isArray(nba.matched_triggers) ? (nba.matched_triggers as string[]) : [];
  const hypothesis = String(latestAction?.reasoning ?? '');
  // Pending proposals = next up
  const pendingProps = proposals
    .filter((p) => p.status === 'pending_review' || p.status === 'approved')
    .slice(0, 3);

  // Build reasoning chain: last 5 iterations → what tool and why
  const recentIters = [...iterations].slice(-5).reverse();

  const statusDot = isStopped ? 'bg-amber' : isRunning ? 'bg-ok' : 'bg-line';

  // Live "Claude is thinking" indicator — written by assessment_loop._claude_select_next_action
  // between hops of the tool-use loop, so the UI can show what Claude is doing during the
  // 30-60s pauses where no task has been queued yet.
  const claudeThinking = loop?.claude_thinking as Record<string, unknown> | undefined;
  const thinkingStatus = String(claudeThinking?.status ?? '');
  const thinkingDetail = String(claudeThinking?.detail ?? '');
  const thinkingHop = Number(claudeThinking?.hop ?? 0);
  const thinkingActive = isRunning && (thinkingStatus === 'thinking' || thinkingStatus === 'tool_use');

  return (
    <div className="op-card p-0 flex flex-col">
      {/* Header */}
      <div className="flex items-center justify-between gap-3 px-3 py-2 border-b border-line-soft">
        <div className="flex items-center gap-2">
          <BrainCircuit size={13} className="text-ai" />
          <span className="font-mono text-[0.7rem] font-semibold uppercase tracking-widest text-ai/80">
            AI · ADAPTIVE PENTEST
          </span>
        </div>
        <div className="flex items-center gap-2">
          <div className={cn('h-1.5 w-1.5 rounded-full', statusDot, isRunning && 'animate-pulse')} />
          <span className="font-mono text-[0.68rem] text-muted uppercase">
            {isStopped ? (stopReason?.replace(/_/g, ' ') ?? 'stopped') : loopStatus.replace(/_/g, ' ')}
          </span>
        </div>
      </div>

      {/* Claude thinking indicator — shows during the multi-second tool-use loop */}
      {thinkingActive && (
        <div className="flex items-center gap-2 px-3 py-1.5 border-b border-line-soft bg-ai/5">
          <span className="text-base animate-pulse">🧠</span>
          <span className="font-mono text-[0.7rem] text-ai/90">
            Claude denkt
            {thinkingStatus === 'tool_use' ? ' · gebruikt tools' : ''}
            {thinkingHop > 0 ? ` · hop ${thinkingHop + 1}/12` : ''}
          </span>
          {thinkingDetail && (
            <span className="ml-auto font-mono text-[0.65rem] text-muted truncate max-w-[60%]">
              {thinkingDetail}
            </span>
          )}
        </div>
      )}

      {/* KPIs — tight row */}
      <div className="grid grid-cols-3 divide-x divide-line-soft border-b border-line-soft">
        {[
          { label: depthLabel, value: String(depthLevel), accent: true },
          { label: 'Stappen', value: String(stepCount), accent: false },
          { label: 'Tools', value: String(tasks.length), accent: false },
        ].map(({ label, value, accent }) => (
          <div key={label} className="px-3 py-2 text-center">
            <div className={cn('text-[1rem] font-bold tabular', accent ? 'text-ai' : 'text-text')}>{value}</div>
            <div className="text-[0.65rem] text-muted truncate">{label}</div>
          </div>
        ))}
      </div>

      {/* Hypothesis — what is the AI doing now */}
      {hypothesis && (
        <div className="px-3 py-2 border-b border-line-soft">
          <div className="mb-0.5 font-mono text-[0.62rem] uppercase tracking-widest text-muted">HYPOTHESIS</div>
          <p className="text-[0.8rem] leading-relaxed text-soft line-clamp-3">{hypothesis}</p>
          {triggers.length > 0 && (
            <div className="mt-1 flex flex-wrap gap-1">
              {triggers.slice(0, 3).map((t) => (
                <span key={t} className="font-mono text-[0.62rem] px-1.5 py-0.5 rounded bg-ai/10 text-ai border border-ai/20">{t}</span>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Reasoning chain */}
      {recentIters.length > 0 && (
        <div className="flex-1 overflow-y-auto px-3 py-2 border-b border-line-soft min-h-0 max-h-[140px]">
          <div className="mb-1 font-mono text-[0.62rem] uppercase tracking-widest text-muted">REASONING CHAIN</div>
          <div className="space-y-0.5">
            {recentIters.map((it, idx) => {
              const na = it.next_action as Record<string, unknown> | undefined;
              const tool = String(na?.tool ?? '?');
              const src = String((na?.params as Record<string, unknown>)?.source ?? '');
              const isPivot = src === 'pivot_engine_followup';
              const isHint = src === 'next_step_hint';
              const isFirst = idx === 0;
              return (
                <div key={idx} className={cn('flex items-start gap-2 text-[0.78rem] py-0.5', isFirst ? 'text-text' : 'text-muted')}>
                  <span className="font-mono shrink-0 text-[0.65rem] text-ink-4 tabular w-3">{recentIters.length - idx}</span>
                  <TerminalSquare size={10} className={cn('mt-0.5 shrink-0', isFirst ? 'text-ai' : 'text-ink-4')} />
                  <span className="font-mono font-medium shrink-0">{tool}</span>
                  {isPivot && <span className="text-[0.62rem] text-amber/70 shrink-0">pivot</span>}
                  {isHint && <span className="text-[0.62rem] text-ok/70 shrink-0">chain</span>}
                  <span className="truncate text-[0.72rem]">{String(na?.reasoning ?? '').slice(0, 60)}</span>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Next up */}
      {pendingProps.length > 0 && (
        <div className="px-3 py-2">
          <div className="mb-1 font-mono text-[0.62rem] uppercase tracking-widest text-muted">NEXT UP</div>
          {pendingProps.map((p) => (
            <div key={p.id} className="flex items-center justify-between gap-2 py-0.5">
              <div className="flex items-center gap-2 min-w-0">
                <span className="font-mono text-[0.78rem] font-semibold text-text shrink-0">{p.proposed_tool}</span>
                <span className="text-[0.72rem] text-muted truncate">{String(p.reasoning_text ?? '').slice(0, 50)}</span>
              </div>
              <span className="font-mono text-[0.68rem] text-ok shrink-0">
                {Math.round(Number(p.confidence_score ?? 0) * 100)}%
              </span>
            </div>
          ))}
        </div>
      )}

      {iterations.length === 0 && !hypothesis && (
        <div className="flex-1 flex items-center justify-center text-[0.8rem] text-muted p-4">
          Loop starts after first tool completes.
        </div>
      )}
    </div>
  );
}

// Dead code retained for reference — not rendered anywhere.


function PhaseChain({
  chain,
  run,
  tasks,
  phases,
  currentPhase,
  canApprovePhase,
  busy,
  onApprove,
}: {
  chain: Partial<AssessmentChain> | JsonMap | null;
  run: Run;
  tasks: Task[];
  phases: PhaseView[];
  currentPhase: PhaseView | null;
  canApprovePhase: boolean;
  busy: boolean;
  onApprove: () => void;
}) {
  const gaps = taskGapSummary(tasks, run);
  const status = chainStatus(chain) || 'No chain';
  const phaseBlocker = phaseBlockerMessage(run, tasks, phases, currentPhase);
  return (
    <div className="glass-panel min-h-[230px] rounded-lg p-4">
      <div className="mb-4 flex items-center justify-between gap-3">
        <h2 className="flex items-center gap-2 text-[1rem] font-semibold text-cyan">
          <Workflow size={15} />
          Phase Chain
        </h2>
        <span className={cn('rounded-full px-2 py-0.5 text-[0.77rem] font-bold uppercase', statusTone(status))}>
          {statusLabel(status)}
        </span>
      </div>
      {gaps.total > 0 && (
        <div className="mb-4 rounded-md border border-amber/25 bg-amber/10 px-3 py-2 text-[0.88rem] leading-5 text-amber">
          {isRunTerminal(run)
            ? `Completed with gaps: ${gaps.failed} failed, ${gaps.notRun} not run.`
            : `Coverage gaps so far: ${gaps.failed} failed, ${gaps.notRun} not run. Current phase is still open.`}
        </div>
      )}
      {phaseBlocker && (
        <div className="mb-4 rounded-md border border-cyan/20 bg-bg/35 px-3 py-2 text-[0.88rem] leading-5 text-muted">
          <span className="font-semibold text-cyan">Why the next phase is waiting: </span>
          {phaseBlocker}
        </div>
      )}
      {phases.length === 0 ? (
        <EmptyBlock title="No phase chain" detail="This run has not returned assessment chain data." />
      ) : (
        <>
          <div className="grid gap-2 sm:grid-cols-2">
            {phases.map((phase) => (
              <div
                key={phase.key}
                className={cn(
                  'rounded-md border px-3 py-3',
                  phase.current ? 'border-cyan/40 bg-cyan/10' : 'border-border bg-surface/40',
                )}
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="truncate text-[0.925rem] font-semibold text-text">{phase.label}</span>
                  <span className={cn('rounded-full px-2 py-0.5 text-[0.77rem] font-bold uppercase', statusTone(phase.status))}>
                    {phase.status}
                  </span>
                </div>
                <p className="mt-1 truncate font-mono text-[0.85rem] text-muted">{phase.key}</p>
              </div>
            ))}
          </div>
          {canApprovePhase && currentPhase && (
            <button
              type="button"
              onClick={onApprove}
              disabled={busy}
              className="mt-4 inline-flex items-center gap-2 rounded-md border border-emerald-400/30 bg-emerald-400/10 px-3 py-2 text-[0.925rem] font-semibold text-emerald-200 transition-colors hover:bg-emerald-400/15 disabled:opacity-50"
            >
              {busy ? <Loader2 size={14} className="animate-spin" /> : <Check size={14} />}
              Approve Phase
            </button>
          )}
        </>
      )}
    </div>
  );
}

function KeyValue({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="flex items-center justify-between gap-3">
      <span className="text-muted">{label}</span>
      <span className="truncate text-right text-text">{value}</span>
    </div>
  );
}

function EmptyBlock({ title, detail }: { title: string; detail: string }) {
  return (
    <div className="flex min-h-[160px] flex-1 flex-col items-center justify-center rounded-md border border-dashed border-border bg-surface/20 p-4 text-center">
      <AlertTriangle size={18} className="living-empty-icon mb-3 text-muted" />
      <p className="text-[1rem] font-semibold text-text">{title}</p>
      <p className="mt-1 max-w-sm text-[0.925rem] leading-5 text-muted">{detail}</p>
    </div>
  );
}
function isAutomaticRun(run: Run): boolean {
  const assessment = assessmentMode(run);
  return Boolean(
    run.autonomous_mode ||
      assessment?.enabled === true ||
      assessment?.auto_advance_on_phase_complete === true ||
      assessment?.authorization_level === 'full',
  );
}

function isAiLoopRun(run: Run): boolean {
  const loop = run.configuration_json?.ai_assessment_loop;
  return Boolean(
    run.configuration_json?.run_mode === 'ai_loop' ||
      (isJsonMap(loop) && loop.run_mode === 'ai_loop'),
  );
}

function isWargamingRun(run: Run): boolean {
  const sandbox = run.configuration_json?.wargaming_sandbox;
  return Boolean(run.profile?.limits_json?.wargaming_sandbox || (isJsonMap(sandbox) && sandbox.simulation_only));
}

function fallbackRunForMissingRun(runs: Run[], missingRun: Run | null, missingRunId: string): Run | null {
  const missingChainId = chainId(missingRun?.assessment_chain ?? null);
  if (missingChainId) {
    const sameChain = runs
      .filter((run) => run.id !== missingRunId && chainId(run.assessment_chain) === missingChainId)
      .sort((left, right) => Date.parse(right.created_at) - Date.parse(left.created_at))[0];
    if (sameChain) return sameChain;
  }
  return runs.find((candidate) => candidate.id !== missingRunId) ?? null;
}

function assessmentMode(run: Run): JsonMap | null {
  const assessment = run.configuration_json?.assessment_mode;
  return isJsonMap(assessment) ? assessment : null;
}

function buildPhaseViews(chain: Partial<AssessmentChain> | JsonMap | null): PhaseView[] {
  if (!isJsonMap(chain)) return [];
  const currentKey = typeof chain.current_phase_key === 'string' ? chain.current_phase_key : null;
  return readArray(chain.phases)
    .map((phase, index): PhaseView | null => {
      if (!isJsonMap(phase)) return null;
      const key = stringValue(phase.key) || stringValue(phase.phase_key) || `phase-${index + 1}`;
      const label = stringValue(phase.label) || stringValue(phase.name) || stringValue(phase.title) || key;
      const status = stringValue(phase.status) || (key === currentKey ? 'active' : 'queued');
      const requiresApproval = Boolean(phase.requires_approval || phase.approval_required);
      return {
        key,
        label,
        status,
        current: key === currentKey || index === numberValue(chain.current_phase_index, -1),
        requiresApproval,
        approved_by: stringValue(phase.approved_by) || null,
      };
    })
    .filter((phase): phase is PhaseView => Boolean(phase));
}

function selectConsoleTask(tasks: Task[], run: Run, selectedTaskId: UUID | null): Task | null {
  if (selectedTaskId) {
    const selected = tasks.find((task) => task.id === selectedTaskId);
    if (selected) return selected;
  }
  return (
    tasks.find((task) => isTaskActiveForRun(task, run)) ??
    tasks.find((task) => isTaskQueuedForRun(task, run)) ??
    tasks.find((task) => taskStatus(task) === 'failed') ??
    tasks.find((task) => taskDisplayStatus(task, run) === 'not_run') ??
    [...tasks].sort((left, right) => Date.parse(right.updated_at) - Date.parse(left.updated_at))[0] ??
    null
  );
}

function phaseBlockerMessage(run: Run, tasks: Task[], phases: PhaseView[], currentPhase: PhaseView | null): string | null {
  if (!currentPhase || isRunTerminal(run)) return null;
  const queuedTask = tasks.find((task) => isTaskQueuedForRun(task, run));
  if (queuedTask) {
    const nextPendingPhase = phases.find((phase) => !phase.current && lowerValue(phase.status).includes('pending'));
    const nextLabel = nextPendingPhase?.label ?? 'the next phase';
    return `${nextLabel} stays pending until ${queuedTask.tool} leaves queued state and Phase ${currentPhase.label} closes.`;
  }
  const runningTask = tasks.find((task) => isTaskActiveForRun(task, run));
  if (runningTask) {
    return `${runningTask.tool} is still ${runningTask.status}; the chain cannot advance until that runner records terminal evidence.`;
  }
  const failedTask = tasks.find((task) => taskStatus(task) === 'failed');
  if (failedTask) {
    return `${failedTask.tool} failed. The chain can only continue after the failed check is reviewed or accepted as a documented gap.`;
  }
  return null;
}

function latestExecution(detail: TaskDetail | undefined) {
  return [...(detail?.executions ?? [])].sort((left, right) =>
    stringValue(right.created_at).localeCompare(stringValue(left.created_at)),
  )[0];
}

function pendingOutputForTask(task: Task, run: Run): string {
  const status = taskDisplayStatus(task, run).toLowerCase();
  if (status === 'queued' || status === 'requested') {
    return [
      'aegispt> task is queued',
      `tool   > ${task.tool}`,
      `target > ${task.target_id || 'pending'}`,
      'stdout > waiting for backend dispatch or worker pickup',
    ].join('\n');
  }
  if (status === 'not_run') {
    return [
      'aegispt> task did not run',
      `tool   > ${task.tool}`,
      `target > ${task.target_id || 'pending'}`,
      'reason > selected run/chain is terminal while this task stayed queued or requested',
    ].join('\n');
  }
  return [
    'aegispt> connecting to task stdout snapshot',
    `tool   > ${task.tool}`,
    `target > ${task.target_id || 'pending'}`,
  ].join('\n');
}

function boundedOutput(detail: TaskDetail): string {
  const newestExecution = latestExecution(detail);
  const executionText = newestExecution?.stdout_text || newestExecution?.stderr_text || '';
  const snapshotLines = detail.stdout_snapshot?.lines?.map((line) => line.text).filter(Boolean).join('\n') ?? '';
  const reason = detail.stdout_snapshot?.reason ? `stdout snapshot: ${detail.stdout_snapshot.reason}` : '';
  const output = executionText || snapshotLines || reason || 'No execution output has been recorded for this task.';
  return output.length > OUTPUT_LIMIT ? `${output.slice(-OUTPUT_LIMIT)}\n[bounded to latest ${OUTPUT_LIMIT} characters]` : output;
}

function commandPreview(task: Task): string {
  const params = isJsonMap(task.params_json) ? task.params_json : {};
  const rawCommand = stringValue(params.command || params.command_line || params.argv);
  if (rawCommand) return `$ ${redactSensitiveText(rawCommand)}`;
  const args = commandArgsForTask(task.tool, params);
  return [`$ ${task.tool}`, ...args, task.target_id ? [quoteShell(task.target_id)] : []]
    .flat()
    .filter(Boolean)
    .join(' ');
}

function commandArgsForTask(tool: string, params: JsonMap): string[] {
  const args: string[] = [];
  const addFlag = (flag: string, value: unknown) => {
    const text = stringValue(value);
    if (text) args.push(flag, quoteShell(redactSensitiveText(text)));
  };
  if (tool === 'nmap') {
    addFlag('-p', params.ports || params.port_range);
    if (params.service_detection || params.version_detection) args.push('-sV');
    if (params.safe_scripts || params.default_scripts) args.push('-sC');
  } else if (tool === 'httpx') {
    if (params.follow_redirects) args.push('--follow-redirects');
    addFlag('--timeout', params.timeout_seconds);
  } else if (tool === 'nuclei') {
    addFlag('-tags', params.tags);
    addFlag('-templates', params.templates || params.template);
  } else if (tool === 'zap') {
    addFlag('--mode', params.mode);
    addFlag('--policy', params.policy);
  } else if (tool === 'sqlmap') {
    addFlag('--risk', params.risk);
    addFlag('--level', params.level);
    if (params.batch !== false) args.push('--batch');
  } else if (tool === 'ssrf-probe') {
    addFlag('--canary-ref', params.canary_ref || params.oob_ref);
  } else if (tool === 'burp') {
    addFlag('--scan-config', params.scan_config || params.profile);
  }
  return args;
}

function redactSensitiveText(value: string): string {
  return value
    .replace(/(authorization:\s*bearer\s+)[^\s]+/gi, '$1[redacted]')
    .replace(/(api[_-]?key=)[^&\s]+/gi, '$1[redacted]')
    .replace(/(token=)[^&\s]+/gi, '$1[redacted]')
    .replace(/(password=)[^&\s]+/gi, '$1[redacted]');
}

function quoteShell(value: string): string {
  if (!value) return '';
  if (/^[a-zA-Z0-9_./:@%+=,-]+$/.test(value)) return value;
  return `'${value.replace(/'/g, "'\"'\"'")}'`;
}

function chainId(chain: Partial<AssessmentChain> | JsonMap | null): UUID | null {
  return isJsonMap(chain) && typeof chain.id === 'string' ? chain.id : null;
}

function chainStatus(chain: Partial<AssessmentChain> | JsonMap | null): string {
  return isJsonMap(chain) && typeof chain.status === 'string' ? chain.status : '';
}

function taskDisplayStatus(task: Task, run: Run): string {
  const status = taskStatus(task);
  if (isRunTerminal(run) && ['queued', 'requested', 'dispatching', 'running'].includes(status)) {
    return 'not_run';
  }
  return status || 'unknown';
}

function taskGapSummary(tasks: Task[], run: Run): { failed: number; notRun: number; total: number } {
  const failed = tasks.filter((task) => taskStatus(task) === 'failed').length;
  const notRun = tasks.filter((task) => taskDisplayStatus(task, run) === 'not_run').length;
  return { failed, notRun, total: failed + notRun };
}

function statusTone(status: string): string {
  const value = status.toLowerCase();
  if (['running', 'active', 'approved', 'completed', 'complete', 'success', 'passed', 'low'].includes(value)) {
    return 'border border-emerald-400/30 bg-emerald-400/10 text-emerald-200';
  }
  if (['queued', 'requested', 'pending', 'medium', 'completed_with_gaps'].includes(value)) {
    return 'border border-amber/30 bg-amber/10 text-amber';
  }
  if (['not_run', 'skipped'].includes(value)) {
    return 'border border-slate-400/25 bg-slate-400/10 text-slate-200';
  }
  if (['failed', 'failure', 'cancelled', 'canceled', 'rejected', 'high', 'critical'].includes(value)) {
    return 'border border-red/30 bg-red/10 text-red';
  }
  return 'border border-cyan/20 bg-cyan/10 text-cyan';
}

function statusLabel(status: string): string {
  return status.replace(/[_-]+/g, ' ');
}

function readArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function isJsonMap(value: unknown): value is JsonMap {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function stringValue(value: unknown): string {
  return typeof value === 'string' ? value : '';
}

function numberValue(value: unknown, fallback: number): number {
  return typeof value === 'number' ? value : fallback;
}

function compactId(value: string): string {
  return value.length > 12 ? `${value.slice(0, 8)}...${value.slice(-4)}` : value;
}

function errorMessage(error: unknown): string {
  if (error instanceof Error) return error.message;
  return 'AegisPT API request failed.';
}

// ── EXPLOITATION CHAIN ────────────────────────────────────────────────────────
// Shows the step-by-step attack chain: what each tool found and what it triggered next.

const SEVERITY_COLOR: Record<string, string> = {
  critical: 'border-red-500 bg-red-500/10 text-red-400',
  high:     'border-orange-400 bg-orange-400/10 text-orange-300',
  medium:   'border-amber/40 bg-amber/10 text-amber',
  low:      'border-border bg-surface/40 text-muted',
  info:     'border-border bg-surface/20 text-muted',
};

const SEVERITY_DOT: Record<string, string> = {
  critical: 'bg-red-500 shadow-[0_0_8px_rgba(239,68,68,0.8)]',
  high:     'bg-orange-400',
  medium:   'bg-amber-400',
  low:      'bg-border',
  info:     'bg-muted',
};

function ExploitChain({ run: _run, tasks, findings }: { run: Run; tasks: Task[]; findings: Finding[] }) {
  const [expanded, setExpanded] = useState<string | null>(null);

  // Build chain steps from tasks + findings
  const steps = useMemo(() => {
    // Sort completed tasks by created_at
    const doneTasks = [...tasks]
      .filter(t => t.status === 'completed' || t.status === 'failed')
      .sort((a, b) => (a.created_at ?? '').localeCompare(b.created_at ?? ''));

    // Match findings to tasks by time window: finding.created_at between task.created_at and next task.created_at
    const findingsByTaskIdx: Record<number, Finding[]> = {};
    for (const f of findings) {
      const fTime = String((f as unknown as Record<string, unknown>).created_at ?? '');
      if (!fTime) continue;
      // Find which task time window this finding falls in
      for (let i = doneTasks.length - 1; i >= 0; i--) {
        const tTime = String(doneTasks[i].created_at ?? '');
        if (fTime >= tTime) {
          (findingsByTaskIdx[i] ??= []).push(f);
          break;
        }
      }
    }

    return doneTasks.map((task, idx) => {
        const params = (task.params_json ?? {}) as Record<string, unknown>;
        const nba = (params.next_best_action_selector ?? {}) as Record<string, unknown>;
        const triggers = Array.isArray(nba.matched_triggers) ? nba.matched_triggers as string[] : [];
        const source = String(params.source ?? nba.source ?? '');
        const vaultInjected = Boolean((params.credential_vault as Record<string, unknown>)?.injected);
        const taskFindings = findingsByTaskIdx[idx] ?? [];

        // Highest severity finding for this task
        const topFinding = [...taskFindings].sort((a, b) => {
          const order: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
          return (order[a.severity] ?? 5) - (order[b.severity] ?? 5);
        })[0];

        return {
          idx,
          task,
          vaultInjected,
          triggers,
          source,
          taskFindings,
          topFinding,
          isLast: idx === doneTasks.length - 1,
        };
      });
  }, [tasks, findings]);

  if (steps.length === 0) return null;

  return (
    <div className="glass-panel rounded-lg p-4">
      <div className="mb-4 flex items-center gap-2">
        <Workflow size={15} className="text-cyan" />
        <h2 className="text-[1rem] font-semibold text-cyan">Exploitation Chain</h2>
        <span className="ml-auto text-[0.75rem] text-muted">{steps.length} stappen</span>
      </div>

      <div className="relative">
        {/* Vertical connector line */}
        <div className="absolute left-[11px] top-4 bottom-4 w-px bg-border" />

        <div className="space-y-0">
          {steps.map(({ idx, task, triggers, source, vaultInjected, taskFindings, topFinding, isLast }) => {
            const isExpanded = expanded === task.id;
            const hasCritical = taskFindings.some(f => f.severity === 'critical');
            const hasHigh = taskFindings.some(f => f.severity === 'high');
            const dotColor = hasCritical ? SEVERITY_DOT.critical : hasHigh ? SEVERITY_DOT.high : taskFindings.length ? SEVERITY_DOT.medium : 'bg-border';

            const why = triggers.length
              ? `gebruikt: ${triggers.slice(0, 2).join(' + ')}`
              : source === 'pivot_engine_followup'
              ? 'pivot: vervolgonderzoek op bevinding'
              : idx === 0 ? 'startpunt' : 'standaard webrecon';

            return (
              <div key={task.id} className="relative pl-7">
                {/* Step dot */}
                <div className={cn(
                  'absolute left-0 top-4 h-[10px] w-[10px] rounded-full border-2 border-bg',
                  dotColor,
                  hasCritical && 'animate-pulse',
                )} />

                {/* Step card */}
                <button
                  type="button"
                  onClick={() => setExpanded(isExpanded ? null : task.id)}
                  className={cn(
                    'w-full text-left rounded-md border px-3 py-2 mb-1 transition-colors',
                    hasCritical ? 'border-red-500/40 bg-red-500/5 hover:bg-red-500/10' :
                    hasHigh ? 'border-orange-400/30 bg-orange-400/5 hover:bg-orange-400/10' :
                    taskFindings.length ? 'border-amber/20 bg-amber/5 hover:bg-amber/10' :
                    'border-border bg-surface/20 hover:bg-surface/40',
                  )}
                >
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="font-mono text-[0.82rem] font-bold text-text">{task.tool}</span>
                    {hasCritical && (
                      <span className="rounded px-1.5 py-0.5 text-[0.68rem] font-bold uppercase bg-red-500/20 text-red-400 border border-red-500/30">CRITICAL</span>
                    )}
                    {!hasCritical && hasHigh && (
                      <span className="rounded px-1.5 py-0.5 text-[0.68rem] font-bold uppercase bg-orange-400/20 text-orange-300 border border-orange-400/30">HIGH</span>
                    )}
                    {taskFindings.length > 0 && !hasCritical && !hasHigh && (
                      <span className="rounded px-1.5 py-0.5 text-[0.68rem] font-bold bg-amber/10 text-amber border border-amber/30">{taskFindings.length} gevonden</span>
                    )}
                    {vaultInjected && (
                      <span className="rounded px-1.5 py-0.5 text-[0.65rem] font-bold bg-cyan/10 text-cyan border border-cyan/20">🔑 met gestolen sessie</span>
                    )}
                    <span className="ml-auto text-[0.72rem] text-muted">{why}</span>
                  </div>

                  {/* Top finding preview */}
                  {topFinding && (
                    <div className={cn('mt-1 text-[0.78rem] truncate font-medium', hasCritical ? 'text-red-400' : hasHigh ? 'text-orange-300' : 'text-amber')}>
                      ↳ {topFinding.title}
                    </div>
                  )}
                </button>

                {/* Expanded detail */}
                {isExpanded && (
                  <div className="mb-2 rounded-md border border-border bg-surface/30 p-3 text-[0.8rem] space-y-2">
                    {triggers.length > 0 && (
                      <div>
                        <span className="text-muted">Geselecteerd op basis van: </span>
                        <span className="text-cyan">{triggers.join(', ')}</span>
                      </div>
                    )}
                    {taskFindings.map(f => (
                      <div key={f.id} className={cn('rounded border px-2 py-1.5', SEVERITY_COLOR[f.severity] ?? SEVERITY_COLOR.info)}>
                        <div className="flex items-center gap-2 font-semibold">
                          <div className={cn('h-1.5 w-1.5 rounded-full', SEVERITY_DOT[f.severity] ?? 'bg-muted')} />
                          <span className="uppercase text-[0.68rem]">{f.severity}</span>
                          <span>{f.title}</span>
                        </div>
                        {f.summary && (
                          <div className="mt-1 text-[0.76rem] opacity-80 leading-relaxed">{f.summary}</div>
                        )}
                      </div>
                    ))}
                    {taskFindings.length === 0 && (
                      <div className="text-muted italic">Geen bevindingen — tool voltooid zonder resultaat.</div>
                    )}
                  </div>
                )}

                {/* Arrow to next */}
                {!isLast && triggers.length > 0 && (
                  <div className="ml-0.5 mb-1 flex items-center gap-1 text-[0.7rem] text-muted/60">
                    <ChevronRight size={10} />
                    <span>triggerde volgende stap</span>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
