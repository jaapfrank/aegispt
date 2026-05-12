/* eslint-disable @typescript-eslint/no-unused-vars */
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import {
  Activity,
  AlertTriangle,
  Bot,
  Check,
  CircleStop,
  Copy,
  Loader2,
  Map as MapIcon,
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
  advanceAssessmentLoop,
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
  InventorySnapshot,
  JsonMap,
  Run,
  RunAiInsights,
  Task,
  TaskDetail,
  UUID,
} from '../../api/types';
import { useAegisStore } from '../../store';
import CinemaMode from '../CinemaMode';
import AutopilotWorkbench from './AutopilotWorkbench';

const POLL_MS = 3000;
const AI_SIGNAL_TYPE_MS = 12;
const ACTIVE_STATUSES = new Set(['queued', 'requested', 'dispatching', 'running']);
const QUEUED_STATUSES = new Set(['queued', 'requested']);
const RUNNING_STATUSES = new Set(['dispatching', 'running']);
const TERMINAL_STATUSES = new Set(['completed', 'failed', 'cancelled', 'canceled']);
const OUTPUT_LIMIT = 5000;
function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

type BusyAction = 'refresh' | 'cancel' | 'dispatch' | 'phase' | 'autopilot-continue' | `proposal-${UUID}` | null;

type ExecutionNotice = {
  title: string;
  detail: string;
  tone: string;
};

type MissionStatus = {
  title: string;
  detail: string;
  operatorAction: string | null;
  tone: 'live' | 'waiting' | 'review' | 'done' | 'gap';
  currentTask: Task | null;
  nextTask: Task | null;
};

type MapNode = {
  id: string;
  label: string;
  type: string;
  state: 'finding' | 'active' | 'complete' | 'idle';
  findingCount: number;
  maxSeverity: string | null;
  x: number;
  y: number;
};

type PhaseView = {
  key: string;
  label: string;
  status: string;
  current: boolean;
  requiresApproval: boolean;
  approved_by?: string | null;
};

type AiSignalEntry = {
  id: string;
  type: 'status' | 'task' | 'finding' | 'reasoning' | 'proposal';
  timestamp: string;
  text: string;
  tone: string;
  proposal?: AgentProposal;
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
const proposalStatus = (proposal: Partial<AgentProposal> | null | undefined): string => lowerValue(proposal?.status);
const profileName = (run: Partial<Run> | null | undefined): string => run?.profile?.name ?? 'selected run';
const isPendingProposal = (proposal: Partial<AgentProposal> | null | undefined): boolean =>
  ['pending', 'pending_review'].includes(proposalStatus(proposal));

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
  const inventory = useAegisStore((state) => state.inventory);
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
  const [cinemaOpen, setCinemaOpen] = useState(false);
  const [launchArrival, setLaunchArrival] = useState(() => readIntakeLaunchState(location.state));
  const refreshInFlightRef = useRef(false);

  const proposals = useMemo(() => aiInsights?.proposals ?? [], [aiInsights?.proposals]);
  const chain = selectedRun?.assessment_chain ?? null;
  const phases = useMemo(() => buildPhaseViews(chain), [chain]);
  const currentPhase = phases.find((phase) => phase.current) ?? phases[0] ?? null;
  const mapNodes = useMemo(() => buildMapNodes(inventory, tasks, findings, selectedRun), [inventory, selectedRun, tasks, findings]);
  const activeTaskCount = selectedRun ? tasks.filter((task) => isTaskActiveForRun(task, selectedRun)).length : 0;
  const pendingProposalCount = proposals.filter((proposal) => proposalStatus(proposal) === 'pending').length;
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
    <section className="flex h-full flex-col">
      <div className="flex shrink-0 flex-wrap items-center justify-between gap-3 border-b border-border pb-4 mb-5">
        <div className="flex min-w-0 flex-wrap items-center gap-3">
          <h1 className="text-xl font-semibold tracking-normal text-text">Mission Control</h1>
          <span className={cn('rounded-full px-2.5 py-1 text-[0.8rem] font-bold uppercase tracking-wider', statusTone(runStatus(selectedRun)))}>
            {statusLabel(runStatus(selectedRun))}
          </span>
          {isPolling && (
            <span className="inline-flex items-center gap-1.5 rounded-full border border-cyan/20 bg-cyan/10 px-2.5 py-1 text-[0.75rem] font-bold uppercase tracking-wider text-cyan">
              <span className="h-1.5 w-1.5 rounded-full bg-cyan animate-pulse-fast" />
              Live
            </span>
          )}
          {selectedRunIsWargaming && (
            <span className="inline-flex items-center gap-1.5 rounded-full border border-amber/30 bg-amber/10 px-2.5 py-1 text-[0.75rem] font-bold uppercase tracking-wider text-amber">
              <ShieldAlert size={12} />
              Wargaming
            </span>
          )}
        </div>

        <div className="flex shrink-0 items-center gap-2">
          <button
            type="button"
            onClick={() => void refreshRun()}
            disabled={busyAction !== null}
            className="inline-flex min-h-9 items-center justify-center gap-2 rounded-md border border-border bg-surface/70 px-3 py-1.5 text-[0.85rem] font-semibold text-text transition-colors hover:border-cyan/40 hover:text-cyan disabled:opacity-50"
          >
            <RefreshCw size={14} className={busyAction === 'refresh' ? 'animate-spin' : ''} />
            Refresh
          </button>
          <button
            type="button"
            onClick={() => setCinemaOpen(true)}
            className="inline-flex min-h-9 items-center justify-center gap-2 rounded-md border border-cyan/30 bg-cyan/10 px-3 py-1.5 text-[0.85rem] font-semibold text-cyan transition-colors hover:bg-cyan/15"
          >
            <MonitorPlay size={14} />
            Cinema Mode
          </button>
          <button
            type="button"
            onClick={() => void handleCancel()}
            disabled={!canCancel || busyAction !== null}
            className="inline-flex min-h-9 items-center justify-center gap-2 rounded-md border border-red/30 bg-red/10 px-3 py-1.5 text-[0.85rem] font-semibold text-red transition-colors hover:bg-red/15 disabled:opacity-40"
          >
            <CircleStop size={14} />
            Kill
          </button>
        </div>
      </div>

      {/* ── scrollable body ── */}
      <div className="flex flex-1 flex-col gap-5 min-h-0 overflow-y-auto pr-1">

      {/* ── STATUS BANNER ── */}
      <MissionStatusBanner run={selectedRun} tasks={tasks} findings={findings} proposals={proposals} />

      {/* ── MAIN: 3-column ── */}
      <div className="grid flex-1 gap-4 grid-cols-1 xl:grid-cols-[minmax(0,1fr)_minmax(0,1.1fr)_minmax(0,0.9fr)] min-h-0">

        {/* COL 1: Activity log — what each tool did, plain Dutch */}
        <ActivityFeed
          run={selectedRun}
          tasks={tasks}
          findings={findings}
          selectedTaskId={consoleTask?.id ?? null}
          onSelect={setSelectedTaskId}
        />

        {/* COL 2: Findings explained in plain Dutch */}
        <FindingsExplained findings={findings} />

        {/* COL 3: Live console + approval + dispatch */}
        <div className="flex flex-col gap-3 min-h-0">
          {proposals.filter((p) => p.status === 'pending').map((proposal) => (
            <div key={proposal.id} className="shrink-0 rounded-lg border border-amber/30 bg-amber/8 p-3">
              <p className="mb-2 text-[0.78rem] font-bold uppercase tracking-wide text-amber">Goedkeuring gevraagd</p>
              <p className="font-mono text-[0.88rem] font-semibold text-text">{proposal.proposed_tool}</p>
              <p className="mb-3 mt-0.5 truncate text-[0.75rem] text-muted">{proposal.proposed_target}</p>
              <div className="flex gap-2">
                <button type="button" onClick={() => void handleProposalReview(proposal, 'approved')} disabled={busyAction !== null}
                  className="inline-flex flex-1 items-center justify-center gap-1 rounded-md border border-emerald-400/30 bg-emerald-400/10 py-1.5 text-[0.8rem] font-semibold text-emerald-300 hover:bg-emerald-400/15">
                  <Check size={12} /> Goedkeuren
                </button>
                <button type="button" onClick={() => void handleProposalReview(proposal, 'rejected')} disabled={busyAction !== null}
                  className="inline-flex items-center gap-1 rounded-md border border-border px-3 py-1.5 text-[0.8rem] text-muted hover:text-text">
                  <X size={12} /> Overslaan
                </button>
              </div>
            </div>
          ))}

          <div className="flex-1 min-h-[200px]">
            <LiveCommandConsole
              run={selectedRun}
              task={consoleTask}
              detail={consoleTask ? taskDetails[consoleTask.id] : undefined}
            />
          </div>

          {isAiLoopRun(selectedRun) && findings.length > 0 && (
            <ExploitChain run={selectedRun} tasks={tasks} findings={findings} />
          )}

          {isAiLoopRun(selectedRun) && (
            <AiLoopPanel run={selectedRun} proposals={proposals} tasks={tasks} />
          )}

          {!isAiLoopRun(selectedRun) && phases.length > 0 && (
            <PhaseChain chain={chain} run={selectedRun} tasks={tasks} phases={phases}
              currentPhase={currentPhase} canApprovePhase={canApprovePhase}
              busy={busyAction === 'phase'} onApprove={() => void handleApprovePhase()} />
          )}

          <button type="button" onClick={() => void handleDispatch()}
            disabled={!canDispatch || busyAction !== null}
            className="flex w-full shrink-0 min-h-[2.5rem] items-center justify-center gap-2 rounded-md border border-emerald-400/30 bg-emerald-400/10 px-4 py-2 text-[0.9rem] font-semibold text-emerald-200 hover:bg-emerald-400/15 disabled:cursor-not-allowed disabled:opacity-40">
            <Play size={15} />
            {selectedRunIsAutomatic ? 'Start wachtrij' : 'Start handmatig'}
          </button>
        </div>
      </div>

      </div>{/* end scrollable body */}

      {cinemaOpen && (
        <CinemaMode onClose={() => setCinemaOpen(false)} />
      )}
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

function ActiveWorkStrip({
  activeRuns,
  selectedRun,
  selectedRunId,
  selectedTasks,
  onSelectRun,
}: {
  activeRuns: Run[];
  selectedRun: Run;
  selectedRunId: UUID;
  selectedTasks: Task[];
  onSelectRun: (runId: UUID | null) => void;
}) {
  const selectedRunningTask = selectedTasks.find((task) => isTaskActiveForRun(task, selectedRun));
  const selectedQueuedTask = selectedTasks.find((task) => isTaskQueuedForRun(task, selectedRun));
  const selectedWorkTask = selectedRunningTask ?? selectedQueuedTask ?? null;
  const selectedRunIsActive = activeRuns.some((run) => run.id === selectedRunId);

  if (activeRuns.length === 0 && !selectedWorkTask) {
    return (
      <div className="rounded-lg border border-border bg-surface/35 px-4 py-3 text-[0.925rem] text-muted">
        No backend run is currently queued, dispatching, or running for this engagement.
      </div>
    );
  }

  return (
    <section className="rounded-lg border border-cyan/20 bg-cyan/5 p-4">
      <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
        <div className="min-w-0">
          <h2 className="flex items-center gap-2 text-[1rem] font-semibold text-cyan">
            <Activity size={15} />
            Active Work
          </h2>
          <p className="mt-1 text-[0.925rem] leading-5 text-muted">
            {selectedRunningTask
              ? `${selectedRunningTask.tool} is ${selectedRunningTask.status} against ${truncateMiddle(selectedRunningTask.target_id || 'recorded target', 96)}.`
              : selectedQueuedTask
                ? `${selectedQueuedTask.tool} is queued against ${truncateMiddle(selectedQueuedTask.target_id || 'recorded target', 96)}. It is not running until dispatch or a worker picks it up.`
              : ['queued', 'requested'].includes(runStatus(selectedRun))
                ? 'This run is queued, but no backend task is running yet. Use Start Queued Checks if automatic dispatch did not begin.'
              : selectedRunIsActive
                ? 'This selected run is active, but the backend has not exposed a current task yet.'
                : `${activeRuns.length} other run(s) are active. Select one below to inspect what is moving.`}
          </p>
        </div>

        <div className="grid w-full gap-2 lg:w-auto lg:min-w-[22rem]">
          {activeRuns.slice(0, 4).map((run) => {
            const isSelected = run.id === selectedRunId;
            const runState = runStatus(run);
            const activeTask = (run.tasks ?? []).find((task) => RUNNING_STATUSES.has(taskStatus(task))) ??
              (run.tasks ?? []).find((task) => QUEUED_STATUSES.has(taskStatus(task)));
            const taskStateCopy = activeTask
              ? QUEUED_STATUSES.has(taskStatus(activeTask))
                ? `${activeTask.tool} queued; not running`
                : `${activeTask.tool} is ${statusLabel(taskStatus(activeTask))}`
              : statusLabel(runState);
            return (
              <button
                key={run.id}
                type="button"
                onClick={() => onSelectRun(run.id)}
                className={cn(
                  'flex min-w-0 items-center justify-between gap-3 rounded-md border px-3 py-2 text-left transition-colors',
                  isSelected
                    ? 'border-cyan/40 bg-cyan/10 text-cyan'
                    : 'border-border bg-bg/30 text-text hover:border-cyan/35 hover:text-cyan',
                )}
              >
                <span className="min-w-0">
                  <span className="block truncate text-[0.925rem] font-semibold">{profileName(run)}</span>
                  <span className="block truncate font-mono text-[0.8rem] text-muted">
                    {compactId(run.id)} · {taskStateCopy}
                  </span>
                </span>
                <span className={cn('shrink-0 rounded-full px-2 py-0.5 text-[0.72rem] font-bold uppercase', statusTone(runState))}>
                  {isSelected ? 'open' : statusLabel(runState)}
                </span>
              </button>
            );
          })}
        </div>
      </div>
    </section>
  );
}

function MissionNowPanel({
  status,
  run,
  tasks,
  currentPhase,
  canDispatch,
  busy,
  onDispatch,
}: {
  status: MissionStatus;
  run: Run;
  tasks: Task[];
  currentPhase: PhaseView | null;
  canDispatch: boolean;
  busy: boolean;
  onDispatch: () => void;
}) {
  const gaps = taskGapSummary(tasks, run);
  const toneClass =
    status.tone === 'live'
      ? 'border-cyan/30 bg-cyan/10'
      : status.tone === 'review'
        ? 'border-amber/30 bg-amber/10'
        : status.tone === 'gap'
          ? 'border-red/25 bg-red/10'
          : status.tone === 'done'
            ? 'border-emerald-400/25 bg-emerald-400/10'
            : 'border-border bg-surface/35';
  return (
    <section className={cn('rounded-lg border px-4 py-3', toneClass)}>
      <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_minmax(18rem,0.34fr)] xl:items-start">
        <div className="min-w-0">
          <p className="text-[0.74rem] font-bold uppercase tracking-[0.18em] text-muted">Mission now</p>
          <h2 className="mt-1 text-[1.15rem] font-semibold text-text">{status.title}</h2>
          <p className="mt-1 max-w-4xl text-[0.95rem] leading-5 text-muted">{status.detail}</p>
          <div className="mt-3 flex flex-wrap gap-2">
            <StatusChip label="Run" value={statusLabel(runStatus(run))} />
            {currentPhase && <StatusChip label="Phase" value={`${currentPhase.label} · ${statusLabel(currentPhase.status)}`} />}
            {status.currentTask && <StatusChip label="Current" value={`${status.currentTask.tool} · ${statusLabel(taskStatus(status.currentTask))}`} />}
            {status.nextTask && <StatusChip label="Next" value={`${status.nextTask.tool} · ${statusLabel(taskStatus(status.nextTask))}`} />}
            {gaps.total > 0 && <StatusChip label="Gaps" value={`${gaps.failed} failed · ${gaps.notRun} not run`} warning />}
          </div>
        </div>
        <div className="flex w-full flex-col gap-2 xl:w-[20rem]">
          {status.operatorAction && (
            <div className="rounded-md border border-border bg-bg/45 px-3 py-2 text-[0.9rem] leading-5 text-text">
              <span className="font-semibold text-cyan">Action: </span>
              {status.operatorAction}
            </div>
          )}
          {canDispatch && (
            <button
              type="button"
              onClick={onDispatch}
              disabled={busy}
              className="inline-flex min-h-10 items-center justify-center gap-2 rounded-md border border-emerald-400/30 bg-emerald-400/10 px-3 py-2 text-[0.9rem] font-semibold text-emerald-200 transition-colors hover:bg-emerald-400/15 disabled:cursor-not-allowed disabled:opacity-40"
            >
              {busy ? <Loader2 size={15} className="animate-spin" /> : <Play size={15} />}
              Start queued check
            </button>
          )}
        </div>
      </div>
      <MissionTimeline tasks={tasks} run={run} />
    </section>
  );
}

function StatusChip({ label, value, warning = false }: { label: string; value: string; warning?: boolean }) {
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-[0.8rem] font-semibold',
        warning ? 'border-amber/30 bg-amber/10 text-amber' : 'border-cyan/20 bg-bg/35 text-cyan',
      )}
    >
      <span className="text-muted">{label}</span>
      {value}
    </span>
  );
}

function MissionTimeline({ tasks, run }: { tasks: Task[]; run: Run }) {
  const visibleTasks = [...tasks]
    .sort((left, right) => Date.parse(left.created_at) - Date.parse(right.created_at))
    .slice(-8);
  if (visibleTasks.length === 0) return null;
  return (
    <div className="mt-3 border-t border-border pt-3">
      <div className="grid gap-2 md:grid-cols-2 xl:grid-cols-4">
        {visibleTasks.map((task, index) => {
          const displayStatus = taskDisplayStatus(task, run);
          const active = isTaskActiveForRun(task, run);
          const queued = isTaskQueuedForRun(task, run);
          const failed = displayStatus.toLowerCase() === 'failed';
          const notRun = displayStatus.toLowerCase() === 'not_run';
          return (
            <div
              key={task.id}
              className={cn(
                'rounded-md border bg-bg/35 px-3 py-2',
                active
                  ? 'border-cyan/45 shadow-[0_0_1rem_rgba(94,207,255,0.14)]'
                  : queued
                    ? 'border-amber/35 bg-amber/5'
                  : failed || notRun
                    ? 'border-amber/35'
                    : 'border-border',
              )}
            >
              <div className="flex items-center justify-between gap-2">
                <span className="truncate font-mono text-[0.82rem] font-semibold text-text">{task.tool}</span>
                <span className={cn('shrink-0 rounded-full px-1.5 py-0.5 text-[0.65rem] font-bold uppercase', statusTone(displayStatus))}>
                  {statusLabel(displayStatus)}
                </span>
              </div>
              <p className="mt-1 truncate text-[0.76rem] text-muted">{truncateMiddle(task.target_id || 'target pending', 34)}</p>
              <p className="mt-1 font-mono text-[0.7rem] text-muted">
                {index === visibleTasks.length - 1 ? 'latest' : formatTime(task.updated_at)}
              </p>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function OperationsSummary({
  run,
  taskCount,
  activeTaskCount,
  findingCount,
  pendingProposalCount,
}: {
  run: Run;
  taskCount: number;
  activeTaskCount: number;
  findingCount: number;
  pendingProposalCount: number;
}) {
  return (
    <div className="glass-panel rounded-lg p-4">
      <div className="mb-4 flex items-center justify-between gap-3">
        <h2 className="flex items-center gap-2 text-[1rem] font-semibold text-cyan">
          <Activity size={15} />
          Run Thread
        </h2>
        <span className="text-[0.85rem] text-muted">Updated {formatDate(run.updated_at)}</span>
      </div>
      <div className="grid grid-cols-2 gap-3">
        <MiniMetric icon={<TerminalSquare size={14} />} label="Tasks" value={taskCount} />
        <MiniMetric icon={<Activity size={14} />} label="Active" value={activeTaskCount} />
        <MiniMetric icon={<ShieldAlert size={14} />} label="Findings" value={findingCount} />
        <MiniMetric icon={<Bot size={14} />} label="AI Queue" value={pendingProposalCount} />
      </div>
      <div className="mt-4 grid gap-2 text-[0.925rem] text-muted">
        <KeyValue
          label="Mode"
          value={(() => {
            const mode = (run.configuration_json?.assessment_mode as Record<string, unknown> | undefined)?.mode as string | undefined;
            return mode ? chainLabel(mode) : (run.profile?.name ?? 'standard');
          })()}
        />
        <KeyValue label="Approvals" value={`${run.granted_approvals}/${run.required_approvals}`} />
        <KeyValue label="Execution" value={executionModeLabel(run)} />
        <KeyValue label="Started" value={run.started_at ? formatDate(run.started_at) : 'Not started'} />
      </div>
    </div>
  );
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
  const input = taskInputPreview(task);
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

function TaskList({
  run,
  tasks,
  selectedTaskId,
  onSelect,
}: {
  run: Run;
  tasks: Task[];
  selectedTaskId: UUID | null;
  onSelect: (taskId: UUID) => void;
}) {
  const gapCount = tasks.filter((task) => isTaskGap(task, run)).length;
  return (
    <div className="glass-panel flex min-h-[300px] flex-col rounded-lg p-4">
      <div className="mb-4 flex items-center justify-between">
        <h2 className="flex items-center gap-2 text-[1rem] font-semibold text-cyan">
          <TerminalSquare size={15} />
          Task Ledger
        </h2>
        <span className="text-[0.85rem] text-muted">
          {tasks.length} backend tasks{gapCount > 0 ? ` · ${gapCount} gap(s)` : ''}
        </span>
      </div>
      {tasks.length === 0 ? (
        <EmptyBlock title="No tasks yet" detail="Queued checks will appear here after backend dispatch." />
      ) : (
        <div className="flex min-h-0 flex-1 flex-col gap-2 overflow-y-auto pr-1">
          {tasks.map((task) => {
            const isSelected = selectedTaskId === task.id;
            const displayStatus = taskDisplayStatus(task, run);
            const statusNote = taskStatusNote(task, run);
            return (
              <button
                type="button"
                key={task.id}
                data-status={displayStatus.toLowerCase()}
                onClick={() => onSelect(task.id)}
                className={cn(
                  'living-task-card rounded-md border bg-surface/45 px-3 py-3 text-left transition-colors',
                  isSelected ? 'border-cyan/70 shadow-[0_0_20px_rgba(94,207,255,0.16)]' : 'border-border hover:border-cyan/35',
                )}
              >
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-mono text-[0.925rem] font-semibold text-text">{task.tool}</span>
                    <span className={cn('rounded-full px-2 py-0.5 text-[0.77rem] font-bold uppercase', statusTone(displayStatus))}>
                      {statusLabel(displayStatus)}
                    </span>
                    {displayStatus !== String(task.status ?? '') && (
                      <span className="rounded-full border border-border bg-bg/40 px-2 py-0.5 text-[0.7rem] font-semibold uppercase text-muted">
                        backend: {task.status ?? 'unknown'}
                      </span>
                    )}
                  </div>
                  <p className="mt-1 truncate text-[0.925rem] text-muted">{task.target_id || 'No target id'}</p>
                  {statusNote && <p className="mt-1 text-[0.8rem] leading-4 text-amber">{statusNote}</p>}
                </div>
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}

function ScanMap({
  nodes,
  inventory,
  materialize = false,
}: {
  nodes: MapNode[];
  inventory: InventorySnapshot | null;
  materialize?: boolean;
}) {
  return (
    <div className={cn('glass-panel flex flex-col h-full min-h-[340px] rounded-lg p-4', materialize && 'animate-[mission-materialize_0.8s_ease-out]')}>
      <div className="mb-4 flex items-center justify-between gap-3 shrink-0">
        <h2 className="flex items-center gap-2 text-[1rem] font-semibold text-cyan">
          <MapIcon size={15} />
          Scan Map
        </h2>
        <span className="text-[0.85rem] text-muted">{inventory ? inventory.status : 'No inventory'}</span>
      </div>
      {nodes.length === 0 ? (
        <EmptyBlock
          title={inventory ? 'No discovered targets yet' : 'Discovery in progress'}
          detail={
            inventory
              ? 'The latest inventory did not contain host or HTTP endpoint records.'
              : 'Mission Control will draw targets after inventory data is available.'
          }
        />
      ) : (
        <div className="relative flex-1 overflow-hidden rounded-md border border-border bg-[#02060c]">
          <svg viewBox="0 0 520 270" preserveAspectRatio="xMidYMid slice" role="img" aria-label="Run inventory scan map" className="absolute inset-0 h-full w-full">
            <defs>
              <radialGradient id="nodeGlow" cx="50%" cy="50%" r="50%">
                <stop offset="0%" stopColor="rgba(94,207,255,0.65)" />
                <stop offset="100%" stopColor="rgba(94,207,255,0)" />
              </radialGradient>
            </defs>
            <line x1="260" y1="135" x2="260" y2="135" stroke="rgba(94,207,255,0.2)" />
            {nodes.map((node) => (
              <g key={`${node.id}-line`}>
                <line
                  x1="260"
                  y1="135"
                  x2={node.x}
                  y2={node.y}
                  stroke={nodeStroke(node)}
                  strokeWidth={node.state === 'finding' ? '1.8' : '1'}
                  className={materialize ? 'animate-[thread-draw_1.1s_ease-out]' : undefined}
                />
                {node.state === 'active' && (
                  <line
                    x1="260"
                    y1="135"
                    x2={node.x}
                    y2={node.y}
                    stroke="rgba(94,207,255,0.58)"
                    strokeWidth="2"
                    className="living-thread-pulse"
                  />
                )}
              </g>
            ))}
            <circle cx="260" cy="135" r="34" fill="rgba(94,207,255,0.08)" stroke="rgba(94,207,255,0.35)" />
            <text x="260" y="139" textAnchor="middle" fill="#5ecfff" fontSize="11" fontFamily="monospace">
              run
            </text>
            {nodes.map((node) => (
              <g key={node.id} className={materialize ? 'animate-[node-pop_0.55s_ease-out]' : undefined}>
                <circle cx={node.x} cy={node.y} r="20" fill="url(#nodeGlow)" opacity="0.45" />
                {node.state === 'active' && (
                  <circle
                    cx={node.x}
                    cy={node.y}
                    r="12"
                    fill="none"
                    stroke="rgba(94,207,255,0.58)"
                    className="living-sonar-ring"
                  />
                )}
                {node.state === 'finding' && (
                  <circle
                    cx={node.x}
                    cy={node.y}
                    r="13"
                    fill="none"
                    stroke={nodeColor(node.state, node.maxSeverity)}
                    opacity="0.58"
                    className="living-finding-hit"
                  />
                )}
                <circle cx={node.x} cy={node.y} r="8" fill={nodeColor(node.state, node.maxSeverity)} />
                {node.findingCount > 0 && (
                  <g className="living-badge-pop" aria-label={`${node.findingCount} findings`}>
                    <circle cx={node.x + 13} cy={node.y - 13} r="9" fill={badgeColor(node.maxSeverity)} stroke="rgba(4,8,15,0.9)" strokeWidth="2" />
                    <text
                      x={node.x + 13}
                      y={node.y - 10}
                      textAnchor="middle"
                      fill="#04080f"
                      fontSize="9"
                      fontWeight="700"
                      fontFamily="monospace"
                    >
                      {node.findingCount}
                    </text>
                  </g>
                )}
                <text
                  x={node.x}
                  y={node.y + 22}
                  textAnchor="middle"
                  fill="#c8d6e5"
                  fontSize="10"
                  fontFamily="monospace"
                >
                  {truncateMiddle(node.label, 18)}
                </text>
              </g>
            ))}
          </svg>
        </div>
      )}
    </div>
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
    bannerColor = 'border-emerald-400/20 bg-emerald-400/5 text-emerald-300';
    bannerText = `${queued.length} tool${queued.length > 1 ? 's' : ''} staat in de wachtrij. Klik 'Start wachtrij' om door te gaan.`;
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
function ActivityFeed({ run, tasks, findings, selectedTaskId, onSelect }: {
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


function FindingsSummaryCard({ findings, run, tasks }: { findings: Finding[]; run: Run; tasks: Task[] }) {
  const bySev = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) {
    const s = (f.severity ?? 'info').toLowerCase() as keyof typeof bySev;
    if (s in bySev) bySev[s]++;
  }
  const total = findings.length;
  const topFindings = [...findings]
    .sort((a, b) => {
      const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
      return (order[(a.severity ?? 'info').toLowerCase() as keyof typeof order] ?? 4) -
             (order[(b.severity ?? 'info').toLowerCase() as keyof typeof order] ?? 4);
    })
    .slice(0, 3);

  const sevConfig = [
    { key: 'critical', label: 'Kritiek', bg: 'bg-red/15', text: 'text-red', border: 'border-red/30' },
    { key: 'high', label: 'Hoog', bg: 'bg-orange-500/15', text: 'text-orange-400', border: 'border-orange-500/30' },
    { key: 'medium', label: 'Gemiddeld', bg: 'bg-yellow-400/15', text: 'text-yellow-300', border: 'border-yellow-400/30' },
    { key: 'low', label: 'Laag', bg: 'bg-blue-500/15', text: 'text-blue-300', border: 'border-blue-500/30' },
    { key: 'info', label: 'Info', bg: 'bg-surface/60', text: 'text-muted', border: 'border-border' },
  ] as const;

  const runningTask = tasks.find((t) => ['running', 'dispatching', 'in_progress'].includes(t.status));
  const loop = run.configuration_json?.ai_assessment_loop as Record<string, unknown> | undefined;
  const iters = loop?.iteration_count ? Number(loop.iteration_count) : 0;

  return (
    <div className="glass-panel shrink-0 rounded-lg p-4">
      <div className="mb-3 flex items-center justify-between">
        <h2 className="flex items-center gap-2 text-[1rem] font-semibold text-cyan">
          <Activity size={15} /> Bevindingen overzicht
        </h2>
        <span className="text-[0.85rem] font-bold text-text">{total} totaal{iters > 0 ? ` · ${iters} iteraties` : ''}</span>
      </div>

      {/* Severity badges */}
      <div className="mb-4 flex flex-wrap gap-2">
        {sevConfig.map(({ key, label, bg, text, border }) => (
          bySev[key] > 0 && (
            <div key={key} className={cn('flex items-center gap-1.5 rounded-full border px-3 py-1', bg, border)}>
              <span className={cn('text-[1.05rem] font-bold', text)}>{bySev[key]}</span>
              <span className={cn('text-[0.77rem] font-semibold', text)}>{label}</span>
            </div>
          )
        ))}
        {total === 0 && <span className="text-[0.88rem] text-muted">Nog geen bevindingen</span>}
      </div>

      {/* Top findings */}
      {topFindings.length > 0 && (
        <div className="space-y-1.5">
          <p className="text-[0.75rem] font-bold uppercase tracking-wide text-muted">Belangrijkste bevindingen</p>
          {topFindings.map((f) => {
            const sev = (f.severity ?? 'info').toLowerCase();
            const colors: Record<string, string> = { critical: 'text-red', high: 'text-orange-400', medium: 'text-yellow-300', low: 'text-blue-300', info: 'text-muted' };
            return (
              <div key={f.id} className="flex items-start gap-2 rounded-md border border-border bg-surface/35 px-3 py-2">
                <span className={cn('mt-0.5 shrink-0 text-[0.75rem] font-bold uppercase', colors[sev] ?? 'text-muted')}>{sev}</span>
                <span className="text-[0.85rem] text-text">{f.title}</span>
              </div>
            );
          })}
        </div>
      )}

      {/* Running indicator */}
      {runningTask && (
        <div className="mt-3 flex items-center gap-2 rounded-md border border-cyan/20 bg-cyan/5 px-3 py-2">
          <span className="h-2 w-2 rounded-full bg-cyan animate-pulse" />
          <span className="text-[0.83rem] text-cyan">
            <strong>{runningTask.tool}</strong> loopt nu
          </span>
        </div>
      )}
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

function TaskResultsPanel({
  run, tasks, findings, selectedTaskId, onSelect,
}: {
  run: Run; tasks: Task[]; findings: Finding[];
  selectedTaskId: UUID | null; onSelect: (id: UUID) => void;
}) {
  const [expanded, setExpanded] = useState<string | null>(null);
  const ordered = [...tasks].sort((a, b) => (a.created_at ?? '') < (b.created_at ?? '') ? -1 : 1);
  const findingsByTask = useMemo(() => {
    const map: Record<string, number> = {};
    for (const f of findings) {
      // Tool matching via methodology_tags or tool field
      const tag = f.methodology_tags?.find((t: string) => tasks.some((tk) => tk.tool === t));
      if (tag) map[tag] = (map[tag] ?? 0) + 1;
    }
    return map;
  }, [findings, tasks]);

  const statusIcon = (status: string) => {
    if (['running', 'dispatching', 'in_progress'].includes(status))
      return <span className="h-2 w-2 rounded-full bg-cyan animate-pulse" />;
    if (status === 'completed') return <Check size={13} className="text-emerald-400" />;
    if (status === 'failed' || status === 'completed_with_errors')
      return <AlertTriangle size={13} className="text-amber" />;
    if (['queued', 'pending'].includes(status))
      return <span className="h-2 w-2 rounded-full bg-muted" />;
    return null;
  };

  const statusLabel = (status: string) => {
    const m: Record<string, string> = {
      completed: 'Klaar', failed: 'Fout', completed_with_errors: 'Overgeslagen',
      running: 'Loopt', dispatching: 'Start op', queued: 'Wacht', pending: 'Wacht',
    };
    return m[status] ?? status;
  };

  const statusColor = (status: string) => {
    if (['running', 'dispatching', 'in_progress'].includes(status)) return 'text-cyan';
    if (status === 'completed') return 'text-emerald-400';
    if (status === 'failed') return 'text-red';
    if (status === 'completed_with_errors') return 'text-amber';
    return 'text-muted';
  };

  return (
    <div className="glass-panel flex min-h-0 flex-col rounded-lg p-4">
      <div className="mb-3 flex items-center justify-between">
        <h2 className="flex items-center gap-2 text-[1rem] font-semibold text-cyan">
          <TerminalSquare size={15} /> Scanresultaten
        </h2>
        <span className="text-[0.82rem] text-muted">{ordered.length} tools</span>
      </div>
      <div className="flex-1 min-h-0 overflow-y-auto space-y-1 pr-1">
        {ordered.map((task) => {
          const info = TOOL_INFO[task.tool ?? ''];
          const taskFindings = findingsByTask[task.tool ?? ''] ?? 0;
          const isOpen = expanded === task.id;
          const isSelected = selectedTaskId === task.id;
          return (
            <div key={task.id} className={cn('rounded-md border transition-colors', isSelected ? 'border-cyan/30 bg-cyan/5' : 'border-border bg-surface/30')}>
              <button
                type="button"
                className="flex w-full items-center gap-3 px-3 py-2.5 text-left"
                onClick={() => { onSelect(task.id); setExpanded(isOpen ? null : task.id); }}
              >
                <span className="shrink-0 w-4 flex justify-center">{statusIcon(task.status ?? '')}</span>
                <span className="flex-1 font-mono text-[0.85rem] font-semibold text-text">{task.tool}</span>
                {taskFindings > 0 && (
                  <span className="shrink-0 rounded-full border border-amber/30 bg-amber/10 px-2 py-0.5 text-[0.72rem] font-bold text-amber">
                    {taskFindings} gevonden
                  </span>
                )}
                <span className={cn('shrink-0 text-[0.77rem] font-semibold', statusColor(task.status ?? ''))}>
                  {statusLabel(task.status ?? '')}
                </span>
                <ChevronRight size={12} className={cn('shrink-0 text-muted transition-transform', isOpen && 'rotate-90')} />
              </button>
              {isOpen && info && (
                <div className="border-t border-border bg-surface/20 px-3 py-2.5 text-[0.82rem] space-y-1">
                  <p><span className="font-semibold text-cyan">Waarom:</span> <span className="text-muted">{info.why}</span></p>
                  <p><span className="font-semibold text-cyan">Wat doet het:</span> <span className="text-muted">{info.what}</span></p>
                  <p><span className="font-semibold text-cyan">Impact:</span> <span className="text-muted">{info.impact}</span></p>
                </div>
              )}
              {isOpen && !info && task.target_id && (
                <div className="border-t border-border px-3 py-2 text-[0.78rem] text-muted">{task.target_id}</div>
              )}
            </div>
          );
        })}
        {ordered.length === 0 && (
          <p className="px-2 py-4 text-center text-[0.88rem] text-muted">Nog geen taken gestart.</p>
        )}
      </div>
    </div>
  );
}


function NarrationStrip({ run, tasks, findings }: { run: Run; tasks: Task[]; findings: Finding[] }) {
  const loop = run.configuration_json?.ai_assessment_loop as Record<string, unknown> | undefined;
  const isAiLoop = run.configuration_json?.run_mode === 'ai_loop' || loop?.run_mode === 'ai_loop';

  const runningTask = tasks.find((t) => ['running', 'dispatching', 'in_progress'].includes(t.status));
  const queuedTask = tasks.find((t) => ['queued', 'pending'].includes(t.status));
  const completedCount = tasks.filter((t) => t.status === 'completed').length;
  const highFindings = findings.filter((f) => ['critical', 'high'].includes(f.severity?.toLowerCase() ?? '')).length;
  const iterations = loop?.iteration_count ? Number(loop.iteration_count) : 0;
  const stopReason = loop?.stop_reason ? String(loop.stop_reason) : null;
  const lastAction = loop?.latest_next_action as Record<string, unknown> | null | undefined;

  let text = '';
  let color = 'text-muted';

  if (stopReason) {
    color = 'text-amber';
    const reasonMap: Record<string, string> = {
      stuck_no_new_signals: 'De AI-scan is gestopt: er zijn geen nieuwe signalen meer gevonden na meerdere iteraties.',
      max_iterations_reached: `De maximale iteratielimiet is bereikt (${iterations} iteraties). Scan voltooid.`,
      kill_switch: 'De scan is handmatig gestopt via de kill-switch.',
    };
    text = reasonMap[stopReason] ?? `Scan gestopt (${stopReason.replace(/_/g, ' ')}).`;
  } else if (runningTask) {
    color = 'text-cyan';
    const toolDescriptions: Record<string, string> = {
      'httpx': 'scant de website en verzamelt basisinformatie zoals links, headers en formulieren',
      'xss-extended': 'test op cross-site scripting (XSS) door payloads in te voeren op ontdekte parameters',
      'zap': 'voert een actieve beveiligingsscan uit op alle ontdekte pagina\'s',
      'nikto': 'controleert op bekende kwetsbaarheden in de webserver',
      'session-security': 'analyseert sessiecookies en authenticatiemechanismen',
      'content-discovery': 'zoekt naar verborgen pagina\'s en endpoints op de server',
      'headers-security': 'controleert of beveiligingsheaders correct zijn ingesteld',
      'ssrf-probe': 'test of de server ongeautoriseerde verzoeken naar interne diensten kan sturen',
      'ssti-probe': 'test op server-side template injectie',
      'auth-flow': 'analyseert het inlogproces en sessieafhandeling',
      'client-state': 'test op client-side state manipulatie en cookie-aanpassingen',
      'crypto-audit': 'controleert de TLS/SSL-configuratie en certificaatinstellingen',
    };
    const desc = toolDescriptions[runningTask.tool] ?? `voert beveiligingstests uit`;
    text = `🔍 ${runningTask.tool} ${desc} op ${(runningTask.target_id ?? '').replace(/^https?:\/\//, '').split('/')[0]}…`;
  } else if (queuedTask) {
    color = 'text-muted';
    text = `⏳ ${queuedTask.tool} staat in de wachtrij en start zodra het vorige resultaat verwerkt is.`;
  } else if (isAiLoop && lastAction) {
    color = 'text-emerald-300';
    const tool = String(lastAction.tool ?? '');
    text = highFindings > 0
      ? `✓ Iteratie ${iterations} voltooid — ${highFindings} hoog/kritiek bevinding(en) gevonden. De AI bepaalt de volgende stap op basis van de bewijzen.`
      : `✓ ${completedCount} tool(s) uitgevoerd in ${iterations} iteraties. De AI zoekt de meest zinvolle volgende stap${tool ? ` na ${tool}` : ''}.`;
  } else if (completedCount > 0) {
    color = 'text-emerald-300';
    text = `✓ Scan voltooid — ${completedCount} tool(s) uitgevoerd, ${findings.length} bevinding(en) gevonden.${highFindings > 0 ? ` Waarvan ${highFindings} hoog/kritiek.` : ''}`;
  } else if (!run || !tasks.length) {
    return null;
  }

  if (!text) return null;

  return (
    <div className={cn('shrink-0 rounded-lg border border-border bg-surface/40 px-4 py-2.5 text-[0.88rem] leading-5', color)}>
      {text}
    </div>
  );
}


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
  const maxIter = Number(loop?.max_iterations ?? 35);
  const iterations = Array.isArray(loop?.iterations) ? (loop.iterations as Record<string, unknown>[]) : [];

  const statusColor =
    loopStatus === 'stopped' || stopReason
      ? 'border-amber/40 bg-amber/10 text-amber'
      : loopStatus === 'waiting_for_execution'
        ? 'border-cyan/40 bg-cyan/10 text-cyan'
        : 'border-border bg-surface/40 text-muted';

  const latestIteration = iterations[iterations.length - 1] as Record<string, unknown> | undefined;
  const latestAction = latestIteration?.next_action as Record<string, unknown> | undefined;

  const loopProposals = proposals.filter(
    (p) => (p.metadata_json as Record<string, unknown>)?.proposal_kind === 'assessment_loop_next_action',
  );

  return (
    <div className="glass-panel min-h-[230px] rounded-lg p-4">
      <div className="mb-3 flex items-center justify-between gap-3">
        <h2 className="flex items-center gap-2 text-[1rem] font-semibold text-cyan">
          <BrainCircuit size={15} />
          AI Adaptive Loop
        </h2>
        <span className={cn('rounded-full border px-2 py-0.5 text-[0.77rem] font-bold uppercase', statusColor)}>
          {stopReason ? `stopped: ${stopReason.replace(/_/g, ' ')}` : loopStatus.replace(/_/g, ' ')}
        </span>
      </div>

      <div className="mb-3 grid grid-cols-3 gap-2 text-center">
        <div className="rounded-md border border-cyan/30 bg-cyan/5 px-2 py-2">
          <div className="text-[1rem] font-bold text-cyan">{depthLevel}</div>
          <div className="text-[0.72rem] text-cyan/70 font-medium truncate">{depthLabel}</div>
        </div>
        <div className="rounded-md border border-border bg-surface/40 px-2 py-2">
          <div className="text-[1.1rem] font-bold text-text">{stepCount}</div>
          <div className="text-[0.77rem] text-muted">Stappen</div>
        </div>
        <div className="rounded-md border border-border bg-surface/40 px-2 py-2">
          <div className="text-[1.1rem] font-bold text-text">{tasks.length}</div>
          <div className="text-[0.77rem] text-muted">Tools</div>
        </div>
      </div>

      {latestAction && (
        <div className="mb-3 rounded-md border border-cyan/20 bg-cyan/5 px-3 py-2 text-[0.85rem]">
          <div className="mb-1 flex items-center gap-2 font-semibold text-cyan">
            <ChevronRight size={13} />
            Last action: <span className="font-mono">{String(latestAction.tool ?? '')}</span>
          </div>
          {latestAction.reasoning && (
            <p className="line-clamp-2 text-muted">{String(latestAction.reasoning)}</p>
          )}
        </div>
      )}

      {iterations.length > 0 ? (
        <div className="max-h-[120px] overflow-y-auto space-y-1 pr-1">
          {[...iterations].reverse().map((it, idx) => {
            const na = it.next_action as Record<string, unknown> | undefined;
            const tool = String(na?.tool ?? '?');
            const status = String(it.status ?? 'unknown');
            const matching = loopProposals.find(
              (p) => String((p.metadata_json as Record<string, unknown>)?.iteration) === String(it.iteration),
            );
            const tone =
              status === 'completed' || matching?.status === 'approved'
                ? 'text-emerald-300'
                : status === 'queued'
                  ? 'text-cyan'
                  : 'text-muted';
            return (
              <div key={idx} className="flex items-center gap-2 rounded px-2 py-1 text-[0.82rem] hover:bg-surface/40">
                <TerminalSquare size={11} className={tone} />
                <span className={cn('font-mono font-semibold', tone)}>{tool}</span>
                <span className="flex-1 truncate text-muted">{na?.target ? String(na.target).replace(/^https?:\/\//, '') : ''}</span>
                <span className={cn('text-[0.75rem] font-bold uppercase', tone)}>{status}</span>
              </div>
            );
          })}
        </div>
      ) : (
        <EmptyBlock title="Loop starting" detail="Iterations will appear here as the AI selects tools." />
      )}
    </div>
  );
}


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

function AiSignalPanel({
  entries,
  proposals,
  busyAction,
  onReview,
}: {
  entries: AiSignalEntry[];
  proposals: AgentProposal[];
  busyAction: BusyAction;
  onReview: (proposal: AgentProposal, decision: 'approved' | 'rejected') => void;
}) {
  const feedRef = useRef<HTMLDivElement | null>(null);
  const entryKey = useMemo(() => entries.map((entry) => entry.id).join('|'), [entries]);
  const pendingProposalCount = proposals.filter((proposal) => isPendingProposal(proposal)).length;
  const streaming = busyAction === 'refresh';
  const signalStatus = pendingProposalCount > 0 ? 'Review' : streaming ? 'Fetching' : entries.length > 0 ? 'Live' : 'Idle';
  const statusTone =
    signalStatus === 'Review'
      ? 'border-amber/30 bg-amber/10 text-amber'
      : signalStatus === 'Idle'
        ? 'border-border bg-bg/50 text-muted'
        : 'border-cyan/25 bg-cyan/10 text-cyan';

  useEffect(() => {
    feedRef.current?.scrollTo({
      top: feedRef.current.scrollHeight,
      behavior: 'smooth',
    });
  }, [entryKey]);

  return (
    <div className="glass-panel flex min-h-[360px] flex-1 flex-col rounded-lg p-4 shadow-[0_0_30px_rgba(94,207,255,0.05)]">
      <div className="mb-4 flex shrink-0 items-center justify-between gap-3">
        <h2 className="flex items-center gap-2 text-[1rem] font-semibold text-cyan">
          <Bot size={15} />
          AI Signal
        </h2>
        <span className={cn('inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 text-[0.77rem] font-bold uppercase', statusTone)}>
          {signalStatus}
          {streaming ? (
            <Loader2 size={12} className="animate-spin" />
          ) : signalStatus === 'Idle' ? (
            <span className="h-1.5 w-1.5 rounded-full bg-muted/70" aria-hidden="true" />
          ) : (
            <span className="h-1.5 w-1.5 rounded-full bg-cyan shadow-[0_0_0.45rem_rgba(94,207,255,0.85)]" aria-hidden="true" />
          )}
        </span>
      </div>

      <div ref={feedRef} className="min-h-0 flex-1 space-y-3 overflow-y-auto pr-1">
        {entries.length === 0 ? (
          <EmptyBlock title="Listening for AI signal" detail="Reasoning records and review-gated proposals will stream here when the backend provides them." />
        ) : (
          entries.map((entry) => (
            <div key={entry.id} className={cn('rounded-md border bg-surface/45 p-3', entry.tone)}>
              <div className="mb-2 flex items-center justify-between gap-3">
                <span className="font-mono text-[0.77rem] font-semibold uppercase text-muted">{formatTime(entry.timestamp)}</span>
                <span className="rounded-full border border-border bg-bg/50 px-2 py-0.5 text-[0.7rem] font-bold uppercase text-muted">{entry.type}</span>
              </div>
              <p className="whitespace-pre-wrap text-[0.925rem] leading-5 text-text">
                {entry.text}
              </p>
              {entry.proposal && (
                <InlineProposalActions
                  proposal={entry.proposal}
                  busy={busyAction === `proposal-${entry.proposal.id}`}
                  disabled={busyAction !== null || !isPendingProposal(entry.proposal)}
                  onReview={onReview}
                />
              )}
            </div>
          ))
        )}
      </div>

      <div className="mt-3 flex shrink-0 items-center justify-between gap-3 border-t border-border pt-3 text-[0.85rem] text-muted">
        <span>{entries.length} signal entries</span>
        <span>{pendingProposalCount} proposal(s) awaiting operator review</span>
      </div>
    </div>
  );
}

function InlineProposalActions({
  proposal,
  busy,
  disabled,
  onReview,
}: {
  proposal: AgentProposal;
  busy: boolean;
  disabled: boolean;
  onReview: (proposal: AgentProposal, decision: 'approved' | 'rejected') => void;
}) {
  if (!isPendingProposal(proposal)) {
    const status = proposalStatus(proposal);
    return (
      <div className="mt-3 inline-flex items-center rounded-md border border-border bg-bg/40 px-2.5 py-1.5 text-[0.85rem] font-semibold text-muted">
        {status === 'approved' ? 'Approved' : status === 'rejected' ? 'Skipped' : status || 'Recorded'}
      </div>
    );
  }
  return (
    <div className="mt-3 flex flex-wrap gap-2">
      <button
        type="button"
        onClick={() => onReview(proposal, 'approved')}
        disabled={disabled}
        className="inline-flex items-center gap-2 rounded-md border border-emerald-400/30 bg-emerald-400/10 px-3 py-1.5 text-[0.925rem] font-semibold text-emerald-200 transition-colors hover:bg-emerald-400/15 disabled:cursor-not-allowed disabled:opacity-40"
        aria-label={`Approve AI proposal ${proposal.proposed_tool}`}
      >
        {busy ? <Loader2 size={14} className="animate-spin" /> : <Check size={14} />}
        Approve
      </button>
      <button
        type="button"
        onClick={() => onReview(proposal, 'rejected')}
        disabled={disabled}
        className="inline-flex items-center gap-2 rounded-md border border-border bg-bg/40 px-3 py-1.5 text-[0.925rem] font-semibold text-muted transition-colors hover:border-amber/40 hover:text-amber disabled:cursor-not-allowed disabled:opacity-40"
        aria-label={`Skip AI proposal ${proposal.proposed_tool}`}
      >
        <X size={14} />
        Skip
      </button>
    </div>
  );
}

function EvidencePanel({ aiInsights, findings }: { aiInsights: unknown; findings: Finding[] }) {
  const reasoningCount = isJsonMap(aiInsights) && Array.isArray(aiInsights.reasoning_records) ? aiInsights.reasoning_records.length : 0;
  return (
    <div className="glass-panel rounded-lg p-4">
      <div className="mb-4 flex items-center justify-between gap-3">
        <h2 className="flex items-center gap-2 text-[1rem] font-semibold text-cyan">
          <ShieldAlert size={15} />
          Evidence References
        </h2>
        <span className="text-[0.85rem] text-muted">{reasoningCount} reasoning records</span>
      </div>
      <div className="grid gap-2">
        {findings.slice(0, 4).map((finding) => (
          <div key={finding.id} className="rounded-md border border-border bg-surface/45 p-3">
            <div className="mb-1 flex items-center justify-between gap-2">
              <p className="truncate text-[0.925rem] font-semibold text-text">{finding.title}</p>
              <span className={cn('rounded-full px-2 py-0.5 text-[0.77rem] font-bold uppercase', statusTone(finding.severity))}>
                {finding.severity}
              </span>
            </div>
            <div className="mt-2 flex items-start gap-2 rounded-md border border-border/80 bg-bg/35 px-2.5 py-2">
              <div className="min-w-0 flex-1">
                <p className="text-[0.72rem] font-bold uppercase tracking-[0.14em] text-muted">Stored ref</p>
                <p className="mt-1 break-all font-mono text-[0.78rem] leading-4 text-muted">{finding.evidence_ref}</p>
              </div>
              <button
                type="button"
                onClick={() => void copyEvidenceReference(finding.evidence_ref)}
                className="inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-md border border-border bg-surface/70 text-muted transition-colors hover:border-cyan/40 hover:text-cyan"
                aria-label={`Copy evidence reference for ${finding.title}`}
                title="Copy evidence reference"
              >
                <Copy size={13} />
              </button>
            </div>
          </div>
        ))}
        {findings.length === 0 && <EmptyBlock title="No findings" detail="Stored evidence references appear here after backend findings are present." />}
      </div>
    </div>
  );
}

async function copyEvidenceReference(reference: string): Promise<void> {
  if (typeof navigator === 'undefined' || !navigator.clipboard || !reference) return;
  try {
    await navigator.clipboard.writeText(reference);
  } catch {
    // Clipboard access can be blocked by browser permissions; the visible ref remains selectable.
  }
}

function MiniMetric({ icon, label, value }: { icon: ReactNode; label: string; value: string | number }) {
  const numericValue = typeof value === 'number' ? value : null;
  const previousValueRef = useRef(numericValue);
  const [popped, setPopped] = useState(false);

  useEffect(() => {
    if (numericValue === null) return;
    const previousValue = previousValueRef.current;
    previousValueRef.current = numericValue;
    if (previousValue !== null && numericValue > previousValue) {
      setPopped(true);
      const timer = window.setTimeout(() => setPopped(false), 460);
      return () => window.clearTimeout(timer);
    }
    return undefined;
  }, [numericValue]);

  return (
    <div className="rounded-md border border-border bg-surface/45 p-3">
      <div className="mb-2 flex items-center gap-2 text-cyan">
        {icon}
        <span className="text-[0.77rem] font-bold uppercase">{label}</span>
      </div>
      <div className={cn('text-xl font-semibold text-text', popped && 'living-badge-pop')}>{value}</div>
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

function executionModeLabel(run: Run): string {
  const dispatchMode = stringValue(runtimeDispatch(run)?.last_dispatch_mode);
  if (dispatchMode && dispatchMode !== 'manual') {
    return `Automatic (${dispatchMode})`;
  }
  if (dispatchMode === 'manual' && isAutomaticRun(run)) {
    return 'Automatic requested; host manual';
  }
  if (isAutomaticRun(run)) {
    return 'Automatic chain';
  }
  return run.autonomous_mode ? 'AI assisted' : 'Manual';
}

function buildExecutionNotice(run: Run, tasks: Task[]): ExecutionNotice | null {
  const queuedCount = tasks.filter((task) => ['queued', 'requested'].includes(task.status)).length;
  const runningTask = tasks.find((task) => ['dispatching', 'running'].includes(task.status));
  const dispatchMode = stringValue(runtimeDispatch(run)?.last_dispatch_mode);
  const queuedTask = tasks.find((task) => ['queued', 'requested'].includes(task.status));

  if (runningTask) {
    const statusText =
      runningTask.status === 'dispatching' ? 'is being handed to the runner' : 'is running';
    return {
      title: 'Runner active',
      detail: `${runningTask.tool} ${statusText} against ${truncateMiddle(runningTask.target_id, 90)}.`,
      tone: 'border-emerald-400/25 bg-emerald-400/10 text-emerald-100',
    };
  }

  if (queuedCount > 0 && dispatchMode === 'manual' && isAutomaticRun(run)) {
    return {
      title: 'Queued, not running',
      detail: 'The run requested automatic dispatch, but the local API host reported manual dispatch mode. No worker is executing this check.',
      tone: 'border-amber/30 bg-amber/10 text-amber',
    };
  }

  if (queuedCount > 0 && isAutomaticRun(run)) {
    return {
      title: 'Queued, waiting for runner',
      detail: queuedTask
        ? `${queuedTask.tool} is queued. It has not started yet; use Start Queued Checks or verify the worker/dispatch mode if it remains queued.`
        : `${queuedCount} check(s) are queued. Mission Control is polling every 3s.`,
      tone: 'border-amber/30 bg-amber/10 text-amber',
    };
  }

  if (chainStatus(run.assessment_chain) === 'pending_phase_approval') {
    return {
      title: 'Approval required',
      detail: 'The current phase is waiting for an approval decision in the phase chain.',
      tone: 'border-amber/30 bg-amber/10 text-amber',
    };
  }

  return null;
}

function buildAiSignalEntries(
  run: Run,
  tasks: Task[],
  findings: Finding[],
  proposals: AgentProposal[],
  aiInsights: RunAiInsights | null,
): AiSignalEntry[] {
  const entries: AiSignalEntry[] = [
    {
      id: `run-${run.id}-${run.updated_at ?? 'updated'}`,
      type: 'status',
      timestamp: stringValue(run.updated_at) || new Date().toISOString(),
      text: `${profileName(run)} is ${statusLabel(runStatus(run))}. ${tasks.length} task(s), ${findings.length} finding(s), and ${proposals.length} AI proposal record(s) are bound to this run.`,
      tone: 'border-cyan/20',
    },
  ];

  for (const task of tasks.slice(0, 4)) {
    entries.push({
      id: `task-${task.id}-${task.updated_at ?? 'updated'}`,
      type: 'task',
      timestamp: stringValue(task.updated_at) || new Date().toISOString(),
      text: `${task.tool} ${statusLabel(taskStatus(task))} against ${truncateMiddle(task.target_id || 'recorded target', 86)}. Output stays bounded to stored task evidence.`,
      tone: ACTIVE_STATUSES.has(taskStatus(task)) ? 'border-cyan/25 bg-cyan/5' : 'border-border',
    });
  }

  for (const finding of findings.slice(0, 4)) {
    const severity = lowerValue(finding.severity) || 'info';
    entries.push({
      id: `finding-${finding.id}-${finding.created_at ?? 'created'}`,
      type: 'finding',
      timestamp: stringValue(finding.created_at) || new Date().toISOString(),
      text: `${titleCase(severity)} signal: ${finding.title || 'Recorded finding'} on ${truncateMiddle(finding.target_id, 82)}. Evidence ref ${finding.evidence_ref || 'recorded by backend'}.`,
      tone: severity === 'critical' ? 'border-red/35 bg-red/10' : 'border-amber/25 bg-amber/5',
    });
  }

  for (const reasoning of (aiInsights?.reasoning_records ?? []).slice(0, 3)) {
    const summary =
      reasoning.summary_text ||
      reasoning.action_text ||
      stringValue(reasoning.observations_json?.[0]) ||
      'AI reasoning record is available for operator review.';
    entries.push({
      id: `reasoning-${reasoning.id}-${reasoning.updated_at ?? 'updated'}`,
      type: 'reasoning',
      timestamp: stringValue(reasoning.updated_at) || new Date().toISOString(),
      text: clampText(summary, 260),
      tone: 'border-violet-300/25 bg-violet-300/5',
    });
  }

  for (const proposal of proposals.slice(0, 5)) {
    entries.push({
      id: `proposal-${proposal.id}-${proposal.updated_at ?? 'updated'}`,
      type: 'proposal',
      timestamp: stringValue(proposal.updated_at) || new Date().toISOString(),
      text: `Proposal: ${proposal.proposed_tool} on ${truncateMiddle(proposal.proposed_target, 80)}. ${clampText(proposal.reasoning_text || 'Review this proposal before any task can be queued.', 190)} Risk tier ${proposal.risk_tier}.`,
      tone: isPendingProposal(proposal) ? 'border-cyan/35 bg-cyan/10' : 'border-border',
      proposal,
    });
  }

  return entries
    .sort((left, right) => Date.parse(left.timestamp) - Date.parse(right.timestamp))
    .slice(-10);
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

function runtimeDispatch(run: Run): JsonMap | null {
  const dispatch = run.configuration_json?.runtime_dispatch;
  return isJsonMap(dispatch) ? dispatch : null;
}

function assessmentMode(run: Run): JsonMap | null {
  const assessment = run.configuration_json?.assessment_mode;
  return isJsonMap(assessment) ? assessment : null;
}

function buildMapNodes(inventory: InventorySnapshot | null, tasks: Task[], findings: Finding[], run: Run | null): MapNode[] {
  const normalized = inventory?.normalized_inventory_json;
  if (!isJsonMap(normalized)) return [];

  const hosts = readArray(normalized.hosts).map((host) => inventoryLabel(host, ['host', 'hostname', 'ip', 'address', 'id']));
  const endpoints = readArray(normalized.http_endpoints).map((endpoint) =>
    inventoryLabel(endpoint, ['url', 'endpoint', 'target', 'host', 'id']),
  );
  const services = readArray(normalized.services).map((service) => inventoryLabel(service, ['service_id', 'host', 'target', 'id']));
  const labels = [...hosts, ...endpoints, ...services].filter(Boolean);
  const uniqueLabels = Array.from(new Set(labels)).slice(0, 14);

  return uniqueLabels.map((label, index) => {
    const angle = (index / Math.max(uniqueLabels.length, 1)) * Math.PI * 2 - Math.PI / 2;
    const radius = index % 2 === 0 ? 95 : 118;
    const x = Math.round(260 + Math.cos(angle) * radius);
    const y = Math.round(135 + Math.sin(angle) * radius * 0.68);
    const matchingFindings = findings.filter((finding) => targetMatches(finding.target_id, label));
    return {
      id: label,
      label,
      type: label.startsWith('http') ? 'http' : 'target',
      state: nodeState(label, tasks, findings, run),
      findingCount: matchingFindings.length,
      maxSeverity: strongestSeverity(matchingFindings.map((finding) => finding.severity)),
      x,
      y,
    };
  });
}

function nodeState(label: string, tasks: Task[], findings: Finding[], run: Run | null): MapNode['state'] {
  if (findings.some((finding) => targetMatches(finding.target_id, label))) return 'finding';
  if (run && tasks.some((task) => isTaskActiveForRun(task, run) && targetMatches(task.target_id, label))) return 'active';
  if (tasks.some((task) => TERMINAL_STATUSES.has(task.status) && targetMatches(task.target_id, label))) return 'complete';
  return 'idle';
}

function targetMatches(candidate: string | null | undefined, label: string): boolean {
  if (!candidate) return false;
  const left = candidate.toLowerCase();
  const right = label.toLowerCase();
  return left.includes(right) || right.includes(left);
}

function inventoryLabel(value: unknown, keys: string[]): string {
  if (typeof value === 'string') return value;
  if (!isJsonMap(value)) return '';
  for (const key of keys) {
    const candidate = value[key];
    if (typeof candidate === 'string' && candidate.trim()) {
      return candidate.trim();
    }
  }
  return '';
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

function buildMissionStatus(
  run: Run,
  tasks: Task[],
  proposals: AgentProposal[],
  currentPhase: PhaseView | null,
): MissionStatus {
  const activeTask = tasks.find((task) => isTaskActiveForRun(task, run)) ?? null;
  const queuedTask = tasks.find((task) => isTaskQueuedForRun(task, run)) ?? null;
  const pendingProposal = proposals.find((proposal) => isPendingProposal(proposal)) ?? null;
  const gaps = taskGapSummary(tasks, run);
  const terminal = isRunTerminal(run);
  const dispatchMode = stringValue(runtimeDispatch(run)?.last_dispatch_mode);
  const phaseSuffix = currentPhase ? ` ${currentPhase.label} remains ${statusLabel(currentPhase.status)}.` : '';

  if (activeTask) {
    return {
      title: `${activeTask.tool} is running`,
      detail: `${activeTask.tool} is executing against ${truncateMiddle(activeTask.target_id || 'the selected target', 110)}. Output and AI Signal update from backend evidence, not from local UI guesses.${phaseSuffix}`,
      operatorAction: null,
      tone: 'live',
      currentTask: activeTask,
      nextTask: nextTaskAfter(tasks, activeTask, run),
    };
  }

  if (queuedTask && !terminal) {
    const manualMode = dispatchMode === 'manual';
    return {
      title: `${queuedTask.tool} is queued, not running`,
      detail: manualMode
        ? `${queuedTask.tool} is waiting because the backend reported manual dispatch mode. No runner is executing this check yet, so the next phase cannot open.${phaseSuffix}`
        : `${queuedTask.tool} is accepted in the backend ledger but has not started yet. The next phase cannot open until this queued check runs, fails, or is accepted as a gap.${phaseSuffix}`,
      operatorAction: manualMode
        ? 'Start a worker or switch TASK_DISPATCH_MODE to inline/dramatiq for local testing; the UI button cannot execute tasks while the backend is manual.'
        : 'Click Start queued check. If it stays queued after that, the worker/dispatch lane is not taking tasks.',
      tone: 'waiting',
      currentTask: queuedTask,
      nextTask: nextTaskAfter(tasks, queuedTask, run),
    };
  }

  if (pendingProposal) {
    return {
      title: `${pendingProposal.proposed_tool} needs operator review`,
      detail: `AI selected ${pendingProposal.proposed_tool} for ${truncateMiddle(pendingProposal.proposed_target || 'the selected target', 110)}, but it is review-gated. No active or intrusive step runs until it is approved.`,
      operatorAction: 'Review the proposal in AI Signal before the mission can continue that branch.',
      tone: 'review',
      currentTask: null,
      nextTask: null,
    };
  }

  if (gaps.total > 0) {
    return {
      title: terminal ? 'Mission finished with gaps' : 'Mission has a coverage gap',
      detail: `${gaps.failed} check(s) failed and ${gaps.notRun} check(s) did not run. The chain keeps those gaps visible; a later phase only opens when the current phase boundary is finished or deliberately accepted with gaps.${phaseSuffix}`,
      operatorAction: terminal ? 'Review failed/not-run checks before treating coverage as complete.' : null,
      tone: 'gap',
      currentTask: null,
      nextTask: null,
    };
  }

  if (terminal) {
    return {
      title: 'Mission completed',
      detail: 'All backend-visible checks for this selected run are terminal. Findings, evidence references, and reports should now be reviewed from stored evidence.',
      operatorAction: null,
      tone: 'done',
      currentTask: null,
      nextTask: null,
    };
  }

  if (currentPhase) {
    return {
      title: `${currentPhase.label} is ${statusLabel(currentPhase.status)}`,
      detail: 'Mission Control is waiting for the backend to expose the next task, proposal, or phase transition.',
      operatorAction: ['queued', 'requested'].includes(runStatus(run)) ? 'Use Start Queued Checks if dispatch did not begin.' : null,
      tone: 'waiting',
      currentTask: null,
      nextTask: null,
    };
  }

  return {
    title: `${profileName(run)} is ${statusLabel(runStatus(run))}`,
    detail: 'The selected run is loaded, but there is no active backend task or proposal attached to it right now.',
    operatorAction: ['queued', 'requested'].includes(runStatus(run)) ? 'Use Start Queued Checks to dispatch accepted work.' : null,
    tone: 'waiting',
    currentTask: null,
    nextTask: null,
  };
}

function nextTaskAfter(tasks: Task[], currentTask: Task, run: Run): Task | null {
  const sorted = [...tasks].sort((left, right) => Date.parse(left.created_at) - Date.parse(right.created_at));
  const index = sorted.findIndex((task) => task.id === currentTask.id);
  if (index < 0) return null;
  return sorted.slice(index + 1).find((task) => !TERMINAL_STATUSES.has(taskDisplayStatus(task, run).toLowerCase())) ?? null;
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

function taskInputPreview(task: Task): string {
  const payload = {
    task_id: task.id,
    tool: task.tool,
    target: task.target_id,
    status: task.status,
    params: sanitizeJson(task.params_json),
  };
  return JSON.stringify(payload, null, 2);
}

function sanitizeJson(value: unknown, depth = 0): unknown {
  if (depth > 6) return '[truncated-depth]';
  if (Array.isArray(value)) return value.slice(0, 50).map((item) => sanitizeJson(item, depth + 1));
  if (!value || typeof value !== 'object') {
    return typeof value === 'string' ? redactSensitiveText(value) : value;
  }
  const result: Record<string, unknown> = {};
  for (const [key, nested] of Object.entries(value as Record<string, unknown>)) {
    if (isSensitiveKey(key)) {
      result[key] = '[redacted]';
    } else if (key === 'limits' || key === 'assessment_loop' || key === 'ai_proposal') {
      result[key] = sanitizeJson(nested, depth + 1);
    } else {
      result[key] = sanitizeJson(nested, depth + 1);
    }
  }
  return result;
}

function isSensitiveKey(key: string): boolean {
  return /(secret|password|passwd|token|cookie|credential|api[_-]?key|authorization|bearer|session_value)/i.test(key);
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

function isTaskGap(task: Task, run: Run): boolean {
  const displayStatus = taskDisplayStatus(task, run).toLowerCase();
  return displayStatus === 'failed' || displayStatus === 'not_run';
}

function taskStatusNote(task: Task, run: Run): string | null {
  if (taskDisplayStatus(task, run) === 'not_run') {
    return 'Run is terminal; backend left this check queued/requested, so Mission Control treats it as not run.';
  }
  if (taskStatus(task) === 'failed') {
    return 'This failed check is why the chain can be completed with gaps.';
  }
  return null;
}

function taskGapSummary(tasks: Task[], run: Run): { failed: number; notRun: number; total: number } {
  const failed = tasks.filter((task) => taskStatus(task) === 'failed').length;
  const notRun = tasks.filter((task) => taskDisplayStatus(task, run) === 'not_run').length;
  return { failed, notRun, total: failed + notRun };
}

function nodeColor(state: MapNode['state'], severity: string | null = null): string {
  if (state === 'finding') return badgeColor(severity);
  if (state === 'active') return '#5ecfff';
  if (state === 'complete') return '#34d399';
  return '#78b1d4';
}

function nodeStroke(node: MapNode): string {
  if (node.state === 'finding') return node.maxSeverity === 'critical' ? 'rgba(239,68,68,0.72)' : 'rgba(251,191,36,0.58)';
  if (node.state === 'complete') return 'rgba(52,211,153,0.38)';
  if (node.state === 'active') return 'rgba(94,207,255,0.48)';
  return 'rgba(94,207,255,0.22)';
}

function badgeColor(severity: string | null): string {
  const value = severity?.toLowerCase();
  if (value === 'critical') return '#ef4444';
  if (value === 'high') return '#f59e0b';
  if (value === 'medium') return '#fde047';
  if (value === 'low') return '#5ecfff';
  return '#f87171';
}

function strongestSeverity(severities: string[]): string | null {
  const order = ['critical', 'high', 'medium', 'low', 'info'];
  const normalized = severities.map((severity) => severity.toLowerCase());
  return order.find((severity) => normalized.includes(severity)) ?? null;
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

function titleCase(value: string): string {
  return value
    .replace(/[_-]/g, ' ')
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function clampText(value: string, maxLength: number): string {
  const trimmed = value.replace(/\s+/g, ' ').trim();
  if (trimmed.length <= maxLength) return trimmed;
  return `${trimmed.slice(0, maxLength - 3).trimEnd()}...`;
}

function truncateMiddle(value: string, maxLength: number): string {
  if (value.length <= maxLength) return value;
  const head = Math.max(4, Math.floor((maxLength - 3) / 2));
  const tail = Math.max(4, maxLength - 3 - head);
  return `${value.slice(0, head)}...${value.slice(-tail)}`;
}

function chainLabel(mode: string): string {
  const map: Record<string, string> = {
    'FULL-EXTERNAL-WEB': 'Full External Web Pentest',
    'FULL-INTERNAL-LAN': 'Full Internal LAN Pentest',
    'FULL-AD-ASSESSMENT': 'Full Active Directory Assessment',
    'FULL-MOBILE-ANDROID': 'Full Android Mobile Assessment',
    'FULL-CLOUD-AWS': 'Full Cloud AWS Assessment',
  };
  return map[mode] ?? mode;
}

function formatDate(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString(undefined, {
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  });
}

function formatTime(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '--:--:--';
  return date.toLocaleTimeString(undefined, {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
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

function ExploitChain({ run, tasks, findings }: { run: Run; tasks: Task[]; findings: Finding[] }) {
  const [expanded, setExpanded] = useState<string | null>(null);

  // Build chain steps from tasks + findings
  const steps = useMemo(() => {
    const findingsByTask: Record<string, Finding[]> = {};
    // Map findings to tasks via source_finding_id or by creation time proximity
    for (const f of findings) {
      const taskId = (f as Record<string, unknown>).task_id as string | undefined;
      if (taskId) {
        (findingsByTask[taskId] ??= []).push(f);
      }
    }

    return tasks
      .filter(t => t.status === 'completed' || t.status === 'failed')
      .map((task, idx) => {
        const params = (task.params_json ?? {}) as Record<string, unknown>;
        const nba = (params.next_best_action_selector ?? {}) as Record<string, unknown>;
        const triggers = Array.isArray(nba.matched_triggers) ? nba.matched_triggers as string[] : [];
        const source = String(params.source ?? nba.source ?? '');
        const taskFindings = findingsByTask[task.id] ?? [];

        // Highest severity finding for this task
        const topFinding = [...taskFindings].sort((a, b) => {
          const order: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
          return (order[a.severity] ?? 5) - (order[b.severity] ?? 5);
        })[0];

        return {
          idx,
          task,
          triggers,
          source,
          taskFindings,
          topFinding,
          isLast: idx === tasks.filter(t => t.status === 'completed' || t.status === 'failed').length - 1,
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
          {steps.map(({ idx, task, triggers, source, taskFindings, topFinding, isLast }) => {
            const isExpanded = expanded === task.id;
            const hasCritical = taskFindings.some(f => f.severity === 'critical');
            const hasHigh = taskFindings.some(f => f.severity === 'high');
            const dotColor = hasCritical ? SEVERITY_DOT.critical : hasHigh ? SEVERITY_DOT.high : taskFindings.length ? SEVERITY_DOT.medium : 'bg-border';

            const why = triggers.length
              ? `omdat ${triggers.slice(0, 2).join(' + ')} ${triggers.length > 2 ? `+${triggers.length - 2}` : ''} gevonden`
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
                  <div className="flex items-center gap-2">
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
                    <span className="ml-auto text-[0.72rem] text-muted">{why}</span>
                  </div>

                  {/* Top finding preview */}
                  {topFinding && (
                    <div className="mt-1 text-[0.78rem] text-muted truncate">
                      {topFinding.title}
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
