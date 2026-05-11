import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import {
  Activity,
  AlertTriangle,
  Bot,
  Check,
  CircleStop,
  Copy,
  FileText,
  Loader2,
  Map,
  MonitorPlay,
  Play,
  RefreshCw,
  ShieldAlert,
  TerminalSquare,
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

const isRunTerminal = (run: Run): boolean => {
  const status = run.status.toLowerCase();
  return TERMINAL_STATUSES.has(status) || chainStatus(run.assessment_chain).toLowerCase() === 'completed_with_gaps';
};

const isTaskActiveForRun = (task: Task, run: Run): boolean => !isRunTerminal(run) && RUNNING_STATUSES.has(task.status);
const isTaskQueuedForRun = (task: Task, run: Run): boolean => !isRunTerminal(run) && QUEUED_STATUSES.has(task.status);

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
  const selectRun = useAegisStore((state) => state.selectRun);

  const [selectedTaskId, setSelectedTaskId] = useState<UUID | null>(null);
  const [taskDetails, setTaskDetails] = useState<Record<UUID, TaskDetail>>({});
  const [busyAction, setBusyAction] = useState<BusyAction>(null);
  const [actionMessage, setActionMessage] = useState<string | null>(null);
  const [cinemaOpen, setCinemaOpen] = useState(false);
  const [launchArrival, setLaunchArrival] = useState(() => readIntakeLaunchState(location.state));
  const refreshInFlightRef = useRef(false);

  const proposals = useMemo(() => aiInsights?.proposals ?? [], [aiInsights?.proposals]);
  const chain = selectedRun?.assessment_chain ?? null;
  const phases = useMemo(() => buildPhaseViews(chain), [chain]);
  const currentPhase = phases.find((phase) => phase.current) ?? phases[0] ?? null;
  const mapNodes = useMemo(() => buildMapNodes(inventory, tasks, findings, selectedRun), [inventory, selectedRun, tasks, findings]);
  const activeTaskCount = selectedRun ? tasks.filter((task) => isTaskActiveForRun(task, selectedRun)).length : 0;
  const executionNotice = useMemo(
    () => (selectedRun ? buildExecutionNotice(selectedRun, tasks) : null),
    [selectedRun, tasks],
  );
  const missionStatus = useMemo(
    () => (selectedRun ? buildMissionStatus(selectedRun, tasks, proposals, currentPhase) : null),
    [currentPhase, proposals, selectedRun, tasks],
  );
  const pendingProposalCount = proposals.filter((proposal) => proposal.status === 'pending').length;
  const activeRuns = useMemo(
    () => runs.filter((run) => ['queued', 'requested', 'dispatching', 'running'].includes(run.status)),
    [runs],
  );
  const canCancel = Boolean(selectedRun && !TERMINAL_STATUSES.has(selectedRun.status));
  const selectedRunIsAutomatic = Boolean(selectedRun && isAutomaticRun(selectedRun));
  const selectedRunIsAiLoop = Boolean(selectedRun && isAiLoopRun(selectedRun));
  const selectedRunIsWargaming = Boolean(selectedRun && isWargamingRun(selectedRun));
  const canDispatch = Boolean(selectedRun && ['queued', 'requested'].includes(selectedRun.status));
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
  const isPolling = Boolean(selectedRun && ACTIVE_STATUSES.has(selectedRun.status));

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
    const shouldPollDetail = selectedRun ? !TERMINAL_STATUSES.has(selectedRun.status) || !TERMINAL_STATUSES.has(consoleTask.status) : false;
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

  async function handleAutopilotContinue() {
    if (!selectedRun) return;
    setBusyAction('autopilot-continue');
    setActionMessage(null);
    try {
      await advanceAssessmentLoop(selectedRun.id, 'Continued from v2 Autopilot Workbench.');
      await refreshRun(selectedRun.id, { quiet: true });
      setActionMessage('AI loop continued through the existing assessment-loop endpoint.');
    } catch (error) {
      setError(errorMessage(error));
      setActionMessage('AI loop continue failed.');
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
    <section className="flex min-h-full flex-col gap-5">
      <div className="flex flex-col gap-4">
        <div className="min-w-0">
          <div className="mb-2 flex flex-wrap items-center gap-2">
            <span className={cn('rounded-full px-2.5 py-1 text-[0.85rem] font-bold uppercase', statusTone(selectedRun.status))}>
              {selectedRun.status}
            </span>
            {isPolling && (
              <span className="inline-flex items-center gap-1.5 rounded-full border border-cyan/20 bg-cyan/10 px-2.5 py-1 text-[0.85rem] font-medium text-cyan">
                <span className="h-1.5 w-1.5 rounded-full bg-cyan animate-pulse-fast" />
                polling every 3s
              </span>
            )}
          </div>
          <h1 className="text-2xl font-semibold tracking-normal">Mission Control</h1>
          <p className="mt-2 max-w-3xl text-[1rem] leading-6 text-muted">
            {selectedRun.profile.name} is backed by run {compactId(selectedRun.id)}. Tasks, proposals, phase state, findings,
            and map nodes are rendered from backend run data.
          </p>
        </div>

        <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-5">
          <button
            type="button"
            onClick={() => void refreshRun()}
            disabled={busyAction !== null}
            className="inline-flex min-h-10 items-center justify-center gap-2 rounded-md border border-border bg-surface/70 px-3 py-2 text-[0.9rem] font-semibold text-text transition-colors hover:border-cyan/40 hover:text-cyan disabled:cursor-not-allowed disabled:opacity-50"
          >
            <RefreshCw size={15} className={busyAction === 'refresh' ? 'animate-spin' : ''} />
            Refresh
          </button>
          <Link
            to="/findings"
            className="inline-flex min-h-10 items-center justify-center gap-2 rounded-md border border-border bg-surface/70 px-3 py-2 text-[0.9rem] font-semibold text-text transition-colors hover:border-cyan/40 hover:text-cyan"
          >
            <FileText size={15} />
            View Findings
          </Link>
          <button
            type="button"
            onClick={() => setCinemaOpen(true)}
            className="inline-flex min-h-10 items-center justify-center gap-2 rounded-md border border-cyan/30 bg-cyan/10 px-3 py-2 text-[0.9rem] font-semibold text-cyan transition-colors hover:bg-cyan/15"
          >
            <MonitorPlay size={15} />
            Cinema Mode
          </button>
          <button
            type="button"
            onClick={() => void handleDispatch()}
            disabled={!canDispatch || busyAction !== null}
            title={selectedRunIsAutomatic ? 'Uses the backend dispatch endpoint; approvals, scope, and kill-switch gates are still enforced.' : undefined}
            className="inline-flex min-h-10 items-center justify-center gap-2 rounded-md border border-emerald-400/30 bg-emerald-400/10 px-3 py-2 text-[0.9rem] font-semibold text-emerald-200 transition-colors hover:bg-emerald-400/15 disabled:cursor-not-allowed disabled:opacity-40"
          >
            <Play size={15} />
            {selectedRunIsAutomatic ? 'Start Queued Checks' : 'Run Queued Checks Now'}
          </button>
          <button
            type="button"
            onClick={() => void handleCancel()}
            disabled={!canCancel || busyAction !== null}
            className="inline-flex min-h-10 items-center justify-center gap-2 rounded-md border border-red/30 bg-red/10 px-3 py-2 text-[0.9rem] font-semibold text-red transition-colors hover:bg-red/15 disabled:cursor-not-allowed disabled:opacity-40"
          >
            <CircleStop size={15} />
            Kill Run
          </button>
        </div>
      </div>

      <ActiveWorkStrip
        activeRuns={activeRuns}
        selectedRun={selectedRun}
        selectedRunId={selectedRun.id}
        selectedTasks={tasks}
        onSelectRun={selectRun}
      />

      <MissionNowPanel
        status={missionStatus ?? buildMissionStatus(selectedRun, tasks, proposals, currentPhase)}
        run={selectedRun}
        tasks={tasks}
        currentPhase={currentPhase}
        canDispatch={canDispatch}
        busy={busyAction === 'dispatch'}
        onDispatch={() => void handleDispatch()}
      />

      {actionMessage && (
        <div className="rounded-md border border-cyan/20 bg-cyan/10 px-4 py-3 text-[1rem] text-cyan">
          {actionMessage}
        </div>
      )}

      {executionNotice && (
        <div className={cn('rounded-md border px-4 py-3 text-[0.95rem] leading-5', executionNotice.tone)}>
          <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
            <span className="font-semibold">{executionNotice.title}</span>
            <span>{executionNotice.detail}</span>
          </div>
        </div>
      )}

      {selectedRunIsWargaming && (
        <section className="rounded-lg border border-amber/30 bg-amber/10 p-4">
          <div className="flex flex-wrap items-start gap-3">
            <ShieldAlert size={18} className="mt-0.5 shrink-0 text-amber" />
            <div className="min-w-0">
              <h2 className="text-[1.08rem] font-semibold text-text">Lab-only wargaming simulation</h2>
              <p className="mt-1 text-[0.925rem] leading-5 text-muted">
                This run is restricted to verified isolated lab or digital-twin evidence. Production gates, scope
                boundaries, credential protections, runtime binding, and kill-switch controls remain active.
              </p>
            </div>
          </div>
        </section>
      )}

      <LiveCommandConsole
        run={selectedRun}
        task={consoleTask}
        detail={consoleTask ? taskDetails[consoleTask.id] : undefined}
      />

      {launchArrival && (
        <div className="overflow-hidden rounded-lg border border-cyan/30 bg-cyan/10 shadow-[0_0_24px_rgba(94,207,255,0.16)] animate-[mission-materialize_0.75s_ease-out]">
          <div className="flex flex-col gap-3 px-4 py-4 md:flex-row md:items-center md:justify-between">
            <div className="min-w-0">
              <p className="text-[0.77rem] font-bold uppercase tracking-widest text-cyan/75">Mission materialized</p>
              <h2 className="mt-1 truncate text-[1.15rem] font-semibold text-text">
                {launchArrival.assessmentType || selectedRun.profile.name}
              </h2>
              <p className="mt-1 truncate text-[0.925rem] text-muted">
                {launchArrival.target || 'Scope bound'} · {launchArrival.depth || executionModeLabel(selectedRun)}
              </p>
            </div>
            <div className="flex shrink-0 items-center gap-2 rounded-full border border-cyan/20 bg-bg/50 px-3 py-1.5 text-[0.85rem] font-semibold text-cyan">
              <span className="h-1.5 w-1.5 rounded-full bg-cyan animate-pulse" />
              Scan map nodes incoming
            </div>
          </div>
        </div>
      )}

      {selectedRunIsAiLoop ? (
        <AutopilotWorkbench
          run={selectedRun}
          tasks={tasks}
          findings={findings}
          proposals={proposals}
          aiInsights={aiInsights}
          busyAction={busyAction}
          onContinue={() => void handleAutopilotContinue()}
          onReview={(proposal, decision) => void handleProposalReview(proposal, decision)}
        />
      ) : (
        <div className="grid min-h-[640px] gap-4 xl:grid-cols-[minmax(240px,0.85fr)_minmax(360px,1.2fr)_minmax(280px,0.95fr)]">
          <div className="flex min-h-0 flex-col gap-4">
            <OperationsSummary
              run={selectedRun}
              taskCount={tasks.length}
              activeTaskCount={activeTaskCount}
              findingCount={findings.length}
              pendingProposalCount={pendingProposalCount}
            />
            <TaskList
              run={selectedRun}
              tasks={tasks}
              selectedTaskId={consoleTask?.id ?? null}
              onSelect={setSelectedTaskId}
            />
          </div>

          <div className="flex min-h-0 flex-col gap-4">
            <ScanMap nodes={mapNodes} inventory={inventory} materialize={Boolean(launchArrival)} />
            <PhaseChain
              chain={chain}
              run={selectedRun}
              tasks={tasks}
              phases={phases}
              currentPhase={currentPhase}
              canApprovePhase={canApprovePhase}
              busy={busyAction === 'phase'}
              onApprove={() => void handleApprovePhase()}
            />
          </div>

          <div className="flex min-h-0 flex-col gap-4">
            <AiSignalPanel
              entries={buildAiSignalEntries(selectedRun, tasks, findings, proposals, aiInsights)}
              proposals={proposals}
              busyAction={busyAction}
              onReview={(proposal, decision) => void handleProposalReview(proposal, decision)}
            />
            <EvidencePanel aiInsights={aiInsights} findings={findings} />
          </div>
        </div>
      )}

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
              : ['queued', 'requested'].includes(selectedRun.status)
                ? 'This run is queued, but no backend task is running yet. Use Start Queued Checks if automatic dispatch did not begin.'
              : selectedRunIsActive
                ? 'This selected run is active, but the backend has not exposed a current task yet.'
                : `${activeRuns.length} other run(s) are active. Select one below to inspect what is moving.`}
          </p>
        </div>

        <div className="grid w-full gap-2 lg:w-auto lg:min-w-[22rem]">
          {activeRuns.slice(0, 4).map((run) => {
            const isSelected = run.id === selectedRunId;
            const activeTask = (run.tasks ?? []).find((task) => RUNNING_STATUSES.has(task.status)) ??
              (run.tasks ?? []).find((task) => QUEUED_STATUSES.has(task.status));
            const taskStateCopy = activeTask
              ? QUEUED_STATUSES.has(activeTask.status)
                ? `${activeTask.tool} queued (not running)`
                : `${activeTask.tool} is ${activeTask.status}`
              : run.status;
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
                  <span className="block truncate text-[0.925rem] font-semibold">{run.profile.name}</span>
                  <span className="block truncate font-mono text-[0.8rem] text-muted">
                    {compactId(run.id)} · {taskStateCopy}
                  </span>
                </span>
                <span className={cn('shrink-0 rounded-full px-2 py-0.5 text-[0.72rem] font-bold uppercase', statusTone(run.status))}>
                  {isSelected ? 'open' : run.status}
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
            <StatusChip label="Run" value={statusLabel(run.status)} />
            {currentPhase && <StatusChip label="Phase" value={`${currentPhase.label} · ${statusLabel(currentPhase.status)}`} />}
            {status.currentTask && <StatusChip label="Current" value={`${status.currentTask.tool} · ${statusLabel(status.currentTask.status)}`} />}
            {status.nextTask && <StatusChip label="Next" value={`${status.nextTask.tool} · ${statusLabel(status.nextTask.status)}`} />}
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
status > ${statusLabel(run.status)}
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
  const taskStatus = displayStatus.toLowerCase();
  const live = RUNNING_STATUSES.has(task.status.toLowerCase()) && !isRunTerminal(run);

  return (
    <section className="rounded-lg border border-cyan/25 bg-[#02060c]/95 p-4 shadow-[0_0_34px_rgba(94,207,255,0.12)]">
      <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
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

      <div className="grid gap-3 lg:grid-cols-[minmax(0,0.9fr)_minmax(0,1.5fr)]">
        <div className="min-w-0 rounded-md border border-border bg-black/60 p-3">
          <p className="text-[0.75rem] font-bold uppercase tracking-widest text-cyan/75">Command</p>
          <pre className="mt-2 overflow-auto whitespace-pre-wrap break-words font-mono text-[0.88rem] leading-5 text-[#d8f3ff]">
            {command}
          </pre>
          <div className="mt-3 grid gap-2 text-[0.85rem] text-muted">
            <KeyValue label="Tool" value={task.tool} />
            <KeyValue label="Target" value={truncateMiddle(task.target_id || 'No target', 72)} />
            <KeyValue label="Backend status" value={task.status} />
            <KeyValue label="Exit code" value={execution?.exit_code === null || execution?.exit_code === undefined ? 'pending' : String(execution.exit_code)} />
          </div>
          <p className="mt-4 text-[0.75rem] font-bold uppercase tracking-widest text-cyan/75">Sanitized Input</p>
          <pre className="mt-2 max-h-[14rem] overflow-auto whitespace-pre-wrap break-words rounded border border-border bg-[#030913] p-3 font-mono text-[0.78rem] leading-5 text-[#aac1d8]">
            {input}
          </pre>
        </div>

        <div className="min-w-0 rounded-md border border-border bg-black/70 p-3">
          <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
            <p className="text-[0.75rem] font-bold uppercase tracking-widest text-cyan/75">
              {taskStatus === 'failed' ? 'Stdout / Stderr' : 'Stdout'}
            </p>
            <span className="font-mono text-[0.75rem] text-muted">
              {detail?.stdout_snapshot?.source || 'task-detail'} {detail?.stdout_snapshot?.stream_terminal === false ? '// streaming' : '// snapshot'}
            </span>
          </div>
          <pre className="min-h-[18rem] max-h-[32rem] overflow-auto whitespace-pre-wrap break-words rounded border border-border bg-[#010409] p-4 font-mono text-[0.9rem] leading-6 text-[#c8d6e5]">
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
                    {displayStatus !== task.status && (
                      <span className="rounded-full border border-border bg-bg/40 px-2 py-0.5 text-[0.7rem] font-semibold uppercase text-muted">
                        backend: {task.status}
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
    <div className={cn('glass-panel min-h-[340px] rounded-lg p-4', materialize && 'animate-[mission-materialize_0.8s_ease-out]')}>
      <div className="mb-4 flex items-center justify-between gap-3">
        <h2 className="flex items-center gap-2 text-[1rem] font-semibold text-cyan">
          <Map size={15} />
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
        <div className="relative h-[270px] overflow-hidden rounded-md border border-border bg-[#02060c]">
          <svg viewBox="0 0 520 270" role="img" aria-label="Run inventory scan map" className="h-full w-full">
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
  const entryKey = useMemo(() => entries.map((entry) => `${entry.id}:${entry.text}`).join('|'), [entries]);
  const totalCharacters = useMemo(() => entries.reduce((total, entry) => total + entry.text.length, 0), [entries]);
  const [typedCharacters, setTypedCharacters] = useState(0);
  const isTyping = typedCharacters < totalCharacters;
  const pendingProposalCount = proposals.filter((proposal) => proposal.status === 'pending').length;
  const streaming = isTyping || busyAction === 'refresh';
  const signalStatus = pendingProposalCount > 0 ? 'Review' : streaming ? 'Streaming' : entries.length > 0 ? 'Live' : 'Idle';
  const statusTone =
    signalStatus === 'Review'
      ? 'border-amber/30 bg-amber/10 text-amber'
      : signalStatus === 'Idle'
        ? 'border-border bg-bg/50 text-muted'
        : 'border-cyan/25 bg-cyan/10 text-cyan';

  useEffect(() => {
    setTypedCharacters(0);
  }, [entryKey]);

  useEffect(() => {
    if (typedCharacters >= totalCharacters) return undefined;
    const timer = window.setTimeout(() => {
      setTypedCharacters((current) => Math.min(totalCharacters, current + 1));
    }, AI_SIGNAL_TYPE_MS);
    return () => window.clearTimeout(timer);
  }, [totalCharacters, typedCharacters]);

  useEffect(() => {
    feedRef.current?.scrollTo({
      top: feedRef.current.scrollHeight,
      behavior: 'smooth',
    });
  }, [entryKey, typedCharacters]);

  let consumedCharacters = 0;

  return (
    <div className="glass-panel ai-signal-panel flex min-h-[360px] flex-col rounded-lg p-4">
      <div className="mb-4 flex items-center justify-between gap-3">
        <h2 className="flex items-center gap-2 text-[1rem] font-semibold text-cyan">
          <Bot size={15} />
          AI Signal
        </h2>
        <span className={cn('inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 text-[0.77rem] font-bold uppercase', statusTone)}>
          {signalStatus}
          {streaming ? (
            <span className="inline-flex gap-0.5" aria-hidden="true">
              <span className="ai-signal-thinking-dot" />
              <span className="ai-signal-thinking-dot [animation-delay:140ms]" />
              <span className="ai-signal-thinking-dot [animation-delay:280ms]" />
            </span>
          ) : signalStatus === 'Idle' ? (
            <span className="h-1.5 w-1.5 rounded-full bg-muted/70" aria-hidden="true" />
          ) : (
            <span className="h-1.5 w-1.5 rounded-full bg-cyan shadow-[0_0_0.45rem_rgba(94,207,255,0.85)]" aria-hidden="true" />
          )}
        </span>
      </div>

      <div ref={feedRef} className="ai-signal-feed min-h-0 flex-1 space-y-3 overflow-y-auto pr-1">
        {entries.length === 0 ? (
          <EmptyBlock title="Listening for AI signal" detail="Reasoning records and review-gated proposals will stream here when the backend provides them." />
        ) : (
          entries.map((entry) => {
            const localStart = consumedCharacters;
            consumedCharacters += entry.text.length;
            const visibleCharacterCount = Math.max(0, Math.min(entry.text.length, typedCharacters - localStart));
            const visibleText = entry.text.slice(0, visibleCharacterCount);
            const isVisible = visibleCharacterCount > 0 || typedCharacters >= localStart;
            const fullyTyped = visibleCharacterCount >= entry.text.length;
            if (!isVisible) return null;
            return (
              <div key={entry.id} className={cn('ai-signal-entry rounded-md border bg-surface/45 p-3', entry.tone)}>
                <div className="mb-2 flex items-center justify-between gap-3">
                  <span className="font-mono text-[0.77rem] font-semibold uppercase text-muted">{formatTime(entry.timestamp)}</span>
                  <span className="rounded-full border border-border bg-bg/50 px-2 py-0.5 text-[0.7rem] font-bold uppercase text-muted">{entry.type}</span>
                </div>
                <p className="min-h-[2.5rem] whitespace-pre-wrap text-[0.925rem] leading-5 text-text">
                  {visibleText}
                  {!fullyTyped && <span className="ai-signal-cursor" aria-hidden="true" />}
                </p>
                {entry.proposal && fullyTyped && (
                  <InlineProposalActions
                    proposal={entry.proposal}
                    busy={busyAction === `proposal-${entry.proposal.id}`}
                    disabled={busyAction !== null || entry.proposal.status !== 'pending'}
                    onReview={onReview}
                  />
                )}
              </div>
            );
          })
        )}
      </div>

      <div className="mt-3 flex items-center justify-between gap-3 border-t border-border pt-3 text-[0.85rem] text-muted">
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
  if (proposal.status !== 'pending') {
    return (
      <div className="mt-3 inline-flex items-center rounded-md border border-border bg-bg/40 px-2.5 py-1.5 text-[0.85rem] font-semibold text-muted">
        {proposal.status === 'approved' ? 'Approved' : proposal.status === 'rejected' ? 'Skipped' : proposal.status}
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
      id: `run-${run.id}-${run.updated_at}`,
      type: 'status',
      timestamp: run.updated_at,
      text: `${run.profile.name} is ${run.status}. ${tasks.length} task(s), ${findings.length} finding(s), and ${proposals.length} AI proposal record(s) are bound to this run.`,
      tone: 'border-cyan/20',
    },
  ];

  for (const task of tasks.slice(0, 4)) {
    entries.push({
      id: `task-${task.id}-${task.updated_at}`,
      type: 'task',
      timestamp: task.updated_at,
      text: `${task.tool} ${task.status} against ${truncateMiddle(task.target_id || 'recorded target', 86)}. Output stays bounded to stored task evidence.`,
      tone: ACTIVE_STATUSES.has(task.status) ? 'border-cyan/25 bg-cyan/5' : 'border-border',
    });
  }

  for (const finding of findings.slice(0, 4)) {
    entries.push({
      id: `finding-${finding.id}-${finding.created_at}`,
      type: 'finding',
      timestamp: finding.created_at,
      text: `${titleCase(finding.severity)} signal: ${finding.title} on ${truncateMiddle(finding.target_id, 82)}. Evidence ref ${finding.evidence_ref || 'recorded by backend'}.`,
      tone: finding.severity.toLowerCase() === 'critical' ? 'border-red/35 bg-red/10' : 'border-amber/25 bg-amber/5',
    });
  }

  for (const reasoning of (aiInsights?.reasoning_records ?? []).slice(0, 3)) {
    const summary =
      reasoning.summary_text ||
      reasoning.action_text ||
      stringValue(reasoning.observations_json?.[0]) ||
      'AI reasoning record is available for operator review.';
    entries.push({
      id: `reasoning-${reasoning.id}-${reasoning.updated_at}`,
      type: 'reasoning',
      timestamp: reasoning.updated_at,
      text: clampText(summary, 260),
      tone: 'border-violet-300/25 bg-violet-300/5',
    });
  }

  for (const proposal of proposals.slice(0, 5)) {
    entries.push({
      id: `proposal-${proposal.id}-${proposal.updated_at}`,
      type: 'proposal',
      timestamp: proposal.updated_at,
      text: `Proposal: ${proposal.proposed_tool} on ${truncateMiddle(proposal.proposed_target, 80)}. ${clampText(proposal.reasoning_text || 'Review this proposal before any task can be queued.', 190)} Risk tier ${proposal.risk_tier}.`,
      tone: proposal.status === 'pending' ? 'border-cyan/35 bg-cyan/10' : 'border-border',
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
  return Boolean(run.profile.limits_json?.wargaming_sandbox || (isJsonMap(sandbox) && sandbox.simulation_only));
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
  const pendingProposal = proposals.find((proposal) => proposal.status === 'pending') ?? null;
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
      operatorAction: ['queued', 'requested'].includes(run.status.toLowerCase()) ? 'Use Start Queued Checks if dispatch did not begin.' : null,
      tone: 'waiting',
      currentTask: null,
      nextTask: null,
    };
  }

  return {
    title: `${run.profile.name} is ${statusLabel(run.status)}`,
    detail: 'The selected run is loaded, but there is no active backend task or proposal attached to it right now.',
    operatorAction: ['queued', 'requested'].includes(run.status.toLowerCase()) ? 'Use Start Queued Checks to dispatch accepted work.' : null,
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
    tasks.find((task) => task.status.toLowerCase() === 'failed') ??
    tasks.find((task) => taskDisplayStatus(task, run) === 'not_run') ??
    [...tasks].sort((left, right) => Date.parse(right.updated_at) - Date.parse(left.updated_at))[0] ??
    null
  );
}

function phaseBlockerMessage(run: Run, tasks: Task[], phases: PhaseView[], currentPhase: PhaseView | null): string | null {
  if (!currentPhase || isRunTerminal(run)) return null;
  const queuedTask = tasks.find((task) => isTaskQueuedForRun(task, run));
  if (queuedTask) {
    const nextPendingPhase = phases.find((phase) => !phase.current && phase.status.toLowerCase().includes('pending'));
    const nextLabel = nextPendingPhase?.label ?? 'the next phase';
    return `${nextLabel} stays pending until ${queuedTask.tool} leaves queued state and Phase ${currentPhase.label} closes.`;
  }
  const runningTask = tasks.find((task) => isTaskActiveForRun(task, run));
  if (runningTask) {
    return `${runningTask.tool} is still ${runningTask.status}; the chain cannot advance until that runner records terminal evidence.`;
  }
  const failedTask = tasks.find((task) => task.status.toLowerCase() === 'failed');
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
  const status = task.status.toLowerCase();
  if (isRunTerminal(run) && ['queued', 'requested', 'dispatching', 'running'].includes(status)) {
    return 'not_run';
  }
  return task.status;
}

function isTaskGap(task: Task, run: Run): boolean {
  const displayStatus = taskDisplayStatus(task, run).toLowerCase();
  return displayStatus === 'failed' || displayStatus === 'not_run';
}

function taskStatusNote(task: Task, run: Run): string | null {
  if (taskDisplayStatus(task, run) === 'not_run') {
    return 'Run is terminal; backend left this check queued/requested, so Mission Control treats it as not run.';
  }
  if (task.status.toLowerCase() === 'failed') {
    return 'This failed check is why the chain can be completed with gaps.';
  }
  return null;
}

function taskGapSummary(tasks: Task[], run: Run): { failed: number; notRun: number; total: number } {
  const failed = tasks.filter((task) => task.status.toLowerCase() === 'failed').length;
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
