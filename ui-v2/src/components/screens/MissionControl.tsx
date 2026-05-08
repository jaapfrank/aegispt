import { useEffect, useMemo, useState } from 'react';
import type { ReactNode } from 'react';
import {
  Activity,
  AlertTriangle,
  Bot,
  Check,
  ChevronDown,
  CircleStop,
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
import { Link } from 'react-router-dom';
import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';
import {
  cancelRun,
  decideAssessmentChainPhase,
  dispatchRun,
  getRun,
  getRunAiInsights,
  getRunFindings,
  getRunInventory,
  getTaskDetail,
  reviewAgentProposal,
} from '../../api/client';
import type {
  AgentProposal,
  AssessmentChain,
  Finding,
  InventorySnapshot,
  JsonMap,
  Run,
  Task,
  TaskDetail,
  UUID,
} from '../../api/types';
import { useAegisStore } from '../../store';
import CinemaMode from '../CinemaMode';

const POLL_MS = 3000;
const ACTIVE_STATUSES = new Set(['queued', 'requested', 'dispatching', 'running']);
const TERMINAL_STATUSES = new Set(['completed', 'failed', 'cancelled', 'canceled']);
const OUTPUT_LIMIT = 900;
function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

type BusyAction = 'refresh' | 'cancel' | 'dispatch' | 'phase' | `proposal-${UUID}` | null;

type ExecutionNotice = {
  title: string;
  detail: string;
  tone: string;
};

type MapNode = {
  id: string;
  label: string;
  type: string;
  state: 'finding' | 'active' | 'complete' | 'idle';
  x: number;
  y: number;
};

type PhaseView = {
  key: string;
  label: string;
  status: string;
  current: boolean;
  requiresApproval: boolean;
};

export default function MissionControl() {
  const selectedRun = useAegisStore((state) => state.selectedRun);
  const selectedRunId = useAegisStore((state) => state.selectedRunId);
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

  const [expandedTaskId, setExpandedTaskId] = useState<UUID | null>(null);
  const [taskDetails, setTaskDetails] = useState<Record<UUID, TaskDetail>>({});
  const [busyAction, setBusyAction] = useState<BusyAction>(null);
  const [actionMessage, setActionMessage] = useState<string | null>(null);
  const [cinemaOpen, setCinemaOpen] = useState(false);

  const proposals = aiInsights?.proposals ?? [];
  const chain = selectedRun?.assessment_chain ?? null;
  const phases = useMemo(() => buildPhaseViews(chain), [chain]);
  const currentPhase = phases.find((phase) => phase.current) ?? phases[0] ?? null;
  const mapNodes = useMemo(() => buildMapNodes(inventory, tasks, findings), [inventory, tasks, findings]);
  const activeTaskCount = tasks.filter((task) => ACTIVE_STATUSES.has(task.status)).length;
  const executionNotice = useMemo(
    () => (selectedRun ? buildExecutionNotice(selectedRun, tasks, currentPhase) : null),
    [currentPhase, selectedRun, tasks],
  );
  const pendingProposalCount = proposals.filter((proposal) => proposal.status === 'pending').length;
  const canCancel = Boolean(selectedRun && !TERMINAL_STATUSES.has(selectedRun.status));
  const selectedRunIsAutomatic = Boolean(selectedRun && isAutomaticRun(selectedRun));
  const canDispatch = Boolean(
    selectedRun && !selectedRunIsAutomatic && ['queued', 'requested'].includes(selectedRun.status),
  );
  const canApprovePhase = Boolean(
    selectedRun &&
      chainId(chain) &&
      currentPhase?.key &&
      (chainStatus(chain) === 'pending_phase_approval' || currentPhase.requiresApproval),
  );
  const isPolling = Boolean(selectedRun && ACTIVE_STATUSES.has(selectedRun.status));

  async function refreshRun(runId = selectedRunId, options: { quiet?: boolean } = {}) {
    if (!runId) return;
    if (!options.quiet) {
      setBusyAction('refresh');
    }
    setLoading('missionControl', true);
    setError(null);
    try {
      const [runResult, findingsResult, inventoryResult, insightsResult] = await Promise.allSettled([
        getRun(runId),
        getRunFindings(runId),
        getRunInventory(runId),
        getRunAiInsights(runId),
      ]);

      if (runResult.status === 'fulfilled') {
        setSelectedRun(runResult.value);
        setTasks(runResult.value.tasks ?? []);
      } else {
        throw runResult.reason;
      }
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
      setError(errorMessage(error));
      if (!options.quiet) {
        setActionMessage('Refresh failed.');
      }
    } finally {
      setLoading('missionControl', false);
      if (!options.quiet) {
        setBusyAction(null);
      }
    }
  }

  useEffect(() => {
    if (!selectedRunId) return;
    void refreshRun(selectedRunId, { quiet: true });
  }, [selectedRunId]);

  useEffect(() => {
    if (!selectedRunId || !isPolling) return;
    const timer = window.setInterval(() => {
      void refreshRun(selectedRunId, { quiet: true });
    }, POLL_MS);
    return () => window.clearInterval(timer);
  }, [isPolling, selectedRunId]);

  useEffect(() => {
    if (!expandedTaskId || taskDetails[expandedTaskId]) return;
    const taskId = expandedTaskId;
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
    return () => {
      cancelled = true;
    };
  }, [expandedTaskId, setError, taskDetails]);

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
      setActionMessage(`Dispatch accepted: ${payload.dispatched_task_ids.length} queued check(s).`);
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
      await reviewAgentProposal(selectedRun.id, proposal.id, {
        decision,
        note: decision === 'approved' ? 'Approved from v2 Mission Control.' : 'Rejected from v2 Mission Control.',
      });
      const insights = await getRunAiInsights(selectedRun.id);
      setAiInsights(insights);
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
    <section className="flex min-h-full flex-col gap-5">
      <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
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

        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={() => void refreshRun()}
            disabled={busyAction !== null}
            className="inline-flex items-center gap-2 rounded-md border border-border bg-surface/70 px-3 py-2 text-[0.925rem] font-semibold text-text transition-colors hover:border-cyan/40 hover:text-cyan disabled:cursor-not-allowed disabled:opacity-50"
          >
            <RefreshCw size={15} className={busyAction === 'refresh' ? 'animate-spin' : ''} />
            Refresh
          </button>
          <Link
            to="/findings"
            className="inline-flex items-center gap-2 rounded-md border border-border bg-surface/70 px-3 py-2 text-[0.925rem] font-semibold text-text transition-colors hover:border-cyan/40 hover:text-cyan"
          >
            <FileText size={15} />
            View Findings
          </Link>
          <button
            type="button"
            onClick={() => setCinemaOpen(true)}
            className="inline-flex items-center gap-2 rounded-md border border-cyan/30 bg-cyan/10 px-3 py-2 text-[0.925rem] font-semibold text-cyan transition-colors hover:bg-cyan/15"
          >
            <MonitorPlay size={15} />
            Cinema Mode
          </button>
          {!selectedRunIsAutomatic && (
            <button
              type="button"
              onClick={() => void handleDispatch()}
              disabled={!canDispatch || busyAction !== null}
              className="inline-flex items-center gap-2 rounded-md border border-emerald-400/30 bg-emerald-400/10 px-3 py-2 text-[0.925rem] font-semibold text-emerald-200 transition-colors hover:bg-emerald-400/15 disabled:cursor-not-allowed disabled:opacity-40"
            >
              <Play size={15} />
              Run Queued Checks Now
            </button>
          )}
          <button
            type="button"
            onClick={() => void handleCancel()}
            disabled={!canCancel || busyAction !== null}
            className="inline-flex items-center gap-2 rounded-md border border-red/30 bg-red/10 px-3 py-2 text-[0.925rem] font-semibold text-red transition-colors hover:bg-red/15 disabled:cursor-not-allowed disabled:opacity-40"
          >
            <CircleStop size={15} />
            Kill Run
          </button>
        </div>
      </div>

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
            tasks={tasks}
            expandedTaskId={expandedTaskId}
            taskDetails={taskDetails}
            onToggle={(taskId) => setExpandedTaskId((current) => (current === taskId ? null : taskId))}
          />
        </div>

        <div className="flex min-h-0 flex-col gap-4">
          <ScanMap nodes={mapNodes} inventory={inventory} />
          <PhaseChain
            chain={chain}
            phases={phases}
            currentPhase={currentPhase}
            canApprovePhase={canApprovePhase}
            busy={busyAction === 'phase'}
            onApprove={() => void handleApprovePhase()}
          />
        </div>

        <div className="flex min-h-0 flex-col gap-4">
          <AiProposalPanel
            proposals={proposals}
            busyAction={busyAction}
            onReview={(proposal, decision) => void handleProposalReview(proposal, decision)}
          />
          <EvidencePanel aiInsights={aiInsights} findings={findings} />
        </div>
      </div>

      {cinemaOpen && (
        <CinemaMode onClose={() => setCinemaOpen(false)} />
      )}
    </section>
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
            return mode ? chainLabel(mode) : run.profile.name;
          })()}
        />
        <KeyValue label="Approvals" value={`${run.granted_approvals}/${run.required_approvals}`} />
        <KeyValue label="Execution" value={executionModeLabel(run)} />
        <KeyValue label="Started" value={run.started_at ? formatDate(run.started_at) : 'Not started'} />
      </div>
    </div>
  );
}

function TaskList({
  tasks,
  expandedTaskId,
  taskDetails,
  onToggle,
}: {
  tasks: Task[];
  expandedTaskId: UUID | null;
  taskDetails: Record<UUID, TaskDetail>;
  onToggle: (taskId: UUID) => void;
}) {
  return (
    <div className="glass-panel flex min-h-[360px] flex-col rounded-lg p-4">
      <div className="mb-4 flex items-center justify-between">
        <h2 className="flex items-center gap-2 text-[1rem] font-semibold text-cyan">
          <TerminalSquare size={15} />
          Task Output
        </h2>
        <span className="text-[0.85rem] text-muted">{tasks.length} backend tasks</span>
      </div>
      {tasks.length === 0 ? (
        <EmptyBlock title="No tasks yet" detail="Queued checks will appear here after backend dispatch." />
      ) : (
        <div className="flex min-h-0 flex-1 flex-col gap-2 overflow-y-auto pr-1">
          {tasks.map((task) => {
            const detail = taskDetails[task.id];
            const isExpanded = expandedTaskId === task.id;
            return (
              <div key={task.id} className="rounded-md border border-border bg-surface/45">
                <button
                  type="button"
                  onClick={() => onToggle(task.id)}
                  className="flex w-full items-center justify-between gap-3 px-3 py-3 text-left"
                >
                  <div className="min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-mono text-[0.925rem] font-semibold text-text">{task.tool}</span>
                      <span className={cn('rounded-full px-2 py-0.5 text-[0.77rem] font-bold uppercase', statusTone(task.status))}>
                        {task.status}
                      </span>
                    </div>
                    <p className="mt-1 truncate text-[0.925rem] text-muted">{task.target_id || 'No target id'}</p>
                  </div>
                  <ChevronDown
                    size={15}
                    className={cn('shrink-0 text-muted transition-transform', isExpanded && 'rotate-180 text-cyan')}
                  />
                </button>
                {isExpanded && (
                  <div className="border-t border-border px-3 py-3">
                    {!detail ? (
                      <div className="flex items-center gap-2 text-[0.925rem] text-muted">
                        <Loader2 size={14} className="animate-spin text-cyan" />
                        Loading bounded execution output
                      </div>
                    ) : (
                      <pre className="max-h-[220px] overflow-auto rounded-md border border-border bg-[#02060c] p-3 font-mono text-[0.85rem] leading-5 text-[#c8d6e5] whitespace-pre-wrap">
                        {boundedOutput(detail)}
                      </pre>
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
}

function ScanMap({ nodes, inventory }: { nodes: MapNode[]; inventory: InventorySnapshot | null }) {
  return (
    <div className="glass-panel min-h-[340px] rounded-lg p-4">
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
              <line
                key={`${node.id}-line`}
                x1="260"
                y1="135"
                x2={node.x}
                y2={node.y}
                stroke={node.state === 'finding' ? 'rgba(248,113,113,0.45)' : 'rgba(94,207,255,0.22)'}
                strokeWidth="1"
              />
            ))}
            <circle cx="260" cy="135" r="34" fill="rgba(94,207,255,0.08)" stroke="rgba(94,207,255,0.35)" />
            <text x="260" y="139" textAnchor="middle" fill="#5ecfff" fontSize="11" fontFamily="monospace">
              run
            </text>
            {nodes.map((node) => (
              <g key={node.id}>
                <circle cx={node.x} cy={node.y} r="20" fill="url(#nodeGlow)" opacity="0.45" />
                <circle cx={node.x} cy={node.y} r="8" fill={nodeColor(node.state)} />
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
  phases,
  currentPhase,
  canApprovePhase,
  busy,
  onApprove,
}: {
  chain: Partial<AssessmentChain> | JsonMap | null;
  phases: PhaseView[];
  currentPhase: PhaseView | null;
  canApprovePhase: boolean;
  busy: boolean;
  onApprove: () => void;
}) {
  return (
    <div className="glass-panel min-h-[230px] rounded-lg p-4">
      <div className="mb-4 flex items-center justify-between gap-3">
        <h2 className="flex items-center gap-2 text-[1rem] font-semibold text-cyan">
          <Workflow size={15} />
          Phase Chain
        </h2>
        <span className="text-[0.85rem] text-muted">{chainStatus(chain) || 'No chain'}</span>
      </div>
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

function AiProposalPanel({
  proposals,
  busyAction,
  onReview,
}: {
  proposals: AgentProposal[];
  busyAction: BusyAction;
  onReview: (proposal: AgentProposal, decision: 'approved' | 'rejected') => void;
}) {
  return (
    <div className="glass-panel flex min-h-[360px] flex-col rounded-lg p-4">
      <div className="mb-4 flex items-center justify-between gap-3">
        <h2 className="flex items-center gap-2 text-[1rem] font-semibold text-cyan">
          <Bot size={15} />
          AI Proposals
        </h2>
        <span className="text-[0.85rem] text-muted">{proposals.length} records</span>
      </div>
      {proposals.length === 0 ? (
        <EmptyBlock title="No AI proposals" detail="AI-assisted proposals will appear after reasoning records are written." />
      ) : (
        <div className="flex min-h-0 flex-1 flex-col gap-3 overflow-y-auto pr-1">
          {proposals.map((proposal) => {
            const busy = busyAction === `proposal-${proposal.id}`;
            const canReview = proposal.status === 'pending';
            return (
              <div key={proposal.id} className="rounded-md border border-border bg-surface/45 p-3">
                <div className="mb-2 flex items-start justify-between gap-2">
                  <div className="min-w-0">
                    <p className="truncate font-mono text-[0.925rem] font-semibold text-text">{proposal.proposed_tool}</p>
                    <p className="mt-1 truncate text-[0.925rem] text-muted">{proposal.proposed_target}</p>
                  </div>
                  <span className={cn('rounded-full px-2 py-0.5 text-[0.77rem] font-bold uppercase', statusTone(proposal.status))}>
                    {proposal.status}
                  </span>
                </div>
                <p className="line-clamp-3 text-[0.925rem] leading-5 text-muted">
                  {proposal.reasoning_text || 'No reasoning summary returned.'}
                </p>
                <div className="mt-3 flex items-center justify-between gap-2">
                  <span className="text-[0.85rem] text-muted">Risk tier {proposal.risk_tier}</span>
                  <div className="flex items-center gap-2">
                    <button
                      type="button"
                      onClick={() => onReview(proposal, 'rejected')}
                      disabled={!canReview || busyAction !== null}
                      className="inline-flex h-8 w-8 items-center justify-center rounded-md border border-border text-muted transition-colors hover:border-red/40 hover:text-red disabled:cursor-not-allowed disabled:opacity-40"
                      aria-label="Reject AI proposal"
                    >
                      {busy ? <Loader2 size={14} className="animate-spin" /> : <X size={14} />}
                    </button>
                    <button
                      type="button"
                      onClick={() => onReview(proposal, 'approved')}
                      disabled={!canReview || busyAction !== null}
                      className="inline-flex h-8 w-8 items-center justify-center rounded-md border border-emerald-400/30 text-emerald-200 transition-colors hover:bg-emerald-400/10 disabled:cursor-not-allowed disabled:opacity-40"
                      aria-label="Approve AI proposal"
                    >
                      {busy ? <Loader2 size={14} className="animate-spin" /> : <Check size={14} />}
                    </button>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}
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
          Evidence Links
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
            <p className="truncate font-mono text-[0.85rem] text-muted">{finding.evidence_ref}</p>
          </div>
        ))}
        {findings.length === 0 && <EmptyBlock title="No findings" detail="Findings will link to backend evidence references when present." />}
      </div>
    </div>
  );
}

function MiniMetric({ icon, label, value }: { icon: ReactNode; label: string; value: string | number }) {
  return (
    <div className="rounded-md border border-border bg-surface/45 p-3">
      <div className="mb-2 flex items-center gap-2 text-cyan">
        {icon}
        <span className="text-[0.77rem] font-bold uppercase">{label}</span>
      </div>
      <div className="text-xl font-semibold text-text">{value}</div>
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
      <AlertTriangle size={18} className="mb-3 text-muted" />
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

function buildExecutionNotice(run: Run, tasks: Task[], currentPhase: PhaseView | null): ExecutionNotice | null {
  const queuedCount = tasks.filter((task) => ['queued', 'requested'].includes(task.status)).length;
  const runningTask = tasks.find((task) => ['dispatching', 'running'].includes(task.status));
  const dispatchMode = stringValue(runtimeDispatch(run)?.last_dispatch_mode);

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
      title: 'Automatic launch blocked',
      detail: 'The run requested automatic dispatch, but the local API host reported manual dispatch mode.',
      tone: 'border-amber/30 bg-amber/10 text-amber',
    };
  }

  if (queuedCount > 0 && isAutomaticRun(run)) {
    return {
      title: 'Automatic launch starting',
      detail: `${queuedCount} check(s) have been accepted for automatic dispatch; Mission Control is polling every 3s.`,
      tone: 'border-cyan/20 bg-cyan/10 text-cyan',
    };
  }

  if (chainStatus(run.assessment_chain) === 'pending_phase_approval' || currentPhase?.requiresApproval) {
    return {
      title: 'Approval required',
      detail: 'The current phase is waiting for an approval decision in the phase chain.',
      tone: 'border-amber/30 bg-amber/10 text-amber',
    };
  }

  return null;
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

function runtimeDispatch(run: Run): JsonMap | null {
  const dispatch = run.configuration_json?.runtime_dispatch;
  return isJsonMap(dispatch) ? dispatch : null;
}

function assessmentMode(run: Run): JsonMap | null {
  const assessment = run.configuration_json?.assessment_mode;
  return isJsonMap(assessment) ? assessment : null;
}

function buildMapNodes(inventory: InventorySnapshot | null, tasks: Task[], findings: Finding[]): MapNode[] {
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
    return {
      id: label,
      label,
      type: label.startsWith('http') ? 'http' : 'target',
      state: nodeState(label, tasks, findings),
      x,
      y,
    };
  });
}

function nodeState(label: string, tasks: Task[], findings: Finding[]): MapNode['state'] {
  if (findings.some((finding) => targetMatches(finding.target_id, label))) return 'finding';
  if (tasks.some((task) => ACTIVE_STATUSES.has(task.status) && targetMatches(task.target_id, label))) return 'active';
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
    .map((phase, index) => {
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
      };
    })
    .filter((phase): phase is PhaseView => Boolean(phase));
}

function boundedOutput(detail: TaskDetail): string {
  const newestExecution = [...(detail.executions ?? [])].sort((left, right) =>
    stringValue(right.created_at).localeCompare(stringValue(left.created_at)),
  )[0];
  const executionText = newestExecution?.stdout_text || newestExecution?.stderr_text || '';
  const snapshotLines = detail.stdout_snapshot?.lines?.map((line) => line.text).filter(Boolean).join('\n') ?? '';
  const reason = detail.stdout_snapshot?.reason ? `stdout snapshot: ${detail.stdout_snapshot.reason}` : '';
  const output = executionText || snapshotLines || reason || 'No execution output has been recorded for this task.';
  return output.length > OUTPUT_LIMIT ? `${output.slice(-OUTPUT_LIMIT)}\n[bounded to latest ${OUTPUT_LIMIT} characters]` : output;
}

function chainId(chain: Partial<AssessmentChain> | JsonMap | null): UUID | null {
  return isJsonMap(chain) && typeof chain.id === 'string' ? chain.id : null;
}

function chainStatus(chain: Partial<AssessmentChain> | JsonMap | null): string {
  return isJsonMap(chain) && typeof chain.status === 'string' ? chain.status : '';
}

function nodeColor(state: MapNode['state']): string {
  if (state === 'finding') return '#f87171';
  if (state === 'active') return '#5ecfff';
  if (state === 'complete') return '#34d399';
  return '#78b1d4';
}

function statusTone(status: string): string {
  const value = status.toLowerCase();
  if (['running', 'active', 'approved', 'completed', 'complete', 'success', 'passed', 'low'].includes(value)) {
    return 'border border-emerald-400/30 bg-emerald-400/10 text-emerald-200';
  }
  if (['queued', 'requested', 'pending', 'medium'].includes(value)) {
    return 'border border-amber/30 bg-amber/10 text-amber';
  }
  if (['failed', 'failure', 'cancelled', 'canceled', 'rejected', 'high', 'critical'].includes(value)) {
    return 'border border-red/30 bg-red/10 text-red';
  }
  return 'border border-cyan/20 bg-cyan/10 text-cyan';
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

function errorMessage(error: unknown): string {
  if (error instanceof Error) return error.message;
  return 'AegisPT API request failed.';
}
