import {
  AlertTriangle,
  Bot,
  Check,
  CirclePause,
  FileText,
  Gauge,
  GitBranch,
  Loader2,
  LockKeyhole,
  Play,
  ShieldCheck,
  X,
} from 'lucide-react';
import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';
import type { AgentProposal, Finding, JsonMap, Run, Task, UUID } from '../../api/types';

function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

type AutopilotWorkbenchProps = {
  run: Run;
  tasks: Task[];
  findings: Finding[];
  proposals: AgentProposal[];
  aiInsights: { operator_workbench?: JsonMap } | null;
  busyAction: string | null;
  onContinue: () => void;
  onReview: (proposal: AgentProposal, decision: 'approved' | 'rejected') => void;
};

export default function AutopilotWorkbench({
  run,
  tasks,
  findings,
  proposals,
  aiInsights,
  busyAction,
  onContinue,
  onReview,
}: AutopilotWorkbenchProps) {
  const workbench = readMap(aiInsights?.operator_workbench);
  const aiLoop = readMap(workbench.ai_loop);
  const loopState = readMap(aiLoop.loop_state);
  const goal = readMap(aiLoop.current_goal);
  const hypotheses = readMaps(readMap(aiLoop.hypotheses).hypotheses).slice(0, 4);
  const nextBestActions = readMaps(readMap(aiLoop.next_best_actions).actions).slice(0, 5);
  const topAction = nextBestActions[0] ?? null;
  const coverageTruth = readMap(aiLoop.coverage_truth);
  const coverageSummary = readMap(coverageTruth.summary);
  const stopCondition = readMap(coverageTruth.stop_condition);
  const coverageSurfaces = readMaps(coverageTruth.surfaces).slice(0, 5);
  const blockers = readArray(aiLoop.blockers).map(stringValue).filter(Boolean).slice(0, 6);
  const approvalGates = readMaps(aiLoop.approval_gates);
  const pendingProposals = proposals.filter((proposal) => proposal.status === 'pending_review' || proposal.status === 'pending');
  const proposalById = new Map(proposals.map((proposal) => [proposal.id, proposal]));
  const gatedProposals = approvalGates
    .map((gate) => proposalById.get(stringValue(gate.proposal_id) as UUID))
    .filter((proposal): proposal is AgentProposal => Boolean(proposal));
  const visibleProposals = gatedProposals.length > 0 ? gatedProposals : pendingProposals;
  const executionContract = readMap(aiLoop.execution_contract);
  const enabled = aiLoop.enabled !== false;
  const objective = stringValue(goal.objective);

  return (
    <div className="grid gap-4 xl:grid-cols-[minmax(320px,0.92fr)_minmax(380px,1.16fr)_minmax(320px,0.92fr)]">
      <div className="flex min-h-0 flex-col gap-4">
        <section className="glass-panel rounded-lg p-4">
          <div className="mb-4 flex items-start justify-between gap-3">
            <div>
              <h2 className="flex items-center gap-2 text-[1rem] font-semibold text-cyan">
                <Bot size={15} />
                Autopilot Goal
              </h2>
              <p className="mt-1 text-[0.875rem] text-muted">Run {compactId(run.id)} uses run_mode=ai_loop.</p>
            </div>
            <span className={cn('rounded-full px-2.5 py-1 text-[0.77rem] font-bold uppercase', enabled ? statusTone('active') : statusTone('blocked'))}>
              {enabled ? stringValue(aiLoop.status) || 'ready' : 'blocked'}
            </span>
          </div>
          {objective ? (
            <div className="rounded-md border border-cyan/20 bg-cyan/10 p-3">
              <p className="text-[0.925rem] font-semibold text-text">{objective}</p>
              <p className="mt-2 text-[0.875rem] leading-5 text-muted">
                Controlled proof, canary evidence, and session exposure risk controls remain bound to recorded evidence.
              </p>
            </div>
          ) : (
            <EmptyBlock
              title="No explicit goal recorded"
              detail="The workbench can still show graph hypotheses and next-best actions from backend evidence."
            />
          )}
          <div className="mt-4 grid grid-cols-3 gap-2">
            <Metric label="Iteration" value={numberValue(loopState.iteration_count)} />
            <Metric label="Tasks" value={tasks.length} />
            <Metric label="Findings" value={findings.length} />
          </div>
        </section>

        <section className="glass-panel rounded-lg p-4">
          <div className="mb-4 flex items-center justify-between gap-3">
            <h2 className="flex items-center gap-2 text-[1rem] font-semibold text-cyan">
              <GitBranch size={15} />
              Evidence Hypotheses
            </h2>
            <span className="text-[0.85rem] text-muted">{hypotheses.length} shown</span>
          </div>
          {hypotheses.length === 0 ? (
            <EmptyBlock title="No hypotheses yet" detail="Evidence-linked hypotheses will appear after graph data is present." />
          ) : (
            <div className="grid gap-3">
              {hypotheses.map((hypothesis, index) => (
                <div key={`${stringValue(hypothesis.id) || index}`} className="rounded-md border border-border bg-surface/45 p-3">
                  <div className="mb-2 flex items-center justify-between gap-2">
                    <p className="truncate text-[0.925rem] font-semibold text-text">
                      {stringValue(hypothesis.title) || stringValue(hypothesis.hypothesis) || `Hypothesis ${index + 1}`}
                    </p>
                    <span className="text-[0.85rem] text-muted">{percentValue(hypothesis.confidence)}</span>
                  </div>
                  <p className="line-clamp-3 text-[0.875rem] leading-5 text-muted">
                    {stringValue(hypothesis.summary) ||
                      stringValue(hypothesis.question) ||
                      stringValue(hypothesis.inferred_next_question) ||
                      'Stored evidence suggests a follow-up observation.'}
                  </p>
                  <p className="mt-2 truncate font-mono text-[0.8rem] text-muted">
                    Sources {readArray(hypothesis.source_ids).map(stringValue).filter(Boolean).slice(0, 3).join(', ') || 'recorded evidence'}
                  </p>
                </div>
              ))}
            </div>
          )}
        </section>
      </div>

      <div className="flex min-h-0 flex-col gap-4">
        <section className="glass-panel rounded-lg p-4">
          <div className="mb-4 flex items-center justify-between gap-3">
            <h2 className="flex items-center gap-2 text-[1rem] font-semibold text-cyan">
              <Gauge size={15} />
              Next-Best Action
            </h2>
            <span className="text-[0.85rem] text-muted">{nextBestActions.length} ranked</span>
          </div>
          {topAction ? (
            <div className="rounded-md border border-cyan/25 bg-cyan/10 p-4">
              <div className="mb-3 flex flex-wrap items-center gap-2">
                <span className={cn('rounded-full px-2.5 py-1 text-[0.77rem] font-bold uppercase', statusTone(stringValue(topAction.decision)))}>
                  {stringValue(topAction.decision) || 'WAIT'}
                </span>
                <span className="font-mono text-[0.95rem] font-semibold text-text">{stringValue(topAction.runner)}</span>
                <span className="truncate text-[0.875rem] text-muted">{stringValue(topAction.target) || 'No approved target'}</span>
              </div>
              <p className="text-[0.925rem] leading-5 text-text">{stringValue(topAction.rationale) || 'Selector returned a governed next action.'}</p>
              <div className="mt-3 grid gap-2 sm:grid-cols-3">
                <Metric label="Proof value" value={percentValue(topAction.expected_proof_value)} />
                <Metric label="Confidence" value={percentValue(topAction.confidence)} />
                <Metric label="Risk" value={stringValue(topAction.risk_tier) || 'active'} />
              </div>
              <p className="mt-3 text-[0.875rem] leading-5 text-muted">
                RUN actions continue through the existing assessment loop. APPROVAL actions stay review-gated before any queued task exists.
              </p>
            </div>
          ) : (
            <EmptyBlock title="No ranked action" detail="The selector is waiting for approved scope, evidence, or runner metadata." />
          )}

          <div className="mt-4 grid gap-2">
            {nextBestActions.slice(1).map((action, index) => (
              <div key={`${stringValue(action.runner)}-${index}`} className="flex items-center justify-between gap-3 rounded-md border border-border bg-surface/45 px-3 py-2">
                <div className="min-w-0">
                  <p className="truncate font-mono text-[0.875rem] text-text">{stringValue(action.runner)}</p>
                  <p className="truncate text-[0.8rem] text-muted">{stringValue(action.rationale)}</p>
                </div>
                <span className={cn('shrink-0 rounded-full px-2 py-0.5 text-[0.7rem] font-bold uppercase', statusTone(stringValue(action.decision)))}>
                  {stringValue(action.decision) || 'WAIT'}
                </span>
              </div>
            ))}
          </div>
        </section>

        <section className="glass-panel rounded-lg p-4">
          <div className="mb-4 flex items-center justify-between gap-3">
            <h2 className="flex items-center gap-2 text-[1rem] font-semibold text-cyan">
              <LockKeyhole size={15} />
              Approval Gates
            </h2>
            <span className="text-[0.85rem] text-muted">{visibleProposals.length} pending</span>
          </div>
          {visibleProposals.length === 0 ? (
            <EmptyBlock title="No approval gate open" detail="Active or intrusive controlled proof remains gated until the backend creates a proposal." />
          ) : (
            <div className="grid gap-3">
              {visibleProposals.map((proposal) => {
                const busy = busyAction === `proposal-${proposal.id}`;
                const canReview = proposal.status === 'pending_review' || proposal.status === 'pending';
                return (
                  <div key={proposal.id} className="rounded-md border border-border bg-surface/45 p-3">
                    <div className="mb-2 flex items-start justify-between gap-2">
                      <div className="min-w-0">
                        <p className="truncate font-mono text-[0.925rem] font-semibold text-text">{proposal.proposed_tool}</p>
                        <p className="truncate text-[0.875rem] text-muted">{proposal.proposed_target}</p>
                      </div>
                      <span className={cn('rounded-full px-2 py-0.5 text-[0.77rem] font-bold uppercase', statusTone(proposal.status))}>
                        {proposal.status}
                      </span>
                    </div>
                    <p className="line-clamp-3 text-[0.875rem] leading-5 text-muted">
                      {proposal.reasoning_text || 'Review this controlled proof proposal before queueing any task.'}
                    </p>
                    <p className="mt-2 text-[0.8rem] leading-5 text-muted">
                      Canary evidence is preferred; session exposure risk and secret material stay redacted.
                    </p>
                    <div className="mt-3 flex items-center justify-between gap-3">
                      <span className="text-[0.8rem] text-muted">Risk tier {proposal.risk_tier}</span>
                      <div className="flex items-center gap-2">
                        <button
                          type="button"
                          onClick={() => onReview(proposal, 'rejected')}
                          disabled={!canReview || busyAction !== null}
                          className="inline-flex h-8 w-8 items-center justify-center rounded-md border border-border text-muted transition-colors hover:border-red/40 hover:text-red disabled:cursor-not-allowed disabled:opacity-40"
                          aria-label="Reject autopilot proposal"
                        >
                          {busy ? <Loader2 size={14} className="animate-spin" /> : <X size={14} />}
                        </button>
                        <button
                          type="button"
                          onClick={() => onReview(proposal, 'approved')}
                          disabled={!canReview || busyAction !== null}
                          className="inline-flex h-8 w-8 items-center justify-center rounded-md border border-emerald-400/30 text-emerald-200 transition-colors hover:bg-emerald-400/10 disabled:cursor-not-allowed disabled:opacity-40"
                          aria-label="Approve autopilot proposal"
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
        </section>
      </div>

      <div className="flex min-h-0 flex-col gap-4">
        <section className="glass-panel rounded-lg p-4">
          <div className="mb-4 flex items-center justify-between gap-3">
            <h2 className="flex items-center gap-2 text-[1rem] font-semibold text-cyan">
              <ShieldCheck size={15} />
              Coverage Truth
            </h2>
            <span className={cn('rounded-full px-2 py-0.5 text-[0.77rem] font-bold uppercase', statusTone(stringValue(stopCondition.state)))}>
              {stringValue(stopCondition.state) || 'unknown'}
            </span>
          </div>
          <div className="grid grid-cols-3 gap-2">
            <Metric label="Tested" value={numberValue(coverageSummary.tested_count)} />
            <Metric label="Partial" value={numberValue(coverageSummary.partially_tested_count)} />
            <Metric label="Blocked" value={numberValue(coverageSummary.blocked_count)} />
          </div>
          <div className="mt-4 grid gap-2">
            {coverageSurfaces.map((surface) => (
              <div key={stringValue(surface.key)} className="flex items-center justify-between gap-3 rounded-md border border-border bg-surface/45 px-3 py-2">
                <span className="truncate text-[0.875rem] text-text">{stringValue(surface.label) || stringValue(surface.key)}</span>
                <span className={cn('shrink-0 rounded-full px-2 py-0.5 text-[0.7rem] font-bold uppercase', statusTone(stringValue(surface.status)))}>
                  {stringValue(surface.status) || 'unknown'}
                </span>
              </div>
            ))}
          </div>
        </section>

        <section className="glass-panel rounded-lg p-4">
          <div className="mb-4 flex items-center justify-between gap-3">
            <h2 className="flex items-center gap-2 text-[1rem] font-semibold text-cyan">
              <CirclePause size={15} />
              Blockers
            </h2>
            <span className="text-[0.85rem] text-muted">{blockers.length} active</span>
          </div>
          {blockers.length === 0 ? (
            <EmptyBlock title="No active blocker" detail="WAIT and SKIP reasons will appear here when prerequisites are missing." />
          ) : (
            <div className="grid gap-2">
              {blockers.map((blocker, index) => (
                <div key={`${blocker}-${index}`} className="rounded-md border border-amber/25 bg-amber/10 p-3 text-[0.875rem] leading-5 text-amber">
                  {blocker}
                </div>
              ))}
            </div>
          )}
        </section>

        <section className="glass-panel rounded-lg p-4">
          <div className="mb-4 flex items-center justify-between gap-3">
            <h2 className="flex items-center gap-2 text-[1rem] font-semibold text-cyan">
              <FileText size={15} />
              Safe Override
            </h2>
            <span className="text-[0.85rem] text-muted">Existing endpoints only</span>
          </div>
          <p className="text-[0.875rem] leading-5 text-muted">
            Continue asks the backend assessment loop for the next governed step. It does not bypass scope, ROE,
            approval gates, runtime binding, or the kill switch.
          </p>
          <button
            type="button"
            onClick={onContinue}
            disabled={busyAction !== null || !enabled}
            className="mt-4 inline-flex w-full items-center justify-center gap-2 rounded-md border border-emerald-400/30 bg-emerald-400/10 px-3 py-2 text-[0.925rem] font-semibold text-emerald-200 transition-colors hover:bg-emerald-400/15 disabled:cursor-not-allowed disabled:opacity-40"
          >
            {busyAction === 'autopilot-continue' ? <Loader2 size={15} className="animate-spin" /> : <Play size={15} />}
            Continue AI Loop
          </button>
          <div className="mt-3 rounded-md border border-border bg-surface/45 p-3 text-[0.8rem] leading-5 text-muted">
            Dispatch direct: {executionContract.dispatches_work_directly === false ? 'no' : 'unknown'} | Scope mutation:{' '}
            {executionContract.mutates_scope === false ? 'no' : 'unknown'} | Approval mutation:{' '}
            {executionContract.mutates_approvals === false ? 'no' : 'unknown'}
          </div>
        </section>
      </div>
    </div>
  );
}

function Metric({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="rounded-md border border-border bg-surface/45 p-3">
      <p className="text-[0.7rem] font-bold uppercase text-muted">{label}</p>
      <p className="mt-1 truncate text-[1rem] font-semibold text-text">{value}</p>
    </div>
  );
}

function EmptyBlock({ title, detail }: { title: string; detail: string }) {
  return (
    <div className="flex min-h-[9rem] flex-1 flex-col items-center justify-center rounded-md border border-dashed border-border bg-surface/20 p-4 text-center">
      <AlertTriangle size={18} className="mb-3 text-muted" />
      <p className="text-[1rem] font-semibold text-text">{title}</p>
      <p className="mt-1 max-w-sm text-[0.875rem] leading-5 text-muted">{detail}</p>
    </div>
  );
}

function statusTone(status: string): string {
  const value = status.toLowerCase();
  if (['run', 'running', 'active', 'approved', 'completed', 'complete', 'tested'].includes(value)) {
    return 'border border-emerald-400/30 bg-emerald-400/10 text-emerald-200';
  }
  if (['wait', 'queued', 'requested', 'pending', 'pending_review', 'partial', 'partially_tested'].includes(value)) {
    return 'border border-amber/30 bg-amber/10 text-amber';
  }
  if (['skip', 'failed', 'failure', 'cancelled', 'canceled', 'rejected', 'blocked', 'not_tested'].includes(value)) {
    return 'border border-red/30 bg-red/10 text-red';
  }
  if (['approval', 'approval_needed'].includes(value)) {
    return 'border border-fuchsia-300/30 bg-fuchsia-300/10 text-fuchsia-100';
  }
  return 'border border-cyan/20 bg-cyan/10 text-cyan';
}

function readMap(value: unknown): JsonMap {
  return typeof value === 'object' && value !== null && !Array.isArray(value) ? (value as JsonMap) : {};
}

function readArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function readMaps(value: unknown): JsonMap[] {
  return readArray(value).filter((item): item is JsonMap => typeof item === 'object' && item !== null && !Array.isArray(item));
}

function stringValue(value: unknown): string {
  return typeof value === 'string' ? value : '';
}

function numberValue(value: unknown): number {
  return typeof value === 'number' && Number.isFinite(value) ? value : 0;
}

function percentValue(value: unknown): string {
  if (typeof value !== 'number' || !Number.isFinite(value)) return 'n/a';
  return `${Math.round(value * 100)}%`;
}

function compactId(value: string): string {
  return value.length > 12 ? `${value.slice(0, 8)}...${value.slice(-4)}` : value;
}
