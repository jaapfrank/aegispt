import type { Finding, Run, Task } from '../api/types';

export type RunTruthStageKey = 'queued' | 'running' | 'observed' | 'verified' | 'persisted' | 'blocked';
export type RunTruthTone = 'idle' | 'active' | 'complete' | 'warning' | 'blocked';

export interface RunTruthStage {
  key: RunTruthStageKey;
  label: string;
  value: string;
  detail: string;
  tone: RunTruthTone;
}

export interface RunTruthModel {
  scopeLabel: string;
  sourceDetail: string;
  summaryHeadline: string;
  summaryDetail: string;
  statusLabel: string;
  phaseLabel: string | null;
  canonicalScore: string;
  canonicalScoreDetail: string;
  runLocalSummary: string;
  truthGapText: string | null;
  attention: {
    tone: 'complete' | 'warning' | 'blocked';
    label: string;
    detail: string;
  };
  stages: RunTruthStage[];
}

const ACTIVE_TASK_STATUSES = new Set(['running', 'dispatching', 'active', 'in_progress', 'executing']);
const QUEUED_TASK_STATUSES = new Set(['queued', 'pending', 'requested', 'waiting', 'pending_approval']);
const COMPLETED_TASK_STATUSES = new Set(['completed', 'succeeded', 'success', 'done']);
const FAILED_TASK_STATUSES = new Set(['failed', 'errored', 'error', 'cancelled', 'canceled', 'timed_out', 'timeout']);

const TERMINAL_RUN_STATUSES = new Set([
  'completed',
  'failed',
  'cancelled',
  'canceled',
  'completed_with_errors',
  'rejected',
  'errored',
  'stopped',
]);

const INCOMPLETE_STATUSES = new Set([
  'failed',
  'errored',
  'error',
  'cancelled',
  'canceled',
  'completed_with_errors',
  'completed_with_gaps',
  'blocked',
  'halted',
  'rejected',
  'stopped',
]);

const VERIFIED_FINDING_STATUSES = new Set([
  'confirmed',
  'validated',
  'validated_confirmed',
  'verified',
  'passed',
  'true_positive',
]);

type SeverityCounts = {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
};

export function buildRunTruthModel(run: Run, tasks: Task[], findings: Finding[]): RunTruthModel {
  const runStatus = normalizeStatus(run.status);
  const chain = recordOrNull(run.assessment_chain);
  const chainId = stringValue(chain?.id);
  const chainStatus = normalizeStatus(stringValue(chain?.status) || runStatus);
  const hasChain = Boolean(chainId);
  const displayStatus = hasChain
    ? `Chain ${humanizeStatus(chainStatus)} / run ${humanizeStatus(runStatus)}`
    : `Run ${humanizeStatus(runStatus)}`;
  const phaseLabel = phaseSummary(chain);

  const taskStats = taskCounts(tasks);
  const runIsTerminal = TERMINAL_RUN_STATUSES.has(runStatus);
  const canonicalSeverity = severityCountsFromFindings(findings);
  const canonicalHighPlus = canonicalSeverity.critical + canonicalSeverity.high;
  const persistedCount = findings.length;
  const evidenceLinkedCount = findings.filter((finding) => stringValue(finding.evidence_ref)).length;
  const verifiedCount = findings.filter(isVerifiedFinding).length;
  const observedSignals = Math.max(taskStats.completed, evidenceLinkedCount);
  const observedWithoutFindings = persistedCount === 0 && observedSignals > 0;

  const runLocalTotal = numberValue(run.findings?.finding_count);
  const runLocalSeverity = severityCountsFromSummary(run.findings?.findings_by_severity);
  const runLocalHighPlus = runLocalSeverity.critical + runLocalSeverity.high;
  const truthGaps: string[] = [];

  if (hasChain && runLocalTotal !== persistedCount) {
    truthGaps.push(`Run-local summary differs: ${runLocalTotal} run-local, ${persistedCount} aggregate`);
  }
  if (hasChain && runLocalHighPlus !== canonicalHighPlus) {
    truthGaps.push(`Run-local high+ differs: ${runLocalHighPlus} run-local, ${canonicalHighPlus} aggregate`);
  }

  const incompleteReasons: string[] = [];
  const hardBlockers: string[] = [];
  if (hasChain && INCOMPLETE_STATUSES.has(chainStatus)) {
    const reason = `assessment chain status is ${humanizeStatus(chainStatus)}`;
    incompleteReasons.push(reason);
    hardBlockers.push(reason);
  } else if (!hasChain && INCOMPLETE_STATUSES.has(runStatus)) {
    const reason = `run status is ${humanizeStatus(runStatus)}`;
    incompleteReasons.push(reason);
    hardBlockers.push(reason);
  }
  if (taskStats.failed > 0) {
    const reason = plural(taskStats.failed, 'failed task');
    incompleteReasons.push(reason);
    hardBlockers.push(reason);
  }
  if (runIsTerminal && taskStats.queued > 0) {
    const reason = `${plural(taskStats.queued, 'queued task')} still listed after run ended`;
    incompleteReasons.push(reason);
    hardBlockers.push(reason);
  }
  if (observedWithoutFindings) {
    const reason = runIsTerminal
      ? 'completed tool output ended without persisted findings'
      : 'completed tool output is not persisted as findings yet';
    incompleteReasons.push(reason);
    if (runIsTerminal) hardBlockers.push(reason);
  }
  if (persistedCount > 0 && verifiedCount < persistedCount) {
    incompleteReasons.push(`${plural(persistedCount - verifiedCount, 'persisted finding')} awaiting verification`);
  }
  if (numberValue(run.pending_approvals) > 0) {
    incompleteReasons.push(`${plural(numberValue(run.pending_approvals), 'approval')} pending`);
  }
  if (truthGaps.length > 0) {
    incompleteReasons.push('run-local summary is not the aggregate');
  }

  const attentionTone = hardBlockers.length > 0
    ? 'blocked'
    : incompleteReasons.length > 0
      ? 'warning'
      : 'complete';

  const canonicalScore = `${persistedCount} persisted / ${canonicalHighPlus} high+`;
  const canonicalScoreDetail = persistedCount > 0
    ? 'Scored from the canonical persisted findings list'
    : observedSignals > 0
      ? 'Tool output seen; score stays 0 until a finding is persisted'
      : 'No score input yet';
  const workflowSummary = taskStats.running > 0
    ? `Running: ${plural(taskStats.running, 'active task')}`
    : taskStats.queued > 0 && !runIsTerminal
      ? `Waiting: ${plural(taskStats.queued, 'task')} queued`
      : runIsTerminal
        ? `Ended: ${humanizeStatus(runStatus)}`
        : 'No active task right now';
  const evidenceSummary = persistedCount > 0
    ? `${plural(persistedCount, 'persisted finding')} / ${plural(verifiedCount, 'verified finding')}`
    : observedSignals > 0
      ? `${plural(observedSignals, 'observed output item')}, 0 persisted findings`
      : 'no observed evidence signal yet';
  const summaryDetail = observedWithoutFindings
    ? runIsTerminal
      ? 'The run has terminal task output but no canonical finding record, so reporting should treat this as a gap until reviewed.'
      : 'This is not blocked yet: completed task output is review-only until the backend creates a finding record.'
    : persistedCount > 0 && verifiedCount < persistedCount
      ? 'Persisted findings exist, but at least one still needs validation before it should be described as verified.'
      : attentionTone === 'complete'
        ? 'Canonical findings, verification state, and persistence agree.'
        : 'Review the attention note before treating this run as report-ready.';

  return {
    scopeLabel: hasChain ? 'Assessment chain aggregate' : 'Run-local truth',
    sourceDetail: hasChain ? `chain:${compactId(chainId)}` : `run:${compactId(run.id)}`,
    summaryHeadline: `${workflowSummary} · ${evidenceSummary}`,
    summaryDetail,
    statusLabel: displayStatus,
    phaseLabel,
    canonicalScore,
    canonicalScoreDetail,
    runLocalSummary: `${runLocalTotal} total / ${runLocalHighPlus} high+`,
    truthGapText: truthGaps.length > 0 ? truthGaps.join('; ') : null,
    attention: {
      tone: attentionTone,
      label: attentionTone === 'complete'
        ? 'Truth chain complete'
        : attentionTone === 'warning'
          ? 'Needs review'
          : 'Blocked / incomplete',
      detail: incompleteReasons.length > 0
        ? incompleteReasons.join('; ')
        : 'Canonical findings, proof state, and persistence agree.',
    },
    stages: [
      {
        key: 'queued',
        label: 'Queued',
        value: taskStats.queued > 0 ? plural(taskStats.queued, 'waiting task') : 'none',
        detail: taskStats.queued > 0 ? 'Work is waiting for dispatch or approval' : 'No queued task state',
        tone: taskStats.queued > 0 ? 'active' : 'idle',
      },
      {
        key: 'running',
        label: 'Running',
        value: taskStats.running > 0 ? plural(taskStats.running, 'active task') : 'idle',
        detail: taskStats.running > 0 ? 'Runtime work is still in flight' : 'No active task is running',
        tone: taskStats.running > 0 || ACTIVE_TASK_STATUSES.has(runStatus) ? 'active' : 'idle',
      },
      {
        key: 'observed',
        label: 'Output',
        value: observedSignals > 0 ? plural(observedSignals, 'output item') : 'none',
        detail: persistedCount === 0 && observedSignals > 0
          ? 'Observed task output only'
          : observedSignals > 0
            ? 'Task output or evidence reference captured'
            : 'No task output captured yet',
        tone: observedSignals > 0 ? 'complete' : 'idle',
      },
      {
        key: 'verified',
        label: 'Verified',
        value: verifiedCount > 0 ? plural(verifiedCount, 'confirmed finding') : 'none',
        detail: verifiedCount === persistedCount && persistedCount > 0
          ? 'Verification matches persisted findings'
          : persistedCount > 0
            ? `${plural(persistedCount - verifiedCount, 'finding')} still needs verification`
            : 'No finding is verified yet',
        tone: verifiedCount > 0 ? (verifiedCount === persistedCount ? 'complete' : 'warning') : 'idle',
      },
      {
        key: 'persisted',
        label: 'Persisted',
        value: persistedCount > 0 ? plural(persistedCount, 'finding') : 'none',
        detail: persistedCount > 0
          ? 'Fully persisted in canonical findings list'
          : observedSignals > 0
            ? 'No persisted findings yet'
            : 'No finding record yet',
        tone: persistedCount > 0 ? 'complete' : observedSignals > 0 ? 'warning' : 'idle',
      },
      {
        key: 'blocked',
        label: 'Attention',
        value: incompleteReasons.length > 0 ? plural(incompleteReasons.length, 'note') : 'clear',
        detail: incompleteReasons[0] ?? 'No incomplete truth-chain state',
        tone: attentionTone,
      },
    ],
  };
}

function taskCounts(tasks: Task[]) {
  return tasks.reduce(
    (counts, task) => {
      const status = normalizeStatus(task.status);
      if (QUEUED_TASK_STATUSES.has(status)) counts.queued += 1;
      if (ACTIVE_TASK_STATUSES.has(status)) counts.running += 1;
      if (COMPLETED_TASK_STATUSES.has(status)) counts.completed += 1;
      if (FAILED_TASK_STATUSES.has(status)) counts.failed += 1;
      return counts;
    },
    { queued: 0, running: 0, completed: 0, failed: 0 },
  );
}

function isVerifiedFinding(finding: Finding): boolean {
  const status = normalizeStatus(finding.validation_status);
  if (VERIFIED_FINDING_STATUSES.has(status)) return true;
  const validation = recordOrNull((finding as unknown as Record<string, unknown>).validation);
  const validationStatus = normalizeStatus(stringValue(validation?.status));
  const verdict = normalizeStatus(stringValue(validation?.verdict));
  return VERIFIED_FINDING_STATUSES.has(validationStatus) || verdict === 'passed';
}

function severityCountsFromFindings(findings: Finding[]): SeverityCounts {
  return findings.reduce<SeverityCounts>(
    (counts, finding) => {
      const severity = normalizeStatus(finding.severity);
      if (severity === 'critical' || severity === 'high' || severity === 'medium' || severity === 'low') {
        counts[severity] += 1;
      } else {
        counts.info += 1;
      }
      return counts;
    },
    { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
  );
}

function severityCountsFromSummary(summary: Record<string, number> | undefined): SeverityCounts {
  return {
    critical: numberValue(summary?.critical),
    high: numberValue(summary?.high),
    medium: numberValue(summary?.medium),
    low: numberValue(summary?.low),
    info: numberValue(summary?.info),
  };
}

function phaseSummary(chain: Record<string, unknown> | null): string | null {
  if (!chain) return null;
  const key = stringValue(chain.current_phase_key);
  const phases = Array.isArray(chain.phases) ? chain.phases : [];
  const activePhase = phases
    .map(recordOrNull)
    .find((phase) => stringValue(phase?.key) === key);
  const label = stringValue(activePhase?.label) || key;
  const status = normalizeStatus(stringValue(activePhase?.status));
  if (!label) return null;
  return status ? `${label} / ${humanizeStatus(status)}` : label;
}

function recordOrNull(value: unknown): Record<string, unknown> | null {
  return value && typeof value === 'object' ? value as Record<string, unknown> : null;
}

function stringValue(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

function numberValue(value: unknown): number {
  return typeof value === 'number' && Number.isFinite(value) ? value : 0;
}

function normalizeStatus(value: unknown): string {
  return stringValue(value).toLowerCase().replace(/\s+/g, '_');
}

function humanizeStatus(value: string): string {
  const normalized = normalizeStatus(value);
  if (!normalized) return 'unknown';
  return normalized.replace(/[_-]+/g, ' ');
}

function compactId(value: string): string {
  return value.length > 12 ? `${value.slice(0, 8)}...${value.slice(-4)}` : value;
}

function plural(count: number, singular: string): string {
  return `${count} ${singular}${count === 1 ? '' : 's'}`;
}
