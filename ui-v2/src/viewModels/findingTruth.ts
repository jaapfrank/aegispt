import type { Finding, FindingEvidenceReplay, FindingTheater } from '../api/types';

export type FindingTruthTone = 'verified' | 'observed' | 'blocked' | 'resolved';

export interface FindingTruthModel {
  displayTitle: string;
  rawTitle: string;
  rawTitleWasNormalized: boolean;
  workflowLabel: string;
  validationLabel: string;
  evidenceLabel: string;
  proofLabel: string;
  proofDetail: string;
  sourceLabel: string;
  tone: FindingTruthTone;
  evidenceSummary: string | null;
  businessImpact: string | null;
  remediationText: string | null;
  nextSteps: string[];
}

const VERIFIED_STATUSES = new Set(['confirmed', 'validated', 'validated_confirmed', 'verified', 'passed', 'true_positive']);
const OBSERVED_STATUSES = new Set(['validation_queued', 'validation_running', 'queued', 'running', 'observed', 'unvalidated']);
const BLOCKED_STATUSES = new Set([
  'validated_not_reproduced',
  'validation_skipped',
  'false_positive',
  'rejected',
  'blocked',
  'failed',
]);

export function buildFindingTruthModel(
  finding: Finding,
  detail: FindingTheater | null,
  evidence: FindingEvidenceReplay | null,
): FindingTruthModel {
  const rawTitle = String(finding.title || 'Untitled finding');
  const rawTitleWasNormalized = isRawRunnerTitle(rawTitle);
  const evidenceLinked = Boolean(String(finding.evidence_ref || '').trim());
  const replayLinked = Boolean(evidence?.related_executions?.length);
  const validationStatus = normalizeStatus(finding.validation_status || detail?.verification_status || '');
  const workflowStatus = normalizeStatus(finding.status);
  const tone = truthTone({ workflowStatus, validationStatus, evidenceLinked });
  const host = targetLabel(finding.target_id);
  const displayTitle = rawTitleWasNormalized
    ? `${tone === 'verified' ? 'Verified' : tone === 'blocked' ? 'Blocked' : 'Observed'} flag capture${host ? ` on ${host}` : ''}`
    : rawTitle;

  const remediationText = firstText([
    detail?.remediation?.ai_narrative,
    detail?.remediation?.detail,
    detail?.remediation?.summary,
  ]);
  const nextSteps = Array.isArray(detail?.next_steps)
    ? detail.next_steps.map((step) => String(step).trim()).filter(Boolean)
    : [];

  return {
    displayTitle,
    rawTitle,
    rawTitleWasNormalized,
    workflowLabel: `Workflow: ${humanizeStatus(workflowStatus || 'unknown')}`,
    validationLabel: `Validation: ${validationLabel(validationStatus, detail?.verification_status)}`,
    evidenceLabel: replayLinked
      ? 'Evidence: replay linked'
      : evidenceLinked
        ? 'Evidence: reference linked'
        : 'Evidence: missing',
    proofLabel: proofLabel(tone),
    proofDetail: proofDetail({ tone, validationStatus, evidenceLinked, replayLinked }),
    sourceLabel: sourceLabel(finding),
    tone,
    evidenceSummary: firstText([detail?.evidence_summary]),
    businessImpact: firstText([detail?.business_impact]),
    remediationText,
    nextSteps,
  };
}

function truthTone({
  workflowStatus,
  validationStatus,
  evidenceLinked,
}: {
  workflowStatus: string;
  validationStatus: string;
  evidenceLinked: boolean;
}): FindingTruthTone {
  if (workflowStatus === 'resolved' || workflowStatus === 'fixed') return 'resolved';
  if (!evidenceLinked || BLOCKED_STATUSES.has(validationStatus) || workflowStatus === 'false_positive') return 'blocked';
  if (VERIFIED_STATUSES.has(validationStatus)) return 'verified';
  if (OBSERVED_STATUSES.has(validationStatus) || evidenceLinked) return 'observed';
  return 'blocked';
}

function proofLabel(tone: FindingTruthTone): string {
  if (tone === 'verified') return 'Verified finding';
  if (tone === 'resolved') return 'Resolved finding';
  if (tone === 'observed') return 'Observed finding';
  return 'Blocked / incomplete';
}

function proofDetail({
  tone,
  validationStatus,
  evidenceLinked,
  replayLinked,
}: {
  tone: FindingTruthTone;
  validationStatus: string;
  evidenceLinked: boolean;
  replayLinked: boolean;
}): string {
  if (!evidenceLinked) return 'No evidence reference is linked to this finding.';
  if (tone === 'verified') {
    return replayLinked
      ? 'Validation and replay evidence are both present.'
      : 'Validation is confirmed; replay detail has not loaded yet.';
  }
  if (tone === 'observed') {
    return `Evidence is present, but validation is ${humanizeStatus(validationStatus || 'not confirmed')}.`;
  }
  if (tone === 'resolved') {
    return 'Workflow is resolved; retest evidence should confirm closure.';
  }
  return `Truth chain is incomplete: validation is ${humanizeStatus(validationStatus || 'unknown')}.`;
}

function validationLabel(validationStatus: string, verificationStatus: string | undefined): string {
  const readable = verificationStatus && verificationStatus.trim()
    ? verificationStatus.trim()
    : humanizeStatus(validationStatus || 'unknown');
  return readable;
}

function sourceLabel(finding: Finding): string {
  const tool = firstText([finding.replay_recipe_json?.tool]);
  if (tool) return `Source: ${tool}`;
  const origin = normalizeStatus(finding.finding_origin || 'runner');
  return `Source: ${humanizeStatus(origin)}`;
}

function isRawRunnerTitle(title: string): boolean {
  const normalized = title.toLowerCase();
  return (
    normalized.includes('flag captured') ||
    normalized.includes('interactive-exploit') ||
    normalized.includes('interactive_exploit') ||
    /^flag\s*[:_-]/i.test(title.trim())
  );
}

function targetLabel(targetId: string): string {
  const trimmed = targetId.trim();
  if (!trimmed) return '';
  try {
    return new URL(trimmed).host;
  } catch {
    return trimmed.length > 80 ? `${trimmed.slice(0, 79)}...` : trimmed;
  }
}

function firstText(values: unknown[]): string | null {
  for (const value of values) {
    if (typeof value === 'string' && value.trim()) return value.trim();
    if (typeof value === 'number' && Number.isFinite(value)) return String(value);
  }
  return null;
}

function normalizeStatus(value: unknown): string {
  return typeof value === 'string' ? value.trim().toLowerCase().replace(/\s+/g, '_') : '';
}

function humanizeStatus(value: string): string {
  const normalized = normalizeStatus(value);
  return normalized ? normalized.replace(/[_-]+/g, ' ') : 'unknown';
}
