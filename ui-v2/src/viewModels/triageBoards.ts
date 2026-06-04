import type { Finding, ProblemRead } from '../api/types';

export type TriageSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info' | 'unknown';
export type ProofStrength = 'strong' | 'partial' | 'missing';

export interface FindingTriageGroup {
  id: string;
  title: string;
  severity: TriageSeverity;
  findings: Finding[];
  representative: Finding;
  count: number;
  targetCount: number;
  evidenceCount: number;
  verifiedCount: number;
  missingEvidenceCount: number;
  dueSoonCount: number;
  slaBreachCount: number;
  highestCvss: number | null;
  targetLabels: string[];
  evidenceRefs: string[];
  proofStrength: ProofStrength;
  proofLabel: string;
  impactLabel: string;
  remediationLabel: string;
  nextAction: string;
}

export interface FindingTriageLane {
  severity: TriageSeverity;
  label: string;
  count: number;
  groups: FindingTriageGroup[];
}

export interface FindingsTriageModel {
  totalFindings: number;
  totalGroups: number;
  evidenceReadyCount: number;
  missingEvidenceCount: number;
  verifiedCount: number;
  dueSoonCount: number;
  slaBreachCount: number;
  lanes: FindingTriageLane[];
  leadGroup: FindingTriageGroup | null;
  repeatedGroups: FindingTriageGroup[];
  decisionLabel: string;
  decisionDetail: string;
  proofDetail: string;
  remediationDetail: string;
}

export interface ProblemDecisionItem {
  id: string;
  findingId: string;
  title: string;
  severity: TriageSeverity;
  status: string;
  assigneeLabel: string;
  ageLabel: string;
  slaLabel: string;
  nextAction: string;
  reason: string;
  problem: ProblemRead;
}

export interface ProblemTriageLane {
  id: 'urgent' | 'due' | 'owner' | 'sla';
  label: string;
  detail: string;
  items: ProblemDecisionItem[];
}

export interface ProblemsTriageModel {
  totalOpen: number;
  leadItem: ProblemDecisionItem | null;
  lanes: ProblemTriageLane[];
  decisionLabel: string;
  decisionDetail: string;
}

const SEVERITY_ORDER: TriageSeverity[] = ['critical', 'high', 'medium', 'low', 'info'];
const VERIFIED_STATUSES = new Set(['confirmed', 'validated', 'validated_confirmed', 'verified', 'passed', 'true_positive']);
const CLOSED_STATUSES = new Set(['resolved', 'fixed', 'verified', 'false_positive']);

export function buildFindingsTriageModel(findings: Finding[], now: Date = new Date()): FindingsTriageModel {
  const groups = groupFindings(findings, now);
  const lanes = SEVERITY_ORDER.map((severity) => {
    const laneGroups = groups.filter((group) => group.severity === severity);
    return {
      severity,
      label: titleCase(severity),
      count: laneGroups.reduce((total, group) => total + group.count, 0),
      groups: laneGroups,
    };
  }).filter((lane) => lane.count > 0);

  const leadGroup = groups[0] ?? null;
  const evidenceReadyCount = findings.filter(hasEvidence).length;
  const missingEvidenceCount = findings.length - evidenceReadyCount;
  const verifiedCount = findings.filter(isVerifiedFinding).length;
  const dueSoonCount = findings.filter((finding) => isDueSoon(finding.remediation_due_date, now)).length;
  const slaBreachCount = findings.filter((finding) => finding.sla_breached).length;

  return {
    totalFindings: findings.length,
    totalGroups: groups.length,
    evidenceReadyCount,
    missingEvidenceCount,
    verifiedCount,
    dueSoonCount,
    slaBreachCount,
    lanes,
    leadGroup,
    repeatedGroups: groups.filter((group) => group.count > 1),
    decisionLabel: leadGroup ? `Fix first: ${leadGroup.title}` : 'No findings need triage',
    decisionDetail: leadGroup
      ? `${leadGroup.count} finding${leadGroup.count === 1 ? '' : 's'} in this group. ${leadGroup.nextAction}`
      : 'No stored findings match the current filters.',
    proofDetail: `${verifiedCount}/${findings.length} verified, ${evidenceReadyCount}/${findings.length} with linked evidence.`,
    remediationDetail: remediationSummary({ dueSoonCount, slaBreachCount, missingEvidenceCount }),
  };
}

export function buildProblemsTriageModel(items: ProblemRead[]): ProblemsTriageModel {
  const openItems = items.filter((item) => !CLOSED_STATUSES.has(normalizeStatus(item.problem_status || item.status)));
  const decisions = openItems.map(problemDecisionItem).sort(compareProblemDecisionItems);
  const urgent = decisions.filter((item) => ['critical', 'high'].includes(item.severity));
  const due = decisions.filter((item) => isProblemDue(item.problem));
  const owner = decisions.filter((item) => !item.problem.assignee);
  const sla = decisions.filter((item) => isProblemSlaWatch(item.problem));
  const leadItem = decisions[0] ?? null;

  return {
    totalOpen: openItems.length,
    leadItem,
    decisionLabel: leadItem ? `Today: ${leadItem.nextAction}` : 'No open problems need action',
    decisionDetail: leadItem
      ? `${leadItem.title} is the top problem because ${leadItem.reason}.`
      : 'The current filters do not return open remediation work.',
    lanes: [
      { id: 'urgent', label: 'Urgent', detail: 'Critical/high problems first', items: urgent },
      { id: 'due', label: 'Due', detail: 'Overdue or due-soon work', items: due },
      { id: 'owner', label: 'Owner needed', detail: 'No assignee in the payload', items: owner },
      { id: 'sla', label: 'SLA watch', detail: 'Overdue bucket or long-open item', items: sla },
    ],
  };
}

function groupFindings(findings: Finding[], now: Date): FindingTriageGroup[] {
  const buckets = new Map<string, Finding[]>();
  for (const finding of findings) {
    const key = `${normalizeSeverity(finding.severity)}:${normalizeFindingTitle(finding.title)}`;
    buckets.set(key, [...(buckets.get(key) ?? []), finding]);
  }

  return [...buckets.entries()]
    .map(([id, items]) => findingGroup(id, items, now))
    .sort(compareFindingGroups);
}

function findingGroup(id: string, findings: Finding[], now: Date): FindingTriageGroup {
  const sorted = [...findings].sort(compareFindings);
  const representative = sorted[0];
  const severity = normalizeSeverity(representative.severity);
  const evidenceRefs = sorted.map((finding) => finding.evidence_ref).filter(Boolean);
  const evidenceCount = sorted.filter(hasEvidence).length;
  const verifiedCount = sorted.filter(isVerifiedFinding).length;
  const missingEvidenceCount = sorted.length - evidenceCount;
  const dueSoonCount = sorted.filter((finding) => isDueSoon(finding.remediation_due_date, now)).length;
  const slaBreachCount = sorted.filter((finding) => finding.sla_breached).length;
  const targetLabels = [...new Set(sorted.map((finding) => compactTarget(finding.target_id)).filter(Boolean))];
  const highestCvss = sorted.reduce<number | null>((current, finding) => {
    if (typeof finding.cvss_score !== 'number') return current;
    return current === null ? finding.cvss_score : Math.max(current, finding.cvss_score);
  }, null);
  const proofStrength = proofStrengthFor({ evidenceCount, verifiedCount, total: sorted.length });

  return {
    id,
    title: cleanFindingTitle(representative.title),
    severity,
    findings: sorted,
    representative,
    count: sorted.length,
    targetCount: targetLabels.length,
    evidenceCount,
    verifiedCount,
    missingEvidenceCount,
    dueSoonCount,
    slaBreachCount,
    highestCvss,
    targetLabels,
    evidenceRefs,
    proofStrength,
    proofLabel: proofLabel(proofStrength),
    impactLabel: impactLabel(severity, highestCvss),
    remediationLabel: remediationLabel({ dueSoonCount, slaBreachCount }),
    nextAction: nextFindingAction({ severity, proofStrength, dueSoonCount, slaBreachCount }),
  };
}

function problemDecisionItem(problem: ProblemRead): ProblemDecisionItem {
  const severity = normalizeSeverity(problem.severity);
  const unassigned = !problem.assignee;
  const due = isProblemDue(problem);
  const sla = isProblemSlaWatch(problem);
  const nextAction = unassigned
    ? 'assign an owner'
    : due
      ? 'set a fix date'
      : severity === 'critical' || severity === 'high'
        ? 'review remediation'
        : 'keep in backlog';
  const reason = [
    severity === 'critical' || severity === 'high' ? `${severity} severity` : null,
    due ? `${problem.age_bucket.replace(/_/g, ' ')} age bucket` : null,
    unassigned ? 'no owner is assigned' : null,
    sla ? 'SLA watch is active' : null,
  ].filter(Boolean).join(', ') || 'it is still open';

  return {
    id: problem.id,
    findingId: problem.finding_id,
    title: cleanFindingTitle(problem.title),
    severity,
    status: problem.problem_status || problem.status,
    assigneeLabel: problem.assignee || 'unassigned',
    ageLabel: `${problem.days_open}d open`,
    slaLabel: sla ? 'SLA watch' : 'No SLA flag',
    nextAction,
    reason,
    problem,
  };
}

function compareFindingGroups(left: FindingTriageGroup, right: FindingTriageGroup): number {
  return (
    severityRank(left.severity) - severityRank(right.severity) ||
    proofRank(left.proofStrength) - proofRank(right.proofStrength) ||
    right.slaBreachCount - left.slaBreachCount ||
    right.dueSoonCount - left.dueSoonCount ||
    (right.highestCvss ?? -1) - (left.highestCvss ?? -1) ||
    right.count - left.count ||
    left.title.localeCompare(right.title)
  );
}

function compareFindings(left: Finding, right: Finding): number {
  return (
    severityRank(normalizeSeverity(left.severity)) - severityRank(normalizeSeverity(right.severity)) ||
    Number(!hasEvidence(left)) - Number(!hasEvidence(right)) ||
    Number(!isVerifiedFinding(left)) - Number(!isVerifiedFinding(right)) ||
    (right.cvss_score ?? -1) - (left.cvss_score ?? -1) ||
    left.title.localeCompare(right.title)
  );
}

function compareProblemDecisionItems(left: ProblemDecisionItem, right: ProblemDecisionItem): number {
  return (
    severityRank(left.severity) - severityRank(right.severity) ||
    Number(!isProblemDue(left.problem)) - Number(!isProblemDue(right.problem)) ||
    Number(Boolean(left.problem.assignee)) - Number(Boolean(right.problem.assignee)) ||
    Number(!isProblemSlaWatch(left.problem)) - Number(!isProblemSlaWatch(right.problem)) ||
    right.problem.days_open - left.problem.days_open ||
    left.title.localeCompare(right.title)
  );
}

function normalizeFindingTitle(title: string): string {
  return cleanFindingTitle(title)
    .toLowerCase()
    .replace(/https?:\/\/\S+/g, '')
    .replace(/[a-f0-9]{12,}/g, '')
    .replace(/[^a-z0-9]+/g, ' ')
    .trim();
}

function cleanFindingTitle(title: string): string {
  const trimmed = title.trim() || 'Untitled finding';
  return trimmed.replace(/\s+/g, ' ');
}

function normalizeSeverity(value: string): TriageSeverity {
  const normalized = value.trim().toLowerCase();
  if (normalized === 'critical' || normalized === 'high' || normalized === 'medium' || normalized === 'low' || normalized === 'info') return normalized;
  return 'unknown';
}

function severityRank(severity: TriageSeverity): number {
  if (severity === 'critical') return 0;
  if (severity === 'high') return 1;
  if (severity === 'medium') return 2;
  if (severity === 'low') return 3;
  if (severity === 'info') return 4;
  return 5;
}

function proofRank(proofStrength: ProofStrength): number {
  if (proofStrength === 'strong') return 0;
  if (proofStrength === 'partial') return 1;
  return 2;
}

function hasEvidence(finding: Finding): boolean {
  return Boolean(finding.evidence_ref?.trim());
}

function isVerifiedFinding(finding: Finding): boolean {
  return VERIFIED_STATUSES.has(normalizeStatus(finding.validation_status));
}

function proofStrengthFor({ evidenceCount, verifiedCount, total }: { evidenceCount: number; verifiedCount: number; total: number }): ProofStrength {
  if (total > 0 && evidenceCount === total && verifiedCount === total) return 'strong';
  if (evidenceCount > 0) return 'partial';
  return 'missing';
}

function proofLabel(proofStrength: ProofStrength): string {
  if (proofStrength === 'strong') return 'Strong proof';
  if (proofStrength === 'partial') return 'Proof needs review';
  return 'Evidence missing';
}

function impactLabel(severity: TriageSeverity, cvss: number | null): string {
  const score = typeof cvss === 'number' ? ` / CVSS ${cvss.toFixed(1)}` : '';
  if (severity === 'critical') return `Highest impact lane${score}`;
  if (severity === 'high') return `High impact lane${score}`;
  if (severity === 'medium') return `Medium impact lane${score}`;
  if (severity === 'low') return `Low impact lane${score}`;
  if (severity === 'info') return `Informational lane${score}`;
  return `Impact needs classification${score}`;
}

function remediationLabel({ dueSoonCount, slaBreachCount }: { dueSoonCount: number; slaBreachCount: number }): string {
  if (slaBreachCount > 0) return `${slaBreachCount} SLA breach${slaBreachCount === 1 ? '' : 'es'}`;
  if (dueSoonCount > 0) return `${dueSoonCount} due soon`;
  return 'No due date pressure in list payload';
}

function nextFindingAction({
  severity,
  proofStrength,
  dueSoonCount,
  slaBreachCount,
}: {
  severity: TriageSeverity;
  proofStrength: ProofStrength;
  dueSoonCount: number;
  slaBreachCount: number;
}): string {
  if (proofStrength === 'missing') return 'Verify evidence before assigning remediation.';
  if (slaBreachCount > 0) return 'Assign owner today and recover the SLA.';
  if (dueSoonCount > 0) return 'Confirm owner and fix date before the due window closes.';
  if (severity === 'critical' || severity === 'high') return 'Assign remediation owner and schedule a retest.';
  return 'Review detail, then keep or close through the normal workflow.';
}

function remediationSummary({
  dueSoonCount,
  slaBreachCount,
  missingEvidenceCount,
}: {
  dueSoonCount: number;
  slaBreachCount: number;
  missingEvidenceCount: number;
}): string {
  if (slaBreachCount > 0) return `${slaBreachCount} item${slaBreachCount === 1 ? '' : 's'} already breach the recorded SLA.`;
  if (dueSoonCount > 0) return `${dueSoonCount} item${dueSoonCount === 1 ? '' : 's'} have a recorded due date in the next seven days.`;
  if (missingEvidenceCount > 0) return `${missingEvidenceCount} item${missingEvidenceCount === 1 ? '' : 's'} need evidence review before remediation.`;
  return 'No due-date or SLA pressure is recorded in the list payload.';
}

function isDueSoon(value: string | null, now: Date): boolean {
  if (!value) return false;
  const due = new Date(value);
  if (Number.isNaN(due.getTime())) return false;
  const delta = due.getTime() - now.getTime();
  return delta <= 7 * 24 * 60 * 60 * 1000;
}

function isProblemDue(problem: ProblemRead): boolean {
  const bucket = normalizeStatus(problem.age_bucket);
  return bucket === 'overdue' || bucket === 'due_soon';
}

function isProblemSlaWatch(problem: ProblemRead): boolean {
  return normalizeStatus(problem.age_bucket) === 'overdue' || problem.days_open >= 14;
}

function normalizeStatus(value: string): string {
  return value.trim().toLowerCase().replace(/[\s-]+/g, '_');
}

function compactTarget(target: string): string {
  const trimmed = target.trim();
  if (!trimmed) return '';
  try {
    const parsed = new URL(trimmed);
    return `${parsed.host}${parsed.pathname === '/' ? '' : parsed.pathname}`;
  } catch {
    return trimmed.length > 60 ? `${trimmed.slice(0, 59)}...` : trimmed;
  }
}

function titleCase(value: string): string {
  return value.replace(/(^|_)([a-z])/g, (_match, _prefix: string, letter: string) => letter.toUpperCase());
}
