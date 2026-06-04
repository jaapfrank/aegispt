import type { Finding, InventorySnapshot, Run, Task, TaskExecution } from '../api/types';

export type MissionPhaseKey = 'map' | 'inspect' | 'test' | 'proof' | 'report';
export type MissionChapterState = 'done' | 'active' | 'waiting';

type TaskWithExecutions = Task & { executions?: TaskExecution[] };

export const MISSION_PHASES: Array<{
  key: MissionPhaseKey;
  label: string;
  shortLabel: string;
  story: string;
}> = [
  {
    key: 'map',
    label: 'Map surface',
    shortLabel: 'Map',
    story: 'AegisPT first draws the outside of the system: hosts, pages, services, and reachable paths.',
  },
  {
    key: 'inspect',
    label: 'Inspect behavior',
    shortLabel: 'Inspect',
    story: 'The system checks how the app behaves so later tests follow the right route.',
  },
  {
    key: 'test',
    label: 'Test routes',
    shortLabel: 'Test',
    story: 'Bounded checks try likely weakness paths. Tool output is still only signal until proof is saved.',
  },
  {
    key: 'proof',
    label: 'Prove impact',
    shortLabel: 'Proof',
    story: 'Evidence turns into reportable proof only when a finding is persisted and linked back to artifacts.',
  },
  {
    key: 'report',
    label: 'Tell outcome',
    shortLabel: 'Report',
    story: 'The final report should reuse the same evidence path, not a separate story.',
  },
];

export interface MissionEvidenceChapter {
  key: MissionPhaseKey;
  label: string;
  shortLabel: string;
  story: string;
  state: MissionChapterState;
  taskCount: number;
  executionCount: number;
  artifactCount: number;
  findingCount: number;
}

export function missionPhaseForTask(task: Pick<Task, 'tool' | 'target_id' | 'status'>): MissionPhaseKey {
  const text = `${task.tool || ''} ${task.target_id || ''}`.toLowerCase();
  if (/\b(report|export|summary)\b/.test(text)) return 'report';
  if (/\b(verif|proof|grader|evidence|persist|finding|m2)\b/.test(text)) return 'proof';
  if (/\b(sqlmap|xss|attack|exploit|rce|exec|ssti|csrf|upload|param|idor|inject|shell|auth-flow|nuclei|zap|burp)\b/.test(text)) return 'test';
  if (/\b(nmap|masscan|recon|surface|target-intel|bootstrap|fingerprint|httpx|content-discovery)\b/.test(text)) return 'map';
  return 'inspect';
}

export function missionPhaseCopy(key: MissionPhaseKey) {
  return MISSION_PHASES.find((phase) => phase.key === key) ?? MISSION_PHASES[1];
}

export function buildMissionEvidenceChapters(
  tasks: TaskWithExecutions[],
  findings: Finding[],
): MissionEvidenceChapter[] {
  return MISSION_PHASES.map((phase) => {
    const phaseTasks = tasks.filter((task) => missionPhaseForTask(task) === phase.key);
    const executionCount = phaseTasks.reduce((total, task) => total + (Array.isArray(task.executions) ? task.executions.length : 0), 0);
    const artifactCount = phaseTasks.reduce(
      (total, task) =>
        total + (Array.isArray(task.executions)
          ? task.executions.reduce((executionTotal, execution) => executionTotal + execution.artifacts.length, 0)
          : 0),
      0,
    );
    const findingCount = phase.key === 'proof' ? findings.length : 0;
    return {
      ...phase,
      state: chapterState(phase.key, phaseTasks, findings),
      taskCount: phaseTasks.length,
      executionCount,
      artifactCount,
      findingCount,
    };
  });
}

function chapterState(key: MissionPhaseKey, tasks: TaskWithExecutions[], findings: Finding[]): MissionChapterState {
  if (key === 'proof' && findings.length > 0) return 'done';
  if (key === 'report' && findings.length > 0) return 'active';
  if (tasks.some((task) => isActiveTaskStatus(task.status))) return 'active';
  if (tasks.some((task) => hasTaskEvidence(task))) return 'done';
  return 'waiting';
}

export function taskJourneyTitle(task: Pick<Task, 'tool' | 'target_id' | 'status'>): string {
  const phase = missionPhaseForTask(task);
  const tool = humanizeMissionTool(task.tool);
  if (phase === 'map') return `${tool} mapped the surface`;
  if (phase === 'inspect') return `${tool} inspected behavior`;
  if (phase === 'test') return `${tool} tested a possible route`;
  if (phase === 'proof') return `${tool} checked proof`;
  return `${tool} prepared the outcome`;
}

export function taskJourneyDetail(task: Pick<Task, 'tool' | 'target_id' | 'status'>): string {
  const phase = missionPhaseCopy(missionPhaseForTask(task));
  return `${phase.story} Status: ${humanizeMissionValue(task.status)}.`;
}

export function taskWhyItMatters(task: Pick<Task, 'tool' | 'target_id' | 'status'>): string {
  const phase = missionPhaseForTask(task);
  if (phase === 'map') return 'This step explains what AegisPT knew before choosing deeper checks.';
  if (phase === 'inspect') return 'This step reduces guesswork by showing how the application behaves.';
  if (phase === 'test') return 'This step shows which attack route was tried and whether it produced usable signal.';
  if (phase === 'proof') return 'This step is where signal should become evidence-backed proof, if a finding is saved.';
  return 'This step connects the recorded evidence to the final customer-facing outcome.';
}

export function safeMissionFindingTitle(finding: Finding): string {
  const title = String(finding.title || '').trim();
  const fallback = findingClusterTitle(finding);
  if (!title) return fallback;
  if (internalMarkerPattern.test(title) || technicalTitlePattern.test(title)) return fallback;
  return title.length > 56 ? `${title.slice(0, 53)}...` : title;
}

export function strongestMissionFinding(findings: Finding[]): Finding | null {
  const rank: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  return [...findings].sort((a, b) => (rank[a.severity?.toLowerCase()] ?? 9) - (rank[b.severity?.toLowerCase()] ?? 9))[0] ?? null;
}

export function summarizeMissionTarget(run: Run, inventory?: InventorySnapshot | null): string {
  const targets = run.configuration_json?.targets;
  if (targets && typeof targets === 'object') {
    const values = Object.values(targets)
      .flatMap((value) => (Array.isArray(value) ? value : []))
      .filter((value): value is string => typeof value === 'string' && value.trim().length > 0);
    if (values[0]) return values[0];
  }
  const summary = inventory?.summary_json;
  const endpointCount = typeof summary?.endpoint_count === 'number' ? summary.endpoint_count : 0;
  const hostCount = typeof summary?.host_count === 'number' ? summary.host_count : 0;
  if (endpointCount > 0) return `${endpointCount} endpoint${endpointCount === 1 ? '' : 's'}`;
  if (hostCount > 0) return `${hostCount} host${hostCount === 1 ? '' : 's'}`;
  return humanizeMissionValue(run.profile?.name || 'selected run');
}

export function humanizeMissionTool(tool: string): string {
  const normalized = humanizeMissionValue(tool);
  if (!normalized) return 'Task';
  if (normalized.toLowerCase() === 'nmap') return 'Nmap';
  if (normalized.toLowerCase() === 'sqlmap') return 'SQL route check';
  if (normalized.toLowerCase() === 'httpx') return 'HTTP reachability';
  if (normalized.toLowerCase() === 'auth flow') return 'Authentication flow';
  if (normalized.toLowerCase() === 'interactive exploit') return 'Proof route';
  return normalized
    .split(' ')
    .map((part) => (part.length <= 3 ? part.toUpperCase() : `${part.charAt(0).toUpperCase()}${part.slice(1)}`))
    .join(' ');
}

export function humanizeMissionValue(value: string | null | undefined): string {
  return String(value || 'unknown').replace(/[_-]+/g, ' ').replace(/\s+/g, ' ').trim();
}

export function isActiveTaskStatus(status: string | null | undefined): boolean {
  return ['running', 'dispatching', 'active', 'in_progress', 'executing'].includes(String(status || '').toLowerCase());
}

function hasTaskEvidence(task: TaskWithExecutions): boolean {
  const status = String(task.status || '').toLowerCase();
  if (['completed', 'succeeded', 'success', 'done', 'failed', 'error'].includes(status)) return true;
  return Array.isArray(task.executions) && task.executions.length > 0;
}

function findingClusterTitle(finding: Finding): string {
  const combined = [
    finding.title,
    finding.summary,
    finding.control_family,
    finding.owasp_category,
    finding.wstg_id,
    ...(finding.methodology_tags ?? []),
  ].join(' ').toLowerCase();
  if (/auth|credential|password|login|account|jwt|token/.test(combined)) return 'Account access protection';
  if (/ssrf|server side request|internal service/.test(combined)) return 'Internal service access protection';
  if (/authorization|access control|idor|permission|privilege|admin/.test(combined)) return 'Authorization and permissions';
  if (/xss|sql injection|path traversal|command injection|upload|ssti|input|template/.test(combined)) return 'Input and data handling';
  if (/cookie|session|csrf|clickjacking|frame|csp|hsts/.test(combined)) return 'Browser and session protection';
  if (/tls|ssl|cipher|https|crypto/.test(combined)) return 'Connection and encryption hygiene';
  if (/api|graphql|workflow|business logic/.test(combined)) return 'API and business process controls';
  if (/exposed|directory|backup|fingerprint|header|configuration/.test(combined)) return 'Exposure and configuration';
  return 'Security control improvement';
}

const internalMarkerPattern = /\b(flag|xbow|xben|interactive[-_ ]exploit|run[-_ ]local|exec[-_ ]plan|sqlmap|grader|benchmark|fixture|aegispt\{)/i;
const technicalTitlePattern = /\b(x-frame|xss|csrf|ssrf|ssti|idor|rce|sql injection|path traversal|command injection|jwt|oauth|cookie|cve|csp|hsts)\b/i;
