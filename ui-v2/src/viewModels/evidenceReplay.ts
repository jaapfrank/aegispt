import type { Finding, JsonMap, Run, TaskDetail, TaskExecution } from '../api/types';
import {
  buildMissionEvidenceChapters,
  missionPhaseCopy,
  missionPhaseForTask,
  safeMissionFindingTitle,
  strongestMissionFinding,
  summarizeMissionTarget,
  taskJourneyDetail,
  taskJourneyTitle,
  taskWhyItMatters,
  type MissionEvidenceChapter,
  type MissionPhaseKey,
} from './missionStory';

export interface EvidenceReplayTaskModel {
  id: string;
  phase: MissionPhaseKey;
  phaseLabel: string;
  journeyTitle: string;
  journeyDetail: string;
  whyItMatters: string;
  technicalLabel: string;
  evidenceState: string;
  transcriptState: string;
  artifactState: string;
  provenanceLabel: string;
  executionCount: number;
  artifactCount: number;
  transcriptLineCount: number;
  hasExecutionEvidence: boolean;
  hasTranscript: boolean;
  linkedFindingCount: number;
}

export interface EvidenceReplayTimelineFact {
  label: string;
  value: string;
}

export interface EvidenceReplayTimelineEvent {
  id: string;
  kind: 'task' | 'finding';
  phase: MissionPhaseKey;
  at: string | null;
  title: string;
  detail: string;
  proves: string;
  doesNotProve: string;
  evidenceState: string;
  routeLabel: string;
  routeHref: string;
  taskId: string | null;
  findingId: string | null;
  linkedTaskTitle: string | null;
  linkedArtifactLabel: string | null;
  target: string;
  facts: EvidenceReplayTimelineFact[];
  tone: 'green' | 'cyan' | 'amber' | 'red' | 'muted';
}

export interface EvidenceReplayModel {
  sourceLabel: string;
  sourceDetail: string;
  conclusionLabel: string;
  conclusionDetail: string;
  missionTitle: string;
  missionDetail: string;
  chapters: MissionEvidenceChapter[];
  taskCount: number;
  executionCount: number;
  artifactCount: number;
  transcriptCount: number;
  tasks: EvidenceReplayTaskModel[];
  timeline: EvidenceReplayTimelineEvent[];
}

export function buildEvidenceReplayModel(run: Run, taskDetails: TaskDetail[], findings: Finding[] = []): EvidenceReplayModel {
  const chainId = typeof run.assessment_chain?.id === 'string' ? run.assessment_chain.id : null;
  const tasks = taskDetails.map((task) => taskModel(task, findings));
  const executionCount = tasks.reduce((total, task) => total + task.executionCount, 0);
  const artifactCount = tasks.reduce((total, task) => total + task.artifactCount, 0);
  const transcriptCount = tasks.reduce((total, task) => total + task.transcriptLineCount, 0);
  const currentPhase = chainId && Array.isArray(run.assessment_chain?.phases)
    ? run.assessment_chain.phases.find((phase) => phase.key === run.assessment_chain?.current_phase_key)
    : null;
  const phaseDetail = currentPhase
    ? `${currentPhase.label} / ${currentPhase.status}`
    : run.status;
  const topFinding = strongestMissionFinding(findings);
  const missionTarget = summarizeMissionTarget(run);
  const missionTitle = topFinding
    ? `Proof route: ${safeMissionFindingTitle(topFinding)}`
    : executionCount > 0
      ? `Evidence route for ${missionTarget}`
      : `No replay evidence for ${missionTarget}`;
  const missionDetail = topFinding
    ? `This evidence path supports ${findings.length} saved finding${findings.length === 1 ? '' : 's'}. Open each step to see transcript, artifacts, and provenance.`
    : 'This page shows what was tried and what evidence exists. A customer-facing conclusion appears only after a finding is saved.';

  return {
    sourceLabel: chainId ? 'Assessment chain route' : 'Selected run route',
    sourceDetail: chainId ? `Chain evidence · ${phaseDetail}` : `${run.profile.name} · ${run.status}`,
    conclusionLabel: 'Not inferred here',
    conclusionDetail: 'Evidence Replay shows execution, transcript, artifact, and provenance state only; finding validation and business conclusions stay in Findings Theater and reports.',
    missionTitle,
    missionDetail,
    chapters: buildMissionEvidenceChapters(taskDetails, findings),
    taskCount: taskDetails.length,
    executionCount,
    artifactCount,
    transcriptCount,
    tasks,
    timeline: buildEvidenceTimeline(taskDetails, findings, tasks),
  };
}

function taskModel(task: TaskDetail, findings: Finding[]): EvidenceReplayTaskModel {
  const phase = missionPhaseForTask(task);
  const phaseCopy = missionPhaseCopy(phase);
  const executionCount = task.executions.length;
  const artifactCount = task.executions.reduce((total, execution) => total + execution.artifacts.length, 0);
  const transcriptLineCount = transcriptLineTotal(task);
  const hasExecutionEvidence = executionCount > 0;
  const hasTranscript = transcriptLineCount > 0 || task.executions.some((execution) => textValue(execution.stderr_text));

  return {
    id: task.id,
    phase,
    phaseLabel: phaseCopy.shortLabel,
    journeyTitle: taskJourneyTitle(task),
    journeyDetail: taskJourneyDetail(task),
    whyItMatters: taskWhyItMatters(task),
    technicalLabel: `${task.tool} · ${task.target_id || 'target not recorded'}`,
    evidenceState: hasExecutionEvidence ? 'Execution evidence present' : 'No execution evidence',
    transcriptState: hasTranscript ? 'Transcript present' : 'No transcript text',
    artifactState: artifactCount > 0 ? `${artifactCount} artifact${artifactCount === 1 ? '' : 's'} linked` : 'No artifacts linked',
    provenanceLabel: task.source_finding_id ? `Source finding ${shortId(task.source_finding_id)}` : `Task ${shortId(task.id)}`,
    executionCount,
    artifactCount,
    transcriptLineCount,
    hasExecutionEvidence,
    hasTranscript,
    linkedFindingCount: findings.filter((finding) => findTaskForFinding(finding, [task])?.task.id === task.id).length,
  };
}

function buildEvidenceTimeline(
  taskDetails: TaskDetail[],
  findings: Finding[],
  taskModels: EvidenceReplayTaskModel[],
): EvidenceReplayTimelineEvent[] {
  const taskEvents = taskDetails.map((task) => {
    const model = taskModels.find((item) => item.id === task.id) ?? taskModel(task, findings);
    const phaseCopy = missionPhaseCopy(model.phase);
    const latestExecution = latestTaskExecution(task);
    const at = latestExecution?.created_at ?? task.updated_at ?? task.created_at ?? null;
    const hasLinkedFinding = model.linkedFindingCount > 0;
    const linkedArtifact = firstArtifact(task);
    return {
      id: `task-${task.id}`,
      kind: 'task' as const,
      phase: model.phase,
      at,
      title: model.journeyTitle,
      detail: model.journeyDetail,
      proves: model.hasExecutionEvidence
        ? 'This proves the task ran and stored execution evidence for replay.'
        : 'This proves the task exists in the run record, but no execution output is stored here.',
      doesNotProve: hasLinkedFinding
        ? 'It still does not prove business impact by itself; Findings owns validation and impact.'
        : 'It does not prove a reportable vulnerability until a saved finding links back to this evidence.',
      evidenceState: hasLinkedFinding
        ? `${model.linkedFindingCount} linked finding${model.linkedFindingCount === 1 ? '' : 's'}`
        : model.evidenceState,
      routeLabel: 'Open CLI',
      routeHref: '/live-cli',
      taskId: task.id,
      findingId: null,
      linkedTaskTitle: model.journeyTitle,
      linkedArtifactLabel: linkedArtifact ? artifactText(linkedArtifact, 'name', 'linked artifact') : null,
      target: task.target_id || 'target not recorded',
      facts: [
        { label: 'Mission step', value: phaseCopy.label },
        { label: 'Task id', value: shortId(task.id) },
        { label: 'Status', value: humanEvidenceValue(task.status) },
        { label: 'Executions', value: String(model.executionCount) },
        { label: 'Artifacts', value: String(model.artifactCount) },
        { label: 'Transcript lines', value: String(model.transcriptLineCount) },
      ],
      tone: model.hasExecutionEvidence ? 'green' as const : 'amber' as const,
    };
  });

  const findingEvents = findings.map((finding) => {
    const match = findTaskForFinding(finding, taskDetails);
    const linkedTaskModel = match ? taskModels.find((task) => task.id === match.task.id) : null;
    const artifact = match?.artifact ?? null;
    const evidenceLinked = Boolean(match);
    return {
      id: `finding-${finding.id}`,
      kind: 'finding' as const,
      phase: 'proof' as MissionPhaseKey,
      at: finding.created_at ?? null,
      title: safeMissionFindingTitle(finding),
      detail: evidenceLinked
        ? `Saved finding linked to ${linkedTaskModel?.journeyTitle ?? match?.task.tool ?? 'recorded task evidence'}.`
        : 'Saved finding is present, but this replay could not match it to loaded task or artifact evidence.',
      proves: evidenceLinked
        ? 'This proves a saved finding points back to recorded evidence in this replay.'
        : 'This proves the finding record exists, but the evidence link needs review.',
      doesNotProve: 'It does not rewrite validation, business impact, remediation, or report wording; those remain in Findings and Reports.',
      evidenceState: evidenceLinked ? 'Finding linked to evidence' : 'Evidence link needs review',
      routeLabel: 'Open Findings',
      routeHref: '/findings',
      taskId: match?.task.id ?? null,
      findingId: finding.id,
      linkedTaskTitle: linkedTaskModel?.journeyTitle ?? (match ? taskJourneyTitle(match.task) : null),
      linkedArtifactLabel: artifact ? artifactText(artifact, 'name', 'linked artifact') : null,
      target: finding.target_id || match?.task.target_id || 'target not recorded',
      facts: [
        { label: 'Finding id', value: shortId(finding.id) },
        { label: 'Severity', value: humanEvidenceValue(finding.severity) },
        { label: 'Evidence ref', value: finding.evidence_ref || 'not linked' },
        { label: 'Validation', value: humanEvidenceValue(finding.validation_status || 'not recorded') },
        { label: 'Linked task', value: linkedTaskModel?.technicalLabel ?? match?.task.tool ?? 'not matched' },
        { label: 'Linked artifact', value: artifact ? artifactText(artifact, 'name', 'linked artifact') : 'not matched' },
      ],
      tone: evidenceLinked ? 'red' as const : 'amber' as const,
    };
  });

  return [...taskEvents, ...findingEvents].sort((left, right) => {
    const leftTime = timeValue(left.at);
    const rightTime = timeValue(right.at);
    if (leftTime !== rightTime) return leftTime - rightTime;
    if (left.kind !== right.kind) return left.kind === 'task' ? -1 : 1;
    return left.title.localeCompare(right.title);
  });
}

function findTaskForFinding(finding: Finding, tasks: TaskDetail[]): { task: TaskDetail; artifact: JsonMap | null; score: number } | null {
  let best: { task: TaskDetail; artifact: JsonMap | null; score: number } | null = null;
  const findingText = findingMatchText(finding);
  for (const task of tasks) {
    let score = 0;
    if (findingText.includes(task.id.toLowerCase())) score += 12;
    if (sameEvidenceHost(finding.target_id, task.target_id)) score += 5;
    if (task.tool && findingText.includes(task.tool.toLowerCase())) score += 3;
    const artifact = matchingArtifact(findingText, task);
    if (artifact) score += 10;
    if (score <= 0) continue;
    if (!best || score > best.score || timeValue(task.updated_at) > timeValue(best.task.updated_at)) {
      best = { task, artifact, score };
    }
  }
  return best;
}

function matchingArtifact(findingText: string, task: TaskDetail): JsonMap | null {
  for (const execution of task.executions) {
    for (const artifact of execution.artifacts as JsonMap[]) {
      const tokens = [
        artifactText(artifact, 'artifact_id', ''),
        artifactText(artifact, 'id', ''),
        artifactText(artifact, 'name', ''),
        artifactText(artifact, 'sha256', ''),
        artifactText(artifact, 'uri', ''),
      ].filter(Boolean);
      if (tokens.some((token) => findingText.includes(token.toLowerCase()))) return artifact;
    }
  }
  return null;
}

function findingMatchText(finding: Finding): string {
  return [
    finding.id,
    finding.title,
    finding.summary,
    finding.target_id,
    finding.evidence_ref,
    JSON.stringify(finding.proof_reference ?? {}),
    JSON.stringify(finding.replay_recipe_json ?? {}),
    ...(finding.methodology_tags ?? []),
  ].join(' ').toLowerCase();
}

function firstArtifact(task: TaskDetail): JsonMap | null {
  for (const execution of task.executions) {
    const first = execution.artifacts[0] as JsonMap | undefined;
    if (first) return first;
  }
  return null;
}

function latestTaskExecution(task: TaskDetail): TaskExecution | null {
  return [...task.executions].sort((left, right) => timeValue(right.created_at) - timeValue(left.created_at))[0] ?? null;
}

function sameEvidenceHost(left: string | null | undefined, right: string | null | undefined): boolean {
  const leftHost = hostFromValue(left);
  const rightHost = hostFromValue(right);
  return Boolean(leftHost && rightHost && leftHost === rightHost);
}

function hostFromValue(value: string | null | undefined): string {
  const raw = String(value || '').trim();
  if (!raw) return '';
  try {
    return new URL(raw).host.toLowerCase();
  } catch {
    return raw.split('/')[0].toLowerCase();
  }
}

function timeValue(value: string | null | undefined): number {
  const parsed = new Date(String(value || '')).getTime();
  return Number.isFinite(parsed) ? parsed : 0;
}

function humanEvidenceValue(value: string | null | undefined): string {
  const text = String(value || 'not recorded').replace(/[_-]+/g, ' ').replace(/\s+/g, ' ').trim();
  return text || 'not recorded';
}

function transcriptLineTotal(task: TaskDetail): number {
  const snapshotLines = Array.isArray(task.stdout_snapshot?.lines) ? task.stdout_snapshot.lines.length : 0;
  const executionLines = task.executions.reduce((total, execution) => {
    const stdout = lineCount(execution.stdout_text);
    const stderr = lineCount(execution.stderr_text);
    return total + stdout + stderr;
  }, 0);
  return snapshotLines + executionLines;
}

function lineCount(value: string | null): number {
  const text = textValue(value);
  return text ? text.split(/\r?\n/).length : 0;
}

function textValue(value: unknown): string | null {
  return typeof value === 'string' && value.trim() ? value.trim() : null;
}

function shortId(value: string): string {
  return value.length <= 12 ? value : value.slice(0, 12);
}

export function artifactText(artifact: JsonMap, key: string, fallback = 'n/a'): string {
  const value = artifact[key];
  if (typeof value === 'string' && value.trim()) return value.trim();
  if (typeof value === 'number' && Number.isFinite(value)) return String(value);
  return fallback;
}
