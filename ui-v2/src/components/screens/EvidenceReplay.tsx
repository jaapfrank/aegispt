import { useEffect, useMemo, useState, type ReactNode } from 'react';
import { Link } from 'react-router-dom';
import { Archive, CheckCircle2, Download, FileText, Fingerprint, GitBranch, HelpCircle, ScrollText, TerminalSquare } from 'lucide-react';
import { downloadArtifactContent, getFindingsForRunContext, getRun, getRunsForEngagement, getTaskDetail, getTasksForRunContext } from '../../api/client';
import type { Finding, JsonMap, Run, TaskDetail, UUID } from '../../api/types';
import { useAegisStore } from '../../store';
import { buildEvidenceReplayModel, artifactText } from '../../viewModels/evidenceReplay';
import type { EvidenceReplayTimelineEvent } from '../../viewModels/evidenceReplay';
import type { MissionPhaseKey } from '../../viewModels/missionStory';
import { ActionButton, EmptyState, Field, MetricCard, PageHeader, Panel, StatusBadge } from './screenPrimitives';
import { cn, formatDate, inputClass } from './screenUtils';

export default function EvidenceReplay() {
  const selectedEngagementId = useAegisStore((state) => state.selectedEngagementId);
  const selectedRunId = useAegisStore((state) => state.selectedRunId);
  const [runs, setRuns] = useState<Run[]>([]);
  const [runId, setRunId] = useState<UUID | ''>(selectedRunId ?? '');
  const [run, setRun] = useState<Run | null>(null);
  const [taskDetails, setTaskDetails] = useState<TaskDetail[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [selectedPhase, setSelectedPhase] = useState<MissionPhaseKey | 'all'>('all');
  const [selectedEvidenceEventId, setSelectedEvidenceEventId] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const replayModel = useMemo(() => (run ? buildEvidenceReplayModel(run, taskDetails, findings) : null), [run, taskDetails, findings]);
  const selectedEvidenceEvent = useMemo(() => {
    if (!replayModel) return null;
    return (
      replayModel.timeline.find((event) => event.id === selectedEvidenceEventId) ??
      replayModel.timeline.find((event) => event.kind === 'finding') ??
      replayModel.timeline[0] ??
      null
    );
  }, [replayModel, selectedEvidenceEventId]);
  const filteredTaskDetails = useMemo(() => {
    if (!replayModel || selectedPhase === 'all') return taskDetails;
    const visibleTaskIds = new Set(replayModel.tasks.filter((task) => task.phase === selectedPhase).map((task) => task.id));
    return taskDetails.filter((task) => visibleTaskIds.has(task.id));
  }, [replayModel, selectedPhase, taskDetails]);

  useEffect(() => {
    setRunId(selectedRunId ?? '');
  }, [selectedRunId]);

  useEffect(() => {
    let cancelled = false;
    async function loadRuns() {
      if (!selectedEngagementId) {
        setRuns([]);
        return;
      }
      const payload = await getRunsForEngagement(selectedEngagementId);
      if (!cancelled) {
        setRuns(payload);
        setRunId((current) => current || payload[0]?.id || '');
      }
    }
    void loadRuns().catch((error) => setMessage(error instanceof Error ? error.message : 'Runs unavailable.'));
    return () => {
      cancelled = true;
    };
  }, [selectedEngagementId]);

  useEffect(() => {
    if (!runId) {
      setRun(null);
      setTaskDetails([]);
      return;
    }
    let cancelled = false;
    async function loadReplay() {
      setLoading(true);
      setMessage(null);
      try {
        const runPayload = await getRun(runId);
        const [contextTasks, findingPayload] = await Promise.all([
          getTasksForRunContext(runPayload),
          getFindingsForRunContext(runPayload),
        ]);
        const detailPayload = await Promise.all(contextTasks.map((task) => getTaskDetail(task.id)));
        if (!cancelled) {
          setRun(runPayload);
          setTaskDetails(detailPayload);
          setFindings(findingPayload);
          setSelectedPhase('all');
          setSelectedEvidenceEventId(null);
        }
      } catch (error) {
        if (!cancelled) setMessage(error instanceof Error ? error.message : 'Evidence replay unavailable.');
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    void loadReplay();
    return () => {
      cancelled = true;
    };
  }, [runId]);

  async function downloadArtifact(artifact: Record<string, unknown>) {
    const artifactId = String(artifact.artifact_id ?? artifact.id ?? '');
    if (!artifactId) {
      setMessage('Artifact id is not exposed for this execution artifact.');
      return;
    }
    try {
      const blob = await downloadArtifactContent(artifactId);
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement('a');
      anchor.href = url;
      anchor.download = String(artifact.name ?? `${artifactId}.bin`);
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(url);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Artifact download failed.');
    }
  }

  if (!selectedEngagementId) {
    return <EmptyState title="No engagement selected" detail="Evidence Replay uses engagement-scoped runs and task executions." />;
  }

  return (
    <section className="flex h-full min-h-0 flex-col">
      <PageHeader eyebrow="Evidence" title="Evidence Replay" detail="Follow the same mission path as Mission Control, then open each step for transcript, artifacts, and provenance." />
      {message && <div className="mb-4 rounded-md border border-amber/30 bg-amber/10 px-3 py-2 text-[0.925rem] text-amber">{message}</div>}

      {run && replayModel && (
        <Panel
          title="Evidence timeline"
          detail="Chronological replay of task output, artifacts, transcript, and finding links. Click a step to inspect what it proves."
          action={<StatusBadge value={`${replayModel.timeline.length} replay steps`} />}
        >
          <EvidenceTimelinePanel
            events={replayModel.timeline}
            selectedEvent={selectedEvidenceEvent}
            onSelect={(event) => {
              setSelectedEvidenceEventId(event.id);
              if (event.phase) setSelectedPhase(event.phase);
            }}
          />
        </Panel>
      )}

      <div className={cn(run && replayModel && 'mt-5')}>
        <Panel title="Run Selector" detail={run && replayModel ? `${run.profile.name} · ${run.status} · ${replayModel.sourceLabel}` : 'Select a run to replay stored execution evidence.'}>
          <Field label="Run">
            <select className={inputClass} value={runId} onChange={(event) => setRunId(event.target.value)}>
              <option value="" className="bg-surface text-text">Select run</option>
              {runs.map((candidate) => (
                <option key={candidate.id} value={candidate.id} className="bg-surface text-text">
                  {formatDate(candidate.created_at)} · {candidate.profile.name} · {candidate.status}
                </option>
              ))}
            </select>
          </Field>
        </Panel>
      </div>

      {run && replayModel && (
        <div className="mt-5">
          <Panel
            title="Mission evidence path"
            detail={replayModel.missionDetail}
            action={<StatusBadge value={findings.length > 0 ? `${findings.length} saved findings` : 'evidence only'} />}
          >
          <div className="theme-surface-card mb-4 rounded-lg border p-4">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div className="min-w-0">
                <div className="font-mono text-[0.66rem] uppercase tracking-[0.22em] text-cyan/75">Current evidence route</div>
                <div className="mt-2 text-[1.35rem] font-semibold leading-tight text-text">{replayModel.missionTitle}</div>
              </div>
              <ActionButton onClick={() => setSelectedPhase('all')} tone={selectedPhase === 'all' ? 'cyan' : 'muted'}>
                <GitBranch size={14} />Show whole path
              </ActionButton>
            </div>
          </div>
          <div className="grid gap-2 md:grid-cols-5">
            {replayModel.chapters.map((chapter, index) => (
              <button
                key={chapter.key}
                type="button"
                onClick={() => {
                  setSelectedPhase(chapter.key);
                  const firstEventInPhase = replayModel.timeline.find((event) => event.phase === chapter.key);
                  setSelectedEvidenceEventId(firstEventInPhase?.id ?? null);
                }}
                className={cn(
                  'relative min-h-[8.25rem] rounded-lg border p-3 text-left transition-colors',
                  selectedPhase === chapter.key ? 'border-cyan/50 bg-cyan/12' : 'border-cyan/15 bg-bg/35 hover:border-cyan/35 hover:bg-cyan/7',
                )}
                aria-pressed={selectedPhase === chapter.key}
              >
                {index < replayModel.chapters.length - 1 && <span className="absolute -right-3 top-8 hidden h-px w-4 bg-cyan/35 md:block" aria-hidden="true" />}
                <div className="flex items-center justify-between gap-2">
                  <span className="font-mono text-[0.62rem] uppercase tracking-widest text-cyan/75">{chapter.shortLabel}</span>
                  <span className={cn('h-2 w-2 rounded-full shadow-[0_0_12px_currentColor]', chapterStateTone(chapter.state))} />
                </div>
                <div className="mt-2 text-[0.95rem] font-semibold leading-5 text-text">{chapter.label}</div>
                <div className="mt-1 line-clamp-2 text-[0.76rem] leading-4 text-muted">{chapter.story}</div>
                <div className="mt-3 flex flex-wrap gap-1">
                  <MiniEvidencePill value={`${chapter.taskCount} tasks`} />
                  <MiniEvidencePill value={`${chapter.artifactCount} artifacts`} />
                  {chapter.findingCount > 0 && <MiniEvidencePill value={`${chapter.findingCount} findings`} tone="red" />}
                </div>
              </button>
            ))}
          </div>
          </Panel>
        </div>
      )}

      {run && replayModel && (
        <div className="mt-5 grid gap-3 lg:grid-cols-4">
          <MetricCard
            icon={<GitBranch size={16} />}
            label="Evidence scope"
            value={replayModel.sourceLabel}
            detail={replayModel.sourceDetail}
          />
          <MetricCard
            icon={<Archive size={16} />}
            label="Evidence state"
            value={`${replayModel.executionCount} executions`}
            detail={`${replayModel.taskCount} tasks · ${replayModel.artifactCount} artifacts · ${replayModel.transcriptCount} transcript lines`}
          />
          <MetricCard
            icon={<Fingerprint size={16} />}
            label="Provenance"
            value={replayModel.artifactCount ? 'Artifacts linked' : 'Task records only'}
            detail="Task ids, runner digests, artifact hashes, redaction, and timestamp status stay visible."
          />
          <MetricCard
            icon={<FileText size={16} />}
            label="Conclusion state"
            value={replayModel.conclusionLabel}
            detail={findings.length > 0 ? `${findings.length} saved finding(s) connect this replay to Findings and Reports.` : replayModel.conclusionDetail}
          />
        </div>
      )}

      <div className="mt-5 min-h-0 flex-1 overflow-y-auto rounded-xl border border-border bg-surface/55 p-4">
        {loading ? (
          <EmptyState title="Loading evidence" detail="Fetching run task details from the backend." />
        ) : filteredTaskDetails.length ? (
          <div className="space-y-3">
            {filteredTaskDetails.map((task) => {
              const taskModel = replayModel?.tasks.find((item) => item.id === task.id);
              return (
              <details key={task.id} className="rounded-lg border border-border bg-bg/30 p-3">
                <summary className="cursor-pointer list-none">
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <div className="min-w-0">
                      <div className="truncate text-[1rem] font-semibold text-text">
                        <TerminalSquare size={14} className="mr-2 inline text-cyan" />{taskModel?.journeyTitle ?? `${task.tool} evidence`}
                      </div>
                      <div className="mt-1 line-clamp-2 text-[0.86rem] leading-5 text-soft">
                        {taskModel?.journeyDetail ?? 'Evidence belongs to this recorded execution step.'}
                      </div>
                      <div className="mt-1 text-[0.925rem] text-muted">
                        {task.executions.length} executions · {taskModel?.artifactState ?? 'No artifacts linked'} · updated {formatDate(task.updated_at)}
                      </div>
                      <div className="mt-1 font-mono text-[0.72rem] text-muted">{taskModel?.technicalLabel ?? `${task.tool} · ${task.target_id}`}</div>
                      {taskModel && (
                        <div className="mt-2 flex flex-wrap gap-2">
                          <TruthPill label="Mission step" value={taskModel.phaseLabel} tone="cyan" />
                          <TruthPill label="Evidence state" value={taskModel.evidenceState} tone={taskModel.hasExecutionEvidence ? 'green' : 'amber'} />
                          <TruthPill label="Transcript" value={taskModel.transcriptState} tone={taskModel.hasTranscript ? 'cyan' : 'amber'} />
                          <TruthPill label="Provenance" value={taskModel.provenanceLabel} tone="muted" />
                        </div>
                      )}
                    </div>
                    <StatusBadge value={task.status} />
                  </div>
                </summary>
                <div className="mt-3 space-y-3 border-t border-border pt-3">
                  {taskModel && (
                    <div className="rounded-lg border border-cyan/15 bg-cyan/7 p-3">
                      <div className="font-mono text-[0.66rem] uppercase tracking-widest text-cyan/75">Why this step matters</div>
                      <p className="mt-2 text-[0.9rem] leading-5 text-text">{taskModel.whyItMatters}</p>
                      <p className="mt-1 text-[0.82rem] leading-5 text-muted">
                        Technical trace: {taskModel.technicalLabel}. Conclusions stay in Findings and Reports.
                      </p>
                    </div>
                  )}
                  {task.executions.map((execution) => (
                    <div key={execution.id} className="rounded-lg border border-border bg-surface/45 p-3">
                      <div className="mb-2 flex flex-wrap items-center justify-between gap-2 text-[0.925rem] text-muted">
                        <span><ScrollText size={13} className="mr-1 inline text-cyan" />{execution.tool_version} · exit {execution.exit_code ?? 'n/a'}</span>
                        <span>{formatDate(execution.created_at)}</span>
                      </div>
                      <div className="mb-3 grid gap-2 md:grid-cols-3">
                        <FactBlock label="Execution provenance" value={execution.id} detail={`Runner digest: ${execution.runner_digest || 'n/a'}`} />
                        <FactBlock label="Tool version" value={execution.tool_version || 'n/a'} detail={`Task id: ${task.id}`} />
                        <FactBlock label="Execution state" value={`exit ${execution.exit_code ?? 'n/a'}`} detail="Exit state is execution evidence, not a finding verdict." />
                      </div>
                      <div className="mb-1 text-[0.77rem] font-bold uppercase tracking-wider text-muted">Transcript stdout</div>
                      <pre className="max-h-[260px] overflow-auto rounded-md border border-border bg-bg/70 p-3 text-[0.85rem] leading-5 text-muted">{execution.stdout_text || '[no stdout]'}</pre>
                      {execution.stderr_text && (
                        <>
                          <div className="mb-1 mt-3 text-[0.77rem] font-bold uppercase tracking-wider text-red">Transcript stderr</div>
                          <pre className="max-h-[180px] overflow-auto rounded-md border border-red/25 bg-red/10 p-3 text-[0.85rem] leading-5 text-red">{execution.stderr_text}</pre>
                        </>
                      )}
                      <div className="mt-2 flex flex-wrap gap-2">
                        {execution.artifacts.map((artifact, index) => {
                          const artifactMap = artifact as JsonMap;
                          return (
                            <div key={index} className="rounded-md border border-border bg-bg/40 p-3">
                              <div className="mb-2 text-[0.77rem] font-bold uppercase tracking-wider text-muted">Artifact provenance</div>
                              <div className="text-[0.925rem] font-semibold text-text">{artifactText(artifactMap, 'name', `artifact ${index + 1}`)}</div>
                              <div className="mt-1 break-all font-mono text-[0.78rem] text-muted">SHA-256: {artifactText(artifactMap, 'sha256')}</div>
                              <div className="mt-1 text-[0.82rem] text-muted">
                                {artifactText(artifactMap, 'kind', 'artifact')} · hash {artifactText(artifactMap, 'hash_status')} · timestamp {artifactText(artifactMap, 'timestamp_status')} · {artifactText(artifactMap, 'redaction_state')}
                              </div>
                              <ActionButton onClick={() => void downloadArtifact(artifactMap)} tone="muted">
                                <Download size={13} />Download {artifactText(artifactMap, 'name', `artifact ${index + 1}`)}
                              </ActionButton>
                            </div>
                          );
                        })}
                        {execution.artifacts.length === 0 && (
                          <div className="rounded-md border border-border bg-bg/40 p-3 text-[0.925rem] text-muted">
                            No artifacts are linked to this execution.
                          </div>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </details>
              );
            })}
          </div>
        ) : (
          <EmptyState title={selectedPhase === 'all' ? 'No execution evidence' : 'No evidence in this mission step'} detail={selectedPhase === 'all' ? 'This run has no task executions exposed by the backend task detail endpoint.' : 'Pick another mission step or show the whole path to inspect the available evidence.'} />
        )}
      </div>
    </section>
  );
}

function EvidenceTimelinePanel({
  events,
  selectedEvent,
  onSelect,
}: {
  events: EvidenceReplayTimelineEvent[];
  selectedEvent: EvidenceReplayTimelineEvent | null;
  onSelect: (event: EvidenceReplayTimelineEvent) => void;
}) {
  if (events.length === 0) {
    return <EmptyState title="No replay timeline yet" detail="No task output, artifact, transcript, or finding-link events are available for this run." />;
  }
  return (
    <div className="grid gap-4 xl:grid-cols-[minmax(0,0.95fr)_minmax(0,1.05fr)]">
      <div className="theme-surface-card rounded-lg border p-4" aria-label="Selected evidence step">
        {selectedEvent ? (
          <>
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div className="min-w-0">
                <div className="font-mono text-[0.66rem] uppercase tracking-[0.22em] text-cyan/75">Selected evidence step</div>
                <h3 className="mt-2 text-[1.25rem] font-semibold leading-tight text-text">{selectedEvent.title}</h3>
                <p className="mt-2 text-[0.94rem] leading-5 text-soft">{selectedEvent.detail}</p>
              </div>
              <StatusBadge value={selectedEvent.evidenceState} />
            </div>
            <div className="mt-4 grid gap-3 md:grid-cols-2">
              <EvidenceTruthBox
                icon={<CheckCircle2 size={15} />}
                title="This evidence proves"
                detail={selectedEvent.proves}
                tone="green"
              />
              <EvidenceTruthBox
                icon={<HelpCircle size={15} />}
                title="This does not prove"
                detail={selectedEvent.doesNotProve}
                tone="amber"
              />
            </div>
            <div className="mt-4 grid gap-2 md:grid-cols-2">
              {selectedEvent.facts.map((fact) => (
                <FactBlock key={`${selectedEvent.id}-${fact.label}`} label={fact.label} value={fact.value} detail={fact.label === 'Evidence ref' ? 'Traceable reference used by Findings and Reports.' : 'Recorded evidence metadata.'} />
              ))}
            </div>
            <div className="mt-4 flex flex-wrap gap-2">
              <EvidenceLinkButton to={selectedEvent.routeHref}>{selectedEvent.routeLabel}</EvidenceLinkButton>
              {selectedEvent.kind === 'finding' && <EvidenceLinkButton to="/reports">Review report claims</EvidenceLinkButton>}
            </div>
            {(selectedEvent.linkedTaskTitle || selectedEvent.linkedArtifactLabel) && (
              <div className="mt-4 rounded-lg border border-cyan/15 bg-bg/45 p-3">
                <div className="font-mono text-[0.62rem] uppercase tracking-widest text-cyan/75">Trace link</div>
                <div className="mt-2 text-[0.9rem] text-text">
                  {selectedEvent.linkedTaskTitle || 'Task not matched'}
                  {selectedEvent.linkedArtifactLabel ? <span className="text-muted"> · artifact {selectedEvent.linkedArtifactLabel}</span> : null}
                </div>
              </div>
            )}
          </>
        ) : (
          <EmptyState title="Pick a replay step" detail="Select a timeline event to inspect its evidence boundary." />
        )}
      </div>
      <div className="rounded-lg border border-border bg-bg/30 p-3" aria-label="Chronological evidence timeline">
        <div className="mb-3 flex items-center justify-between gap-3">
          <div>
            <div className="font-mono text-[0.66rem] uppercase tracking-[0.22em] text-cyan/75">Chronological replay</div>
            <div className="mt-1 text-[0.86rem] text-muted">Newest report claims must trace back to these events.</div>
          </div>
          <span className="font-mono text-[0.68rem] uppercase tracking-widest text-muted">{events.length} steps</span>
        </div>
        <div className="max-h-[26rem] space-y-2 overflow-auto pr-1">
          {events.map((event, index) => (
            <button
              key={event.id}
              type="button"
              onClick={() => onSelect(event)}
              aria-pressed={selectedEvent?.id === event.id}
              className={cn(
                'grid w-full grid-cols-[2.35rem_minmax(0,1fr)] gap-3 rounded-lg border p-3 text-left transition-colors',
                selectedEvent?.id === event.id ? 'border-cyan/50 bg-cyan/12' : 'border-border bg-surface/45 hover:border-cyan/35 hover:bg-cyan/7',
              )}
            >
              <div className="relative flex flex-col items-center">
                <span className={cn('flex h-7 w-7 items-center justify-center rounded-full border font-mono text-[0.72rem] font-semibold', timelineTone(event.tone))}>
                  {index + 1}
                </span>
                {index < events.length - 1 && <span className="mt-1 h-full min-h-[2rem] w-px bg-cyan/25" aria-hidden="true" />}
              </div>
              <div className="min-w-0">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-mono text-[0.6rem] uppercase tracking-widest text-cyan/75">{event.kind}</span>
                  <span className="font-mono text-[0.68rem] text-muted">{event.at ? formatDate(event.at) : 'time not recorded'}</span>
                </div>
                <div className="mt-1 line-clamp-2 text-[0.96rem] font-semibold leading-5 text-text">{event.title}</div>
                <div className="mt-1 line-clamp-2 text-[0.78rem] leading-4 text-muted">{event.target}</div>
              </div>
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}

function EvidenceTruthBox({ icon, title, detail, tone }: { icon: ReactNode; title: string; detail: string; tone: 'green' | 'amber' }) {
  return (
    <div className={cn('rounded-lg border p-3', tone === 'green' ? 'border-green/25 bg-green/10' : 'border-amber/25 bg-amber/10')}>
      <div className={cn('flex items-center gap-2 font-mono text-[0.64rem] uppercase tracking-widest', tone === 'green' ? 'text-green' : 'text-amber')}>
        {icon}
        {title}
      </div>
      <p className="mt-2 text-[0.88rem] leading-5 text-text">{detail}</p>
    </div>
  );
}

function EvidenceLinkButton({ to, children }: { to: string; children: ReactNode }) {
  return (
    <Link
      to={to}
      className="inline-flex items-center justify-center rounded-md border border-cyan/30 bg-cyan/10 px-3 py-2 text-[0.92rem] font-semibold text-cyan transition-colors hover:bg-cyan/15"
    >
      {children}
    </Link>
  );
}

function timelineTone(tone: EvidenceReplayTimelineEvent['tone']) {
  const toneClass = {
    green: 'border-green/30 bg-green/10 text-green',
    cyan: 'border-cyan/30 bg-cyan/10 text-cyan',
    amber: 'border-amber/30 bg-amber/10 text-amber',
    red: 'border-red/30 bg-red/10 text-red',
    muted: 'border-border bg-bg/50 text-muted',
  }[tone];
  return toneClass;
}

function MiniEvidencePill({ value, tone = 'cyan' }: { value: string; tone?: 'cyan' | 'red' }) {
  return (
    <span className={cn(
      'rounded-full border px-2 py-0.5 font-mono text-[0.58rem] uppercase tracking-widest',
      tone === 'red' ? 'border-red/25 bg-red/10 text-red' : 'border-cyan/20 bg-cyan/7 text-cyan/80',
    )}>
      {value}
    </span>
  );
}

function chapterStateTone(state: 'done' | 'active' | 'waiting') {
  if (state === 'active') return 'bg-amber text-amber';
  if (state === 'done') return 'bg-green text-green';
  return 'bg-muted text-muted';
}

function TruthPill({
  label,
  value,
  tone,
}: {
  label: string;
  value: string;
  tone: 'green' | 'cyan' | 'amber' | 'muted';
}) {
  const toneClass = {
    green: 'border-green/25 bg-green/10 text-green',
    cyan: 'border-cyan/25 bg-cyan/10 text-cyan',
    amber: 'border-amber/25 bg-amber/10 text-amber',
    muted: 'border-border bg-surface/60 text-muted',
  }[tone];
  return (
    <span className={cn('inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[0.72rem] font-semibold', toneClass)}>
      <span className="uppercase opacity-75">{label}:</span>
      {value}
    </span>
  );
}

function FactBlock({ label, value, detail }: { label: string; value: string; detail: string }) {
  return (
    <div className="rounded-md border border-border bg-bg/40 p-3">
      <div className="text-[0.72rem] font-bold uppercase tracking-wider text-muted">{label}</div>
      <div className="mt-1 break-all text-[0.9rem] font-semibold text-text">{value}</div>
      <div className="mt-1 break-all text-[0.78rem] text-muted">{detail}</div>
    </div>
  );
}
