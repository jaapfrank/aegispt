import { useEffect, useState } from 'react';
import { Download, ScrollText, TerminalSquare } from 'lucide-react';
import { downloadArtifactContent, getRun, getRunsForEngagement, getTaskDetail } from '../../api/client';
import type { Run, TaskDetail, UUID } from '../../api/types';
import { useAegisStore } from '../../store';
import { ActionButton, EmptyState, Field, PageHeader, Panel, StatusBadge, formatDate, inputClass } from './screenPrimitives';

export default function EvidenceReplay() {
  const selectedEngagementId = useAegisStore((state) => state.selectedEngagementId);
  const selectedRunId = useAegisStore((state) => state.selectedRunId);
  const [runs, setRuns] = useState<Run[]>([]);
  const [runId, setRunId] = useState<UUID | ''>(selectedRunId ?? '');
  const [run, setRun] = useState<Run | null>(null);
  const [taskDetails, setTaskDetails] = useState<TaskDetail[]>([]);
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState<string | null>(null);

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
        const detailPayload = await Promise.all(runPayload.tasks.map((task) => getTaskDetail(task.id)));
        if (!cancelled) {
          setRun(runPayload);
          setTaskDetails(detailPayload);
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
      <PageHeader eyebrow="Evidence" title="Evidence Replay" detail="Task execution stdout, stderr, and artifact references from the existing task detail API." />
      {message && <div className="mb-4 rounded-md border border-amber/30 bg-amber/10 px-3 py-2 text-[12px] text-amber">{message}</div>}

      <Panel title="Run Selector" detail={run ? `${run.profile.name} · ${run.status}` : 'Select a run to replay stored execution evidence.'}>
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

      <div className="mt-5 min-h-0 flex-1 overflow-y-auto rounded-xl border border-border bg-surface/55 p-4">
        {loading ? (
          <EmptyState title="Loading evidence" detail="Fetching run task details from the backend." />
        ) : taskDetails.length ? (
          <div className="space-y-3">
            {taskDetails.map((task) => (
              <details key={task.id} className="rounded-lg border border-border bg-bg/30 p-3">
                <summary className="cursor-pointer list-none">
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <div className="min-w-0">
                      <div className="truncate text-[13px] font-semibold text-text"><TerminalSquare size={14} className="mr-2 inline text-cyan" />{task.tool} · {task.target_id}</div>
                      <div className="mt-1 text-[12px] text-muted">{task.executions.length} executions · updated {formatDate(task.updated_at)}</div>
                    </div>
                    <StatusBadge value={task.status} />
                  </div>
                </summary>
                <div className="mt-3 space-y-3 border-t border-border pt-3">
                  {task.executions.map((execution) => (
                    <div key={execution.id} className="rounded-lg border border-border bg-surface/45 p-3">
                      <div className="mb-2 flex flex-wrap items-center justify-between gap-2 text-[12px] text-muted">
                        <span><ScrollText size={13} className="mr-1 inline text-cyan" />{execution.tool_version} · exit {execution.exit_code ?? 'n/a'}</span>
                        <span>{formatDate(execution.created_at)}</span>
                      </div>
                      <pre className="max-h-[260px] overflow-auto rounded-md border border-border bg-bg/70 p-3 text-[11px] leading-5 text-muted">{execution.stdout_text || '[no stdout]'}</pre>
                      {execution.stderr_text && <pre className="mt-2 max-h-[180px] overflow-auto rounded-md border border-red/25 bg-red/10 p-3 text-[11px] leading-5 text-red">{execution.stderr_text}</pre>}
                      <div className="mt-2 flex flex-wrap gap-2">
                        {execution.artifacts.map((artifact, index) => (
                          <ActionButton key={index} onClick={() => void downloadArtifact(artifact)} tone="muted">
                            <Download size={13} />Download artifact {index + 1}
                          </ActionButton>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              </details>
            ))}
          </div>
        ) : (
          <EmptyState title="No execution evidence" detail="This run has no task executions exposed by the backend task detail endpoint." />
        )}
      </div>
    </section>
  );
}
