import { useEffect, useMemo, useState, useCallback, type ReactNode } from 'react';
import { BadgeAlert, CalendarClock, CheckCircle2, Clock, ListChecks, ShieldAlert, UserRound } from 'lucide-react';
import { bulkUpdateProblems, getProblems } from '../../api/client';
import type { ProblemRead, ProblemsQuery, ProblemsRead, UUID } from '../../api/types';
import { useAegisStore } from '../../store';
import { safeErrorMessage } from '../../viewModels/safeMessaging';
import { buildProblemsTriageModel, type ProblemDecisionItem, type ProblemsTriageModel } from '../../viewModels/triageBoards';
import { ActionButton, EmptyState, Field, MetricCard, PageHeader, Panel, StatusBadge } from './screenPrimitives';
import { cn, formatDate, inputClass, jsonNumber } from './screenUtils';

export default function ProblemsCenter() {
  const engagements = useAegisStore((state) => state.engagements);
  const [payload, setPayload] = useState<ProblemsRead | null>(null);
  const [selectedFindingIds, setSelectedFindingIds] = useState<UUID[]>([]);
  const [severity, setSeverity] = useState('all');
  const [status, setStatus] = useState('all');
  const [engagementId, setEngagementId] = useState('all');
  const [age, setAge] = useState('all');
  const [assignee, setAssignee] = useState('');
  const [bulkAssignee, setBulkAssignee] = useState('');
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState<string | null>(null);

  const query = useMemo<ProblemsQuery>(() => ({
    severity,
    status,
    engagement_id: engagementId === 'all' ? undefined : engagementId,
    age,
    assignee,
    limit: 100,
  }), [age, assignee, engagementId, severity, status]);

  const problemTriage = useMemo(() => buildProblemsTriageModel(payload?.items ?? []), [payload?.items]);

  const loadProblems = useCallback(async () => {
    setLoading(true);
    setMessage(null);
    try {
      const next = await getProblems(query);
      setPayload(next);
      setSelectedFindingIds((current) => current.filter((id) => next.items.some((item) => item.finding_id === id)));
    } catch (error) {
      setMessage(safeErrorMessage(error, {
        fallback: 'Problems could not load. Refresh or adjust filters.',
        unavailable: 'Problems are temporarily unavailable. Stored findings remain available in Findings Theater.',
      }));
      setPayload(null);
    } finally {
      setLoading(false);
    }
  }, [query]);

  useEffect(() => {
    void loadProblems();
  }, [loadProblems]);

  async function runBulk(action: 'assign' | 'resolve' | 'schedule_retest') {
    if (!selectedFindingIds.length) {
      setMessage('Select one or more problems first.');
      return;
    }
    setLoading(true);
    try {
      const result = await bulkUpdateProblems({
        finding_ids: selectedFindingIds,
        action,
        assignee: action === 'assign' ? bulkAssignee || 'unassigned' : undefined,
        status: action === 'resolve' ? 'resolved' : undefined,
        retest_notes: action === 'schedule_retest' ? 'Requested from React v2 Problems Center.' : undefined,
      });
      setMessage(result.message);
      setSelectedFindingIds([]);
      await loadProblems();
    } catch (error) {
      setMessage(safeErrorMessage(error, {
        fallback: 'Problems bulk action could not be completed. Try again or adjust the selection.',
        unavailable: 'Problems bulk action is temporarily unavailable.',
      }));
    } finally {
      setLoading(false);
    }
  }

  function toggleProblem(findingId: UUID) {
    setSelectedFindingIds((current) => current.includes(findingId) ? current.filter((id) => id !== findingId) : [...current, findingId]);
  }

  const stats = payload?.stats ?? {};

  return (
    <section className="flex h-full min-h-0 flex-col">
      <PageHeader
        eyebrow="Lifecycle"
        title="Problems Center"
        detail="Cross-engagement finding lifecycle view from the existing Problems API."
        actions={<ActionButton onClick={() => void loadProblems()} loading={loading}>Refresh</ActionButton>}
      />
      {message && <div className="mb-4 rounded-md border border-cyan/25 bg-cyan/10 px-3 py-2 text-[0.925rem] text-cyan">{message}</div>}

      <ProblemsTriageBoard model={problemTriage} selected={selectedFindingIds} toggleProblem={toggleProblem} />

      <div className="mb-5 grid gap-3 md:grid-cols-3 xl:grid-cols-6">
        <MetricCard icon={<BadgeAlert size={15} />} label="Open Critical" value={jsonNumber(stats.open_critical)} />
        <MetricCard icon={<BadgeAlert size={15} />} label="Open High" value={jsonNumber(stats.open_high)} />
        <MetricCard icon={<BadgeAlert size={15} />} label="Visible" value={jsonNumber(stats.total_filtered)} />
        <MetricCard icon={<CheckCircle2 size={15} />} label="All Findings" value={jsonNumber(stats.total_findings)} />
        <MetricCard icon={<Clock size={15} />} label="Avg Resolve" value={`${jsonNumber(stats.avg_days_to_resolve_30d).toFixed(1)}d`} />
        <MetricCard icon={<CheckCircle2 size={15} />} label="Resolved Week" value={jsonNumber(stats.resolved_this_week)} />
      </div>

      <Panel title="Filters">
        <div className="grid gap-3 md:grid-cols-5">
          <Field label="Engagement">
            <select className={inputClass} value={engagementId} onChange={(event) => setEngagementId(event.target.value)}>
              <option value="all" className="bg-surface text-text">All</option>
              {engagements.map((engagement) => <option key={engagement.id} value={engagement.id} className="bg-surface text-text">{engagement.name}</option>)}
            </select>
          </Field>
          <Field label="Severity">
            <select className={inputClass} value={severity} onChange={(event) => setSeverity(event.target.value)}>
              {['all', 'critical', 'high', 'medium', 'low'].map((value) => <option key={value} value={value} className="bg-surface text-text">{value}</option>)}
            </select>
          </Field>
          <Field label="Status">
            <select className={inputClass} value={status} onChange={(event) => setStatus(event.target.value)}>
              {['all', 'open', 'in_progress', 'resolved', 'verified'].map((value) => <option key={value} value={value} className="bg-surface text-text">{value}</option>)}
            </select>
          </Field>
          <Field label="Age">
            <select className={inputClass} value={age} onChange={(event) => setAge(event.target.value)}>
              {['all', 'overdue', 'due_soon', 'recent'].map((value) => <option key={value} value={value} className="bg-surface text-text">{value}</option>)}
            </select>
          </Field>
          <Field label="Assignee">
            <input className={inputClass} value={assignee} onChange={(event) => setAssignee(event.target.value)} placeholder="Any assignee" />
          </Field>
        </div>
      </Panel>

      <div className="my-5 flex flex-wrap items-end gap-2 rounded-xl border border-border bg-surface/45 p-3">
        <Field label="Bulk assignee">
          <input className={inputClass} value={bulkAssignee} onChange={(event) => setBulkAssignee(event.target.value)} placeholder="operator name" />
        </Field>
        <ActionButton onClick={() => void runBulk('assign')} disabled={!selectedFindingIds.length} loading={loading} tone="cyan">Bulk assign</ActionButton>
        <ActionButton onClick={() => void runBulk('schedule_retest')} disabled={!selectedFindingIds.length} loading={loading} tone="amber">Bulk retest</ActionButton>
        <ActionButton onClick={() => void runBulk('resolve')} disabled={!selectedFindingIds.length} loading={loading} tone="green">Bulk resolve</ActionButton>
        <span className="ml-auto text-[0.925rem] text-muted">{selectedFindingIds.length} selected</span>
      </div>

      <div className="grid min-h-0 flex-1 gap-5 xl:grid-cols-[1fr_360px]">
        <Panel title="Open Problems" detail={`${payload?.items.length ?? 0} visible`}>
          <ProblemList items={payload?.items ?? []} selected={selectedFindingIds} setSelected={setSelectedFindingIds} />
        </Panel>
        <Panel title="Recently Resolved" detail="From the Problems API lifecycle summary.">
          <ProblemList items={payload?.recently_resolved ?? []} selected={[]} setSelected={() => undefined} compact />
        </Panel>
      </div>
    </section>
  );
}

function ProblemsTriageBoard({
  model,
  selected,
  toggleProblem,
}: {
  model: ProblemsTriageModel;
  selected: UUID[];
  toggleProblem: (findingId: UUID) => void;
}) {
  const lead = model.leadItem;
  return (
    <section
      aria-label="Problems triage board"
      className="neon-panel mb-5 rounded-xl border border-cyan/25 p-4"
    >
      <div className="grid gap-4 xl:grid-cols-[minmax(280px,0.85fr)_minmax(0,1.65fr)]">
        <div className="rounded-lg border border-border bg-bg/30 p-4">
          <div className="mb-2 flex items-center gap-2 font-mono text-[0.68rem] font-semibold uppercase tracking-[0.22em] text-cyan">
            <ListChecks size={14} />
            Decisions today
          </div>
          <h2 className="text-xl font-semibold text-text">{model.decisionLabel}</h2>
          <p className="mt-2 text-[1rem] leading-6 text-muted">{model.decisionDetail}</p>
          <div className="mt-4 grid gap-2 sm:grid-cols-2">
            <ProblemDecisionFact icon={<BadgeAlert size={14} />} label="Open work" value={`${model.totalOpen} problems`} />
            <ProblemDecisionFact icon={<CheckCircle2 size={14} />} label="Selected" value={`${selected.length} for action`} />
          </div>
          {lead && (
            <button
              type="button"
              onClick={() => toggleProblem(lead.findingId)}
              className={cn(
                'mt-4 inline-flex items-center gap-2 rounded-md border px-3 py-2 text-[1rem] font-semibold transition-colors',
                selected.includes(lead.findingId)
                  ? 'border-green/30 bg-green/10 text-green'
                  : 'border-cyan/30 bg-cyan/10 text-cyan hover:bg-cyan/15',
              )}
            >
              {selected.includes(lead.findingId) ? 'Selected for bulk action' : 'Select top problem'}
            </button>
          )}
        </div>

        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
          {model.lanes.map((lane) => (
            <div key={lane.id} className="rounded-lg border border-border bg-bg/25 p-3">
              <div className="mb-3 flex items-start justify-between gap-2">
                <div>
                  <div className="flex items-center gap-2 text-[0.9rem] font-semibold text-text">
                    {laneIcon(lane.id)}
                    {lane.label}
                  </div>
                  <p className="mt-1 text-[0.78rem] leading-4 text-muted">{lane.detail}</p>
                </div>
                <span className="rounded-full border border-border bg-surface/55 px-2 py-0.5 text-[0.72rem] font-semibold text-muted">{lane.items.length}</span>
              </div>
              <div className="space-y-2">
                {lane.items.slice(0, 3).map((item) => (
                  <ProblemDecisionButton
                    key={`${lane.id}-${item.id}`}
                    item={item}
                    selected={selected.includes(item.findingId)}
                    onToggle={() => toggleProblem(item.findingId)}
                  />
                ))}
                {!lane.items.length && (
                  <div className="rounded-md border border-border bg-surface/30 p-3 text-[0.85rem] leading-5 text-muted">
                    Nothing in this lane.
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

function ProblemDecisionButton({
  item,
  selected,
  onToggle,
}: {
  item: ProblemDecisionItem;
  selected: boolean;
  onToggle: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onToggle}
      className={cn(
        'w-full rounded-md border p-3 text-left transition-colors',
        selected ? 'border-green/35 bg-green/10' : 'border-border bg-surface/35 hover:border-cyan/35 hover:bg-cyan/10',
      )}
      aria-label={`${item.nextAction}: ${item.title}`}
    >
      <div className="flex items-center justify-between gap-2">
        <StatusBadge value={item.severity} />
        <span className="font-mono text-[0.68rem] uppercase tracking-wider text-muted">{item.nextAction}</span>
      </div>
      <div className="mt-2 line-clamp-2 text-[0.95rem] font-semibold leading-5 text-text">{item.title}</div>
      <div className="mt-2 space-y-1 text-[0.78rem] leading-4 text-muted">
        <div>{item.assigneeLabel} · {item.ageLabel}</div>
        <div>{item.slaLabel}</div>
      </div>
    </button>
  );
}

function ProblemDecisionFact({ icon, label, value }: { icon: ReactNode; label: string; value: string }) {
  return (
    <div className="rounded-md border border-border bg-surface/35 p-3">
      <div className="mb-1 flex items-center gap-2 font-mono text-[0.62rem] uppercase tracking-widest text-muted">
        {icon}
        {label}
      </div>
      <div className="text-[0.95rem] font-semibold text-text">{value}</div>
    </div>
  );
}

function laneIcon(laneId: ProblemsTriageModel['lanes'][number]['id']) {
  if (laneId === 'urgent') return <ShieldAlert size={14} className="text-red" />;
  if (laneId === 'due') return <CalendarClock size={14} className="text-amber" />;
  if (laneId === 'owner') return <UserRound size={14} className="text-cyan" />;
  return <Clock size={14} className="text-purple" />;
}

function ProblemList({
  items,
  selected,
  setSelected,
  compact,
}: {
  items: ProblemRead[];
  selected: UUID[];
  setSelected: (ids: UUID[]) => void;
  compact?: boolean;
}) {
  if (!items.length) {
    return <EmptyState title="No problems" detail="No findings match the current Problems Center filters." />;
  }
  return (
    <div className="max-h-[58vh] space-y-2 overflow-y-auto pr-1">
      {items.map((item) => (
        <div key={item.id} className="rounded-lg border border-border bg-bg/30 p-3">
          <div className="flex items-start gap-3">
            {!compact && (
              <input
                type="checkbox"
                checked={selected.includes(item.finding_id)}
                onChange={(event) => setSelected(event.target.checked ? [...selected, item.finding_id] : selected.filter((id) => id !== item.finding_id))}
                className="mt-1 h-4 w-4 accent-cyan"
              />
            )}
            <div className="min-w-0 flex-1">
              <div className="flex flex-wrap items-center gap-2">
                <StatusBadge value={item.severity} />
                <StatusBadge value={item.problem_status} />
              </div>
              <div className="mt-2 text-[1rem] font-semibold text-text">{item.title}</div>
              <div className="mt-1 text-[0.925rem] leading-5 text-muted">{item.engagement_name} · {item.target_id} · {item.days_open}d open</div>
              <div className="mt-2 flex flex-wrap gap-2 text-[0.85rem] text-muted">
                <span className="inline-flex items-center gap-1"><UserRound size={12} />{item.assignee ?? 'unassigned'}</span>
                <span>{formatDate(item.updated_at)}</span>
              </div>
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}
