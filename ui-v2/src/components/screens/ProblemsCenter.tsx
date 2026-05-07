import { useEffect, useMemo, useState } from 'react';
import { BadgeAlert, CheckCircle2, Clock, UserRound } from 'lucide-react';
import { bulkUpdateProblems, getProblems } from '../../api/client';
import type { ProblemRead, ProblemsQuery, ProblemsRead, UUID } from '../../api/types';
import { useAegisStore } from '../../store';
import { ActionButton, EmptyState, Field, MetricCard, PageHeader, Panel, StatusBadge, formatDate, inputClass, jsonNumber } from './screenPrimitives';

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

  useEffect(() => {
    void loadProblems();
  }, [query]);

  async function loadProblems() {
    setLoading(true);
    setMessage(null);
    try {
      const next = await getProblems(query);
      setPayload(next);
      setSelectedFindingIds((current) => current.filter((id) => next.items.some((item) => item.finding_id === id)));
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Problems endpoint unavailable.');
      setPayload(null);
    } finally {
      setLoading(false);
    }
  }

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
      setMessage(error instanceof Error ? error.message : 'Bulk update failed.');
    } finally {
      setLoading(false);
    }
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
      {message && <div className="mb-4 rounded-md border border-cyan/25 bg-cyan/10 px-3 py-2 text-[12px] text-cyan">{message}</div>}

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
        <span className="ml-auto text-[12px] text-muted">{selectedFindingIds.length} selected</span>
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
              <div className="mt-2 text-[13px] font-semibold text-text">{item.title}</div>
              <div className="mt-1 text-[12px] leading-5 text-muted">{item.engagement_name} · {item.target_id} · {item.days_open}d open</div>
              <div className="mt-2 flex flex-wrap gap-2 text-[11px] text-muted">
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
