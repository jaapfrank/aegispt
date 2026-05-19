import { useEffect, useMemo, useState } from 'react';
import { BarChart3, CalendarDays, GitCompare, Search, Trash2 } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { getPortfolioRuns } from '../../api/client';
import type { PortfolioRun, UUID } from '../../api/types';
import { useAegisStore } from '../../store';
import { ActionButton, EmptyState, Field, MetricCard, PageHeader, Panel, StatusBadge } from './screenPrimitives';
import { formatDate, inputClass } from './screenUtils';

export default function HistoryScreen() {
  const navigate = useNavigate();
  const engagements = useAegisStore((state) => state.engagements);
  const selectEngagement = useAegisStore((state) => state.selectEngagement);
  const setSelectedRun = useAegisStore((state) => state.setSelectedRun);
  const [runs, setRuns] = useState<PortfolioRun[]>([]);
  const [selectedForCompare, setSelectedForCompare] = useState<UUID[]>([]);
  const [selectedForDelete, setSelectedForDelete] = useState<Set<UUID>>(new Set());
  const [deleting, setDeleting] = useState(false);
  const [status, setStatus] = useState('all');
  const [engagementId, setEngagementId] = useState('all');
  const [dateFrom, setDateFrom] = useState('');
  const [query, setQuery] = useState('');
  const [compareRequested, setCompareRequested] = useState(false);
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    async function loadRuns() {
      setLoading(true);
      setMessage(null);
      try {
        const payload = await getPortfolioRuns();
        if (!cancelled) setRuns(payload);
      } catch (error) {
        if (!cancelled) setMessage(error instanceof Error ? error.message : 'Run history is unavailable.');
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    void loadRuns();
    return () => {
      cancelled = true;
    };
  }, []);

  const filteredRuns = useMemo(() => {
    const lower = query.trim().toLowerCase();
    const fromTime = dateFrom ? Date.parse(dateFrom) : null;
    return runs.filter((run) => {
      if (status !== 'all' && run.status !== status) return false;
      if (engagementId !== 'all' && run.engagement_id !== engagementId) return false;
      if (fromTime && Date.parse(run.created_at) < fromTime) return false;
      if (lower && !`${run.engagement_name} ${run.profile.name} ${run.status}`.toLowerCase().includes(lower)) return false;
      return true;
    });
  }, [dateFrom, engagementId, query, runs, status]);

  const comparison = useMemo(() => (compareRequested ? compareRuns(selectedForCompare, runs) : null), [compareRequested, runs, selectedForCompare]);

  function openRun(run: PortfolioRun) {
    selectEngagement(run.engagement_id);
    setSelectedRun(run);
    navigate('/mission-control');
  }

  function toggleCompare(runId: UUID) {
    setSelectedForCompare((current) => {
      if (current.includes(runId)) return current.filter((id) => id !== runId);
      return [...current, runId].slice(-2);
    });
    setCompareRequested(false);
  }

  function toggleDeleteSelect(runId: UUID) {
    setSelectedForDelete((current) => {
      const next = new Set(current);
      if (next.has(runId)) next.delete(runId);
      else next.add(runId);
      return next;
    });
  }

  function selectAllFiltered() {
    setSelectedForDelete(new Set(filteredRuns.map((r) => r.id)));
  }

  function clearDeleteSelect() {
    setSelectedForDelete(new Set());
  }

  async function deleteSelected() {
    if (selectedForDelete.size === 0) return;
    const count = selectedForDelete.size;
    if (!window.confirm(`Delete ${count} run(s)? This cannot be undone.`)) return;
    setDeleting(true);
    setMessage(null);
    let failed = 0;
    for (const runId of selectedForDelete) {
      try {
        await fetch(`/api/v1/runs/${runId}`, { method: 'DELETE', headers: { 'X-Actor': 'operator-ui' } });
      } catch {
        failed++;
      }
    }
    setSelectedForDelete(new Set());
    try {
      const payload = await getPortfolioRuns();
      setRuns(payload);
    } catch {
      // ignore reload errors
    }
    setDeleting(false);
    setMessage(failed > 0 ? `${count - failed} deleted, ${failed} failed.` : `${count} run(s) deleted.`);
  }

  return (
    <section className="flex h-full min-h-0 flex-col">
      <PageHeader
        eyebrow="Run Ledger"
        title="History"
        detail="Portfolio run history assembled from the existing engagement-scoped run endpoints."
        actions={<ActionButton onClick={() => void getPortfolioRuns().then(setRuns)} loading={loading}>Refresh</ActionButton>}
      />
      {message && <div className="mb-4 rounded-md border border-amber/30 bg-amber/10 px-3 py-2 text-[0.925rem] text-amber">{message}</div>}

      <Panel title="Filters">
        <div className="grid gap-3 md:grid-cols-4">
          <Field label="Search">
            <div className="relative">
              <Search size={14} className="pointer-events-none absolute left-3 top-3 text-muted" />
              <input className={`${inputClass} pl-9`} value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Profile, engagement, status" />
            </div>
          </Field>
          <Field label="Engagement">
            <select className={inputClass} value={engagementId} onChange={(event) => setEngagementId(event.target.value)}>
              <option value="all" className="bg-surface text-text">All engagements</option>
              {engagements.map((engagement) => (
                <option key={engagement.id} value={engagement.id} className="bg-surface text-text">{engagement.name}</option>
              ))}
            </select>
          </Field>
          <Field label="Status">
            <select className={inputClass} value={status} onChange={(event) => setStatus(event.target.value)}>
              {['all', 'queued', 'requested', 'running', 'completed', 'failed', 'cancelled'].map((value) => (
                <option key={value} value={value} className="bg-surface text-text">{value}</option>
              ))}
            </select>
          </Field>
          <Field label="Created after">
            <input className={inputClass} type="date" value={dateFrom} onChange={(event) => setDateFrom(event.target.value)} />
          </Field>
        </div>
      </Panel>

      <div className="my-5 flex flex-wrap items-center gap-3 rounded-xl border border-border bg-surface/45 p-3">
        <ActionButton onClick={() => setCompareRequested(true)} disabled={selectedForCompare.length !== 2}>
          <GitCompare size={14} />Compare
        </ActionButton>
        <span className="text-[0.925rem] text-muted">{selectedForCompare.length}/2 selected for comparison</span>

        <div className="ml-auto flex flex-wrap items-center gap-2">
          {selectedForDelete.size > 0 ? (
            <>
              <button type="button" onClick={clearDeleteSelect} className="rounded-md border border-border px-3 py-1.5 text-[0.85rem] text-muted hover:text-text">
                Clear ({selectedForDelete.size})
              </button>
              <button
                type="button"
                onClick={() => void deleteSelected()}
                disabled={deleting}
                className="inline-flex items-center gap-2 rounded-md border border-red/30 bg-red/10 px-3 py-1.5 text-[0.85rem] font-semibold text-red hover:bg-red/15 disabled:opacity-50"
              >
                <Trash2 size={13} />
                {deleting ? 'Deleting…' : `Delete ${selectedForDelete.size} run(s)`}
              </button>
            </>
          ) : (
            <button type="button" onClick={selectAllFiltered} className="rounded-md border border-border px-3 py-1.5 text-[0.85rem] text-muted hover:text-text">
              Select all ({filteredRuns.length})
            </button>
          )}
        </div>
      </div>

      {comparison && (
        <div className="mb-5 grid gap-3 md:grid-cols-3">
          <MetricCard icon={<GitCompare size={15} />} label="Finding Delta" value={comparison.delta >= 0 ? `+${comparison.delta}` : comparison.delta} detail="Difference between selected run finding totals" />
          <MetricCard icon={<BarChart3 size={15} />} label="Critical Delta" value={comparison.criticalDelta >= 0 ? `+${comparison.criticalDelta}` : comparison.criticalDelta} detail="Critical finding count change" />
          <MetricCard icon={<CalendarDays size={15} />} label="Selected Runs" value="2" detail={`${comparison.left.profile.name} vs ${comparison.right.profile.name}`} />
        </div>
      )}

      <div className="min-h-0 flex-1 overflow-hidden rounded-xl border border-border bg-surface/55">
        <div className="max-h-full overflow-auto">
          <table className="min-w-[860px] w-full text-left text-[0.925rem]">
            <thead className="sticky top-0 bg-surface text-[0.77rem] uppercase tracking-wider text-muted">
              <tr>
                <th className="w-8 px-3 py-3">
                  <input
                    type="checkbox"
                    aria-label="Select all visible"
                    checked={filteredRuns.length > 0 && filteredRuns.every((r) => selectedForDelete.has(r.id))}
                    onChange={(e) => e.target.checked ? selectAllFiltered() : clearDeleteSelect()}
                  />
                </th>
                <th className="px-3 py-3">Compare</th>
                <th className="px-3 py-3">Date</th>
                <th className="px-3 py-3">Engagement</th>
                <th className="px-3 py-3">Profile</th>
                <th className="px-3 py-3">Status</th>
                <th className="px-3 py-3">Findings</th>
                <th className="px-3 py-3">Duration</th>
              </tr>
            </thead>
            <tbody>
              {filteredRuns.map((run) => (
                <tr key={run.id} className={`border-t border-border hover:bg-cyan/5 ${selectedForDelete.has(run.id) ? 'bg-red/5' : ''}`}>
                  <td className="px-3 py-3">
                    <input
                      type="checkbox"
                      aria-label="Select for deletion"
                      checked={selectedForDelete.has(run.id)}
                      onChange={() => toggleDeleteSelect(run.id)}
                      className="h-4 w-4 accent-red"
                    />
                  </td>
                  <td className="px-3 py-3">
                    <input type="checkbox" checked={selectedForCompare.includes(run.id)} onChange={() => toggleCompare(run.id)} className="h-4 w-4 accent-cyan" />
                  </td>
                  <td className="px-3 py-3 text-muted">{formatDate(run.created_at)}</td>
                  <td className="px-3 py-3 text-text">
                    <button type="button" onClick={() => openRun(run)} className="max-w-[220px] truncate text-left font-semibold hover:text-cyan">{run.engagement_name}</button>
                  </td>
                  <td className="px-3 py-3 text-muted">{run.profile.name}</td>
                  <td className="px-3 py-3"><StatusBadge value={run.status} /></td>
                  <td className="px-3 py-3 text-muted">
                    C {run.findings.findings_by_severity.critical ?? 0} · H {run.findings.findings_by_severity.high ?? 0} · M {run.findings.findings_by_severity.medium ?? 0}
                  </td>
                  <td className="px-3 py-3 text-muted">{durationLabel(run.created_at, run.updated_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {!filteredRuns.length && <EmptyState title="No runs match filters" detail="The current backend data returned no portfolio runs for these filters." />}
        </div>
      </div>
    </section>
  );
}

function compareRuns(selected: UUID[], runs: PortfolioRun[]) {
  if (selected.length !== 2) return null;
  const [left, right] = selected.map((id) => runs.find((run) => run.id === id));
  if (!left || !right) return null;
  return {
    left,
    right,
    delta: right.findings.finding_count - left.findings.finding_count,
    criticalDelta: (right.findings.findings_by_severity.critical ?? 0) - (left.findings.findings_by_severity.critical ?? 0),
  };
}

function durationLabel(start: string, end: string): string {
  const delta = Math.max(0, Date.parse(end) - Date.parse(start));
  const minutes = Math.round(delta / 60000);
  if (minutes < 1) return '<1m';
  if (minutes < 60) return `${minutes}m`;
  return `${Math.round(minutes / 60)}h`;
}
