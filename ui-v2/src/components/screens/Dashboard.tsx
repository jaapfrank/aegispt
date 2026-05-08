import { useEffect, useMemo, useState } from 'react';
import { Activity, ArrowRight, BadgeAlert, FileText, Gauge, Shield, Target } from 'lucide-react';
import { Link } from 'react-router-dom';
import { getDashboard } from '../../api/client';
import type { DashboardRead } from '../../api/types';
import { useAegisStore } from '../../store';
import { ActionButton, EmptyState, MetricCard, PageHeader, Panel, StatusBadge, formatDate, jsonNumber, jsonString } from './screenPrimitives';

export default function DashboardScreen() {
  const selectedEngagementId = useAegisStore((state) => state.selectedEngagementId);
  const engagements = useAegisStore((state) => state.engagements);
  const runs = useAegisStore((state) => state.runs);
  const findings = useAegisStore((state) => state.findings);
  const [dashboard, setDashboard] = useState<DashboardRead | null>(null);
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    async function loadDashboard() {
      setLoading(true);
      setMessage(null);
      try {
        const payload = await getDashboard(selectedEngagementId);
        if (!cancelled) setDashboard(payload);
      } catch (error) {
        if (!cancelled) setMessage(error instanceof Error ? error.message : 'Dashboard API unavailable.');
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    void loadDashboard();
    return () => {
      cancelled = true;
    };
  }, [selectedEngagementId]);

  const activeTaskCount = useMemo(
    () => runs.reduce((total, run) => total + run.tasks.filter((task) => ['queued', 'running', 'requested'].includes(task.status)).length, 0),
    [runs],
  );
  const openProblemTotal = jsonNumber(dashboard?.open_problems.total, findings.filter((finding) => finding.status === 'open').length);
  const reportReadyRuns = runs.filter((run) => run.status === 'completed').length;

  return (
    <section className="flex h-full min-h-0 flex-col">
      <PageHeader
        eyebrow="Portfolio"
        title="Dashboard"
        detail="Live portfolio posture from the existing dashboard, engagement, run, and finding data contracts."
        actions={<ActionButton onClick={() => void getDashboard(selectedEngagementId).then(setDashboard)} loading={loading}>Refresh</ActionButton>}
      />

      {message && <div className="mb-4 rounded-md border border-amber/30 bg-amber/10 px-3 py-2 text-[0.925rem] text-amber">{message}</div>}

      <div className="mb-5 grid gap-3 md:grid-cols-2 xl:grid-cols-5">
        <MetricCard icon={<Shield size={15} />} label="Portfolio" value={dashboard?.engagements.length ?? engagements.length} detail="Engagements in scope" />
        <MetricCard icon={<Activity size={15} />} label="Active Tasks" value={activeTaskCount || jsonNumber(dashboard?.active_run?.tasks_running)} detail={dashboard?.active_run ? jsonString(dashboard.active_run.profile_name, 'Active run') : 'No active run'} />
        <MetricCard icon={<Gauge size={15} />} label="Portfolio Risk" value={jsonNumber(dashboard?.risk_score.score).toFixed(1)} detail={jsonString(dashboard?.risk_score.trend, 'stable')} />
        <MetricCard icon={<BadgeAlert size={15} />} label="Open Problems" value={openProblemTotal} detail={`${jsonNumber(dashboard?.open_problems.critical)} critical · ${jsonNumber(dashboard?.open_problems.high)} high`} />
        <MetricCard icon={<FileText size={15} />} label="Reports" value={reportReadyRuns} detail="Completed runs with report catalog potential" />
      </div>

      {!dashboard?.has_engagements && (
        <div className="mb-5">
          <FirstRunPanel />
        </div>
      )}

      <div className="grid min-h-0 flex-1 gap-5 xl:grid-cols-[1fr_1fr]">
        <Panel title="Quick Actions" detail="Shortcuts keep the rebuilt UI task-focused without bypassing existing backend gates.">
          <div className="grid gap-3 sm:grid-cols-2">
            <QuickAction to="/intake" label="New Mission" detail="Create scope and ROE-backed runs." />
            <QuickAction to="/problems" label="Open Problems" detail="Triage cross-engagement findings." />
            <QuickAction to="/reports" label="Reports" detail="Preview and export evidence-backed reports." />
            <QuickAction to="/mission-control" label="Mission Control" detail="Return to live run operations." />
          </div>
        </Panel>

        <Panel title="Activity Feed" detail={`Generated ${formatDate(dashboard?.generated_at)}`}>
          {dashboard?.activity_feed.length ? (
            <div className="space-y-2">
              {dashboard.activity_feed.slice(0, 8).map((item) => (
                <div key={String(item.id)} className="rounded-lg border border-border bg-bg/30 p-3">
                  <div className="flex items-center justify-between gap-3">
                    <div className="min-w-0 truncate text-[1rem] font-semibold text-text">{jsonString(item.label)}</div>
                    <span className="shrink-0 text-[0.85rem] text-muted">{formatDate(String(item.timestamp))}</span>
                  </div>
                  <p className="mt-1 line-clamp-2 text-[0.925rem] leading-5 text-muted">{jsonString(item.detail, jsonString(item.engagement_name, 'No detail'))}</p>
                </div>
              ))}
            </div>
          ) : (
            <EmptyState title="No activity yet" detail="The dashboard endpoint returned no activity feed entries for the current tenant context." />
          )}
        </Panel>
      </div>

      <Panel title="Engagement Snapshot" detail="Backend engagement summaries from the dashboard endpoint.">
        {dashboard?.engagements.length ? (
          <div className="grid gap-3 lg:grid-cols-2">
            {dashboard.engagements.slice(0, 6).map((engagement) => (
              <div key={String(engagement.id)} className="rounded-lg border border-border bg-bg/30 p-3">
                <div className="flex items-center justify-between gap-3">
                  <div className="min-w-0 truncate text-[1rem] font-semibold text-text">{jsonString(engagement.name)}</div>
                  <StatusBadge value={jsonString(engagement.last_run_status, 'no runs')} />
                </div>
                <div className="mt-2 grid grid-cols-3 gap-2 text-[0.85rem] text-muted">
                  <span>Risk {jsonNumber(engagement.risk_score).toFixed(1)}</span>
                  <span>{jsonNumber(engagement.open_critical_count)} critical</span>
                  <span>{jsonNumber(engagement.run_count)} runs</span>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <EmptyState title="No engagement summaries" detail="Create an engagement from Intake to populate portfolio dashboard data." />
        )}
      </Panel>
    </section>
  );
}

function QuickAction({ to, label, detail }: { to: string; label: string; detail: string }) {
  return (
    <Link to={to} className="group rounded-lg border border-border bg-bg/30 p-4 transition-colors hover:border-cyan/35 hover:bg-cyan/10">
      <div className="flex items-center justify-between gap-3">
        <span className="text-[1rem] font-semibold text-text">{label}</span>
        <ArrowRight size={15} className="text-cyan transition-transform group-hover:translate-x-0.5" />
      </div>
      <p className="mt-2 text-[0.925rem] leading-5 text-muted">{detail}</p>
    </Link>
  );
}

function FirstRunPanel() {
  const steps = [
    ['Connect ChatGPT', '/settings'],
    ['Create engagement', '/intake'],
    ['Run first scan', '/mission-control'],
  ];
  return (
    <Panel title="First Run" detail="New installs start with configuration, scoped mission creation, and governed validation.">
      <div className="grid gap-3 md:grid-cols-3">
        {steps.map(([label, to], index) => (
          <Link key={label} to={to} className="rounded-lg border border-cyan/25 bg-cyan/10 p-4">
            <div className="mb-2 inline-flex h-7 w-7 items-center justify-center rounded-md bg-cyan text-bg">
              <Target size={15} />
            </div>
            <div className="text-[1rem] font-semibold text-text">{index + 1}. {label}</div>
          </Link>
        ))}
      </div>
    </Panel>
  );
}
