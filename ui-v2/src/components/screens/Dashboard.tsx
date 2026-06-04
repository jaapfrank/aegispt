import { useEffect, useMemo, useState } from 'react';
import { Activity, ArrowRight, BadgeAlert, FileText, Gauge, Shield, Siren, Target } from 'lucide-react';
import { Link } from 'react-router-dom';
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { getDashboard, launchZeroDayRapidResponseScan } from '../../api/client';
import type { DashboardRead } from '../../api/types';
import { useAegisStore } from '../../store';
import { safeErrorMessage } from '../../viewModels/safeMessaging';
import { ActionButton, EmptyState, MetricCard, PageHeader, Panel, StatusBadge } from './screenPrimitives';
import { formatDate, jsonNumber, jsonString } from './screenUtils';

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
        if (!cancelled) {
          setDashboard(null);
          setMessage(safeErrorMessage(error, {
            fallback: 'Dashboard data could not load. Refresh or select another engagement.',
            unavailable: 'Dashboard API is temporarily unavailable. Mission Control still shows the selected run when available.',
          }));
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    void loadDashboard();
    return () => {
      cancelled = true;
    };
  }, [selectedEngagementId]);

  const localActiveTaskCount = useMemo(
    () => runs.reduce((total, run) => total + run.tasks.filter((task) => ['queued', 'running', 'requested'].includes(task.status)).length, 0),
    [runs],
  );
  const dashboardActiveRun = dashboard?.active_run ?? null;
  const dashboardActiveTaskCount = dashboardActiveRun
    ? jsonNumber(dashboardActiveRun.tasks_running) + jsonNumber(dashboardActiveRun.tasks_queued) + jsonNumber(dashboardActiveRun.tasks_requested)
    : null;
  const activeTaskCount = dashboardActiveTaskCount ?? localActiveTaskCount;
  const openProblemTotal = jsonNumber(dashboard?.open_problems?.total, findings.filter((finding) => finding.status === 'open').length);
  const reportReadyRuns = runs.filter((run) => run.status === 'completed').length;
  const blastRadiusScore = jsonNumber(dashboard?.blast_radius?.score);
  const blastRadiusTier = jsonString(dashboard?.blast_radius?.tier, 'none');
  const blastRadiusProcesses = Array.isArray(dashboard?.blast_radius?.affected_business_processes)
    ? dashboard.blast_radius.affected_business_processes
    : [];
  const zeroDay = dashboard?.zero_day_rapid_response ?? {};
  const zeroDayAlerts = Array.isArray(zeroDay.alerts) ? zeroDay.alerts : [];
  const riskTrendData = useMemo(() => buildRiskTrendData(dashboard), [dashboard]);
  const findingDistributionData = useMemo(() => buildFindingDistributionData(dashboard, findings), [dashboard, findings]);

  async function handleZeroDayScan(alert: Record<string, unknown>) {
    const engagementId = jsonString(alert.engagement_id, selectedEngagementId ?? '');
    const recordId = jsonString(alert.record_id);
    if (!engagementId || !recordId) {
      setMessage('Zero-day alert is missing engagement or advisory context.');
      return;
    }
    setLoading(true);
    setMessage(null);
    try {
      const result = await launchZeroDayRapidResponseScan(engagementId, recordId, jsonString(alert.target, '') || null);
      setMessage(`Rapid response scan staged as ${result.profile_name}; status ${result.run_status}.`);
      setDashboard(await getDashboard(selectedEngagementId));
    } catch (error) {
      setMessage(safeErrorMessage(error, {
        fallback: 'Rapid response scan could not be staged. Check scope and try again.',
        unavailable: 'Rapid response scan staging is temporarily unavailable.',
      }));
    } finally {
      setLoading(false);
    }
  }

  async function refreshDashboard() {
    setLoading(true);
    setMessage(null);
    try {
      setDashboard(await getDashboard(selectedEngagementId));
    } catch (error) {
      setMessage(safeErrorMessage(error, {
        fallback: 'Dashboard data could not refresh. Select another engagement or try again.',
        unavailable: 'Dashboard API is temporarily unavailable. Existing run data remains available in Mission Control.',
      }));
    } finally {
      setLoading(false);
    }
  }

  return (
    <section className="flex h-full min-h-0 flex-col">
      <PageHeader
        eyebrow="Portfolio"
        title="Dashboard"
        detail="Live portfolio posture from the existing dashboard, engagement, run, and finding data contracts."
        actions={<ActionButton onClick={() => void refreshDashboard()} loading={loading}>Refresh</ActionButton>}
      />

      {message && <div className="mb-4 rounded-md border border-amber/30 bg-amber/10 px-3 py-2 text-[0.925rem] text-amber">{message}</div>}

      <div className="mb-5 grid gap-3 md:grid-cols-2 xl:grid-cols-6">
        <MetricCard icon={<Shield size={15} />} label="Portfolio" value={dashboard?.engagements?.length ?? engagements.length} detail="Engagements in scope" />
        <MetricCard icon={<Activity size={15} />} label="Active Tasks" value={activeTaskCount} detail={dashboardActiveRun ? jsonString(dashboardActiveRun.profile_name, 'Active run') : 'No active run'} />
        <MetricCard icon={<Gauge size={15} />} label="Portfolio Risk" value={jsonNumber(dashboard?.risk_score?.score).toFixed(1)} detail={jsonString(dashboard?.risk_score?.trend, 'stable')} />
        <MetricCard icon={<Target size={15} />} label="Blast Radius" value={blastRadiusScore.toFixed(1)} detail={`${titleCase(blastRadiusTier)} business impact`} />
        <MetricCard icon={<BadgeAlert size={15} />} label="Open Problems" value={openProblemTotal} detail={`${jsonNumber(dashboard?.open_problems?.critical)} critical · ${jsonNumber(dashboard?.open_problems?.high)} high`} />
        <MetricCard icon={<FileText size={15} />} label="Reports" value={reportReadyRuns} detail="Completed runs with report catalog potential" />
      </div>

      <div className="mb-5">
        <Panel title="Zero-Day Rapid Response" detail={`${jsonNumber(zeroDay.alert_count)} stored-inventory matches from local threat intel.`}>
          {zeroDayAlerts.length ? (
            <div className="grid gap-3 lg:grid-cols-2">
              {zeroDayAlerts.slice(0, 4).map((alert) => (
                <div key={jsonString(alert.id, `${jsonString(alert.record_id)}-${jsonString(alert.target)}`)} className="rounded-lg border border-rose-400/25 bg-rose-400/10 p-3">
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <div className="flex items-center gap-2 text-[0.85rem] font-bold uppercase text-rose-200">
                        <Siren size={14} />
                        {jsonString(alert.advisory_id, 'CVE')}
                      </div>
                      <div className="mt-1 truncate text-[1rem] font-semibold text-text">{jsonString(alert.title, 'Rapid response advisory')}</div>
                      <p className="mt-1 line-clamp-2 text-[0.925rem] leading-5 text-muted">
                        {jsonString(alert.target, 'Target')} · {jsonString(alert.version_detail, 'Inventory version requires review')}
                      </p>
                    </div>
                    <ActionButton onClick={() => void handleZeroDayScan(alert)} loading={loading}>Scan Now</ActionButton>
                  </div>
                  <div className="mt-3 flex flex-wrap gap-2 text-[0.77rem] font-semibold uppercase">
                    <span className="rounded-full border border-rose-300/25 px-2 py-0.5 text-rose-100">{jsonString(alert.severity, 'high')}</span>
                    <span className="rounded-full border border-cyan/25 px-2 py-0.5 text-cyan">{jsonString(alert.version_status, 'unknown')}</span>
                    <span className="rounded-full border border-border px-2 py-0.5 text-muted">{jsonString(alert.matched_product?.product, 'product')}</span>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <EmptyState title="No zero-day matches" detail="Stored threat-intel records do not currently match detected tech stack inventory." />
          )}
        </Panel>
      </div>

      <div className="mb-5 grid gap-5 xl:grid-cols-[1.25fr_0.75fr]">
        <Panel title="Risk Trend" detail="Interactive score projection from current dashboard and engagement data.">
          <div className="h-[240px]">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={riskTrendData} margin={{ left: 0, right: 12, top: 14, bottom: 0 }}>
                <defs>
                  <linearGradient id="riskTrendGlow" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#5ecfff" stopOpacity={0.55} />
                    <stop offset="100%" stopColor="#5ecfff" stopOpacity={0.04} />
                  </linearGradient>
                </defs>
                <CartesianGrid stroke="rgba(142,191,228,0.12)" vertical={false} />
                <XAxis dataKey="label" stroke="#8ebfe4" tickLine={false} axisLine={false} tick={{ fontSize: 12 }} />
                <YAxis stroke="#8ebfe4" tickLine={false} axisLine={false} domain={[0, 10]} tick={{ fontSize: 12 }} />
                <Tooltip content={<ChartTooltip valueLabel="Risk" />} />
                <Area
                  type="monotone"
                  dataKey="risk"
                  stroke="#5ecfff"
                  strokeWidth={2.5}
                  fill="url(#riskTrendGlow)"
                  activeDot={{ r: 5, stroke: '#04080f', strokeWidth: 2, fill: '#5ecfff' }}
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </Panel>

        <Panel title="Findings Distribution" detail="Open severity balance from dashboard problems and current run findings.">
          <div className="h-[240px]">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={findingDistributionData} margin={{ left: -20, right: 6, top: 14, bottom: 0 }}>
                <CartesianGrid stroke="rgba(142,191,228,0.12)" vertical={false} />
                <XAxis dataKey="label" stroke="#8ebfe4" tickLine={false} axisLine={false} tick={{ fontSize: 12 }} />
                <YAxis allowDecimals={false} stroke="#8ebfe4" tickLine={false} axisLine={false} tick={{ fontSize: 12 }} />
                <Tooltip content={<ChartTooltip valueLabel="Findings" />} />
                <Bar dataKey="count" radius={[6, 6, 0, 0]}>
                  {findingDistributionData.map((entry) => (
                    <Cell key={entry.label} fill={entry.color} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Panel>
      </div>

      <div className="mb-5">
        <Panel title="Blast Radius" detail={jsonString(dashboard?.blast_radius?.advisory_note, 'Business impact is derived from stored evidence only.')}>
          <div className="grid gap-3 md:grid-cols-[220px_1fr]">
            <div className="rounded-lg border border-cyan/20 bg-cyan/10 p-4">
              <div className="text-[0.85rem] font-bold uppercase text-muted">Modeled Impact</div>
              <div className="mt-2 text-3xl font-semibold text-text">{blastRadiusScore.toFixed(1)}</div>
              <div className="mt-1 text-[0.925rem] text-cyan">{titleCase(blastRadiusTier)}</div>
            </div>
            <div className="grid gap-2 md:grid-cols-3">
              {(blastRadiusProcesses.length ? blastRadiusProcesses.slice(0, 3) : [{ label: 'No critical process tagged', category_label: 'Awaiting inventory tags', criticality: 'none' }]).map((process) => (
                <div key={jsonString(process.id, jsonString(process.label, 'process'))} className="rounded-lg border border-border bg-bg/30 p-3">
                  <div className="truncate text-[1rem] font-semibold text-text">{jsonString(process.label, 'Business process')}</div>
                  <div className="mt-1 text-[0.85rem] text-muted">{jsonString(process.category_label, 'Predefined category')}</div>
                  <div className="mt-2 inline-flex rounded-full border border-border px-2 py-0.5 text-[0.77rem] font-semibold uppercase text-cyan">
                    {jsonString(process.criticality, 'unknown')}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </Panel>
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
          {dashboard?.activity_feed?.length ? (
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
        {dashboard?.engagements?.length ? (
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

function buildRiskTrendData(dashboard: DashboardRead | null): Array<{ label: string; risk: number }> {
  const current = clampRisk(jsonNumber(dashboard?.risk_score?.score, 0));
  const engagementScores = (dashboard?.engagements ?? [])
    .map((engagement) => clampRisk(jsonNumber(engagement.risk_score, current)))
    .filter((score) => score > 0);
  if (engagementScores.length >= 3) {
    return engagementScores.slice(0, 6).map((risk, index) => ({ label: `E${index + 1}`, risk }));
  }
  const trend = jsonString(dashboard?.risk_score?.trend, 'stable').toLowerCase();
  const direction = trend.includes('rising') || trend.includes('up') ? 1 : trend.includes('falling') || trend.includes('down') ? -1 : 0.25;
  return ['T-5', 'T-4', 'T-3', 'T-2', 'T-1', 'Now'].map((label, index) => ({
    label,
    risk: clampRisk(current - (5 - index) * 0.34 * direction),
  }));
}

function buildFindingDistributionData(dashboard: DashboardRead | null, findings: Array<{ severity: string }>) {
  const fallbackCounts = findings.reduce<Record<string, number>>((counts, finding) => {
    const key = finding.severity.toLowerCase();
    counts[key] = (counts[key] ?? 0) + 1;
    return counts;
  }, {});
  const problemMap = dashboard?.open_problems ?? {};
  return [
    ['Critical', 'critical', '#ef4444'],
    ['High', 'high', '#f59e0b'],
    ['Medium', 'medium', '#fde047'],
    ['Low', 'low', '#5ecfff'],
  ].map(([label, key, color]) => ({
    label,
    count: jsonNumber(problemMap[key], fallbackCounts[key] ?? 0),
    color,
  }));
}

function clampRisk(value: number): number {
  return Math.max(0, Math.min(10, Number(value.toFixed(1))));
}

function titleCase(value: string): string {
  return value
    .replace(/[-_]/g, ' ')
    .split(' ')
    .filter(Boolean)
    .map((part) => `${part.slice(0, 1).toUpperCase()}${part.slice(1)}`)
    .join(' ') || 'None';
}

function ChartTooltip({ active, payload, label, valueLabel }: { active?: boolean; payload?: Array<{ value?: number }>; label?: string; valueLabel: string }) {
  if (!active || !payload?.length) return null;
  return (
    <div className="rounded-md border border-cyan/25 bg-panel/95 px-3 py-2 shadow-[0_0_1rem_var(--panel-glow)]">
      <div className="text-[0.85rem] font-bold uppercase text-cyan">{label}</div>
      <div className="text-[0.925rem] text-text">{valueLabel}: {payload[0]?.value ?? 0}</div>
    </div>
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
