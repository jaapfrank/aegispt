import { useEffect, useMemo, useState } from 'react';
import type { ReactNode } from 'react';
import {
  BarChart3,
  Check,
  ChevronDown,
  Download,
  FileText,
  Hash,
  History,
  Loader2,
  ScrollText,
  Shield,
} from 'lucide-react';
import { Link } from 'react-router-dom';
import {
  Bar,
  BarChart as ReBarChart,
  CartesianGrid,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';
import {
  downloadRunReport,
  getFindingsForRunContext,
  getRunReportMarkdown,
  getRunReports,
  getRunsForEngagement,
} from '../../api/client';
import { ApiError } from '../../api/client';
import type { Engagement, Finding, Run, RunReportCatalogItem, UUID } from '../../api/types';
import { useAegisStore } from '../../store';

type ReportTab = 'reports' | 'dossier';
type ReportAction = 'preview' | 'html' | 'pdf' | null;

function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export default function ReportCenter() {
  const selectedEngagement = useAegisStore((state) => state.selectedEngagement);
  const selectedEngagementId = useAegisStore((state) => state.selectedEngagementId);
  const selectedRun = useAegisStore((state) => state.selectedRun);
  const selectedRunId = useAegisStore((state) => state.selectedRunId);
  const runs = useAegisStore((state) => state.runs);
  const setRuns = useAegisStore((state) => state.setRuns);
  const selectRun = useAegisStore((state) => state.selectRun);
  const setError = useAegisStore((state) => state.setError);

  const [activeTab, setActiveTab] = useState<ReportTab>('reports');
  const [catalog, setCatalog] = useState<RunReportCatalogItem[]>([]);
  const [selectedVariant, setSelectedVariant] = useState<string | null>(null);
  const [markdown, setMarkdown] = useState<string | null>(null);
  const [loadingCatalog, setLoadingCatalog] = useState(false);
  const [action, setAction] = useState<ReportAction>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [compareRunId, setCompareRunId] = useState<UUID | ''>('');
  const [comparison, setComparison] = useState<ComparisonSummary | null>(null);
  const [loadingComparison, setLoadingComparison] = useState(false);

  const selectedReport = catalog.find((report) => report.variant === selectedVariant) ?? catalog[0] ?? null;
  const reportRuns = useMemo(() => reportRunOptions(runs, selectedRun), [runs, selectedRun]);
  const selectedReportRun = useMemo(
    () => reportRuns.find((run) => selectedRun !== null && sameReportGroup(run, selectedRun)) ?? selectedRun,
    [reportRuns, selectedRun],
  );
  const previousRuns = useMemo(() => earlierRuns(reportRuns, selectedReportRun), [reportRuns, selectedReportRun]);
  const timelineRuns = useMemo(() => [...runs].sort(sortRunsDescending), [runs]);

  useEffect(() => {
    if (!selectedRunId) {
      setCatalog([]);
      setSelectedVariant(null);
      setMarkdown(null);
      return;
    }

    const runId = selectedRunId;
    let cancelled = false;
    async function loadCatalog() {
      setLoadingCatalog(true);
      setMessage(null);
      setError(null);
      try {
        const payload = await getRunReports(runId);
        if (cancelled) return;
        setCatalog(payload);
        const nextVariant = payload.some((report) => report.variant === selectedVariant)
          ? selectedVariant
          : payload[0]?.variant ?? null;
        setSelectedVariant(nextVariant);
        setMarkdown(null);
      } catch (error) {
        if (cancelled) return;
        setCatalog([]);
        setSelectedVariant(null);
        setMarkdown(null);
        setError(errorMessage(error));
      } finally {
        if (!cancelled) {
          setLoadingCatalog(false);
        }
      }
    }

    void loadCatalog();
    return () => {
      cancelled = true;
    };
  }, [selectedRunId, selectedVariant, setError]);

  useEffect(() => {
    setComparison(null);
    setCompareRunId('');
  }, [selectedRunId]);

  async function selectReport(report: RunReportCatalogItem) {
    setSelectedVariant(report.variant);
    setMessage(null);
    if (selectedRunId && report.preview_allowed) {
      await loadMarkdownPreview(selectedRunId, report.variant);
    } else {
      setMarkdown(null);
      setMessage(report.availability_reason || 'Preview is not available for this report.');
    }
  }

  async function handleGeneratePreview() {
    if (!selectedRunId || !selectedReport) return;
    if (!selectedReport.preview_allowed) {
      setMessage(selectedReport.availability_reason || 'Preview is not available for this report.');
      return;
    }
    await loadMarkdownPreview(selectedRunId, selectedReport.variant);
  }

  async function loadMarkdownPreview(runId: UUID, variant: string) {
    setAction('preview');
    setMessage(null);
    try {
      const payload = await getRunReportMarkdown(runId, variant);
      setMarkdown(payload);
      setMessage('Markdown preview generated from stored run evidence.');
    } catch (error) {
      setMarkdown(null);
      setMessage(errorMessage(error));
    } finally {
      setAction(null);
    }
  }

  async function handleDownload(format: 'html' | 'pdf') {
    if (!selectedRunId || !selectedReport) return;
    if (!selectedReport.export_allowed) {
      setMessage(selectedReport.availability_reason || `${format.toUpperCase()} download is not available for this report.`);
      return;
    }
    setAction(format);
    setMessage(null);
    try {
      const blob = await downloadRunReport(selectedRunId, selectedReport.variant, format);
      const filename =
        selectedReport.download_names[format] ?? `aegispt-run-${selectedRunId}-${selectedReport.variant}.${format}`;
      triggerDownload(blob, filename);
      setMessage(`${format.toUpperCase()} download prepared.`);
    } catch (error) {
      setMessage(errorMessage(error));
    } finally {
      setAction(null);
    }
  }

  async function handleCompare(nextRunId: UUID | '') {
    setCompareRunId(nextRunId);
    setComparison(null);
    const previousRun = previousRuns.find((run) => run.id === nextRunId) ?? null;
    if (!selectedRun || !previousRun || !nextRunId) return;
    setLoadingComparison(true);
    setMessage(null);
    try {
      const [currentFindings, previousFindings] = await Promise.all([
        getFindingsForRunContext(selectedRun),
        getFindingsForRunContext(previousRun),
      ]);
      setComparison(compareFindings(currentFindings, previousFindings));
    } catch (error) {
      setMessage(errorMessage(error));
    } finally {
      setLoadingComparison(false);
    }
  }

  async function handleRefreshRuns() {
    if (!selectedEngagementId) return;
    try {
      const payload = await getRunsForEngagement(selectedEngagementId);
      setRuns(payload);
    } catch (error) {
      setMessage(errorMessage(error));
    }
  }

  if (!selectedEngagementId) {
    return (
      <EmptyState
        title="No Engagement Selected"
        detail="Select an engagement before opening Report Center."
        action={<Link to="/intake" className="rounded-md border border-cyan/30 bg-cyan/10 px-4 py-2 text-[1rem] font-semibold text-cyan">New Mission</Link>}
      />
    );
  }

  if (!selectedRunId) {
    return (
      <EmptyState
        title="No Run Selected"
        detail="Report catalog and dossier timeline unlock after a run exists for the selected engagement."
        action={<Link to="/intake" className="rounded-md border border-cyan/30 bg-cyan/10 px-4 py-2 text-[1rem] font-semibold text-cyan">Create Run</Link>}
      />
    );
  }

  return (
    <section className="flex h-full min-h-0 flex-col">
      <header className="mb-5 flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold text-text">Report Center</h1>
          <p className="mt-1 text-[1rem] text-muted">
            {selectedEngagement?.name ?? 'Selected engagement'} · evidence-backed exports
          </p>
        </div>
        <div className="flex rounded-lg border border-border bg-surface/55 p-1">
          <TabButton active={activeTab === 'reports'} onClick={() => setActiveTab('reports')} icon={<FileText size={14} />}>Reports</TabButton>
          <TabButton active={activeTab === 'dossier'} onClick={() => setActiveTab('dossier')} icon={<History size={14} />}>Dossier</TabButton>
        </div>
      </header>

      {activeTab === 'reports' ? (
        <div className="grid min-h-0 flex-1 gap-5 xl:grid-cols-[40fr_60fr]">
          <div className="flex min-h-0 flex-col overflow-hidden rounded-xl border border-border bg-surface/50 backdrop-blur-md">
            <RunStrip selectedRun={selectedReportRun} runs={reportRuns} selectedRunId={selectedReportRun?.id ?? selectedRunId} selectRun={selectRun} />
            <div className="min-h-0 flex-1 overflow-y-auto p-4">
              {loadingCatalog ? (
                <LoadingPanel label="Loading report catalog from API" />
              ) : catalog.length === 0 ? (
                <EmptyInline title="No reports available" detail="The backend did not return report catalog entries for this run." />
              ) : (
                <div className="grid gap-3">
                  {catalog.map((report) => (
                    <ReportCard
                      key={report.variant}
                      report={report}
                      selected={report.variant === selectedReport?.variant}
                      onClick={() => void selectReport(report)}
                    />
                  ))}
                </div>
              )}
            </div>
          </div>

          <div className="min-h-0 overflow-hidden rounded-xl border border-border bg-surface/60 backdrop-blur-md">
            {selectedReport ? (
              <div className="flex h-full min-h-0 flex-col">
                <ReportPreviewHeader report={selectedReport} run={selectedRun} />
                <ReportChartStrip report={selectedReport} run={selectedRun} />
                <div className="border-b border-border p-4">
                  <div className="flex flex-wrap gap-2">
                    <ActionButton onClick={handleGeneratePreview} loading={action === 'preview'} icon={<ScrollText size={14} />}>
                      Generate Markdown Preview
                    </ActionButton>
                    <ActionButton onClick={() => void handleDownload('html')} loading={action === 'html'} icon={<Download size={14} />}>
                      Download HTML
                    </ActionButton>
                    <ActionButton onClick={() => void handleDownload('pdf')} loading={action === 'pdf'} icon={<Download size={14} />}>
                      Download PDF
                    </ActionButton>
                    {selectedRunId && (
                      <button
                        type="button"
                        onClick={() => void (async () => {
                          const resp = await fetch(`/api/v1/runs/${selectedRunId}/report?format=markdown&variant=management_nl`, { headers: { 'X-Actor': 'operator-ui' } });
                          const text = await resp.text();
                          const blob = new Blob([text], { type: 'text/markdown' });
                          const url = URL.createObjectURL(blob);
                          const a = document.createElement('a');
                          a.href = url;
                          a.download = `aegispt-management-rapport-${selectedRunId.slice(0,8)}.md`;
                          document.body.appendChild(a);
                          a.click();
                          a.remove();
                          URL.revokeObjectURL(url);
                        })()}
                        className="inline-flex items-center gap-2 rounded-md border border-amber/30 bg-amber/10 px-3 py-2 text-[0.925rem] font-semibold text-amber hover:bg-amber/15"
                      >
                        <Download size={14} />
                        🇳🇱 Nederlands Management Rapport
                      </button>
                    )}
                  </div>
                  {message && <div className="mt-3 rounded-md border border-cyan/20 bg-cyan/10 px-3 py-2 text-[0.925rem] text-cyan">{message}</div>}
                </div>

                <div className="min-h-0 flex-1 overflow-y-auto p-4">
                  <EvidenceHash report={selectedReport} />
                  <div className="mt-4 rounded-lg border border-border bg-bg/30 p-4">
                    {markdown ? (
                      <div className="prose-preview">{renderMarkdown(markdown)}</div>
                    ) : (
                      <EmptyInline title="Preview not generated" detail="Generate a Markdown preview or select an available report card." />
                    )}
                  </div>
                  <ComparePanel
                    previousRuns={previousRuns}
                    compareRunId={compareRunId}
                    comparison={comparison}
                    loading={loadingComparison}
                    onCompare={handleCompare}
                  />
                </div>
              </div>
            ) : (
              <EmptyInline title="Select a report" detail="Choose a report card to open preview actions." />
            )}
          </div>
        </div>
      ) : (
        <DossierTab
          engagement={selectedEngagement}
          selectedRunId={selectedRunId}
          runs={timelineRuns}
          fallback="Repo truth: /api/v1/engagements/{engId}/dossier is not implemented in the current backend. This tab uses real engagement and run timeline data from existing APIs instead."
          selectRun={selectRun}
          refreshRuns={handleRefreshRuns}
        />
      )}
    </section>
  );
}

function ReportChartStrip({ report, run }: { report: RunReportCatalogItem; run: Run | null }) {
  const readinessData = [
    { label: 'Preview', value: report.preview_allowed ? 1 : 0, color: report.preview_allowed ? '#5ecfff' : '#475569' },
    { label: 'Export', value: report.export_allowed ? 1 : 0, color: report.export_allowed ? '#34d399' : '#475569' },
    { label: 'Draft', value: report.draft_allowed ? 1 : 0, color: report.draft_allowed ? '#d06bff' : '#475569' },
  ];
  const severityData = ['critical', 'high', 'medium', 'low'].map((severity) => ({
    label: severity[0].toUpperCase() + severity.slice(1),
    value: run?.findings.findings_by_severity?.[severity] ?? 0,
    color: severityColor(severity),
  }));

  return (
    <div className="grid gap-3 border-b border-border p-4 lg:grid-cols-2">
      <div className="rounded-lg border border-border bg-bg/25 p-3">
        <div className="mb-3 flex items-center justify-between gap-2">
          <h3 className="text-[0.925rem] font-semibold text-text">Report Readiness</h3>
          <span className="text-[0.77rem] font-bold uppercase text-muted">{report.availability_label}</span>
        </div>
        <div className="h-[150px]">
          <ResponsiveContainer width="100%" height="100%">
            <ReBarChart data={readinessData} margin={{ left: -22, right: 6, top: 4, bottom: 0 }}>
              <CartesianGrid stroke="rgba(142,191,228,0.1)" vertical={false} />
              <XAxis dataKey="label" stroke="#8ebfe4" tickLine={false} axisLine={false} tick={{ fontSize: 11 }} />
              <YAxis allowDecimals={false} domain={[0, 1]} hide />
              <Tooltip content={<ReportTooltip valueLabel="Ready" booleanValue />} />
              <Bar dataKey="value" radius={[6, 6, 0, 0]}>
                {readinessData.map((entry) => <Cell key={entry.label} fill={entry.color} />)}
              </Bar>
            </ReBarChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="rounded-lg border border-border bg-bg/25 p-3">
        <div className="mb-3 flex items-center justify-between gap-2">
          <h3 className="text-[0.925rem] font-semibold text-text">Severity Summary</h3>
          <span className="text-[0.77rem] font-bold uppercase text-muted">Run findings</span>
        </div>
        <div className="h-[150px]">
          <ResponsiveContainer width="100%" height="100%">
            <ReBarChart data={severityData} margin={{ left: -18, right: 6, top: 4, bottom: 0 }}>
              <CartesianGrid stroke="rgba(142,191,228,0.1)" vertical={false} />
              <XAxis dataKey="label" stroke="#8ebfe4" tickLine={false} axisLine={false} tick={{ fontSize: 11 }} />
              <YAxis allowDecimals={false} stroke="#8ebfe4" tickLine={false} axisLine={false} tick={{ fontSize: 11 }} />
              <Tooltip content={<ReportTooltip valueLabel="Findings" />} />
              <Bar dataKey="value" radius={[6, 6, 0, 0]}>
                {severityData.map((entry) => <Cell key={entry.label} fill={entry.color} />)}
              </Bar>
            </ReBarChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
}

function ReportTooltip({
  active,
  payload,
  label,
  valueLabel,
  booleanValue = false,
}: {
  active?: boolean;
  payload?: Array<{ value?: number }>;
  label?: string;
  valueLabel: string;
  booleanValue?: boolean;
}) {
  if (!active || !payload?.length) return null;
  const value = payload[0]?.value ?? 0;
  return (
    <div className="rounded-md border border-cyan/25 bg-[#06101d]/95 px-3 py-2 shadow-[0_0_1rem_rgba(94,207,255,0.16)]">
      <div className="text-[0.8rem] font-bold uppercase text-cyan">{label}</div>
      <div className="text-[0.9rem] text-text">{valueLabel}: {booleanValue ? (value ? 'Yes' : 'No') : value}</div>
    </div>
  );
}

function severityColor(severity: string): string {
  if (severity === 'critical') return '#ef4444';
  if (severity === 'high') return '#f59e0b';
  if (severity === 'medium') return '#fde047';
  if (severity === 'low') return '#5ecfff';
  return '#8ebfe4';
}

function TabButton({ active, onClick, icon, children }: { active: boolean; onClick: () => void; icon: ReactNode; children: ReactNode }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={cn(
        'inline-flex items-center gap-2 rounded-md px-3 py-2 text-[1rem] font-semibold transition-colors',
        active ? 'bg-cyan/10 text-cyan' : 'text-muted hover:bg-bg/40 hover:text-text',
      )}
    >
      {icon}
      {children}
    </button>
  );
}

function RunStrip({
  selectedRun,
  runs,
  selectedRunId,
  selectRun,
}: {
  selectedRun: Run | null;
  runs: Run[];
  selectedRunId: UUID | null;
  selectRun: (runId: UUID | null) => void;
}) {
  return (
    <div className="border-b border-border bg-[rgba(5,9,18,0.72)] p-4">
      <label className="block">
        <span className="mb-1 block text-[0.85rem] font-bold uppercase text-muted">Selected Run</span>
        <select
          aria-label="Report Center selected run"
          value={selectedRunId ?? ''}
          onChange={(event) => selectRun(event.target.value || null)}
          className="h-10 w-full rounded-lg border border-border bg-surface px-3 text-[1rem] text-text outline-none focus:border-cyan/50"
        >
          {runs.map((run) => (
            <option key={run.id} value={run.id} className="bg-surface text-text">
              {reportRunLabel(run)}
            </option>
          ))}
        </select>
      </label>
      <div className="mt-3 grid gap-2 sm:grid-cols-3">
        <MiniMetric label="Profile" value={selectedRun?.profile.name ?? 'Unknown'} />
        <MiniMetric label="Created" value={selectedRun ? formatDate(selectedRun.created_at) : 'Unknown'} />
        <MiniMetric label="Status" value={selectedRun?.status ?? 'Unknown'} />
      </div>
    </div>
  );
}

function MiniMetric({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-md border border-border bg-bg/30 px-3 py-2">
      <div className="text-[0.77rem] font-bold uppercase text-muted">{label}</div>
      <div className="truncate text-[0.925rem] font-semibold text-text">{value}</div>
    </div>
  );
}

function ReportCard({ report, selected, onClick }: { report: RunReportCatalogItem; selected: boolean; onClick: () => void }) {
  const Icon = reportIcon(report.variant);
  return (
    <button
      type="button"
      onClick={onClick}
      className={cn(
        'w-full rounded-lg border p-4 text-left transition-all',
        selected ? 'border-cyan/50 bg-cyan/10 shadow-[0_0_18px_rgba(94,207,255,0.1)]' : 'border-border bg-bg/25 hover:border-cyan/30 hover:bg-cyan/5',
      )}
    >
      <div className="mb-3 flex items-start justify-between gap-3">
        <div className="flex min-w-0 items-center gap-3">
          <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-cyan/20 bg-cyan/10 text-cyan">
            <Icon size={18} />
          </div>
          <div className="min-w-0">
            <div className="truncate text-[1.08rem] font-semibold text-text">{report.title}</div>
            <div className="text-[0.85rem] font-semibold uppercase text-muted">{report.variant}</div>
          </div>
        </div>
        <AvailabilityBadge report={report} />
      </div>
      <p className="line-clamp-3 text-[0.925rem] leading-5 text-muted">{report.description}</p>
    </button>
  );
}

function ReportPreviewHeader({ report, run }: { report: RunReportCatalogItem; run: Run | null }) {
  const profileLabel =
    typeof report.source_scope_profile.run_profile === 'string' && report.source_scope_profile.run_profile.trim()
      ? report.source_scope_profile.run_profile
      : run?.profile.name ?? 'Selected run';
  return (
    <header className="border-b border-border bg-[rgba(5,9,18,0.78)] p-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="mb-2 flex flex-wrap items-center gap-2">
            <AvailabilityBadge report={report} />
            <span className="rounded-full border border-border bg-bg/40 px-2 py-0.5 text-[0.77rem] font-semibold text-muted">
              {report.version_label}
            </span>
          </div>
          <h2 className="break-words text-lg font-semibold text-text">{report.title}</h2>
          <p className="mt-1 text-[0.925rem] text-muted">
            {profileLabel} · generated {formatDate(report.generated_at)}
          </p>
        </div>
      </div>
      <p className="mt-3 text-[0.925rem] leading-5 text-muted">{report.availability_reason}</p>
    </header>
  );
}

function ActionButton({ onClick, loading, icon, children }: { onClick: () => void; loading: boolean; icon: ReactNode; children: ReactNode }) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={loading}
      className="inline-flex items-center gap-2 rounded-md border border-cyan/30 bg-cyan/10 px-3 py-2 text-[1rem] font-semibold text-cyan disabled:opacity-50"
    >
      {loading ? <Loader2 size={14} className="animate-spin" /> : icon}
      {children}
    </button>
  );
}

function EvidenceHash({ report }: { report: RunReportCatalogItem }) {
  return (
    <details className="rounded-lg border border-border bg-bg/30 p-3">
      <summary className="flex cursor-pointer list-none items-center justify-between gap-3 text-[0.925rem] font-semibold text-text">
        <span className="flex items-center gap-2">
          <Check size={14} className="text-green" />
          Evidence hash: verified
        </span>
        <ChevronDown size={14} className="text-muted" />
      </summary>
      <div className="mt-3 flex items-start gap-2 text-[0.925rem] text-muted">
        <Hash size={14} className="mt-0.5 text-cyan" />
        <span className="break-all font-mono text-text">{report.content_sha256}</span>
      </div>
    </details>
  );
}

function ComparePanel({
  previousRuns,
  compareRunId,
  comparison,
  loading,
  onCompare,
}: {
  previousRuns: Run[];
  compareRunId: UUID | '';
  comparison: ComparisonSummary | null;
  loading: boolean;
  onCompare: (runId: UUID | '') => void;
}) {
  return (
    <section className="mt-4 rounded-lg border border-border bg-bg/25 p-4">
      <div className="mb-3 flex items-center gap-2 text-[0.925rem] font-bold uppercase text-text">
        <BarChart3 size={14} />
        Compare with Earlier Run
      </div>
      <select
        aria-label="Compare with earlier run"
        value={compareRunId}
        onChange={(event) => onCompare(event.target.value as UUID | '')}
        className="h-10 w-full rounded-lg border border-border bg-surface px-3 text-[1rem] text-text outline-none focus:border-cyan/50"
      >
        <option value="" className="bg-surface text-text">Select earlier run</option>
        {previousRuns.map((run) => (
          <option key={run.id} value={run.id} className="bg-surface text-text">
            {reportRunLabel(run)}
          </option>
        ))}
      </select>
      {loading && <div className="mt-3 flex items-center gap-2 text-[0.925rem] text-cyan"><Loader2 size={14} className="animate-spin" /> Comparing stored findings</div>}
      {comparison && (
        <div className="mt-3 grid gap-2 sm:grid-cols-3">
          <MiniMetric label="New findings" value={String(comparison.newFindings)} />
          <MiniMetric label="Resolved findings" value={String(comparison.resolvedFindings)} />
          <MiniMetric label="Unchanged findings" value={String(comparison.unchangedFindings)} />
        </div>
      )}
      {!loading && previousRuns.length === 0 && (
        <p className="mt-3 text-[0.925rem] text-muted">No earlier runs exist for this engagement yet.</p>
      )}
    </section>
  );
}

function DossierTab({
  engagement,
  selectedRunId,
  runs,
  fallback,
  selectRun,
  refreshRuns,
}: {
  engagement: Engagement | null;
  selectedRunId: UUID | null;
  runs: Run[];
  fallback: string | null;
  selectRun: (runId: UUID | null) => void;
  refreshRuns: () => Promise<void>;
}) {
  return (
    <div className="min-h-0 flex-1 overflow-hidden rounded-xl border border-border bg-surface/55 backdrop-blur-md">
      <div className="flex flex-wrap items-start justify-between gap-4 border-b border-border bg-[rgba(5,9,18,0.72)] p-4">
        <div>
          <h2 className="text-lg font-semibold text-text">{engagement?.name ?? 'Engagement Dossier'}</h2>
          <p className="mt-1 text-[1rem] text-muted">{engagement?.client || 'Client not recorded'} · {runs.length} runs</p>
          {fallback && <p className="mt-2 max-w-3xl text-[0.925rem] leading-5 text-amber">{fallback}</p>}
        </div>
        <button
          type="button"
          onClick={() => void refreshRuns()}
          className="rounded-md border border-cyan/30 bg-cyan/10 px-3 py-2 text-[1rem] font-semibold text-cyan"
        >
          Refresh Timeline
        </button>
      </div>
      <div className="min-h-0 overflow-y-auto p-4">
        {runs.length === 0 ? (
          <EmptyInline title="No run history" detail="Create a run to build this engagement timeline." />
        ) : (
          <div className="space-y-3">
            {runs.map((run) => (
              <Link
                key={run.id}
                to="/mission-control"
                onClick={() => selectRun(run.id)}
                className={cn(
                  'grid gap-3 rounded-lg border p-4 transition-all md:grid-cols-[1fr_auto]',
                  run.id === selectedRunId ? 'border-cyan/50 bg-cyan/10' : 'border-border bg-bg/25 hover:border-cyan/30 hover:bg-cyan/5',
                )}
              >
                <div className="min-w-0">
                  <div className="mb-2 flex flex-wrap items-center gap-2">
                    <span className="rounded-full border border-border bg-bg/40 px-2 py-0.5 text-[0.77rem] font-semibold uppercase text-muted">{run.status}</span>
                    <span className="text-[0.85rem] text-muted">{formatDate(run.created_at)}</span>
                  </div>
                  <div className="truncate text-[1.08rem] font-semibold text-text">{run.profile.name}</div>
                  <div className="mt-1 truncate text-[0.925rem] text-muted">{run.id}</div>
                </div>
                <div className="grid grid-cols-3 gap-2 text-right">
                  <MiniMetric label="Findings" value={String(run.findings.finding_count)} />
                  <MiniMetric label="Open" value={String(run.findings.findings_by_status.open ?? 0)} />
                  <MiniMetric label="High+" value={String((run.findings.findings_by_severity.high ?? 0) + (run.findings.findings_by_severity.critical ?? 0))} />
                </div>
              </Link>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function AvailabilityBadge({ report }: { report: RunReportCatalogItem }) {
  return (
    <span className={cn('shrink-0 rounded-full border px-2 py-0.5 text-[0.77rem] font-bold uppercase', availabilityClass(report.availability_status))}>
      {report.availability_label || report.availability_status}
    </span>
  );
}

function LoadingPanel({ label }: { label: string }) {
  return (
    <div className="flex h-full min-h-[260px] items-center justify-center rounded-lg border border-border bg-bg/20 text-[1rem] text-muted">
      <Loader2 size={16} className="mr-2 animate-spin text-cyan" />
      {label}
    </div>
  );
}

function EmptyState({ title, detail, action }: { title: string; detail: string; action?: ReactNode }) {
  return (
    <section className="flex h-full min-h-[520px] items-center justify-center">
      <div className="max-w-md rounded-xl border border-border bg-surface/60 p-6 text-center">
        <FileText size={28} className="mx-auto mb-3 text-cyan" />
        <h1 className="text-xl font-semibold text-text">{title}</h1>
        <p className="mt-2 text-[1rem] leading-6 text-muted">{detail}</p>
        {action && <div className="mt-4">{action}</div>}
      </div>
    </section>
  );
}

function EmptyInline({ title, detail }: { title: string; detail: string }) {
  return (
    <div className="rounded-lg border border-border bg-bg/25 p-6 text-center">
      <h2 className="text-[1.15rem] font-semibold text-text">{title}</h2>
      <p className="mt-2 text-[1rem] text-muted">{detail}</p>
    </div>
  );
}

function renderMarkdown(markdown: string): ReactNode[] {
  const nodes: ReactNode[] = [];
  const lines = markdown.split(/\r?\n/);
  let codeLines: string[] = [];
  let listItems: string[] = [];
  let inCode = false;

  function flushList(key: string) {
    if (!listItems.length) return;
    nodes.push(
      <ul key={`list-${key}`} className="my-3 list-disc space-y-1 pl-5 text-[1rem] leading-6 text-muted">
        {listItems.map((item, index) => (
          <li key={`${key}-${index}`}>{renderInline(item)}</li>
        ))}
      </ul>,
    );
    listItems = [];
  }

  function flushCode(key: string) {
    nodes.push(
      <pre key={`code-${key}`} className="my-3 overflow-auto rounded-md border border-border bg-[#030712] p-3 font-mono text-[0.925rem] leading-5 text-text">
        {codeLines.join('\n')}
      </pre>,
    );
    codeLines = [];
  }

  lines.forEach((line, index) => {
    if (line.startsWith('```')) {
      if (inCode) {
        flushCode(String(index));
        inCode = false;
      } else {
        flushList(String(index));
        inCode = true;
      }
      return;
    }
    if (inCode) {
      codeLines.push(line);
      return;
    }
    if (line.startsWith('- ')) {
      listItems.push(line.slice(2));
      return;
    }
    flushList(String(index));
    if (!line.trim()) return;
    if (line.startsWith('# ')) {
      nodes.push(<h1 key={index} className="mb-3 text-xl font-semibold text-text">{renderInline(line.slice(2))}</h1>);
    } else if (line.startsWith('## ')) {
      nodes.push(<h2 key={index} className="mb-2 mt-4 text-lg font-semibold text-text">{renderInline(line.slice(3))}</h2>);
    } else if (line.startsWith('### ')) {
      nodes.push(<h3 key={index} className="mb-2 mt-3 text-[1.15rem] font-semibold text-text">{renderInline(line.slice(4))}</h3>);
    } else {
      nodes.push(<p key={index} className="mb-2 text-[1rem] leading-6 text-muted">{renderInline(line)}</p>);
    }
  });
  if (inCode) flushCode('tail');
  flushList('tail');
  return nodes;
}

function renderInline(value: string): ReactNode[] {
  const parts = value.split(/(\*\*[^*]+\*\*)/g);
  return parts.map((part, index) => {
    if (part.startsWith('**') && part.endsWith('**')) {
      return <strong key={index} className="font-semibold text-text">{part.slice(2, -2)}</strong>;
    }
    return <span key={index}>{part}</span>;
  });
}

type ComparisonSummary = {
  newFindings: number;
  resolvedFindings: number;
  unchangedFindings: number;
};

function compareFindings(current: Finding[], previous: Finding[]): ComparisonSummary {
  const currentKeys = new Set(current.map(findingKey));
  const previousKeys = new Set(previous.map(findingKey));
  let newFindings = 0;
  let resolvedFindings = 0;
  let unchangedFindings = 0;
  for (const key of currentKeys) {
    if (previousKeys.has(key)) unchangedFindings += 1;
    else newFindings += 1;
  }
  for (const key of previousKeys) {
    if (!currentKeys.has(key)) resolvedFindings += 1;
  }
  return { newFindings, resolvedFindings, unchangedFindings };
}

function findingKey(finding: Finding): string {
  return `${finding.title.toLowerCase()}|${finding.target_id.toLowerCase()}|${finding.severity.toLowerCase()}`;
}

function reportGroupKey(run: Run): string {
  const chainId = typeof run.assessment_chain?.id === 'string' ? run.assessment_chain.id : '';
  return chainId ? `chain:${chainId}` : `run:${run.id}`;
}

function sameReportGroup(left: Run, right: Run): boolean {
  return reportGroupKey(left) === reportGroupKey(right);
}

function reportRunOptions(runs: Run[], selectedRun: Run | null): Run[] {
  const grouped = new Map<string, Run>();
  for (const run of runs) {
    const key = reportGroupKey(run);
    const existing = grouped.get(key);
    if (!existing) {
      grouped.set(key, run);
      continue;
    }
    if (selectedRun && sameReportGroup(run, selectedRun) && run.id === selectedRun.id) {
      grouped.set(key, run);
      continue;
    }
    if (!selectedRun || !sameReportGroup(existing, selectedRun)) {
      grouped.set(key, newerRun(existing, run));
    }
  }
  return [...grouped.values()].sort(sortRunsDescending);
}

function newerRun(left: Run, right: Run): Run {
  return new Date(right.created_at).getTime() > new Date(left.created_at).getTime() ? right : left;
}

function reportRunLabel(run: Run): string {
  const chainId = typeof run.assessment_chain?.id === 'string' ? run.assessment_chain.id : '';
  if (!chainId) return `${run.profile.name} · ${formatDate(run.created_at)} · ${run.status}`;
  const mode = typeof run.assessment_chain?.assessment_mode === 'string'
    ? run.assessment_chain.assessment_mode
    : 'assessment-chain';
  const status = typeof run.assessment_chain?.status === 'string' ? run.assessment_chain.status : run.status;
  return `${humanizeLabel(mode)} · ${formatDate(run.created_at)} · ${status}`;
}

function humanizeLabel(value: string): string {
  return value
    .replace(/[_-]+/g, ' ')
    .trim()
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function earlierRuns(runs: Run[], selectedRun: Run | null): Run[] {
  if (!selectedRun) return [];
  const selectedTime = new Date(selectedRun.created_at).getTime();
  return runs
    .filter((run) => run.id !== selectedRun.id && new Date(run.created_at).getTime() <= selectedTime)
    .sort(sortRunsDescending);
}

function sortRunsDescending(a: Run, b: Run): number {
  return new Date(b.created_at).getTime() - new Date(a.created_at).getTime();
}

function reportIcon(variant: string) {
  if (variant.includes('compliance') || ['soc2', 'iso27001', 'pci_dss', 'nis2', 'dora'].includes(variant)) return Shield;
  if (variant.includes('summary') || variant.includes('executive')) return BarChart3;
  return FileText;
}

function availabilityClass(status: string): string {
  if (status === 'export_ready') return 'border-green/30 bg-green/10 text-green';
  if (status === 'generating' || status === 'draft_only') return 'border-amber/30 bg-amber/10 text-amber';
  return 'border-border bg-bg/40 text-muted';
}

function formatDate(value: string): string {
  return new Intl.DateTimeFormat(undefined, {
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  }).format(new Date(value));
}

function triggerDownload(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

function errorMessage(error: unknown): string {
  if (error instanceof ApiError) {
    if (typeof error.detail === 'string' && error.detail.trim()) return error.detail;
    return error.message;
  }
  if (error instanceof Error) return error.message;
  return 'AegisPT API request failed.';
}
