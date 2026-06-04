import { useEffect, useMemo, useState } from 'react';
import type { ReactNode } from 'react';
import {
  AlertTriangle,
  ArrowRight,
  BarChart3,
  Check,
  CheckCircle2,
  ChevronDown,
  Database,
  Download,
  Eye,
  FileCheck2,
  FileText,
  GitBranch,
  Hash,
  History,
  Layers3,
  ListChecks,
  Loader2,
  PackageCheck,
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
  getRunBriefing,
  getRunReportMarkdown,
  getRunReports,
  getRunsForEngagement,
} from '../../api/client';
import type { Engagement, Finding, Run, RunReportCatalogItem, UUID } from '../../api/types';
import { useAegisStore } from '../../store';
import {
  buildCrossSurfaceConsistency,
  type CrossSurfaceCheck,
  type CrossSurfaceConsistencyModel,
  type CrossSurfaceOverallStatus,
} from '../../viewModels/crossSurfaceConsistency';
import {
  buildManagementReportProof,
  type ManagementReportRouteStep,
  type ManagementReportStandardBadge,
} from '../../viewModels/managementReportProof';
import {
  buildReportTruth,
  countStatusLabel,
  countStatusTone,
  stageDetailCopy,
  type ReportStage,
  type ReportTruthModel,
} from '../../viewModels/reportTruth';
import { safeErrorMessage, safeProviderText } from '../../viewModels/safeMessaging';

type ReportTab = 'reports' | 'dossier';
type ReportAction = 'preview' | 'html' | 'pdf' | null;

const SAFE_BRIEFING_FALLBACK =
  'Executive briefing is using canonical report facts right now. AI wording is unavailable, but the evidence, findings, and export checks below remain usable.';

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
  const [briefing, setBriefing] = useState<string | null>(null);
  const [loadingBriefing, setLoadingBriefing] = useState(false);
  const [reportFindings, setReportFindings] = useState<Finding[]>([]);
  const [loadingFindings, setLoadingFindings] = useState(false);
  const [selectedStage, setSelectedStage] = useState<ReportStage>('findings');

  const selectedReport = catalog.find((report) => report.variant === selectedVariant) ?? catalog[0] ?? null;
  const reportRuns = useMemo(() => reportRunOptions(runs, selectedRun), [runs, selectedRun]);
  const selectedReportRun = useMemo(
    () => reportRuns.find((run) => selectedRun !== null && sameReportGroup(run, selectedRun)) ?? selectedRun,
    [reportRuns, selectedRun],
  );
  const activeReportRunId = selectedReportRun?.id ?? selectedRunId;
  const reportTruth = useMemo(
    () => buildReportTruth(selectedReport, reportFindings, loadingFindings),
    [selectedReport, reportFindings, loadingFindings],
  );
  const crossSurfaceConsistency = useMemo(
    () =>
      buildCrossSurfaceConsistency({
        run: selectedReportRun,
        findings: reportFindings,
        reports: catalog,
        selectedReport,
        markdownPreview: markdown,
        loadingFindings,
        loadingReports: loadingCatalog,
      }),
    [catalog, loadingCatalog, loadingFindings, markdown, reportFindings, selectedReport, selectedReportRun],
  );
  const previousRuns = useMemo(() => earlierRuns(reportRuns, selectedReportRun), [reportRuns, selectedReportRun]);
  const timelineRuns = useMemo(() => [...runs].sort(sortRunsDescending), [runs]);

  useEffect(() => {
    if (!activeReportRunId) {
      setCatalog([]);
      setSelectedVariant(null);
      setMarkdown(null);
      setBriefing(null);
      return;
    }

    setBriefing(null);
    setLoadingBriefing(true);
    getRunBriefing(activeReportRunId)
      .then((payload) => {
        if (typeof payload.briefing === 'string') setBriefing(safeProviderText(payload.briefing, SAFE_BRIEFING_FALLBACK));
      })
      .catch(() => undefined)
      .finally(() => setLoadingBriefing(false));

    const runId = activeReportRunId;
    let cancelled = false;
    async function loadCatalog() {
      setLoadingCatalog(true);
      setMessage(null);
      setError(null);
      try {
        const payload = await getRunReports(runId);
        if (cancelled) return;
        setCatalog(payload);
        setSelectedVariant((current) =>
          payload.some((report) => report.variant === current) ? current : payload[0]?.variant ?? null,
        );
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
  }, [activeReportRunId, setError]);

  useEffect(() => {
    const runForFindings = selectedReportRun ?? selectedRun;
    if (!runForFindings) {
      setReportFindings([]);
      setLoadingFindings(false);
      return;
    }
    const runContext = runForFindings;
    let cancelled = false;
    async function loadFindings() {
      setLoadingFindings(true);
      try {
        const payload = await getFindingsForRunContext(runContext);
        if (!cancelled) setReportFindings(payload);
      } catch (error) {
        if (!cancelled) {
          setReportFindings([]);
          setMessage(errorMessage(error));
        }
      } finally {
        if (!cancelled) setLoadingFindings(false);
      }
    }
    void loadFindings();
    return () => {
      cancelled = true;
    };
  }, [selectedReportRun, selectedRun]);

  useEffect(() => {
    setComparison(null);
    setCompareRunId('');
  }, [selectedRunId]);

  async function selectReport(report: RunReportCatalogItem) {
    setSelectedVariant(report.variant);
    setMessage(null);
    if (activeReportRunId && report.preview_allowed) {
      await loadMarkdownPreview(activeReportRunId, report.variant);
    } else {
      setMarkdown(null);
      setMessage(report.availability_reason || 'Preview is not available for this report.');
    }
  }

  async function handleGeneratePreview() {
    if (!activeReportRunId || !selectedReport) return;
    if (!selectedReport.preview_allowed) {
      setMessage(selectedReport.availability_reason || 'Preview is not available for this report.');
      return;
    }
    await loadMarkdownPreview(activeReportRunId, selectedReport.variant);
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

  async function handleDownloadNlPdf() {
    if (!activeReportRunId) return;
    setAction('pdf');
    setMessage('PDF wordt aangemaakt — grafieken en tabellen worden gegenereerd...');
    try {
      const blob = await downloadRunReport(activeReportRunId, 'management_nl', 'pdf');
      triggerDownload(blob, `aegispt-management-rapport-${activeReportRunId.slice(0, 8)}.pdf`);
      setMessage('PDF management rapport gedownload.');
    } catch (error) {
      setMessage(`PDF genereren mislukt: ${errorMessage(error)}`);
    } finally {
      setAction(null);
    }
  }

  async function handleDownloadNl() {
    if (!activeReportRunId) return;
    setAction('preview');
    setMessage('Nederlands management rapport wordt gegenereerd...');
    try {
      const text = await getRunReportMarkdown(activeReportRunId, 'management_nl');
      const blob = new Blob([text], { type: 'text/markdown' });
      triggerDownload(blob, `aegispt-management-rapport-nl-${activeReportRunId.slice(0, 8)}.md`);
      setMessage('Nederlands management rapport gedownload.');
    } catch (error) {
      setMessage(`Rapport genereren mislukt: ${errorMessage(error)}`);
    } finally {
      setAction(null);
    }
  }

  async function handleDownload(format: 'html' | 'pdf') {
    if (!activeReportRunId || !selectedReport) return;
    if (!selectedReport.export_allowed) {
      setMessage(selectedReport.availability_reason || `${format.toUpperCase()} download is not available for this report.`);
      return;
    }
    setAction(format);
    setMessage(null);
    try {
      const blob = await downloadRunReport(activeReportRunId, selectedReport.variant, format);
      const filename =
        selectedReport.download_names[format] ?? `aegispt-run-${activeReportRunId}-${selectedReport.variant}.${format}`;
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

      {/* AI Executive Briefing — shown when available */}
      {(briefing || loadingBriefing) && activeTab === 'reports' && (
        <div className="mb-4 rounded border border-line-soft bg-surface px-4 py-3">
          <div className="mb-1 flex items-center gap-2">
            <Shield size={12} className="text-ai shrink-0" />
            <span className="font-mono text-[0.62rem] font-semibold uppercase tracking-widest text-ai/70">
              AI · EXECUTIVE BRIEFING
            </span>
          </div>
          {loadingBriefing ? (
            <div className="flex items-center gap-2 text-[0.82rem] text-muted">
              <Loader2 size={12} className="animate-spin" />
              Generating briefing…
            </div>
          ) : (
            <p className="text-[0.9rem] font-medium leading-relaxed text-text">{briefing}</p>
          )}
        </div>
      )}

      {activeTab === 'reports' ? (
        <div className="min-h-0 flex-1 overflow-y-auto pr-1">
          <div className="grid gap-5 2xl:grid-cols-[minmax(0,1fr)_430px]">
            <div className="min-w-0 space-y-5">
              {selectedReport ? (
                <>
                  <ReportPackagePanel
                    report={selectedReport}
                    run={selectedReportRun}
                    truth={reportTruth}
                    selectedStage={selectedStage}
                    onSelectStage={setSelectedStage}
                  />
                  <ManagementReportProofPanel
                    report={selectedReport}
                    run={selectedReportRun}
                    truth={reportTruth}
                    findings={reportFindings}
                  />
                  <CrossSurfaceConsistencyPanel consistency={crossSurfaceConsistency} />
                  <div className="grid gap-5 xl:grid-cols-[0.95fr_1.05fr]">
                    <ReportChartStrip report={selectedReport} truth={reportTruth} />
                    <ScopeInclusionPanel report={selectedReport} truth={reportTruth} />
                  </div>
                  <ReportPreviewPanel markdown={markdown} />
                </>
              ) : loadingCatalog ? (
                <LoadingPanel label="Loading report catalog from API" />
              ) : (
                <EmptyInline title="No reports available" detail="The backend did not return report catalog entries for this run." />
              )}
            </div>

            <aside className="min-w-0 space-y-5">
              <RunStrip selectedRun={selectedReportRun} runs={reportRuns} selectedRunId={selectedReportRun?.id ?? selectedRunId} selectRun={selectRun} />
              <ReportVariantPanel
                catalog={catalog}
                selectedReport={selectedReport}
                loading={loadingCatalog}
                onSelect={(report) => void selectReport(report)}
              />
              {selectedReport && (
                <>
                  <ReportActionsPanel
                    action={action}
                    message={message}
                    onPreview={handleGeneratePreview}
                    onDownloadHtml={() => void handleDownload('html')}
                    onDownloadPdf={() => void handleDownload('pdf')}
                    onDownloadNlPdf={() => void handleDownloadNlPdf()}
                    onDownloadNlMarkdown={() => void handleDownloadNl()}
                  />
                  <EvidenceHash report={selectedReport} />
                  <ComparePanel
                    previousRuns={previousRuns}
                    compareRunId={compareRunId}
                    comparison={comparison}
                    loading={loadingComparison}
                    onCompare={handleCompare}
                  />
                </>
              )}
            </aside>
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

function ManagementReportProofPanel({
  report,
  run,
  truth,
  findings,
}: {
  report: RunReportCatalogItem;
  run: Run | null;
  truth: ReportTruthModel;
  findings: Finding[];
}) {
  const proof = useMemo(
    () => buildManagementReportProof(report, truth, findings, run),
    [findings, report, run, truth],
  );

  return (
    <section
      className="neon-panel rounded-lg border border-cyan/20 p-4 backdrop-blur-md"
      aria-label="Management report export proof"
    >
      <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="mb-2 flex items-center gap-2 text-cyan">
            <Shield size={16} />
            <span className="text-[0.72rem] font-bold uppercase tracking-[0.18em]">Management proof</span>
          </div>
          <h2 className="text-[1.15rem] font-semibold text-text">Built from evidence, standards, and the same attack route</h2>
          <p className="mt-1 max-w-4xl text-[0.92rem] leading-5 text-muted">{proof.storyHeadline}</p>
        </div>
        <StatusPill tone={proof.isManagementReady ? 'green' : 'amber'}>{proof.exportReadiness}</StatusPill>
      </div>

      <div className="grid gap-3 xl:grid-cols-[1.25fr_0.9fr]">
        <div className="theme-surface-card rounded-lg border p-3">
          <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
            <div>
              <h3 className="text-[0.98rem] font-semibold text-text">Attack map preview</h3>
              <p className="mt-0.5 text-[0.82rem] text-muted">What was tested, in management language.</p>
            </div>
            <StatusPill tone="cyan">{truth.canonicalTotal} canonical</StatusPill>
          </div>
          <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3 2xl:grid-cols-5">
            {proof.route.map((step, index) => (
              <ManagementRouteNode key={step.key} step={step} index={index} />
            ))}
          </div>
        </div>

        <div className="theme-surface-card rounded-lg border p-3">
          <div className="mb-3 flex items-center justify-between gap-2">
            <h3 className="text-[0.98rem] font-semibold text-text">Standards badges</h3>
            <span className="text-[0.72rem] font-bold uppercase tracking-[0.16em] text-muted">not certification</span>
          </div>
          <div className="grid gap-2 sm:grid-cols-2">
            {proof.standards.map((standard) => (
              <StandardBadgeCard key={standard.badge} standard={standard} />
            ))}
          </div>
        </div>
      </div>

      <div className="mt-3 grid gap-3 xl:grid-cols-[0.9fr_1.1fr]">
        <div className="rounded-lg border border-border bg-bg/25 p-3">
          <div className="mb-2 flex items-center gap-2 text-cyan">
            <ListChecks size={15} />
            <h3 className="text-[0.98rem] font-semibold text-text">Techniques in plain language</h3>
          </div>
          <div className="grid gap-2">
            {proof.techniques.map((technique) => (
              <div key={technique.label} className="theme-subcard rounded-md border px-3 py-2">
                <div className="text-[0.92rem] font-semibold text-text">{technique.label}</div>
                <div className="mt-0.5 text-[0.82rem] leading-4 text-muted">{technique.plain}</div>
                <div className="mt-1 truncate text-[0.72rem] font-bold uppercase tracking-[0.12em] text-cyan/80">{technique.basis}</div>
              </div>
            ))}
          </div>
        </div>

        <div className="rounded-lg border border-border bg-bg/25 p-3">
          <div className="mb-2 flex items-center gap-2 text-cyan">
            <PackageCheck size={15} />
            <h3 className="text-[0.98rem] font-semibold text-text">What IT and Engineering should do</h3>
          </div>
          <div className="grid gap-2 lg:grid-cols-3">
            {proof.actions.map((action) => (
              <div key={action.owner} className="theme-subcard rounded-md border px-3 py-2">
                <div className="text-[0.72rem] font-bold uppercase tracking-[0.16em] text-cyan">{action.owner}</div>
                <div className="mt-1 text-[0.88rem] leading-4 text-text">{action.action}</div>
                <div className="mt-2 text-[0.78rem] leading-4 text-muted">{action.doneWhen}</div>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="mt-3 grid gap-2 rounded-lg border border-border/80 bg-bg/20 p-3 md:grid-cols-[0.9fr_1.1fr]">
        <div>
          <div className="text-[0.72rem] font-bold uppercase tracking-[0.16em] text-cyan">Evidence basis</div>
          <p className="mt-1 text-[0.9rem] leading-5 text-muted">{proof.evidenceBasis}</p>
          <p className="mt-1 text-[0.82rem] leading-4 text-muted">Tested scope: {proof.testedScope}</p>
        </div>
        <div>
          <div className="text-[0.72rem] font-bold uppercase tracking-[0.16em] text-amber">Not claimed</div>
          <div className="mt-1 grid gap-1 sm:grid-cols-2">
            {proof.notClaimed.slice(0, 4).map((item) => (
              <CompactFact key={item} text={item} />
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}

function ManagementRouteNode({ step, index }: { step: ManagementReportRouteStep; index: number }) {
  return (
    <div className="relative min-h-[128px] rounded-lg border border-cyan/15 bg-bg/30 px-3 py-2">
      {index > 0 && <div className="absolute -left-2 top-1/2 hidden h-px w-4 bg-cyan/55 2xl:block" />}
      <div className={cn('mb-2 inline-flex h-7 w-7 items-center justify-center rounded-full border text-[0.78rem] font-bold', routeToneClass(step.tone))}>
        {index + 1}
      </div>
      <div className="text-[0.72rem] font-bold uppercase tracking-[0.16em] text-muted">{step.label}</div>
      <div className="mt-1 line-clamp-3 text-[0.9rem] font-semibold leading-4 text-text">{step.detail}</div>
    </div>
  );
}

function StandardBadgeCard({ standard }: { standard: ManagementReportStandardBadge }) {
  return (
    <div className="rounded-md border border-border/80 bg-bg/30 px-3 py-2">
      <div className="mb-1 flex items-center justify-between gap-2">
        <span className="font-mono text-[0.78rem] font-bold text-cyan">{standard.badge}</span>
        <span
          className={cn(
            'rounded-full border px-1.5 py-0.5 text-[0.64rem] font-bold uppercase',
            standard.state === 'used'
              ? 'border-green/25 bg-green/10 text-green'
              : 'border-border bg-bg/40 text-muted',
          )}
        >
          {standard.state === 'used' ? 'used' : 'mapped'}
        </span>
      </div>
      <div className="text-[0.88rem] font-semibold text-text">{standard.label}</div>
      <div className="mt-0.5 text-[0.76rem] leading-4 text-muted">{standard.meaning}</div>
    </div>
  );
}

function ReportPackagePanel({
  report,
  run,
  truth,
  selectedStage,
  onSelectStage,
}: {
  report: RunReportCatalogItem;
  run: Run | null;
  truth: ReportTruthModel;
  selectedStage: ReportStage;
  onSelectStage: (stage: ReportStage) => void;
}) {
  const profileLabel =
    typeof report.source_scope_profile.run_profile === 'string' && report.source_scope_profile.run_profile.trim()
      ? report.source_scope_profile.run_profile
      : run?.profile.name ?? 'Selected run';
  const stages: Array<{ id: ReportStage; label: string; icon: ReactNode; status: string; tone: string }> = [
    { id: 'evidence', label: 'Evidence', icon: <Database size={15} />, status: truth.evidenceVerified ? 'verified' : 'needs review', tone: truth.evidenceVerified ? 'green' : 'amber' },
    { id: 'scope', label: 'Scope', icon: <GitBranch size={15} />, status: `${truth.includedInventory} asset${truth.includedInventory === 1 ? '' : 's'}`, tone: 'cyan' },
    { id: 'findings', label: 'Findings', icon: <ListChecks size={15} />, status: `${truth.canonicalTotal} canonical`, tone: truth.countStatus === 'mismatch' ? 'red' : 'cyan' },
    { id: 'variant', label: 'Variant', icon: <FileText size={15} />, status: report.variant, tone: report.draft_allowed ? 'amber' : 'cyan' },
    { id: 'export', label: 'Export', icon: <FileCheck2 size={15} />, status: report.export_allowed ? 'ready' : 'blocked', tone: report.export_allowed ? 'green' : 'red' },
  ];

  return (
    <section className="neon-panel rounded-lg border border-border bg-surface/55 p-4 backdrop-blur-md">
      <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="mb-2 flex flex-wrap items-center gap-2">
            <AvailabilityBadge report={report} />
            <span className="rounded-full border border-cyan/20 bg-cyan/10 px-2 py-0.5 text-[0.77rem] font-semibold uppercase text-cyan">
              Report package
            </span>
          </div>
          <h2 className="break-words text-xl font-semibold text-text">{report.title}</h2>
          <p className="mt-1 text-[0.925rem] text-muted">
            {profileLabel} · generated {formatDate(report.generated_at)}
          </p>
        </div>
        <div className="grid grid-cols-2 gap-2 text-right sm:grid-cols-3">
          <ReportTruthMetric label="Canonical findings" value={`${truth.canonicalTotal} total`} detail={`${truth.canonicalHighPlus} high+`} />
          <ReportTruthMetric
            label="Included in selected report"
            value={truth.includedTotal === null ? 'listed' : String(truth.includedTotal)}
            detail={countStatusLabel(truth.countStatus)}
          />
          <ReportTruthMetric label="Export" value={report.export_allowed ? 'Ready' : 'Blocked'} detail={report.available_formats.join(' / ') || 'no format'} />
        </div>
      </div>

      <div className="overflow-x-auto pb-1">
        <div className="flex min-w-[760px] items-center gap-2">
          {stages.map((stage, index) => (
            <div key={stage.id} className="flex flex-1 items-center gap-2">
              <ReportStageButton
                active={selectedStage === stage.id}
                stage={stage}
                onClick={() => onSelectStage(stage.id)}
              />
              {index < stages.length - 1 && <ArrowRight size={18} className="shrink-0 text-cyan/60" />}
            </div>
          ))}
        </div>
      </div>

      <StageDetail stage={selectedStage} report={report} truth={truth} />
    </section>
  );
}

function CrossSurfaceConsistencyPanel({ consistency }: { consistency: CrossSurfaceConsistencyModel }) {
  return (
    <section className="neon-panel rounded-lg border border-border bg-surface/55 p-4 backdrop-blur-md" aria-label="Cross-surface truth consistency">
      <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
        <div>
          <div className="mb-2 flex items-center gap-2 text-cyan">
            <Shield size={16} />
            <span className="text-[0.72rem] font-bold uppercase tracking-[0.18em]">Truth consistency</span>
          </div>
          <h2 className="text-[1.08rem] font-semibold text-text">{consistency.headline}</h2>
          <p className="mt-1 max-w-3xl text-[0.925rem] leading-5 text-muted">{consistency.detail}</p>
        </div>
        <StatusPill tone={crossSurfaceTone(consistency.status)}>{crossSurfaceLabel(consistency.status)}</StatusPill>
      </div>

      <div className="grid gap-3 md:grid-cols-4">
        <ConsistencyMetric label="Canonical" value={formatFindingCount(consistency.canonicalTotal)} detail={`${consistency.canonicalHighPlus} high+`} />
        <ConsistencyMetric
          label="Run-local"
          value={consistency.runSummaryTotal === null ? 'not listed' : formatFindingCount(consistency.runSummaryTotal)}
          detail="source summary"
        />
        <ConsistencyMetric
          label="Catalog"
          value={consistency.selectedReportTotal === null ? 'not listed' : formatFindingCount(consistency.selectedReportTotal)}
          detail="selected report"
        />
        <ConsistencyMetric
          label="Evidence"
          value={`${consistency.evidenceLinkedTotal} linked`}
          detail={consistency.previewTotal === null ? 'preview pending' : `preview ${consistency.previewTotal}`}
        />
      </div>

      <div className="mt-3 grid gap-2 lg:grid-cols-4">
        {consistency.checks.map((check) => (
          <ConsistencyCheckCard key={check.id} check={check} />
        ))}
      </div>
    </section>
  );
}

function ConsistencyMetric({ label, value, detail }: { label: string; value: string; detail: string }) {
  return (
    <div className="theme-surface-card rounded-lg border px-3 py-2">
      <div className="text-[0.68rem] font-bold uppercase tracking-[0.16em] text-muted">{label}</div>
      <div className="mt-1 truncate text-[1.02rem] font-semibold text-text">{value}</div>
      <div className="truncate text-[0.8rem] text-muted">{detail}</div>
    </div>
  );
}

function ConsistencyCheckCard({ check }: { check: CrossSurfaceCheck }) {
  const isGood = check.status === 'match';
  const isProblem = check.status === 'mismatch';
  const icon = isGood ? <CheckCircle2 size={14} /> : <AlertTriangle size={14} />;
  return (
    <div
      className={cn(
        'rounded-lg border px-3 py-2',
        isGood
          ? 'border-green/20 bg-green/5'
          : isProblem
            ? 'border-red/25 bg-red/5'
            : 'border-amber/25 bg-amber/5',
      )}
    >
      <div className={cn('mb-1 flex items-center gap-2 text-[0.72rem] font-bold uppercase tracking-[0.14em]', consistencyCheckTone(check.status))}>
        {icon}
        <span>{check.label}</span>
      </div>
      <div className="text-[0.9rem] font-semibold text-text">{check.observed}</div>
      <div className="text-[0.78rem] text-muted">Expected {check.expected}</div>
      <p className="mt-1 text-[0.8rem] leading-4 text-muted">{check.detail}</p>
    </div>
  );
}

function crossSurfaceTone(status: CrossSurfaceOverallStatus): 'cyan' | 'green' | 'amber' | 'red' | 'muted' {
  if (status === 'consistent') return 'green';
  if (status === 'mismatch') return 'red';
  if (status === 'review' || status === 'loading') return 'amber';
  return 'muted';
}

function crossSurfaceLabel(status: CrossSurfaceOverallStatus): string {
  if (status === 'consistent') return 'aligned';
  if (status === 'mismatch') return 'mismatch';
  if (status === 'review') return 'review';
  if (status === 'loading') return 'loading';
  return 'unknown';
}

function consistencyCheckTone(status: CrossSurfaceCheck['status']): string {
  if (status === 'match') return 'text-green';
  if (status === 'mismatch') return 'text-red';
  if (status === 'loading' || status === 'warning') return 'text-amber';
  return 'text-muted';
}

function formatFindingCount(count: number): string {
  return `${count} finding${count === 1 ? '' : 's'}`;
}

function ReportTruthMetric({ label, value, detail }: { label: string; value: string; detail: string }) {
  return (
    <div className="theme-surface-card min-w-[128px] rounded-lg border px-3 py-2">
      <div className="text-[0.68rem] font-bold uppercase tracking-[0.16em] text-muted">{label}</div>
      <div className="mt-1 truncate text-[1.05rem] font-semibold text-text">{value}</div>
      <div className="truncate text-[0.8rem] text-muted">{detail}</div>
    </div>
  );
}

function ReportStageButton({
  stage,
  active,
  onClick,
}: {
  stage: { id: ReportStage; label: string; icon: ReactNode; status: string; tone: string };
  active: boolean;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={cn(
        'group min-h-[92px] flex-1 rounded-lg border p-3 text-left transition-all',
        active
          ? 'border-cyan/60 bg-cyan/10 shadow-[0_0_18px_rgba(94,207,255,0.14)]'
          : 'border-border bg-surface/55 hover:border-cyan/35 hover:bg-cyan/5',
      )}
    >
      <div className={cn('mb-2 flex items-center gap-2', stageToneClass(stage.tone))}>
        {stage.icon}
        <span className="text-[0.68rem] font-bold uppercase tracking-[0.18em]">{stage.label}</span>
      </div>
      <div className="truncate text-[1rem] font-semibold text-text">{stage.status}</div>
      <div className="mt-1 text-[0.8rem] text-muted">click for detail</div>
    </button>
  );
}

function StageDetail({ stage, report, truth }: { stage: ReportStage; report: RunReportCatalogItem; truth: ReportTruthModel }) {
  const detail = stageDetailCopy(stage, report, truth);
  return (
    <div className="theme-surface-card mt-4 grid gap-3 rounded-lg border p-3 md:grid-cols-[220px_1fr]">
      <div>
        <div className="text-[0.68rem] font-bold uppercase tracking-[0.18em] text-cyan">{detail.label}</div>
        <div className="mt-1 text-[1rem] font-semibold text-text">{detail.title}</div>
      </div>
      <div className="grid gap-2 sm:grid-cols-2">
        {detail.items.map((item) => (
          <div key={item} className="flex items-start gap-2 rounded-md border border-border/80 bg-bg/25 px-3 py-2 text-[0.9rem] leading-5 text-muted">
            <CheckCircle2 size={14} className="mt-0.5 shrink-0 text-cyan" />
            <span>{item}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function ScopeInclusionPanel({ report, truth }: { report: RunReportCatalogItem; truth: ReportTruthModel }) {
  return (
    <section className="neon-panel rounded-lg border border-border bg-surface/55 p-4 backdrop-blur-md">
      <div className="mb-4 flex items-start justify-between gap-3">
        <div>
          <h2 className="text-[1.08rem] font-semibold text-text">What will be included</h2>
          <p className="mt-1 text-[0.925rem] text-muted">Selected report scope, without tool-output guesses.</p>
        </div>
        <StatusPill tone={countStatusTone(truth.countStatus)}>
          {countStatusLabel(truth.countStatus)}
        </StatusPill>
      </div>
      <div className="grid gap-3 lg:grid-cols-2">
        <div className="theme-surface-card rounded-lg border p-3">
          <div className="mb-3 flex items-center gap-2 text-cyan">
            <PackageCheck size={15} />
            <span className="text-[0.72rem] font-bold uppercase tracking-[0.18em]">Included</span>
          </div>
          <div className="space-y-2">
            {truth.includedBullets.map((item) => (
              <CompactFact key={item} text={item} />
            ))}
          </div>
        </div>
        <div className="rounded-lg border border-amber/20 bg-amber/5 p-3">
          <div className="mb-3 flex items-center gap-2 text-amber">
            <AlertTriangle size={15} />
            <span className="text-[0.72rem] font-bold uppercase tracking-[0.18em]">What is not claimed</span>
          </div>
          <div className="space-y-2">
            {truth.excludedBullets.map((item) => (
              <CompactFact key={item} text={item} />
            ))}
          </div>
        </div>
      </div>
      {truth.internalCopyWarning && (
        <div className="mt-3 rounded-md border border-amber/30 bg-amber/10 px-3 py-2 text-[0.9rem] font-semibold text-amber">
          Customer copy needs review: internal benchmark, lab, fixture, smoke, or debug wording was detected in this selected report metadata.
        </div>
      )}
      {!truth.internalCopyWarning && (
        <div className="mt-3 rounded-md border border-green/25 bg-green/10 px-3 py-2 text-[0.9rem] font-semibold text-green">
          Customer copy check passed for selected report metadata.
        </div>
      )}
      <div className="mt-3 flex flex-wrap gap-2">
        {report.methodology_references.slice(0, 4).map((item) => (
          <span key={item} className="rounded-full border border-border bg-bg/30 px-2 py-0.5 text-[0.77rem] font-semibold uppercase text-muted">
            {item}
          </span>
        ))}
      </div>
    </section>
  );
}

function CompactFact({ text }: { text: string }) {
  return (
    <div className="flex items-start gap-2 text-[0.9rem] leading-5 text-muted">
      <span className="mt-2 h-1.5 w-1.5 shrink-0 rounded-full bg-cyan" />
      <span>{text}</span>
    </div>
  );
}

function ReportChartStrip({ report, truth }: { report: RunReportCatalogItem; truth: ReportTruthModel }) {
  const readinessData = [
    { label: 'Preview', value: report.preview_allowed ? 1 : 0, color: report.preview_allowed ? '#5ecfff' : '#475569' },
    { label: 'Export', value: report.export_allowed ? 1 : 0, color: report.export_allowed ? '#34d399' : '#475569' },
    { label: 'Draft', value: report.draft_allowed ? 1 : 0, color: report.draft_allowed ? '#d06bff' : '#475569' },
  ];

  return (
    <section className="neon-panel rounded-lg border border-border bg-surface/55 p-4 backdrop-blur-md">
      <div className="mb-4 flex items-start justify-between gap-3">
        <div>
          <h2 className="text-[1.08rem] font-semibold text-text">Report truth charts</h2>
          <p className="mt-1 text-[0.925rem] text-muted">Graphs use canonical findings, not the run-local summary.</p>
        </div>
        <StatusPill tone={countStatusTone(truth.countStatus)}>{truth.canonicalTotal} canonical</StatusPill>
      </div>
      <div className="theme-surface-card mb-3 grid gap-3 rounded-lg border p-3 md:grid-cols-[160px_1fr]">
        <ReportTruthDonut truth={truth} />
        <div className="flex min-w-0 flex-col justify-center">
          <div className="text-[0.72rem] font-bold uppercase tracking-[0.18em] text-cyan">Report inclusion ratio</div>
          <div className="mt-2 text-[1.05rem] font-semibold text-text">
            {truth.includedTotal === null ? 'Included count not listed' : `${truth.includedTotal} included of ${truth.canonicalTotal} canonical findings`}
          </div>
          <p className="mt-1 text-[0.9rem] leading-5 text-muted">
            The selected report may export only what the catalog lists. A mismatch stays visible before download.
          </p>
        </div>
      </div>
      <div className="grid gap-3 lg:grid-cols-2">
        <div className="rounded-lg border border-border bg-bg/25 p-3">
          <div className="mb-3 flex items-center justify-between gap-2">
            <h3 className="text-[0.925rem] font-semibold text-text">Severity</h3>
            <span className="text-[0.77rem] font-bold uppercase text-muted">canonical</span>
          </div>
          <div className="h-[170px]">
            <ResponsiveContainer width="100%" height="100%">
              <ReBarChart data={truth.severityData} margin={{ left: -18, right: 6, top: 4, bottom: 0 }}>
                <CartesianGrid stroke="rgba(142,191,228,0.1)" vertical={false} />
                <XAxis dataKey="label" stroke="#8ebfe4" tickLine={false} axisLine={false} tick={{ fontSize: 11 }} />
                <YAxis allowDecimals={false} stroke="#8ebfe4" tickLine={false} axisLine={false} tick={{ fontSize: 11 }} />
                <Tooltip content={<ReportTooltip valueLabel="Findings" />} />
                <Bar dataKey="value" radius={[6, 6, 0, 0]}>
                  {truth.severityData.map((entry) => <Cell key={entry.label} fill={entry.color} />)}
                </Bar>
              </ReBarChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="rounded-lg border border-border bg-bg/25 p-3">
          <div className="mb-3 flex items-center justify-between gap-2">
            <h3 className="text-[0.925rem] font-semibold text-text">Readiness</h3>
            <span className="text-[0.77rem] font-bold uppercase text-muted">{report.availability_label}</span>
          </div>
          <div className="h-[170px]">
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
      </div>
    </section>
  );
}

function ReportVariantPanel({
  catalog,
  selectedReport,
  loading,
  onSelect,
}: {
  catalog: RunReportCatalogItem[];
  selectedReport: RunReportCatalogItem | null;
  loading: boolean;
  onSelect: (report: RunReportCatalogItem) => void;
}) {
  return (
    <section className="neon-panel rounded-lg border border-border bg-surface/55 p-4 backdrop-blur-md">
      <div className="mb-4 flex items-center justify-between gap-3">
        <div>
          <h2 className="text-[1.08rem] font-semibold text-text">Report variants</h2>
          <p className="mt-1 text-[0.925rem] text-muted">Pick the audience first.</p>
        </div>
        <StatusPill tone="cyan">{catalog.length} variants</StatusPill>
      </div>
      {loading ? (
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
              onClick={() => onSelect(report)}
            />
          ))}
        </div>
      )}
    </section>
  );
}

function ReportActionsPanel({
  action,
  message,
  onPreview,
  onDownloadHtml,
  onDownloadPdf,
  onDownloadNlPdf,
  onDownloadNlMarkdown,
}: {
  action: ReportAction;
  message: string | null;
  onPreview: () => void;
  onDownloadHtml: () => void;
  onDownloadPdf: () => void;
  onDownloadNlPdf: () => void;
  onDownloadNlMarkdown: () => void;
}) {
  return (
    <section className="neon-panel rounded-lg border border-border bg-surface/55 p-4 backdrop-blur-md">
      <div className="mb-4 flex items-center justify-between gap-3">
        <div>
          <h2 className="text-[1.08rem] font-semibold text-text">Preview and export</h2>
          <p className="mt-1 text-[0.925rem] text-muted">Generate only from stored evidence.</p>
        </div>
        <Eye size={16} className="text-cyan" />
      </div>
      <div className="grid gap-2">
        <ActionButton onClick={onPreview} loading={action === 'preview'} icon={<ScrollText size={14} />}>
          Markdown Preview
        </ActionButton>
        <div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-1 2xl:grid-cols-2">
          <ActionButton onClick={onDownloadHtml} loading={action === 'html'} icon={<Download size={14} />}>
            HTML
          </ActionButton>
          <ActionButton onClick={onDownloadPdf} loading={action === 'pdf'} icon={<Download size={14} />}>
            PDF
          </ActionButton>
          <ActionButton onClick={onDownloadNlPdf} loading={action === 'pdf'} icon={<Download size={14} />}>
            NL PDF
          </ActionButton>
          <ActionButton onClick={onDownloadNlMarkdown} loading={action === 'preview'} icon={<Download size={14} />}>
            NL Markdown
          </ActionButton>
        </div>
      </div>
      {message && <div className="mt-3 rounded-md border border-cyan/20 bg-cyan/10 px-3 py-2 text-[0.9rem] text-cyan">{message}</div>}
    </section>
  );
}

function ReportPreviewPanel({ markdown }: { markdown: string | null }) {
  return (
    <section className="neon-panel rounded-lg border border-border bg-surface/55 p-4 backdrop-blur-md">
      <div className="mb-4 flex items-center justify-between gap-3">
        <div>
          <h2 className="text-[1.08rem] font-semibold text-text">Report preview</h2>
          <p className="mt-1 text-[0.925rem] text-muted">Rendered markdown from the selected variant.</p>
        </div>
        <StatusPill tone={markdown ? 'green' : 'muted'}>{markdown ? 'loaded' : 'not loaded'}</StatusPill>
      </div>
      <div className="max-h-[460px] overflow-y-auto rounded-lg border border-border bg-bg/30 p-4">
        {markdown ? (
          <div className="prose-preview">{renderMarkdown(markdown)}</div>
        ) : (
          <EmptyInline title="Preview not generated" detail="Generate a Markdown preview or select an available report card." />
        )}
      </div>
    </section>
  );
}

function StatusPill({ tone, children }: { tone: 'cyan' | 'green' | 'amber' | 'red' | 'muted'; children: ReactNode }) {
  const toneClass = {
    cyan: 'border-cyan/25 bg-cyan/10 text-cyan',
    green: 'border-green/25 bg-green/10 text-green',
    amber: 'border-amber/30 bg-amber/10 text-amber',
    red: 'border-red/30 bg-red/10 text-red',
    muted: 'border-border bg-bg/40 text-muted',
  }[tone];
  return (
    <span className={cn('inline-flex shrink-0 rounded-full border px-2 py-0.5 text-[0.77rem] font-bold uppercase', toneClass)}>
      {children}
    </span>
  );
}

function stageToneClass(tone: string): string {
  if (tone === 'green') return 'text-green';
  if (tone === 'amber') return 'text-amber';
  if (tone === 'red') return 'text-red';
  return 'text-cyan';
}

function routeToneClass(tone: ManagementReportRouteStep['tone']): string {
  if (tone === 'good') return 'border-green/35 bg-green/10 text-green';
  if (tone === 'proof') return 'border-red/35 bg-red/10 text-red';
  if (tone === 'outcome') return 'border-ai/35 bg-ai/10 text-ai';
  if (tone === 'scope') return 'border-cyan/35 bg-cyan/10 text-cyan';
  return 'border-border bg-bg/40 text-muted';
}

function ReportTruthDonut({ truth }: { truth: ReportTruthModel }) {
  const total = Math.max(truth.canonicalTotal, truth.includedTotal ?? 0, 1);
  const included = Math.min(truth.includedTotal ?? truth.canonicalTotal, total);
  const ratio = included / total;
  const circumference = 2 * Math.PI * 42;
  const dash = circumference * ratio;
  return (
    <div className="flex items-center justify-center">
      <svg className="h-[150px] w-[150px]" viewBox="0 0 120 120" role="img" aria-label="Report inclusion ratio">
        <circle cx="60" cy="60" r="42" fill="none" stroke="rgba(142,191,228,0.14)" strokeWidth="12" />
        <circle
          cx="60"
          cy="60"
          r="42"
          fill="none"
          stroke={truth.countStatus === 'mismatch' ? '#ef4444' : '#5ecfff'}
          strokeLinecap="round"
          strokeWidth="12"
          strokeDasharray={`${dash} ${circumference - dash}`}
          transform="rotate(-90 60 60)"
        />
        <text x="60" y="56" textAnchor="middle" fill="#e5edf5" className="text-[1.2rem] font-bold">
          {included}
        </text>
        <text x="60" y="74" textAnchor="middle" fill="#8aa0b8" className="text-[0.62rem] uppercase tracking-widest">
          included
        </text>
      </svg>
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
    <div className="dark-canvas rounded-md border border-cyan/25 bg-[#06101d]/95 px-3 py-2 shadow-[0_0_1rem_rgba(94,207,255,0.16)]">
      <div className="text-[0.8rem] font-bold uppercase text-cyan">{label}</div>
      <div className="text-[0.9rem] text-text">{valueLabel}: {booleanValue ? (value ? 'Yes' : 'No') : value}</div>
    </div>
  );
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
    <section className="neon-panel rounded-lg border border-border bg-surface/55 p-4 backdrop-blur-md">
      <div className="mb-3 flex items-center justify-between gap-3">
        <h2 className="text-[1.08rem] font-semibold text-text">Report run</h2>
        <Layers3 size={16} className="text-cyan" />
      </div>
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
    </section>
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
    <details className="neon-panel rounded-lg border border-border bg-surface/55 p-4 backdrop-blur-md">
      <summary className="flex cursor-pointer list-none items-center justify-between gap-3 text-[0.925rem] font-semibold text-text">
        <span className="flex items-center gap-2">
          <Check size={14} className="text-green" />
          Report content hash
        </span>
        <ChevronDown size={14} className="text-muted" />
      </summary>
      <div className="mt-3 flex items-start gap-2 text-[0.925rem] text-muted">
        <Hash size={14} className="mt-0.5 text-cyan" />
        <span className="break-all font-mono text-text">{report.content_sha256}</span>
      </div>
      <p className="mt-2 text-[0.85rem] leading-5 text-muted">
        This identifies the generated report content. Evidence integrity remains tied to the stored artifacts and finding evidence references.
      </p>
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
    <section className="neon-panel rounded-lg border border-border bg-surface/55 p-4 backdrop-blur-md">
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
      <div className="flex flex-wrap items-start justify-between gap-4 border-b border-border bg-bg/45 p-4">
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
      <pre key={`code-${key}`} className="terminal-code my-3 overflow-auto rounded-md border p-3 font-mono text-[0.925rem] leading-5">
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
  return safeErrorMessage(error, {
    fallback: 'Report data could not be prepared. Refresh the catalog or select another run.',
    unavailable: 'Report generation is temporarily unavailable. Canonical findings and evidence remain visible for review.',
    notFound: 'This report or run is no longer available. Refresh the run list before exporting.',
  });
}
