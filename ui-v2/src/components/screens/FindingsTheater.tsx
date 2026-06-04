import { useEffect, useMemo, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import { AnimatePresence } from 'framer-motion';
import {
  AlertTriangle,
  Bot,
  CalendarClock,
  Check,
  ChevronDown,
  ChevronRight,
  Clipboard,
  ExternalLink,
  Filter,
  GitPullRequest,
  Hash,
  Layers3,
  ListChecks,
  Loader2,
  Search,
  ShieldAlert,
  Sparkles,
  Ticket,
  X,
} from 'lucide-react';
import { Link } from 'react-router-dom';
import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';
import { buildFindingTruthModel, type FindingTruthTone } from '../../viewModels/findingTruth';
import { safeErrorMessage } from '../../viewModels/safeMessaging';
import {
  buildFindingsTriageModel,
  type FindingTriageGroup,
  type FindingsTriageModel,
  type ProofStrength,
} from '../../viewModels/triageBoards';
import {
  enrichFinding,
  createFindingFixPullRequest,
  getFindingEvidence,
  getFindingTheater,
  getFindingsForRunContext,
  handoffFindingToJira,
  updateFindingStatus,
} from '../../api/client';
import type { Finding, FindingEvidenceReplay, FindingTheater as FindingTheaterDetail, JsonMap, UUID } from '../../api/types';
import { useAegisStore } from '../../store';

type SeverityFilter = 'all' | 'critical' | 'high' | 'medium' | 'low' | 'info';
type StatusFilter = 'all' | 'open' | 'false-positive' | 'fixed';
type DrawerAction = 'enrich' | 'fixed' | 'false-positive' | 'jira' | 'fix-pr' | null;

const SEVERITIES: SeverityFilter[] = ['critical', 'high', 'medium', 'low', 'info'];
const STATUS_FILTERS: StatusFilter[] = ['all', 'open', 'false-positive', 'fixed'];
const SECTION_DEFAULTS = ['truth', 'summary', 'evidence-summary', 'evidence', 'business-impact', 'ai', 'remediation', 'fix-pr', 'push', 'attack-path'];

function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export default function FindingsTheater() {
  const selectedRun = useAegisStore((state) => state.selectedRun);
  const selectedRunId = useAegisStore((state) => state.selectedRunId);
  const findings = useAegisStore((state) => state.findings);
  const selectedFindingId = useAegisStore((state) => state.selectedFindingId);
  const settings = useAegisStore((state) => state.settings);
  const setFindings = useAegisStore((state) => state.setFindings);
  const selectFinding = useAegisStore((state) => state.selectFinding);
  const setError = useAegisStore((state) => state.setError);

  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>('all');
  const [statusFilter, setStatusFilter] = useState<StatusFilter>('all');
  const [query, setQuery] = useState('');
  const [loadingFindings, setLoadingFindings] = useState(false);
  const [detail, setDetail] = useState<FindingTheaterDetail | null>(null);
  const [evidence, setEvidence] = useState<FindingEvidenceReplay | null>(null);
  const [loadingDetail, setLoadingDetail] = useState(false);
  const [action, setAction] = useState<DrawerAction>(null);
  const [actionMessage, setActionMessage] = useState<string | null>(null);
  const [falsePositiveReason, setFalsePositiveReason] = useState('Analyst reviewed the stored evidence and marked this finding as a false positive.');
  const [openSections, setOpenSections] = useState<Set<string>>(() => new Set(SECTION_DEFAULTS));

  const selectedFinding = findings.find((finding) => finding.id === selectedFindingId) ?? null;
  const visibleFindings = useMemo(
    () => filterFindings(findings, severityFilter, statusFilter, query),
    [findings, query, severityFilter, statusFilter],
  );
  const groupedFindings = useMemo(() => groupBySeverity(visibleFindings), [visibleFindings]);
  const triageModel = useMemo(() => buildFindingsTriageModel(visibleFindings), [visibleFindings]);
  const findingCount = findings.length;
  const jiraConfigured = isJiraConfigured(settings.settings);

  useEffect(() => {
    if (!selectedRun) {
      setFindings([]);
      selectFinding(null);
      return;
    }

    const run = selectedRun;
    let cancelled = false;
    async function loadFindings() {
      setLoadingFindings(true);
      setError(null);
      try {
        const payload = await getFindingsForRunContext(run);
        if (!cancelled) {
          setFindings(payload);
          if (payload.length === 0) {
            selectFinding(null);
          }
        }
      } catch (error) {
        if (!cancelled) {
          setFindings([]);
          setError(errorMessage(error));
        }
      } finally {
        if (!cancelled) {
          setLoadingFindings(false);
        }
      }
    }

    void loadFindings();
    return () => {
      cancelled = true;
    };
  }, [selectFinding, selectedRun, setError, setFindings]);

  useEffect(() => {
    if (!selectedFindingId) {
      setDetail(null);
      setEvidence(null);
      return;
    }

    const findingId = selectedFindingId;
    let cancelled = false;
    async function loadDetail() {
      setLoadingDetail(true);
      setActionMessage(null);
      setError(null);
      try {
        const [theaterPayload, evidencePayload] = await Promise.all([
          getFindingTheater(findingId),
          getFindingEvidence(findingId),
        ]);
        if (!cancelled) {
          setDetail(theaterPayload);
          setEvidence(evidencePayload);
        }
      } catch (error) {
        if (!cancelled) {
          setDetail(null);
          setEvidence(null);
          setError(errorMessage(error));
        }
      } finally {
        if (!cancelled) {
          setLoadingDetail(false);
        }
      }
    }

    void loadDetail();
    return () => {
      cancelled = true;
    };
  }, [selectedFindingId, setError]);

  function toggleSection(section: string) {
    setOpenSections((current) => {
      const next = new Set(current);
      if (next.has(section)) next.delete(section);
      else next.add(section);
      return next;
    });
  }

  async function refreshSelectedFinding(findingId: UUID) {
    const [theaterPayload, evidencePayload, listPayload] = await Promise.all([
      getFindingTheater(findingId),
      getFindingEvidence(findingId),
      selectedRun ? getFindingsForRunContext(selectedRun) : Promise.resolve(findings),
    ]);
    setDetail(theaterPayload);
    setEvidence(evidencePayload);
    setFindings(listPayload);
    selectFinding(findingId);
  }

  async function handleEnrich() {
    if (!selectedFinding) return;
    setAction('enrich');
    setActionMessage(null);
    try {
      await enrichFinding(selectedFinding.id);
      await refreshSelectedFinding(selectedFinding.id);
      setActionMessage('AI enrichment request recorded.');
    } catch (error) {
      setActionMessage(errorMessage(error));
    } finally {
      setAction(null);
    }
  }

  async function handleMarkFixed() {
    if (!selectedFinding) return;
    setAction('fixed');
    setActionMessage(null);
    try {
      await updateFindingStatus(selectedFinding.id, {
        status: 'resolved',
        reason: 'Marked Fixed from React v2 Findings Theater after operator review.',
      });
      await refreshSelectedFinding(selectedFinding.id);
      setActionMessage('Finding marked Fixed.');
    } catch (error) {
      setActionMessage(errorMessage(error));
    } finally {
      setAction(null);
    }
  }

  async function handleFalsePositive() {
    if (!selectedFinding) return;
    const reason = falsePositiveReason.trim();
    if (!reason) {
      setActionMessage('False positive reason is required.');
      return;
    }
    setAction('false-positive');
    setActionMessage(null);
    try {
      await updateFindingStatus(selectedFinding.id, {
        status: 'false_positive',
        false_positive_reason: reason,
      });
      await refreshSelectedFinding(selectedFinding.id);
      setActionMessage('Finding marked false positive.');
    } catch (error) {
      setActionMessage(errorMessage(error));
    } finally {
      setAction(null);
    }
  }

  async function handleJira() {
    if (!selectedFinding) return;
    setAction('jira');
    setActionMessage(null);
    try {
      await handoffFindingToJira(selectedFinding.id);
      await refreshSelectedFinding(selectedFinding.id);
      setActionMessage('Jira handoff prepared.');
    } catch (error) {
      setActionMessage(errorMessage(error));
    } finally {
      setAction(null);
    }
  }

  async function handleCreateFixPr() {
    if (!selectedFinding) return;
    setAction('fix-pr');
    setActionMessage(null);
    try {
      const pullRequest = await createFindingFixPullRequest(selectedFinding.id);
      await refreshSelectedFinding(selectedFinding.id);
      const label = pullRequest.provider === 'gitlab' ? 'merge request' : 'pull request';
      setActionMessage(`AI-generated ${label} prepared for human review.`);
    } catch (error) {
      setActionMessage(errorMessage(error));
    } finally {
      setAction(null);
    }
  }

  if (!selectedRunId) {
    return (
      <EmptyState
        title="No Run Selected"
        detail="Select or create a run before opening Findings Theater."
        action={<Link to="/intake" className="rounded-md border border-cyan/30 bg-cyan/10 px-4 py-2 text-[1rem] font-semibold text-cyan">New Mission</Link>}
      />
    );
  }

  return (
    <section className="flex h-full min-h-0 flex-col">
      <header className="mb-5 flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold text-text">Findings Theater</h1>
          <p className="mt-1 text-[1rem] text-muted">
            {selectedRun ? `${selectedRun.profile.name} · ${selectedRun.status}` : 'Selected run'} · evidence-backed findings
          </p>
        </div>
        <div className="flex gap-2">
          <Metric label="Findings" value={findingCount} />
          <Metric label="Visible" value={visibleFindings.length} />
        </div>
      </header>

      <FindingsTriageBoard model={triageModel} onSelectFinding={selectFinding} />

      <div className={cn('grid min-h-0 flex-1 gap-5', selectedFinding ? 'xl:grid-cols-1' : 'xl:grid-cols-1')}>
        <div className="flex min-h-0 flex-col overflow-hidden rounded-xl border border-border bg-surface/50 backdrop-blur-md">
          <FilterBar
            severity={severityFilter}
            setSeverity={setSeverityFilter}
            status={statusFilter}
            setStatus={setStatusFilter}
            query={query}
            setQuery={setQuery}
            loading={loadingFindings}
          />

          <div aria-label="Findings result list" className="min-h-0 flex-1 overflow-y-auto p-4">
            {loadingFindings ? (
              <LoadingPanel label="Loading findings from API" />
            ) : visibleFindings.length === 0 ? (
              <EmptyInline title="No findings match this view" detail="Adjust filters or select a run with stored findings." />
            ) : (
              <div className="space-y-5">
                {groupedFindings.map(({ severity, items }) => (
                  <div key={severity}>
                    <div className="mb-2 flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <SeverityBadge severity={severity} />
                        <span className="text-[0.925rem] font-semibold text-muted">{items.length} findings</span>
                      </div>
                    </div>
                    <div className="space-y-2">
                      {items.map((finding) => (
                        <FindingRow
                          key={finding.id}
                          finding={finding}
                          selected={finding.id === selectedFindingId}
                          onClick={() => selectFinding(finding.id)}
                        />
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        <AnimatePresence mode="wait">
          {selectedFinding && (
            <FindingDrawer open={true}
              key={selectedFinding.id}
              finding={selectedFinding}
              detail={detail}
              evidence={evidence}
              loading={loadingDetail}
              chatgptConnected={settings.chatgpt_connected}
              jiraConfigured={jiraConfigured}
              action={action}
              actionMessage={actionMessage}
              falsePositiveReason={falsePositiveReason}
              setFalsePositiveReason={setFalsePositiveReason}
              openSections={openSections}
              toggleSection={toggleSection}
              onClose={() => selectFinding(null)}
              onEnrich={handleEnrich}
              onMarkFixed={handleMarkFixed}
              onFalsePositive={handleFalsePositive}
              onJira={handleJira}
              onCreateFixPr={handleCreateFixPr}
            />
          )}
        </AnimatePresence>
      </div>
    </section>
  );
}

function FindingsTriageBoard({
  model,
  onSelectFinding,
}: {
  model: FindingsTriageModel;
  onSelectFinding: (findingId: UUID) => void;
}) {
  const lead = model.leadGroup;
  return (
    <section
      aria-label="Findings triage board"
      className="neon-panel mb-5 rounded-xl border border-cyan/25 p-4"
    >
      <div className="grid gap-3 xl:grid-cols-[minmax(0,1.15fr)_minmax(0,2fr)]">
        <div className="rounded-lg border border-border bg-bg/30 p-4">
          <div className="mb-2 flex items-center gap-2 font-mono text-[0.68rem] font-semibold uppercase tracking-[0.22em] text-cyan">
            <ListChecks size={14} />
            Decision now
          </div>
          <h2 className="text-xl font-semibold text-text">{model.decisionLabel}</h2>
          <p className="mt-2 max-w-2xl text-[1rem] leading-6 text-muted">{model.decisionDetail}</p>
          <div className="mt-4 grid gap-2 sm:grid-cols-3">
            <TriageFact label="Proof" value={model.proofDetail} />
            <TriageFact label="Groups" value={`${model.totalGroups} grouped / ${model.totalFindings} findings`} />
            <TriageFact label="Remediation" value={model.remediationDetail} />
          </div>
          {lead && (
            <button
              type="button"
              onClick={() => onSelectFinding(lead.representative.id)}
              className="mt-4 inline-flex items-center gap-2 rounded-md border border-cyan/30 bg-cyan/10 px-3 py-2 text-[1rem] font-semibold text-cyan transition-colors hover:bg-cyan/15"
            >
              Open lead finding
              <ChevronRight size={15} />
            </button>
          )}
        </div>

        <div className="grid gap-3 lg:grid-cols-[minmax(0,1.45fr)_minmax(260px,0.8fr)]">
          <div className="rounded-lg border border-border bg-bg/25 p-3">
            <div className="mb-3 flex items-center justify-between gap-3">
              <div className="flex items-center gap-2 font-mono text-[0.68rem] font-semibold uppercase tracking-[0.22em] text-muted">
                <Layers3 size={14} className="text-cyan" />
                Severity lanes
              </div>
              <span className="rounded-full border border-border bg-surface/60 px-2 py-0.5 text-[0.72rem] font-semibold uppercase text-muted">
                click a group
              </span>
            </div>
            {model.lanes.length ? (
              <div className="grid gap-2 md:grid-cols-2 2xl:grid-cols-3">
                {model.lanes.map((lane) => (
                  <div key={lane.severity} className="rounded-lg border border-border bg-surface/40 p-3">
                    <div className="mb-2 flex items-center justify-between">
                      <SeverityBadge severity={lane.severity} />
                      <span className="text-[0.85rem] font-semibold text-muted">{lane.count}</span>
                    </div>
                    <div className="space-y-2">
                      {lane.groups.slice(0, 3).map((group) => (
                        <FindingTriageGroupButton key={group.id} group={group} onSelect={() => onSelectFinding(group.representative.id)} />
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <EmptyInline title="No findings in current filters" detail="Reset filters or choose a run with stored findings." />
            )}
          </div>

          <div className="rounded-lg border border-border bg-bg/25 p-3">
            <div className="mb-3 flex items-center gap-2 font-mono text-[0.68rem] font-semibold uppercase tracking-[0.22em] text-muted">
              <CalendarClock size={14} className="text-amber" />
              Grouped repeated findings
            </div>
            {model.repeatedGroups.length ? (
              <div className="space-y-2">
                {model.repeatedGroups.slice(0, 3).map((group) => (
                  <button
                    key={group.id}
                    type="button"
                    onClick={() => onSelectFinding(group.representative.id)}
                    className="w-full rounded-lg border border-border bg-surface/45 p-3 text-left transition-colors hover:border-cyan/35 hover:bg-cyan/10"
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="line-clamp-1 text-[0.98rem] font-semibold text-text">{group.title}</span>
                      <span className="shrink-0 rounded-full border border-cyan/25 bg-cyan/10 px-2 py-0.5 text-[0.75rem] font-bold text-cyan">
                        {group.count} findings
                      </span>
                    </div>
                    <div className="mt-2 text-[0.85rem] leading-5 text-muted">
                      {group.evidenceCount} linked evidence refs across {group.targetCount} target{group.targetCount === 1 ? '' : 's'}.
                    </div>
                    <div className="mt-2 line-clamp-1 font-mono text-[0.72rem] text-muted">
                      {group.evidenceRefs.join(' · ') || 'no evidence refs'}
                    </div>
                  </button>
                ))}
              </div>
            ) : (
              <p className="rounded-lg border border-border bg-surface/35 p-3 text-[0.925rem] leading-5 text-muted">
                No repeated finding groups in the current filters. Individual evidence remains visible in the list and drawer.
              </p>
            )}
          </div>
        </div>
      </div>
    </section>
  );
}

function FindingTriageGroupButton({ group, onSelect }: { group: FindingTriageGroup; onSelect: () => void }) {
  return (
    <button
      type="button"
      onClick={onSelect}
      className="w-full rounded-md border border-border bg-bg/35 p-2 text-left transition-colors hover:border-cyan/35 hover:bg-cyan/10"
      aria-label={`${group.title}, ${group.count} findings, ${group.proofLabel}`}
    >
      <div className="flex items-start justify-between gap-2">
        <span className="line-clamp-2 text-[0.95rem] font-semibold leading-5 text-text">{group.title}</span>
        <span className={cn('shrink-0 rounded-full border px-2 py-0.5 text-[0.68rem] font-bold uppercase', proofStrengthClass(group.proofStrength))}>
          {group.proofLabel}
        </span>
      </div>
      <div className="mt-2 grid gap-1 text-[0.78rem] leading-4 text-muted">
        <span>{group.impactLabel}</span>
        <span>{group.evidenceCount}/{group.count} evidence linked · {group.verifiedCount}/{group.count} verified</span>
        <span>{group.remediationLabel}</span>
      </div>
    </button>
  );
}

function TriageFact({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-md border border-border bg-surface/35 p-3">
      <div className="font-mono text-[0.62rem] uppercase tracking-widest text-muted">{label}</div>
      <div className="mt-1 text-[0.92rem] font-semibold leading-5 text-text">{value}</div>
    </div>
  );
}

function FilterBar({
  severity,
  setSeverity,
  status,
  setStatus,
  query,
  setQuery,
  loading,
}: {
  severity: SeverityFilter;
  setSeverity: (value: SeverityFilter) => void;
  status: StatusFilter;
  setStatus: (value: StatusFilter) => void;
  query: string;
  setQuery: (value: string) => void;
  loading: boolean;
}) {
  return (
    <div className="border-b border-border bg-bg/45 p-4">
      <div className="grid gap-3 lg:grid-cols-[180px_180px_1fr]">
        <SelectControl
          label="Severity"
          icon={<Filter size={14} />}
          value={severity}
          onChange={(value) => setSeverity(value as SeverityFilter)}
          options={[{ value: 'all', label: 'All' }, ...SEVERITIES.map((item) => ({ value: item, label: titleCase(item) }))]}
        />
        <SelectControl
          label="Status"
          icon={<Check size={14} />}
          value={status}
          onChange={(value) => setStatus(value as StatusFilter)}
          options={STATUS_FILTERS.map((item) => ({ value: item, label: item === 'all' ? 'All' : item === 'false-positive' ? 'False Positive' : titleCase(item) }))}
        />
        <label className="block">
          <span className="mb-1 flex items-center gap-2 text-[0.85rem] font-bold uppercase text-muted">
            <Search size={14} />
            Search
            {loading && <Loader2 size={12} className="animate-spin text-cyan" />}
          </span>
          <input
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Title, target, tool, evidence ref"
            className="h-10 w-full rounded-lg border border-border bg-surface px-3 text-[1rem] text-text outline-none transition-colors placeholder:text-muted focus:border-cyan/50"
          />
        </label>
      </div>
    </div>
  );
}

function SelectControl({
  label,
  icon,
  value,
  onChange,
  options,
}: {
  label: string;
  icon: ReactNode;
  value: string;
  onChange: (value: string) => void;
  options: Array<{ value: string; label: string }>;
}) {
  return (
    <label className="block">
      <span className="mb-1 flex items-center gap-2 text-[0.85rem] font-bold uppercase text-muted">
        {icon}
        {label}
      </span>
      <select
        value={value}
        onChange={(event) => onChange(event.target.value)}
        className="h-10 w-full rounded-lg border border-border bg-surface px-3 text-[1rem] text-text outline-none transition-colors focus:border-cyan/50"
      >
        {options.map((option) => (
          <option key={option.value} value={option.value} className="bg-surface text-text">
            {option.label}
          </option>
        ))}
      </select>
    </label>
  );
}

function FindingRow({ finding, selected, onClick }: { finding: Finding; selected: boolean; onClick: () => void }) {
  const truth = buildFindingTruthModel(finding, null, null);
  return (
    <button
      type="button"
      onClick={onClick}
      className={cn(
        'grid w-full gap-3 rounded-lg border p-3 text-left transition-all md:grid-cols-[minmax(0,1fr)_auto]',
        selected ? 'border-cyan/50 bg-cyan/10 shadow-[0_0_18px_rgba(94,207,255,0.1)]' : 'border-border bg-bg/25 hover:border-cyan/30 hover:bg-cyan/5',
      )}
    >
      <div className="min-w-0">
        <div className="mb-2 flex flex-wrap items-center gap-2">
          <SeverityBadge severity={finding.severity} />
          <TruthBadge tone={truth.tone} label={truth.proofLabel} />
          <EvidenceBadge label={truth.evidenceLabel} tone={truth.tone} />
          <StatusBadge status={finding.status} />
        </div>
        <div className="truncate text-[1.08rem] font-semibold text-text">{truth.displayTitle}</div>
        <div className="mt-1 flex flex-wrap gap-x-3 gap-y-1 text-[0.925rem] text-muted">
          <span className="truncate">{truncate(finding.target_id, 36)}</span>
          <span>{truth.validationLabel}</span>
          <span>{truth.sourceLabel}</span>
        </div>
        <SeverityBar severity={finding.severity} />
      </div>
      <div className="flex items-center justify-end text-muted">
        <ChevronRight size={16} />
      </div>
    </button>
  );
}

function FindingDrawer({
  finding,
  detail,
  evidence,
  loading,
  chatgptConnected,
  jiraConfigured,
  action,
  actionMessage,
  falsePositiveReason,
  setFalsePositiveReason,
  openSections,
  toggleSection,
  onClose,
  onEnrich,
  onMarkFixed,
  onFalsePositive,
  onJira,
  onCreateFixPr,
  open,
}: {
  finding: Finding;
  detail: FindingTheaterDetail | null;
  evidence: FindingEvidenceReplay | null;
  loading: boolean;
  chatgptConnected: boolean;
  jiraConfigured: boolean;
  action: DrawerAction;
  actionMessage: string | null;
  falsePositiveReason: string;
  setFalsePositiveReason: (value: string) => void;
  openSections: Set<string>;
  toggleSection: (section: string) => void;
  onClose: () => void;
  onEnrich: () => void;
  onMarkFixed: () => void;
  onFalsePositive: () => void;
  onJira: () => void;
  onCreateFixPr: () => void;
  open?: boolean;
}) {
  const truth = buildFindingTruthModel(finding, detail, evidence);
  const evidenceText = technicalEvidenceText(evidence, detail, finding);
  const storedSha = storedSha256(detail, evidence);
  const enrichment = detail?.ai_enrichment ?? {};
  const hasEnrichment = boolValue(enrichment.available);
  const chains = chainList(detail);
  const repositoryContext = detail?.repository_context ?? {};
  const latestPullRequest = isJsonMap(repositoryContext.latest_pull_request) ? repositoryContext.latest_pull_request : {};
  const fixPrSupported = boolValue(repositoryContext.pull_request_supported);
  const repositoryAvailable = boolValue(repositoryContext.available);
  const repositoryUrl = textValue(repositoryContext.external_url) || textValue(repositoryContext.repository_url);
  const latestPullRequestUrl = textValue(latestPullRequest.pull_request_url);

  return (
    <aside
      className={cn("finding-drawer", open && "open")}
    >
      <div className="flex h-full min-h-0 flex-col">
        <header className="border-b border-border bg-bg/45 p-4">
          <div className="mb-3 flex items-start justify-between gap-3">
            <div className="min-w-0">
              <div className="mb-2 flex flex-wrap items-center gap-2">
                <SeverityBadge severity={finding.severity} />
                <TruthBadge tone={truth.tone} label={truth.proofLabel} />
                <EvidenceBadge label={truth.evidenceLabel} tone={truth.tone} />
                <StatusBadge status={finding.status} />
              </div>
              <h2 className="break-words text-lg font-semibold text-text">{truth.displayTitle}</h2>
              <p className="mt-1 break-words text-[0.925rem] text-muted">{finding.target_id}</p>
              {truth.rawTitleWasNormalized && (
                <p className="mt-1 break-words text-[0.78rem] text-muted">Stored title: {truth.rawTitle}</p>
              )}
            </div>
            <button
              type="button"
              onClick={onClose}
              aria-label="Close finding drawer"
              className="rounded-md p-2 text-muted transition-colors hover:bg-surface hover:text-text"
            >
              <X size={18} />
            </button>
          </div>
          {loading && <div className="flex items-center gap-2 text-[0.925rem] text-cyan"><Loader2 size={14} className="animate-spin" /> Loading evidence detail</div>}
          {actionMessage && <div className="rounded-md border border-cyan/20 bg-cyan/10 px-3 py-2 text-[0.925rem] text-cyan">{actionMessage}</div>}
        </header>

        <div className="min-h-0 flex-1 space-y-3 overflow-y-auto p-4">
          <DrawerSection title="Finding Truth" id="truth" openSections={openSections} toggleSection={toggleSection}>
            <div className="grid gap-2 md:grid-cols-2">
              <TruthFact label="Proof state" value={truth.proofLabel} detail={truth.proofDetail} tone={truth.tone} />
              <TruthFact label="Evidence state" value={truth.evidenceLabel} detail={truth.sourceLabel} tone={truth.tone} />
              <TruthFact label="Validation state" value={truth.validationLabel} detail={detail?.verification_status ?? finding.validation_status} tone={truth.tone} />
              <TruthFact label="Workflow state" value={truth.workflowLabel} detail={finding.status} tone={truth.tone} />
            </div>
          </DrawerSection>

          <DrawerSection title="Summary" id="summary" openSections={openSections} toggleSection={toggleSection}>
            <p className="text-[1rem] leading-6 text-muted">{detail?.technical_details || finding.summary || 'No summary text is available for this finding.'}</p>
            <div className="mt-4 grid gap-3 sm:grid-cols-2">
              <CvssGauge score={finding.cvss_score} />
              <div className="rounded-lg border border-border bg-bg/30 p-3">
                <div className="mb-2 text-[0.85rem] font-bold uppercase text-muted">OWASP</div>
                <div className="text-[1rem] font-semibold text-text">{owaspLabel(finding, detail)}</div>
                <div className="mt-1 text-[0.925rem] text-muted">{finding.owasp_reference || textValue(mapValue(detail?.methodology, 'owasp.reference')) || 'No OWASP reference recorded'}</div>
              </div>
            </div>
          </DrawerSection>

          <DrawerSection title="Evidence Summary" id="evidence-summary" openSections={openSections} toggleSection={toggleSection}>
            <p className="text-[1rem] leading-6 text-muted">
              {truth.evidenceSummary ?? 'No evidence summary was returned for this finding.'}
            </p>
            <div className="mt-3 rounded-md border border-border bg-bg/30 p-3 text-[0.925rem] text-muted">
              <span className="font-semibold text-text">{truth.evidenceLabel}</span>
              <span className="mx-2 text-muted">/</span>
              <span>{truth.proofDetail}</span>
            </div>
          </DrawerSection>

          <DrawerSection title="Technical Evidence" id="evidence" openSections={openSections} toggleSection={toggleSection}>
            <div className="terminal-code overflow-hidden rounded-lg border">
              <div className="flex items-center justify-between border-b border-border px-3 py-2">
                <span className="flex items-center gap-2 text-[0.85rem] font-bold uppercase text-muted">
                  <Clipboard size={13} />
                  Raw Evidence View
                </span>
                <button
                  type="button"
                  onClick={() => void copyText(evidenceText)}
                  className="rounded-md px-2 py-1 text-[0.85rem] font-semibold text-cyan transition-colors hover:bg-cyan/10"
                >
                  Copy
                </button>
              </div>
              <pre className="max-h-[320px] overflow-auto whitespace-pre-wrap p-3 font-mono text-[0.925rem] leading-5">{evidenceText}</pre>
            </div>
            <div className="mt-3 flex items-start gap-2 rounded-md border border-border bg-bg/30 p-3 text-[0.925rem] text-muted">
              <Hash size={14} className="mt-0.5 text-cyan" />
              <span className="break-all">
                SHA-256: <span className="font-mono text-text">{storedSha || 'No stored artifact hash available'}</span>
              </span>
            </div>
          </DrawerSection>

          <DrawerSection title="Business Impact" id="business-impact" openSections={openSections} toggleSection={toggleSection}>
            <p className="text-[1rem] leading-6 text-muted">
              {truth.businessImpact ?? 'No business-impact statement was returned for this finding.'}
            </p>
          </DrawerSection>

          <DrawerSection title="AI Enrichment" id="ai" openSections={openSections} toggleSection={toggleSection}>
            {hasEnrichment ? (
              <div className="space-y-3 text-[1rem] leading-6 text-muted">
                <p><strong className="text-text">Business impact:</strong> {textValue(enrichment.business_impact) || 'No AI business-impact text stored.'}</p>
                <p><strong className="text-text">Remediation:</strong> {textValue(enrichment.remediation_narrative) || 'No AI remediation text stored.'}</p>
              </div>
            ) : chatgptConnected ? (
              <button
                type="button"
                onClick={onEnrich}
                disabled={action === 'enrich'}
                className="inline-flex items-center gap-2 rounded-md border border-cyan/30 bg-cyan/10 px-3 py-2 text-[1rem] font-semibold text-cyan disabled:opacity-50"
              >
                {action === 'enrich' ? <Loader2 size={14} className="animate-spin" /> : <Sparkles size={14} />}
                Enrich Now
              </button>
            ) : (
              <Link to="/settings" className="inline-flex items-center gap-2 rounded-md border border-border bg-bg/40 px-3 py-2 text-[1rem] font-semibold text-muted hover:text-text">
                <Bot size={14} />
                Connect ChatGPT in Settings to enable
              </Link>
            )}
          </DrawerSection>

          <DrawerSection title="Remediation" id="remediation" openSections={openSections} toggleSection={toggleSection}>
            <div className="space-y-3">
              <p className="text-[1rem] leading-6 text-muted">
                {truth.remediationText ?? 'No supported remediation guidance returned for this finding.'}
              </p>
              {truth.nextSteps.length > 0 ? (
                <ol className="space-y-2">
                  {truth.nextSteps.map((step) => (
                    <li key={step} className="rounded-md border border-border bg-bg/30 p-3 text-[0.925rem] text-muted">{step}</li>
                  ))}
                </ol>
              ) : (
                <div className="rounded-md border border-border bg-bg/30 p-3 text-[0.925rem] text-muted">
                  No supported next steps returned for this finding.
                </div>
              )}
              <div className="grid gap-2 md:grid-cols-2">
                <button
                  type="button"
                  onClick={onMarkFixed}
                  disabled={action === 'fixed'}
                  className="inline-flex items-center justify-center gap-2 rounded-md border border-green/30 bg-green/10 px-3 py-2 text-[1rem] font-semibold text-green disabled:opacity-50"
                >
                  {action === 'fixed' ? <Loader2 size={14} className="animate-spin" /> : <Check size={14} />}
                  Mark as Fixed
                </button>
                <button
                  type="button"
                  onClick={onFalsePositive}
                  disabled={action === 'false-positive'}
                  className="inline-flex items-center justify-center gap-2 rounded-md border border-amber/30 bg-amber/10 px-3 py-2 text-[1rem] font-semibold text-amber disabled:opacity-50"
                >
                  {action === 'false-positive' ? <Loader2 size={14} className="animate-spin" /> : <AlertTriangle size={14} />}
                  Mark as False Positive
                </button>
              </div>
              <label className="block">
                <span className="mb-1 block text-[0.85rem] font-bold uppercase text-muted">False positive reason</span>
                <textarea
                  value={falsePositiveReason}
                  onChange={(event) => setFalsePositiveReason(event.target.value)}
                  rows={3}
                  className="w-full rounded-md border border-border bg-bg/40 p-3 text-[0.925rem] text-text outline-none focus:border-cyan/50"
                />
              </label>
            </div>
          </DrawerSection>

          {repositoryAvailable && (
            <DrawerSection title="Fix Pull Request" id="fix-pr" openSections={openSections} toggleSection={toggleSection}>
              <div className="space-y-3">
                <div className="rounded-md border border-border bg-bg/30 p-3">
                  <div className="flex flex-wrap items-center gap-2 text-[0.925rem] text-muted">
                    <span className="font-semibold text-text">{titleCase(textValue(repositoryContext.provider) || 'repository')}</span>
                    <span>{textValue(repositoryContext.repository_path) || 'linked source path'}</span>
                    {textValue(repositoryContext.repository_branch) && <span>on {textValue(repositoryContext.repository_branch)}</span>}
                  </div>
                  {repositoryUrl && (
                    <a href={repositoryUrl} target="_blank" rel="noreferrer" className="mt-2 inline-flex items-center gap-2 text-[0.925rem] text-cyan">
                      <ExternalLink size={13} />
                      Open linked code
                    </a>
                  )}
                </div>
                {latestPullRequestUrl ? (
                  <a href={latestPullRequestUrl} target="_blank" rel="noreferrer" className="inline-flex items-center gap-2 rounded-md border border-green/30 bg-green/10 px-3 py-2 text-[1rem] font-semibold text-green">
                    <GitPullRequest size={14} />
                    Open Generated PR
                  </a>
                ) : fixPrSupported ? (
                  <button
                    type="button"
                    onClick={onCreateFixPr}
                    disabled={action === 'fix-pr'}
                    className="inline-flex items-center gap-2 rounded-md border border-cyan/30 bg-cyan/10 px-3 py-2 text-[1rem] font-semibold text-cyan disabled:opacity-50"
                  >
                    {action === 'fix-pr' ? <Loader2 size={14} className="animate-spin" /> : <GitPullRequest size={14} />}
                    Generate Review PR
                  </button>
                ) : (
                  <div className="rounded-md border border-border bg-bg/30 p-3 text-[0.925rem] text-muted">
                    AutoFix code suggestion is required before AegisPT can prepare a human-review PR.
                  </div>
                )}
              </div>
            </DrawerSection>
          )}

          {jiraConfigured && (
            <DrawerSection title="Push To Jira" id="push" openSections={openSections} toggleSection={toggleSection}>
              <button
                type="button"
                onClick={onJira}
                disabled={action === 'jira'}
                className="inline-flex items-center gap-2 rounded-md border border-cyan/30 bg-cyan/10 px-3 py-2 text-[1rem] font-semibold text-cyan disabled:opacity-50"
              >
                {action === 'jira' ? <Loader2 size={14} className="animate-spin" /> : <Ticket size={14} />}
                Push to Jira
              </button>
              {jiraLink(detail) && (
                <a href={jiraLink(detail) ?? undefined} target="_blank" rel="noreferrer" className="mt-3 flex items-center gap-2 text-[0.925rem] text-cyan">
                  <ExternalLink size={13} />
                  Open linked Jira issue
                </a>
              )}
            </DrawerSection>
          )}

          {chains.length > 0 && (
            <DrawerSection title="Attack Path" id="attack-path" openSections={openSections} toggleSection={toggleSection}>
              <div className="space-y-4">
                {chains.map((chain) => (
                  <div key={textValue(chain.id) || textValue(chain.title)} className="rounded-lg border border-border bg-bg/30 p-3">
                    <div className="mb-3 flex flex-wrap items-center gap-2">
                      <span className="text-[1rem] font-semibold text-text">{textValue(chain.title) || 'Evidence-linked chain'}</span>
                      <span className="rounded-full border border-border px-2 py-0.5 text-[0.77rem] text-muted">{textValue(chain.status) || 'recorded'}</span>
                    </div>
                    <div className="flex gap-2 overflow-x-auto pb-2">
                      {componentFindings(chain).map((component, index) => (
                        <div key={`${textValue(component.finding_id)}-${index}`} className="flex items-center gap-2">
                          {index > 0 && <span className="text-[0.85rem] text-muted">enabled</span>}
                          <div className="min-w-[180px] rounded-md border border-cyan/20 bg-cyan/10 p-3">
                            <SeverityBadge severity={textValue(component.severity) || 'unknown'} />
                            <div className="mt-2 line-clamp-2 text-[0.925rem] font-semibold text-text">{textValue(component.title) || textValue(component.finding_id)}</div>
                            <div className="mt-1 truncate text-[0.85rem] text-muted">{textValue(component.evidence_ref) || 'No evidence ref'}</div>
                          </div>
                        </div>
                      ))}
                    </div>
                    <p className="mt-2 text-[0.925rem] leading-5 text-muted">{textValue(chain.combined_impact) || 'Chain context is present in stored finding-chain records.'}</p>
                  </div>
                ))}
              </div>
            </DrawerSection>
          )}
        </div>
      </div>
    </aside>
  );
}

function DrawerSection({
  title,
  id,
  openSections,
  toggleSection,
  children,
}: {
  title: string;
  id: string;
  openSections: Set<string>;
  toggleSection: (id: string) => void;
  children: ReactNode;
}) {
  const open = openSections.has(id);
  return (
    <section className="rounded-lg border border-border bg-bg/25">
      <button type="button" onClick={() => toggleSection(id)} className="flex w-full items-center justify-between px-4 py-3 text-left">
        <span className="text-[0.925rem] font-bold uppercase text-text">{title}</span>
        {open ? <ChevronDown size={15} className="text-muted" /> : <ChevronRight size={15} className="text-muted" />}
      </button>
      {open && <div className="border-t border-border p-4">{children}</div>}
    </section>
  );
}

function CvssGauge({ score }: { score: number | null }) {
  const value = typeof score === 'number' ? Math.max(0, Math.min(10, score)) : null;
  const pct = value === null ? 0 : value * 10;
  return (
    <div className="rounded-lg border border-border bg-bg/30 p-3">
      <div className="mb-2 text-[0.85rem] font-bold uppercase text-muted">CVSS</div>
      <div className="flex items-end gap-2">
        <span className="text-2xl font-semibold text-text">{value === null ? 'N/A' : value.toFixed(1)}</span>
        <span className="pb-1 text-[0.85rem] text-muted">/ 10</span>
      </div>
      <div className="mt-3 h-2 overflow-hidden rounded-full bg-surface">
        <div className={cn('living-severity-bar h-full rounded-full', cvssToneClass(value))} style={{ width: `${pct}%` }} />
      </div>
    </div>
  );
}

function Metric({ label, value }: { label: string; value: number }) {
  const previousValueRef = useRef(value);
  const [popped, setPopped] = useState(false);

  useEffect(() => {
    const previousValue = previousValueRef.current;
    previousValueRef.current = value;
    if (value > previousValue) {
      setPopped(true);
      const timer = window.setTimeout(() => setPopped(false), 460);
      return () => window.clearTimeout(timer);
    }
    return undefined;
  }, [value]);

  return (
    <div className="rounded-lg border border-border bg-surface/55 px-4 py-2">
      <div className="text-[0.77rem] font-bold uppercase text-muted">{label}</div>
      <div className={cn('text-lg font-semibold text-text', popped && 'living-badge-pop')}>{value}</div>
    </div>
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
        <ShieldAlert size={28} className="living-empty-icon mx-auto mb-3 text-cyan" />
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
      <AlertTriangle size={22} className="living-empty-icon mx-auto mb-3 text-muted" />
      <h2 className="text-[1.15rem] font-semibold text-text">{title}</h2>
      <p className="mt-2 text-[1rem] text-muted">{detail}</p>
    </div>
  );
}

function SeverityBar({ severity }: { severity: string }) {
  const normalized = severity.toLowerCase();
  return (
    <div className="mt-3 h-1.5 overflow-hidden rounded-full bg-surface/80" aria-label={`${normalized || 'unknown'} severity`}>
      <div
        className={cn('living-severity-bar h-full rounded-full', severityBarClass(normalized))}
        style={{ width: `${severityPercent(normalized)}%` }}
      />
    </div>
  );
}

function SeverityBadge({ severity }: { severity: string }) {
  const normalized = severity.toLowerCase();
  return (
    <span className={cn('rounded-full border px-2 py-0.5 text-[0.77rem] font-bold uppercase', severityClass(normalized))}>
      {normalized || 'unknown'}
    </span>
  );
}

function StatusBadge({ status }: { status: string }) {
  return (
    <span className="rounded-full border border-border bg-bg/50 px-2 py-0.5 text-[0.77rem] font-semibold uppercase text-muted">
      {status === 'resolved' ? 'fixed' : status.replace(/_/g, ' ')}
    </span>
  );
}

function TruthBadge({ tone, label }: { tone: FindingTruthTone; label: string }) {
  return (
    <span className={cn('rounded-full border px-2 py-0.5 text-[0.77rem] font-semibold uppercase', truthToneClass(tone))}>
      {label}
    </span>
  );
}

function EvidenceBadge({ label, tone }: { label: string; tone: FindingTruthTone }) {
  return (
    <span className={cn('rounded-full border px-2 py-0.5 text-[0.77rem] font-semibold', evidenceToneClass(tone))}>
      {label}
    </span>
  );
}

function TruthFact({
  label,
  value,
  detail,
  tone,
}: {
  label: string;
  value: string;
  detail: string | null | undefined;
  tone: FindingTruthTone;
}) {
  return (
    <div className={cn('rounded-md border p-3', truthFactClass(tone))}>
      <div className="font-mono text-[0.62rem] uppercase tracking-widest text-muted">{label}</div>
      <div className="mt-1 text-[0.95rem] font-semibold text-text">{value}</div>
      {detail && <div className="mt-1 text-[0.78rem] leading-snug text-muted">{detail}</div>}
    </div>
  );
}

function filterFindings(findings: Finding[], severity: SeverityFilter, status: StatusFilter, query: string): Finding[] {
  const normalizedQuery = query.trim().toLowerCase();
  return findings.filter((finding) => {
    if (severity !== 'all' && finding.severity.toLowerCase() !== severity) return false;
    if (status !== 'all' && statusKey(finding.status) !== status) return false;
    if (!normalizedQuery) return true;
    const haystack = [
      finding.title,
      finding.target_id,
      finding.status,
      finding.severity,
      finding.evidence_ref,
      finding.finding_origin,
      sourceTool(finding),
    ].join(' ').toLowerCase();
    return haystack.includes(normalizedQuery);
  });
}

function groupBySeverity(findings: Finding[]): Array<{ severity: string; items: Finding[] }> {
  const groups = new Map<string, Finding[]>();
  for (const finding of findings) {
    const severity = finding.severity.toLowerCase() || 'unknown';
    groups.set(severity, [...(groups.get(severity) ?? []), finding]);
  }
  return [...groups.entries()]
    .sort(([a], [b]) => severityRank(a) - severityRank(b))
    .map(([severity, items]) => ({ severity, items }));
}

function severityRank(severity: string): number {
  return ['critical', 'high', 'medium', 'low', 'info'].indexOf(severity) === -1
    ? 99
    : ['critical', 'high', 'medium', 'low', 'info'].indexOf(severity);
}

function statusKey(status: string): StatusFilter {
  const normalized = status.toLowerCase();
  if (normalized === 'false_positive') return 'false-positive';
  if (normalized === 'resolved' || normalized === 'fixed') return 'fixed';
  if (normalized === 'open') return 'open';
  return 'all';
}

function sourceTool(finding: Finding): string {
  const recipeTool = textValue(finding.replay_recipe_json?.tool);
  if (recipeTool) return recipeTool;
  const origin = finding.finding_origin || 'runner';
  return origin.replace(/[_-]/g, ' ');
}

function technicalEvidenceText(
  evidence: FindingEvidenceReplay | null,
  detail: FindingTheaterDetail | null,
  finding: Finding,
): string {
  const execution = evidence?.related_executions?.[0];
  const stdout = execution?.stdout_excerpt?.trim();
  const stderr = execution?.stderr_excerpt?.trim();
  if (stdout || stderr) {
    return [stdout ? `stdout:\n${stdout}` : '', stderr ? `stderr:\n${stderr}` : ''].filter(Boolean).join('\n\n');
  }
  const proof = Object.keys(finding.proof_reference ?? {}).length ? JSON.stringify(finding.proof_reference, null, 2) : null;
  return [
    `evidence_ref: ${finding.evidence_ref || 'missing'}`,
    detail?.evidence_summary ? `summary: ${detail.evidence_summary}` : null,
    proof ? `proof_reference:\n${proof}` : null,
  ]
    .filter(Boolean)
    .join('\n\n');
}

function storedSha256(detail: FindingTheaterDetail | null, evidence: FindingEvidenceReplay | null): string | null {
  const integritySha = textValue(detail?.evidence_integrity?.sha256);
  if (integritySha) return integritySha;
  return evidence?.related_executions?.[0]?.artifacts?.[0]?.sha256 ?? null;
}

function chainList(detail: FindingTheaterDetail | null): JsonMap[] {
  if (!detail || !boolValue(detail.vulnerability_chains.available)) return [];
  const chains = detail.vulnerability_chains.chains;
  return Array.isArray(chains) ? chains.filter(isJsonMap) : [];
}

function componentFindings(chain: JsonMap): JsonMap[] {
  const components = chain.component_findings;
  return Array.isArray(components) ? components.filter(isJsonMap).filter((item) => !boolValue(item.missing)) : [];
}

function owaspLabel(finding: Finding, detail: FindingTheaterDetail | null): string {
  return (
    finding.owasp_category ||
    textValue(mapValue(detail?.methodology, 'owasp.category')) ||
    textValue(mapValue(detail?.methodology, 'owasp.framework')) ||
    'No OWASP category recorded'
  );
}

function jiraLink(detail: FindingTheaterDetail | null): string | null {
  const link = mapValue(detail?.remediation, 'integrations.jira.issue_url');
  return textValue(link);
}

function isJiraConfigured(settings: { sections: Array<{ settings: Array<{ key: string; value: unknown; configured: boolean }> }> } | null): boolean {
  const allSettings = settings?.sections.flatMap((section) => section.settings) ?? [];
  return allSettings.some((setting) => setting.key === 'integrations.jira_base_url' && (setting.configured || Boolean(setting.value)));
}

function mapValue(source: JsonMap | undefined, dottedPath: string): unknown {
  if (!source) return undefined;
  return dottedPath.split('.').reduce<unknown>((current, key) => {
    if (!isJsonMap(current)) return undefined;
    return current[key];
  }, source);
}

function isJsonMap(value: unknown): value is JsonMap {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function boolValue(value: unknown): boolean {
  return value === true || value === 'true';
}

function textValue(value: unknown): string | null {
  if (typeof value === 'string' && value.trim()) return value;
  if (typeof value === 'number' && Number.isFinite(value)) return String(value);
  return null;
}

function severityClass(severity: string): string {
  if (severity === 'critical') return 'border-red/40 bg-red/15 text-red';
  if (severity === 'high') return 'border-amber/40 bg-amber/15 text-amber';
  if (severity === 'medium') return 'border-yellow-300/40 bg-yellow-300/10 text-yellow-200';
  if (severity === 'low') return 'border-cyan/40 bg-cyan/10 text-cyan';
  return 'border-border bg-surface/70 text-muted';
}

function truthToneClass(tone: FindingTruthTone): string {
  if (tone === 'verified') return 'border-green/35 bg-green/10 text-green';
  if (tone === 'resolved') return 'border-cyan/35 bg-cyan/10 text-cyan';
  if (tone === 'observed') return 'border-amber/35 bg-amber/10 text-amber';
  return 'border-red/35 bg-red/10 text-red';
}

function evidenceToneClass(tone: FindingTruthTone): string {
  if (tone === 'blocked') return 'border-red/30 bg-red/10 text-red';
  if (tone === 'observed') return 'border-amber/30 bg-amber/10 text-amber';
  return 'border-border bg-surface/70 text-muted';
}

function proofStrengthClass(strength: ProofStrength): string {
  if (strength === 'strong') return 'border-green/35 bg-green/10 text-green';
  if (strength === 'partial') return 'border-amber/35 bg-amber/10 text-amber';
  return 'border-red/35 bg-red/10 text-red';
}

function truthFactClass(tone: FindingTruthTone): string {
  if (tone === 'verified') return 'border-green/25 bg-green/5';
  if (tone === 'resolved') return 'border-cyan/25 bg-cyan/5';
  if (tone === 'observed') return 'border-amber/25 bg-amber/5';
  return 'border-red/25 bg-red/5';
}

function severityBarClass(severity: string): string {
  if (severity === 'critical') return 'bg-red shadow-[0_0_0.55rem_rgba(239,68,68,0.42)]';
  if (severity === 'high') return 'bg-amber shadow-[0_0_0.45rem_rgba(251,191,36,0.34)]';
  if (severity === 'medium') return 'bg-yellow-300';
  if (severity === 'low') return 'bg-cyan';
  return 'bg-muted';
}

function severityPercent(severity: string): number {
  if (severity === 'critical') return 100;
  if (severity === 'high') return 82;
  if (severity === 'medium') return 58;
  if (severity === 'low') return 34;
  if (severity === 'info') return 18;
  return 12;
}

function cvssToneClass(score: number | null): string {
  if (score === null) return 'bg-border';
  if (score >= 9) return 'bg-red';
  if (score >= 7) return 'bg-amber';
  if (score >= 4) return 'bg-yellow-300';
  return 'bg-cyan';
}

function truncate(value: string, max: number): string {
  return value.length <= max ? value : `${value.slice(0, max - 1)}...`;
}

function titleCase(value: string): string {
  return value.replace(/(^|-)([a-z])/g, (_match, prefix: string, letter: string) => `${prefix ? ' ' : ''}${letter.toUpperCase()}`);
}

async function copyText(value: string) {
  await navigator.clipboard?.writeText(value);
}

function errorMessage(error: unknown): string {
  return safeErrorMessage(error, {
    fallback: 'Findings could not load for this run. Refresh or select another run.',
    unavailable: 'Findings are temporarily unavailable. Evidence and run history remain available for review.',
  });
}
