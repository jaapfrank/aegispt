import { useEffect, useMemo, useState } from 'react';
import type { ReactNode } from 'react';
import { AnimatePresence, motion } from 'framer-motion';
import {
  AlertTriangle,
  Bot,
  Check,
  ChevronDown,
  ChevronRight,
  Clipboard,
  ExternalLink,
  Filter,
  Hash,
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
import {
  enrichFinding,
  getFindingEvidence,
  getFindingTheater,
  getRunTheaterFindings,
  handoffFindingToJira,
  updateFindingStatus,
} from '../../api/client';
import type { Finding, FindingEvidenceReplay, FindingTheater as FindingTheaterDetail, JsonMap, UUID } from '../../api/types';
import { useAegisStore } from '../../store';

type SeverityFilter = 'all' | 'critical' | 'high' | 'medium' | 'low' | 'info';
type StatusFilter = 'all' | 'open' | 'false-positive' | 'fixed';
type DrawerAction = 'enrich' | 'fixed' | 'false-positive' | 'jira' | null;

const SEVERITIES: SeverityFilter[] = ['critical', 'high', 'medium', 'low', 'info'];
const STATUS_FILTERS: StatusFilter[] = ['all', 'open', 'false-positive', 'fixed'];
const SECTION_DEFAULTS = ['summary', 'evidence', 'ai', 'remediation', 'push', 'attack-path'];

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
  const findingCount = findings.length;
  const jiraConfigured = isJiraConfigured(settings.settings);

  useEffect(() => {
    if (!selectedRunId) {
      setFindings([]);
      selectFinding(null);
      return;
    }

    const runId = selectedRunId;
    let cancelled = false;
    async function loadFindings() {
      setLoadingFindings(true);
      setError(null);
      try {
        const payload = await getRunTheaterFindings(runId);
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
  }, [selectFinding, selectedRunId, setError, setFindings]);

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
      selectedRunId ? getRunTheaterFindings(selectedRunId) : Promise.resolve(findings),
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

  if (!selectedRunId) {
    return (
      <EmptyState
        title="No Run Selected"
        detail="Select or create a run before opening Findings Theater."
        action={<Link to="/intake" className="rounded-md border border-cyan/30 bg-cyan/10 px-4 py-2 text-[13px] font-semibold text-cyan">New Mission</Link>}
      />
    );
  }

  return (
    <section className="flex h-full min-h-0 flex-col">
      <header className="mb-5 flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold text-text">Findings Theater</h1>
          <p className="mt-1 text-[13px] text-muted">
            {selectedRun ? `${selectedRun.profile.name} · ${selectedRun.status}` : 'Selected run'} · evidence-backed findings
          </p>
        </div>
        <div className="flex gap-2">
          <Metric label="Findings" value={findingCount} />
          <Metric label="Visible" value={visibleFindings.length} />
        </div>
      </header>

      <div className={cn('grid min-h-0 flex-1 gap-5', selectedFinding ? 'xl:grid-cols-[55fr_45fr]' : 'xl:grid-cols-1')}>
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

          <div className="min-h-0 flex-1 overflow-y-auto p-4">
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
                        <span className="text-[12px] font-semibold text-muted">{items.length} findings</span>
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
            <FindingDrawer
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
            />
          )}
        </AnimatePresence>
      </div>
    </section>
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
    <div className="border-b border-border bg-[rgba(5,9,18,0.72)] p-4">
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
          <span className="mb-1 flex items-center gap-2 text-[11px] font-bold uppercase text-muted">
            <Search size={14} />
            Search
            {loading && <Loader2 size={12} className="animate-spin text-cyan" />}
          </span>
          <input
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Title, target, tool, evidence ref"
            className="h-10 w-full rounded-lg border border-border bg-surface px-3 text-[13px] text-text outline-none transition-colors placeholder:text-muted focus:border-cyan/50"
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
      <span className="mb-1 flex items-center gap-2 text-[11px] font-bold uppercase text-muted">
        {icon}
        {label}
      </span>
      <select
        value={value}
        onChange={(event) => onChange(event.target.value)}
        className="h-10 w-full rounded-lg border border-border bg-surface px-3 text-[13px] text-text outline-none transition-colors focus:border-cyan/50"
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
  const tool = sourceTool(finding);
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
          <span className="rounded-full border border-border bg-surface/70 px-2 py-0.5 text-[10px] font-semibold text-muted">
            {tool}
          </span>
          <StatusBadge status={finding.status} />
        </div>
        <div className="truncate text-[14px] font-semibold text-text">{finding.title}</div>
        <div className="mt-1 truncate text-[12px] text-muted">{truncate(finding.target_id, 30)}</div>
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
}) {
  const evidenceText = technicalEvidenceText(evidence, detail, finding);
  const storedSha = storedSha256(detail, evidence);
  const enrichment = detail?.ai_enrichment ?? {};
  const hasEnrichment = boolValue(enrichment.available);
  const chains = chainList(detail);

  return (
    <motion.aside
      initial={{ opacity: 0, x: 48 }}
      animate={{ opacity: 1, x: 0 }}
      exit={{ opacity: 0, x: 48 }}
      transition={{ duration: 0.22, ease: 'easeOut' }}
      className="min-h-0 overflow-hidden rounded-xl border border-border bg-surface/70 backdrop-blur-md"
    >
      <div className="flex h-full min-h-0 flex-col">
        <header className="border-b border-border bg-[rgba(5,9,18,0.78)] p-4">
          <div className="mb-3 flex items-start justify-between gap-3">
            <div className="min-w-0">
              <div className="mb-2 flex flex-wrap items-center gap-2">
                <SeverityBadge severity={finding.severity} />
                <StatusBadge status={finding.status} />
              </div>
              <h2 className="break-words text-lg font-semibold text-text">{finding.title}</h2>
              <p className="mt-1 break-words text-[12px] text-muted">{finding.target_id}</p>
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
          {loading && <div className="flex items-center gap-2 text-[12px] text-cyan"><Loader2 size={14} className="animate-spin" /> Loading evidence detail</div>}
          {actionMessage && <div className="rounded-md border border-cyan/20 bg-cyan/10 px-3 py-2 text-[12px] text-cyan">{actionMessage}</div>}
        </header>

        <div className="min-h-0 flex-1 space-y-3 overflow-y-auto p-4">
          <DrawerSection title="Summary" id="summary" openSections={openSections} toggleSection={toggleSection}>
            <p className="text-[13px] leading-6 text-muted">{detail?.technical_details || finding.summary || 'No summary text is available for this finding.'}</p>
            <div className="mt-4 grid gap-3 sm:grid-cols-2">
              <CvssGauge score={finding.cvss_score} />
              <div className="rounded-lg border border-border bg-bg/30 p-3">
                <div className="mb-2 text-[11px] font-bold uppercase text-muted">OWASP</div>
                <div className="text-[13px] font-semibold text-text">{owaspLabel(finding, detail)}</div>
                <div className="mt-1 text-[12px] text-muted">{finding.owasp_reference || textValue(mapValue(detail?.methodology, 'owasp.reference')) || 'No OWASP reference recorded'}</div>
              </div>
            </div>
          </DrawerSection>

          <DrawerSection title="Technical Evidence" id="evidence" openSections={openSections} toggleSection={toggleSection}>
            <div className="overflow-hidden rounded-lg border border-border bg-[#030712]">
              <div className="flex items-center justify-between border-b border-border px-3 py-2">
                <span className="flex items-center gap-2 text-[11px] font-bold uppercase text-muted">
                  <Clipboard size={13} />
                  Raw Evidence View
                </span>
                <button
                  type="button"
                  onClick={() => void copyText(evidenceText)}
                  className="rounded-md px-2 py-1 text-[11px] font-semibold text-cyan transition-colors hover:bg-cyan/10"
                >
                  Copy
                </button>
              </div>
              <pre className="max-h-[320px] overflow-auto whitespace-pre-wrap p-3 font-mono text-[12px] leading-5 text-text">{evidenceText}</pre>
            </div>
            <div className="mt-3 flex items-start gap-2 rounded-md border border-border bg-bg/30 p-3 text-[12px] text-muted">
              <Hash size={14} className="mt-0.5 text-cyan" />
              <span className="break-all">
                SHA-256: <span className="font-mono text-text">{storedSha || 'No stored artifact hash available'}</span>
              </span>
            </div>
          </DrawerSection>

          <DrawerSection title="AI Enrichment" id="ai" openSections={openSections} toggleSection={toggleSection}>
            {hasEnrichment ? (
              <div className="space-y-3 text-[13px] leading-6 text-muted">
                <p><strong className="text-text">Business impact:</strong> {textValue(enrichment.business_impact) || detail?.business_impact}</p>
                <p><strong className="text-text">Remediation:</strong> {textValue(enrichment.remediation_narrative) || textValue(mapValue(detail?.remediation, 'ai_narrative'))}</p>
              </div>
            ) : chatgptConnected ? (
              <button
                type="button"
                onClick={onEnrich}
                disabled={action === 'enrich'}
                className="inline-flex items-center gap-2 rounded-md border border-cyan/30 bg-cyan/10 px-3 py-2 text-[13px] font-semibold text-cyan disabled:opacity-50"
              >
                {action === 'enrich' ? <Loader2 size={14} className="animate-spin" /> : <Sparkles size={14} />}
                Enrich Now
              </button>
            ) : (
              <Link to="/settings" className="inline-flex items-center gap-2 rounded-md border border-border bg-bg/40 px-3 py-2 text-[13px] font-semibold text-muted hover:text-text">
                <Bot size={14} />
                Connect ChatGPT in Settings to enable
              </Link>
            )}
          </DrawerSection>

          <DrawerSection title="Remediation" id="remediation" openSections={openSections} toggleSection={toggleSection}>
            <div className="space-y-3">
              <p className="text-[13px] leading-6 text-muted">{textValue(mapValue(detail?.remediation, 'detail')) || 'Review and remediate according to the linked evidence.'}</p>
              <ol className="space-y-2">
                {(detail?.next_steps?.length ? detail.next_steps : ['Review stored evidence.', 'Apply the remediation.', 'Retest before closure.']).map((step) => (
                  <li key={step} className="rounded-md border border-border bg-bg/30 p-3 text-[12px] text-muted">{step}</li>
                ))}
              </ol>
              <div className="grid gap-2 md:grid-cols-2">
                <button
                  type="button"
                  onClick={onMarkFixed}
                  disabled={action === 'fixed'}
                  className="inline-flex items-center justify-center gap-2 rounded-md border border-green/30 bg-green/10 px-3 py-2 text-[13px] font-semibold text-green disabled:opacity-50"
                >
                  {action === 'fixed' ? <Loader2 size={14} className="animate-spin" /> : <Check size={14} />}
                  Mark as Fixed
                </button>
                <button
                  type="button"
                  onClick={onFalsePositive}
                  disabled={action === 'false-positive'}
                  className="inline-flex items-center justify-center gap-2 rounded-md border border-amber/30 bg-amber/10 px-3 py-2 text-[13px] font-semibold text-amber disabled:opacity-50"
                >
                  {action === 'false-positive' ? <Loader2 size={14} className="animate-spin" /> : <AlertTriangle size={14} />}
                  Mark as False Positive
                </button>
              </div>
              <label className="block">
                <span className="mb-1 block text-[11px] font-bold uppercase text-muted">False positive reason</span>
                <textarea
                  value={falsePositiveReason}
                  onChange={(event) => setFalsePositiveReason(event.target.value)}
                  rows={3}
                  className="w-full rounded-md border border-border bg-bg/40 p-3 text-[12px] text-text outline-none focus:border-cyan/50"
                />
              </label>
            </div>
          </DrawerSection>

          {jiraConfigured && (
            <DrawerSection title="Push To Jira" id="push" openSections={openSections} toggleSection={toggleSection}>
              <button
                type="button"
                onClick={onJira}
                disabled={action === 'jira'}
                className="inline-flex items-center gap-2 rounded-md border border-cyan/30 bg-cyan/10 px-3 py-2 text-[13px] font-semibold text-cyan disabled:opacity-50"
              >
                {action === 'jira' ? <Loader2 size={14} className="animate-spin" /> : <Ticket size={14} />}
                Push to Jira
              </button>
              {jiraLink(detail) && (
                <a href={jiraLink(detail) ?? undefined} target="_blank" rel="noreferrer" className="mt-3 flex items-center gap-2 text-[12px] text-cyan">
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
                      <span className="text-[13px] font-semibold text-text">{textValue(chain.title) || 'Evidence-linked chain'}</span>
                      <span className="rounded-full border border-border px-2 py-0.5 text-[10px] text-muted">{textValue(chain.status) || 'recorded'}</span>
                    </div>
                    <div className="flex gap-2 overflow-x-auto pb-2">
                      {componentFindings(chain).map((component, index) => (
                        <div key={`${textValue(component.finding_id)}-${index}`} className="flex items-center gap-2">
                          {index > 0 && <span className="text-[11px] text-muted">enabled</span>}
                          <div className="min-w-[180px] rounded-md border border-cyan/20 bg-cyan/10 p-3">
                            <SeverityBadge severity={textValue(component.severity) || 'unknown'} />
                            <div className="mt-2 line-clamp-2 text-[12px] font-semibold text-text">{textValue(component.title) || textValue(component.finding_id)}</div>
                            <div className="mt-1 truncate text-[11px] text-muted">{textValue(component.evidence_ref) || 'No evidence ref'}</div>
                          </div>
                        </div>
                      ))}
                    </div>
                    <p className="mt-2 text-[12px] leading-5 text-muted">{textValue(chain.combined_impact) || 'Chain context is present in stored finding-chain records.'}</p>
                  </div>
                ))}
              </div>
            </DrawerSection>
          )}
        </div>
      </div>
    </motion.aside>
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
        <span className="text-[12px] font-bold uppercase text-text">{title}</span>
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
      <div className="mb-2 text-[11px] font-bold uppercase text-muted">CVSS</div>
      <div className="flex items-end gap-2">
        <span className="text-2xl font-semibold text-text">{value === null ? 'N/A' : value.toFixed(1)}</span>
        <span className="pb-1 text-[11px] text-muted">/ 10</span>
      </div>
      <div className="mt-3 h-2 overflow-hidden rounded-full bg-surface">
        <div className={cn('h-full rounded-full', cvssToneClass(value))} style={{ width: `${pct}%` }} />
      </div>
    </div>
  );
}

function Metric({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded-lg border border-border bg-surface/55 px-4 py-2">
      <div className="text-[10px] font-bold uppercase text-muted">{label}</div>
      <div className="text-lg font-semibold text-text">{value}</div>
    </div>
  );
}

function LoadingPanel({ label }: { label: string }) {
  return (
    <div className="flex h-full min-h-[260px] items-center justify-center rounded-lg border border-border bg-bg/20 text-[13px] text-muted">
      <Loader2 size={16} className="mr-2 animate-spin text-cyan" />
      {label}
    </div>
  );
}

function EmptyState({ title, detail, action }: { title: string; detail: string; action?: ReactNode }) {
  return (
    <section className="flex h-full min-h-[520px] items-center justify-center">
      <div className="max-w-md rounded-xl border border-border bg-surface/60 p-6 text-center">
        <ShieldAlert size={28} className="mx-auto mb-3 text-cyan" />
        <h1 className="text-xl font-semibold text-text">{title}</h1>
        <p className="mt-2 text-[13px] leading-6 text-muted">{detail}</p>
        {action && <div className="mt-4">{action}</div>}
      </div>
    </section>
  );
}

function EmptyInline({ title, detail }: { title: string; detail: string }) {
  return (
    <div className="rounded-lg border border-border bg-bg/25 p-6 text-center">
      <h2 className="text-[15px] font-semibold text-text">{title}</h2>
      <p className="mt-2 text-[13px] text-muted">{detail}</p>
    </div>
  );
}

function SeverityBadge({ severity }: { severity: string }) {
  const normalized = severity.toLowerCase();
  return (
    <span className={cn('rounded-full border px-2 py-0.5 text-[10px] font-bold uppercase', severityClass(normalized))}>
      {normalized || 'unknown'}
    </span>
  );
}

function StatusBadge({ status }: { status: string }) {
  return (
    <span className="rounded-full border border-border bg-bg/50 px-2 py-0.5 text-[10px] font-semibold uppercase text-muted">
      {status === 'resolved' ? 'fixed' : status.replace(/_/g, ' ')}
    </span>
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
  if (error instanceof Error) return error.message;
  return 'AegisPT API request failed.';
}
