import { useEffect, useMemo, useState } from 'react';
import { ScrollText, WandSparkles } from 'lucide-react';
import { generateAiResearchScript, getAiResearchLab } from '../../api/client';
import type { AiResearchGeneration, AiResearchGenerationInput, AiResearchLab, ThreatIntelRecord } from '../../api/types';
import { useAegisStore } from '../../store';
import {
  ActionButton,
  EmptyState,
  Field,
  PageHeader,
  Panel,
  StatusBadge,
} from './screenPrimitives';
import { formatDate, inputClass, jsonString } from './screenUtils';

export default function ResearchScreen() {
  const selectedEngagement = useAegisStore((state) => state.selectedEngagement);
  const selectedEngagementId = useAegisStore((state) => state.selectedEngagementId);
  const [lab, setLab] = useState<AiResearchLab | null>(null);
  const [selectedRecordId, setSelectedRecordId] = useState('');
  const [description, setDescription] = useState('');
  const [outputKind, setOutputKind] = useState<AiResearchGenerationInput['output_kind']>('nuclei_yaml');
  const [generation, setGeneration] = useState<AiResearchGeneration | null>(null);
  const [loading, setLoading] = useState(false);
  const [generating, setGenerating] = useState(false);
  const [message, setMessage] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    async function loadResearch() {
      if (!selectedEngagementId) {
        setLab(null);
        setSelectedRecordId('');
        return;
      }
      setLoading(true);
      setMessage(null);
      try {
        const payload = await getAiResearchLab(selectedEngagementId);
        if (cancelled) return;
        setLab(payload);
        setSelectedRecordId((current) => current || String(payload.cve_records[0]?.id ?? ''));
      } catch (error) {
        if (!cancelled) setMessage(error instanceof Error ? error.message : 'Research lab unavailable.');
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    void loadResearch();
    return () => {
      cancelled = true;
    };
  }, [selectedEngagementId]);

  const selectedRecord = useMemo(
    () => lab?.cve_records.find((record) => String(record.id) === selectedRecordId) ?? null,
    [lab?.cve_records, selectedRecordId],
  );

  useEffect(() => {
    if (!selectedRecord || description.trim()) return;
    setDescription(recordPrompt(selectedRecord));
  }, [description, selectedRecord]);

  async function runGeneration() {
    if (!selectedEngagementId) return;
    const trimmedDescription = description.trim();
    if (!trimmedDescription) {
      setMessage('Describe the research target before generating a review draft.');
      return;
    }
    setGenerating(true);
    setMessage(null);
    setGeneration(null);
    try {
      const payload = await generateAiResearchScript({
        engagement_id: selectedEngagementId,
        description: trimmedDescription,
        output_kind: outputKind,
      });
      setGeneration(payload);
      setMessage(payload.message || `Generation returned ${payload.status}.`);
      const refreshed = await getAiResearchLab(selectedEngagementId);
      setLab(refreshed);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Research generation failed.');
    } finally {
      setGenerating(false);
    }
  }

  if (!selectedEngagementId) {
    return <EmptyState title="No engagement selected" detail="AI research is engagement-scoped and remains tied to the existing pack review lifecycle." />;
  }

  return (
    <section className="flex h-full min-h-0 flex-col">
      <PageHeader
        eyebrow="Research"
        title="AI Research"
        detail={`${selectedEngagement?.name ?? 'Selected engagement'} review-only research workspace. Generated artifacts still require validation, approval, and deployment through existing pack gates.`}
        actions={<ActionButton onClick={() => selectedEngagementId && void getAiResearchLab(selectedEngagementId).then(setLab)} loading={loading}>Refresh</ActionButton>}
      />
      {message && <div className="mb-4 rounded-md border border-cyan/25 bg-cyan/10 px-3 py-2 text-[0.925rem] leading-5 text-cyan">{message}</div>}

      <div className="grid min-h-0 flex-1 gap-5 xl:grid-cols-[420px_1fr]">
        <div className="space-y-5">
          <Panel
            title="Research Draft"
            detail={lab?.lifecycle_note ?? 'AI can draft research output; execution stays behind registered runners and explicit lifecycle gates.'}
          >
            <div className="space-y-3">
              <Field label="CVE or advisory">
                <select
                  className={inputClass}
                  value={selectedRecordId}
                  onChange={(event) => {
                    const recordId = event.target.value;
                    const record = lab?.cve_records.find((candidate) => String(candidate.id) === recordId) ?? null;
                    setSelectedRecordId(recordId);
                    setDescription(record ? recordPrompt(record) : '');
                  }}
                >
                  <option value="" className="bg-surface text-text">Manual research note</option>
                  {(lab?.cve_records ?? []).map((record) => (
                    <option key={record.id} value={record.id} className="bg-surface text-text">
                      {record.advisory_id} · {record.title}
                    </option>
                  ))}
                </select>
              </Field>
              <Field label="Output kind">
                <select className={inputClass} value={outputKind} onChange={(event) => setOutputKind(event.target.value as AiResearchGenerationInput['output_kind'])}>
                  <option value="nuclei_yaml" className="bg-surface text-text">Nuclei YAML review draft</option>
                  <option value="python_detection" className="bg-surface text-text">Python detection idea</option>
                </select>
              </Field>
              <Field label="Research description">
                <textarea
                  className={`${inputClass} min-h-[160px] py-2 leading-5`}
                  value={description}
                  onChange={(event) => setDescription(event.target.value)}
                  placeholder="Describe the advisory, canary evidence goal, affected product, and safe detection approach."
                />
              </Field>
              <ActionButton onClick={() => void runGeneration()} loading={generating} disabled={!description.trim()}>
                <WandSparkles size={14} />Generate review draft
              </ActionButton>
            </div>
          </Panel>

          <Panel title="Threat Intel Records" detail={`${lab?.cve_records.length ?? 0} records available for this engagement.`}>
            {lab?.cve_records.length ? (
              <div className="max-h-[38vh] space-y-2 overflow-y-auto pr-1">
                {lab.cve_records.map((record) => (
                  <button
                    key={record.id}
                    type="button"
                    onClick={() => {
                      setSelectedRecordId(record.id);
                      setDescription(recordPrompt(record));
                    }}
                    className={`w-full rounded-lg border p-3 text-left transition-colors ${record.id === selectedRecordId ? 'border-cyan/40 bg-cyan/10' : 'border-border bg-bg/30 hover:border-cyan/25'}`}
                  >
                    <div className="flex items-center justify-between gap-3">
                      <span className="truncate text-[1rem] font-semibold text-text">{record.advisory_id}</span>
                      <StatusBadge value={record.severity ?? 'unknown'} />
                    </div>
                    <p className="mt-2 line-clamp-2 text-[0.925rem] leading-5 text-muted">{record.title}</p>
                  </button>
                ))}
              </div>
            ) : (
              <EmptyState title="No threat intel records" detail="Import or synchronize threat intel before using CVE-backed research drafting." />
            )}
          </Panel>
        </div>

        <div className="space-y-5">
          <Panel title="Generation Result" detail="Results are review artifacts, not deployed runtime behavior.">
            {generation ? (
              <div className="space-y-4">
                <div className="grid gap-3 md:grid-cols-3">
                  <Mini label="Status" value={generation.status} />
                  <Mini label="Pack" value={generation.pack_id ? String(generation.pack_id) : 'not created'} />
                  <Mini label="Artifact" value={generation.artifact_id ? String(generation.artifact_id) : 'not created'} />
                </div>
                <div className="rounded-lg border border-border bg-bg/35 p-3">
                  <div className="mb-2 flex items-center gap-2 text-[0.925rem] font-semibold text-text">
                    <ScrollText size={14} className="text-cyan" />Validation
                  </div>
                  <pre className="max-h-[180px] overflow-auto text-[0.85rem] leading-5 text-muted">{JSON.stringify(generation.validation, null, 2)}</pre>
                </div>
                {(generation.template_yaml || generation.yaml_diff) && (
                  <pre className="max-h-[360px] overflow-auto rounded-lg border border-border bg-bg/70 p-3 text-[0.85rem] leading-5 text-muted">
                    {generation.template_yaml ?? generation.yaml_diff}
                  </pre>
                )}
              </div>
            ) : (
              <EmptyState title="No generation yet" detail="Generate a review draft to see provider status, validation output, and lifecycle references." />
            )}
          </Panel>

          <Panel title="Research Proposal Log" detail={`${lab?.research_proposals.length ?? 0} proposal records from existing pack provenance.`}>
            {lab?.research_proposals.length ? (
              <div className="max-h-[58vh] space-y-2 overflow-y-auto pr-1">
                {lab.research_proposals.map((proposal) => (
                  <div key={proposal.id} className="rounded-lg border border-border bg-bg/30 p-3">
                    <div className="flex flex-wrap items-center justify-between gap-3">
                      <div className="min-w-0">
                        <div className="truncate text-[1rem] font-semibold text-text">{proposal.title}</div>
                        <div className="mt-1 text-[0.925rem] text-muted">{proposal.advisory_id ?? proposal.source} · {formatDate(proposal.created_at)}</div>
                      </div>
                      <div className="flex flex-wrap gap-2">
                        <StatusBadge value={proposal.status} />
                        <StatusBadge value={proposal.pack_status} />
                      </div>
                    </div>
                    {proposal.description && <p className="mt-2 line-clamp-2 text-[0.925rem] leading-5 text-muted">{proposal.description}</p>}
                    {proposal.safety_notes.length > 0 && (
                      <div className="mt-2 text-[0.85rem] leading-5 text-muted">{proposal.safety_notes.join(' · ')}</div>
                    )}
                  </div>
                ))}
              </div>
            ) : (
              <EmptyState title="No proposals" detail="Research proposals appear after provider-backed generation creates review artifacts through the governed API." />
            )}
          </Panel>
        </div>
      </div>
    </section>
  );
}

function recordPrompt(record: ThreatIntelRecord): string {
  const products = record.affected_products_json.length ? `Affected products: ${record.affected_products_json.join(', ')}.` : '';
  const patterns = record.suggested_test_patterns_json.length ? `Suggested safe patterns: ${record.suggested_test_patterns_json.join(', ')}.` : '';
  return [record.advisory_id, record.title, jsonString(record.summary, ''), products, patterns].filter(Boolean).join('\n');
}

function Mini({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-lg border border-border bg-bg/30 p-3">
      <div className="text-[0.77rem] font-bold uppercase text-muted">{label}</div>
      <div className="mt-1 truncate font-mono text-[0.85rem] text-text">{value}</div>
    </div>
  );
}
