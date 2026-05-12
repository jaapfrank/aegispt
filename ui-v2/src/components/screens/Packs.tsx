import { useEffect, useState, useCallback } from 'react';
import { Box, Check, Rocket, ShieldCheck } from 'lucide-react';
import { approvePack, deployPack, getEngagementPacks, getPackArtifacts, validatePack } from '../../api/client';
import type { CapabilityPack, CapabilityPackArtifact, UUID } from '../../api/types';
import { useAegisStore } from '../../store';
import { ActionButton, EmptyState, PageHeader, Panel, StatusBadge } from './screenPrimitives';
import { formatDate } from './screenUtils';

type PackAction = 'validate' | 'approve' | 'deploy' | null;

export default function PacksScreen() {
  const selectedEngagement = useAegisStore((state) => state.selectedEngagement);
  const selectedEngagementId = useAegisStore((state) => state.selectedEngagementId);
  const [packs, setPacks] = useState<CapabilityPack[]>([]);
  const [selectedPackId, setSelectedPackId] = useState<UUID | null>(null);
  const [artifacts, setArtifacts] = useState<CapabilityPackArtifact[]>([]);
  const [loading, setLoading] = useState(false);
  const [action, setAction] = useState<PackAction>(null);
  const [message, setMessage] = useState<string | null>(null);

  const loadPacks = useCallback(async () => {
    if (!selectedEngagementId) {
      setPacks([]);
      setSelectedPackId(null);
      return;
    }
    setLoading(true);
    setMessage(null);
    try {
      const payload = await getEngagementPacks(selectedEngagementId);
      setPacks(payload);
      setSelectedPackId((current) => current && payload.some((pack) => pack.id === current) ? current : payload[0]?.id ?? null);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Pack list unavailable.');
      setPacks([]);
    } finally {
      setLoading(false);
    }
  }, [selectedEngagementId]);

  useEffect(() => {
    void loadPacks();
  }, [loadPacks]);

  useEffect(() => {
    if (!selectedPackId) {
      setArtifacts([]);
      return;
    }
    const packId = selectedPackId;
    let cancelled = false;
    async function loadArtifacts() {
      try {
        const payload = await getPackArtifacts(packId);
        if (!cancelled) setArtifacts(payload);
      } catch (error) {
        if (!cancelled) setMessage(error instanceof Error ? error.message : 'Pack artifacts unavailable.');
      }
    }
    void loadArtifacts();
    return () => {
      cancelled = true;
    };
  }, [selectedPackId]);

  async function runAction(kind: Exclude<PackAction, null>) {
    if (!selectedPackId || !selectedEngagementId) return;
    setAction(kind);
    try {
      if (kind === 'validate') {
        const result = await validatePack(selectedPackId);
        setMessage(`Validation ${result.status}: ${result.summary ?? 'no summary returned'}`);
      } else if (kind === 'approve') {
        const result = await approvePack(selectedPackId);
        setMessage(`Pack ${result.name} is now ${result.status}.`);
      } else {
        const result = await deployPack(selectedPackId, selectedEngagementId);
        setMessage(`Deployment ${result.status} recorded through existing pack lifecycle.`);
      }
      await loadPacks();
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Pack lifecycle action failed.');
    } finally {
      setAction(null);
    }
  }

  const selectedPack = packs.find((pack) => pack.id === selectedPackId) ?? null;

  if (!selectedEngagementId) {
    return <EmptyState title="No engagement selected" detail="Capability packs are engagement-scoped in the current backend contract." />;
  }

  return (
    <section className="flex h-full min-h-0 flex-col">
      <PageHeader
        eyebrow="Build Lane"
        title="Packs"
        detail={`${selectedEngagement?.name ?? 'Selected engagement'} capability packs from the existing governed pack lifecycle.`}
        actions={<ActionButton onClick={() => void loadPacks()} loading={loading}>Refresh</ActionButton>}
      />
      {message && <div className="mb-4 rounded-md border border-cyan/25 bg-cyan/10 px-3 py-2 text-[0.925rem] text-cyan">{message}</div>}

      <div className="grid min-h-0 flex-1 gap-5 xl:grid-cols-[380px_1fr]">
        <Panel title="Pack List" detail={`${packs.length} packs for selected engagement`}>
          {packs.length ? (
            <div className="max-h-[70vh] space-y-2 overflow-y-auto pr-1">
              {packs.map((pack) => (
                <button
                  type="button"
                  key={pack.id}
                  onClick={() => setSelectedPackId(pack.id)}
                  className={`w-full rounded-lg border p-3 text-left transition-colors ${pack.id === selectedPackId ? 'border-cyan/40 bg-cyan/10' : 'border-border bg-bg/30 hover:border-cyan/25'}`}
                >
                  <div className="flex items-center justify-between gap-3">
                    <span className="truncate text-[1rem] font-semibold text-text">{pack.name}</span>
                    <StatusBadge value={pack.status} />
                  </div>
                  <div className="mt-2 text-[0.925rem] text-muted">v{pack.version} · {formatDate(pack.created_at)}</div>
                  <div className="mt-2 flex flex-wrap gap-1">
                    {pack.methodology_tags.slice(0, 4).map((tag) => <span key={tag} className="rounded-full bg-bg/50 px-2 py-0.5 text-[0.77rem] text-muted">{tag}</span>)}
                  </div>
                </button>
              ))}
            </div>
          ) : (
            <EmptyState title="No packs" detail="No capability packs exist for this engagement yet." />
          )}
        </Panel>

        <Panel
          title={selectedPack?.name ?? 'Pack Detail'}
          detail={selectedPack ? selectedPack.description ?? 'No description supplied.' : 'Select a pack to review artifacts.'}
          action={selectedPack && (
            <div className="flex flex-wrap gap-2">
              <ActionButton onClick={() => void runAction('validate')} loading={action === 'validate'}><ShieldCheck size={14} />Validate</ActionButton>
              <ActionButton onClick={() => void runAction('approve')} loading={action === 'approve'} tone="green"><Check size={14} />Approve</ActionButton>
              <ActionButton onClick={() => void runAction('deploy')} loading={action === 'deploy'} tone="amber"><Rocket size={14} />Deploy</ActionButton>
            </div>
          )}
        >
          {selectedPack ? (
            <div className="space-y-4">
              <div className="grid gap-3 md:grid-cols-3">
                <Mini label="Status" value={selectedPack.status} />
                <Mini label="Generated by" value={selectedPack.generated_by} />
                <Mini label="Mode" value={selectedPack.generation_mode} />
              </div>
              <div className="space-y-2">
                {artifacts.length ? artifacts.map((artifact) => (
                  <details key={artifact.id} className="rounded-lg border border-border bg-bg/30 p-3">
                    <summary className="cursor-pointer list-none">
                      <div className="flex items-center justify-between gap-3">
                        <div className="min-w-0">
                          <div className="truncate text-[1rem] font-semibold text-text"><Box size={14} className="mr-2 inline text-cyan" />{artifact.logical_name}</div>
                          <div className="mt-1 text-[0.925rem] text-muted">{artifact.artifact_type} · {artifact.checksum_sha256.slice(0, 12)}</div>
                        </div>
                        <StatusBadge value={artifact.status} />
                      </div>
                    </summary>
                    <pre className="mt-3 max-h-[260px] overflow-auto rounded-md border border-border bg-bg/60 p-3 text-[0.85rem] leading-5 text-muted">{artifact.content_text ?? JSON.stringify(artifact.content_json ?? artifact.provenance_json, null, 2)}</pre>
                  </details>
                )) : <EmptyState title="No artifacts" detail="The selected pack has no artifacts returned by the backend." />}
              </div>
            </div>
          ) : (
            <EmptyState title="No pack selected" detail="Select a pack to review artifacts and lifecycle controls." />
          )}
        </Panel>
      </div>
    </section>
  );
}

function Mini({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-lg border border-border bg-bg/30 p-3">
      <div className="text-[0.77rem] font-bold uppercase text-muted">{label}</div>
      <div className="mt-1 truncate text-[1rem] font-semibold text-text">{value}</div>
    </div>
  );
}