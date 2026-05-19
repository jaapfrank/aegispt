import { useEffect, useMemo, useState } from 'react';
import { Boxes, CircleDot, Network, Play, Search } from 'lucide-react';
import { getLatestEngagementInventory, simulateAttackPaths } from '../../api/client';
import type { AttackPathSimulation, InventorySnapshot, JsonMap } from '../../api/types';
import { useAegisStore } from '../../store';
import { EmptyState, Field, MetricCard, PageHeader, Panel, StatusBadge } from './screenPrimitives';
import { inputClass, jsonString } from './screenUtils';

type SurfaceTab = 'assets' | 'attack-map' | 'simulation' | 'insights';

export default function SurfaceMap() {
  const selectedEngagement = useAegisStore((state) => state.selectedEngagement);
  const selectedEngagementId = useAegisStore((state) => state.selectedEngagementId);
  const selectedRunId = useAegisStore((state) => state.selectedRunId);
  const findings = useAegisStore((state) => state.findings);
  const [snapshot, setSnapshot] = useState<InventorySnapshot | null>(null);
  const [activeTab, setActiveTab] = useState<SurfaceTab>('assets');
  const [query, setQuery] = useState('');
  const [startingPoint, setStartingPoint] = useState('Assume CEO laptop is compromised');
  const [simulation, setSimulation] = useState<AttackPathSimulation | null>(null);
  const [simulating, setSimulating] = useState(false);
  const [message, setMessage] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    async function loadInventory() {
      if (!selectedEngagementId) {
        setSnapshot(null);
        return;
      }
      try {
        const payload = await getLatestEngagementInventory(selectedEngagementId);
        if (!cancelled) setSnapshot(payload);
      } catch (error) {
        if (!cancelled) setMessage(error instanceof Error ? error.message : 'Inventory endpoint unavailable.');
      }
    }
    void loadInventory();
    return () => {
      cancelled = true;
    };
  }, [selectedEngagementId]);

  const assets = useMemo(() => extractAssets(snapshot), [snapshot]);
  const filteredAssets = assets.filter((asset) => `${asset.host} ${asset.services.join(' ')} ${asset.endpoints.join(' ')}`.toLowerCase().includes(query.toLowerCase()));
  const findingCountByTarget = useMemo(() => {
    const counts = new Map<string, number>();
    findings.forEach((finding) => counts.set(finding.target_id, (counts.get(finding.target_id) ?? 0) + 1));
    return counts;
  }, [findings]);

  async function runSimulation() {
    if (!selectedRunId) {
      setMessage('Select a run before running predictive simulation.');
      return;
    }
    setSimulating(true);
    setMessage(null);
    try {
      setSimulation(await simulateAttackPaths(selectedRunId, startingPoint));
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Predictive simulation unavailable.');
    } finally {
      setSimulating(false);
    }
  }

  if (!selectedEngagementId) {
    return <EmptyState title="No engagement selected" detail="Surface Map needs an engagement so it can read the latest inventory snapshot." />;
  }

  return (
    <section className="flex h-full min-h-0 flex-col">
      <PageHeader
        eyebrow="Inventory"
        title="Surface Map"
        detail={`${selectedEngagement?.name ?? 'Selected engagement'} asset and endpoint view from stored inventory evidence.`}
      />
      {message && <div className="mb-4 rounded-md border border-amber/30 bg-amber/10 px-3 py-2 text-[0.925rem] text-amber">{message}</div>}

      <div className="mb-5 flex gap-1 overflow-x-auto rounded-lg border border-border bg-surface/55 p-1">
        {[
          ['assets', 'Assets'],
          ['attack-map', 'Attack Map'],
          ['simulation', 'Simulation'],
          ['insights', 'Insights'],
        ].map(([id, label]) => (
          <button key={id} type="button" onClick={() => setActiveTab(id as SurfaceTab)} className={`rounded-md px-3 py-2 text-[1rem] font-semibold ${activeTab === id ? 'bg-cyan/10 text-cyan' : 'text-muted hover:bg-bg/40 hover:text-text'}`}>
            {label}
          </button>
        ))}
      </div>

      {activeTab === 'assets' && (
        <Panel title="Assets" detail={`${filteredAssets.length} visible from latest inventory snapshot.`}>
          <Field label="Search">
            <div className="relative mb-4">
              <Search size={14} className="pointer-events-none absolute left-3 top-3 text-muted" />
              <input className={`${inputClass} pl-9`} value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Host, service, endpoint" />
            </div>
          </Field>
          {filteredAssets.length ? (
            <div className="max-h-[62vh] overflow-auto">
              <table className="min-w-[760px] w-full text-left text-[0.925rem]">
                <thead className="sticky top-0 bg-surface text-[0.77rem] uppercase tracking-wider text-muted">
                  <tr>
                    <th className="px-3 py-3">Host</th>
                    <th className="px-3 py-3">Services</th>
                    <th className="px-3 py-3">Endpoints</th>
                    <th className="px-3 py-3">Findings</th>
                    <th className="px-3 py-3">Confidence</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredAssets.map((asset) => (
                    <tr key={asset.host} className="border-t border-border">
                      <td className="px-3 py-3 font-semibold text-text">{asset.host}</td>
                      <td className="px-3 py-3 text-muted">{asset.services.join(', ') || 'n/a'}</td>
                      <td className="px-3 py-3 text-muted">{asset.endpoints.slice(0, 3).join(', ') || 'n/a'}</td>
                      <td className="px-3 py-3"><StatusBadge value={`${findingCountByTarget.get(asset.host) ?? 0} findings`} /></td>
                      <td className="px-3 py-3 text-muted">{Math.round(asset.confidence * 100)}%</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <EmptyState title="No assets" detail="The latest inventory snapshot did not expose hosts or endpoints for this engagement." />
          )}
        </Panel>
      )}

      {activeTab === 'attack-map' && (
        <Panel title="Static Attack Map" detail="A non-animated SVG map from stored inventory and finding links only.">
          <StaticMap assets={filteredAssets.length ? filteredAssets : assets} findingCountByTarget={findingCountByTarget} />
        </Panel>
      )}

      {activeTab === 'simulation' && (
        <Panel title="Simulation Mode" detail="Read-only hypothetical paths are separate from evidence-backed attack paths.">
          <div className="grid gap-3 lg:grid-cols-[minmax(0,0.8fr)_minmax(0,1.2fr)]">
            <div className="rounded-lg border border-border bg-bg/30 p-3">
              <Field label="Starting Point">
                <input className={inputClass} value={startingPoint} onChange={(event) => setStartingPoint(event.target.value)} placeholder="Assume CEO laptop is compromised" />
              </Field>
              <button
                type="button"
                onClick={() => void runSimulation()}
                disabled={simulating}
                className="mt-3 inline-flex items-center gap-2 rounded-md border border-amber/30 bg-amber/10 px-3 py-2 text-[1rem] font-semibold text-amber transition-colors hover:bg-amber/15 disabled:cursor-not-allowed disabled:opacity-55"
              >
                <Play size={14} />
                {simulating ? 'Simulating' : 'Simulate'}
              </button>
              <p className="mt-3 text-[0.925rem] leading-5 text-muted">
                {jsonString(simulation?.boundary?.mode, 'No simulation has been run for the selected run.')}
              </p>
            </div>
            <div className="space-y-3">
              {simulation?.simulated_paths.length ? (
                simulation.simulated_paths.map((path) => (
                  <div key={jsonString(path.id)} className="rounded-lg border border-dashed border-amber/45 bg-amber/10 p-3">
                    <div className="flex items-center justify-between gap-3">
                      <div className="text-[1rem] font-semibold text-text">{jsonString(path.target_label, 'Critical target')}</div>
                      <StatusBadge value="hypothetical" />
                    </div>
                    <div className="mt-2 flex flex-wrap gap-2">
                      {(Array.isArray(path.labels) ? path.labels : []).map((label, index) => (
                        <span key={`${String(label)}-${index}`} className="rounded-full border border-amber/25 px-2 py-0.5 text-[0.77rem] font-semibold uppercase text-amber">
                          {jsonString(label)}
                        </span>
                      ))}
                    </div>
                    <p className="mt-2 text-[0.925rem] leading-5 text-muted">{jsonString(path.explanation)}</p>
                  </div>
                ))
              ) : (
                <EmptyState title="No simulated paths" detail="Run a simulation from a hypothetical starting point to see possible routes to critical assets." />
              )}
            </div>
          </div>
        </Panel>
      )}

      {activeTab === 'insights' && (
        <div className="grid gap-3 md:grid-cols-4">
          <MetricCard icon={<Boxes size={15} />} label="Hosts" value={assets.length} />
          <MetricCard icon={<Network size={15} />} label="Services" value={assets.reduce((total, asset) => total + asset.services.length, 0)} />
          <MetricCard icon={<CircleDot size={15} />} label="Endpoints" value={assets.reduce((total, asset) => total + asset.endpoints.length, 0)} />
          <MetricCard icon={<CircleDot size={15} />} label="Findings" value={findings.length} detail="Selected-run findings mapped by target where possible" />
        </div>
      )}
    </section>
  );
}

function extractAssets(snapshot: InventorySnapshot | null) {
  const normalized = (snapshot?.normalized_inventory_json ?? {}) as JsonMap;
  const hosts = arrayOfMaps(normalized.hosts);
  const services = arrayOfMaps(normalized.services);
  const endpoints = arrayOfMaps(normalized.http_endpoints);
  const hostNames = new Set<string>();
  hosts.forEach((host) => hostNames.add(jsonString(host.host, 'unknown')));
  services.forEach((service) => hostNames.add(jsonString(service.host, 'unknown')));
  endpoints.forEach((endpoint) => {
    const url = jsonString(endpoint.url, '');
    try {
      if (url) hostNames.add(new URL(url).host);
    } catch {
      if (url) hostNames.add(url);
    }
  });
  return [...hostNames].filter((host) => host !== 'unknown').map((host) => ({
    host,
    confidence: Math.max(...hosts.filter((item) => item.host === host).map((item) => typeof item.confidence === 'number' ? item.confidence : 0.5), 0.5),
    services: services.filter((item) => item.host === host).map((item) => `${jsonString(item.service, 'service')}:${String(item.port ?? '?')}`),
    endpoints: endpoints.filter((item) => {
      const url = jsonString(item.url, '');
      return url.includes(host);
    }).map((item) => jsonString(item.url)),
  }));
}

function arrayOfMaps(value: unknown): JsonMap[] {
  return Array.isArray(value) ? value.filter((item): item is JsonMap => typeof item === 'object' && item !== null) : [];
}

function StaticMap({ assets, findingCountByTarget }: { assets: ReturnType<typeof extractAssets>; findingCountByTarget: Map<string, number> }) {
  if (!assets.length) return <EmptyState title="No map data" detail="No inventory hosts are available for static map rendering." />;
  const width = 760;
  const height = 360;
  const columns = Math.min(4, Math.max(1, Math.ceil(Math.sqrt(assets.length))));
  return (
    <div className="overflow-x-auto">
      <svg width={width} height={height} role="img" aria-label="Static surface map" className="min-w-[760px] rounded-lg border border-border bg-bg/30">
        {assets.map((asset, index) => {
          const col = index % columns;
          const row = Math.floor(index / columns);
          const x = 90 + col * 180;
          const y = 80 + row * 120;
          const findings = findingCountByTarget.get(asset.host) ?? 0;
          return (
            <g key={asset.host}>
              {index > 0 && <line x1={90} y1={80} x2={x} y2={y} stroke="rgba(120,177,212,0.22)" strokeWidth="1" />}
              <circle cx={x} cy={y} r={28} fill={findings ? 'rgba(239,68,68,0.18)' : 'rgba(94,207,255,0.14)'} stroke={findings ? '#ef4444' : '#5ecfff'} />
              <text x={x} y={y + 48} textAnchor="middle" fill="#e4eeff" fontSize="11">{asset.host.slice(0, 22)}</text>
              {findings > 0 && <text x={x} y={y + 4} textAnchor="middle" fill="#ef4444" fontSize="12" fontWeight="700">{findings}</text>}
            </g>
          );
        })}
      </svg>
    </div>
  );
}
