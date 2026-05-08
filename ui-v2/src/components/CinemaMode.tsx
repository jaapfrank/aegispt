import { useEffect, useMemo, useRef, useState } from 'react';
import { Canvas, useFrame } from '@react-three/fiber';
import { Bloom, EffectComposer } from '@react-three/postprocessing';
import { Html, Line, Sphere, Text } from '@react-three/drei';
import { X } from 'lucide-react';
import * as THREE from 'three';
import { getRun, getTaskDetail } from '../api/client';
import type { Finding, InventorySnapshot, JsonMap, Task, TaskDetail, UUID } from '../api/types';
import { useAegisStore } from '../store';

const POLL_MS = 4000;
const FONT_URL = '/fonts/FiraMono-Regular.ttf';
const ACTIVE_STATUSES = new Set(['queued', 'requested', 'dispatching', 'running']);

type EventLog = {
  id: string;
  tool: string;
  target: string;
  msg: string;
  status: string;
  createdAt: string | null;
};

type CinemaNode = {
  id: string;
  label: string;
  position: THREE.Vector3;
  color: string;
  severity: 'critical' | 'high' | 'none';
  findingCount: number;
  waiting: boolean;
};

function Terminal3D({ logs }: { logs: EventLog[] }) {
  const visibleLogs = logs.length
    ? logs
    : [{ id: 'waiting', tool: 'SYSTEM', target: 'run', msg: 'Waiting for task stdout evidence', status: 'waiting', createdAt: null }];

  return (
    <group position={[-25, 10, -30]} rotation={[0, Math.PI / 6, 0]}>
      <Text position={[0, 2, 0]} fontSize={1.5} color="#5ecfff" anchorX="left" font={FONT_URL}>
        AEGISPT // SYSTEM.STDOUT
        <meshBasicMaterial attach="material" toneMapped={false} />
      </Text>
      {visibleLogs.map((log, i) => {
        const isLatest = i === 0 && logs.length > 0;
        return (
          <Text
            key={log.id}
            position={[0, -i * 1.8, 0]}
            fontSize={isLatest ? 1.2 : 1}
            color={isLatest ? '#e4eeff' : 'rgba(120,177,212,0.55)'}
            anchorX="left"
            font={FONT_URL}
          >
            {`[${log.tool}] ${truncate(log.target, 28)} -> ${truncate(log.msg, 88)}`}
            <meshBasicMaterial attach="material" toneMapped={false} />
          </Text>
        );
      })}
    </group>
  );
}

function Network({
  activeEvent,
  activeIndex,
  logs,
  nodes,
}: {
  activeEvent: EventLog | null;
  activeIndex: number;
  logs: EventLog[];
  nodes: CinemaNode[];
}) {
  const lines = useMemo(() => {
    const edges: [THREE.Vector3, THREE.Vector3][] = [];
    for (let index = 1; index < nodes.length; index += 1) {
      edges.push([nodes[index - 1].position, nodes[index].position]);
    }
    if (nodes.length > 2) {
      edges.push([nodes[0].position, nodes[nodes.length - 1].position]);
    }
    return edges;
  }, [nodes]);

  const desiredPosition = useMemo(() => new THREE.Vector3(), []);
  const lookAtVec = useMemo(() => new THREE.Vector3(), []);
  const orbitCenter = useMemo(() => new THREE.Vector3(0, 0, 0), []);

  useFrame((state) => {
    const targetNode = nodes[activeIndex] ?? null;
    if (targetNode && !targetNode.waiting) {
      desiredPosition.copy(targetNode.position).add(new THREE.Vector3(5, 3, 12));
      state.camera.position.lerp(desiredPosition, 0.025);
      lookAtVec.lerp(targetNode.position, 0.05);
      state.camera.lookAt(lookAtVec);
      return;
    }

    const elapsed = state.clock.getElapsedTime() * 0.12;
    desiredPosition.set(Math.cos(elapsed) * 70, 18, Math.sin(elapsed) * 70);
    state.camera.position.lerp(desiredPosition, 0.01);
    lookAtVec.lerp(orbitCenter, 0.025);
    state.camera.lookAt(lookAtVec);
  });

  return (
    <group>
      <Terminal3D logs={logs} />

      {lines.map((points, index) => (
        <Line key={index} points={points} color="#0ea5e9" opacity={0.15} lineWidth={1} transparent />
      ))}

      {nodes.map((node, index) => {
        const isActive = index === activeIndex && !node.waiting;
        const nodeColor = isActive ? '#fbbf24' : node.color;
        return (
          <group key={node.id} position={node.position}>
            <Sphere args={[isActive ? 0.7 : node.waiting ? 0.45 : 0.28, 24, 24]}>
              <meshBasicMaterial color={nodeColor} toneMapped={false} />
            </Sphere>

            {node.findingCount > 0 && (
              <Sphere args={[isActive ? 1.15 : 0.85, 24, 24]}>
                <meshBasicMaterial color={node.color} transparent opacity={0.14} toneMapped={false} />
              </Sphere>
            )}

            <Text
              position={[0, isActive ? 2.15 : 1.35, 0]}
              fontSize={isActive ? 1.45 : 0.95}
              color={nodeColor}
              anchorX="center"
              anchorY="middle"
              font={FONT_URL}
            >
              {truncate(node.label, 30)}
              <meshBasicMaterial attach="material" toneMapped={false} color={nodeColor} />
            </Text>

            {node.findingCount > 0 && (
              <Text position={[0, -1.35, 0]} fontSize={0.8} color={node.color} anchorX="center" anchorY="middle" font={FONT_URL}>
                {`${node.findingCount} FINDINGS`}
                <meshBasicMaterial attach="material" toneMapped={false} color={node.color} />
              </Text>
            )}

            {isActive && activeEvent && (
              <Html position={[2, 0, 0]} center className="pointer-events-none">
                <div className="min-w-[250px] rounded border border-amber/40 bg-[rgba(10,18,31,0.92)] p-3 shadow-[0_0_20px_rgba(251,191,36,0.2)] backdrop-blur-md">
                  <div className="mb-1 flex items-center gap-2">
                    <div className="h-1.5 w-1.5 animate-pulse rounded-full bg-amber" />
                    <span className="text-[0.77rem] font-bold uppercase tracking-widest text-amber">
                      {activeEvent.tool} ACTIVE
                    </span>
                  </div>
                  <div className="font-cinema text-xs text-text">{activeEvent.msg}</div>
                </div>
              </Html>
            )}
          </group>
        );
      })}
    </group>
  );
}

export default function CinemaMode({ onClose }: { onClose: () => void }) {
  const selectedRunId = useAegisStore((state) => state.selectedRunId);
  const selectedRun = useAegisStore((state) => state.selectedRun);
  const storeTasks = useAegisStore((state) => state.tasks);
  const inventory = useAegisStore((state) => state.inventory);
  const findings = useAegisStore((state) => state.findings);
  const proposals = useAegisStore((state) => state.proposals);
  const setSelectedRun = useAegisStore((state) => state.setSelectedRun);
  const setTasks = useAegisStore((state) => state.setTasks);

  const [logs, setLogs] = useState<EventLog[]>([]);
  const [pollState, setPollState] = useState<'connected' | 'waiting' | 'error'>('waiting');
  const [pollMessage, setPollMessage] = useState('Waiting for run data');
  const fingerprints = useRef<Map<UUID, string>>(new Map());

  const nodes = useMemo(() => buildNodes(inventory, findings), [findings, inventory]);
  const activeEvent = logs[0] ?? eventFromTasks(storeTasks);
  const activeTargetIndex = useMemo(
    () => (activeEvent ? findNodeIndexForTarget(nodes, activeEvent.target) : -1),
    [activeEvent, nodes],
  );
  const activeTask = useMemo(() => selectActiveTask(storeTasks), [storeTasks]);
  const stats = useMemo(
    () => ({
      critical: findings.filter((finding) => finding.severity.toLowerCase() === 'critical').length,
      high: findings.filter((finding) => finding.severity.toLowerCase() === 'high').length,
      hosts: nodes.filter((node) => !node.waiting).length,
      proposals: proposals.filter((proposal) => proposal.status === 'pending').length,
    }),
    [findings, nodes, proposals],
  );

  useEffect(() => {
    if (!selectedRunId) {
      setPollState('waiting');
      setPollMessage('No selected run');
      return;
    }

    const runId = selectedRunId;
    let cancelled = false;

    async function pollRunTasks() {
      try {
        const run = await getRun(runId);
        if (cancelled) return;
        setSelectedRun(run);
        setTasks(run.tasks ?? []);

        const details = await Promise.all((run.tasks ?? []).slice(0, 18).map((task) => getTaskDetail(task.id).catch(() => null)));
        if (cancelled) return;

        const newEvents = details
          .map((detail) => (detail ? eventFromTaskDetail(detail) : null))
          .filter((event): event is EventLog => Boolean(event))
          .filter((event) => {
            const previous = fingerprints.current.get(event.id);
            const next = `${event.target}|${event.msg}|${event.status}`;
            fingerprints.current.set(event.id, next);
            return previous !== next;
          });

        if (newEvents.length > 0) {
          setLogs((current) => [...newEvents.reverse(), ...current].slice(0, 10));
        }
        setPollState('connected');
        setPollMessage(`Polling real task evidence for ${run.profile.name}`);
      } catch (error) {
        if (!cancelled) {
          setPollState('error');
          setPollMessage(error instanceof Error ? error.message : 'Task polling failed');
        }
      }
    }

    void pollRunTasks();
    const timer = window.setInterval(() => void pollRunTasks(), POLL_MS);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [selectedRunId, setSelectedRun, setTasks]);

  return (
    <div className="fixed inset-0 z-[999] select-none overflow-hidden bg-[#020408]">
      <div className="absolute left-8 top-8 z-10 flex items-center gap-4">
        <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-cyan text-sm font-extrabold text-[#04080f] shadow-[0_0_20px_rgba(94,207,255,0.6)]">
          AP
        </div>
        <div>
          <h2 className="text-base font-bold uppercase tracking-widest text-cyan drop-shadow-[0_0_5px_rgba(94,207,255,0.8)]">
            Live Cinema Mode
          </h2>
          <p className="font-cinema mt-0.5 text-[0.85rem] uppercase tracking-widest text-cyan/60">{pollMessage}</p>
        </div>
      </div>

      <button
        type="button"
        onClick={onClose}
        className="font-cinema absolute right-8 top-8 z-10 inline-flex items-center gap-2 rounded-lg border border-cyan/40 bg-cyan/5 px-5 py-2.5 text-[0.85rem] uppercase tracking-[0.2em] text-cyan transition-all hover:border-cyan hover:bg-cyan/20 hover:shadow-[0_0_15px_rgba(94,207,255,0.4)]"
      >
        <X size={14} />
        Exit Cinema Mode
      </button>

      <div className="font-cinema absolute bottom-8 left-8 z-10 flex max-w-[min(520px,calc(100vw-3rem))] flex-col gap-1 text-[0.77rem] uppercase tracking-widest text-cyan/55">
        <p>SYS.TOPOLOGY.MAP // {pollState.toUpperCase()}</p>
        <p>RUN // {selectedRun ? compactId(selectedRun.id) : 'NO RUN'}</p>
        <p>ACTIVE.TOOL // {activeEvent?.tool ?? activeTask?.tool.toUpperCase() ?? 'WAITING'}</p>
        <p>TARGET // {activeEvent?.target ?? activeTask?.target_id ?? 'WAITING FOR DISCOVERY'}</p>
      </div>

      <div className="absolute bottom-8 right-8 z-10 grid w-[min(360px,calc(100vw-3rem))] grid-cols-2 gap-2">
        <Stat label="Critical" value={stats.critical} tone="text-red" />
        <Stat label="High" value={stats.high} tone="text-amber" />
        <Stat label="Hosts" value={stats.hosts} tone="text-cyan" />
        <Stat label="AI Proposals" value={stats.proposals} tone="text-emerald-200" />
      </div>

      <Canvas className="absolute inset-0 h-full w-full" camera={{ position: [0, 0, 100], fov: 60 }} data-testid="cinema-canvas">
        <color attach="background" args={['#020408']} />
        <ambientLight intensity={0.2} />
        <Network activeEvent={activeEvent} activeIndex={activeTargetIndex} logs={logs} nodes={nodes} />
        <EffectComposer enableNormalPass={false}>
          <Bloom luminanceThreshold={0.1} mipmapBlur intensity={1.5} radius={0.8} />
        </EffectComposer>
      </Canvas>
    </div>
  );
}

function Stat({ label, value, tone }: { label: string; value: number; tone: string }) {
  return (
    <div className="rounded-lg border border-cyan/20 bg-[rgba(10,18,31,0.72)] px-3 py-2 backdrop-blur-md">
      <div className="font-cinema text-[0.77rem] uppercase tracking-widest text-cyan/55">{label}</div>
      <div className={`mt-1 text-2xl font-semibold ${tone}`}>{value}</div>
    </div>
  );
}

function buildNodes(inventory: InventorySnapshot | null, findings: Finding[]): CinemaNode[] {
  const hosts = inventoryHosts(inventory);
  if (!hosts.length) {
    return [
      {
        id: 'waiting-for-discovery',
        label: 'waiting for discovery',
        position: new THREE.Vector3(0, 0, 0),
        color: '#78b1d4',
        severity: 'none',
        findingCount: 0,
        waiting: true,
      },
    ];
  }

  return hosts.slice(0, 24).map((host, index) => {
    const relatedFindings = findings.filter((finding) => targetMatches(finding.target_id, host));
    const hasCritical = relatedFindings.some((finding) => finding.severity.toLowerCase() === 'critical');
    const hasHigh = relatedFindings.some((finding) => finding.severity.toLowerCase() === 'high');
    const severity = hasCritical ? 'critical' : hasHigh ? 'high' : 'none';
    return {
      id: host,
      label: host,
      position: seededPosition(host, index, hosts.length),
      color: severity === 'critical' ? '#ef4444' : severity === 'high' ? '#fbbf24' : '#5ecfff',
      severity,
      findingCount: relatedFindings.length,
      waiting: false,
    };
  });
}

function inventoryHosts(inventory: InventorySnapshot | null): string[] {
  const normalized = inventory?.normalized_inventory_json;
  if (!isJsonMap(normalized)) return [];
  const hosts = readArray(normalized.hosts)
    .map((host) => inventoryLabel(host, ['host', 'hostname', 'ip', 'address', 'target', 'id']))
    .filter(Boolean);
  return Array.from(new Set(hosts));
}

function seededPosition(label: string, index: number, total: number): THREE.Vector3 {
  const hash = hashString(label);
  const ring = 22 + (hash % 4) * 8;
  const angle = ((index / Math.max(total, 1)) * Math.PI * 2) + ((hash % 360) * Math.PI) / 180;
  const y = (((hash >> 3) % 31) - 15) * 0.9;
  return new THREE.Vector3(Math.cos(angle) * ring, y, Math.sin(angle) * ring);
}

function findNodeIndexForTarget(nodes: CinemaNode[], target: string): number {
  const index = nodes.findIndex((node) => !node.waiting && targetMatches(target, node.label));
  return index >= 0 ? index : -1;
}

function eventFromTasks(tasks: Task[]): EventLog | null {
  const task = selectActiveTask(tasks);
  if (!task) return null;
  return {
    id: task.id,
    tool: task.tool.toUpperCase(),
    target: task.target_id || 'run',
    msg: `Task ${task.status}`,
    status: task.status,
    createdAt: task.updated_at,
  };
}

function selectActiveTask(tasks: Task[]): Task | null {
  return (
    tasks.find((task) => ACTIVE_STATUSES.has(task.status)) ??
    [...tasks].sort((left, right) => Date.parse(right.updated_at) - Date.parse(left.updated_at))[0] ??
    null
  );
}

function eventFromTaskDetail(detail: TaskDetail): EventLog | null {
  const newestExecution = [...(detail.executions ?? [])].sort((left, right) =>
    stringValue(right.created_at).localeCompare(stringValue(left.created_at)),
  )[0];
  const stdout = newestExecution?.stdout_text ?? '';
  const stderr = newestExecution?.stderr_text ?? '';
  const snapshot = detail.stdout_snapshot?.lines?.map((line) => line.text).filter(Boolean).join('\n') ?? '';
  const lines = (stdout || stderr || snapshot)
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
  const msg = lines.slice(-2).join(' / ') || `Task ${detail.status}`;
  return {
    id: detail.id,
    tool: detail.tool.toUpperCase(),
    target: detail.target_id || 'run',
    msg,
    status: detail.status,
    createdAt: newestExecution?.created_at ?? detail.updated_at,
  };
}

function targetMatches(candidate: string | null | undefined, label: string): boolean {
  if (!candidate) return false;
  const left = candidate.toLowerCase();
  const right = label.toLowerCase();
  return left.includes(right) || right.includes(left);
}

function inventoryLabel(value: unknown, keys: string[]): string {
  if (typeof value === 'string') return value.trim();
  if (!isJsonMap(value)) return '';
  for (const key of keys) {
    const candidate = value[key];
    if (typeof candidate === 'string' && candidate.trim()) return candidate.trim();
  }
  return '';
}

function readArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function isJsonMap(value: unknown): value is JsonMap {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function stringValue(value: unknown): string {
  return typeof value === 'string' ? value : '';
}

function hashString(value: string): number {
  let hash = 0;
  for (let index = 0; index < value.length; index += 1) {
    hash = (hash * 31 + value.charCodeAt(index)) >>> 0;
  }
  return hash;
}

function truncate(value: string, maxLength: number): string {
  return value.length > maxLength ? `${value.slice(0, maxLength - 3)}...` : value;
}

function compactId(value: string): string {
  return value.length > 12 ? `${value.slice(0, 8)}...${value.slice(-4)}` : value;
}
