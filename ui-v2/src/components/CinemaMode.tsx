import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { createPortal } from 'react-dom';
import { Canvas, useFrame } from '@react-three/fiber';
import { Bloom, EffectComposer } from '@react-three/postprocessing';
import { Html, Line, OrbitControls, Sphere, Text, Grid, Trail, Box, Octahedron, Cylinder } from '@react-three/drei';
import { BrainCircuit, ChevronRight, Pause, Play, RotateCcw, X } from 'lucide-react';
import * as THREE from 'three';
import {
  ApiError,
  getFindingsForRunContext,
  getInventoryForRun,
  getRun,
  getTaskDetail,
  getTasksForRunContext,
} from '../api/client';
import type { AgentProposal, Finding, InventorySnapshot, JsonMap, Task, TaskDetail, UUID } from '../api/types';
import { useAegisStore } from '../store';

const POLL_MS = 4000;
const FONT_URL = `${import.meta.env.BASE_URL}fonts/FiraMono-Regular.ttf`;

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
  target: string;
  status: string;
  position: THREE.Vector3;
  color: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'none';
  findingCount: number;
  kind: 'task' | 'finding' | 'surface' | 'waiting';
  tool?: string;
  waiting: boolean;
};

type ReplayStep = {
  id: string;
  tool: string;
  target: string;
  message: string;
  status: string;
  findingCount: number;
  severity: CinemaNode['severity'];
  command: string;
  taskNodeId: string | null;
  targetNodeId: string | null;
};

type ChainNode = {
  id: string;
  label: string;
  tool: string;
  kind: 'tool' | 'finding' | 'pivot';
  severity: CinemaNode['severity'];
  position: THREE.Vector3;
  color: string;
  reasoningText: string | null;
  iterationIndex: number;
  pulsing: boolean;
};

type ChainLink = {
  from: ChainNode;
  to: ChainNode;
  color: string;
};

function PulsingNode({ color, radius = 0.6 }: { color: string; radius?: number }) {
  const meshRef = useRef<THREE.Mesh>(null);
  const matRef = useRef<THREE.MeshStandardMaterial>(null);
  useFrame((state) => {
    if (!matRef.current) return;
    matRef.current.emissiveIntensity = 1.5 + Math.sin(state.clock.getElapsedTime() * 2.2) * 1.0;
  });
  return (
    <Sphere ref={meshRef} args={[radius, 20, 20]}>
      <meshStandardMaterial ref={matRef} color={color} emissive={color} emissiveIntensity={1.5} toneMapped={false} />
    </Sphere>
  );
}

function AiChainNetwork({
  nodes,
  links,
  manualCamera,
  selectedNodeId,
  onSelectNode,
}: {
  nodes: ChainNode[];
  links: ChainLink[];
  manualCamera: boolean;
  selectedNodeId: string | null;
  onSelectNode: (id: string) => void;
}) {
  const desiredPosition = useMemo(() => new THREE.Vector3(), []);
  const lookAtVec = useMemo(() => new THREE.Vector3(), []);

  useFrame((state) => {
    if (manualCamera) return;
    const selectedNode = selectedNodeId ? nodes.find((n) => n.id === selectedNodeId) ?? null : null;
    if (selectedNode) {
      desiredPosition.set(selectedNode.position.x + 8, selectedNode.position.y + 12, selectedNode.position.z + 40);
      state.camera.position.lerp(desiredPosition, 0.05);
      lookAtVec.lerp(selectedNode.position, 0.1);
      state.camera.lookAt(lookAtVec);
      return;
    }
    const elapsed = state.clock.getElapsedTime() * 0.06;
    desiredPosition.set(Math.cos(elapsed) * 10, 22, 90 + Math.sin(elapsed) * 12);
    state.camera.position.lerp(desiredPosition, 0.012);
    lookAtVec.set(0, 0, 0);
    lookAtVec.lerp(new THREE.Vector3(0, 0, 0), 0.02);
    state.camera.lookAt(lookAtVec);
  });

  return (
    <group>
      <LaneLabel label="PASSIVE" position={[-56, 18, -30]} />
      <LaneLabel label="ACTIVE" position={[0, 18, -30]} />
      <LaneLabel label="INTRUSIVE" position={[56, 18, -30]} />

      {links.map((link, i) => (
        <Line
          key={`${link.from.id}:${link.to.id}:${i}`}
          points={[link.from.position, link.to.position]}
          color={link.color}
          opacity={0.55}
          lineWidth={1.6}
          transparent
        />
      ))}

      {nodes.map((node) => {
        const isSelected = selectedNodeId === node.id;
        const nc = isSelected ? '#5ecfff' : node.color;
        return (
          <group
            key={node.id}
            position={node.position}
            onClick={(e) => { e.stopPropagation(); onSelectNode(node.id); }}
          >
            {node.kind === 'finding' ? (
              <PulsingNode color={nc} radius={isSelected ? 1.1 : 0.65} />
            ) : node.kind === 'pivot' ? (
              <Octahedron args={[isSelected ? 1.0 : 0.55]}>
                <meshStandardMaterial color={nc} emissive={nc} emissiveIntensity={isSelected ? 3 : 1.8} toneMapped={false} />
              </Octahedron>
            ) : (
              <Cylinder args={[isSelected ? 0.65 : 0.38, isSelected ? 0.65 : 0.38, isSelected ? 1.4 : 0.8, 28]}>
                <meshStandardMaterial color={nc} emissive={nc} emissiveIntensity={isSelected ? 3 : 1.8} toneMapped={false} />
              </Cylinder>
            )}

            {/* glow halo */}
            {node.kind === 'finding' ? (
              <Sphere args={[isSelected ? 1.8 : 1.1, 20, 20]}>
                <meshStandardMaterial color={nc} transparent opacity={isSelected ? 0.18 : 0.1} emissive={nc} emissiveIntensity={0.6} toneMapped={false} />
              </Sphere>
            ) : node.kind === 'pivot' ? (
              <Octahedron args={[isSelected ? 1.6 : 0.95]}>
                <meshStandardMaterial color={nc} transparent opacity={isSelected ? 0.18 : 0.1} emissive={nc} emissiveIntensity={0.5} toneMapped={false} />
              </Octahedron>
            ) : (
              <Cylinder args={[isSelected ? 1.1 : 0.7, isSelected ? 1.1 : 0.7, isSelected ? 2.2 : 1.4, 28]}>
                <meshStandardMaterial color={nc} transparent opacity={isSelected ? 0.18 : 0.1} emissive={nc} emissiveIntensity={0.5} toneMapped={false} />
              </Cylinder>
            )}

            <Text
              position={[0, (node.kind === 'finding' ? 1.8 : 1.4) + (isSelected ? 0.6 : 0), 0]}
              fontSize={isSelected ? 0.86 : 0.58}
              color={nc}
              anchorX="center"
              anchorY="middle"
              font={FONT_URL}
              maxWidth={13}
              textAlign="center"
            >
              {node.label}
              <meshBasicMaterial attach="material" toneMapped={false} color={nc} />
            </Text>

            {isSelected && node.reasoningText && (
              <Html position={[2, 0, 0]} center className="pointer-events-none">
                <div className="min-w-[280px] max-w-[340px] rounded border border-cyan/30 bg-[rgba(4,10,20,0.72)] p-3 text-xs leading-5 text-muted backdrop-blur-md">
                  <p className="mb-1 font-bold uppercase tracking-widest text-cyan/70" style={{ fontSize: '0.65rem' }}>
                    AI REASONING · ITER {node.iterationIndex}
                  </p>
                  <p className="line-clamp-4">{node.reasoningText}</p>
                </div>
              </Html>
            )}
          </group>
        );
      })}
    </group>
  );
}

function Terminal3D({ steps, activeStepIndex }: { steps: ReplayStep[]; activeStepIndex: number }) {
  const visibleSteps = steps.length
    ? steps.slice(Math.max(0, activeStepIndex - 4), activeStepIndex + 1).reverse()
    : [];

  return (
    <group position={[-46, 34, -34]} rotation={[0, Math.PI / 10, 0]}>
      <Text position={[0, 2, 0]} fontSize={1.15} color="#5ecfff" anchorX="left" font={FONT_URL}>
        AEGISPT // COMMAND REPLAY
        <meshBasicMaterial attach="material" toneMapped={false} />
      </Text>
      {(visibleSteps.length ? visibleSteps : [{ id: 'waiting', tool: 'SYSTEM', target: 'run', message: 'Waiting for task stdout evidence', status: 'waiting', command: 'poll --run', findingCount: 0, severity: 'none' as const, taskNodeId: null, targetNodeId: null }]).map((step, i) => {
        const isLatest = i === 0 && steps.length > 0;
        return (
          <Text
            key={step.id}
            position={[0, -i * 1.45, 0]}
            fontSize={isLatest ? 0.86 : 0.72}
            color={isLatest ? '#e4eeff' : 'rgba(120,177,212,0.55)'}
            anchorX="left"
            font={FONT_URL}
          >
            {`${step.command} -> ${truncate(step.target, 46)}`}
            <meshBasicMaterial attach="material" toneMapped={false} />
          </Text>
        );
      })}
    </group>
  );
}

function Network({
  activeStep,
  activeStepIndex,
  manualCamera,
  nodes,
  onSelectNode,
  selectedNodeId,
  steps,
}: {
  activeStep: ReplayStep | null;
  activeStepIndex: number;
  manualCamera: boolean;
  nodes: CinemaNode[];
  onSelectNode: (nodeId: string) => void;
  selectedNodeId: string | null;
  steps: ReplayStep[];
}) {
  const desiredPosition = useMemo(() => new THREE.Vector3(), []);
  const lookAtVec = useMemo(() => new THREE.Vector3(), []);
  const orbitCenter = useMemo(() => new THREE.Vector3(0, 0, 0), []);
  const pairMidpoint = useMemo(() => new THREE.Vector3(), []);
  const links = useMemo(() => buildReplayLinks(steps, nodes), [nodes, steps]);
  const visibleLinks = useMemo(() => {
    const activeLinks = links.filter((link) => activeStep?.id === link.stepId);
    if (!selectedNodeId) return activeLinks;
    const selectedLinks = links
      .filter((link) => selectedNodeId === link.from.id || selectedNodeId === link.to.id)
      .sort((left, right) => {
        const severityDelta = severityRank(right.severity) - severityRank(left.severity);
        return severityDelta || right.findingCount - left.findingCount;
      })
      .slice(0, 8);
    const seen = new Set<string>();
    return [...activeLinks, ...selectedLinks].filter((link) => {
      const key = `${link.from.id}:${link.to.id}:${link.stepId}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }, [activeStep?.id, links, selectedNodeId]);

  useFrame((state) => {
    if (manualCamera) return;
    const selectedNode = selectedNodeId ? nodes.find((node) => node.id === selectedNodeId) ?? null : null;
    if (selectedNode && !selectedNode.waiting) {
      desiredPosition.set(
        selectedNode.position.x + 10,
        selectedNode.position.y + 8,
        selectedNode.position.z + 30,
      );
      state.camera.position.lerp(desiredPosition, 0.06);
      lookAtVec.lerp(selectedNode.position, 0.12);
      state.camera.lookAt(lookAtVec);
      return;
    }

    const activeLink = activeStep ? links.find((link) => link.stepId === activeStep.id) ?? null : null;
    if (activeLink) {
      pairMidpoint.copy(activeLink.from.position).add(activeLink.to.position).multiplyScalar(0.5);
      const distance = Math.max(54, activeLink.from.position.distanceTo(activeLink.to.position) * 0.74);
      desiredPosition.set(pairMidpoint.x, pairMidpoint.y + 18, pairMidpoint.z + distance);
      state.camera.position.lerp(desiredPosition, 0.04);
      lookAtVec.lerp(pairMidpoint, 0.07);
      state.camera.lookAt(lookAtVec);
      return;
    }

    const elapsed = state.clock.getElapsedTime() * 0.08;
    desiredPosition.set(Math.cos(elapsed) * 18, 34, 112 + Math.sin(elapsed) * 10);
    state.camera.position.lerp(desiredPosition, 0.014);
    lookAtVec.lerp(orbitCenter, 0.025);
    state.camera.lookAt(lookAtVec);
  });

  return (
    <group>
      <Terminal3D steps={steps} activeStepIndex={activeStepIndex} />

      <LaneLabel label="CHECKS" position={[-58, 18, -34]} />
      <LaneLabel label="TARGETS" position={[4, 28, -34]} />
      <LaneLabel label="FINDINGS" position={[58, 18, -34]} />

      {visibleLinks.map((link) => {
        const active = activeStep?.id === link.stepId;
        const selected = selectedNodeId === link.from.id || selectedNodeId === link.to.id;
        return (
          <Line
            key={`${link.from.id}:${link.to.id}:${link.stepId}`}
            points={[link.from.position, link.to.position]}
            color={active ? '#5ecfff' : severityColor(link.severity)}
            opacity={active ? 0.86 : selected ? 0.62 : 0.24}
            lineWidth={active || selected ? 2.4 : link.findingCount > 0 ? 1.4 : 0.8}
            transparent
          />
        );
      })}

      {activeStep && <ReplayBeam step={activeStep} nodes={nodes} />}

      {nodes.map((node) => {
        const isActive = activeStep?.taskNodeId === node.id || activeStep?.targetNodeId === node.id;
        const isSelected = selectedNodeId === node.id;
        const showLabel = isSelected || isActive || node.findingCount > 0;
        const nodeColorValue = nodeColor(node, isSelected || isActive);
        return (
          <group
            key={node.id}
            position={node.position}
            onClick={(event) => {
              event.stopPropagation();
              onSelectNode(node.id);
            }}
          >
            {node.kind === 'task' ? (
              <Cylinder args={[isSelected ? 0.7 : isActive ? 0.5 : 0.25, isSelected ? 0.7 : isActive ? 0.5 : 0.25, isSelected ? 1.4 : isActive ? 1.0 : 0.5, 32]}>
                <meshStandardMaterial color={nodeColorValue} emissive={nodeColorValue} emissiveIntensity={isSelected || isActive ? 2.5 : 1.5} toneMapped={false} />
              </Cylinder>
            ) : node.kind === 'surface' ? (
              <Box args={[isSelected ? 1.5 : isActive ? 1.2 : 0.6, isSelected ? 1.5 : isActive ? 1.2 : 0.6, isSelected ? 1.5 : isActive ? 1.2 : 0.6]}>
                <meshStandardMaterial color={nodeColorValue} emissive={nodeColorValue} emissiveIntensity={isSelected || isActive ? 2.5 : 1.5} toneMapped={false} />
              </Box>
            ) : node.kind === 'finding' ? (
              <Octahedron args={[isSelected ? 1.0 : isActive ? 0.8 : 0.4]}>
                <meshStandardMaterial color={nodeColorValue} emissive={nodeColorValue} emissiveIntensity={isSelected || isActive ? 2.5 : 1.5} toneMapped={false} />
              </Octahedron>
            ) : (
              <Sphere args={[isSelected ? 0.9 : isActive ? 0.7 : node.waiting ? 0.45 : 0.32, 24, 24]}>
                <meshStandardMaterial color={nodeColorValue} emissive={nodeColorValue} emissiveIntensity={isSelected || isActive ? 2.5 : 1.5} toneMapped={false} />
              </Sphere>
            )}

            {(node.findingCount > 0 || isActive || isSelected) && (
              node.kind === 'task' ? (
                <Cylinder args={[isSelected ? 1.1 : isActive ? 0.9 : 0.6, isSelected ? 1.1 : isActive ? 0.9 : 0.6, isSelected ? 2.2 : isActive ? 1.8 : 1.2, 32]}>
                  <meshStandardMaterial color={nodeColorValue} transparent opacity={isSelected ? 0.25 : 0.15} emissive={nodeColorValue} emissiveIntensity={0.8} toneMapped={false} />
                </Cylinder>
              ) : node.kind === 'surface' ? (
                <Box args={[isSelected ? 2.2 : isActive ? 1.8 : 1.0, isSelected ? 2.2 : isActive ? 1.8 : 1.0, isSelected ? 2.2 : isActive ? 1.8 : 1.0]}>
                  <meshStandardMaterial color={nodeColorValue} transparent opacity={isSelected ? 0.25 : 0.15} emissive={nodeColorValue} emissiveIntensity={0.8} toneMapped={false} />
                </Box>
              ) : node.kind === 'finding' ? (
                <Octahedron args={[isSelected ? 1.6 : isActive ? 1.2 : 0.8]}>
                  <meshStandardMaterial color={nodeColorValue} transparent opacity={isSelected ? 0.25 : 0.15} emissive={nodeColorValue} emissiveIntensity={0.8} toneMapped={false} />
                </Octahedron>
              ) : (
                <Sphere args={[isSelected ? 1.45 : isActive ? 1.15 : 0.85, 24, 24]}>
                  <meshStandardMaterial color={nodeColorValue} transparent opacity={isSelected ? 0.25 : 0.15} emissive={nodeColorValue} emissiveIntensity={0.8} toneMapped={false} />
                </Sphere>
              )
            )}

            {showLabel && (
              <Text
                position={[0, isSelected ? 2.65 : isActive ? 2.35 : 1.5, 0]}
                fontSize={isSelected ? 0.9 : isActive ? 0.78 : 0.5}
                color={nodeColorValue}
                anchorX="center"
                anchorY="middle"
                font={FONT_URL}
                maxWidth={14}
                textAlign="center"
              >
                {truncate(node.label, 20)}
                <meshBasicMaterial attach="material" toneMapped={false} color={nodeColorValue} />
              </Text>
            )}

            {(isSelected || isActive) && node.target && (
              <Text
                position={[0, isSelected ? 1.55 : 1.25, 0]}
                fontSize={isSelected ? 0.42 : 0.34}
                color="rgba(226,239,255,0.72)"
                anchorX="center"
                anchorY="middle"
                font={FONT_URL}
                maxWidth={12}
                textAlign="center"
              >
                {truncate(node.target, 34)}
                <meshBasicMaterial attach="material" toneMapped={false} color="rgba(226,239,255,0.72)" />
              </Text>
            )}

            {node.findingCount > 0 && (
              <Text position={[0, -1.35, 0]} fontSize={0.62} color={severityColor(node.severity)} anchorX="center" anchorY="middle" font={FONT_URL}>
                {`${node.findingCount} FINDINGS`}
                <meshBasicMaterial attach="material" toneMapped={false} color={severityColor(node.severity)} />
              </Text>
            )}

            {(isSelected || isActive) && (
              <Html position={[2, 0, 0]} center className="pointer-events-none">
                <div className="min-w-[290px] max-w-[360px] rounded border border-cyan/35 bg-[rgba(4,10,20,0.62)] p-3 shadow-[0_0_24px_rgba(94,207,255,0.18)] backdrop-blur-md">
                  <div className="mb-1 flex items-center gap-2">
                    <div className="h-1.5 w-1.5 animate-pulse rounded-full" style={{ backgroundColor: nodeColorValue }} />
                    <span className="text-[0.77rem] font-bold uppercase tracking-widest" style={{ color: nodeColorValue }}>
                      {isSelected ? 'SELECTED' : 'REPLAY'} · {node.label}
                    </span>
                  </div>
                  <div className="font-cinema max-h-36 overflow-hidden text-xs leading-5 text-text">
                    <p>{node.status.toUpperCase()} · {node.kind.toUpperCase()}</p>
                    <p className="text-muted">{truncate(node.target, 110)}</p>
                    {isActive && activeStep && <p className="mt-1 text-cyan/80">{truncate(activeStep.message, 180)}</p>}
                    {node.findingCount > 0 && <p className="mt-1" style={{ color: severityColor(node.severity) }}>{node.findingCount} finding(s), severity {node.severity}</p>}
                  </div>
                </div>
              </Html>
            )}
          </group>
        );
      })}
    </group>
  );
}

function LaneLabel({ label, position }: { label: string; position: [number, number, number] }) {
  return (
    <Text position={position} fontSize={0.8} color="rgba(120,177,212,0.36)" anchorX="center" anchorY="middle" font={FONT_URL}>
      {label}
      <meshBasicMaterial attach="material" toneMapped={false} color="rgba(120,177,212,0.36)" />
    </Text>
  );
}

function ReplayBeam({ step, nodes }: { step: ReplayStep; nodes: CinemaNode[] }) {
  const meshRef = useRef<THREE.Mesh>(null);
  const from = step.taskNodeId ? nodes.find((node) => node.id === step.taskNodeId) ?? null : null;
  const to = step.targetNodeId ? nodes.find((node) => node.id === step.targetNodeId) ?? null : null;
  const color = step.findingCount > 0 ? severityColor(step.severity) : '#5ecfff';

  useFrame((state) => {
    if (!meshRef.current || !from || !to) return;
    const progress = (state.clock.getElapsedTime() * 0.42) % 1;
    meshRef.current.position.lerpVectors(from.position, to.position, progress);
  });

  if (!from || !to) return null;
  return (
    <Trail width={1.5} length={8} color={color} attenuation={(t) => t * t}>
      <Sphere ref={meshRef} args={[0.4, 16, 16]}>
        <meshStandardMaterial color={color} emissive={color} emissiveIntensity={3} toneMapped={false} />
      </Sphere>
    </Trail>
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
  const setFindings = useAegisStore((state) => state.setFindings);
  const setInventory = useAegisStore((state) => state.setInventory);
  const isAiLoop = isAiLoopRunCinema(selectedRun);

  const [logs, setLogs] = useState<EventLog[]>([]);
  const [pollState, setPollState] = useState<'connected' | 'waiting' | 'error'>('waiting');
  const [pollMessage, setPollMessage] = useState('Waiting for run data');
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [manualCamera, setManualCamera] = useState(false);
  const [replayPlaying, setReplayPlaying] = useState(true);
  const [activeStepIndex, setActiveStepIndex] = useState(0);
  const fingerprints = useRef<Map<UUID, string>>(new Map());

  const nodes = useMemo(() => buildNodes(inventory, findings, storeTasks), [findings, inventory, storeTasks]);
  const steps = useMemo(() => buildReplaySteps(nodes, storeTasks, findings, logs), [findings, logs, nodes, storeTasks]);
  const activeStep = steps[activeStepIndex] ?? steps[0] ?? null;

  // AI chain nodes derived from proposals (only for ai_loop mode)
  const { chainNodes, chainLinks } = useMemo(
    () => (isAiLoop ? buildAiChain(proposals, findings) : { chainNodes: [], chainLinks: [] }),
    [findings, isAiLoop, proposals],
  );
  const latestHypothesis = useMemo(() => {
    if (!isAiLoop || proposals.length === 0) return null;
    const sorted = [...proposals].sort((a, b) => Date.parse(b.created_at) - Date.parse(a.created_at));
    return sorted[0]?.reasoning_text ?? null;
  }, [isAiLoop, proposals]);

  const stats = useMemo(
    () => ({
      critical: findings.filter((finding) => finding.severity.toLowerCase() === 'critical').length,
      high: findings.filter((finding) => finding.severity.toLowerCase() === 'high').length,
      medium: findings.filter((finding) => finding.severity.toLowerCase() === 'medium').length,
      clean: nodes.filter((node) => !node.waiting && node.kind === 'surface' && node.findingCount === 0).length,
      checks: steps.length,
      proposals: proposals.filter((proposal) => proposal.status === 'pending').length,
    }),
    [findings, nodes, proposals, steps.length],
  );

  const selectedNode = useMemo(
    () => (selectedNodeId ? nodes.find((node) => node.id === selectedNodeId) ?? null : null),
    [nodes, selectedNodeId],
  );

  function focusNode(nodeId: string | null) {
    setSelectedNodeId(nodeId);
    setManualCamera(false);
  }

  function focusStep(index: number) {
    const boundedIndex = Math.max(0, Math.min(index, Math.max(steps.length - 1, 0)));
    setActiveStepIndex(boundedIndex);
    const step = steps[boundedIndex];
    setSelectedNodeId(step?.taskNodeId ?? step?.targetNodeId ?? null);
    setManualCamera(false);
    setReplayPlaying(false);
  }

  useEffect(() => {
    if (activeStepIndex >= steps.length) {
      setActiveStepIndex(Math.max(steps.length - 1, 0));
    }
  }, [activeStepIndex, steps.length]);

  useEffect(() => {
    if (!replayPlaying || steps.length <= 1) return undefined;
    const timer = window.setInterval(() => {
      setActiveStepIndex((current) => (current + 1) % steps.length);
      setSelectedNodeId(null);
      setManualCamera(false);
    }, 2400);
    return () => window.clearInterval(timer);
  }, [replayPlaying, steps.length]);

  useEffect(() => {
    function handleKeyDown(event: KeyboardEvent) {
      if (event.key === 'Escape') {
        onClose();
      }
    }
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [onClose]);

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
        const [tasksResult, findingsResult, inventoryResult] = await Promise.allSettled([
          getTasksForRunContext(run),
          getFindingsForRunContext(run),
          getInventoryForRun(run),
        ]);
        if (cancelled) return;

        const nextTasks = tasksResult.status === 'fulfilled' ? tasksResult.value : run.tasks ?? [];
        setSelectedRun(run);
        setTasks(nextTasks);
        if (findingsResult.status === 'fulfilled') {
          setFindings(findingsResult.value);
        }
        if (inventoryResult.status === 'fulfilled') {
          setInventory(inventoryResult.value);
        }

        const details = await Promise.all(nextTasks.slice(0, 18).map((task) => getTaskDetail(task.id).catch(() => null)));
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
        setPollMessage(`Polling ${nextTasks.length} real task outputs for ${run.profile.name}`);
      } catch (error) {
        if (!cancelled) {
          if (error instanceof ApiError && error.status === 404) {
            setPollState('waiting');
            setPollMessage('Selected run was removed; reopen Mission Control selection');
          } else {
            setPollState('error');
            setPollMessage(error instanceof Error ? error.message : 'Task polling failed');
          }
        }
      }
    }

    void pollRunTasks();
    const timer = window.setInterval(() => void pollRunTasks(), POLL_MS);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [selectedRunId, setFindings, setInventory, setSelectedRun, setTasks]);

  const content = (
    <div className="dark-canvas fixed inset-0 z-[9999] select-none overflow-hidden bg-[#020408]" data-testid="cinema-mode">
      <div className="absolute left-4 right-4 top-4 z-20 flex flex-col gap-3 sm:left-6 sm:right-6 sm:flex-row sm:items-start sm:justify-between">
        <div className="flex min-w-0 items-center gap-3">
          <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-cyan text-sm font-extrabold text-[#04080f] shadow-[0_0_20px_rgba(94,207,255,0.6)]">
            AP
          </div>
          <div className="min-w-0">
            <h2 className="truncate text-[0.9rem] font-bold uppercase tracking-widest text-cyan drop-shadow-[0_0_5px_rgba(94,207,255,0.8)]">
              Live Cinema Mode
            </h2>
            <p className="font-cinema mt-0.5 truncate text-[0.74rem] uppercase tracking-widest text-cyan/60">{pollMessage}</p>
          </div>
        </div>

        <button
          type="button"
          onClick={onClose}
          className="font-cinema inline-flex min-h-10 shrink-0 items-center justify-center gap-2 rounded-lg border border-cyan/50 bg-[#07111f]/90 px-4 py-2 text-[0.78rem] uppercase tracking-[0.16em] text-cyan shadow-[0_0_20px_rgba(2,6,12,0.65)] backdrop-blur-md transition-all hover:border-cyan hover:bg-cyan/15 hover:shadow-[0_0_15px_rgba(94,207,255,0.4)]"
        >
          <X size={14} />
          Exit
        </button>
      </div>

      <div className="absolute left-4 top-[5.5rem] z-20 w-[min(24rem,calc(100vw-2rem))] rounded-lg border border-cyan/15 bg-[#06111f]/38 p-3 text-text shadow-[0_0_24px_rgba(2,6,12,0.28)] backdrop-blur-md sm:left-6">
        <div className="flex items-center justify-between gap-3">
          <div>
            <p className="font-cinema text-[0.7rem] uppercase tracking-widest text-cyan/65">Replay Camera</p>
            <p className="mt-1 font-cinema text-[0.68rem] uppercase tracking-widest text-muted">
              {activeStep ? `${activeStepIndex + 1}/${steps.length} · ${activeStep.tool}` : 'Waiting'}
            </p>
          </div>
          <div className="flex gap-2">
            <ReplayIconButton label={replayPlaying ? 'Pause replay' : 'Play replay'} onClick={() => setReplayPlaying((current) => !current)}>
              {replayPlaying ? <Pause size={14} /> : <Play size={14} />}
            </ReplayIconButton>
            <ReplayIconButton label="Restart replay" onClick={() => focusStep(0)}>
              <RotateCcw size={14} />
            </ReplayIconButton>
          </div>
        </div>
        <div className="mt-3 grid grid-cols-4 gap-2 font-cinema text-[0.62rem] uppercase tracking-widest">
          <LegendDot color="#5ecfff" label="active" />
          <LegendDot color="#34d399" label="clean" />
          <LegendDot color="#f59e0b" label="high" />
          <LegendDot color="#ef4444" label="critical" />
        </div>
      </div>

      {isAiLoop ? (
        <AiAttackChainPanel proposals={proposals} hypothesis={latestHypothesis} />
      ) : (
        <CommandReplayPanel
          activeStepIndex={activeStepIndex}
          focusStep={focusStep}
          replayPlaying={replayPlaying}
          steps={steps}
          toggleReplay={() => setReplayPlaying((current) => !current)}
        />
      )}

      <div className="font-cinema absolute bottom-4 left-4 z-20 flex max-w-[min(520px,calc(100vw-2rem))] flex-col gap-1 text-[0.72rem] uppercase tracking-widest text-cyan/55 sm:bottom-6 sm:left-6">
        {isAiLoop ? (
          <>
            <p>SYS.AI.ADAPTIVE // {pollState.toUpperCase()}</p>
            <p>RUN // {selectedRun ? compactId(selectedRun.id) : 'NO RUN'}</p>
            <p>MODE // AI ADAPTIVE PENTEST — EXPLOITING CONFIRMED FINDINGS</p>
            <p>CAMERA // {manualCamera ? 'MANUAL ZOOM/ORBIT' : selectedNode ? `FOCUSED ${truncate(selectedNode.label, 26)}` : 'AUTO FOLLOW'}</p>
          </>
        ) : (
          <>
            <p>SYS.TOPOLOGY.MAP // {pollState.toUpperCase()}</p>
            <p>RUN // {selectedRun ? compactId(selectedRun.id) : 'NO RUN'}</p>
            <p>REPLAY.TOOL // {activeStep?.tool ?? 'WAITING'}</p>
            <p>CAMERA // {manualCamera ? 'MANUAL ZOOM/ORBIT' : selectedNode ? `FOCUSED ${truncate(selectedNode.label, 26)}` : 'AUTO FOLLOW'}</p>
            <p>COLOR // BLUE REPLAY · GREEN CLEAN · YELLOW MEDIUM · AMBER HIGH · RED CRITICAL</p>
            <p className="break-all">TARGET // {activeStep?.target ?? 'WAITING FOR DISCOVERY'}</p>
          </>
        )}
      </div>

      <div className="absolute bottom-4 right-4 z-20 grid w-[min(360px,calc(100vw-2rem))] grid-cols-2 gap-2 sm:bottom-6 sm:right-6">
        <Stat label="Critical" value={stats.critical} tone="text-red" />
        <Stat label="High" value={stats.high} tone="text-amber" />
        <Stat label="Medium" value={stats.medium} tone="text-yellow-200" />
        <Stat label="Clean Targets" value={stats.clean} tone="text-emerald-200" />
      </div>

      {selectedNode && (
        <SelectedNodePanel node={selectedNode} onClear={() => focusNode(null)} />
      )}

      <Canvas className="absolute inset-0 h-full w-full" camera={{ position: [0, 28, 118], fov: 72 }} data-testid="cinema-canvas">
        <color attach="background" args={['#010204']} />
        <fog attach="fog" args={['#010204', 50, 180]} />
        <ambientLight intensity={0.4} />
        <Grid position={[0, -18, 0]} args={[400, 400]} cellSize={5} cellThickness={1.2} cellColor="#0a1a36" sectionSize={25} sectionThickness={1.8} sectionColor="#18325c" fadeDistance={160} fadeStrength={2} />
        {isAiLoop ? (
          <AiChainNetwork
            nodes={chainNodes}
            links={chainLinks}
            manualCamera={manualCamera}
            selectedNodeId={selectedNodeId}
            onSelectNode={(nodeId) => focusNode(nodeId)}
          />
        ) : (
          <Network
            activeStep={activeStep}
            activeStepIndex={activeStepIndex}
            manualCamera={manualCamera}
            nodes={nodes}
            onSelectNode={(nodeId) => focusNode(nodeId)}
            selectedNodeId={selectedNodeId}
            steps={steps}
          />
        )}
        <OrbitControls
          makeDefault
          enableDamping
          enablePan
          enableRotate
          enableZoom
          dampingFactor={0.08}
          minDistance={36}
          maxDistance={220}
          onStart={() => setManualCamera(true)}
        />
        <EffectComposer enableNormalPass={false}>
          <Bloom luminanceThreshold={0.1} mipmapBlur intensity={1.15} radius={0.75} />
        </EffectComposer>
      </Canvas>
    </div>
  );

  if (typeof document === 'undefined') {
    return content;
  }

  return createPortal(content, document.body);
}

function SelectedNodePanel({ node, onClear }: { node: CinemaNode; onClear: () => void }) {
  const color = nodeColor(node, true);
  return (
    <aside className="absolute right-4 top-[26rem] z-20 w-[min(28rem,calc(100vw-2rem))] rounded-lg border border-cyan/20 bg-[#06111f]/58 p-4 text-text shadow-[0_0_2rem_rgba(2,6,12,0.35)] backdrop-blur-md sm:right-6">
      <div className="mb-3 flex items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="font-cinema text-[0.72rem] uppercase tracking-widest text-cyan/65">Selected check</p>
          <h3 className="mt-1 truncate text-[1.05rem] font-semibold" style={{ color }}>{node.label}</h3>
        </div>
        <button
          type="button"
          onClick={onClear}
          className="rounded-md border border-border bg-bg/45 px-2 py-1 font-cinema text-[0.64rem] uppercase tracking-widest text-muted hover:border-cyan/40 hover:text-cyan"
        >
          Clear
        </button>
      </div>
      <div className="grid gap-2 font-cinema text-[0.76rem] leading-5">
        <DetailRow label="Kind" value={node.kind} />
        <DetailRow label="Status" value={node.status} />
        <DetailRow label="Target" value={node.target || 'No target'} />
        <DetailRow label="Findings" value={node.findingCount > 0 ? `${node.findingCount} · ${node.severity}` : '0 · clean'} valueColor={node.findingCount > 0 ? severityColor(node.severity) : '#34d399'} />
      </div>
    </aside>
  );
}

function isAiLoopRunCinema(run: { configuration_json?: Record<string, unknown> } | null): boolean {
  if (!run?.configuration_json) return false;
  const cfg = run.configuration_json;
  const loop = cfg.ai_assessment_loop as Record<string, unknown> | undefined;
  return cfg.run_mode === 'ai_loop' || loop?.run_mode === 'ai_loop';
}

function AiAttackChainPanel({
  proposals,
  hypothesis,
}: {
  proposals: AgentProposal[];
  hypothesis: string | null;
}) {
  const sorted = useMemo(
    () => [...proposals].sort((a, b) => Date.parse(b.created_at) - Date.parse(a.created_at)),
    [proposals],
  );

  return (
    <aside className="absolute right-4 top-[5.5rem] z-20 w-[min(28rem,calc(100vw-2rem))] rounded-lg border border-cyan/20 bg-[#06111f]/56 p-3 text-text shadow-[0_0_2rem_rgba(2,6,12,0.36)] backdrop-blur-md sm:right-6">
      <div className="mb-3 flex items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <BrainCircuit size={14} className="text-cyan" />
          <p className="font-cinema text-[0.72rem] uppercase tracking-widest text-cyan/80">AI Attack Chain</p>
        </div>
        <span className="font-cinema text-[0.65rem] uppercase tracking-widest text-muted">
          {proposals.length} proposal{proposals.length !== 1 ? 's' : ''}
        </span>
      </div>

      {hypothesis && (
        <div className="mb-3 rounded-md border border-cyan/15 bg-cyan/5 px-3 py-2">
          <p className="mb-1 font-cinema text-[0.65rem] uppercase tracking-widest text-cyan/65">
            Current hypothesis
          </p>
          <p className="line-clamp-3 text-[0.78rem] leading-5 text-muted">{hypothesis}</p>
        </div>
      )}

      <div className="max-h-[260px] space-y-1 overflow-y-auto pr-1">
        {sorted.map((proposal, idx) => {
          const tier = proposal.risk_tier ?? 'passive';
          const dotColor =
            tier === 'intrusive' ? '#a855f7' : tier === 'active' ? '#f97316' : '#5ecfff';
          const status = proposal.status;
          return (
            <div
              key={proposal.id}
              className="flex items-start gap-2 rounded-md border border-transparent px-2 py-1.5 hover:border-cyan/15 hover:bg-cyan/5"
            >
              <span
                className="mt-1 h-2 w-2 shrink-0 rounded-full"
                style={{ backgroundColor: dotColor, boxShadow: `0 0 6px ${dotColor}` }}
              />
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-1.5">
                  <span className="font-cinema text-[0.72rem] uppercase tracking-widest text-text">
                    {prettyTool(proposal.proposed_tool)}
                  </span>
                  <ChevronRight size={10} className="text-muted/40" />
                  <span className="truncate font-mono text-[0.65rem] text-muted">
                    {proposal.proposed_target.replace(/^https?:\/\//, '').substring(0, 40)}
                  </span>
                </div>
                {proposal.reasoning_text && idx === 0 && (
                  <p className="mt-0.5 line-clamp-2 text-[0.65rem] text-muted/70">
                    {proposal.reasoning_text}
                  </p>
                )}
              </div>
              <span
                className={`shrink-0 font-cinema text-[0.62rem] uppercase ${
                  status === 'approved' ? 'text-cyan' : status === 'pending' ? 'text-amber-400' : 'text-muted/60'
                }`}
              >
                {status}
              </span>
            </div>
          );
        })}
        {proposals.length === 0 && (
          <p className="px-2 py-3 text-[0.78rem] text-muted">
            AI loop starting — proposals will appear here.
          </p>
        )}
      </div>
    </aside>
  );
}

function CommandReplayPanel({
  activeStepIndex,
  focusStep,
  replayPlaying,
  steps,
  toggleReplay,
}: {
  activeStepIndex: number;
  focusStep: (index: number) => void;
  replayPlaying: boolean;
  steps: ReplayStep[];
  toggleReplay: () => void;
}) {
  const startIndex = activeStepIndex >= 14 ? Math.max(0, activeStepIndex - 6) : 0;
  const visibleSteps = steps.slice(startIndex, startIndex + 14);
  return (
    <aside className="absolute right-4 top-[5.5rem] z-20 w-[min(28rem,calc(100vw-2rem))] rounded-lg border border-cyan/20 bg-[#06111f]/56 p-3 text-text shadow-[0_0_2rem_rgba(2,6,12,0.36)] backdrop-blur-md sm:right-6">
      <div className="mb-3 flex items-center justify-between gap-3">
        <div>
          <p className="font-cinema text-[0.72rem] uppercase tracking-widest text-cyan/65">Command Replay</p>
          <p className="mt-1 font-cinema text-[0.66rem] uppercase tracking-widest text-muted">
            Commands pull checks toward evidence targets
          </p>
        </div>
        <button
          type="button"
          onClick={toggleReplay}
          className="inline-flex h-8 w-8 items-center justify-center rounded-md border border-cyan/25 bg-cyan/10 text-cyan hover:border-cyan/55"
          aria-label={replayPlaying ? 'Pause command replay' : 'Play command replay'}
        >
          {replayPlaying ? <Pause size={14} /> : <Play size={14} />}
        </button>
      </div>

      <div className="space-y-1.5">
        {visibleSteps.length ? visibleSteps.map((step, index) => {
          const absoluteIndex = startIndex + index;
          const active = absoluteIndex === activeStepIndex;
          const color = active ? '#5ecfff' : step.findingCount > 0 ? severityColor(step.severity) : '#34d399';
          return (
            <button
              key={step.id}
              type="button"
              onClick={() => focusStep(absoluteIndex)}
              className={`grid w-full grid-cols-[0.65rem_minmax(0,1fr)_auto] items-center gap-2 rounded-md border px-2.5 py-2 text-left transition-colors ${
                active ? 'border-cyan/55 bg-cyan/12' : 'border-transparent bg-[#020814]/28 hover:border-cyan/25 hover:bg-cyan/8'
              }`}
            >
              <span className="h-2.5 w-2.5 rounded-full shadow-[0_0_12px_currentColor]" style={{ color, backgroundColor: color }} />
              <span className="min-w-0">
                <span className="block truncate font-cinema text-[0.72rem] uppercase tracking-widest text-text">{step.command}</span>
                <span className="mt-0.5 block truncate font-mono text-[0.68rem] text-muted">{step.target}</span>
              </span>
              <span
                className="rounded-full border px-2 py-0.5 font-cinema text-[0.62rem] uppercase tracking-wider"
                style={{ borderColor: `${color}66`, color }}
              >
                {step.findingCount > 0 ? `${step.findingCount} finding` : step.status}
              </span>
            </button>
          );
        }) : (
          <p className="rounded-md border border-cyan/10 bg-[#020814]/28 px-3 py-3 text-[0.82rem] leading-5 text-muted">
            No task commands are available for replay yet.
          </p>
        )}
      </div>
    </aside>
  );
}

function ReplayIconButton({ children, label, onClick }: { children: ReactNode; label: string; onClick: () => void }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="inline-flex h-8 w-8 items-center justify-center rounded-md border border-cyan/25 bg-cyan/10 text-cyan hover:border-cyan/55"
      aria-label={label}
    >
      {children}
    </button>
  );
}

function LegendDot({ color, label }: { color: string; label: string }) {
  return (
    <span className="inline-flex items-center gap-1.5 text-muted">
      <span className="h-2 w-2 rounded-full" style={{ backgroundColor: color }} />
      {label}
    </span>
  );
}

function DetailRow({ label, value, valueColor }: { label: string; value: string; valueColor?: string }) {
  return (
    <div className="grid grid-cols-[5.5rem_minmax(0,1fr)] gap-3 rounded-md bg-bg/32 px-3 py-2">
      <span className="uppercase tracking-widest text-muted">{label}</span>
      <span className="min-w-0 break-words text-text" style={valueColor ? { color: valueColor } : undefined}>{value}</span>
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

function buildNodes(inventory: InventorySnapshot | null, findings: Finding[], tasks: Task[]): CinemaNode[] {
  const taskNodes = tasks.slice(0, 40).map((task) => {
    const relatedFindings = findingsForTask(task, findings);
    const severity = severityLevel(strongestSeverity(relatedFindings.map((finding) => finding.severity)));
    return {
      id: `task:${task.id}`,
      label: prettyTool(task.tool),
      target: targetLabel(task.target_id) || 'recorded target',
      status: task.status,
      position: new THREE.Vector3(0, 0, 0),
      color: severityColor(severity),
      severity,
      findingCount: relatedFindings.length,
      kind: 'task' as const,
      tool: task.tool,
      waiting: false,
    };
  });

  const surfaceNodes = surfaceLabels(inventory, findings, tasks)
    .slice(0, Math.max(0, 36 - taskNodes.length))
    .map((label) => {
      const relatedFindings = findings.filter((finding) => targetMatches(finding.target_id, label));
      const severity = severityLevel(strongestSeverity(relatedFindings.map((finding) => finding.severity)));
      return {
        id: `surface:${label}`,
        label: shortHostLabel(label),
        target: label,
        status: relatedFindings.length > 0 ? 'finding' : 'observed',
        position: new THREE.Vector3(0, 0, 0),
        color: severityColor(severity),
        severity,
        findingCount: relatedFindings.length,
        kind: 'surface' as const,
        waiting: false,
      };
    });

  const matchedFindingIds = new Set(taskNodes.flatMap((node) => findingsForToolTarget(node.tool ?? '', node.target, findings).map((finding) => finding.id)));
  const unmatchedFindingNodes = findings
    .filter((finding) => !matchedFindingIds.has(finding.id))
    .slice(0, Math.max(0, 40 - taskNodes.length - surfaceNodes.length))
    .map((finding) => {
      const severity = severityLevel(finding.severity);
      return {
        id: `finding:${finding.id}`,
        label: `${titleCase(severity)} finding`,
        target: targetLabel(finding.target_id) || finding.title,
        status: finding.status,
        position: new THREE.Vector3(0, 0, 0),
        color: severityColor(severity),
        severity,
        findingCount: 1,
        kind: 'finding' as const,
        waiting: false,
      };
    });

  const nodes = [...taskNodes, ...surfaceNodes, ...unmatchedFindingNodes];

  if (!nodes.length) {
    return [
      {
        id: 'waiting-for-discovery',
        label: 'waiting for discovery',
        target: 'waiting for backend inventory',
        status: 'waiting',
        position: new THREE.Vector3(0, 0, 0),
        color: '#78b1d4',
        severity: 'none',
        findingCount: 0,
        kind: 'waiting',
        waiting: true,
      },
    ];
  }

  return nodes.map((node, index) => ({
    ...node,
    position: lanePosition(node, index, nodes),
  }));
}

function surfaceLabels(inventory: InventorySnapshot | null, findings: Finding[], tasks: Task[]): string[] {
  const labels = [
    ...inventoryHosts(inventory),
    ...findings.map((finding) => targetLabel(finding.target_id)),
    ...tasks.map((task) => targetLabel(task.target_id)),
  ].filter(Boolean);
  return Array.from(new Set(labels)).slice(0, 24);
}

function inventoryHosts(inventory: InventorySnapshot | null): string[] {
  const normalized = inventory?.normalized_inventory_json;
  if (!isJsonMap(normalized)) return [];
  const hosts = readArray(normalized.hosts)
    .map((host) => inventoryLabel(host, ['host', 'hostname', 'ip', 'address', 'target', 'id']))
    .filter(Boolean);
  const endpoints = readArray(normalized.http_endpoints)
    .map((endpoint) => inventoryLabel(endpoint, ['url', 'endpoint', 'target', 'host', 'hostname', 'id']))
    .filter(Boolean)
    .map(targetLabel);
  const services = readArray(normalized.services)
    .map((service) => inventoryLabel(service, ['service_id', 'host', 'hostname', 'ip', 'address', 'target']))
    .filter(Boolean);
  return Array.from(new Set([...hosts, ...endpoints, ...services]));
}

function targetLabel(value: string | null | undefined): string {
  if (!value) return '';
  const trimmed = value.trim();
  if (!trimmed) return '';
  try {
    const parsed = new URL(trimmed);
    const pathname = parsed.pathname && parsed.pathname !== '/' ? parsed.pathname.replace(/\/$/, '') : '';
    return `${parsed.hostname}${pathname}`.slice(0, 72);
  } catch {
    return trimmed.replace(/^https?:\/\//i, '').replace(/\/$/, '').slice(0, 72);
  }
}

function lanePosition(node: CinemaNode, index: number, nodes: CinemaNode[]): THREE.Vector3 {
  const sameKindBefore = nodes.slice(0, index).filter((candidate) => candidate.kind === node.kind).length;
  const sameKindTotal = Math.max(1, nodes.filter((candidate) => candidate.kind === node.kind).length);
  const hash = hashString(`${node.kind}:${node.id}:${node.target}`);
  const jitter = ((hash % 9) - 4) * 0.8;

  if (node.kind === 'task') {
    const progress = sameKindTotal > 1 ? sameKindBefore / (sameKindTotal - 1) : 0.5;
    const angle = progress * Math.PI * 0.9 - Math.PI * 0.45;
    const radius = 55 + (sameKindBefore % 2) * 12;
    return new THREE.Vector3(
      -60 + Math.cos(angle) * 12 + jitter,
      Math.sin(angle) * radius * 0.45 + jitter * 0.5,
      Math.sin(angle) * radius
    );
  }
  if (node.kind === 'surface') {
    const goldenRatio = (1 + Math.sqrt(5)) / 2;
    const theta = sameKindBefore * goldenRatio * Math.PI * 2;
    const radius = Math.sqrt(sameKindBefore) * 8;
    return new THREE.Vector3(
      Math.cos(theta) * radius * 1.1 + jitter * 0.5,
      ((sameKindBefore % 3) * 8 - 8) + jitter,
      Math.sin(theta) * radius
    );
  }
  if (node.kind === 'finding') {
    const progress = sameKindTotal > 1 ? sameKindBefore / (sameKindTotal - 1) : 0.5;
    const angle = progress * Math.PI * 0.9 - Math.PI * 0.45;
    const radius = 60 + (sameKindBefore % 3) * 10;
    return new THREE.Vector3(
      65 - Math.cos(angle) * 18 + jitter,
      Math.sin(angle) * radius * 0.5 + 8 + jitter * 0.5,
      Math.sin(angle) * radius
    );
  }
  return new THREE.Vector3(0, 0, 0);
}

function buildReplaySteps(nodes: CinemaNode[], tasks: Task[], findings: Finding[], logs: EventLog[]): ReplayStep[] {
  const logByTaskId = new Map(logs.map((log) => [log.id, log]));
  const steps = tasks.slice(0, 40).map((task) => {
    const relatedFindings = findingsForTask(task, findings);
    const severity = severityLevel(strongestSeverity(relatedFindings.map((finding) => finding.severity)));
    const target = targetLabel(task.target_id) || task.target_id || 'recorded target';
    const taskNode = nodes.find((node) => node.id === `task:${task.id}`) ?? null;
    const targetNode = findBestTargetNode(nodes, target, relatedFindings) ?? taskNode;
    const log = logByTaskId.get(task.id);
    return {
      id: `step:${task.id}`,
      tool: prettyTool(task.tool),
      target,
      message: log?.msg ?? `Task ${task.status}`,
      status: task.status,
      findingCount: relatedFindings.length,
      severity,
      command: commandLabel(task),
      taskNodeId: taskNode?.id ?? null,
      targetNodeId: targetNode?.id ?? null,
    };
  });

  const fallbackLogSteps = logs
    .filter((log) => !steps.some((step) => step.id === `step:${log.id}`))
    .map((log) => {
      const targetNode = findBestTargetNode(nodes, targetLabel(log.target), []);
      return {
        id: `log:${log.id}`,
        tool: log.tool,
        target: targetLabel(log.target) || log.target,
        message: log.msg,
        status: log.status,
        findingCount: 0,
        severity: 'none' as const,
        command: `$ ${log.tool.toLowerCase()} ${truncate(targetLabel(log.target) || log.target, 34)}`,
        taskNodeId: null,
        targetNodeId: targetNode?.id ?? null,
      };
    });

  return [...steps, ...fallbackLogSteps].sort((left, right) => severityRank(right.severity) - severityRank(left.severity));
}

function buildReplayLinks(steps: ReplayStep[], nodes: CinemaNode[]) {
  return steps
    .map((step) => {
      const from = step.taskNodeId ? nodes.find((node) => node.id === step.taskNodeId) ?? null : null;
      const to = step.targetNodeId ? nodes.find((node) => node.id === step.targetNodeId) ?? null : null;
      if (!from || !to || from.id === to.id) return null;
      return { from, to, stepId: step.id, severity: step.severity, findingCount: step.findingCount };
    })
    .filter((link): link is { from: CinemaNode; to: CinemaNode; stepId: string; severity: CinemaNode['severity']; findingCount: number } => Boolean(link));
}

function findBestTargetNode(nodes: CinemaNode[], target: string, relatedFindings: Finding[]): CinemaNode | null {
  const targetNode = nodes.find((node) => node.kind === 'surface' && targetMatches(target, node.target));
  if (targetNode) return targetNode;
  const findingTarget = relatedFindings[0]?.target_id;
  if (findingTarget) {
    const findingNode = nodes.find((node) => node.kind === 'finding' && targetMatches(findingTarget, node.target));
    if (findingNode) return findingNode;
  }
  return nodes.find((node) => !node.waiting && targetMatches(target, node.target)) ?? null;
}

function commandLabel(task: Task): string {
  const tool = task.tool.toLowerCase();
  const target = truncate(targetLabel(task.target_id) || task.target_id || 'target', 34);
  if (tool.includes('httpx')) return `$ httpx -u ${target}`;
  if (tool.includes('nuclei')) return `$ nuclei -u ${target}`;
  if (tool.includes('zap')) return `$ zap-baseline ${target}`;
  if (tool.includes('nmap')) return `$ nmap ${target}`;
  if (tool.includes('nikto')) return `$ nikto -h ${target}`;
  return `$ ${tool || 'check'} ${target}`;
}

function findingsForTask(task: Task, findings: Finding[]): Finding[] {
  return findingsForToolTarget(task.tool, targetLabel(task.target_id), findings);
}

function findingsForToolTarget(tool: string, _target: string, findings: Finding[]): Finding[] {
  const normalizedTool = normalizeToken(tool);
  return findings.filter((finding) => {
    const findingBlob = normalizeToken(
      [
        finding.finding_origin,
        finding.title,
        finding.evidence_ref,
        JSON.stringify(finding.proof_reference ?? {}),
        JSON.stringify(finding.replay_recipe_json ?? {}),
        finding.summary ?? '',
      ].join(' '),
    );
    const toolLinked = normalizedTool.length > 0 && findingBlob.includes(normalizedTool);
    const exactEvidenceLinked = finding.evidence_ref.includes(tool) || JSON.stringify(finding.proof_reference ?? {}).includes(tool);
    if (toolLinked || exactEvidenceLinked) return true;

    // For imported evidence that lacks tool provenance, keep the finding separate instead of painting
    // every same-target check red. This preserves honest per-check coloring in Cinema Mode.
    return false;
  });
}

function normalizeToken(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, '');
}

function prettyTool(value: string): string {
  const normalized = value.replace(/[_-]+/g, ' ').trim();
  return normalized ? normalized.toUpperCase() : 'CHECK';
}

function shortHostLabel(value: string): string {
  const label = targetLabel(value) || value;
  if (!label) return 'target';
  const parts = label.split('/');
  return parts[0].length > 26 ? truncate(parts[0], 26) : truncate(label, 32);
}

function nodeColor(node: CinemaNode, active: boolean): string {
  if (active) return '#5ecfff';
  if (node.findingCount > 0) return severityColor(node.severity);
  if (node.kind === 'finding') return severityColor(node.severity);
  return '#34d399';
}

function severityColor(severity: CinemaNode['severity']): string {
  if (severity === 'critical') return '#ef4444';
  if (severity === 'high') return '#f59e0b';
  if (severity === 'medium') return '#fde047';
  if (severity === 'low') return '#a78bfa';
  return '#34d399';
}

function severityLevel(value: string | null): CinemaNode['severity'] {
  const normalized = value?.toLowerCase() ?? '';
  if (normalized === 'critical') return 'critical';
  if (normalized === 'high') return 'high';
  if (normalized === 'medium') return 'medium';
  if (normalized === 'low' || normalized === 'info' || normalized === 'informational') return 'low';
  return 'none';
}

function strongestSeverity(severities: string[]): string | null {
  const normalized = severities.map((severity) => severity.toLowerCase());
  for (const severity of ['critical', 'high', 'medium', 'low', 'info']) {
    if (normalized.includes(severity)) return severity;
  }
  return null;
}

function severityRank(severity: CinemaNode['severity']): number {
  if (severity === 'critical') return 4;
  if (severity === 'high') return 3;
  if (severity === 'medium') return 2;
  if (severity === 'low') return 1;
  return 0;
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

function titleCase(value: string): string {
  return value
    .replace(/[_-]+/g, ' ')
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function buildAiChain(
  proposals: AgentProposal[],
  findings: Finding[],
): { chainNodes: ChainNode[]; chainLinks: ChainLink[] } {
  if (proposals.length === 0) return { chainNodes: [], chainLinks: [] };

  const sorted = [...proposals].sort((a, b) => Date.parse(a.created_at) - Date.parse(b.created_at));
  const chainNodes: ChainNode[] = [];
  const chainLinks: ChainLink[] = [];

  const tierX: Record<string, number> = { passive: -52, active: 0, intrusive: 52 };

  sorted.forEach((proposal, index) => {
    const tier = (proposal.risk_tier ?? 'passive').toLowerCase().includes('intrusive')
      ? 'intrusive'
      : (proposal.risk_tier ?? 'passive').toLowerCase().includes('active')
      ? 'active'
      : 'passive';
    const baseX = tierX[tier] ?? 0;
    const ySpacing = 14;
    const totalInTier = sorted.filter((p) => {
      const t = (p.risk_tier ?? 'passive').toLowerCase();
      return tier === 'intrusive' ? t.includes('intrusive') : tier === 'active' ? t.includes('active') && !t.includes('intrusive') : !t.includes('active') && !t.includes('intrusive');
    }).length;
    const tierIndex = sorted.slice(0, index + 1).filter((p) => {
      const t = (p.risk_tier ?? 'passive').toLowerCase();
      return tier === 'intrusive' ? t.includes('intrusive') : tier === 'active' ? t.includes('active') && !t.includes('intrusive') : !t.includes('active') && !t.includes('intrusive');
    }).length - 1;
    const yBase = (tierIndex - (totalInTier - 1) / 2) * ySpacing;
    const xJitter = hashString(proposal.id) % 8 - 4;

    const toolColor = tier === 'intrusive' ? '#a855f7' : tier === 'active' ? '#f97316' : '#5ecfff';
    const toolNode: ChainNode = {
      id: `ct:${proposal.id}`,
      label: prettyTool(proposal.proposed_tool),
      tool: proposal.proposed_tool,
      kind: tier === 'intrusive' ? 'pivot' : 'tool',
      severity: 'none',
      position: new THREE.Vector3(baseX + xJitter, yBase, 0),
      color: toolColor,
      reasoningText: proposal.reasoning_text,
      iterationIndex: index + 1,
      pulsing: false,
    };
    chainNodes.push(toolNode);

    // Finding node: match findings by tool name
    const toolToken = normalizeToken(proposal.proposed_tool);
    const relatedFindings = findings.filter((f) => {
      const blob = normalizeToken([f.finding_origin ?? '', f.evidence_ref, JSON.stringify(f.proof_reference ?? {})].join(' '));
      return toolToken.length > 3 && blob.includes(toolToken);
    });

    if (relatedFindings.length > 0) {
      const sev = severityLevel(strongestSeverity(relatedFindings.map((f) => f.severity)));
      const findingNode: ChainNode = {
        id: `cf:${proposal.id}`,
        label: `${relatedFindings.length} FINDING${relatedFindings.length > 1 ? 'S' : ''}`,
        tool: proposal.proposed_tool,
        kind: 'finding',
        severity: sev,
        position: new THREE.Vector3(baseX + xJitter + 10, yBase + 8, 0),
        color: severityColor(sev),
        reasoningText: null,
        iterationIndex: index + 1,
        pulsing: true,
      };
      chainNodes.push(findingNode);
      chainLinks.push({ from: toolNode, to: findingNode, color: severityColor(sev) });

      // Pivot link: if the next proposal follows this finding, connect it
      if (index + 1 < sorted.length) {
        const nextTool = sorted[index + 1];
        const nextTier = (nextTool.risk_tier ?? 'passive').toLowerCase().includes('intrusive')
          ? 'intrusive'
          : (nextTool.risk_tier ?? 'passive').toLowerCase().includes('active')
          ? 'active'
          : 'passive';
        if (nextTier !== tier) {
          const nextNodeId = `ct:${nextTool.id}`;
          chainLinks.push({
            from: findingNode,
            to: { ...findingNode, id: nextNodeId, position: new THREE.Vector3(tierX[nextTier] ?? 0, yBase, 0) },
            color: '#f97316',
          });
        }
      }
    }

    // Sequential link to previous tool node in same tier
    if (index > 0) {
      const prevInSameTier = chainNodes
        .slice(0, -relatedFindings.length > 0 ? -2 : -1)
        .filter((n) => n.kind !== 'finding' && n.tool !== toolNode.tool)
        .slice(-1)[0] ?? null;
      if (prevInSameTier && prevInSameTier.color === toolColor) {
        chainLinks.push({ from: prevInSameTier, to: toolNode, color: toolColor });
      }
    }
  });

  return { chainNodes, chainLinks };
}
