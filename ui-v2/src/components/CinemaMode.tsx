import { useMemo, useState, useEffect } from 'react';
import { Canvas, useFrame } from '@react-three/fiber';
import { Line, Sphere, Text, Html } from '@react-three/drei';
import { EffectComposer, Bloom } from '@react-three/postprocessing';
import * as THREE from 'three';

// Realistic mock targets based on standard pentest ranges
const TARGETS = [
  'api.example.com', 'shop.example.com', 'staging.example.com',
  '10.0.20.14', '10.0.20.15', 'db.internal.lan', 'dc01.corp.local',
  'vpn.example.com', 'mail.example.com', '10.0.50.200'
];

type EventLog = {
  tool: string;
  target: string;
  msg: string;
};

// Realistic event stream to simulate real tools working
const EVENT_STREAM: EventLog[] = [
  { tool: 'NMAP', target: '10.0.20.14', msg: 'Discovered open port 22/tcp (OpenSSH 8.2p1)' },
  { tool: 'NMAP', target: '10.0.20.15', msg: 'Discovered open port 80/tcp (nginx 1.18.0)' },
  { tool: 'HTTPX', target: 'api.example.com', msg: 'Status 200 OK [Content-Length: 4012]' },
  { tool: 'NUCLEI', target: 'api.example.com', msg: 'Template: exposures/tokens/jwt-leak' },
  { tool: 'NUCLEI', target: 'shop.example.com', msg: 'Found out-of-date WordPress 5.8' },
  { tool: 'ZAP', target: 'staging.example.com', msg: 'Spidering 142 endpoints completed' },
  { tool: 'SQLMAP', target: 'db.internal.lan', msg: 'Testing parameter "id" for SQLi...' },
  { tool: 'SQLMAP', target: 'db.internal.lan', msg: 'Payload found: boolean-based blind' },
  { tool: 'HYDRA', target: '10.0.20.14', msg: 'Brute-forcing SSH with common credentials...' },
  { tool: 'HYDRA', target: '10.0.20.14', msg: 'CRITICAL: Valid credentials found: admin:admin' },
  { tool: 'BLOODHOUND', target: 'dc01.corp.local', msg: 'Ingesting AD topology and sessions...' }
];

function Terminal3D({ logs }: { logs: typeof EVENT_STREAM }) {
  // Render a massive 3D text terminal floating in the sky
  return (
    <group position={[-25, 10, -30]} rotation={[0, Math.PI / 6, 0]}>
      <Text
        position={[0, 2, 0]}
        fontSize={1.5}
        color="#5ecfff"
        anchorX="left"
        font="https://fonts.gstatic.com/s/firamono/v14/N0bX2SlFPv1weGeLZDtgJv7S.woff"
      >
        AEGISPT // SYSTEM.STDOUT
        <meshBasicMaterial attach="material" toneMapped={false} />
      </Text>
      {logs.map((log, i) => {
        const isLatest = i === 0;
        return (
          <Text
            key={i + log.msg}
            position={[0, -i * 1.8, 0]}
            fontSize={isLatest ? 1.2 : 1}
            color={isLatest ? '#e4eeff' : 'rgba(120,177,212,0.4)'}
            anchorX="left"
            font="https://fonts.gstatic.com/s/firamono/v14/N0bX2SlFPv1weGeLZDtgJv7S.woff"
          >
            {`[${log.tool}] ${log.target} -> ${log.msg}`}
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
}: {
  activeEvent: EventLog;
  activeIndex: number;
  logs: EventLog[];
}) {
  const nodes = useMemo(() => {
    return TARGETS.map((label, i) => ({
      id: i,
      position: new THREE.Vector3(
        (Math.random() - 0.5) * 80,
        (Math.random() - 0.5) * 40,
        (Math.random() - 0.5) * 80
      ),
      label,
      color: label.includes('dc01') || label.includes('db') ? '#ef4444' : '#0ea5e9'
    }));
  }, []);

  const lines = useMemo(() => {
    const arr: [THREE.Vector3, THREE.Vector3][] = [];
    for (let i = 0; i < nodes.length; i++) {
      const connections = Math.floor(Math.random() * 2) + 1;
      for (let j = 0; j < connections; j++) {
        const closest = Math.floor(Math.random() * nodes.length);
        arr.push([nodes[i].position, nodes[closest].position]);
      }
    }
    return arr;
  }, [nodes]);

  const vec = useMemo(() => new THREE.Vector3(), []);
  const lookAtVec = useMemo(() => new THREE.Vector3(), []);

  useFrame((state) => {
    const targetNode = nodes[activeIndex];
    if (!targetNode) return;

    // Desired camera position (offset from the node so we fly *past/into* it)
    vec.copy(targetNode.position).add(new THREE.Vector3(5, 2, 10));

    // Smoothly interpolate the camera position
    state.camera.position.lerp(vec, 0.02);

    // Smoothly interpolate where the camera is looking
    lookAtVec.lerp(targetNode.position, 0.04);
    state.camera.lookAt(lookAtVec);
  });

  return (
    <group>
      <Terminal3D logs={logs} />

      {/* Network Edges */}
      {lines.map((pts, i) => (
        <Line
          key={i}
          points={pts}
          color="#0ea5e9"
          opacity={0.15}
          lineWidth={1}
          transparent
        />
      ))}

      {/* Target Nodes */}
      {nodes.map((node, i) => {
        const isActive = i === activeIndex;
        return (
          <group key={node.id} position={node.position}>
            {/* Glowing core */}
            <Sphere args={[isActive ? 0.6 : 0.2, 16, 16]}>
              <meshBasicMaterial color={isActive ? '#fbbf24' : node.color} toneMapped={false} />
            </Sphere>

            {/* Label */}
            <Text
              position={[0, isActive ? 2 : 1.2, 0]}
              fontSize={isActive ? 1.5 : 1}
              color={isActive ? '#fbbf24' : node.color}
              anchorX="center"
              anchorY="middle"
              font="https://fonts.gstatic.com/s/firamono/v14/N0bX2SlFPv1weGeLZDtgJv7S.woff"
            >
              {node.label}
              <meshBasicMaterial attach="material" toneMapped={false} color={isActive ? '#fbbf24' : node.color} />
            </Text>

            {/* Live Tool execution tag attached directly to the active node */}
            {isActive && activeEvent && (
              <Html position={[2, 0, 0]} center className="pointer-events-none">
                <div className="bg-[rgba(10,18,31,0.9)] border border-amber/40 p-3 rounded backdrop-blur-md min-w-[250px] shadow-[0_0_20px_rgba(251,191,36,0.2)]">
                  <div className="flex items-center gap-2 mb-1">
                    <div className="w-1.5 h-1.5 bg-amber rounded-full animate-pulse" />
                    <span className="text-[10px] text-amber font-bold uppercase tracking-widest">
                      {activeEvent.tool} ACTIVE
                    </span>
                  </div>
                  <div className="text-xs text-text font-mono">
                    {activeEvent.msg}
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

export default function CinemaMode({ onClose }: { onClose: () => void }) {
  const [eventIndex, setEventIndex] = useState(0);
  const [logs, setLogs] = useState<typeof EVENT_STREAM>([]);

  useEffect(() => {
    const interval = setInterval(() => {
      setEventIndex((prev) => (prev + 1) % EVENT_STREAM.length);
    }, 3500); // Trigger a new realistic event every 3.5 seconds

    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    // Add the new event to the top of our log array
    setLogs(prev => {
      const newLogs = [EVENT_STREAM[eventIndex], ...prev];
      return newLogs.slice(0, 10); // Keep only the last 10 logs for the 3D terminal
    });
  }, [eventIndex]);

  const activeEvent = EVENT_STREAM[eventIndex];
  // Find which node index matches this target
  const activeTargetIndex = TARGETS.findIndex(t => t === activeEvent.target) || 0;

  return (
    <div className="fixed inset-0 z-[999] bg-[#020408] overflow-hidden select-none">

      {/* Cinematic Overlay UI */}
      <div className="absolute top-8 left-8 z-10 flex items-center gap-4">
        <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-cyan text-lg font-extrabold text-[#04080f] shadow-[0_0_20px_rgba(94,207,255,0.6)]">
          ◈
        </div>
        <div>
          <h2 className="text-base font-bold tracking-widest text-cyan uppercase drop-shadow-[0_0_5px_rgba(94,207,255,0.8)]">Live Attack Path</h2>
          <p className="text-[11px] font-mono text-cyan/60 uppercase tracking-widest mt-0.5">3D Spatial Reconnaissance</p>
        </div>
      </div>

      <button
        onClick={onClose}
        className="absolute top-8 right-8 z-10 px-8 py-2.5 rounded-lg border border-cyan/40 bg-cyan/5 text-cyan font-mono text-[11px] hover:bg-cyan/20 hover:border-cyan hover:shadow-[0_0_15px_rgba(94,207,255,0.4)] transition-all uppercase tracking-[0.2em] cursor-pointer"
      >
        Exit Cinema Mode
      </button>

      {/* Decorative HUD Elements */}
      <div className="absolute bottom-8 left-8 z-10 flex flex-col gap-1 font-mono text-[10px] text-cyan/50 uppercase tracking-widest">
        <p>SYS.TOPOLOGY.MAP // OK</p>
        <p>ACTIVE.TOOL // {activeEvent.tool}</p>
        <p>TARGET // {activeEvent.target}</p>
      </div>

      {/* The 3D Canvas */}
      <Canvas camera={{ position: [0, 0, 100], fov: 60 }}>
        <color attach="background" args={['#020408']} />

        {/* Subtle ambient light so lines aren't pure black */}
        <ambientLight intensity={0.2} />

        <Network activeEvent={activeEvent} activeIndex={activeTargetIndex} logs={logs} />

        {/* High-end Bloom effect for the glow */}
        <EffectComposer enableNormalPass={false}>
          <Bloom luminanceThreshold={0.1} mipmapBlur intensity={1.5} radius={0.8} />
        </EffectComposer>
      </Canvas>
    </div>
  );
}
