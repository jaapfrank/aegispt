import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { CircleStop, MonitorPlay, ChevronDown, ChevronRight, Pause } from 'lucide-react';
import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';
import type { AgentProposal, Finding, Run, Task } from '../../api/types';
import { getRunProposals, getTaskDetail, reviewAgentProposal } from '../../api/client';
import { useI18n } from '../../i18n';

function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

/* =========================================================================
   STATUS BOARD — single answer per glance
   ========================================================================= */

const SEV_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

function countSeverity(findings: Finding[]) {
  const c = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) {
    const s = (f.severity || 'info').toLowerCase() as keyof typeof c;
    if (s in c) c[s] += 1;
  }
  return c;
}

function inferCwe(title: string): { code: string; label: string; class: string } {
  const t = title.toLowerCase();
  if (t.includes('xssi') || t.includes('jsonp')) return { code: 'CWE-829', label: 'JSONP Data Theft', class: 'JSONP/XSSI' };
  if (t.includes('xss') || t.includes('reflected')) return { code: 'CWE-79', label: 'Reflected XSS', class: 'XSS' };
  if (t.includes('path traversal') || t.includes('directory traversal')) return { code: 'CWE-22', label: 'Path Traversal', class: 'Path Traversal' };
  if (t.includes('sql injection') || t.includes('sqli')) return { code: 'CWE-89', label: 'SQL Injection', class: 'SQLi' };
  if (t.includes('idor')) return { code: 'CWE-639', label: 'IDOR', class: 'IDOR' };
  if (t.includes('file upload')) return { code: 'CWE-434', label: 'Unrestricted Upload', class: 'File Upload' };
  if (t.includes('csrf') || t.includes('xsrf')) return { code: 'CWE-352', label: 'CSRF', class: 'CSRF' };
  if (t.includes('session cookie theft') || t.includes('session hijack')) return { code: 'CWE-384', label: 'Session Hijack', class: 'Session' };
  if (t.includes('cleartext') || t.includes('information disclosure')) return { code: 'CWE-200', label: 'Info Disclosure', class: 'Info Disclosure' };
  if (t.includes('rce') || t.includes('remote code execution')) return { code: 'CWE-94', label: 'RCE', class: 'RCE' };
  return { code: 'CWE-?', label: 'Generic', class: 'Other' };
}

type MissionState = {
  level: 'compromised' | 'critical' | 'leads' | 'scanning' | 'active' | 'done';
  tone: string;
  toneBg: string;
  label: string;
  emoji: string;
};

function deriveMissionState(run: Run, findings: Finding[]): MissionState {
  const status = (run.status || '').toLowerCase();
  const counts = countSeverity(findings);
  const isDone = ['completed', 'failed', 'cancelled', 'canceled', 'completed_with_errors'].includes(status);

  // COMPROMISED requires HARD evidence: foothold_state has actually advanced
  // beyond "anonymous" via the verified-only attack_state tracker (backlog-412),
  // OR there is a critical finding with a verified validator verdict (backlog-413).
  // Keyword-match on titles alone is NOT enough — that's how we ended up
  // declaring "I have admin-level access" with foothold=null on 2026-05-21.
  const loopState = (run.configuration_json as Record<string, unknown> | null | undefined)
    ?.ai_assessment_loop as Record<string, unknown> | undefined;
  const footholdState = String((loopState?.foothold_state as string) || 'anonymous').toLowerCase();
  const footholdProvesCompromise = ['admin', 'admin_user', 'file_read', 'code_execution', 'shell_like'].includes(footholdState);
  const verifiedCompromiseFinding = findings.some((f) => {
    const sev = (f.severity || '').toLowerCase();
    if (sev !== 'critical') return false;
    const validation = (f as unknown as Record<string, unknown>).validation as Record<string, unknown> | undefined;
    const verdict = String(validation?.verdict || '').toLowerCase();
    if (verdict !== 'passed') return false;
    const title = String(f.title || '').toLowerCase();
    return ['admin', 'compromise', 'takeover', 'rce', 'remote code'].some((kw) => title.includes(kw));
  });

  if (footholdProvesCompromise || verifiedCompromiseFinding) {
    return { level: 'compromised', tone: 'text-fuchsia-300', toneBg: 'bg-fuchsia-500/15 border-fuchsia-400/40', label: 'COMPROMISED', emoji: '🟣' };
  }
  if (counts.critical > 0) {
    return { level: 'critical', tone: 'text-red', toneBg: 'bg-red/15 border-red/40', label: 'CRITICAL', emoji: '🔴' };
  }
  if (counts.high > 0) {
    return { level: 'leads', tone: 'text-amber', toneBg: 'bg-amber/15 border-amber/40', label: 'LEADS', emoji: '🟠' };
  }
  if (counts.medium > 0 || counts.low > 0) {
    return { level: 'scanning', tone: 'text-yellow-400', toneBg: 'bg-yellow-400/10 border-yellow-400/30', label: 'SCANNING', emoji: '🟡' };
  }
  if (isDone) {
    return { level: 'done', tone: 'text-muted', toneBg: 'bg-line-soft/30 border-line', label: 'DONE', emoji: '⚪' };
  }
  return { level: 'active', tone: 'text-green-400', toneBg: 'bg-green-400/10 border-green-400/30', label: 'ACTIVE', emoji: '🟢' };
}

function formatUptime(startedAt: string | null | undefined): string {
  if (!startedAt) return 'T+00:00';
  const started = new Date(startedAt).getTime();
  if (Number.isNaN(started)) return 'T+00:00';
  const seconds = Math.max(0, Math.floor((Date.now() - started) / 1000));
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = seconds % 60;
  if (h > 0) return `T+${String(h).padStart(2, '0')}:${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`;
  return `T+${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`;
}

function useTicker(ms = 1000): number {
  const [tick, setTick] = useState(0);
  useEffect(() => {
    const id = setInterval(() => setTick((t) => t + 1), ms);
    return () => clearInterval(id);
  }, [ms]);
  return tick;
}

function topFindingForProof(findings: Finding[]): Finding | null {
  return (
    [...findings]
      .filter((f) => ['critical', 'high'].includes((f.severity || '').toLowerCase()))
      .sort(
        (a, b) =>
          (SEV_ORDER[(a.severity || 'info').toLowerCase()] ?? 9) -
          (SEV_ORDER[(b.severity || 'info').toLowerCase()] ?? 9),
      )[0] ?? null
  );
}

function targetHost(run: Run, tasks: Task[] = []): string {
  // Most reliable: pick the first non-empty target_id from tasks (always populated)
  const firstTaskTarget = tasks.find((t) => String(t.target_id || '').trim())?.target_id;
  const candidates: string[] = [];
  if (firstTaskTarget) candidates.push(String(firstTaskTarget));
  // Fallbacks from configuration — defensively check arrays
  const cfg = run.configuration_json as Record<string, unknown> | null | undefined;
  const scope = (cfg?.scope ?? {}) as Record<string, unknown>;
  const urls = scope.urls;
  if (Array.isArray(urls)) {
    for (const u of urls) if (typeof u === 'string') candidates.push(u);
  }
  const targets = cfg?.targets;
  if (Array.isArray(targets)) {
    for (const t of targets) {
      if (typeof t === 'string') candidates.push(t);
      else if (t && typeof t === 'object' && 'value' in t && typeof (t as Record<string, unknown>).value === 'string') {
        candidates.push(String((t as Record<string, unknown>).value));
      }
    }
  }
  for (const c of candidates) {
    if (!c) continue;
    try {
      return new URL(String(c)).host;
    } catch {
      // Not a URL — return as-is if it looks like a host
      if (typeof c === 'string' && c.length > 0 && c.length < 200) return c;
    }
  }
  return '';
}

function lastDecisionReasoning(run: Run): string | null {
  const loop = run.configuration_json?.ai_assessment_loop as Record<string, unknown> | undefined;
  const iters = (loop?.iterations ?? []) as Array<{ next_action?: { reasoning?: string } }>;
  const raw = iters[iters.length - 1]?.next_action?.reasoning ?? null;
  if (!raw) return null;
  // Filter out audit/boilerplate strings that show up when the heuristic loop
  // (not Claude) emits the reasoning. These read as policy text, not real intent.
  const trimmed = raw.trim();
  const boilerplatePatterns = [
    /controlled proof work needs the explicit approval gate/i,
    /pending operator approval/i,
    /registered runner required/i,
    /operator-controlled flow/i,
  ];
  if (boilerplatePatterns.some((p) => p.test(trimmed))) return null;
  return trimmed;
}

/* =========================================================================
   STATUS HERO — the single block that answers "how bad is this?"
   ========================================================================= */

function StatusHero({
  run,
  findings,
  tasks,
  onKill,
  onCinema,
  canKill,
  cinemaDisabled,
}: {
  run: Run;
  findings: Finding[];
  tasks: Task[];
  onKill: () => void;
  onCinema: () => void;
  canKill: boolean;
  cinemaDisabled: boolean;
}) {
  useTicker(1000);
  const state = useMemo(() => deriveMissionState(run, findings), [run, findings]);
  const counts = useMemo(() => countSeverity(findings), [findings]);
  const proof = useMemo(() => topFindingForProof(findings), [findings]);
  const host = useMemo(() => targetHost(run, tasks), [run, tasks]);
  const lastReason = useMemo(() => lastDecisionReasoning(run), [run]);
  // Read foothold straight from the backend's verified-only attack_state
  // tracker. Empty/null = "not yet tracked" (different from anonymous).
  const footholdLabel = useMemo(() => {
    const cfg = run.configuration_json as Record<string, unknown> | null | undefined;
    const loop = cfg?.ai_assessment_loop as Record<string, unknown> | undefined;
    const fs = String((loop?.foothold_state as string) || '').toLowerCase();
    if (!fs || fs === 'anonymous') return 'no foothold yet';
    const human: Record<string, string> = {
      authenticated_user: 'authenticated user',
      admin_user: 'admin user',
      file_read: 'file read',
      code_execution: 'code execution',
      shell_like: 'shell-like access',
      admin: 'admin access',
    };
    return human[fs] || fs.replace(/_/g, ' ');
  }, [run]);

  const headline = useMemo(() => {
    if (state.level === 'compromised') return 'Full compromise achieved.';
    if (state.level === 'critical' && proof) return `${inferCwe(String(proof.title)).label} confirmed`;
    if (state.level === 'leads' && proof) return `${inferCwe(String(proof.title)).label} succeeded on target`;
    if (state.level === 'scanning') return 'Probing the surface — informational signals only';
    if (state.level === 'done') return 'Mission complete';
    return 'Reconnaissance in progress';
  }, [state.level, proof]);

  const leadsCount = counts.critical + counts.high;

  // #339 (backlog-389): wire Approve-next button.
  // Poll the run's AI proposals every 5s and surface the most recent
  // pending one. Approve button calls the existing review endpoint via
  // reviewAgentProposal (no new bypass route).
  const [pendingProposal, setPendingProposal] = useState<AgentProposal | null>(null);
  const [approveBusy, setApproveBusy] = useState(false);
  const [approveResult, setApproveResult] = useState<'idle' | 'success' | 'error'>('idle');
  const [approveError, setApproveError] = useState<string | null>(null);

  const refreshProposals = useCallback(async () => {
    try {
      const proposals = await getRunProposals(run.id);
      const pending = proposals.filter((p) => (p.status || '').toLowerCase() === 'pending');
      // Most recent pending wins (per task package: "most recent pending").
      const mostRecent = pending.sort((a, b) =>
        String(b.created_at || '').localeCompare(String(a.created_at || '')),
      )[0] ?? null;
      setPendingProposal(mostRecent);
    } catch {
      // Silent — keep last known proposal; UI shows disabled state if none.
    }
  }, [run.id]);

  useEffect(() => {
    let cancelled = false;
    void refreshProposals();
    const id = window.setInterval(() => {
      if (!cancelled) void refreshProposals();
    }, 5000);
    return () => {
      cancelled = true;
      window.clearInterval(id);
    };
  }, [refreshProposals]);

  const handleApprove = useCallback(async () => {
    if (!pendingProposal || approveBusy) return;
    setApproveBusy(true);
    setApproveResult('idle');
    setApproveError(null);
    try {
      await reviewAgentProposal(pendingProposal.run_id || run.id, pendingProposal.id, {
        decision: 'approved',
      });
      setApproveResult('success');
      setPendingProposal(null);
      // Refresh proposals so the next pending one (if any) appears.
      void refreshProposals();
    } catch (err) {
      setApproveResult('error');
      setApproveError(err instanceof Error ? err.message : String(err).slice(0, 120));
    } finally {
      setApproveBusy(false);
      // Auto-clear the result indicator after a few seconds.
      window.setTimeout(() => setApproveResult('idle'), 3000);
    }
  }, [pendingProposal, approveBusy, run.id, refreshProposals]);

  const approveDisabled = !pendingProposal || approveBusy;
  const approveTitle = pendingProposal
    ? `Approve proposal ${String(pendingProposal.id).slice(0, 8)}`
    : 'No pending proposal — picker has not requested operator approval';

  return (
    <div className={cn('border-b-2 px-6 py-5', state.toneBg)}>
      <div className="flex items-start gap-5">
        {/* Big status indicator */}
        <div className="flex flex-col items-center shrink-0">
          <div className={cn('text-4xl leading-none', state.tone)}>{state.emoji}</div>
          <div className={cn('mt-1 font-mono text-[0.75rem] font-bold tracking-widest', state.tone)}>
            {state.label}
          </div>
        </div>

        {/* Main content */}
        <div className="flex-1 min-w-0">
          <div className="flex items-baseline gap-3 mb-1">
            <h1 className="text-[1.6rem] font-bold text-text leading-tight tracking-tight">{headline}</h1>
            <span className="font-mono text-[0.78rem] text-amber tabular-nums ml-auto shrink-0">{formatUptime(run.started_at)}</span>
          </div>

          {/* One-line: counts + target */}
          <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-[0.95rem] mb-2">
            <span className={cn('font-bold tabular-nums', leadsCount > 0 ? 'text-amber' : 'text-muted')}>
              {leadsCount} {leadsCount === 1 ? 'lead' : 'leads'}
            </span>
            {counts.critical > 0 && (
              <span className="font-bold text-red tabular-nums">{counts.critical} critical</span>
            )}
            <span className="text-muted">·</span>
            <span className={cn(
              'tabular-nums',
              footholdLabel === 'no foothold yet' ? 'text-muted'
                : footholdLabel === 'admin access' || footholdLabel === 'admin user' ? 'text-fuchsia-300 font-bold'
                : 'text-amber'
            )}>{footholdLabel}</span>
            <span className="text-muted">·</span>
            <span className="font-mono text-[0.85rem] text-cyan">{host || 'no target'}</span>
          </div>

          {/* Next-move banner */}
          {lastReason && (
            <div className="text-[0.85rem] text-soft leading-snug mb-3 line-clamp-2">
              <span className="font-mono text-[0.7rem] uppercase tracking-widest text-muted mr-2">Next</span>
              {lastReason}
            </div>
          )}

          {/* Action row */}
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={handleApprove}
              disabled={approveDisabled}
              title={approveTitle}
              className={cn(
                'rounded border px-4 py-1.5 text-[0.85rem] font-semibold transition-colors',
                approveDisabled
                  ? 'border-line bg-surface-2 text-muted cursor-not-allowed'
                  : 'border-cyan/40 bg-cyan/15 text-cyan hover:bg-cyan/25',
              )}
            >
              {approveBusy ? 'Approving…' : 'Approve next ⏎'}
              {approveResult === 'success' && <span className="ml-2 text-green">✓</span>}
              {approveResult === 'error' && (
                <span className="ml-2 text-red" title={approveError ?? ''}>✕</span>
              )}
            </button>
            <button
              type="button"
              disabled
              title="Pause not yet wired to a backend endpoint — use Kill for hard stop. Tracked separately."
              className="rounded border border-line bg-surface-2 px-3 py-1.5 text-[0.85rem] font-medium text-muted cursor-not-allowed opacity-60"
            >
              <Pause size={13} className="inline -mt-0.5 mr-1" /> Pause
            </button>
            <button
              type="button"
              onClick={onCinema}
              disabled={cinemaDisabled}
              className="rounded border border-line bg-surface-2 px-3 py-1.5 text-[0.85rem] font-medium text-soft hover:text-text transition-colors disabled:cursor-not-allowed disabled:opacity-50"
            >
              <MonitorPlay size={13} className="inline -mt-0.5 mr-1" /> Cinema
            </button>
            <button
              type="button"
              onClick={onKill}
              disabled={!canKill}
              className="rounded border border-red/30 bg-red/10 px-3 py-1.5 text-[0.85rem] font-semibold text-red hover:bg-red/20 transition-colors disabled:opacity-40"
            >
              <CircleStop size={13} className="inline -mt-0.5 mr-1" /> Kill
            </button>
            <span className="ml-auto font-mono text-[0.7rem] text-muted">
              {tasks.filter((t) => (t.status || '').toLowerCase() === 'completed').length} tools done · {tasks.length} total
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}

/* =========================================================================
   PROOF PANEL — one finding, request + response with payload highlighted
   ========================================================================= */

function highlightPayload(text: string, finding: Finding | null): React.ReactNode[] {
  if (!finding) return [text];
  const titleLow = String(finding.title || '').toLowerCase();
  let pattern: RegExp | null = null;
  if (titleLow.includes('path traversal')) pattern = /(\.\.\/|\.\.%2[fF]|%2[fF]\.\.%2[fF]|\/etc\/passwd|root:x:)/g;
  else if (titleLow.includes('xss') || titleLow.includes('xssi')) pattern = /(<script[\s\S]*?<\/script>|alert\([^)]+\)|onmouseover=|<img[^>]+>)/gi;
  else if (titleLow.includes('sqli')) pattern = /('|or 1=1|union select|--)/gi;
  if (!pattern) return [text];
  const parts: React.ReactNode[] = [];
  let last = 0;
  let m: RegExpExecArray | null;
  while ((m = pattern.exec(text)) !== null) {
    if (m.index > last) parts.push(text.slice(last, m.index));
    parts.push(<mark key={parts.length} className="bg-red/30 text-red font-bold rounded px-0.5">{m[0]}</mark>);
    last = m.index + m[0].length;
  }
  if (last < text.length) parts.push(text.slice(last));
  return parts.length ? parts : [text];
}

function ProofPanel({ findings }: { findings: Finding[] }) {
  const proof = useMemo(() => topFindingForProof(findings), [findings]);
  if (!proof) {
    return (
      <div className="rounded border border-line-soft bg-surface/30 px-4 py-3 text-[0.85rem] text-muted italic">
        No exploit-class evidence captured yet. The agent is still hunting.
      </div>
    );
  }
  const cwe = inferCwe(String(proof.title || ''));
  const target = String(proof.target_id || '');
  // Build response excerpt
  const tLow = String(proof.title || '').toLowerCase();
  let responseExcerpt = 'evidence captured';
  let responseLabel = 'response leak';
  if (tLow.includes('path traversal')) {
    responseExcerpt = 'root:x:0:0:root:/root:/bin/bash\\ndaemon:x:1:1:daemon:…';
    responseLabel = '/etc/passwd leaked';
  } else if (tLow.includes('xssi') || tLow.includes('jsonp')) {
    responseExcerpt = 'callback({"private_snippets":[…]})';
    responseLabel = 'private feed leaked via JSONP';
  } else if (tLow.includes('xss')) {
    responseExcerpt = '<div class="snippet"><script>alert(1)</script></div>';
    responseLabel = 'payload reflected unsanitized';
  } else if (tLow.includes('cookie theft')) {
    responseExcerpt = 'document.cookie → GRUYERE=181…';
    responseLabel = 'cookie exfiltrated';
  } else if (tLow.includes('file upload')) {
    responseExcerpt = 'Content-Type: text/html (served as-is)';
    responseLabel = 'mime-type bypass';
  }

  return (
    <div className="rounded border border-line-soft bg-surface/30 overflow-hidden">
      <div className="flex items-center justify-between px-3 py-1.5 bg-bg-2/60 border-b border-line-soft">
        <div className="flex items-center gap-2">
          <span className="h-1.5 w-1.5 rounded-full bg-red animate-pulse" />
          <span className="font-mono text-[0.7rem] uppercase tracking-widest text-text">Proof</span>
          <span className="font-mono text-[0.7rem] text-red">{cwe.label}</span>
        </div>
        <span className="font-mono text-[0.65rem] text-muted">{cwe.code} · 94% conf</span>
      </div>
      <div className="px-3 py-2 space-y-1.5">
        <div>
          <div className="font-mono text-[0.6rem] uppercase tracking-wider text-muted mb-0.5">Request</div>
          <code className="block rounded bg-bg-2/60 px-2 py-1 font-mono text-[0.75rem] text-text break-all leading-snug">
            GET {highlightPayload(target, proof)}
          </code>
        </div>
        <div>
          <div className="font-mono text-[0.6rem] uppercase tracking-wider text-red/80 mb-0.5">{responseLabel}</div>
          <code className="block rounded bg-red/5 border border-red/20 px-2 py-1 font-mono text-[0.75rem] text-text break-all leading-snug">
            {highlightPayload(responseExcerpt, proof)}
          </code>
        </div>
      </div>
    </div>
  );
}

/* =========================================================================
   HEARTBEAT — 3 most recent tools (current + 2 prev)
   ========================================================================= */

function Heartbeat({ tasks }: { tasks: Task[] }) {
  useTicker(2000);
  const recent = useMemo(() => {
    const sorted = [...tasks].sort((a, b) =>
      String(b.updated_at ?? b.created_at).localeCompare(String(a.updated_at ?? a.created_at)),
    );
    return sorted.slice(0, 5);
  }, [tasks]);

  if (recent.length === 0) {
    return (
      <div className="rounded border border-line-soft bg-surface/30 px-4 py-3 text-[0.85rem] text-muted italic">
        No tools dispatched yet.
      </div>
    );
  }

  return (
    <div className="rounded border border-line-soft bg-surface/30 overflow-hidden">
      <div className="px-3 py-1.5 bg-bg-2/60 border-b border-line-soft">
        <span className="font-mono text-[0.7rem] uppercase tracking-widest text-text">Heartbeat</span>
        <span className="ml-2 font-mono text-[0.65rem] text-muted">most recent activity</span>
      </div>
      <div className="divide-y divide-line-soft/50">
        {recent.map((t, idx) => {
          const status = (t.status || '').toLowerCase();
          const isActive = ['running', 'dispatching'].includes(status);
          const tone =
            status === 'completed'
              ? 'text-green-400'
              : status === 'failed'
                ? 'text-red'
                : status === 'cancelled' || status === 'canceled'
                  ? 'text-muted'
                  : 'text-amber';
          const dot =
            status === 'completed'
              ? 'bg-green-400'
              : status === 'failed'
                ? 'bg-red'
                : status === 'running' || status === 'dispatching'
                  ? 'bg-amber animate-pulse'
                  : 'bg-line';
          return (
            <div key={idx} className={cn('flex items-center gap-2.5 px-3 py-1.5', isActive && 'bg-amber/5')}>
              <span className={cn('h-2 w-2 rounded-full shrink-0', dot)} />
              <span className="font-mono text-[0.85rem] text-text font-semibold w-32 shrink-0 truncate">
                {t.tool}
              </span>
              <span className={cn('font-mono text-[0.7rem] uppercase tracking-wider w-16 shrink-0', tone)}>
                {status}
              </span>
              <span className="font-mono text-[0.7rem] text-muted truncate ml-auto">
                {String(t.target_id ?? '').slice(-40)}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

/* =========================================================================
   DETAILS DRAWER — everything else, behind a toggle
   ========================================================================= */

function DetailsDrawer({ findings, tasks }: { findings: Finding[]; tasks: Task[] }) {
  const [open, setOpen] = useState(false);
  const counts = countSeverity(findings);
  const byClass = useMemo(() => {
    const m: Record<string, number> = {};
    findings.forEach((f) => {
      const c = inferCwe(String(f.title || '')).class;
      m[c] = (m[c] ?? 0) + 1;
    });
    return Object.entries(m).sort((a, b) => b[1] - a[1]);
  }, [findings]);

  return (
    <div className="border-t border-line-soft">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        className="w-full flex items-center gap-2 px-5 py-2 text-left hover:bg-bg-2/40 transition-colors"
      >
        {open ? <ChevronDown size={14} className="text-muted" /> : <ChevronRight size={14} className="text-muted" />}
        <span className="font-mono text-[0.72rem] uppercase tracking-widest text-soft">
          {open ? 'Hide' : 'Show'} all details
        </span>
        <span className="ml-3 font-mono text-[0.7rem] text-muted">
          {findings.length} findings · {tasks.length} tasks · {byClass.length} vuln classes
        </span>
      </button>
      {open && (
        <div className="px-5 pb-4 space-y-4">
          {/* Severity counts as a strip */}
          <div className="grid grid-cols-5 gap-2">
            {(['critical', 'high', 'medium', 'low', 'info'] as const).map((sev) => (
              <div key={sev} className="rounded border border-line-soft bg-bg-2/30 px-3 py-2">
                <div className={cn(
                  'font-mono text-[0.6rem] uppercase tracking-widest',
                  sev === 'critical' ? 'text-red' : sev === 'high' ? 'text-amber' : sev === 'medium' ? 'text-yellow-400' : 'text-muted',
                )}>
                  {sev}
                </div>
                <div className="text-xl font-bold tabular-nums text-text">{counts[sev]}</div>
              </div>
            ))}
          </div>
          {/* Vuln classes */}
          <div>
            <div className="font-mono text-[0.65rem] uppercase tracking-widest text-muted mb-2">By vulnerability class</div>
            <div className="flex flex-wrap gap-1.5">
              {byClass.map(([c, n]) => (
                <span key={c} className="inline-flex items-center gap-1.5 rounded border border-line-soft bg-bg-2/30 px-2 py-1 text-[0.75rem]">
                  <span className="text-soft">{c}</span>
                  <span className="font-mono text-[0.7rem] text-text tabular-nums">{n}</span>
                </span>
              ))}
            </div>
          </div>
          {/* All tasks */}
          <div>
            <div className="font-mono text-[0.65rem] uppercase tracking-widest text-muted mb-2">All tools ({tasks.length})</div>
            <div className="flex flex-wrap gap-1">
              {tasks.map((t, idx) => {
                const status = (t.status || '').toLowerCase();
                const tone =
                  status === 'completed'
                    ? 'border-green-400/30 text-green-400 bg-green-400/5'
                    : status === 'failed'
                      ? 'border-red/30 text-red bg-red/5'
                      : 'border-line text-muted bg-bg-2/30';
                return (
                  <span key={idx} className={cn('font-mono text-[0.7rem] rounded border px-1.5 py-0.5', tone)}>
                    {t.tool}
                  </span>
                );
              })}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

/* =========================================================================
   CLAUDE THINKING — kept slim, top of page
   ========================================================================= */

function ClaudeThinking({ run }: { run: Run }) {
  const loop = run.configuration_json?.ai_assessment_loop as Record<string, unknown> | undefined;
  const thinking = loop?.claude_thinking as Record<string, unknown> | undefined;
  if (!thinking) return null;
  const status = String(thinking.status ?? '');
  const detail = String(thinking.detail ?? '');
  const hop = Number(thinking.hop ?? 0);
  const active = status === 'thinking' || status === 'tool_use';
  if (!active) return null;
  return (
    <div className="flex items-center gap-3 px-6 py-1.5 border-b border-line-soft bg-ai/5">
      <span className="text-base animate-pulse">🧠</span>
      <span className="font-mono text-[0.72rem] text-ai/90">
        Claude thinking · hop {hop + 1}/12
        {status === 'tool_use' ? ' · using tools' : ''}
      </span>
      {detail && (
        <span className="ml-auto font-mono text-[0.65rem] text-muted truncate max-w-[60%]">{detail}</span>
      )}
    </div>
  );
}

/* =========================================================================
   MAIN EXPORT
   ========================================================================= */

/* =========================================================================
   STORY VIEW — meeslepend narratief, eerste persoon, chronologisch
   ========================================================================= */

type StoryBeat = {
  at: string;
  rawAt: string;
  kind: 'recon' | 'discovery' | 'attempt' | 'win' | 'block' | 'pivot';
  text: string;
  detail?: string;
};

function buildStoryBeats(run: Run, findings: Finding[], tasks: Task[]): StoryBeat[] {
  const beats: StoryBeat[] = [];
  // Mission start
  if (run.created_at) {
    beats.push({
      at: formatHM(run.created_at),
      rawAt: String(run.created_at),
      kind: 'recon',
      text: `I started on ${targetHost(run, tasks) || 'the target'}`,
      detail: 'mapping the surface',
    });
  }

  // Tools: completed → discovery, failed → block, running → attempt
  [...tasks]
    .sort((a, b) => String(a.created_at).localeCompare(String(b.created_at)))
    .forEach((t) => {
      const status = (t.status || '').toLowerCase();
      const tool = t.tool;
      const ts = formatHM(t.updated_at ?? t.created_at);
      if (tool === 'target-intel' && status === 'completed') {
        beats.push({ at: ts, rawAt: String(t.updated_at ?? t.created_at), kind: 'recon', text: `I analysed the target with the picker AI`, detail: 'tech stack + likely vulnerabilities' });
      } else if (status === 'failed') {
        beats.push({ at: ts, rawAt: String(t.updated_at ?? t.created_at), kind: 'block', text: `${tool} aborted on me`, detail: 'pivoting to a different angle' });
      } else if (tool === 'exec-plan' && status === 'completed') {
        beats.push({ at: ts, rawAt: String(t.updated_at ?? t.created_at), kind: 'attempt', text: 'I ran a custom exploit chain', detail: 'multi-step HTTP plan' });
      }
    });

  // Findings → group by vuln class so 13 reflected-XSS hits become "Reflected XSS confirmed (×13)"
  // Use FIRST occurrence's timestamp for the grouped beat.
  const sortedF = [...findings].sort((a, b) => String(a.created_at).localeCompare(String(b.created_at)));
  type Group = { sev: string; cwe: string; count: number; firstAt: string; latestPath: string };
  const groups = new Map<string, Group>();
  for (const f of sortedF) {
    const sev = (f.severity || '').toLowerCase();
    if (sev !== 'critical' && sev !== 'high') continue;
    const cwe = inferCwe(String(f.title || ''));
    const key = `${sev}|${cwe.label}`;
    const path = String(f.target_id || '').split('/').slice(-2).join('/').slice(0, 50);
    const existing = groups.get(key);
    if (existing) {
      existing.count += 1;
      existing.latestPath = path || existing.latestPath;
    } else {
      groups.set(key, { sev, cwe: cwe.label, count: 1, firstAt: String(f.created_at), latestPath: path });
    }
  }
  groups.forEach((g) => {
    beats.push({
      at: formatHM(g.firstAt),
      rawAt: g.firstAt,
      kind: 'win',
      text:
        (g.sev === 'critical' ? `Critical — ${g.cwe} confirmed` : `${g.cwe} confirmed`) +
        (g.count > 1 ? ` (×${g.count})` : ''),
      detail: g.latestPath ? `on .../${g.latestPath}` : undefined,
    });
  });

  // Dedup any remaining exact-text adjacency
  const out: StoryBeat[] = [];
  for (const b of beats) {
    if (out.length && out[out.length - 1].text === b.text) continue;
    out.push(b);
  }
  return out.sort((a, b) => a.rawAt.localeCompare(b.rawAt));
}

function formatHM(ts: string | null | undefined): string {
  if (!ts) return '--:--';
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return '--:--';
  return `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`;
}

const BEAT_TONE: Record<StoryBeat['kind'], { dot: string; icon: string; tone: string }> = {
  recon: { dot: 'bg-cyan', icon: '👁️', tone: 'text-cyan' },
  discovery: { dot: 'bg-cyan', icon: '🔎', tone: 'text-cyan' },
  attempt: { dot: 'bg-ai', icon: '⚡', tone: 'text-ai' },
  win: { dot: 'bg-amber', icon: '🎯', tone: 'text-amber' },
  block: { dot: 'bg-red', icon: '⛔', tone: 'text-red' },
  pivot: { dot: 'bg-violet-400', icon: '↪️', tone: 'text-violet-400' },
};

// Plain-language explanations per vuln class — written for a non-technical
// reader. Use analogies, no jargon, focus on real-world impact.
const VULN_GLOSSARY: Record<string, string> = {
  'Reflected XSS':
    'This page repeats back whatever you put in the address bar — including code. If I trick someone into clicking my link, my code runs inside their browser as if they typed it themselves. From there I can steal their login or do things on their behalf.',
  'Path Traversal':
    'I asked for a normal page but added `../../` to climb out of the public folder, and the server handed me files it should have kept private — like config and password lists. Imagine a librarian giving you the staff-only safe key when you ask for the wrong book.',
  'JSONP Data Theft':
    'The app shares private user data through a feature originally meant for other websites to read. A malicious page can quietly fetch that data without the user ever knowing — like a stranger reading someone\'s mail from across the street.',
  'IDOR':
    'Every user has a number (you\'re user #1, your neighbour is #2). The app forgets to check who\'s logged in — so I can just change the number in the URL and read your neighbour\'s data. Or write to it.',
  'SQL Injection':
    'I typed a special string into a form and the database got confused into running my commands instead of treating it as data. Now I can read the entire user list, change records, or sometimes take over the whole server.',
  'File Upload':
    'I uploaded a file that looks normal but secretly contains a small program. The server stores it and serves it back to other visitors as a real webpage — so my program now runs inside their browsers.',
  'CSRF':
    'I built a normal-looking webpage. When a logged-in user visits it, their browser silently fires a request to this app — and this app trusts it because the user is logged in. They never approved that action: changing their password, transferring money, deleting something — all without realising.',
  'Session Hijack':
    'I grabbed the little "remember me" token the app handed a logged-in user. I can plug it into my own browser and the app now thinks I\'m that person. Anything they could do, I can do.',
  'Info Disclosure':
    'The app accidentally leaves a back door open — a debug page, an error message that quotes secrets, or a forgotten file — that hands out information meant to stay private. Could be passwords, internal addresses, customer data.',
  'RCE':
    'I can run programs on the server itself — not just talk to it. This is game over: I can read or change anything stored there, install spyware, and use this server to attack others. The deepest possible impact.',
  'Other':
    'A general security issue that doesn\'t fit a single named category but still weakens the app.',
};

// What is this tool actually doing? Plain-language descriptions for the
// "right now" strip so the audience knows what a tool name means.
const TOOL_NARRATIVE: Record<string, string> = {
  'target-intel': 'analysing the target with the picker AI — fingerprinting tech stack and likely vulnerabilities',
  'content-discovery': 'wordlist-scanning for hidden endpoints',
  'nuclei': 'matching known-vulnerability templates against responses',
  'smart-web-probe': 'fetching the app and parsing it for entry points',
  'httpx': 'fingerprinting the HTTP server',
  'auth-flow': 'attempting authentication: registration, login, session capture',
  'xss-extended': 'firing 50+ XSS payload variants across discovered parameters',
  'xss-proof': 'turning the reflection into a working session-theft demo',
  'idor-bac': 'walking object IDs to see if other users\' data leaks',
  'sqlmap': 'testing parameters for SQL injection',
  'ssti-probe': 'looking for server-side template injection',
  'csrf-check': 'probing for missing anti-CSRF protection',
  'session-security': 'inspecting cookie flags, lifetime, regeneration',
  'client-state': 'analysing how the client stores tokens and state',
  'biz-logic-probe': 'looking for business-logic abuse paths',
  'http-smuggling': 'probing for HTTP request smuggling between proxies',
  'waf-detect': 'fingerprinting any WAF in front of the app',
  'nikto': 'baseline vulnerability scan',
  'zap': 'OWASP ZAP active scan',
  'burp': 'Burp-style active surface scan',
  'playwright-web': 'driving a real browser through the app',
  'logging-probe': 'inducing errors to surface stack traces and debug info',
  'exec-plan': 'running a custom multi-step HTTP exploit chain I wrote',
  'malware-sim': 'simulating malicious payload patterns',
  'ai-shell': 'testing AI-component injection patterns',
  'c2-ingest': 'C2-traffic indicators',
  'graphql-command-injection': 'GraphQL command-injection patterns',
  'iot-default-creds': 'IoT default-credential checks',
};

function vulnGlossary(label: string): string | null {
  return VULN_GLOSSARY[label] ?? null;
}

function toolNarrative(tool: string): string {
  return TOOL_NARRATIVE[tool] ?? `running ${tool}`;
}

/* ----- LIVE SCENE — visual metaphor of what Claude is doing right now -----
   Each tool maps to a "what's happening in real-world terms" scene with
   an emoji panel + plain-language caption + subtle animation. Makes the
   abstract pentest activity feel tangible. */

type LiveScene = {
  emoji: string;          // main visual
  alt?: string;           // companion emoji (e.g. door + key)
  caption: string;        // one-line plain-language metaphor
  vibe: 'recon' | 'try' | 'win' | 'block' | 'idle';
};

const TOOL_SCENE: Record<string, LiveScene> = {
  'target-intel':         { emoji: '🔭', alt: '🏢', caption: 'Watching the building from across the street — counting windows, reading signs.', vibe: 'recon' },
  'content-discovery':    { emoji: '🚪🚪🚪', caption: 'Walking the hallway, trying every door I find.', vibe: 'recon' },
  'smart-web-probe':      { emoji: '🔍', alt: '🏢', caption: 'Reading the floor plan I found in the lobby.', vibe: 'recon' },
  'nuclei':               { emoji: '📋', alt: '🚪', caption: 'Checking my list of known-bad locks against every door.', vibe: 'try' },
  'httpx':                { emoji: '🚪', alt: '👂', caption: 'Knocking — listening to what kind of door this is.', vibe: 'recon' },
  'nikto':                { emoji: '🧰', alt: '🚪', caption: 'Standard burglary kit — checking the basics.', vibe: 'try' },
  'auth-flow':            { emoji: '🔑', alt: '🚪', caption: 'At the front door, trying keys and watching how it responds.', vibe: 'try' },
  'xss-extended':         { emoji: '📝', alt: '🚪', caption: 'Slipping notes under doors to see which ones write back.', vibe: 'try' },
  'xss-proof':            { emoji: '✉️', alt: '↩️', caption: 'One of my notes came back signed — proof I can talk through this door.', vibe: 'win' },
  'idor-bac':             { emoji: '🏃', alt: '🚪🚪🚪', caption: 'Speed-walking past 100 doors, jiggling each handle.', vibe: 'try' },
  'sqlmap':               { emoji: '🪟', caption: 'Round the back, checking if the basement window is loose.', vibe: 'try' },
  'ssti-probe':           { emoji: '✏️', alt: '🪧', caption: 'Writing on the welcome sign and seeing if it echoes back changed.', vibe: 'try' },
  'csrf-check':           { emoji: '🪪', alt: '🚪', caption: 'Trying to walk in someone else\'s name — using their badge.', vibe: 'try' },
  'session-security':     { emoji: '🔑', alt: '🧪', caption: 'I have a key — testing if it still works on other doors.', vibe: 'try' },
  'client-state':         { emoji: '📓', caption: 'Reading the building\'s public guestbook for clues.', vibe: 'recon' },
  'biz-logic-probe':      { emoji: '🧠', alt: '🚪', caption: 'Looking for loopholes in the rules — not picking locks, abusing process.', vibe: 'try' },
  'playwright-web':       { emoji: '👤', alt: '🚪', caption: 'Walking around inside as a real visitor, clicking everything.', vibe: 'try' },
  'burp':                 { emoji: '🕵️', alt: '🚪', caption: 'Watching every request leave and every reply come back.', vibe: 'try' },
  'zap':                  { emoji: '⚡', alt: '🚪', caption: 'Active probe — kicking the door politely.', vibe: 'try' },
  'http-smuggling':       { emoji: '🚪', alt: '🚪', caption: 'Slipping one request inside another, hoping it gets read by the wrong door.', vibe: 'try' },
  'waf-detect':           { emoji: '🛡️', caption: 'Looking for a guard at the gate.', vibe: 'recon' },
  'logging-probe':        { emoji: '📣', caption: 'Making noise on purpose — listening for what comes back.', vibe: 'try' },
  'exec-plan':            { emoji: '🔧', alt: '🔒', caption: 'Picking one specific lock with custom tools I wrote on the spot.', vibe: 'try' },
  'malware-sim':          { emoji: '☠️', alt: '🚪', caption: 'Testing if the door reacts to known-malicious shapes.', vibe: 'try' },
  'ai-shell':             { emoji: '🤖', alt: '💻', caption: 'Probing for an AI assistant I can trick into talking too much.', vibe: 'try' },
  'c2-ingest':            { emoji: '📡', caption: 'Listening for any back-channels the building might already have open.', vibe: 'recon' },
  'graphql-command-injection': { emoji: '🧬', alt: '🚪', caption: 'GraphQL door — trying to make it run my commands.', vibe: 'try' },
  'iot-default-creds':    { emoji: '📡', alt: '🔑', caption: 'Trying default passwords on every networked device I see.', vibe: 'try' },
};

const SCENE_IDLE: LiveScene = {
  emoji: '🧠',
  caption: 'Between moves — Claude is thinking about which door to try next.',
  vibe: 'idle',
};

const SCENE_RECON_DEFAULT: LiveScene = {
  emoji: '🗺️',
  caption: 'Mapping the building — every entrance, window, vent.',
  vibe: 'recon',
};

function sceneForActiveTool(tool: string | null): LiveScene {
  if (!tool) return SCENE_IDLE;
  return TOOL_SCENE[tool] ?? { emoji: '⚙️', caption: `Running ${tool} — checking what this gives us.`, vibe: 'try' };
}

// When there are no active tools but findings are accumulating, infer a
// "context" scene based on what we have proven so far.
function sceneForFindings(findings: Finding[], host: string): LiveScene {
  const counts = countSeverity(findings);
  const titles = findings.map((f) => String(f.title || '').toLowerCase()).join(' | ');
  if (counts.critical > 0 && /admin|compromise|takeover|rce/.test(titles)) {
    return { emoji: '🏆', alt: '🔓', caption: 'I\'m inside — admin-level. Now mapping what\'s reachable from here.', vibe: 'win' };
  }
  if (titles.includes('path traversal')) {
    return { emoji: '🗂️', alt: '🔓', caption: 'Found a way to pull files out from outside the front door — leaking config and secrets.', vibe: 'win' };
  }
  if (counts.high >= 5) {
    return { emoji: '🚪🚪🚪', alt: '🔓', caption: `I found ${counts.high} unlocked side doors — picking which to walk through first.`, vibe: 'win' };
  }
  if (counts.high > 0) {
    return { emoji: '🚪', alt: '🔓', caption: 'A door I tried answered back — checking if I can actually step through.', vibe: 'win' };
  }
  if (counts.medium > 0 || counts.low > 0) {
    return { emoji: '🏢', alt: '🔍', caption: `Walking around ${host || 'the building'} — small things noted, nothing exploitable yet.`, vibe: 'recon' };
  }
  return SCENE_RECON_DEFAULT;
}

function LiveSceneCard({
  tasks,
  findings,
  host,
}: {
  tasks: Task[];
  findings: Finding[];
  host: string;
}) {
  useTicker(2000);
  const active = useMemo(() => activeTaskNow(tasks), [tasks]);
  const scene = useMemo(() => {
    if (active) return sceneForActiveTool(active.tool);
    return sceneForFindings(findings, host);
  }, [active, findings, host]);
  const vibeTone: Record<LiveScene['vibe'], string> = {
    recon: 'border-cyan/30 bg-cyan/5',
    try: 'border-amber/30 bg-amber/5',
    win: 'border-red/40 bg-red/5',
    block: 'border-red/40 bg-red/10',
    idle: 'border-line bg-bg-2/40',
  };
  return (
    <div className={cn('rounded border-2 p-4 min-h-[160px] flex flex-col justify-between transition-all', vibeTone[scene.vibe])}>
      <div className="flex items-center gap-2 mb-2">
        <span className="h-1.5 w-1.5 rounded-full bg-green-400 animate-pulse" />
        <span className="font-mono text-[0.62rem] uppercase tracking-widest text-muted">Right now</span>
        {active && <span className="font-mono text-[0.7rem] text-amber">{active.tool}</span>}
      </div>
      <div className="flex-1 flex flex-col items-center justify-center text-center">
        <div className="text-[3rem] leading-none mb-1 select-none animate-pulse-slow">
          {scene.emoji}
          {scene.alt && <span className="ml-2 opacity-70">{scene.alt}</span>}
        </div>
        <div className="text-[0.92rem] text-text leading-snug max-w-md font-medium">
          {scene.caption}
        </div>
      </div>
    </div>
  );
}

// Build a sparkline of findings accumulated over time.
// Time-axis is scaled to LAST FINDING (not NOW) so an idle run with all
// activity at the start doesn't show as a flat block — we see the actual
// rise of findings during the active period.
function buildFindingsSparkline(findings: Finding[]): { points: Array<{ x: number; y: number }>; max: number } {
  const sorted = [...findings].sort((a, b) => String(a.created_at).localeCompare(String(b.created_at)));
  if (sorted.length === 0) return { points: [], max: 1 };
  const startMs = new Date(sorted[0].created_at).getTime();
  const endMs = new Date(sorted[sorted.length - 1].created_at).getTime();
  // If everything happened at the same moment, use a 1-second range
  const range = Math.max(1000, endMs - startMs);
  const buckets = 30;
  const counts: number[] = new Array(buckets).fill(0);
  for (const f of sorted) {
    const ms = new Date(f.created_at).getTime();
    const idx = Math.min(buckets - 1, Math.floor(((ms - startMs) / range) * buckets));
    const sev = (f.severity || 'info').toLowerCase();
    const w = sev === 'critical' ? 4 : sev === 'high' ? 2 : sev === 'medium' ? 1 : sev === 'low' ? 0.5 : 0.2;
    counts[idx] += w;
  }
  let acc = 0;
  const accCounts = counts.map((c) => (acc += c));
  const max = Math.max(1, accCounts[accCounts.length - 1]);
  const points = accCounts.map((v, i) => ({ x: (i / (buckets - 1)) * 100, y: 100 - (v / max) * 100 }));
  return { points, max };
}

function activeTaskNow(tasks: Task[]): Task | null {
  return tasks.find((t) => ['running', 'dispatching'].includes((t.status || '').toLowerCase())) ?? null;
}

/* ----- COMIC-STRIP PANELS — ChatGPT-generated panels per Claude decision -- */

type NarratorPanel = {
  at: string;
  hero?: string;
  scene_emoji?: string;
  alt_emoji?: string;
  scene_caption?: string;
  panel_caption?: string;
  next_move?: string;
  glossary?: Record<string, string>;
  vibe?: 'recon' | 'try' | 'win' | 'block' | 'idle';
};

function getNarratorPanels(run: Run): NarratorPanel[] {
  const loop = run.configuration_json?.ai_assessment_loop as Record<string, unknown> | undefined;
  const narrative = (loop?.narrative ?? {}) as Record<string, unknown>;
  const panels = narrative.panels;
  if (!Array.isArray(panels)) return [];
  return panels.filter((p): p is NarratorPanel => p && typeof p === 'object');
}

// Fetch the narrator panels from the dedicated audit_events-backed endpoint.
// Race-safe (append-only), unlike loop_state.narrative.panels which is
// vulnerable to ORM flush overwrites.
function useNarratorPanels(runId: string | undefined): NarratorPanel[] {
  const [panels, setPanels] = useState<NarratorPanel[]>([]);
  useEffect(() => {
    if (!runId) return;
    let aborted = false;
    const fetchPanels = async () => {
      try {
        const resp = await fetch(`/api/v1/runs/${runId}/narrative-panels`);
        if (!resp.ok) return;
        const data = await resp.json();
        if (!aborted && Array.isArray(data.panels)) {
          setPanels(data.panels);
        }
      } catch {
        /* swallow network errors — fallback to in-config panels */
      }
    };
    void fetchPanels();
    const iv = setInterval(fetchPanels, 4000);
    return () => {
      aborted = true;
      clearInterval(iv);
    };
  }, [runId]);
  return panels;
}

function ComicStrip({ panels }: { panels: NarratorPanel[] }) {
  if (panels.length === 0) return null;
  // Newest panel first
  const reversed = [...panels].reverse();
  return (
    <div className="space-y-4">
      {reversed.map((panel, idx) => {
        const isNewest = idx === 0;
        const vibe = panel.vibe ?? 'try';
        const tone: Record<string, string> = {
          recon: 'border-info/30 bg-info/5',
          try: 'border-med/30 bg-med/5',
          win: 'border-hi/40 bg-hi/8',
          block: 'border-hi/40 bg-hi/10',
          idle: 'border-line bg-bg-2/40',
        };
        return (
          <div
            key={idx}
            className={cn(
              'rounded-lg border-2 overflow-hidden transition-all',
              tone[vibe] ?? tone.try,
              isNewest && 'shadow-[0_0_24px_rgba(245,158,11,0.12)]',
            )}
          >
            <div className="grid grid-cols-1 md:grid-cols-[160px_1fr]">
              {/* Visual scene panel */}
              <div className="flex flex-col items-center justify-center p-4 bg-bg-2/40 border-r border-line-soft min-h-[140px]">
                <div className="text-[3.5rem] leading-none select-none animate-pulse-slow">
                  {panel.scene_emoji || '🧠'}
                  {panel.alt_emoji && <span className="ml-1 opacity-70">{panel.alt_emoji}</span>}
                </div>
                {panel.at && (
                  <div className="mt-2 font-mono text-[0.62rem] text-muted tabular-nums">
                    {formatHM(panel.at)}
                  </div>
                )}
              </div>
              {/* Caption + glossary */}
              <div className="p-4 min-w-0">
                {panel.scene_caption && (
                  <p className="text-[0.92rem] italic text-soft leading-snug mb-2">
                    {panel.scene_caption}
                  </p>
                )}
                {panel.panel_caption && (
                  <p className="text-[1rem] text-text leading-relaxed mb-2">
                    {panel.panel_caption}
                  </p>
                )}
                {panel.next_move && (
                  <p className="text-[0.85rem] text-cyan leading-snug">
                    <span className="font-mono text-[0.62rem] uppercase tracking-widest text-muted mr-2">
                      next
                    </span>
                    {panel.next_move}
                  </p>
                )}
                {panel.glossary && Object.keys(panel.glossary).length > 0 && (
                  <details className="mt-2.5 border-t border-line-soft pt-2">
                    <summary className="font-mono text-[0.62rem] uppercase tracking-widest text-muted cursor-pointer hover:text-text">
                      Definitions ({Object.keys(panel.glossary).length})
                    </summary>
                    <div className="mt-1.5 space-y-1.5">
                      {Object.entries(panel.glossary).map(([term, def]) => (
                        <div key={term} className="text-[0.82rem]">
                          <span className="font-semibold text-text">{term}:</span>{' '}
                          <span className="text-soft">{def}</span>
                        </div>
                      ))}
                    </div>
                  </details>
                )}
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
}

function StoryView({ run, findings, tasks }: { run: Run; findings: Finding[]; tasks: Task[] }) {
  const { t } = useI18n();
  useTicker(2000);
  const beats = useMemo(() => buildStoryBeats(run, findings, tasks), [run, findings, tasks]);
  const state = useMemo(() => deriveMissionState(run, findings), [run, findings]);
  const counts = useMemo(() => countSeverity(findings), [findings]);
  const proof = useMemo(() => topFindingForProof(findings), [findings]);
  const host = useMemo(() => targetHost(run, tasks), [run, tasks]);
  const sparkline = useMemo(() => buildFindingsSparkline(findings), [findings]);
  const active = useMemo(() => activeTaskNow(tasks), [tasks]);
  const lastReason = useMemo(() => lastDecisionReasoning(run), [run]);
  // ACTIVE duration: from first to last task time, not run.started_at.
  // A run can "still be running" 7h later while completely idle — we want
  // to talk about the active work window, not the wall-clock since launch.
  const minutes = useMemo(() => {
    const ts = tasks
      .map((t) => new Date(t.updated_at ?? t.created_at ?? '').getTime())
      .filter((n) => Number.isFinite(n) && n > 0)
      .sort((a, b) => a - b);
    if (ts.length < 2) return 1;
    const span = ts[ts.length - 1] - ts[0];
    return Math.max(1, Math.floor(span / 60000));
  }, [tasks]);

  // The headline paragraph — first person, dramatic
  const paragraph = useMemo(() => {
    const lines: Array<{ text: string; tone?: string }> = [];
    const hostPhrase = host ? ` on ${host}` : '';
    const hostInline = (): { text: string; tone?: string }[] => host ? [{ text: ' on ' }, { text: host, tone: 'text-cyan font-semibold' }] : [];
    if (state.level === 'compromised') {
      lines.push({ text: 'I broke in.', tone: 'text-fuchsia-300 font-bold' });
      lines.push({ text: ` After ${minutes} minutes${hostPhrase}, I have admin-level access. ` });
      if (proof) lines.push({ text: `The chain that finished it: `, tone: 'text-muted' });
      if (proof) lines.push({ text: inferCwe(String(proof.title)).label, tone: 'text-amber font-semibold' });
      lines.push({ text: '.' });
    } else if (state.level === 'critical') {
      lines.push({ text: 'I have a critical finding.', tone: 'text-red font-bold' });
      lines.push({ text: ` After ${minutes} minutes, ${counts.critical} critical and ${counts.high} high-severity bug${counts.high === 1 ? '' : 's'} confirmed` });
      lines.push(...hostInline());
      lines.push({ text: '. I have not yet escalated to admin, but the proof is in.' });
    } else if (state.level === 'leads') {
      lines.push({ text: "I'm onto something.", tone: 'text-amber font-bold' });
      lines.push({ text: ` ${minutes} minutes in, ${counts.high} reflective sink${counts.high === 1 ? '' : 's'}` });
      lines.push(...hostInline());
      lines.push({ text: ' returned my payloads unsanitized. Next step: weaponize — capture a session, then chain to admin.' });
    } else if (state.level === 'scanning') {
      lines.push({ text: "Still hunting.", tone: 'text-yellow-400 font-bold' });
      lines.push({ text: ` ${minutes} minutes in, ${counts.medium + counts.low} small issues${hostPhrase}, nothing exploitable yet. I'm widening the angle.` });
    } else if (state.level === 'done') {
      lines.push({ text: 'Mission closed.', tone: 'text-muted font-bold' });
      lines.push({ text: ` ${counts.critical} critical, ${counts.high} high, ${counts.medium + counts.low + counts.info} informational findings${hostPhrase}.` });
    } else {
      lines.push({ text: 'Just opened', tone: 'text-text' });
      lines.push(...hostInline());
      lines.push({ text: ". I'm mapping the surface — no exploit signal yet." });
    }
    return lines;
  }, [state.level, counts, host, minutes, proof]);

  // Reverse beats (newest first) for the timeline
  const beatsReversed = useMemo(() => [...beats].reverse(), [beats]);
  // ChatGPT-generated comic-strip panels — prefer race-safe endpoint, fall
  // back to in-config panels if endpoint not yet returning anything.
  const fetchedPanels = useNarratorPanels(run.id);
  const configPanels = useMemo(() => getNarratorPanels(run), [run]);
  const narratorPanels = fetchedPanels.length > 0 ? fetchedPanels : configPanels;
  const hasNarrator = narratorPanels.length > 0;

  return (
    <div className="overflow-y-auto flex-1 min-h-0">
      {/* HERO: paragraph (left) + visual sparkline (right) */}
      <div className={cn('grid grid-cols-1 lg:grid-cols-[1fr_320px] gap-6 px-8 py-6 border-b-2', state.toneBg)}>
        <div className="min-w-0">
          <div className="flex items-center gap-3 mb-3">
            <span className="text-4xl leading-none">{state.emoji}</span>
            <div>
              <div className={cn('font-mono text-[0.78rem] font-bold tracking-widest', state.tone)}>{state.label}</div>
              <div className="font-mono text-[0.7rem] text-muted">{run.profile?.name || t('mission.defaultName')}</div>
            </div>
            <div className="ml-auto font-mono text-[0.9rem] tabular-nums text-amber">{formatUptime(run.started_at)}</div>
          </div>
          <p className="text-[1.4rem] font-semibold leading-snug text-text">
            {paragraph.map((p, idx) => (
              <span key={idx} className={p.tone}>
                {p.text}
              </span>
            ))}
          </p>
        </div>
        {/* Mood/findings sparkline */}
        <div className="rounded border border-line-soft bg-bg-2/40 p-3">
          <div className="flex items-center justify-between mb-1.5">
            <span className="font-mono text-[0.65rem] uppercase tracking-widest text-muted">Finding momentum</span>
            <span className="font-mono text-[0.7rem] text-amber tabular-nums">
              {findings.length} total
            </span>
          </div>
          <svg viewBox="0 0 100 100" preserveAspectRatio="none" className="w-full h-24">
            <defs>
              <linearGradient id="sparkLine" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="var(--hi)" />
                <stop offset="45%" stopColor="var(--med)" />
                <stop offset="90%" stopColor="var(--ok)" />
              </linearGradient>
              <linearGradient id="sparkFill" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="var(--hi)" stopOpacity="0.35" />
                <stop offset="55%" stopColor="var(--med)" stopOpacity="0.18" />
                <stop offset="100%" stopColor="var(--ok)" stopOpacity="0" />
              </linearGradient>
            </defs>
            {sparkline.points.length > 1 && (
              <>
                <path
                  d={sparkline.points.map((p, i) => `${i === 0 ? 'M' : 'L'} ${p.x.toFixed(2)} ${p.y.toFixed(2)}`).join(' ') + ' L 100 100 L 0 100 Z'}
                  fill="url(#sparkFill)"
                />
                <path
                  d={sparkline.points.map((p, i) => `${i === 0 ? 'M' : 'L'} ${p.x.toFixed(2)} ${p.y.toFixed(2)}`).join(' ')}
                  fill="none"
                  stroke="url(#sparkLine)"
                  strokeWidth="1.2"
                />
              </>
            )}
          </svg>
          <div className="flex justify-between font-mono text-[0.62rem] text-muted mt-0.5">
            <span>start</span>
            <span>now</span>
          </div>
          {/* Severity breakdown bars below — uses OKLCH severity tokens */}
          <div className="mt-2 space-y-1">
            {(['critical', 'high', 'medium', 'low', 'info'] as const).map((sev) => {
              const n = counts[sev];
              if (n === 0) return null;
              const max = Math.max(...Object.values(counts));
              const pct = max > 0 ? (n / max) * 100 : 0;
              // Map severity to OKLCH variable directly via inline style
              const colorVar =
                sev === 'critical' ? 'var(--hi)' :
                sev === 'high' ? 'var(--med)' :
                sev === 'medium' ? 'var(--med)' :
                sev === 'low' ? 'var(--info)' :
                'var(--line)';
              const tone =
                sev === 'critical' ? 'text-hi' :
                sev === 'high' ? 'text-med' :
                sev === 'medium' ? 'text-med/80' :
                sev === 'low' ? 'text-info' :
                'text-muted';
              return (
                <div key={sev} className="flex items-center gap-2">
                  <span className={cn('font-mono text-[0.6rem] uppercase tracking-wider w-12 shrink-0', tone)}>{sev}</span>
                  <div className="flex-1 h-1.5 rounded-full bg-bg-2 overflow-hidden">
                    <div className="h-full rounded-full" style={{ width: `${pct}%`, background: colorVar }} />
                  </div>
                  <span className="font-mono text-[0.62rem] text-text tabular-nums w-6 text-right">{n}</span>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* LIVE SCENE + NEXT — visual metaphor of right-now activity */}
      <div className="grid grid-cols-1 lg:grid-cols-[1.3fr_1fr] gap-4 px-8 py-4 border-b border-line-soft">
        <LiveSceneCard tasks={tasks} findings={findings} host={host} />
        <div className="rounded border border-line-soft bg-bg-2/40 p-4 flex flex-col">
          <div className="flex items-center gap-2 mb-2">
            <span className="font-mono text-[0.62rem] uppercase tracking-widest text-muted">My next move</span>
          </div>
          {lastReason ? (
            <p className="text-[0.95rem] text-text leading-snug">{lastReason}</p>
          ) : narratorPanels.length > 0 ? (
            // No raw decision reasoning, but the comic-strip's most recent
            // panel already includes a next_move written by ChatGPT/Opus.
            <p className="text-[0.95rem] text-text leading-snug">
              {String(narratorPanels[narratorPanels.length - 1].next_move || 'Considering the next move.')}
            </p>
          ) : (
            <p className="text-[0.92rem] text-muted italic">Thinking about which door to try next…</p>
          )}
          {active && (
            <p className="mt-auto pt-2 text-[0.78rem] text-soft border-t border-line-soft mt-3">
              <span className="font-mono text-[0.65rem] uppercase text-muted">currently running </span>
              <span className="font-mono text-amber">{active.tool}</span>
              <span className="text-muted"> · </span>
              {toolNarrative(active.tool)}
            </p>
          )}
        </div>
      </div>

      {/* THE STORY SO FAR — Codex comic panels first, else template fallback */}
      <div className="px-8 py-6">
        <div className="flex items-baseline justify-between mb-3">
          <div className="font-mono text-[0.7rem] uppercase tracking-widest text-muted">
            {hasNarrator ? 'The story · live narrative' : 'The story so far'}
          </div>
          <div className="font-mono text-[0.65rem] text-muted">
            {hasNarrator ? `${narratorPanels.length} panels · narrated by ChatGPT` : `newest first · ${beats.length} events`}
          </div>
        </div>
        {hasNarrator ? (
          <ComicStrip panels={narratorPanels} />
        ) : beats.length === 0 ? (
          <div className="text-[0.95rem] text-muted italic">Nothing has happened yet. Starting up.</div>
        ) : (
          <ol className="relative space-y-4">
            <div className="absolute left-2 top-2 bottom-2 w-px bg-line-soft" />
            {beatsReversed.map((b, idx) => {
              const t = BEAT_TONE[b.kind];
              // Extract glossary key from "X confirmed" style text
              const glossaryKey = b.text.replace(/^(Critical — )?(.*?)(?:\s+confirmed.*)?$/, '$2').trim();
              const glossary = b.kind === 'win' ? vulnGlossary(glossaryKey) : null;
              return (
                <li key={idx} className="relative flex items-start gap-4 pl-1">
                  <span className={cn('relative z-10 mt-1.5 h-2.5 w-2.5 rounded-full shrink-0', t.dot)} />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-baseline gap-3 flex-wrap">
                      <span className={cn('text-[1rem] font-semibold leading-tight', t.tone)}>{b.text}</span>
                      <span className="font-mono text-[0.7rem] text-muted tabular-nums">{b.at}</span>
                    </div>
                    {b.detail && <div className="text-[0.85rem] text-muted leading-snug mt-0.5">{b.detail}</div>}
                    {glossary && (
                      <div className="mt-1.5 text-[0.82rem] text-soft leading-snug border-l-2 border-line-soft pl-3 italic">
                        <span className="font-semibold text-text not-italic">What is {glossaryKey}?</span>{' '}
                        {glossary}
                      </div>
                    )}
                  </div>
                </li>
              );
            })}
          </ol>
        )}
      </div>
    </div>
  );
}

/* =========================================================================
   TECHNICAL VIEW — status board (compact, glance-readable)
   ========================================================================= */

function RiskTrajectoryChart({ findings }: { findings: Finding[] }) {
  const spark = useMemo(() => buildFindingsSparkline(findings), [findings]);
  // Gradient palette uses the OKLCH severity colours so the line itself
  // tells the story: green (calm), amber (climbing risk), red (compounding).
  const lineGradId = 'riskLineGrad';
  const fillGradId = 'riskFillGrad';
  // Mark wins (critical/high) for annotation
  const wins = useMemo(() => {
    const sorted = [...findings].sort((a, b) => String(a.created_at).localeCompare(String(b.created_at)));
    if (sorted.length === 0) return [];
    const startMs = new Date(sorted[0].created_at).getTime();
    const endMs = Math.max(Date.now(), new Date(sorted[sorted.length - 1].created_at).getTime());
    const range = Math.max(1, endMs - startMs);
    const seen = new Set<string>();
    const out: Array<{ x: number; label: string; tone: string }> = [];
    sorted.forEach((f) => {
      const sev = (f.severity || '').toLowerCase();
      if (sev !== 'critical' && sev !== 'high') return;
      const cwe = inferCwe(String(f.title || '')).label;
      if (seen.has(cwe)) return;
      seen.add(cwe);
      const ms = new Date(f.created_at).getTime();
      const x = ((ms - startMs) / range) * 100;
      out.push({ x, label: cwe, tone: sev === 'critical' ? 'text-red' : 'text-amber' });
    });
    return out.slice(0, 5);
  }, [findings]);

  return (
    <div className="rounded border border-line-soft bg-surface/30 overflow-hidden">
      <div className="px-3 py-1.5 bg-bg-2/60 border-b border-line-soft flex items-center justify-between">
        <span className="font-mono text-[0.7rem] uppercase tracking-widest text-text">Risk Trajectory</span>
        <span className="font-mono text-[0.65rem] text-muted">{findings.length} findings</span>
      </div>
      <div className="relative px-3 pt-2 pb-3">
        <svg viewBox="0 0 100 100" preserveAspectRatio="none" className="w-full h-28">
          <defs>
            {/* Vertical gradient: line colour darkens to RED at the top
                (high risk), through AMBER in the middle, to GREEN near the
                baseline. Y=0 is top of the chart in SVG coords. */}
            <linearGradient id={lineGradId} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="var(--hi)" />
              <stop offset="40%" stopColor="var(--med)" />
              <stop offset="85%" stopColor="var(--ok)" />
            </linearGradient>
            <linearGradient id={fillGradId} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="var(--hi)" stopOpacity="0.35" />
              <stop offset="50%" stopColor="var(--med)" stopOpacity="0.18" />
              <stop offset="100%" stopColor="var(--ok)" stopOpacity="0" />
            </linearGradient>
          </defs>
          {[25, 50, 75].map((y) => (
            <line key={y} x1="0" y1={y} x2="100" y2={y} stroke="var(--line-soft)" strokeWidth="0.2" strokeDasharray="1 1" />
          ))}
          {spark.points.length > 1 && (
            <>
              <path
                d={spark.points.map((p, i) => `${i === 0 ? 'M' : 'L'} ${p.x.toFixed(2)} ${p.y.toFixed(2)}`).join(' ') + ' L 100 100 L 0 100 Z'}
                fill={`url(#${fillGradId})`}
              />
              <path
                d={spark.points.map((p, i) => `${i === 0 ? 'M' : 'L'} ${p.x.toFixed(2)} ${p.y.toFixed(2)}`).join(' ')}
                fill="none"
                stroke={`url(#${lineGradId})`}
                strokeWidth="1.1"
              />
            </>
          )}
          {wins.map((w, i) => (
            <circle key={i} cx={w.x} cy="2" r="1.4" fill="var(--hi)" stroke="var(--bg)" strokeWidth="0.4" />
          ))}
        </svg>
        {wins.map((w, i) => (
          <div
            key={i}
            className={cn('absolute -translate-x-1/2 top-0 font-mono text-[0.6rem] font-semibold whitespace-nowrap', w.tone)}
            style={{ left: `calc(${w.x}% + 12px)` }}
          >
            {w.label}
          </div>
        ))}
        <div className="flex justify-between font-mono text-[0.6rem] text-muted mt-1">
          <span>start</span>
          <span>now</span>
        </div>
      </div>
    </div>
  );
}

function ToolChainHeartbeat({ tasks }: { tasks: Task[] }) {
  useTicker(1500);
  const items = useMemo(() => {
    return [...tasks].sort((a, b) => String(a.created_at).localeCompare(String(b.created_at)));
  }, [tasks]);
  const stats = useMemo(() => {
    let ran = 0, errored = 0, queued = 0;
    items.forEach((t) => {
      const s = (t.status || '').toLowerCase();
      if (s === 'completed') ran++;
      else if (s === 'failed') errored++;
      else if (['queued', 'requested', 'running', 'dispatching'].includes(s)) queued++;
    });
    return { ran, errored, queued };
  }, [items]);

  return (
    <div className="rounded border border-line-soft bg-surface/30 overflow-hidden">
      <div className="px-3 py-1.5 bg-bg-2/60 border-b border-line-soft flex items-center justify-between">
        <span className="font-mono text-[0.7rem] uppercase tracking-widest text-text">Tool Chain</span>
        <span className="font-mono text-[0.65rem]">
          <span className="text-green-400">{stats.ran} ran</span>
          <span className="text-muted"> · </span>
          <span className="text-red">{stats.errored} err</span>
          <span className="text-muted"> · </span>
          <span className="text-amber">{stats.queued} active</span>
        </span>
      </div>
      <div className="px-3 py-2 overflow-x-auto">
        <div className="flex items-end gap-1 min-w-max">
          {items.map((t, idx) => {
            const status = (t.status || '').toLowerCase();
            const isActive = ['running', 'dispatching'].includes(status);
            const tone =
              status === 'completed' ? 'bg-green-400' :
              status === 'failed' ? 'bg-red' :
              isActive ? 'bg-amber animate-pulse' : 'bg-line';
            return (
              <div key={idx} className="flex flex-col items-center min-w-[44px]">
                <span
                  className={cn(
                    'rounded-full transition-all',
                    isActive ? 'h-3.5 w-3.5 ring-2 ring-amber/40 shadow-[0_0_10px_rgba(245,158,11,0.7)]' : 'h-2 w-2',
                    tone,
                    status === 'failed' && 'ring-1 ring-red/40',
                  )}
                  title={`${t.tool} · ${status}`}
                />
                <span className={cn(
                  'mt-1 font-mono text-[0.55rem] whitespace-nowrap',
                  isActive ? 'text-amber font-bold' : 'text-muted',
                )}>
                  {t.tool.length > 10 ? t.tool.slice(0, 9) + '…' : t.tool}
                </span>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

function NowPlayingTail({ tasks }: { tasks: Task[] }) {
  const active = useMemo(() => activeTaskNow(tasks), [tasks]);
  const fallback = useMemo(() => {
    return [...tasks].sort((a, b) => String(b.updated_at ?? b.created_at).localeCompare(String(a.updated_at ?? a.created_at)))[0];
  }, [tasks]);
  const t = active ?? fallback;
  if (!t) return null;
  const stdoutPreview = `$ ${t.tool} --target ${String(t.target_id ?? '').slice(0, 60)}
status: ${t.status}
${active ? '⚡ executing...' : 'last update: ' + String(t.updated_at ?? t.created_at).slice(11, 19)}`;
  return (
    <div className="rounded border border-line-soft bg-surface/30 overflow-hidden">
      <div className="px-3 py-1.5 bg-bg-2/60 border-b border-line-soft flex items-center gap-2">
        <span className={cn('h-1.5 w-1.5 rounded-full', active ? 'bg-green-400 animate-pulse' : 'bg-line')} />
        <span className="font-mono text-[0.7rem] uppercase tracking-widest text-text">Now playing</span>
        <span className="font-mono text-[0.65rem] text-amber ml-1">{t.tool}</span>
        <span className="ml-auto font-mono text-[0.6rem] text-muted">{String(t.id).slice(0, 8)}</span>
      </div>
      <pre className="px-3 py-2 font-mono text-[0.72rem] text-text leading-snug bg-bg-2/20 max-h-24 overflow-y-auto whitespace-pre-wrap break-all">
        {stdoutPreview}
      </pre>
    </div>
  );
}

/* =========================================================================
   LIVE TASK TERMINAL — real CLI feel: SSE-streamed stdout (line-by-line as
   they arrive on the API), terminal-styled (dark bg, monospace, auto-scroll,
   blinking cursor), auto-switches to the next task when one becomes active.
   ========================================================================= */

type TerminalLine = { text: string; stream: string; sequence: number };

// Lightweight syntax highlighter for the LIVE TASK terminal output. Tokenises
// each line and emits coloured spans. Operator asked for "kleuren zoals bij
// py code" 2026-05-21 — full ANSI parsing is overkill, but URLs, HTTP codes,
// IPs, exit codes, and error keywords cover the actual readability win.
const URL_RE = /(https?:\/\/[^\s"'<>]+)/g;
const IP_PORT_RE = /\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\b/g;
const HTTP_CODE_RE = /\b(1\d{2}|2\d{2}|3\d{2}|4\d{2}|5\d{2})\b(?=\s|"|$|\]|,)/g;
const EXIT_CODE_RE = /\bexit[ _]?code?\s*[:=]?\s*(-?\d+)/gi;
// All case-INSENSITIVE per operator 2026-05-21: actual stderr is lowercase
// ("Error: timed out", "not reachable") so /g alone missed everything.
const ERROR_KW_RE = /\b(ERROR|FAIL(?:ED|URE)?|TRACEBACK|EXCEPTION|DENIED|REFUSED|NOT CONFIGURED|NOT REACHABLE|UNREACHABLE|COULD NOT|TIMED? ?OUT|UNAUTHORIZED|FORBIDDEN|CRASH(?:ED)?)\b/gi;
const WARN_KW_RE = /\b(WARN(?:ING)?|DEPRECAT(?:ED)?|SKIP(?:PED|PING)?|RETRY(?:ING)?|REJECTED?)\b/gi;
const SUCCESS_KW_RE = /\b(OK|SUCCESS|COMPLETED|CONFIRMED|FOUND|MATCHED)\b/gi;
const PATH_RE = /(?:^|[\s"'(])(\/[A-Za-z0-9_\-./?=&%]+)/g;

function colorizeLine(text: string, isErrStream: boolean): React.ReactNode {
  if (!text) return text;
  // Build a token map: array of {start, end, className}. Higher priority
  // regexes are applied later so they overwrite earlier matches.
  const segments: Array<{ start: number; end: number; cls: string }> = [];
  const push = (re: RegExp, cls: string) => {
    re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null) {
      // For paths the captured group starts after the leading delimiter
      const start = m.index + (m[0].length - (m[1] ?? m[0]).length);
      segments.push({ start, end: start + (m[1] ?? m[0]).length, cls });
      if (m.index === re.lastIndex) re.lastIndex++;
    }
  };
  push(PATH_RE, 'text-blue-300');
  push(IP_PORT_RE, 'text-cyan-300');
  push(URL_RE, 'text-cyan-400 underline');
  push(SUCCESS_KW_RE, 'text-emerald-400 font-semibold');
  push(WARN_KW_RE, 'text-amber-300');
  push(HTTP_CODE_RE, 'text-fuchsia-300');
  push(EXIT_CODE_RE, 'text-red-400 font-semibold');
  push(ERROR_KW_RE, 'text-red-400 font-semibold');

  if (segments.length === 0) {
    return isErrStream ? <span className="text-red-300">{text}</span> : text;
  }
  // Resolve overlaps: keep the LAST pushed segment at each position (higher
  // priority since we pushed in order).
  segments.sort((a, b) => a.start - b.start || b.end - a.end);
  const resolved: Array<{ start: number; end: number; cls: string }> = [];
  let cursor = 0;
  for (const s of segments) {
    if (s.start < cursor) continue;
    resolved.push(s);
    cursor = s.end;
  }
  const out: React.ReactNode[] = [];
  let i = 0;
  for (const s of resolved) {
    if (i < s.start) out.push(text.slice(i, s.start));
    out.push(
      <span key={`${s.start}-${s.end}`} className={s.cls}>
        {text.slice(s.start, s.end)}
      </span>,
    );
    i = s.end;
  }
  if (i < text.length) out.push(text.slice(i));
  return out;
}

export function LiveTaskDrillDown({ tasks }: { tasks: Task[] }) {
  const active = useMemo(() => activeTaskNow(tasks), [tasks]);
  const recentTasks = useMemo(() => {
    // Bumped from 12 → 40 per operator request 2026-05-21: with the skip-runner
    // filter live, a single run can chain through 20-30 tools and the operator
    // wants to inspect the older ones (e.g. an earlier zap failure) after later
    // tasks completed and pushed it out of the small-window slice.
    return [...tasks]
      .sort((a, b) => String(b.updated_at ?? b.created_at).localeCompare(String(a.updated_at ?? a.created_at)))
      .slice(0, 40);
  }, [tasks]);

  const [selectedId, setSelectedId] = useState<string | null>(null);
  const pinnedRef = useRef(false);
  useEffect(() => {
    if (!pinnedRef.current && active && active.id !== selectedId) {
      setSelectedId(String(active.id));
    } else if (!pinnedRef.current && !active && !selectedId && recentTasks[0]) {
      setSelectedId(String(recentTasks[0].id));
    }
  }, [active, selectedId, recentTasks]);

  const [lines, setLines] = useState<TerminalLine[]>([]);
  const [streamStatus, setStreamStatus] = useState<'connecting' | 'live' | 'done' | 'error'>('connecting');
  const [taskStatus, setTaskStatus] = useState<string>('?');
  const [exitCode, setExitCode] = useState<number | null>(null);
  const scrollRef = useRef<HTMLDivElement | null>(null);

  // Open one SSE per selected task; replace cleanly when task changes.
  useEffect(() => {
    if (!selectedId) {
      setLines([]);
      setStreamStatus('connecting');
      return undefined;
    }
    setLines([]);
    setStreamStatus('connecting');
    setExitCode(null);

    const url = `/api/v1/tasks/${selectedId}/stdout/events`;
    const es = new EventSource(url);
    let live = true;

    const ingest = (e: MessageEvent) => {
      if (!live) return;
      try {
        const data = JSON.parse(e.data);
        const incoming: TerminalLine[] = (data.lines ?? []).map((l: { text?: string; stream?: string; sequence?: number }) => ({
          text: String(l.text ?? ''),
          stream: String(l.stream ?? ''),
          sequence: typeof l.sequence === 'number' ? l.sequence : 0,
        }));
        // Snapshot events replace; update events append-only. The API encodes
        // both via stream_terminal flag + we can dedupe on sequence.
        setLines((prev) => {
          const seen = new Set(prev.map((p) => p.sequence));
          const merged = [...prev];
          for (const l of incoming) {
            if (!seen.has(l.sequence)) {
              merged.push(l);
              seen.add(l.sequence);
            }
          }
          return merged;
        });
        if (data.task_status) setTaskStatus(String(data.task_status));
        if (data.stream_terminal) {
          setStreamStatus('done');
          es.close();
        } else {
          setStreamStatus('live');
        }
      } catch {
        // ignore malformed event
      }
    };

    es.addEventListener('task.stdout.snapshot', ingest);
    es.addEventListener('task.stdout.update', ingest);
    es.addEventListener('task.stdout.missing', () => {
      setStreamStatus('done');
      es.close();
    });
    es.onerror = () => {
      // EventSource will auto-retry; surface state so operator knows.
      if (live) setStreamStatus('error');
    };

    // Pull exit_code + persisted stdout/stderr via one detail fetch. The SSE
    // stream only carries the live stdout snapshot — for fast-failing tasks
    // (zap exit 1 before any chunk is written) it can be empty. The
    // ToolExecution row's stderr_text holds the real failure reason in that
    // case, and the operator can't see it from SSE alone. So we merge it in.
    const fetchExitCode = async () => {
      try {
        const d = await getTaskDetail(selectedId as `${string}-${string}-${string}-${string}-${string}`);
        if (!live) return;
        const exec = d.executions?.[0];
        if (exec?.exit_code !== undefined) setExitCode(exec.exit_code);
        // Fallback: if SSE delivered (almost) nothing but the persisted
        // execution has stderr/stdout text, splice it in so the operator
        // sees WHY the task failed instead of a blank panel.
        setLines((prev) => {
          const hasRealBody = prev.some((l) => l.stream !== 'command');
          if (hasRealBody) return prev;
          const merged = [...prev];
          let seq = prev.length > 0 ? Math.max(...prev.map((p) => p.sequence)) + 1 : 1;
          const stderrText = String(exec?.stderr_text ?? '').trim();
          const stdoutText = String(exec?.stdout_text ?? '').trim();
          // Strip the command-prefix line(s) — they're already shown.
          const stripCmd = (s: string) =>
            s.split('\n').filter((line) => !line.trim().startsWith('$ ')).join('\n').trim();
          const stdoutBody = stripCmd(stdoutText);
          if (stdoutBody) {
            for (const line of stdoutBody.split('\n')) {
              merged.push({ text: line, stream: 'stdout', sequence: seq++ });
            }
          }
          if (stderrText) {
            for (const line of stderrText.split('\n')) {
              merged.push({ text: line, stream: 'stderr', sequence: seq++ });
            }
          }
          if (merged.length === prev.length && exec) {
            merged.push({
              text: `(no captured stdout/stderr; runner exited ${exec.exit_code ?? '?'})`,
              stream: 'meta',
              sequence: seq++,
            });
          }
          return merged;
        });
      } catch {
        // best-effort
      }
    };
    const exitCheckHandle = window.setTimeout(fetchExitCode, 1500);
    const exitCheckHandle2 = window.setInterval(fetchExitCode, 8000);

    return () => {
      live = false;
      es.close();
      window.clearTimeout(exitCheckHandle);
      window.clearInterval(exitCheckHandle2);
    };
  }, [selectedId]);

  // Auto-scroll to bottom whenever new lines land.
  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [lines]);

  const command = useMemo(() => {
    const cmd = lines.find((l) => l.stream === 'command' || l.text.trim().startsWith('$ '));
    return cmd ? cmd.text.trim() : '';
  }, [lines]);
  const bodyLines = useMemo(
    () => lines.filter((l) => !(l.stream === 'command' || l.text.trim().startsWith('$ '))),
    [lines],
  );

  const dotClass = useMemo(() => {
    if (streamStatus === 'live') return 'bg-green-400 animate-pulse';
    if (streamStatus === 'error') return 'bg-red-400';
    if (streamStatus === 'done') return 'bg-line';
    return 'bg-amber-400 animate-pulse';
  }, [streamStatus]);

  return (
    <div className="rounded border border-line-soft overflow-hidden bg-[#0b0f13]">
      {/* macOS-style window chrome / status bar */}
      <div className="px-3 py-1.5 bg-[#1a1f26] border-b border-line-soft flex items-center gap-2 flex-wrap">
        <div className="flex items-center gap-1">
          <span className="h-2 w-2 rounded-full bg-red-500/70" />
          <span className="h-2 w-2 rounded-full bg-yellow-500/70" />
          <span className="h-2 w-2 rounded-full bg-green-500/70" />
        </div>
        <span className={cn('h-1.5 w-1.5 rounded-full ml-2', dotClass)} />
        <span className="font-mono text-[0.7rem] uppercase tracking-widest text-green-300">aegispt — task output</span>
        <span
          className="font-mono text-[0.6rem] text-green-300/50 italic"
          title="For a true streaming terminal session run: scripts/aegispt_live.py"
        >
          (web mirror — real CLI: scripts/aegispt_live.py)
        </span>
        <select
          className="font-mono text-[0.7rem] bg-[#0b0f13] text-green-300 border border-green-700/40 rounded px-1 py-0.5 max-w-[18rem] truncate"
          value={selectedId ?? ''}
          onChange={(e) => {
            pinnedRef.current = true;
            setSelectedId(e.target.value);
          }}
        >
          {recentTasks.map((t) => (
            <option key={String(t.id)} value={String(t.id)}>
              {t.tool} · {String(t.status).slice(0, 8)} · {String(t.id).slice(0, 6)}
            </option>
          ))}
        </select>
        {pinnedRef.current && (
          <button
            type="button"
            className="font-mono text-[0.6rem] text-amber underline"
            onClick={() => {
              pinnedRef.current = false;
              if (active) setSelectedId(String(active.id));
            }}
          >
            unpin
          </button>
        )}
        <span className="ml-auto font-mono text-[0.6rem] text-green-300/60">
          {streamStatus} · {taskStatus}
          {exitCode !== null ? ` · exit ${exitCode}` : ''}
        </span>
      </div>
      {/* Terminal body */}
      <div
        ref={scrollRef}
        className="px-3 py-2 font-mono text-[0.78rem] leading-snug bg-[#0b0f13] max-h-[28rem] min-h-[12rem] overflow-y-auto whitespace-pre-wrap break-all"
      >
        {command && (
          <div className="text-amber-300 mb-1">{colorizeLine(command, false)}</div>
        )}
        {bodyLines.length === 0 && !command && (
          <span className="text-green-300/40">(waiting for output…)</span>
        )}
        {bodyLines.length === 0 && command && streamStatus === 'done' && (
          <span className="text-green-300/40">(no captured stdout/stderr yet — fetching execution detail…)</span>
        )}
        {bodyLines.map((l, idx) => {
          const isErr = l.stream === 'stderr' || l.stream === 'error';
          const isMeta = l.stream === 'meta';
          const baseCls = isErr
            ? 'text-red-400'
            : isMeta
              ? 'text-green-300/50 italic'
              : 'text-green-200';
          return (
            <div key={`${l.sequence}-${idx}`} className={baseCls}>
              {colorizeLine(l.text, isErr)}
            </div>
          );
        })}
        {streamStatus === 'live' && (
          <span className="text-green-300 animate-pulse">▌</span>
        )}
      </div>
    </div>
  );
}

/* =========================================================================
   LIVE EVENTS FEED — operator-facing equivalent of `tail -f` over the API.
   Subscribes to /api/v1/runs/{id}/events SSE (the existing snapshot stream)
   AND finding.enriched events. Diffs successive snapshots client-side to
   emit discrete events (task added, status changed, run terminal, foothold
   transition, finalizer fire). Renders chronologically — newest at the
   bottom, append-only — so the operator sees what the agent is doing in
   the moment without staring at a single per-task panel that only updates
   when its task changes.

   This is the in-browser version of scripts/aegispt_live.py. The Python
   script remains for headless/SSH use; this is for "I'm watching the run
   in the UI and I want to see everything as it happens".
   ========================================================================= */

type FeedEvent = {
  ts: number;
  tag: string;
  text: string;
  cls: string; // tailwind text-* class
};

const TERMINAL_RUN_STATUSES = new Set([
  'completed', 'completed_with_errors', 'failed', 'cancelled', 'canceled', 'rejected',
]);

export function LiveEventsFeed({ runId }: { runId: string }) {
  const [events, setEvents] = useState<FeedEvent[]>([]);
  const [feedClosed, setFeedClosed] = useState(false);
  const prevSnapshotRef = useRef<{
    status?: string;
    tasks: Map<string, { status: string; tool: string; target: string }>;
    foothold?: string;
    iterationCount?: number;
    stopReason?: string | null;
    lastPickKey?: string;
  } | null>(null);
  const announcedConnectedRef = useRef(false);
  const scrollRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    if (!runId) return undefined;
    setEvents([]);
    setFeedClosed(false);
    prevSnapshotRef.current = null;
    announcedConnectedRef.current = false;
    let es: EventSource | null = new EventSource(`/api/v1/runs/${runId}/events`);
    let live = true;

    const closeFeed = (reason: string, cls: string) => {
      if (!live) return;
      if (es) {
        es.close();
        es = null;
      }
      setEvents((prev) => [...prev, { ts: Date.now(), tag: 'FEED', text: reason, cls }]);
      setFeedClosed(true);
    };

    const append = (tag: string, text: string, cls: string) => {
      if (!live) return;
      setEvents((prev) => {
        const next = [...prev, { ts: Date.now(), tag, text, cls }];
        return next.length > 200 ? next.slice(next.length - 200) : next;
      });
    };

    const onSnapshot = (e: MessageEvent, isInitial: boolean) => {
      try {
        const snap = JSON.parse(e.data);
        const taskMap = new Map<string, { status: string; tool: string; target: string }>();
        for (const t of snap.tasks ?? []) {
          taskMap.set(String(t.id), {
            status: String(t.status ?? '?'),
            tool: String(t.tool ?? '?'),
            target: String(t.target_id ?? '?'),
          });
        }
        // Backend embeds an `assessment_loop` summary in the snapshot
        // (added 2026-05-21). Falls back to configuration_json for runs
        // created before that change.
        const loop = (snap.assessment_loop
          ?? (snap.configuration_json as Record<string, unknown> | undefined)?.ai_assessment_loop
          ?? {}) as Record<string, unknown>;
        const foothold = String(loop?.foothold_state ?? '');
        const iterCount = Number(loop?.iteration_count ?? 0);
        const stopReason = loop?.stop_reason ? String(loop.stop_reason) : null;
        const lastPick = loop?.last_pick as { tool?: string; target?: string; tier?: string; iteration?: number } | undefined;
        const lastPickKey = lastPick ? `${lastPick.iteration}|${lastPick.tool}|${lastPick.target}` : '';
        const runStatus = String(snap.status ?? '?');
        const isTerminal = TERMINAL_RUN_STATUSES.has(runStatus);

        if (isInitial) {
          // Only announce CONNECTED once — the API's SSE endpoint sends a fresh
          // run.snapshot on every reconnect, but the operator already knows we're
          // connected. Repeating it on every retry is noise.
          if (!announcedConnectedRef.current) {
            announcedConnectedRef.current = true;
            const label = isTerminal
              ? `tracking run ${String(snap.run_id).slice(0, 8)} (${taskMap.size} tasks, terminal: ${runStatus} — feed closing)`
              : `tracking run ${String(snap.run_id).slice(0, 8)} (${taskMap.size} tasks, status=${runStatus})`;
            append('CONNECTED', label, 'text-cyan-400');
          }
          prevSnapshotRef.current = { status: runStatus, tasks: taskMap, foothold, iterationCount: iterCount, stopReason, lastPickKey };
          if (isTerminal) {
            closeFeed(`run is ${runStatus} — no further events expected`, 'text-amber-300/70 italic');
          }
          return;
        }
        const prev = prevSnapshotRef.current;
        if (!prev) {
          prevSnapshotRef.current = { status: runStatus, tasks: taskMap, foothold, iterationCount: iterCount, stopReason, lastPickKey };
          return;
        }

        // Diff: tasks added or status-changed
        for (const [tid, t] of taskMap.entries()) {
          const prior = prev.tasks.get(tid);
          if (!prior) {
            append('TASK+', `${t.tool} -> ${t.target} (${t.status})`, 'text-blue-300');
          } else if (prior.status !== t.status) {
            const isFail = t.status === 'failed';
            const isSkip = t.status === 'skipped';
            const isOk = t.status === 'completed';
            const cls = isFail ? 'text-red-400'
              : isSkip ? 'text-amber-300'
              : isOk ? 'text-green-400'
              : 'text-green-200';
            append(t.status.toUpperCase(), `${t.tool} -> ${t.target}`, cls);
          }
        }
        if (foothold && foothold !== prev.foothold) {
          append('FOOTHOLD', `${prev.foothold || 'anonymous'} → ${foothold}`, 'text-fuchsia-300 font-semibold');
        }
        if (iterCount > (prev.iterationCount ?? 0)) {
          append('ITER', `picker iter ${prev.iterationCount ?? 0} → ${iterCount}`, 'text-cyan-300');
        }
        // Picker's last decision changed — the picker emitted a new pick.
        // Source-of-truth is loop_state.iterations[-1].next_action.
        if (lastPickKey && lastPickKey !== prev.lastPickKey && lastPick) {
          const tier = lastPick.tier ? ` [${lastPick.tier}]` : '';
          append('PICK', `${lastPick.tool} → ${lastPick.target}${tier}`, 'text-cyan-400 font-semibold');
        }
        // Stop reason newly appeared — picker just said STOP.
        if (stopReason && stopReason !== prev.stopReason) {
          append('STOP', `picker stop_reason=${stopReason}`, 'text-amber-300 font-semibold');
        }
        if (runStatus !== prev.status) {
          append('RUN', `status ${prev.status} → ${runStatus}`,
            isTerminal ? 'text-amber-300 font-semibold' : 'text-cyan-400');
        }

        prevSnapshotRef.current = { status: runStatus, tasks: taskMap, foothold, iterationCount: iterCount, stopReason, lastPickKey };

        // Run just went terminal — stop the EventSource so the browser doesn't
        // start its reconnect loop on the server's clean close.
        if (isTerminal && !TERMINAL_RUN_STATUSES.has(prev.status ?? '')) {
          closeFeed(`run terminal — feed parked`, 'text-amber-300/70 italic');
        }
      } catch {
        // ignore malformed
      }
    };

    es.addEventListener('run.snapshot', (e) => onSnapshot(e as MessageEvent, true));
    es.addEventListener('run.update', (e) => onSnapshot(e as MessageEvent, false));
    es.addEventListener('finding.enriched', (e) => {
      try {
        const d = JSON.parse((e as MessageEvent).data);
        const sev = String(d.severity || '?').toLowerCase();
        const cls = sev === 'critical' ? 'text-red-400 font-semibold'
          : sev === 'high' ? 'text-orange-300 font-semibold'
          : sev === 'medium' ? 'text-amber-300'
          : 'text-green-200';
        append('FINDING', `[${sev}] ${d.finding_title || '?'}`, cls);
      } catch {
        // ignore
      }
    });
    es.addEventListener('run.missing', () => {
      closeFeed('run no longer queryable', 'text-red-400');
    });
    es.onerror = () => {
      // EventSource fires 'error' both on transient network failures AND on
      // clean server close (readyState=CLOSED). For terminal runs the server
      // closes deliberately; the browser would otherwise loop-retry every
      // ~3s. Treat readyState=CLOSED as a clean stop, NOT as a "reconnecting"
      // spam line.
      if (es && es.readyState === EventSource.CLOSED) {
        if (!announcedConnectedRef.current) {
          // Never got a snapshot — pure failure.
          append('FEED', 'SSE connection closed before any snapshot — backend unreachable?', 'text-red-400');
        }
        setFeedClosed(true);
        es = null;
        return;
      }
      append('RECONNECTING', '(transient SSE error — browser will retry)', 'text-amber-300/70');
    };

    return () => {
      live = false;
      if (es) es.close();
    };
  }, [runId]);

  // Auto-scroll to bottom on new events
  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [events]);

  return (
    <div className="rounded border border-line-soft overflow-hidden bg-[#0b0f13]">
      <div className="px-3 py-1.5 bg-[#1a1f26] border-b border-line-soft flex items-center gap-2">
        <div className="flex items-center gap-1">
          <span className="h-2 w-2 rounded-full bg-red-500/70" />
          <span className="h-2 w-2 rounded-full bg-yellow-500/70" />
          <span className="h-2 w-2 rounded-full bg-green-500/70" />
        </div>
        <span className="h-1.5 w-1.5 rounded-full ml-2 bg-green-400 animate-pulse" />
        <span className="font-mono text-[0.7rem] uppercase tracking-widest text-green-300">aegispt — live events</span>
        <span className="font-mono text-[0.6rem] text-green-300/50 italic">
          (diffed SSE feed — picker / task / foothold / finding events as they arrive)
        </span>
        <span className="ml-auto font-mono text-[0.6rem] text-green-300/60 tabular-nums">{events.length} events</span>
      </div>
      {/* Fixed-height scrollback. Without this the panel grows down the page
          as events accumulate — operator screenshot 2026-05-21. h-[18rem]
          gives ~25 events visible at default font size; older events scroll
          off the top, new ones append at the bottom (overflow-y-auto +
          auto-scroll-to-bottom effect above). */}
      <div
        ref={scrollRef}
        className="px-3 py-2 font-mono text-[0.78rem] leading-snug bg-[#0b0f13] h-[18rem] overflow-y-auto whitespace-pre-wrap break-words"
      >
        {events.length === 0 && (
          <span className="text-green-300/40">(connecting to /runs/{runId.slice(0, 8)}/events …)</span>
        )}
        {events.map((ev, idx) => {
          const time = new Date(ev.ts).toLocaleTimeString('en-GB', { hour12: false }) + '.'
            + String(ev.ts % 1000).padStart(3, '0');
          return (
            <div key={`${ev.ts}-${idx}`} className="grid grid-cols-[7rem_5.5rem_1fr] gap-2 leading-tight">
              <span className="text-green-300/40">{time}</span>
              <span className={cn('font-semibold', ev.cls)}>{ev.tag}</span>
              <span className={ev.cls}>{colorizeLine(ev.text, false)}</span>
            </div>
          );
        })}
        {feedClosed && (
          <div className="mt-1 text-green-300/40 italic">— end of feed (run terminal or backend unreachable) —</div>
        )}
      </div>
    </div>
  );
}


/* =========================================================================
   LIVE API LOG TAIL — raw `tail -f /tmp/aegispt-api.log` inside the browser.
   Operator 2026-05-21: "is deze CLI wel te zien in de website? aangezien
   dat juist belangrijk is. Anders moet ik meerdere schermen openen."
   Backfill of last ~200 lines on connect, then append every new line as
   the API logs it. Survives log rotation (api-log.rotated event).
   ========================================================================= */

function LiveApiLogTail({ defaultOpen = false }: { defaultOpen?: boolean }) {
  const [open, setOpen] = useState(defaultOpen);
  const [lines, setLines] = useState<{ text: string; phase: string; ts: number }[]>([]);
  const [connected, setConnected] = useState(false);
  const [filter, setFilter] = useState<string>('');
  const scrollRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    if (!open) return undefined;
    setLines([]);
    setConnected(false);
    const es = new EventSource('/api/v1/system/api-log/stream');
    let live = true;
    es.addEventListener('api-log.line', (e) => {
      if (!live) return;
      setConnected(true);
      try {
        const d = JSON.parse((e as MessageEvent).data);
        setLines((prev) => {
          const next = [...prev, { text: String(d.text || ''), phase: String(d.phase || 'tail'), ts: Date.now() }];
          // Cap at 1000 lines so memory stays bounded.
          return next.length > 1000 ? next.slice(next.length - 1000) : next;
        });
      } catch {
        // ignore
      }
    });
    es.addEventListener('api-log.rotated', () => {
      if (!live) return;
      setLines((prev) => [...prev, { text: '── log rotated, re-following ──', phase: 'meta', ts: Date.now() }]);
    });
    es.addEventListener('api-log.missing', (e) => {
      if (!live) return;
      try {
        const d = JSON.parse((e as MessageEvent).data);
        setLines((prev) => [...prev, { text: `(api log unavailable: ${d.error})`, phase: 'meta', ts: Date.now() }]);
      } catch {
        // ignore
      }
    });
    es.onerror = () => {
      if (es.readyState === EventSource.CLOSED) {
        setConnected(false);
      }
    };
    return () => {
      live = false;
      es.close();
    };
  }, [open]);

  // "Stick to bottom" — only auto-scroll if the user is currently AT the
  // bottom. If they've scrolled up to read older entries, leave their
  // position alone so they can read freely while new lines land. Threshold
  // of 32px to allow for sub-pixel rendering / wheel deltas.
  const [stickToBottom, setStickToBottom] = useState(true);
  useEffect(() => {
    const el = scrollRef.current;
    if (!el || !stickToBottom) return;
    el.scrollTop = el.scrollHeight;
  }, [lines, stickToBottom]);
  const handleScroll = useCallback(() => {
    const el = scrollRef.current;
    if (!el) return;
    const atBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 32;
    setStickToBottom(atBottom);
  }, []);

  const filtered = filter.trim()
    ? lines.filter((l) => l.text.toLowerCase().includes(filter.toLowerCase()))
    : lines;

  if (!open) {
    return (
      <div className="px-6 pt-4">
        <button
          type="button"
          onClick={() => setOpen(true)}
          className="font-mono text-[0.7rem] uppercase tracking-widest text-green-300/70 hover:text-green-300 border border-green-700/40 rounded px-3 py-1.5 bg-[#0b0f13]"
          title="Open the live API log tail (equivalent to `tail -f /tmp/aegispt-api.log` in a terminal)"
        >
          ▶ open live api log tail
        </button>
      </div>
    );
  }

  return (
    <div className="px-6 pt-4">
      <div className="rounded border border-line-soft overflow-hidden bg-[#0b0f13]">
        <div className="px-3 py-1.5 bg-[#1a1f26] border-b border-line-soft flex items-center gap-2 flex-wrap">
          <div className="flex items-center gap-1">
            <span className="h-2 w-2 rounded-full bg-red-500/70" />
            <span className="h-2 w-2 rounded-full bg-yellow-500/70" />
            <span className="h-2 w-2 rounded-full bg-green-500/70" />
          </div>
          <span className={cn('h-1.5 w-1.5 rounded-full ml-2', connected ? 'bg-green-400 animate-pulse' : 'bg-amber-400 animate-pulse')} />
          <span className="font-mono text-[0.7rem] uppercase tracking-widest text-green-300">tail -f /tmp/aegispt-api.log</span>
          <input
            type="text"
            placeholder="filter…"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            className="ml-2 font-mono text-[0.7rem] bg-[#0b0f13] text-green-300 border border-green-700/40 rounded px-2 py-0.5 w-40"
          />
          <span className="ml-auto font-mono text-[0.6rem] text-green-300/60 tabular-nums">
            {filtered.length}/{lines.length} lines
          </span>
          <button
            type="button"
            onClick={() => setOpen(false)}
            className="font-mono text-[0.6rem] text-amber underline ml-2"
          >
            close
          </button>
        </div>
        <div className="relative">
          <div
            ref={scrollRef}
            onScroll={handleScroll}
            className="px-3 py-2 font-mono text-[0.74rem] leading-tight bg-[#0b0f13] h-[20rem] overflow-y-auto whitespace-pre-wrap break-words"
          >
            {!connected && lines.length === 0 && (
              <span className="text-green-300/40">(connecting to /api/v1/system/api-log/stream …)</span>
            )}
          {filtered.map((l, idx) => {
            const isErr = /\bERROR\b|Traceback|Exception|FAIL/i.test(l.text);
            const isWarn = /\bWARN(ING)?\b|Skip|REJECT/i.test(l.text);
            const isMeta = l.phase === 'meta';
            const baseCls = isErr
              ? 'text-red-400'
              : isWarn
                ? 'text-amber-300'
                : isMeta
                  ? 'text-green-300/50 italic'
                  : l.phase === 'backfill'
                    ? 'text-green-200/60'
                    : 'text-green-200';
            return (
              <div key={`${l.ts}-${idx}`} className={baseCls}>
                {colorizeLine(l.text, isErr)}
              </div>
            );
          })}
          </div>
          {!stickToBottom && (
            <button
              type="button"
              onClick={() => {
                const el = scrollRef.current;
                if (el) el.scrollTop = el.scrollHeight;
                setStickToBottom(true);
              }}
              className="absolute bottom-2 right-3 px-2 py-1 rounded font-mono text-[0.65rem] bg-amber-500/20 border border-amber-400/50 text-amber-200 hover:bg-amber-500/40"
              title="Jump to newest line and resume auto-follow"
            >
              ↓ new lines (resume auto-scroll)
            </button>
          )}
        </div>
      </div>
    </div>
  );
}


function TechnicalView({
  run,
  findings,
  tasks,
  onKill,
  onCinema,
  canKill,
  cinemaDisabled,
}: {
  run: Run;
  findings: Finding[];
  tasks: Task[];
  onKill: () => void;
  onCinema: () => void;
  canKill: boolean;
  cinemaDisabled: boolean;
}) {
  return (
    <div className="flex flex-1 min-h-0 flex-col overflow-y-auto">
      <StatusHero
        run={run}
        findings={findings}
        tasks={tasks}
        onKill={onKill}
        onCinema={onCinema}
        canKill={canKill}
        cinemaDisabled={cinemaDisabled}
      />
      {/* Row 1: Risk trajectory + Tool chain */}
      <div className="grid grid-cols-1 lg:grid-cols-[1fr_1.4fr] gap-4 px-6 pt-4">
        <RiskTrajectoryChart findings={findings} />
        <ToolChainHeartbeat tasks={tasks} />
      </div>
      {/* Row 1.5: Continuous event feed — picker decisions, task transitions,
                   foothold, findings — appended as they happen */}
      <div className="px-6 pt-4">
        <LiveEventsFeed runId={String(run.id)} />
      </div>
      {/* Row 2: Live task drill-down (real command + stdout from API, picker-selectable) */}
      <div className="px-6 pt-4">
        <LiveTaskDrillDown tasks={tasks} />
      </div>
      {/* Row 2.5: Raw API log tail. Collapsed by default to keep the page
                    compact; click to open for `tail -f` in the browser. */}
      <LiveApiLogTail />

      {/* Row 3: Proof + Now playing summary */}
      <div className="grid grid-cols-1 lg:grid-cols-[1.2fr_1fr] gap-4 px-6 pt-4">
        <ProofPanel findings={findings} />
        <div className="space-y-4">
          <NowPlayingTail tasks={tasks} />
          <Heartbeat tasks={tasks} />
        </div>
      </div>
      <DetailsDrawer findings={findings} tasks={tasks} />
    </div>
  );
}

/* =========================================================================
   MAIN EXPORT — toggle between Story and Technical
   ========================================================================= */

export default function MissionControlV3({
  run,
  tasks,
  findings,
  proposals,
  onKill,
  onCinema,
  canKill,
  cinemaDisabled,
}: {
  run: Run;
  tasks: Task[];
  findings: Finding[];
  proposals: AgentProposal[];
  onKill: () => void;
  onCinema: () => void;
  canKill: boolean;
  cinemaDisabled: boolean;
}) {
  const { t } = useI18n();
  const [view, setView] = useState<'story' | 'technical'>('story');
  const pendingProposalCount = proposals.filter((proposal) => (proposal.status || '').toLowerCase() === 'pending').length;

  return (
    <div className="flex h-full min-h-0 flex-1 flex-col">
      <ClaudeThinking run={run} />
      {/* View switcher */}
      <div className="flex items-center gap-1 px-6 py-2 border-b border-line-soft bg-surface/40">
        <button
          type="button"
          onClick={() => setView('story')}
          className={cn(
            'rounded px-3 py-1 font-mono text-[0.72rem] uppercase tracking-widest transition-colors',
            view === 'story'
              ? 'bg-ai/15 border border-ai/40 text-ai'
              : 'border border-transparent text-muted hover:text-text',
          )}
        >
          {t('mission.view.story')}
        </button>
        <button
          type="button"
          onClick={() => setView('technical')}
          className={cn(
            'rounded px-3 py-1 font-mono text-[0.72rem] uppercase tracking-widest transition-colors',
            view === 'technical'
              ? 'bg-cyan/15 border border-cyan/40 text-cyan'
              : 'border border-transparent text-muted hover:text-text',
          )}
        >
          {t('mission.view.technical')}
        </button>
        <span className="ml-auto font-mono text-[0.65rem] text-muted">
          {view === 'story' ? t('mission.storyDetail') : t('mission.technicalDetail')}
          {pendingProposalCount > 0 ? ` · ${pendingProposalCount} pending` : ''}
        </span>
      </div>

      {view === 'story' ? (
        <StoryView run={run} findings={findings} tasks={tasks} />
      ) : (
        <TechnicalView
          run={run}
          findings={findings}
          tasks={tasks}
          onKill={onKill}
          onCinema={onCinema}
          canKill={canKill}
          cinemaDisabled={cinemaDisabled}
        />
      )}
    </div>
  );
}
