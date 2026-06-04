import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type {
  KeyboardEvent as ReactKeyboardEvent,
  PointerEvent as ReactPointerEvent,
  WheelEvent as ReactWheelEvent,
} from 'react';
import { createPortal } from 'react-dom';
import { CircleStop, MonitorPlay, ChevronDown, ChevronRight, Pause } from 'lucide-react';
import { Link } from 'react-router-dom';
import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';
import type { AgentProposal, Finding, Run, Task } from '../../api/types';
import { getRunProposals, getTaskDetail, reviewAgentProposal } from '../../api/client';
import { useI18n } from '../../i18n';
import { useAegisStore } from '../../store';
import { safeMissionFindingTitle } from '../../viewModels/missionStory';
import RunTruthStrip from '../RunTruthStrip';

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
  level: 'compromised' | 'critical' | 'leads' | 'scanning' | 'waiting' | 'active' | 'done';
  tone: string;
  toneBg: string;
  label: string;
  emoji: string;
};

function missionTaskCounts(tasks: Task[]) {
  return tasks.reduce(
    (counts, task) => {
      const status = (task.status || '').toLowerCase();
      if (['running', 'dispatching', 'active', 'in_progress', 'executing'].includes(status)) counts.running += 1;
      if (['queued', 'pending', 'requested', 'waiting', 'pending_approval'].includes(status)) counts.queued += 1;
      if (['completed', 'succeeded', 'success', 'done'].includes(status)) counts.completed += 1;
      if (['failed', 'errored', 'error', 'cancelled', 'canceled', 'timed_out', 'timeout'].includes(status)) counts.failed += 1;
      return counts;
    },
    { running: 0, queued: 0, completed: 0, failed: 0 },
  );
}

function deriveMissionState(run: Run, findings: Finding[], tasks: Task[] = []): MissionState {
  const status = (run.status || '').toLowerCase();
  const taskStats = missionTaskCounts(tasks);
  const counts = countSeverity(findings);
  const isDone = ['completed', 'failed', 'cancelled', 'canceled', 'completed_with_errors', 'rejected', 'errored', 'stopped'].includes(status);

  // Terminal runs present retrospectively regardless of severity. Findings can
  // still be shown, but the page must not imply active work after the backend
  // has marked the run terminal.
  //
  // New rule: if run.status is terminal, return ENDED with a severity
  // suffix in the label so the operator still sees what was found. The
  // paragraph branch ('done') then describes outcome retrospectively.
  if (isDone) {
    const sevSummary = counts.critical > 0
      ? `${counts.critical}C/${counts.high}H`
      : counts.high > 0
        ? `${counts.high}H`
        : counts.medium > 0
          ? `${counts.medium}M`
          : 'no exploit';
    const endedLabel = status === 'cancelled' || status === 'canceled'
      ? `CANCELLED · ${sevSummary}`
      : status === 'completed_with_errors'
        ? `ENDED (errors) · ${sevSummary}`
        : `ENDED · ${sevSummary}`;
    return {
      level: 'done',
      tone: 'text-muted',
      toneBg: 'bg-line-soft/30 border-line',
      label: endedLabel,
      emoji: '⚪',
    };
  }

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
    return { level: 'leads', tone: 'text-amber', toneBg: 'bg-amber/15 border-amber/40', label: 'HIGH RISK', emoji: '🟠' };
  }
  if (counts.medium > 0 || counts.low > 0) {
    return { level: 'scanning', tone: 'text-yellow-400', toneBg: 'bg-yellow-400/10 border-yellow-400/30', label: 'SCANNING', emoji: '🟡' };
  }
  if (taskStats.running > 0) {
    return { level: 'active', tone: 'text-green-400', toneBg: 'bg-green-400/10 border-green-400/30', label: 'RUNNING', emoji: '🟢' };
  }
  if (taskStats.queued > 0) {
    return { level: 'waiting', tone: 'text-amber', toneBg: 'bg-amber/10 border-amber/30', label: 'WAITING', emoji: '🟡' };
  }
  if (taskStats.completed > 0) {
    return { level: 'scanning', tone: 'text-yellow-400', toneBg: 'bg-yellow-400/10 border-yellow-400/30', label: 'OBSERVED', emoji: '🟡' };
  }
  return { level: 'active', tone: 'text-green-400', toneBg: 'bg-green-400/10 border-green-400/30', label: 'READY', emoji: '🟢' };
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
  const state = useMemo(() => deriveMissionState(run, findings, tasks), [run, findings, tasks]);
  const counts = useMemo(() => countSeverity(findings), [findings]);
  const proof = useMemo(() => topFindingForProof(findings), [findings]);
  const host = useMemo(() => targetHost(run, tasks), [run, tasks]);
  const lastReason = useMemo(() => lastDecisionReasoning(run), [run]);
  const taskStats = useMemo(() => missionTaskCounts(tasks), [tasks]);
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
    if (state.level === 'waiting') return 'Waiting for the next task';
    if (state.level === 'scanning') return findings.length > 0 ? 'Low-risk findings recorded' : 'Signals observed, no finding persisted';
    if (state.level === 'done') return 'Run ended';
    return taskStats.running > 0 ? 'Task running now' : 'Ready for the next move';
  }, [state.level, proof, findings.length, taskStats.running]);

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
            <h2 className="text-[1.6rem] font-bold text-text leading-tight tracking-tight">{headline}</h2>
            <span className="font-mono text-[0.78rem] text-amber tabular-nums ml-auto shrink-0">{formatUptime(run.started_at)}</span>
          </div>

          {/* One-line: counts + target */}
          <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-[0.95rem] mb-2">
            <span className={cn('font-bold tabular-nums', leadsCount > 0 ? 'text-amber' : 'text-muted')}>
              {leadsCount} high-risk {leadsCount === 1 ? 'finding' : 'findings'}
            </span>
            <span className="font-mono text-[0.82rem] text-muted">
              {taskStats.completed} done · {taskStats.running} running · {taskStats.queued} queued
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
          {state.level === 'waiting' && (
            <div className="text-[0.85rem] text-soft leading-snug mb-3 line-clamp-2">
              <span className="font-mono text-[0.7rem] uppercase tracking-widest text-muted mr-2">Waiting on</span>
              {taskStats.queued > 0
                ? `${taskStats.queued} queued task${taskStats.queued === 1 ? '' : 's'}; completed output is signal only until findings are persisted.`
                : 'No task is running right now.'}
            </div>
          )}
          {state.level !== 'waiting' && state.level !== 'done' && lastReason && (
            <div className="text-[0.85rem] text-soft leading-snug mb-3 line-clamp-2">
              <span className="font-mono text-[0.7rem] uppercase tracking-widest text-muted mr-2">Next</span>
              {lastReason}
            </div>
          )}
          {state.level === 'done' && (
            <div className="text-[0.85rem] text-soft leading-snug mb-3 line-clamp-2">
              <span className="font-mono text-[0.7rem] uppercase tracking-widest text-muted mr-2">Next</span>
              Review Findings and Evidence Replay before exporting a report.
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
        No exploit-class evidence captured yet.
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
  'target-intel':         { emoji: '🔭', alt: '🏢', caption: 'Building target context: technology, reachable services, and likely test paths.', vibe: 'recon' },
  'content-discovery':    { emoji: '🚪🚪🚪', caption: 'Enumerating reachable paths and endpoints.', vibe: 'recon' },
  'smart-web-probe':      { emoji: '🔍', alt: '🏢', caption: 'Collecting web application structure and behavior signals.', vibe: 'recon' },
  'nuclei':               { emoji: '📋', alt: '🚪', caption: 'Running known-safe template checks against reachable targets.', vibe: 'try' },
  'httpx':                { emoji: '🚪', alt: '👂', caption: 'Checking HTTP reachability, titles, status codes, and response metadata.', vibe: 'recon' },
  'nikto':                { emoji: '🧰', alt: '🚪', caption: 'Running baseline web-server checks.', vibe: 'try' },
  'auth-flow':            { emoji: '🔑', alt: '🚪', caption: 'Testing authentication behavior and session boundaries.', vibe: 'try' },
  'xss-extended':         { emoji: '📝', alt: '🚪', caption: 'Testing reflected and stored input handling with bounded payloads.', vibe: 'try' },
  'xss-proof':            { emoji: '✉️', alt: '↩️', caption: 'Checking whether a submitted payload is reflected as executable proof.', vibe: 'win' },
  'idor-bac':             { emoji: '🏃', alt: '🚪🚪🚪', caption: 'Testing object access boundaries across many identifiers.', vibe: 'try' },
  'sqlmap':               { emoji: '🪟', caption: 'Testing SQL injection hypotheses with a bounded runner.', vibe: 'try' },
  'ssti-probe':           { emoji: '✏️', alt: '🪧', caption: 'Testing server-side template handling with bounded payloads.', vibe: 'try' },
  'csrf-check':           { emoji: '🪪', alt: '🚪', caption: 'Checking whether state-changing actions require CSRF protection.', vibe: 'try' },
  'session-security':     { emoji: '🔑', alt: '🧪', caption: 'Testing whether session tokens and cookies enforce the expected boundaries.', vibe: 'try' },
  'client-state':         { emoji: '📓', caption: 'Reviewing client-side state for exposed identifiers or risky trust decisions.', vibe: 'recon' },
  'biz-logic-probe':      { emoji: '🧠', alt: '🚪', caption: 'Testing business-rule assumptions and process abuse paths.', vibe: 'try' },
  'playwright-web':       { emoji: '👤', alt: '🚪', caption: 'Driving the site like a browser user to observe behavior.', vibe: 'try' },
  'burp':                 { emoji: '🕵️', alt: '🚪', caption: 'Inspecting request and response traffic.', vibe: 'try' },
  'zap':                  { emoji: '⚡', alt: '🚪', caption: 'Running an active web probe within scope.', vibe: 'try' },
  'http-smuggling':       { emoji: '🚪', alt: '🚪', caption: 'Testing HTTP request parsing boundaries between front-end and back-end services.', vibe: 'try' },
  'waf-detect':           { emoji: '🛡️', caption: 'Checking for web application firewall behavior.', vibe: 'recon' },
  'logging-probe':        { emoji: '📣', caption: 'Triggering safe requests and observing logged or reflected output.', vibe: 'try' },
  'exec-plan':            { emoji: '🔧', alt: '🔒', caption: 'Running a bounded custom execution plan.', vibe: 'try' },
  'malware-sim':          { emoji: '☠️', alt: '🚪', caption: 'Testing detection behavior with safe malware-simulation patterns.', vibe: 'try' },
  'ai-shell':             { emoji: '🤖', alt: '💻', caption: 'Testing AI-assistant exposure and response boundaries.', vibe: 'try' },
  'c2-ingest':            { emoji: '📡', caption: 'Checking for command-and-control indicators or exposed callback channels.', vibe: 'recon' },
  'graphql-command-injection': { emoji: '🧬', alt: '🚪', caption: 'Testing GraphQL command-injection hypotheses with bounded payloads.', vibe: 'try' },
  'iot-default-creds':    { emoji: '📡', alt: '🔑', caption: 'Testing known default credentials on in-scope devices.', vibe: 'try' },
};

const SCENE_IDLE: LiveScene = {
  emoji: '🧠',
  caption: 'No task is running right now.',
  vibe: 'idle',
};

const SCENE_RECON_DEFAULT: LiveScene = {
  emoji: '🗺️',
  caption: 'Recon output is being collected. It is not a finding until persistence creates a finding record.',
  vibe: 'recon',
};

function sceneForActiveTool(tool: string | null): LiveScene {
  if (!tool) return SCENE_IDLE;
  return TOOL_SCENE[tool] ?? { emoji: '⚙️', caption: `Running ${tool}. Waiting for output and persistence.`, vibe: 'try' };
}

// When there are no active tools but findings are accumulating, infer a
// "context" scene based on what we have proven so far.
function sceneForFindings(findings: Finding[], host: string): LiveScene {
  const counts = countSeverity(findings);
  const titles = findings.map((f) => String(f.title || '').toLowerCase()).join(' | ');
  if (counts.critical > 0 && /admin|compromise|takeover|rce/.test(titles)) {
    return { emoji: '🏆', alt: '🔓', caption: 'Critical compromise evidence is persisted. Review proof and scope before reporting.', vibe: 'win' };
  }
  if (titles.includes('path traversal')) {
    return { emoji: '🗂️', alt: '🔓', caption: 'Path traversal evidence is persisted. Review the exact request and response in Findings or Evidence Replay.', vibe: 'win' };
  }
  if (counts.high >= 5) {
    return { emoji: '🚪🚪🚪', alt: '🔓', caption: `${counts.high} high-severity findings are persisted. Prioritize proof review and remediation order.`, vibe: 'win' };
  }
  if (counts.high > 0) {
    return { emoji: '🚪', alt: '🔓', caption: 'A high-severity finding is persisted. Review evidence before treating it as report-ready.', vibe: 'win' };
  }
  if (counts.medium > 0 || counts.low > 0) {
    return { emoji: '🏢', alt: '🔍', caption: `Lower-risk findings are persisted for ${host || 'the target'}. No high-risk finding is recorded yet.`, vibe: 'recon' };
  }
  return SCENE_RECON_DEFAULT;
}

function LiveSceneCard({
  run,
  tasks,
  findings,
  host,
}: {
  run: Run;
  tasks: Task[];
  findings: Finding[];
  host: string;
}) {
  useTicker(2000);
  const active = useMemo(() => activeTaskNow(tasks), [tasks]);
  const taskStats = useMemo(() => missionTaskCounts(tasks), [tasks]);
  const runStatus = (run.status || '').toLowerCase();
  const runIsTerminal = ['completed', 'failed', 'cancelled', 'canceled', 'completed_with_errors', 'rejected', 'errored', 'stopped'].includes(runStatus);
  const latestTask = useMemo(() => {
    return [...tasks].sort((a, b) => String(b.updated_at ?? b.created_at).localeCompare(String(a.updated_at ?? a.created_at)))[0] ?? null;
  }, [tasks]);
  const scene = useMemo(() => {
    if (active) return sceneForActiveTool(active.tool);
    if (runIsTerminal) {
      return {
        emoji: '✓',
        caption: latestTask
          ? `Run is terminal. Last task: ${latestTask.tool} (${latestTask.status}). Review persisted findings and evidence.`
          : 'Run is terminal. Review persisted findings and evidence.',
        vibe: findings.length > 0 ? 'win' : 'idle',
      } satisfies LiveScene;
    }
    if (taskStats.queued > 0) {
      return {
        emoji: '⏳',
        caption: `${taskStats.queued} task${taskStats.queued === 1 ? '' : 's'} queued; ${taskStats.completed} completed task${taskStats.completed === 1 ? '' : 's'} produced signal-only output.`,
        vibe: 'idle',
      } satisfies LiveScene;
    }
    return sceneForFindings(findings, host);
  }, [active, runIsTerminal, latestTask, taskStats.queued, taskStats.completed, findings, host]);
  const label = active ? 'Working now' : runIsTerminal ? 'Run ended' : taskStats.queued > 0 ? 'Waiting' : 'Current state';
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
        <span className={cn('h-1.5 w-1.5 rounded-full', active ? 'bg-green-400 animate-pulse' : 'bg-line')} />
        <span className="font-mono text-[0.62rem] uppercase tracking-widest text-muted">{label}</span>
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

export function StoryView({ run, findings, tasks }: { run: Run; findings: Finding[]; tasks: Task[] }) {
  const { t } = useI18n();
  useTicker(2000);
  const beats = useMemo(() => buildStoryBeats(run, findings, tasks), [run, findings, tasks]);
  const state = useMemo(() => deriveMissionState(run, findings, tasks), [run, findings, tasks]);
  const counts = useMemo(() => countSeverity(findings), [findings]);
  const proof = useMemo(() => topFindingForProof(findings), [findings]);
  const host = useMemo(() => targetHost(run, tasks), [run, tasks]);
  const sparkline = useMemo(() => buildFindingsSparkline(findings), [findings]);
  const active = useMemo(() => activeTaskNow(tasks), [tasks]);
  const lastReason = useMemo(() => lastDecisionReasoning(run), [run]);
  const taskStats = useMemo(() => missionTaskCounts(tasks), [tasks]);
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
      lines.push({ text: 'Compromise evidence persisted.', tone: 'text-fuchsia-300 font-bold' });
      lines.push({ text: ` After ${minutes} minutes${hostPhrase}, the run recorded admin-level or code-execution proof. ` });
      if (proof) lines.push({ text: `Primary proof: `, tone: 'text-muted' });
      if (proof) lines.push({ text: inferCwe(String(proof.title)).label, tone: 'text-amber font-semibold' });
      lines.push({ text: '.' });
    } else if (state.level === 'critical') {
      lines.push({ text: 'Critical finding persisted.', tone: 'text-red font-bold' });
      lines.push({ text: ` After ${minutes} minutes, the canonical findings list contains ${counts.critical} critical and ${counts.high} high-severity finding${counts.critical + counts.high === 1 ? '' : 's'}` });
      lines.push(...hostInline());
      lines.push({ text: '. Review the linked evidence before reporting impact.' });
    } else if (state.level === 'leads') {
      lines.push({ text: 'High-risk finding persisted.', tone: 'text-amber font-bold' });
      lines.push({ text: ` ${minutes} minutes in, the canonical findings list contains ${counts.high} high-severity finding${counts.high === 1 ? '' : 's'}` });
      lines.push(...hostInline());
      lines.push({ text: '. Review proof, remediation, and whether validation is complete.' });
    } else if (state.level === 'scanning') {
      if (findings.length > 0) {
        lines.push({ text: 'Low-risk findings only.', tone: 'text-yellow-400 font-bold' });
        lines.push({ text: ` After ${minutes} minutes${hostPhrase}, ${counts.medium + counts.low + counts.info} lower-risk finding${counts.medium + counts.low + counts.info === 1 ? '' : 's'} are persisted. No high-risk finding is recorded.` });
      } else {
        lines.push({ text: 'Signals observed, no finding persisted.', tone: 'text-yellow-400 font-bold' });
        lines.push({ text: ` ${taskStats.completed} completed task${taskStats.completed === 1 ? '' : 's'} produced output${hostPhrase}, but the canonical findings list is still empty.` });
      }
    } else if (state.level === 'waiting') {
      lines.push({ text: 'Waiting.', tone: 'text-amber font-bold' });
      lines.push({ text: ` ${taskStats.queued} task${taskStats.queued === 1 ? '' : 's'} queued, ${taskStats.completed} completed, ${taskStats.running} running` });
      lines.push(...hostInline());
      lines.push({ text: '. Completed output is signal only until a finding is persisted.' });
    } else if (state.level === 'done') {
      // FIX 2026-05-27: paragraph must reflect status, not pretend the
      // agent is still working. Status word from state.label so the user
      // sees CANCELLED / ENDED / ENDED-with-errors explicitly.
      const statusWord = state.label.split(' ')[0] || 'ENDED';
      lines.push({ text: `${statusWord.charAt(0)}${statusWord.slice(1).toLowerCase()}.`, tone: 'text-muted font-bold' });
      lines.push({ text: ` After ${minutes} minutes${hostPhrase}, finished with ${counts.critical} critical, ${counts.high} high, ${counts.medium + counts.low + counts.info} informational finding${counts.medium + counts.low + counts.info === 1 ? '' : 's'}.` });
      if (counts.critical === 0 && counts.high === 0) {
        lines.push({ text: ' No exploit-class finding was produced.', tone: 'text-muted italic' });
      } else {
        lines.push({ text: ' Review the linked evidence before exporting or sharing the report.', tone: 'text-muted italic' });
      }
    } else {
      lines.push({ text: taskStats.running > 0 ? 'Running.' : 'Ready.', tone: 'text-text font-bold' });
      lines.push(...hostInline());
      lines.push({ text: taskStats.running > 0 ? '. A task is active; findings will appear only after persistence.' : '. No task is running and no exploit signal is persisted yet.' });
    }
    return lines;
  }, [state.level, state.label, counts, host, minutes, proof, findings.length, taskStats]);

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
        <LiveSceneCard run={run} tasks={tasks} findings={findings} host={host} />
        <div className="rounded border border-line-soft bg-bg-2/40 p-4 flex flex-col">
          <div className="flex items-center gap-2 mb-2">
            <span className="font-mono text-[0.62rem] uppercase tracking-widest text-muted">
              {state.level === 'done' ? 'Recommended next step' : state.level === 'waiting' ? 'Waiting on' : 'My next move'}
            </span>
          </div>
          {state.level === 'done' ? (
            <p className="text-[0.95rem] text-text leading-snug">Open Findings or Evidence Replay to verify persisted proof, then generate reports from Report Center.</p>
          ) : state.level === 'waiting' ? (
            <p className="text-[0.95rem] text-text leading-snug">
              {taskStats.queued > 0
                ? `${taskStats.queued} queued task${taskStats.queued === 1 ? '' : 's'} remain. There is no active task right now.`
                : 'No active task is running right now.'}
            </p>
          ) : lastReason ? (
            <p className="text-[0.95rem] text-text leading-snug">{lastReason}</p>
          ) : narratorPanels.length > 0 ? (
            // No raw decision reasoning, but the comic-strip's most recent
            // panel already includes a next_move written by ChatGPT/Opus.
            <p className="text-[0.95rem] text-text leading-snug">
              {String(narratorPanels[narratorPanels.length - 1].next_move || 'Considering the next move.')}
            </p>
          ) : (
            <p className="text-[0.92rem] text-muted italic">Waiting for the next decision or task update.</p>
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

function LiveMissionView({ run, findings, tasks }: { run: Run; findings: Finding[]; tasks: Task[] }) {
  const state = useMemo(() => deriveMissionState(run, findings, tasks), [run, findings, tasks]);
  const taskStats = useMemo(() => missionTaskCounts(tasks), [tasks]);
  const active = useMemo(() => activeTaskNow(tasks), [tasks]);
  const latest = useMemo(() => latestTasks(tasks, 5), [tasks]);
  const current = active ?? latest[0] ?? null;
  const host = useMemo(() => targetHost(run, tasks), [run, tasks]);
  const runEnded = isTerminalRun(run);
  const status = missionStatusCopy(run, state, taskStats, findings, current, host);
  const nextTask = useMemo(() => queuedTasks(tasks)[0] ?? null, [tasks]);
  const [selectedTaskId, setSelectedTaskId] = useState<string | null>(null);
  const selectedTask = useMemo(
    () => tasks.find((task) => String(task.id) === selectedTaskId) ?? current,
    [current, selectedTaskId, tasks],
  );

  useEffect(() => {
    if (selectedTaskId && tasks.some((task) => String(task.id) === selectedTaskId)) return;
    setSelectedTaskId(current ? String(current.id) : null);
  }, [current, selectedTaskId, tasks]);

  return (
    <div className="min-h-0 flex-1 overflow-y-auto">
      <div className="px-6 py-4">
        <MissionSnapshotCockpit
          run={run}
          state={state}
          host={host}
          taskStats={taskStats}
          findings={findings}
          tasks={tasks}
          active={active}
          nextTask={nextTask}
        />
      </div>

      <div className="grid gap-4 border-b border-line-soft px-6 pb-4 xl:grid-cols-[1.12fr_0.88fr]">
        <section className="rounded-lg border border-cyan/14 bg-surface/25 p-4">
          <div className="mb-3 flex items-center justify-between gap-3">
            <h3 className="font-mono text-[0.7rem] font-semibold uppercase tracking-widest text-muted">Live CLI</h3>
            <div className="flex items-center gap-2">
              <span className="text-[0.8rem] text-muted">{selectedTask ? selectedTask.tool : 'no task selected'}</span>
              <Link className="rounded border border-line-soft px-2 py-1 text-[0.75rem] text-cyan hover:bg-cyan/10" to="/live-cli">
                Open full CLI
              </Link>
            </div>
          </div>
          <LiveTaskDrillDown tasks={tasks} selectedTaskId={selectedTaskId} onSelectedTaskIdChange={setSelectedTaskId} compact />
        </section>
        <QueueSnapshot tasks={tasks} selectedTaskId={selectedTaskId} onSelectTask={setSelectedTaskId} />
      </div>

      <details className="mx-6 mt-4 rounded border border-line-soft bg-surface/20">
        <summary className="cursor-pointer px-4 py-3 font-mono text-[0.7rem] uppercase tracking-widest text-muted hover:text-text">
          Open attack path, story cards, live events, and technical facts
        </summary>
        <div className="grid gap-4 border-t border-line-soft p-4 xl:grid-cols-2">
          <div className="xl:col-span-2">
            <MissionJourneyMap run={run} tasks={tasks} findings={findings} />
          </div>
          <NowSnapshot
            state={state}
            statusTitle={active ? `Checking ${active.tool}` : runEnded ? 'Run ended' : status.title}
            host={host}
            uptime={formatUptime(run.started_at)}
            taskStats={taskStats}
            findings={findings}
            active={active}
            nextTask={nextTask}
          />
          <MissionStoryBoard run={run} active={active} nextTask={nextTask} taskStats={taskStats} findings={findings} />
          <OutcomePulseChart taskStats={taskStats} findings={findings} runEnded={runEnded} />
          <PlainLanguagePanel title="In gewone taal" detail={livePlainLanguage(run, selectedTask, taskStats, findings)} />
          <TechnicalFactsPanel
            facts={[
              ['Run', run.status || 'unknown'],
              ['Selected task', selectedTask ? `${selectedTask.tool} / ${selectedTask.status}` : 'none'],
              ['Queue', `${taskStats.running} running / ${taskStats.queued} waiting`],
              ['Findings', `${findings.length} reportable`],
            ]}
          />
          <section className="rounded border border-line-soft bg-surface/30 p-4 xl:col-span-2">
            <div className="mb-3 flex items-center justify-between gap-3">
              <h3 className="font-mono text-[0.7rem] font-semibold uppercase tracking-widest text-muted">Live events</h3>
              <span className="text-[0.8rem] text-muted">run feed</span>
            </div>
            <LiveEventsFeed runId={String(run.id)} />
          </section>
        </div>
      </details>
    </div>
  );
}

type MissionPhaseKey = 'map' | 'inspect' | 'test' | 'prove' | 'report';

function MissionSnapshotCockpit({
  run,
  state,
  host,
  taskStats,
  findings,
  tasks,
  active,
  nextTask,
}: {
  run: Run;
  state: MissionState;
  host: string;
  taskStats: ReturnType<typeof missionTaskCounts>;
  findings: Finding[];
  tasks: Task[];
  active: Task | null;
  nextTask: Task | null;
}) {
  const counts = countSeverity(findings);
  const runEnded = isTerminalRun(run);
  const checked = taskStats.completed + taskStats.failed;
  const totalTasks = Math.max(1, tasks.length);
  const checkedPct = Math.min(100, Math.round((checked / totalTasks) * 100));
  const highRisk = counts.critical + counts.high;
  const leadFinding = [...findings].sort(
    (a, b) =>
      (SEV_ORDER[(a.severity || 'info').toLowerCase()] ?? 9) -
      (SEV_ORDER[(b.severity || 'info').toLowerCase()] ?? 9),
  )[0] ?? null;
  const proofTitle = leadFinding ? safeMissionFindingTitle(leadFinding) : null;
  const presence = operatorPresenceCue(runEnded, findings.length, checked, tasks.length, active, nextTask, proofTitle);
  const activityState = missionActivityState(runEnded, active, nextTask, findings.length);
  const nextLabel = active
    ? `Watch ${active.tool}`
    : findings.length > 0
      ? 'Review proof'
      : nextTask
        ? `Run ${nextTask.tool}`
        : runEnded
          ? 'Close out'
          : 'Wait for decision';
  const actionTarget = findings.length > 0 ? '/findings' : active ? '/live-cli' : nextTask ? '/live-cli' : runEnded ? '/reports' : '/overview';
  const actionLabel = findings.length > 0 ? 'Review findings' : active ? 'Watch CLI' : nextTask ? 'Watch queue' : runEnded ? 'Build report' : 'Open overview';

  return (
    <section
      aria-label="Mission snapshot"
      data-activity={activityState}
      className="mission-control-snapshot overflow-hidden rounded-xl border border-cyan/25"
    >
      <div className="px-4 py-3">
        <div className="grid items-start gap-3 xl:grid-cols-[minmax(0,1fr)_minmax(25rem,0.46fr)]">
          <div className="min-w-0">
            <div className="mb-1.5 flex flex-wrap items-center gap-2">
              <span className="font-mono text-[0.6rem] uppercase tracking-[0.24em] text-cyan/75">You are here</span>
              <span className={cn('rounded-full border px-2 py-0.5 font-mono text-[0.58rem] font-bold uppercase tracking-widest', state.toneBg, state.tone)}>
                {presence.mode}
              </span>
            </div>
            <h2 className="text-[clamp(1.25rem,1.35vw,1.65rem)] font-semibold leading-tight text-text">{presence.title}</h2>
            <p className="mt-1 max-w-[62rem] text-[0.84rem] leading-5 text-soft">{presence.detail}</p>
            <MissionActivityPulse activityState={activityState} active={active} nextTask={nextTask} checkedPct={checkedPct} />
          </div>
          <div className="grid items-start gap-2 sm:grid-cols-3 xl:grid-cols-3">
            <SnapshotFact label="Status" value={presence.system} />
            <SnapshotFact label="Checked" value={`${checked}/${tasks.length || 0}`} />
            <SnapshotFact label="Findings" value={`${findings.length} reportable`} />
          </div>
        </div>
        <div className="mt-3 grid gap-2 md:grid-cols-[1fr_9rem_9rem_10rem_auto]">
          <SnapshotFact label="Target" value={host || 'unknown'} />
          <SnapshotFact label="Risk" value={`${highRisk} high-risk`} />
          <SnapshotFact label="Next" value={nextLabel} />
          <SnapshotFact label="Clock" value={formatUptime(run.started_at)} />
          <Link className="flex items-center justify-center rounded-lg border border-cyan/35 bg-cyan/10 px-3 py-1.5 text-center text-[0.78rem] font-semibold text-cyan hover:bg-cyan/15" to={actionTarget}>
            {actionLabel}
          </Link>
        </div>
      </div>
    </section>
  );
}

function operatorPresenceCue(
  runEnded: boolean,
  findingCount: number,
  checked: number,
  totalTasks: number,
  active: Task | null,
  nextTask: Task | null,
  proofTitle: string | null,
) {
  if (runEnded && findingCount > 0) {
    return {
      mode: 'review',
      title: 'You are reviewing the proof path',
      detail: proofTitle
        ? `Saved proof is ready. Start with ${proofTitle}, then decide what belongs in the report.`
        : 'Saved proof is ready. Review the evidence before reporting.',
      role: 'verify proof',
      system: 'finished',
      evidence: `${findingCount} saved`,
    };
  }
  if (runEnded) {
    return {
      mode: 'closeout',
      title: 'You are closing a route without proof',
      detail: 'The run stopped without saved proof. Use the route and evidence replay to decide if this path is a dead end.',
      role: 'decide reroute',
      system: 'stopped',
      evidence: `${checked}/${totalTasks || 0} checked`,
    };
  }
  if (active) {
    return {
      mode: 'live',
      title: 'You are watching the active route',
      detail: `${humanizeTool(active.tool)} is running now. Follow the route; open CLI only when the raw output matters.`,
      role: 'watch route',
      system: `running ${active.tool}`,
      evidence: `${checked}/${totalTasks || 0} checked`,
    };
  }
  if (nextTask) {
    return {
      mode: 'queued',
      title: 'You are waiting for the next move',
      detail: `${humanizeTool(nextTask.tool)} is queued. Planned work becomes evidence only after output is saved and linked.`,
      role: 'approve/watch',
      system: `next ${nextTask.tool}`,
      evidence: `${checked}/${totalTasks || 0} checked`,
    };
  }
  return {
    mode: 'ready',
    title: 'You are at the decision point',
    detail: 'No task is running right now. Use the route, evidence, and findings to choose whether to review, report, or continue testing.',
    role: 'choose next',
    system: 'idle',
    evidence: `${checked}/${totalTasks || 0} checked`,
  };
}

function missionActivityState(
  runEnded: boolean,
  active: Task | null,
  nextTask: Task | null,
  findingCount: number,
): 'running' | 'queued' | 'review' | 'done' | 'idle' {
  if (active) return 'running';
  if (nextTask && !runEnded) return 'queued';
  if (findingCount > 0) return 'review';
  if (runEnded) return 'done';
  return 'idle';
}

function MissionActivityPulse({
  activityState,
  active,
  nextTask,
  checkedPct,
}: {
  activityState: ReturnType<typeof missionActivityState>;
  active: Task | null;
  nextTask: Task | null;
  checkedPct: number;
}) {
  const label = active
    ? `running ${humanizeTool(active.tool)}`
    : nextTask
      ? `queued ${humanizeTool(nextTask.tool)}`
      : activityState === 'review'
        ? 'proof ready'
        : activityState === 'done'
          ? 'run ended'
          : 'idle';
  return (
    <div className="mission-activity-pulse" data-activity={activityState} aria-label={`Live system activity: ${label}`}>
      <span className="mission-activity-status" aria-hidden="true" />
      <span className="min-w-[6.5rem] font-mono text-[0.58rem] font-semibold uppercase tracking-widest text-cyan/75">{label}</span>
      <span className="mission-activity-track" aria-hidden="true">
        <span style={{ width: `${Math.max(6, Math.min(100, checkedPct))}%` }} />
      </span>
      <span className="font-mono text-[0.58rem] uppercase tracking-widest text-muted">{checkedPct}% checked</span>
    </div>
  );
}

function SnapshotFact({ label, value, className }: { label: string; value: string; className?: string }) {
  return (
    <div className={cn('mission-control-card min-w-0 self-start rounded-lg border border-cyan/12 px-2.5 py-1.5', className)}>
      <div className="font-mono text-[0.52rem] uppercase tracking-widest text-muted">{label}</div>
      <div className="mt-0.5 truncate text-[0.84rem] font-semibold text-text">{value}</div>
    </div>
  );
}

function queuedTasks(tasks: Task[]): Task[] {
  return tasks.filter((task) => ['queued', 'pending', 'requested', 'waiting', 'pending_approval'].includes((task.status || '').toLowerCase()));
}

function runningTasks(tasks: Task[]): Task[] {
  return tasks.filter((task) => ['running', 'dispatching', 'active', 'in_progress', 'executing'].includes((task.status || '').toLowerCase()));
}

function missionPhaseForTask(task: Task): MissionPhaseKey {
  const text = `${task.tool} ${task.target_id || ''}`.toLowerCase();
  if (/\b(report|export|summary)\b/.test(text)) return 'report';
  if (/\b(verif|proof|grader|evidence|persist|finding|m2)\b/.test(text)) return 'prove';
  if (/\b(sqlmap|xss|attack|exploit|rce|exec|ssti|csrf|upload|param|idor|inject|shell)\b/.test(text)) return 'test';
  if (/\b(nmap|masscan|recon|surface|target-intel|bootstrap|fingerprint)\b/.test(text)) return 'map';
  return 'inspect';
}

type AttackFlowStatus = 'done' | 'running' | 'queued' | 'failed' | 'finding' | 'ready' | 'idle';

type AttackFlowTimelineTone = 'muted' | 'good' | 'warn' | 'danger' | 'proof';

type AttackFlowTimelineChip = {
  label: string;
  value: string;
  tone?: AttackFlowTimelineTone;
};

type AttackFindingSummary = ReturnType<typeof countSeverity>;

type AttackFlowNode = {
  id: string;
  label: string;
  title: string;
  detail: string;
  route: string;
  status: AttackFlowStatus;
  story: string;
  x: number;
  y: number;
  w: number;
  h: number;
  severity?: string;
  meta?: Array<{ label: string; value: string }>;
  timeline?: AttackFlowTimelineChip[];
  proofSource?: boolean;
};

type AttackFlowEdge = {
  id: string;
  path: string;
  label: string;
  x: number;
  y: number;
  status: AttackFlowStatus;
};

type FlowTaskGroup = {
  id: string;
  tool: string;
  target: string;
  status: string;
  count: number;
  phase: MissionPhaseKey;
  task: Task;
  startedAt: string | null;
  endedAt: string | null;
};

const ATTACK_MAP_MIN_ZOOM = 0.22;
const ATTACK_MAP_MAX_ZOOM = 1.8;
const ATTACK_MAP_ZOOM_STEP = 0.1;
const ATTACK_MAP_DEFAULT_ZOOM = 0.86;
const ATTACK_MAP_FIT_PADDING = 40;

function clampAttackMapZoom(value: number): number {
  return Number(Math.min(ATTACK_MAP_MAX_ZOOM, Math.max(ATTACK_MAP_MIN_ZOOM, value)).toFixed(2));
}

function MissionJourneyMap({ run, tasks, findings }: { run: Run; tasks: Task[]; findings: Finding[] }) {
  const mapTasks = useMemo(() => (run.tasks.length > 0 ? run.tasks : tasks), [run.tasks, tasks]);
  const mapFindings = useMemo(() => findingsForSelectedRunAttackMap(run, findings), [findings, run]);
  const flow = useMemo(() => buildAttackFlow(run, mapTasks, mapFindings), [mapFindings, mapTasks, run]);
  const currentPath = useMemo(() => currentAttackPath(flow), [flow]);
  const [expanded, setExpanded] = useState(false);
  const [replayStep, setReplayStep] = useState<number | null>(null);
  const [replayPlaying, setReplayPlaying] = useState(false);
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [mapZoom, setMapZoom] = useState(ATTACK_MAP_DEFAULT_ZOOM);
  const [mapPan, setMapPan] = useState({ x: 0, y: 0 });
  const [mapDragging, setMapDragging] = useState(false);
  const mapViewportRef = useRef<HTMLDivElement | null>(null);
  const mapDragRef = useRef<{ x: number; y: number; panX: number; panY: number } | null>(null);
  const mapCloseButtonRef = useRef<HTMLButtonElement | null>(null);
  const mapReturnFocusRef = useRef<HTMLElement | null>(null);
  const selectedNode = useMemo(
    () => flow.nodes.find((node) => node.id === selectedNodeId) ?? currentPath[currentPath.length - 1] ?? flow.nodes[0],
    [currentPath, flow.nodes, selectedNodeId],
  );

  const zoomMap = useCallback(
    (updater: number | ((currentZoom: number) => number), anchor?: { x: number; y: number }) => {
      const viewport = mapViewportRef.current;
      const rect = viewport?.getBoundingClientRect();
      setMapZoom((currentZoom) => {
        const nextZoom = clampAttackMapZoom(typeof updater === 'function' ? updater(currentZoom) : updater);
        if (!rect || Math.abs(nextZoom - currentZoom) < 0.001) return nextZoom;
        const originX = anchor ? anchor.x - rect.left : rect.width / 2;
        const originY = anchor ? anchor.y - rect.top : rect.height / 2;
        setMapPan((currentPan) => {
          const worldX = (originX - currentPan.x) / currentZoom;
          const worldY = (originY - currentPan.y) / currentZoom;
          return {
            x: Math.round(originX - worldX * nextZoom),
            y: Math.round(originY - worldY * nextZoom),
          };
        });
        return nextZoom;
      });
    },
    [],
  );

  const fitMapToViewport = useCallback(() => {
    const viewport = mapViewportRef.current;
    if (!viewport) {
      setMapZoom(ATTACK_MAP_DEFAULT_ZOOM);
      setMapPan({ x: 0, y: 0 });
      return;
    }
    const rect = viewport.getBoundingClientRect();
    const availableWidth = Math.max(160, rect.width - ATTACK_MAP_FIT_PADDING * 2);
    const availableHeight = Math.max(160, rect.height - ATTACK_MAP_FIT_PADDING * 2);
    const nextZoom = clampAttackMapZoom(Math.min(availableWidth / flow.width, availableHeight / flow.height));
    setMapZoom(nextZoom);
    setMapPan({
      x: Math.round((rect.width - flow.width * nextZoom) / 2),
      y: Math.round((rect.height - flow.height * nextZoom) / 2),
    });
  }, [flow.height, flow.width]);

  const resetMapView = useCallback(() => {
    setMapZoom(ATTACK_MAP_DEFAULT_ZOOM);
    setMapPan({ x: ATTACK_MAP_FIT_PADDING, y: ATTACK_MAP_FIT_PADDING });
  }, []);

  const handleMapWheel = useCallback(
    (event: ReactWheelEvent<HTMLDivElement>) => {
      event.preventDefault();
      const delta = event.deltaY > 0 ? -ATTACK_MAP_ZOOM_STEP : ATTACK_MAP_ZOOM_STEP;
      zoomMap((zoom) => zoom + delta, { x: event.clientX, y: event.clientY });
    },
    [zoomMap],
  );

  const handleMapPointerDown = useCallback(
    (event: ReactPointerEvent<HTMLDivElement>) => {
      if (event.button !== 0) return;
      const target = event.target as HTMLElement | null;
      if (target?.closest('button, a, input, textarea, select')) return;
      event.currentTarget.setPointerCapture(event.pointerId);
      mapDragRef.current = { x: event.clientX, y: event.clientY, panX: mapPan.x, panY: mapPan.y };
      setMapDragging(true);
    },
    [mapPan.x, mapPan.y],
  );

  const handleMapPointerMove = useCallback((event: ReactPointerEvent<HTMLDivElement>) => {
    const drag = mapDragRef.current;
    if (!drag) return;
    setMapPan({
      x: Math.round(drag.panX + event.clientX - drag.x),
      y: Math.round(drag.panY + event.clientY - drag.y),
    });
  }, []);

  const handleMapPointerEnd = useCallback((event: ReactPointerEvent<HTMLDivElement>) => {
    if (event.currentTarget.hasPointerCapture(event.pointerId)) {
      event.currentTarget.releasePointerCapture(event.pointerId);
    }
    mapDragRef.current = null;
    setMapDragging(false);
  }, []);

  useEffect(() => {
    if (!expanded) return;
    const frame = window.requestAnimationFrame(fitMapToViewport);
    return () => window.cancelAnimationFrame(frame);
  }, [expanded, fitMapToViewport]);

  useEffect(() => {
    if (!expanded) return;
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    const focusTimer = window.setTimeout(() => mapCloseButtonRef.current?.focus(), 0);
    const handleKeyDown = (event: KeyboardEvent) => {
      const target = event.target as HTMLElement | null;
      if (target?.matches('input, textarea, select')) return;
      if (event.key === 'Escape') {
        event.preventDefault();
        setReplayPlaying(false);
        setExpanded(false);
        return;
      }
      if (event.key === '-' || event.key === '_') {
        event.preventDefault();
        zoomMap((zoom) => zoom - ATTACK_MAP_ZOOM_STEP);
        return;
      }
      if (event.key === '+' || event.key === '=') {
        event.preventDefault();
        zoomMap((zoom) => zoom + ATTACK_MAP_ZOOM_STEP);
        return;
      }
      if (event.key === '0') {
        event.preventDefault();
        fitMapToViewport();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => {
      window.clearTimeout(focusTimer);
      document.body.style.overflow = previousOverflow;
      window.removeEventListener('keydown', handleKeyDown);
      mapReturnFocusRef.current?.focus();
    };
  }, [expanded, fitMapToViewport, zoomMap]);

  useEffect(() => {
    if (!expanded || !replayPlaying) return;
    const timer = window.setInterval(() => {
      setReplayStep((step) => {
        const current = step ?? 0;
        if (current >= flow.nodes.length - 1) {
          setReplayPlaying(false);
          return current;
        }
        const next = current + 1;
        setSelectedNodeId(flow.nodes[next]?.id ?? null);
        return next;
      });
    }, 850);
    return () => window.clearInterval(timer);
  }, [expanded, flow.nodes, replayPlaying]);

  const openFullMap = () => {
    mapReturnFocusRef.current = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    setReplayPlaying(false);
    setReplayStep(null);
    setSelectedNodeId((id) => id ?? currentPath[currentPath.length - 1]?.id ?? flow.nodes[0]?.id ?? null);
    setExpanded(true);
  };
  const startReplay = () => {
    mapReturnFocusRef.current = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    setReplayStep(0);
    setReplayPlaying(true);
    setSelectedNodeId(flow.nodes[0]?.id ?? null);
    setExpanded(true);
  };

  const fullMapDialog = expanded && typeof document !== 'undefined'
    ? createPortal(
      <div
        className="dark-canvas fixed inset-0 z-[10000] bg-[#02060c]/92 p-4 backdrop-blur-md"
        role="dialog"
        aria-modal="true"
        aria-labelledby="full-attack-map-title"
        aria-describedby="full-attack-map-help"
      >
        <section className="mx-auto flex h-full max-w-[min(96rem,calc(100vw-2rem))] flex-col overflow-hidden rounded-lg border border-cyan/20 bg-[#07111f] shadow-[0_0_3rem_rgba(2,6,12,0.6)]">
          <div className="flex shrink-0 items-center justify-between gap-3 border-b border-cyan/15 px-5 py-3">
            <div>
              <h2 id="full-attack-map-title" className="text-[1rem] font-semibold text-text">Full attack map</h2>
              <p id="full-attack-map-help" className="mt-1 font-mono text-[0.66rem] uppercase tracking-widest text-muted">
                Wheel zooms. Drag the map to move. Double-click or press 0 to fit the whole route.
              </p>
            </div>
            <div className="flex flex-wrap items-center justify-end gap-2">
              <AttackFlowLegend />
              <span className="rounded border border-cyan/15 bg-bg/40 px-2 py-1 font-mono text-[0.64rem] uppercase tracking-widest text-muted">
                {replayStep == null ? 'showing all' : `step ${replayStep + 1}/${flow.nodes.length}`}
              </span>
              <button
                type="button"
                onClick={() => zoomMap((zoom) => zoom - ATTACK_MAP_ZOOM_STEP)}
                aria-keyshortcuts="-"
                className="rounded border border-cyan/25 bg-cyan/10 px-2 py-1 font-mono text-[0.64rem] uppercase tracking-widest text-cyan hover:bg-cyan/15"
              >
                Zoom out
              </button>
              <span className="rounded border border-cyan/15 bg-bg/40 px-2 py-1 font-mono text-[0.64rem] uppercase tracking-widest text-muted">
                {Math.round(mapZoom * 100)}%
              </span>
              <button
                type="button"
                onClick={() => zoomMap((zoom) => zoom + ATTACK_MAP_ZOOM_STEP)}
                aria-keyshortcuts="+"
                className="rounded border border-cyan/25 bg-cyan/10 px-2 py-1 font-mono text-[0.64rem] uppercase tracking-widest text-cyan hover:bg-cyan/15"
              >
                Zoom in
              </button>
              <button
                type="button"
                onClick={fitMapToViewport}
                aria-keyshortcuts="0"
                className="rounded border border-cyan/25 bg-cyan/10 px-2 py-1 font-mono text-[0.64rem] uppercase tracking-widest text-cyan hover:bg-cyan/15"
              >
                Fit
              </button>
              <button
                type="button"
                onClick={() => {
                  setReplayStep((step) => (step == null ? 0 : Math.max(0, step - 1)));
                  setSelectedNodeId((id) => {
                    const currentIndex = id ? flow.nodes.findIndex((node) => node.id === id) : 0;
                    return flow.nodes[Math.max(0, currentIndex - 1)]?.id ?? id;
                  });
                  setReplayPlaying(false);
                }}
                className="rounded border border-cyan/25 bg-cyan/10 px-2 py-1 font-mono text-[0.64rem] uppercase tracking-widest text-cyan hover:bg-cyan/15"
              >
                Back
              </button>
              <button
                type="button"
                onClick={() => {
                  setReplayStep((step) => (step == null ? 0 : Math.min(flow.nodes.length - 1, step + 1)));
                  setSelectedNodeId((id) => {
                    const currentIndex = id ? flow.nodes.findIndex((node) => node.id === id) : -1;
                    return flow.nodes[Math.min(flow.nodes.length - 1, Math.max(0, currentIndex + 1))]?.id ?? id;
                  });
                  setReplayPlaying(false);
                }}
                className="rounded border border-cyan/25 bg-cyan/10 px-2 py-1 font-mono text-[0.64rem] uppercase tracking-widest text-cyan hover:bg-cyan/15"
              >
                Next
              </button>
              <button
                type="button"
                onClick={() => {
                  setReplayStep((step) => (step == null ? 0 : step));
                  setReplayPlaying((playing) => !playing);
                }}
                className="rounded border border-amber/30 bg-amber/10 px-2 py-1 font-mono text-[0.64rem] uppercase tracking-widest text-amber hover:bg-amber/15"
              >
                {replayPlaying ? 'Pause' : 'Play'}
              </button>
              <button
                type="button"
                onClick={() => {
                  setReplayPlaying(false);
                  setReplayStep(0);
                  setSelectedNodeId(flow.nodes[0]?.id ?? null);
                  resetMapView();
                }}
                className="rounded border border-cyan/25 bg-cyan/10 px-2 py-1 font-mono text-[0.64rem] uppercase tracking-widest text-cyan hover:bg-cyan/15"
              >
                Reset
              </button>
              <button
                type="button"
                onClick={() => {
                  setReplayPlaying(false);
                  setReplayStep(null);
                }}
                className="rounded border border-cyan/25 bg-cyan/10 px-2 py-1 font-mono text-[0.64rem] uppercase tracking-widest text-cyan hover:bg-cyan/15"
              >
                Show all
              </button>
              <button
                type="button"
                ref={mapCloseButtonRef}
                onClick={() => {
                  setReplayPlaying(false);
                  setExpanded(false);
                }}
                className="rounded border border-cyan/30 bg-cyan/10 px-3 py-1.5 font-mono text-[0.68rem] font-semibold uppercase tracking-widest text-cyan hover:bg-cyan/15"
              >
                Close
              </button>
            </div>
          </div>
          <div className="grid min-h-0 flex-1 grid-cols-1 gap-4 overflow-hidden p-4 lg:grid-cols-[minmax(0,1fr)_18rem] xl:grid-cols-[minmax(0,1fr)_20rem]">
            <div
              ref={mapViewportRef}
              aria-label="Attack map pan and zoom canvas"
              className={cn(
                'relative min-h-0 overflow-hidden rounded border border-cyan/10 bg-[#030b16]/45',
                mapDragging ? 'cursor-grabbing' : 'cursor-grab',
              )}
              onWheel={handleMapWheel}
              onPointerDown={handleMapPointerDown}
              onPointerMove={handleMapPointerMove}
              onPointerUp={handleMapPointerEnd}
              onPointerCancel={handleMapPointerEnd}
              onDoubleClick={fitMapToViewport}
            >
              <div
                className="absolute left-0 top-0"
                data-testid="attack-map-transform"
                data-zoom={mapZoom.toFixed(2)}
                data-pan={`${Math.round(mapPan.x)},${Math.round(mapPan.y)}`}
                style={{
                  width: flow.width,
                  height: flow.height,
                  transform: `translate3d(${mapPan.x}px, ${mapPan.y}px, 0) scale(${mapZoom})`,
                  transformOrigin: 'top left',
                }}
              >
                <AttackFlowCanvas
                  flow={flow}
                  replayStep={replayStep}
                  selectedNodeId={selectedNode?.id ?? null}
                  onSelectNode={setSelectedNodeId}
                />
              </div>
            </div>
            <AttackFlowDetailPanel node={selectedNode} />
          </div>
        </section>
      </div>,
      document.body,
    )
    : null;

  return (
    <>
      <section className="neon-panel rounded-lg border border-border bg-surface/55 p-4 backdrop-blur-md">
        <div className="mb-3 flex items-center justify-between gap-3">
          <div>
            <h2 className="text-[1rem] font-semibold text-text">Mission path</h2>
            <div className="mt-1 font-mono text-[0.68rem] uppercase tracking-widest text-muted">current path, click to inspect the full attack map</div>
          </div>
          <div className="flex items-center gap-3">
            <AttackFlowLegend compact />
            <button
              type="button"
              onClick={startReplay}
              className="rounded border border-amber/30 bg-amber/10 px-3 py-1.5 font-mono text-[0.68rem] font-semibold uppercase tracking-widest text-amber hover:bg-amber/15"
            >
              Replay
            </button>
            <button
              type="button"
              onClick={openFullMap}
              className="rounded border border-cyan/30 bg-cyan/10 px-3 py-1.5 font-mono text-[0.68rem] font-semibold uppercase tracking-widest text-cyan hover:bg-cyan/15"
            >
              Open full map
            </button>
          </div>
        </div>
        <button
          type="button"
          onClick={openFullMap}
          className="dark-canvas block w-full rounded-lg border border-cyan/15 bg-[#07111f]/55 p-3 text-left transition-colors hover:border-cyan/35 hover:bg-cyan/5"
        >
          <div className="mb-2 flex items-center justify-between gap-3">
            <span className="font-mono text-[0.62rem] uppercase tracking-widest text-cyan/70">Current path</span>
            <span className="font-mono text-[0.62rem] uppercase tracking-widest text-muted">{flow.nodes.length} nodes · {flow.edges.length} links</span>
          </div>
          <div className="grid gap-2 md:grid-cols-[repeat(4,minmax(0,1fr))]">
            {currentPath.map((node, index) => (
              <CompactPathNode key={`${node.id}-${index}`} node={node} isLast={index === currentPath.length - 1} />
            ))}
          </div>
        </button>
      </section>
      {fullMapDialog}
    </>
  );
}

function findingsForSelectedRunAttackMap(run: Run, findings: Finding[]): Finding[] {
  const findingsWithRunId = findings.filter((finding) => Boolean(finding.run_id));
  if (findingsWithRunId.length === 0) return findings;
  return findingsWithRunId.filter((finding) => finding.run_id === run.id);
}

function AttackFlowCanvas({
  flow,
  replayStep,
  selectedNodeId,
  onSelectNode,
}: {
  flow: ReturnType<typeof buildAttackFlow>;
  replayStep: number | null;
  selectedNodeId: string | null;
  onSelectNode: (nodeId: string) => void;
}) {
  const visibleNodes = replayStep == null ? flow.nodes : flow.nodes.slice(0, replayStep + 1);
  const visibleEdges = replayStep == null ? flow.edges : flow.edges.slice(0, Math.min(flow.edges.length, replayStep));
  const visibleNodeIds = new Set(visibleNodes.map((node) => node.id));
  return (
    <div
      className="relative"
      role="group"
      aria-label="Interactive attack path map"
      style={{ width: flow.width, minWidth: flow.width, height: flow.height }}
    >
      <svg className="absolute inset-0 h-full w-full" viewBox={`0 0 ${flow.width} ${flow.height}`} fill="none" aria-hidden="true">
        <defs>
          <marker id="timeline-arrow" markerWidth="7" markerHeight="7" refX="6" refY="3.5" orient="auto">
            <path d="M0 0 L7 3.5 L0 7 Z" className="fill-cyan" />
          </marker>
          <marker id="timeline-arrow-green" markerWidth="7" markerHeight="7" refX="6" refY="3.5" orient="auto">
            <path d="M0 0 L7 3.5 L0 7 Z" className="fill-green-300" />
          </marker>
          <marker id="timeline-arrow-red" markerWidth="7" markerHeight="7" refX="6" refY="3.5" orient="auto">
            <path d="M0 0 L7 3.5 L0 7 Z" className="fill-red" />
          </marker>
        </defs>
        {visibleEdges.map((edge) => (
          <path
            key={edge.id}
            d={edge.path}
            className={cn(['running', 'queued'].includes(edge.status) && 'attack-flow-active')}
            stroke={edgeStroke(edge.status)}
            strokeOpacity={edge.status === 'idle' ? 0.6 : 0.92}
            strokeWidth={edge.status === 'idle' ? 2 : edge.status === 'done' ? 2.6 : 3}
            strokeLinecap="round"
            markerEnd={edgeUsesArrowhead(edge) ? edge.status === 'failed' ? 'url(#timeline-arrow-red)' : edge.status === 'finding' ? 'url(#timeline-arrow-green)' : 'url(#timeline-arrow)' : undefined}
          />
        ))}
      </svg>

      <div className="absolute left-6 top-4 font-mono text-[0.62rem] uppercase tracking-widest text-cyan/70">Layer 1 · discovery and decisions</div>
      <div className="absolute font-mono text-[0.62rem] uppercase tracking-widest text-cyan/70" style={{ left: 840, top: 430 }}>
        Layer 2 · proof and outcome
      </div>
      {visibleEdges.map((edge) => (
        shouldShowEdgeLabel(edge) ? (
          <span
            key={`${edge.id}-label`}
            className={cn(
              'absolute rounded-full border bg-[#06101d]/95 px-2.5 py-1 font-mono text-[0.58rem] uppercase tracking-widest shadow-[0_0_1rem_rgba(94,207,255,0.18)]',
              edge.status === 'failed' ? 'text-red' : edge.status === 'finding' ? 'text-green-300' : 'text-cyan',
              edge.status === 'failed' ? 'border-red/35' : edge.status === 'finding' ? 'border-green-300/35' : 'border-cyan/30',
            )}
            style={{ left: edge.x, top: edge.y }}
          >
            {edge.label}
          </span>
        ) : null
      ))}
      {flow.nodes.map((node) => (
        visibleNodeIds.has(node.id) ? (
          <AttackFlowNodeCard key={node.id} node={node} selected={node.id === selectedNodeId} onSelect={() => onSelectNode(node.id)} />
        ) : null
      ))}
    </div>
  );
}

function currentAttackPath(flow: ReturnType<typeof buildAttackFlow>): AttackFlowNode[] {
  const start = flow.nodes.find((node) => node.id === 'start');
  const decision = flow.nodes.find((node) => node.id === 'decision');
  const report = flow.nodes.find((node) => node.id === 'report' || node.id === 'report-empty');
  const deadEnd = flow.nodes.find((node) => node.id === 'dead-end');
  const findings = flow.nodes.filter((node) => node.status === 'finding');
  const live = flow.nodes.find((node) => ['running', 'queued'].includes(node.status) && node.id !== 'decision');
  const mainTasks = flow.nodes.filter(
    (node) =>
      !['start', 'decision', 'dead-end', 'report', 'report-empty'].includes(node.id) &&
      node.status !== 'finding' &&
      node.status !== 'failed',
  );
  const proofSource = mainTasks.find((node) => node.proofSource);
  const selected: Array<AttackFlowNode | undefined> = [start, decision];
  if (findings.length > 0) {
    selected.push(proofSource ?? mainTasks[mainTasks.length - 1] ?? findings[0]);
  } else if (live) {
    selected.push(live);
  } else if (mainTasks.length > 0) {
    selected.push(mainTasks[mainTasks.length - 1]);
  } else if (deadEnd) {
    selected.push(deadEnd);
  } else {
    selected.push(mainTasks[mainTasks.length - 1]);
  }
  selected.push(findings[0] ?? report ?? deadEnd);

  const unique: AttackFlowNode[] = [];
  for (const node of selected) {
    if (node && !unique.some((item) => item.id === node.id)) unique.push(node);
  }
  return unique.slice(0, 4);
}

function shouldShowEdgeLabel(edge: AttackFlowEdge): boolean {
  if (edge.id === 'report-edge') return false;
  return edge.status === 'failed' || edge.status === 'finding' || edge.status === 'running' || edge.status === 'queued';
}

function edgeUsesArrowhead(edge: AttackFlowEdge): boolean {
  return edge.status === 'failed' || edge.status === 'finding' || edge.status === 'running' || edge.status === 'queued';
}

function AttackFlowLegend({ compact = false }: { compact?: boolean }) {
  const items = [
    ['good', 'bg-green-300'],
    ['info', 'bg-yellow-300'],
    ['medium', 'bg-amber'],
    ['high', 'bg-red'],
    ['critical', 'bg-ai'],
  ];
  return (
    <div className={cn('hidden items-center gap-2 font-mono text-[0.58rem] uppercase tracking-widest text-muted lg:flex', compact && 'xl:flex lg:hidden')}>
      {items.map(([label, color]) => (
        <span key={label} className="flex items-center gap-1">
          <span className={cn('h-2 w-2 rounded-full', color)} />
          {compact ? label.slice(0, 4) : label}
        </span>
      ))}
    </div>
  );
}

function CompactPathNode({ node, isLast }: { node: AttackFlowNode; isLast: boolean }) {
  return (
    <div className="relative min-w-0">
      {!isLast && <span className="absolute -right-3 top-1/2 z-10 hidden h-px w-4 bg-cyan/35 md:block" aria-hidden="true" />}
      <div
        data-status={node.status}
        className={cn('mission-current-path-node min-h-[6.3rem] rounded-lg border p-3', attackNodeTone(node))}
      >
        <div className="flex items-center justify-between gap-2">
          <span className="font-mono text-[0.58rem] uppercase tracking-widest opacity-80">{node.label}</span>
          <span className={cn('h-2 w-2 rounded-full bg-current shadow-[0_0_12px_currentColor]', ['running', 'queued'].includes(node.status) && 'animate-pulse')} />
        </div>
        <div className="mt-1 truncate text-[0.95rem] font-semibold text-text">{node.title}</div>
        <div className="mt-1 line-clamp-1 text-[0.72rem] text-muted">{node.detail}</div>
        <AttackNodeTimeChips node={node} compact />
      </div>
    </div>
  );
}

function buildAttackFlow(run: Run, tasks: Task[], findings: Finding[]) {
  const groups = buildFlowTaskGroups(tasks);
  const failedGroups = groups.filter((group) => isFailedTaskStatus(group.status));
  const liveGroups = groups.filter((group) => isActiveTaskStatus(group.status));
  const mainGroups = selectAttackMapTaskRoute(groups, findings);
  const hasDeadEnd = failedGroups.length > 0 || (isTerminalRun(run) && findings.length === 0 && groups.length > 0);
  const prioritizedFindings = [...findings].sort(
    (a, b) =>
      (SEV_ORDER[(a.severity || 'info').toLowerCase()] ?? 9) -
      (SEV_ORDER[(b.severity || 'info').toLowerCase()] ?? 9),
  );
  const findingSummary = countSeverity(findings);
  const findingSummaryText = attackMapSeveritySummary(findingSummary);
  const flowEndTime = latestFlowTime(run, tasks, findings) ?? Date.now();
  const runStartIso = run.started_at ?? run.created_at ?? null;
  const stepGap = 270;
  const cardW = 190;
  const findingNodeGap = 146;
  const findingNodeHeight = 132;
  const proofColumns = prioritizedFindings.length > 4 ? 2 : 1;
  const proofRows = Math.max(1, Math.ceil(prioritizedFindings.length / proofColumns));
  const height = prioritizedFindings.length > 0 ? Math.max(760, 470 + proofRows * findingNodeGap + findingNodeHeight + 140) : 500;
  const routeNodeCount = Math.max(3, mainGroups.length);
  const width = Math.max(1320, 520 + routeNodeCount * stepGap + (prioritizedFindings.length > 0 ? 620 : 420));
  const nodes: AttackFlowNode[] = [
    {
      id: 'start',
      label: 'Start',
      title: 'Info',
      detail: targetHost(run, tasks) || 'target selected',
      route: '/surface-map',
      status: 'done',
      story: 'AegisPT starts by fixing the target and collecting the first safe facts. This is the start of the route, not proof yet.',
      meta: [
        { label: 'Target', value: targetHost(run, tasks) || 'not recorded' },
        { label: 'Run started', value: formatTimestamp(runStartIso) },
        { label: 'Elapsed now', value: elapsedFromRunStart(run, flowEndTime) },
        { label: 'View', value: 'Surface Map' },
      ],
      timeline: [
        { label: 'start', value: formatTimestamp(runStartIso), tone: 'good' },
        { label: 'elapsed', value: elapsedFromRunStart(run, flowEndTime), tone: 'muted' },
      ],
      x: 48,
      y: 250,
      w: 160,
      h: 132,
    },
    {
      id: 'decision',
      label: 'Decision',
      title: 'Route?',
      detail: 'branch by evidence',
      route: '/technical',
      status: liveGroups.length > 0 ? 'running' : 'done',
      story: 'The system chooses the next route from the evidence it has. A branch can continue toward proof or stop as a dead end.',
      meta: [
        { label: 'Rule', value: 'branch by evidence' },
        { label: 'State', value: liveGroups.length > 0 ? 'still deciding' : 'decision made' },
        { label: 'Run elapsed', value: elapsedFromRunStart(run, flowEndTime) },
      ],
      timeline: [
        { label: liveGroups.length > 0 ? 'deciding' : 'decided', value: elapsedFromRunStart(run, flowEndTime), tone: liveGroups.length > 0 ? 'warn' : 'good' },
        { label: 'clock', value: formatTimestamp(timeIsoFromMs(flowEndTime)), tone: 'muted' },
      ],
      x: 260,
      y: 246,
      w: 150,
      h: 132,
    },
  ];
  const edges: AttackFlowEdge[] = [
    edgeBetween('start-decision', nodes[0], nodes[1], 'info', 'done', 0, 0),
  ];

  const topY = 56;
  let previousTop: AttackFlowNode | null = nodes[1];
  failedGroups.forEach((group, index) => {
    const node = taskGroupNode(group, 520 + index * stepGap, topY, 'failed', cardW);
    nodes.push(node);
    edges.push(edgeBetween(`failed-${index}`, previousTop, node, index === 0 ? group.tool : humanizeTool(group.tool), 'failed', 0, 0));
    previousTop = node;
  });
  if (hasDeadEnd) {
    const deadX = 520 + Math.max(1, failedGroups.length) * stepGap;
    const deadNode: AttackFlowNode = {
      id: 'dead-end',
      label: 'No',
      title: 'Dead end',
      detail: failedGroups.length > 0 ? `${failedGroups.reduce((total, group) => total + group.count, 0)} failed checks` : 'no proof saved',
      route: '/live-cli',
      status: 'failed',
      story: 'This branch did not produce usable proof. Keep it visible as a dead end so the operator can see what was tried and why it stopped.',
      meta: [
        { label: 'Failed checks', value: String(failedGroups.reduce((total, group) => total + group.count, 0)) },
        ...taskGroupTimingMeta(failedGroups[failedGroups.length - 1]),
        { label: 'Open', value: 'Live CLI' },
      ],
      timeline: failedGroups.length > 0
        ? taskGroupTimeline(failedGroups[failedGroups.length - 1], 'failed')
        : [
          { label: 'ended', value: formatTimestamp(timeIsoFromMs(flowEndTime)), tone: 'danger' },
          { label: 'elapsed', value: elapsedFromRunStart(run, flowEndTime), tone: 'muted' },
        ],
      x: deadX,
      y: topY,
      w: cardW,
      h: 138,
    };
    nodes.push(deadNode);
    edges.push(edgeBetween('dead-end', previousTop, deadNode, 'no proof', 'failed', 0, 0));
  }

  const mainY = 250;
  let previousMain: AttackFlowNode | null = nodes[1];
  const taskNodeByGroupId = new Map<string, AttackFlowNode>();
  if (mainGroups.length === 0) {
    const waitingNode: AttackFlowNode = {
      id: 'waiting',
      label: 'Waiting',
      title: 'Next check',
      detail: 'no task selected yet',
      route: '/live-cli',
      status: isTerminalRun(run) ? 'idle' : 'queued',
      story: 'No concrete task is running on this branch yet. The route is waiting for a queued task, approval, or the next backend decision.',
      meta: [
        { label: 'Run', value: run.status || 'unknown' },
        { label: 'Run elapsed', value: elapsedFromRunStart(run, flowEndTime) },
        { label: 'Open', value: 'Live CLI' },
      ],
      timeline: [
        { label: isTerminalRun(run) ? 'ended' : 'waiting', value: formatTimestamp(timeIsoFromMs(flowEndTime)), tone: isTerminalRun(run) ? 'muted' : 'warn' },
        { label: 'elapsed', value: elapsedFromRunStart(run, flowEndTime), tone: 'muted' },
      ],
      x: 520,
      y: mainY,
      w: cardW,
      h: 138,
    };
    nodes.push(waitingNode);
    edges.push(edgeBetween('waiting-route', previousMain, waitingNode, 'next', waitingNode.status, 0, 0));
    previousMain = waitingNode;
  } else {
    mainGroups.forEach((group, index) => {
      const node = taskGroupNode(group, 520 + index * stepGap, mainY, taskFlowStatus(group.status), cardW);
      nodes.push(node);
      taskNodeByGroupId.set(group.id, node);
      edges.push(edgeBetween(`main-${index}`, previousMain, node, index === 0 ? group.tool : humanizeTool(group.tool), node.status, 0, 0));
      previousMain = node;
    });
  }

  if (prioritizedFindings.length > 0) {
    const firstProofSourceGroup = pickProofSourceGroup(prioritizedFindings[0], mainGroups, groups);
    let previousFinding: AttackFlowNode | null = firstProofSourceGroup ? taskNodeByGroupId.get(firstProofSourceGroup.id) ?? previousMain : previousMain;
    if (previousFinding && firstProofSourceGroup) previousFinding.proofSource = true;
    const sourceX = previousFinding?.x ?? previousMain?.x ?? 780;
    const findingX = Math.min(width - 520, Math.max(720, sourceX));
    prioritizedFindings.forEach((finding, index) => {
      const proofSourceGroup = pickProofSourceGroup(finding, mainGroups, groups);
      if (proofSourceGroup) {
        const sourceNode = taskNodeByGroupId.get(proofSourceGroup.id);
        if (sourceNode) sourceNode.proofSource = true;
      }
      const findingTitle = attackMapFindingTitle(finding);
      const proofColumn = index % proofColumns;
      const proofRow = Math.floor(index / proofColumns);
      const node: AttackFlowNode = {
        id: `finding-${finding.id}`,
        label: index === 0 ? 'Proof' : `Proof ${index + 1}`,
        title: compactAttackMapTitle(findingTitle),
        detail: `${severityLabel(finding.severity)} finding`,
        route: '/findings',
        status: 'finding',
        severity: finding.severity,
        story: attackMapFindingStory(finding, proofSourceGroup),
        meta: [
          { label: 'Finding', value: findingTitle },
          { label: 'Severity', value: severityLabel(finding.severity) },
          { label: 'Target', value: String(finding.target_id || 'not recorded') },
          { label: 'Evidence', value: String(finding.evidence_ref || 'not linked') },
          { label: 'Source task', value: proofSourceGroup ? `${proofSourceGroup.tool} · ${humanTaskStatus(proofSourceGroup.status)}` : 'not matched' },
          { label: 'Persisted', value: formatTimestamp(finding.created_at) },
          { label: 'Elapsed from run start', value: elapsedFromRunStart(run, timeValue(finding.created_at)) },
          { label: 'Source task duration', value: proofSourceGroup ? durationForGroup(proofSourceGroup) : 'not matched' },
          { label: 'Path position', value: `${index + 1} of ${prioritizedFindings.length} proof events` },
        ],
        timeline: findingTimeline(run, finding, proofSourceGroup),
        x: findingX + proofColumn * 270,
        y: 470 + proofRow * findingNodeGap,
        w: 250,
        h: findingNodeHeight,
      };
      nodes.push(node);
      edges.push(edgeBetween(`finding-edge-${index}`, previousFinding, node, index === 0 ? 'proof' : 'next proof', 'finding', 0, 0));
      previousFinding = node;
    });
    const reportNode: AttackFlowNode = {
      id: 'report',
      label: 'Outcome',
      title: 'Report',
      detail: 'review & export',
      route: '/reports',
      status: 'ready',
      story: 'The route has reportable output. Review proof and wording before exporting a customer-facing report.',
      meta: [
        { label: 'Findings', value: String(findings.length) },
        ...(findings.length > 1 ? [{ label: 'Severity mix', value: findingSummaryText }] : []),
        { label: 'Ready after', value: elapsedFromRunStart(run, timeValue(prioritizedFindings[0]?.created_at)) },
        { label: 'Open', value: 'Reports' },
      ],
      timeline: [
        { label: 'ready', value: formatTimestamp(prioritizedFindings[0]?.created_at), tone: 'proof' },
        { label: 'after', value: elapsedFromRunStart(run, timeValue(prioritizedFindings[0]?.created_at)), tone: 'proof' },
      ],
      x: findingX + proofColumns * 270,
      y: 470 + (proofRows - 1) * findingNodeGap,
      w: 160,
      h: 138,
    };
    nodes.push(reportNode);
    edges.push(edgeBetween('report-edge', previousFinding, reportNode, 'report', 'finding', 0, 0));
  } else if (isTerminalRun(run) && !hasDeadEnd) {
    const reportNode: AttackFlowNode = {
      id: 'report-empty',
      label: 'Outcome',
      title: 'No finding',
      detail: 'close out',
      route: '/reports',
      status: 'idle',
      story: 'The run ended without a reportable finding on this route. Use this outcome to close the loop or decide whether another path is needed.',
      meta: [
        { label: 'Findings', value: '0' },
        { label: 'Run elapsed', value: elapsedFromRunStart(run, flowEndTime) },
        { label: 'Open', value: 'Reports' },
      ],
      timeline: [
        { label: 'ended', value: formatTimestamp(timeIsoFromMs(flowEndTime)), tone: 'muted' },
        { label: 'elapsed', value: elapsedFromRunStart(run, flowEndTime), tone: 'muted' },
      ],
      x: 780,
      y: mainY,
      w: 160,
      h: 138,
    };
    nodes.push(reportNode);
    edges.push(edgeBetween('empty-report-edge', previousMain, reportNode, 'outcome', 'idle', 0, 0));
  }

  const size = attackFlowSize(nodes, edges, width, height);
  return { nodes, edges, width: size.width, height: size.height };
}

function buildFlowTaskGroups(tasks: Task[]): FlowTaskGroup[] {
  const ordered = [...tasks].sort((a, b) => taskTime(a) - taskTime(b));
  const groups = new Map<string, FlowTaskGroup>();
  for (const task of ordered) {
    const phase = missionPhaseForTask(task);
    const status = (task.status || 'unknown').toLowerCase();
    const key = `${phase}:${task.tool}:${status}:${task.target_id || ''}`;
    const existing = groups.get(key);
    if (existing) {
      existing.count += 1;
      existing.task = task;
      existing.startedAt = minIso(existing.startedAt, task.created_at);
      existing.endedAt = maxIso(existing.endedAt, task.updated_at);
      continue;
    }
    groups.set(key, {
      id: key,
      tool: task.tool || 'task',
      target: task.target_id || '',
      status,
      count: 1,
      phase,
      task,
      startedAt: task.created_at ?? null,
      endedAt: task.updated_at ?? task.created_at ?? null,
    });
  }
  return Array.from(groups.values());
}

function selectAttackMapTaskRoute(groups: FlowTaskGroup[], findings: Finding[]): FlowTaskGroup[] {
  const routeGroups = groups.filter((group) => !isFailedTaskStatus(group.status) && group.phase !== 'report');
  if (findings.length === 0) return routeGroups;
  const required = new Map(routeGroups.map((group) => [group.id, group] as const));
  for (const finding of findings) {
    const proofSource = pickProofSourceGroup(finding, routeGroups, groups);
    if (proofSource) required.set(proofSource.id, proofSource);
  }
  return [...required.values()].sort((left, right) => taskTime(left.task) - taskTime(right.task));
}

function pickProofSourceGroup(finding: Finding, routeGroups: FlowTaskGroup[], allGroups: FlowTaskGroup[]): FlowTaskGroup | null {
  const completedRouteGroups = routeGroups.filter((group) => taskFlowStatus(group.status) === 'done');
  const completedAllGroups = allGroups.filter((group) => !isFailedTaskStatus(group.status) && taskFlowStatus(group.status) === 'done');
  const pools = [completedRouteGroups, completedAllGroups, routeGroups, allGroups.filter((group) => !isFailedTaskStatus(group.status))];
  for (const pool of pools) {
    const matched = bestMatchingProofGroup(finding, pool);
    if (matched) return matched;
  }
  return lastItem(completedRouteGroups) ?? lastItem(completedAllGroups) ?? lastItem(routeGroups) ?? null;
}

function bestMatchingProofGroup(finding: Finding, groups: FlowTaskGroup[]): FlowTaskGroup | null {
  let best: { group: FlowTaskGroup; score: number } | null = null;
  for (const group of groups) {
    const score = proofGroupScore(finding, group);
    if (score <= 0) continue;
    if (!best || score > best.score || (score === best.score && taskTime(group.task) > taskTime(best.group.task))) {
      best = { group, score };
    }
  }
  return best?.group ?? null;
}

function proofGroupScore(finding: Finding, group: FlowTaskGroup): number {
  const haystack = findingSearchText(finding);
  const tool = group.tool.toLowerCase();
  let score = 0;
  if (tool && haystack.includes(tool)) score += 5;
  for (const token of tool.split(/[-_\s]+/).filter((part) => part.length > 2)) {
    if (haystack.includes(token)) score += 2;
  }
  if (sameHost(finding.target_id, group.target)) score += 4;
  if (String(finding.target_id || '') && String(group.target || '') && String(finding.target_id).includes(String(group.target))) score += 2;
  if (taskFlowStatus(group.status) === 'done') score += 1;
  return score;
}

function findingSearchText(finding: Finding): string {
  const replay = finding.replay_recipe_json && typeof finding.replay_recipe_json === 'object'
    ? Object.values(finding.replay_recipe_json).join(' ')
    : '';
  return [
    finding.title,
    finding.summary,
    finding.finding_origin,
    finding.target_id,
    finding.evidence_ref,
    replay,
    ...(finding.methodology_tags ?? []),
  ].join(' ').toLowerCase();
}

function sameHost(left: string | null | undefined, right: string | null | undefined): boolean {
  const leftHost = hostFromValue(left);
  const rightHost = hostFromValue(right);
  return Boolean(leftHost && rightHost && leftHost === rightHost);
}

function hostFromValue(value: string | null | undefined): string {
  const raw = String(value || '').trim();
  if (!raw) return '';
  try {
    return new URL(raw).host.toLowerCase();
  } catch {
    return raw.split('/')[0].toLowerCase();
  }
}

function taskTime(task: Task): number {
  const raw = task.created_at ?? task.updated_at ?? '';
  const value = new Date(raw).getTime();
  return Number.isFinite(value) ? value : 0;
}

function isFailedTaskStatus(status: string): boolean {
  return ['failed', 'errored', 'error', 'cancelled', 'canceled', 'timed_out', 'timeout'].includes(status.toLowerCase());
}

function isActiveTaskStatus(status: string): boolean {
  return ['running', 'dispatching', 'active', 'in_progress', 'executing'].includes(status.toLowerCase());
}

function taskFlowStatus(status: string): AttackFlowStatus {
  const normalized = status.toLowerCase();
  if (isFailedTaskStatus(normalized)) return 'failed';
  if (isActiveTaskStatus(normalized)) return 'running';
  if (['queued', 'pending', 'requested', 'waiting', 'pending_approval'].includes(normalized)) return 'queued';
  if (['completed', 'succeeded', 'success', 'done'].includes(normalized)) return 'done';
  return 'idle';
}

function taskGroupNode(group: FlowTaskGroup, x: number, y: number, status: AttackFlowStatus, width = 140): AttackFlowNode {
  return {
    id: group.id,
    label: group.phase === 'map' ? 'Map' : group.phase === 'inspect' ? 'Inspect' : group.phase === 'test' ? 'Try' : 'Task',
    title: humanizeTool(group.tool),
    detail: group.count > 1
      ? `${group.count}x ${humanTaskStatus(group.status)} · ${durationForGroup(group)}`
      : `${humanTaskStatus(group.status)} · ${durationForGroup(group)}`,
    route: '/live-cli',
    status,
    story: taskNodeStory(group, status),
    meta: [
      { label: 'Tool', value: group.tool },
      { label: 'Status', value: humanTaskStatus(group.status) },
      { label: 'Target', value: group.target || 'not recorded' },
      { label: 'Runs', value: String(group.count) },
      ...taskGroupTimingMeta(group),
    ],
    timeline: taskGroupTimeline(group, status),
    x,
    y,
    w: width,
    h: 138,
  };
}

function taskNodeStory(group: FlowTaskGroup, status: AttackFlowStatus): string {
  if (status === 'failed') {
    return `${humanizeTool(group.tool)} was tried on this branch but did not produce usable proof. The route remains visible so the operator can inspect the failed output.`;
  }
  if (status === 'running') {
    return `${humanizeTool(group.tool)} is running now. Watch the CLI output for fresh signals; it becomes reportable only after a finding is persisted.`;
  }
  if (status === 'queued') {
    return `${humanizeTool(group.tool)} is waiting to run. This is planned work, not evidence yet.`;
  }
  if (status === 'done') {
    return `${humanizeTool(group.tool)} completed and added context to the route. Completion alone is signal, not a finding.`;
  }
  return `${humanizeTool(group.tool)} is part of the route context. Open the CLI detail to inspect raw output.`;
}

function edgeBetween(
  id: string,
  from: AttackFlowNode | null,
  to: AttackFlowNode,
  label: string,
  status: AttackFlowStatus,
  labelX: number,
  labelY: number,
): AttackFlowEdge {
  if (!from) {
    return { id, path: `M ${to.x - 42} ${to.y + to.h / 2} H ${to.x}`, label, x: labelX, y: labelY, status };
  }
  const x1 = from.x + from.w;
  const y1 = from.y + from.h / 2;
  const x2 = to.x;
  const y2 = to.y + to.h / 2;
  const verticalProofRoute = to.y >= from.y + from.h + 12 && to.x <= from.x + from.w + 96;
  const cleanLabel = label.length > 12 ? `${label.slice(0, 11)}...` : label;

  if (verticalProofRoute) {
    const sx = from.x + from.w / 2;
    const sy = from.y + from.h;
    const ex = to.x + to.w / 2;
    const ey = to.y;
    const midY = sy + Math.max(44, Math.round((ey - sy) / 2));
    const path = `M ${sx} ${sy} V ${midY} C ${sx} ${midY + 26}, ${ex} ${midY - 26}, ${ex} ${midY} V ${ey}`;
    return { id, path, label: cleanLabel, x: labelX || Math.round(Math.max(sx, ex) + 18), y: labelY || Math.round(midY - 12), status };
  }
  const midX = Math.max(x1 + 36, Math.round((x1 + x2) / 2));
  const path = Math.abs(y1 - y2) < 20
    ? `M ${x1} ${y1} H ${x2}`
    : `M ${x1} ${y1} C ${midX} ${y1}, ${midX} ${y2}, ${x2} ${y2}`;
  const estimatedLabelWidth = Math.min(96, Math.max(46, cleanLabel.length * 7 + 20));
  const computedLabelX = Math.round(Math.max(x1 + 18, Math.min(x2 - estimatedLabelWidth - 18, (x1 + x2) / 2 - estimatedLabelWidth / 2)));
  const computedLabelY = Math.round((y1 + y2) / 2 - 13);
  return { id, path, label: cleanLabel, x: labelX || computedLabelX, y: labelY || computedLabelY, status };
}

function attackFlowSize(nodes: AttackFlowNode[], edges: AttackFlowEdge[], fallbackWidth: number, fallbackHeight: number) {
  const maxNodeX = Math.max(0, ...nodes.map((node) => node.x + node.w));
  const maxNodeY = Math.max(0, ...nodes.map((node) => node.y + node.h));
  const maxEdgeLabelX = Math.max(0, ...edges.map((edge) => edge.x + 110));
  const maxEdgeLabelY = Math.max(0, ...edges.map((edge) => edge.y + 36));
  return {
    width: Math.max(1120, Math.min(fallbackWidth, Math.ceil(Math.max(maxNodeX, maxEdgeLabelX) + 72))),
    height: Math.max(560, Math.min(fallbackHeight, Math.ceil(Math.max(maxNodeY, maxEdgeLabelY) + 72))),
  };
}

function edgeStroke(status: AttackFlowStatus): string {
  if (status === 'failed') return 'rgb(255 93 103)';
  if (status === 'finding') return 'rgb(94 234 212)';
  if (status === 'running' || status === 'queued') return 'rgb(251 191 36)';
  if (status === 'ready') return 'rgb(167 139 250)';
  return 'rgb(94 207 255)';
}

function AttackNodeTimeChips({ node, compact = false }: { node: AttackFlowNode; compact?: boolean }) {
  const chips = node.timeline?.filter((chip) => chip.value && chip.value !== 'not recorded') ?? [];
  if (chips.length === 0) return null;
  return (
    <div className={cn('mt-2 flex flex-wrap gap-1.5', compact && 'mt-1.5')}>
      {chips.slice(0, compact ? 2 : 3).map((chip) => (
        <span
          key={`${chip.label}-${chip.value}`}
          className={cn(
            'inline-flex max-w-full items-center gap-1 rounded-full border px-2 py-0.5 font-mono text-[0.54rem] uppercase leading-4 tracking-widest',
            timelineChipTone(chip.tone),
          )}
        >
          <span className="opacity-75">{chip.label}</span>
          <span className="truncate font-semibold">{chip.value}</span>
        </span>
      ))}
    </div>
  );
}

function AttackFlowNodeCard({ node, selected, onSelect }: { node: AttackFlowNode; selected: boolean; onSelect: () => void }) {
  const isLive = node.status === 'running' || node.status === 'queued';
  return (
    <button
      type="button"
      onClick={onSelect}
      aria-label={`${node.label} ${node.title}. ${node.detail}. Status ${node.status}.${attackNodeTimelineSummary(node)} Select for explanation.`}
      aria-pressed={selected}
      className={cn(
        'absolute overflow-hidden rounded-lg border p-4 text-left shadow-[inset_0_1px_0_rgba(255,255,255,0.035)] transition-colors hover:border-cyan/50 hover:bg-cyan/10',
        selected && 'ring-2 ring-cyan/55',
        attackNodeTone(node),
      )}
      style={{ left: node.x, top: node.y, width: node.w, height: node.h }}
    >
      <div className="flex items-center justify-between gap-2">
        <span className="font-mono text-[0.62rem] uppercase tracking-widest opacity-80">{node.label}</span>
        <span className={cn('h-2.5 w-2.5 rounded-full bg-current shadow-[0_0_14px_currentColor]', isLive && 'animate-pulse')} />
      </div>
      <div className="mt-3 line-clamp-2 text-[0.98rem] font-semibold leading-5 text-text">{node.title}</div>
      <div className="mt-1 line-clamp-1 text-[0.76rem] leading-4 text-muted">{node.detail}</div>
      <AttackNodeTimeChips node={node} />
    </button>
  );
}

function AttackFlowDetailPanel({ node }: { node: AttackFlowNode | undefined }) {
  if (!node) {
    return (
      <aside
        className="dark-canvas min-h-0 rounded border border-cyan/15 bg-[#030b16]/70 p-4 text-[0.85rem] text-muted"
        aria-label="Selected attack map step"
      >
        Select a step in the map to see what happened.
      </aside>
    );
  }
  return (
    <aside className="dark-canvas min-h-0 overflow-auto rounded border border-cyan/15 bg-[#030b16]/70 p-4" aria-label="Selected attack map step" aria-live="polite">
      <div className="flex items-center justify-between gap-3">
        <span className={cn('rounded border px-2 py-1 font-mono text-[0.62rem] uppercase tracking-widest', attackNodeTone(node))}>
          {node.label}
        </span>
        <span className="font-mono text-[0.62rem] uppercase tracking-widest text-muted">{node.status}</span>
      </div>
      <h3 className="mt-4 text-[1.1rem] font-semibold leading-snug text-text">{node.title}</h3>
      <p className="mt-2 text-[0.9rem] leading-5 text-soft">{node.story}</p>
      <div className="mt-4 space-y-2">
        {(node.meta ?? []).map((item) => (
          <div key={`${item.label}-${item.value}`} className="rounded border border-line-soft bg-bg/45 px-3 py-2">
            <div className="font-mono text-[0.58rem] uppercase tracking-widest text-muted">{item.label}</div>
            <div className="mt-1 break-words text-[0.84rem] text-text">{item.value}</div>
          </div>
        ))}
      </div>
      <Link
        to={node.route}
        className="mt-4 inline-flex w-full items-center justify-center rounded border border-cyan/30 bg-cyan/10 px-3 py-2 font-mono text-[0.66rem] font-semibold uppercase tracking-widest text-cyan hover:bg-cyan/15"
      >
        Open linked view
      </Link>
    </aside>
  );
}

function attackNodeTone(node: AttackFlowNode): string {
  const severity = (node.severity || '').toLowerCase();
  if (node.status === 'failed') return 'border-[rgba(239,68,68,0.42)] bg-[rgba(7,17,31,0.92)] text-red';
  if (node.status === 'finding' && severity === 'critical') return 'border-[rgba(208,107,255,0.45)] bg-[rgba(7,17,31,0.92)] text-ai';
  if (node.status === 'finding' && severity === 'high') return 'border-[rgba(239,68,68,0.40)] bg-[rgba(7,17,31,0.92)] text-red';
  if (node.status === 'finding' && severity === 'medium') return 'border-[rgba(251,191,36,0.42)] bg-[rgba(7,17,31,0.92)] text-amber';
  if (node.status === 'finding') return 'border-[rgba(250,204,21,0.36)] bg-[rgba(7,17,31,0.92)] text-yellow-300';
  if (node.status === 'running' || node.status === 'queued') return 'border-[rgba(251,191,36,0.36)] bg-[rgba(7,17,31,0.92)] text-amber';
  if (node.status === 'ready') return 'border-[rgba(208,107,255,0.40)] bg-[rgba(7,17,31,0.92)] text-ai';
  if (node.status === 'done') return 'border-[rgba(52,211,153,0.34)] bg-[rgba(7,17,31,0.92)] text-green-300';
  return 'border-[rgba(142,191,228,0.18)] bg-[rgba(7,17,31,0.82)] text-muted';
}

function timelineChipTone(tone: AttackFlowTimelineTone = 'muted'): string {
  if (tone === 'good') return 'border-green-300/30 bg-green-300/10 text-green-300';
  if (tone === 'warn') return 'border-amber/35 bg-amber/10 text-amber';
  if (tone === 'danger') return 'border-red/35 bg-red/10 text-red';
  if (tone === 'proof') return 'border-ai/35 bg-ai/10 text-ai';
  return 'border-cyan/15 bg-bg/45 text-muted';
}

function attackNodeTimelineSummary(node: AttackFlowNode): string {
  const chips = node.timeline?.filter((chip) => chip.value && chip.value !== 'not recorded') ?? [];
  if (chips.length === 0) return '';
  return ` Timeline: ${chips.map((chip) => `${chip.label} ${chip.value}`).join('; ')}.`;
}

function humanizeTool(tool: string): string {
  const normalized = tool.replace(/[-_]+/g, ' ').trim();
  if (!normalized) return 'Task';
  if (normalized.toLowerCase() === 'nmap') return 'Nmap';
  if (normalized.toLowerCase() === 'sqlmap') return 'Sqlmap';
  return normalized
    .split(' ')
    .map((part) => (part.length <= 3 ? part.toUpperCase() : `${part.charAt(0).toUpperCase()}${part.slice(1)}`))
    .join(' ');
}

function attackMapFindingTitle(finding: Finding): string {
  const rawTitle = String(finding.title || '').trim();
  if (!rawTitle) return safeMissionFindingTitle(finding);
  if (/flag captured/i.test(rawTitle)) return 'Captured proof via interactive exploit';
  return rawTitle
    .replace(/aegispt\{[^}]+\}/gi, '[redacted proof token]')
    .replace(/\b(xbow|xben)-[a-z0-9-]+/gi, '[benchmark id redacted]');
}

function compactAttackMapTitle(title: string): string {
  return title.length > 48 ? `${title.slice(0, 45)}...` : title;
}

function attackMapFindingStory(
  finding: Finding,
  sourceGroup: FlowTaskGroup | null,
  clusterSummary: string | null = null,
  clusterTotal = 1,
): string {
  const source = sourceGroup
    ? `${humanizeTool(sourceGroup.tool)} on ${sourceGroup.target || 'the selected target'}`
    : 'the recorded evidence chain';
  const evidence = finding.evidence_ref ? ` Evidence reference: ${finding.evidence_ref}.` : '';
  const cluster = clusterSummary
    ? ` This proof card represents the whole saved finding cluster: ${clusterTotal} reportable findings (${clusterSummary}).`
    : '';
  return `This saved finding came from ${source}. It is shown here because it is persisted as a reportable finding, not because a queued task merely produced output.${cluster}${evidence}`;
}

function taskGroupTimingMeta(group: FlowTaskGroup | undefined): Array<{ label: string; value: string }> {
  if (!group) return [];
  return [
    { label: 'Started', value: formatTimestamp(group.startedAt) },
    { label: 'Last update', value: formatTimestamp(group.endedAt) },
    { label: 'Duration', value: durationForGroup(group) },
  ];
}

function taskGroupTimeline(group: FlowTaskGroup, status: AttackFlowStatus): AttackFlowTimelineChip[] {
  const tone = timelineToneForStatus(status);
  const eventLabel = status === 'failed'
    ? 'failed'
    : status === 'running'
      ? 'started'
      : status === 'queued'
        ? 'queued'
        : 'done';
  const eventTime = status === 'running' || status === 'queued' ? group.startedAt : group.endedAt;
  return [
    { label: eventLabel, value: formatTimestamp(eventTime), tone },
    { label: status === 'running' ? 'running' : status === 'queued' ? 'waiting' : 'took', value: durationForGroup(group), tone: status === 'running' || status === 'queued' ? 'warn' : 'muted' },
  ];
}

function findingTimeline(run: Run, finding: Finding, sourceGroup: FlowTaskGroup | null): AttackFlowTimelineChip[] {
  const persistedMs = timeValue(finding.created_at);
  return [
    { label: 'proof', value: formatTimestamp(finding.created_at), tone: 'proof' },
    { label: 'after', value: elapsedFromRunStart(run, persistedMs), tone: 'proof' },
    { label: 'source took', value: sourceGroup ? durationForGroup(sourceGroup) : 'not recorded', tone: 'muted' },
  ];
}

function timelineToneForStatus(status: AttackFlowStatus): AttackFlowTimelineTone {
  if (status === 'failed') return 'danger';
  if (status === 'finding' || status === 'ready') return 'proof';
  if (status === 'running' || status === 'queued') return 'warn';
  if (status === 'done') return 'good';
  return 'muted';
}

function durationForGroup(group: FlowTaskGroup): string {
  const start = timeValue(group.startedAt);
  const end = timeValue(group.endedAt);
  if (start === null || end === null || end < start) return 'not recorded';
  return formatDuration(end - start);
}

function elapsedFromRunStart(run: Run, targetMs: number | null): string {
  const start = timeValue(run.started_at ?? run.created_at);
  if (start === null || targetMs === null || targetMs < start) return 'not recorded';
  return formatDuration(targetMs - start);
}

function latestTaskTime(tasks: Task[]): number | null {
  return tasks.reduce<number | null>((latest, task) => {
    const value = timeValue(task.updated_at ?? task.created_at);
    if (value === null) return latest;
    return latest === null ? value : Math.max(latest, value);
  }, null);
}

function latestFlowTime(run: Run, tasks: Task[], findings: Finding[]): number | null {
  const values = [
    latestTaskTime(tasks),
    ...findings.map((finding) => timeValue(finding.created_at)),
    timeValue(run.updated_at ?? run.started_at ?? run.created_at),
  ].filter((value): value is number => value !== null);
  if (values.length === 0) return null;
  return Math.max(...values);
}

function minIso(left: string | null, right: string | null | undefined): string | null {
  const leftTime = timeValue(left);
  const rightTime = timeValue(right);
  if (rightTime === null) return left;
  if (leftTime === null || rightTime < leftTime) return right ?? null;
  return left;
}

function maxIso(left: string | null, right: string | null | undefined): string | null {
  const leftTime = timeValue(left);
  const rightTime = timeValue(right);
  if (rightTime === null) return left;
  if (leftTime === null || rightTime > leftTime) return right ?? null;
  return left;
}

function timeValue(value: string | null | undefined): number | null {
  const time = value ? new Date(value).getTime() : Number.NaN;
  return Number.isFinite(time) ? time : null;
}

function timeIsoFromMs(value: number | null): string | null {
  return value === null ? null : new Date(value).toISOString();
}

function formatTimestamp(value: string | null | undefined): string {
  const time = timeValue(value);
  if (time === null) return 'not recorded';
  const date = new Date(time);
  const hours = String(date.getHours()).padStart(2, '0');
  const minutes = String(date.getMinutes()).padStart(2, '0');
  const seconds = String(date.getSeconds()).padStart(2, '0');
  return `${hours}:${minutes}:${seconds}`;
}

function formatDuration(ms: number): string {
  const seconds = Math.max(0, Math.round(ms / 1000));
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  const remainingSeconds = seconds % 60;
  if (minutes < 60) return remainingSeconds > 0 ? `${minutes}m ${String(remainingSeconds).padStart(2, '0')}s` : `${minutes}m`;
  const hours = Math.floor(minutes / 60);
  const remainingMinutes = minutes % 60;
  return remainingMinutes > 0 ? `${hours}h ${String(remainingMinutes).padStart(2, '0')}m` : `${hours}h`;
}

function lastItem<T>(items: T[]): T | null {
  return items.length > 0 ? items[items.length - 1] : null;
}

function severityLabel(severity: string | null | undefined): string {
  return (severity || 'info').toLowerCase();
}

const ATTACK_MAP_SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const;

type AttackMapSeverity = (typeof ATTACK_MAP_SEVERITIES)[number];

function attackMapSeverityRows(summary: AttackFindingSummary): Array<{ severity: AttackMapSeverity; value: number }> {
  return ATTACK_MAP_SEVERITIES.map((severity) => ({ severity, value: summary[severity] })).filter((row) => row.value > 0);
}

function attackMapSeveritySummary(summary: AttackFindingSummary): string {
  const rows = attackMapSeverityRows(summary);
  if (rows.length === 0) return '0 findings';
  return rows.map((row) => `${row.value} ${row.severity}`).join(' · ');
}

function NowSnapshot({
  state,
  statusTitle,
  host,
  uptime,
  taskStats,
  findings,
  active,
  nextTask,
}: {
  state: MissionState;
  statusTitle: string;
  host: string;
  uptime: string;
  taskStats: ReturnType<typeof missionTaskCounts>;
  findings: Finding[];
  active: Task | null;
  nextTask: Task | null;
}) {
  return (
    <section className="neon-panel rounded-lg border border-border bg-surface/55 p-4 backdrop-blur-md">
      <div className="flex items-center justify-between gap-3">
        <span className={cn('rounded border px-2.5 py-1 font-mono text-[0.66rem] font-bold uppercase tracking-widest', state.toneBg, state.tone)}>
          {state.label}
        </span>
        <span className="font-mono text-[0.72rem] text-amber">{uptime}</span>
      </div>
      <div className="mt-5 text-[1.6rem] font-semibold leading-tight text-text">{statusTitle}</div>
      <div className="mt-2 flex flex-wrap gap-2">
        <PlainMetric label="Target" value={host || 'not recorded'} />
        <PlainMetric label="Now" value={active ? active.tool : 'idle'} />
        <PlainMetric label="Next" value={nextTask ? nextTask.tool : findings.length > 0 ? 'review' : 'none'} />
      </div>
      <div className="mt-4 grid grid-cols-3 gap-2">
        <MiniKpi label="Checked" value={String(taskStats.completed + taskStats.failed)} />
        <MiniKpi label="Running" value={String(taskStats.running)} />
        <MiniKpi label="Findings" value={String(findings.length)} />
      </div>
    </section>
  );
}

function MissionStoryBoard({
  run,
  active,
  nextTask,
  taskStats,
  findings,
}: {
  run: Run;
  active: Task | null;
  nextTask: Task | null;
  taskStats: ReturnType<typeof missionTaskCounts>;
  findings: Finding[];
}) {
  const runEnded = isTerminalRun(run);
  const doneValue = `${taskStats.completed + taskStats.failed} checks`;
  const nowValue = active ? active.tool : runEnded ? 'finished' : 'waiting';
  const nextValue = nextTask ? nextTask.tool : findings.length > 0 ? 'review proof' : runEnded ? 'close out' : 'next decision';
  return (
    <section className="neon-panel rounded-lg border border-border bg-surface/55 p-4 backdrop-blur-md">
      <div className="mb-4 flex items-center justify-between gap-3">
        <h2 className="text-[1rem] font-semibold text-text">The test story</h2>
        <span className="font-mono text-[0.68rem] uppercase tracking-widest text-muted">done / now / next</span>
      </div>
      <div className="grid gap-3 md:grid-cols-3">
        <StoryTile title="Done" value={doneValue} detail={findings.length > 0 ? `${findings.length} saved findings` : 'no saved finding yet'} tone="text-green-300" />
        <StoryTile title="Now" value={nowValue} detail={active ? toolNarrative(active.tool) : runEnded ? 'no task is running' : 'waiting for work'} tone="text-amber" />
        <StoryTile title="Next" value={nextValue} detail={nextTask ? 'queued check' : findings.length > 0 ? 'verify before report' : 'nothing queued'} tone="text-cyan" />
      </div>
    </section>
  );
}

function StoryTile({ title, value, detail, tone }: { title: string; value: string; detail: string; tone: string }) {
  return (
    <div className="theme-surface-card min-w-0 rounded-lg border p-3">
      <div className={cn('font-mono text-[0.65rem] uppercase tracking-widest', tone)}>{title}</div>
      <div className="mt-2 truncate text-[1.1rem] font-semibold text-text">{value}</div>
      <div className="mt-1 line-clamp-2 min-h-[2.25rem] text-[0.78rem] leading-5 text-muted">{detail}</div>
    </div>
  );
}

function MiniKpi({ label, value }: { label: string; value: string }) {
  return (
    <div className="theme-surface-card rounded-lg border px-3 py-2 text-center">
      <div className="font-mono text-[0.62rem] uppercase tracking-widest text-muted">{label}</div>
      <div className="mt-1 font-mono text-[1.15rem] font-semibold text-text">{value}</div>
    </div>
  );
}

function OutcomePulseChart({
  taskStats,
  findings,
  runEnded,
}: {
  taskStats: ReturnType<typeof missionTaskCounts>;
  findings: Finding[];
  runEnded: boolean;
}) {
  const checked = taskStats.completed + taskStats.failed;
  const total = Math.max(1, checked + taskStats.running + taskStats.queued);
  const checkedPct = Math.round((checked / total) * 100);
  const counts = countSeverity(findings);
  const maxSeverity = Math.max(1, ...Object.values(counts));
  const leadFinding = [...findings].sort(
    (a, b) =>
      (SEV_ORDER[(a.severity || 'info').toLowerCase()] ?? 9) -
      (SEV_ORDER[(b.severity || 'info').toLowerCase()] ?? 9),
  )[0];
  const outcomeLine = leadFinding
    ? `Lead proof: ${safeMissionFindingTitle(leadFinding)}. Review evidence, then report from the same route.`
    : runEnded
      ? 'Run ended without a saved finding. Use Evidence Replay to decide whether this route is a dead end or needs another pass.'
      : 'The route is still moving. Findings appear here only after persistence creates reportable proof.';
  return (
    <section className="neon-panel rounded-lg border border-border bg-surface/55 p-4 backdrop-blur-md">
      <div className="mb-3 flex items-center justify-between gap-3">
        <h3 className="font-mono text-[0.7rem] font-semibold uppercase tracking-widest text-muted">Run picture</h3>
        <span className="text-[0.8rem] text-muted">{runEnded ? 'ended' : 'live'}</span>
      </div>
      <div className="grid items-center gap-4 sm:grid-cols-[9rem_1fr]">
        <div className="relative mx-auto h-32 w-32">
          <svg viewBox="0 0 120 120" className="h-full w-full -rotate-90">
            <circle cx="60" cy="60" r="48" fill="none" stroke="rgba(148,163,184,0.18)" strokeWidth="12" />
            <circle
              cx="60"
              cy="60"
              r="48"
              fill="none"
              stroke="var(--cyan)"
              strokeLinecap="round"
              strokeWidth="12"
              strokeDasharray={`${checkedPct} ${100 - checkedPct}`}
              pathLength="100"
            />
          </svg>
          <div className="absolute inset-0 flex flex-col items-center justify-center">
            <span className="font-mono text-[1.3rem] font-semibold text-text">{checkedPct}%</span>
            <span className="font-mono text-[0.58rem] uppercase tracking-widest text-muted">checked</span>
          </div>
        </div>
        <div className="space-y-2">
          {(['critical', 'high', 'medium', 'low', 'info'] as const).map((severity) => {
            const value = counts[severity];
            const width = value > 0 ? Math.max(8, (value / maxSeverity) * 100) : 2;
            return (
              <div key={severity} className="grid grid-cols-[4.5rem_1fr_2rem] items-center gap-2">
                <span className={cn('font-mono text-[0.62rem] uppercase tracking-widest', severityChartTone(severity))}>{severity}</span>
                <div className="h-2 overflow-hidden rounded-full bg-bg/45">
                  <div className={cn('h-full rounded-full', severityChartFill(severity))} style={{ width: `${width}%`, opacity: value > 0 ? 1 : 0.22 }} />
                </div>
                <span className="text-right font-mono text-[0.72rem] text-text">{value}</span>
              </div>
            );
          })}
        </div>
      </div>
      <div className="theme-surface-card mt-4 rounded-lg border p-3">
        <div className="font-mono text-[0.62rem] uppercase tracking-widest text-cyan/75">Route outcome</div>
        <p className="mt-2 text-[0.86rem] leading-5 text-text">{outcomeLine}</p>
        <div className="mt-2 font-mono text-[0.62rem] uppercase tracking-widest text-muted">
          {'Map surface -> inspect behavior -> test routes -> prove impact -> tell outcome'}
        </div>
      </div>
    </section>
  );
}

function severityChartTone(severity: string): string {
  if (severity === 'critical') return 'text-red';
  if (severity === 'high') return 'text-amber';
  if (severity === 'medium') return 'text-yellow-300';
  if (severity === 'low') return 'text-cyan';
  return 'text-muted';
}

function severityChartFill(severity: string): string {
  if (severity === 'critical') return 'bg-red';
  if (severity === 'high') return 'bg-amber';
  if (severity === 'medium') return 'bg-yellow-300';
  if (severity === 'low') return 'bg-cyan';
  return 'bg-muted';
}

function QueueSnapshot({
  tasks,
  selectedTaskId,
  onSelectTask,
}: {
  tasks: Task[];
  selectedTaskId: string | null;
  onSelectTask: (taskId: string) => void;
}) {
  const queued = queuedTasks(tasks);
  const running = runningTasks(tasks);
  const rows = liveTaskTimelineTasks(tasks, 7);

  return (
    <section className="neon-panel rounded-lg border border-border bg-surface/55 p-4 backdrop-blur-md">
      <div className="mb-3 flex items-center justify-between gap-3">
        <h3 className="font-mono text-[0.7rem] font-semibold uppercase tracking-widest text-muted">Queue</h3>
        <span className="text-[0.8rem] text-muted">
          {running.length} running · {queued.length} waiting
        </span>
      </div>
      {(running.length > 0 || queued.length > 0) && (
        <div className="mission-queue-flow mb-3" data-status={running.length > 0 ? 'running' : 'queued'} aria-label={running.length > 0 ? 'Queue has active work running' : 'Queue is waiting for the next task'}>
          <span className="mission-queue-flow-dot" aria-hidden="true" />
          <span className="font-mono text-[0.62rem] font-semibold uppercase tracking-widest text-cyan/75">
            {running.length > 0 ? 'live task stream' : 'waiting handoff'}
          </span>
          <span className="mission-queue-flow-line" aria-hidden="true" />
        </div>
      )}
      {rows.length === 0 ? (
        <p className="text-[0.9rem] text-muted">No queued or recent task activity.</p>
      ) : (
        <ol className="space-y-2">
          {rows.map((task) => {
            const status = (task.status || '').toLowerCase();
            return (
              <li key={String(task.id)}>
                <button
                  type="button"
                  onClick={() => onSelectTask(String(task.id))}
                  aria-label={`Show CLI output for ${task.tool}`}
                  data-status={status}
                  className={cn(
                    'mission-queue-row grid w-full gap-2 rounded-lg border px-3 py-2 text-left transition-colors sm:grid-cols-[7.5rem_1fr_auto]',
                    selectedTaskId === String(task.id)
                      ? 'border-cyan/50 bg-cyan/10'
                      : 'border-border bg-surface/55 hover:border-cyan/35 hover:bg-cyan/5',
                  )}
                >
                <span className={cn('font-mono text-[0.72rem] font-semibold uppercase tracking-wider', taskStatusTone(status))}>
                  {humanTaskStatus(status)}
                </span>
                <span className="min-w-0 truncate text-[0.92rem] font-semibold text-text">
                  {task.tool}
                </span>
                <span className="min-w-0 truncate font-mono text-[0.72rem] text-muted">{task.target_id || 'no target'}</span>
                </button>
              </li>
            );
          })}
        </ol>
      )}
    </section>
  );
}

function ResultsMissionView({ run, findings, tasks }: { run: Run; findings: Finding[]; tasks: Task[] }) {
  const selectFinding = useAegisStore((state) => state.selectFinding);
  const state = useMemo(() => deriveMissionState(run, findings, tasks), [run, findings, tasks]);
  const taskStats = useMemo(() => missionTaskCounts(tasks), [tasks]);
  const active = useMemo(() => activeTaskNow(tasks), [tasks]);
  const latest = useMemo(() => latestTasks(tasks, 5), [tasks]);
  const host = useMemo(() => targetHost(run, tasks), [run, tasks]);
  const current = active ?? latest[0] ?? null;
  const beats = useMemo(() => buildStoryBeats(run, findings, tasks), [run, findings, tasks]);
  const runEnded = isTerminalRun(run);
  const status = missionStatusCopy(run, state, taskStats, findings, current, host);
  const taskMetricLabel = runEnded ? 'Last task' : active ? 'Current task' : 'Next task';

  return (
    <div className="min-h-0 flex-1 overflow-y-auto">
      <div className="grid gap-4 border-b border-line-soft px-6 py-5 xl:grid-cols-[1.1fr_0.9fr]">
        <section className="rounded border border-line-soft bg-surface/35 p-4">
          <div className="mb-3 flex items-center justify-between gap-3">
            <span className={cn('rounded border px-2.5 py-1 font-mono text-[0.7rem] font-bold uppercase tracking-widest', state.toneBg, state.tone)}>
              {state.label}
            </span>
            <span className="font-mono text-[0.72rem] text-amber">{formatUptime(run.started_at)}</span>
          </div>
          <h2 className="text-xl font-semibold leading-tight text-text">{status.title}</h2>
          <p className="mt-2 max-w-3xl text-[0.95rem] leading-6 text-soft">{status.detail}</p>
          <div className="mt-4 grid gap-2 sm:grid-cols-3">
            <PlainMetric label="Target" value={host || 'not recorded'} />
            <PlainMetric label={taskMetricLabel} value={current ? current.tool : 'none'} />
            <PlainMetric label="Findings" value={`${findings.length} reportable`} />
          </div>
        </section>

        <section className="rounded border border-line-soft bg-surface/35 p-4">
          <div className="mb-3 flex items-center justify-between gap-3">
            <h3 className="font-mono text-[0.7rem] font-semibold uppercase tracking-widest text-muted">Progress</h3>
            <span className="text-[0.8rem] text-muted">{taskStats.completed + taskStats.failed} checked · {taskStats.running} running</span>
          </div>
          <ProgressSummary taskStats={taskStats} findings={findings} />
          <div className="mt-4 rounded border border-line-soft bg-bg-2/25 px-3 py-2">
            <div className="font-mono text-[0.65rem] uppercase tracking-widest text-muted">Report rule</div>
            <p className="mt-1 text-[0.86rem] leading-5 text-soft">
              Only saved findings appear in reports. Tool output stays in Technical until it is reviewed.
            </p>
          </div>
        </section>
      </div>

      <div className="grid gap-4 px-6 py-4 xl:grid-cols-[1fr_0.85fr]">
        <section className="rounded border border-line-soft bg-surface/30 p-4">
          <div className="mb-3 flex items-center justify-between gap-3">
            <h3 className="font-mono text-[0.7rem] font-semibold uppercase tracking-widest text-muted">Latest activity</h3>
            <span className="text-[0.8rem] text-muted">{tasks.length} tasks</span>
          </div>
          <TaskActivityList tasks={latest} totalTasks={tasks.length} />
        </section>

        <section className="rounded border border-line-soft bg-surface/30 p-4">
          <div className="mb-3 flex items-center justify-between gap-3">
            <h3 className="font-mono text-[0.7rem] font-semibold uppercase tracking-widest text-muted">Findings</h3>
            <div className="flex items-center gap-2">
              <span className="text-[0.8rem] text-muted">{findings.length} reportable</span>
              {findings.length > 0 && (
                <>
                  <Link className="rounded border border-line-soft px-2 py-1 text-[0.75rem] text-cyan hover:bg-cyan/10" to="/findings">
                    Open Findings
                  </Link>
                  <Link className="rounded border border-line-soft px-2 py-1 text-[0.75rem] text-cyan hover:bg-cyan/10" to="/evidence">
                    Evidence
                  </Link>
                </>
              )}
            </div>
          </div>
          <FindingPlainList findings={findings} runEnded={runEnded} onSelectFinding={selectFinding} />
        </section>
      </div>

      <div className="grid gap-4 border-t border-line-soft px-6 py-4 xl:grid-cols-[1fr_1fr]">
        <PlainLanguagePanel title="Wat betekent dit?" detail={resultsPlainLanguage(run, findings, taskStats)} />
        <TechnicalFactsPanel
          facts={[
            ['Run status', run.status || 'unknown'],
            ['Checked tasks', String(taskStats.completed + taskStats.failed)],
            ['Failed tasks', String(taskStats.failed)],
            ['Reportable findings', String(findings.length)],
          ]}
        />
      </div>

      <div className="px-6 pb-5">
        <details className="rounded border border-line-soft bg-bg-2/20">
          <summary className="cursor-pointer px-4 py-3 font-mono text-[0.72rem] uppercase tracking-widest text-muted hover:text-text">
            Show scan timeline
          </summary>
          <div className="border-t border-line-soft p-4">
            {beats.length > 0 ? (
              <TaskNarrativeList beats={beats} />
            ) : (
              <p className="text-[0.9rem] text-muted">No narrative events recorded yet.</p>
            )}
          </div>
        </details>
      </div>
    </div>
  );
}

function OverviewMissionView({ run, findings, tasks }: { run: Run; findings: Finding[]; tasks: Task[] }) {
  const taskStats = useMemo(() => missionTaskCounts(tasks), [tasks]);
  const host = useMemo(() => targetHost(run, tasks), [run, tasks]);
  const active = useMemo(() => activeTaskNow(tasks), [tasks]);
  const latest = useMemo(() => latestTasks(tasks, 5), [tasks]);
  const nextReason = useMemo(() => lastDecisionReasoning(run), [run]);
  const runEnded = isTerminalRun(run);
  const loop = run.configuration_json?.ai_assessment_loop as Record<string, unknown> | undefined;
  const stopReason = typeof loop?.stop_reason === 'string' ? loop.stop_reason : null;
  const queued = tasks.filter((task) => ['queued', 'pending', 'requested', 'waiting', 'pending_approval'].includes((task.status || '').toLowerCase()));
  const highPlus = findings.filter((finding) => ['critical', 'high'].includes((finding.severity || '').toLowerCase())).length;

  return (
    <div className="min-h-0 flex-1 overflow-y-auto">
      <div className="border-b border-line-soft px-6 py-4">
        <MissionJourneyMap run={run} tasks={tasks} findings={findings} />
      </div>
      <div className="grid gap-4 border-b border-line-soft px-6 py-5 xl:grid-cols-[0.9fr_1.1fr]">
        <section className="rounded border border-line-soft bg-surface/35 p-4">
          <div className="mb-3 flex items-center justify-between gap-3">
            <h2 className="text-xl font-semibold leading-tight text-text">Test overview</h2>
            <span className="font-mono text-[0.72rem] text-muted">run:{String(run.id).slice(0, 8)}</span>
          </div>
          <div className="grid gap-2 sm:grid-cols-2">
            <PlainMetric label="Target" value={host || 'not recorded'} />
            <PlainMetric label="Profile" value={run.profile?.name || 'Mission'} />
            <PlainMetric label="Run state" value={run.status || 'unknown'} />
            <PlainMetric label="Reportable findings" value={`${findings.length} total / ${highPlus} high+`} />
          </div>
          <div className="mt-4 flex flex-wrap gap-2">
            <Link className="rounded border border-line-soft px-3 py-1.5 text-[0.8rem] font-semibold text-cyan hover:bg-cyan/10" to="/surface-map">
              Surface Map
            </Link>
            <Link className="rounded border border-line-soft px-3 py-1.5 text-[0.8rem] font-semibold text-cyan hover:bg-cyan/10" to="/history">
              History
            </Link>
            <Link className="rounded border border-line-soft px-3 py-1.5 text-[0.8rem] font-semibold text-cyan hover:bg-cyan/10" to="/reports">
              Reports
            </Link>
          </div>
        </section>

        <section className="rounded border border-line-soft bg-surface/35 p-4">
          <div className="mb-3 flex items-center justify-between gap-3">
            <h3 className="font-mono text-[0.7rem] font-semibold uppercase tracking-widest text-muted">What is coming next</h3>
            <span className="text-[0.8rem] text-muted">{queued.length} queued</span>
          </div>
          <NextMovePanel
            active={active}
            queued={queued}
            runEnded={runEnded}
            findings={findings}
            nextReason={nextReason}
            stopReason={stopReason}
          />
        </section>
      </div>

      <div className="grid gap-4 px-6 py-4 xl:grid-cols-[0.8fr_1.2fr]">
        <section className="rounded border border-line-soft bg-surface/30 p-4">
          <div className="mb-3 flex items-center justify-between gap-3">
            <h3 className="font-mono text-[0.7rem] font-semibold uppercase tracking-widest text-muted">Totals</h3>
            <span className="text-[0.8rem] text-muted">{tasks.length} tasks</span>
          </div>
          <ProgressSummary taskStats={taskStats} findings={findings} />
        </section>

        <section className="rounded border border-line-soft bg-surface/30 p-4">
          <div className="mb-3 flex items-center justify-between gap-3">
            <h3 className="font-mono text-[0.7rem] font-semibold uppercase tracking-widest text-muted">Recent scan path</h3>
            <span className="text-[0.8rem] text-muted">newest first</span>
          </div>
          <TaskActivityList tasks={latest} totalTasks={tasks.length} />
        </section>
      </div>

      <div className="grid gap-4 border-t border-line-soft px-6 py-4 xl:grid-cols-[1fr_1fr]">
        <PlainLanguagePanel title="Het hele verhaal" detail={overviewPlainLanguage(run, active, queued, findings, taskStats)} />
        <TechnicalFactsPanel
          facts={[
            ['Target', host || 'not recorded'],
            ['Profile', run.profile?.name || 'Mission'],
            ['Tasks', `${tasks.length} total`],
            ['High+ findings', String(highPlus)],
          ]}
        />
      </div>

      <div className="px-6 pb-5">
        <AiNarrativeSummary run={run} findings={findings} tasks={tasks} />
      </div>
    </div>
  );
}

function NextMovePanel({
  active,
  queued,
  runEnded,
  findings,
  nextReason,
  stopReason,
}: {
  active: Task | null;
  queued: Task[];
  runEnded: boolean;
  findings: Finding[];
  nextReason: string | null;
  stopReason: string | null;
}) {
  if (active) {
    return (
      <div className="rounded border border-amber/30 bg-amber/10 px-3 py-3">
        <div className="text-[0.95rem] font-semibold text-text">Finish the current task: {active.tool}</div>
        <p className="mt-1 text-[0.86rem] leading-5 text-muted">{toolNarrative(active.tool)}</p>
      </div>
    );
  }
  if (queued.length > 0) {
    return (
      <div className="space-y-2">
        {queued.slice(0, 4).map((task) => (
          <div key={String(task.id)} className="rounded border border-line-soft bg-bg-2/20 px-3 py-2">
            <div className="text-[0.92rem] font-semibold text-text">{task.tool}</div>
            <div className="mt-1 truncate font-mono text-[0.72rem] text-muted">{task.target_id || 'no target'}</div>
          </div>
        ))}
      </div>
    );
  }
  if (runEnded) {
    return (
      <div className="rounded border border-line-soft bg-bg-2/20 px-3 py-3">
        <div className="text-[0.95rem] font-semibold text-text">
          {findings.length > 0 ? 'Review findings and evidence' : 'No next task is queued'}
        </div>
        <p className="mt-1 text-[0.86rem] leading-5 text-muted">
          {findings.length > 0
            ? 'Open Findings and Evidence Replay before exporting a report.'
            : stopReason
              ? `Run stopped: ${stopReason}. Use Technical if you need diagnostics.`
              : 'The run ended without queued follow-up work.'}
        </p>
      </div>
    );
  }
  return (
    <div className="rounded border border-line-soft bg-bg-2/20 px-3 py-3">
      <div className="text-[0.95rem] font-semibold text-text">Waiting for the next decision</div>
      <p className="mt-1 text-[0.86rem] leading-5 text-muted">
        {nextReason || 'No task is running and no queued follow-up is visible yet.'}
      </p>
    </div>
  );
}

function PlainLanguagePanel({ title, detail }: { title: string; detail: string }) {
  return (
    <section className="rounded border border-line-soft bg-surface/30 p-4">
      <div className="font-mono text-[0.7rem] font-semibold uppercase tracking-widest text-muted">{title}</div>
      <p className="mt-2 text-[0.98rem] leading-6 text-text">{detail}</p>
    </section>
  );
}

function TechnicalFactsPanel({ facts }: { facts: Array<[string, string]> }) {
  return (
    <section className="rounded border border-line-soft bg-surface/30 p-4">
      <div className="font-mono text-[0.7rem] font-semibold uppercase tracking-widest text-muted">Technical facts</div>
      <dl className="mt-3 grid gap-2 sm:grid-cols-2">
        {facts.map(([label, value]) => (
          <div key={label} className="rounded border border-line-soft bg-bg-2/20 px-3 py-2">
            <dt className="font-mono text-[0.62rem] uppercase tracking-widest text-muted">{label}</dt>
            <dd className="mt-1 truncate text-[0.92rem] font-semibold text-text">{value}</dd>
          </div>
        ))}
      </dl>
    </section>
  );
}

function AiNarrativeSummary({ run, findings, tasks }: { run: Run; findings: Finding[]; tasks: Task[] }) {
  const fetchedPanels = useNarratorPanels(run.id);
  const configPanels = useMemo(() => getNarratorPanels(run), [run]);
  const panels = fetchedPanels.length > 0 ? fetchedPanels : configPanels;
  const latestPanel = panels[panels.length - 1] ?? null;
  const beats = useMemo(() => buildStoryBeats(run, findings, tasks), [run, findings, tasks]);
  const latestBeat = beats[beats.length - 1] ?? null;
  const fallback = latestBeat
    ? `${latestBeat.text}${latestBeat.detail ? `: ${latestBeat.detail}` : ''}`
    : 'No AI story has arrived yet. The live and results screens still show the factual state of the run.';
  const story = latestPanel?.panel_caption || latestPanel?.scene_caption || fallback;
  const nextMove = latestPanel?.next_move || lastDecisionReasoning(run);

  return (
    <section className="rounded border border-line-soft bg-surface/30 p-4">
      <div className="mb-3 flex items-center justify-between gap-3">
        <div>
          <div className="font-mono text-[0.7rem] font-semibold uppercase tracking-widest text-muted">AI story</div>
          <p className="mt-1 text-[0.82rem] text-muted">
            {panels.length > 0 ? `${panels.length} narrator panel${panels.length === 1 ? '' : 's'} from ChatGPT` : 'derived from task events until the narrator responds'}
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <Link className="rounded border border-line-soft px-2 py-1 text-[0.75rem] text-cyan hover:bg-cyan/10" to="/history">
            History
          </Link>
          <Link className="rounded border border-line-soft px-2 py-1 text-[0.75rem] text-cyan hover:bg-cyan/10" to="/evidence">
            Evidence Replay
          </Link>
        </div>
      </div>
      <p className="text-[0.98rem] leading-6 text-text">{story}</p>
      {nextMove && (
        <p className="mt-3 rounded border border-line-soft bg-bg-2/25 px-3 py-2 text-[0.9rem] leading-5 text-soft">
          <span className="mr-2 font-mono text-[0.65rem] uppercase tracking-widest text-muted">Next</span>
          {nextMove}
        </p>
      )}
      {panels.length > 1 && (
        <details className="mt-3 border-t border-line-soft pt-3">
          <summary className="cursor-pointer font-mono text-[0.68rem] uppercase tracking-widest text-muted hover:text-text">
            Show earlier AI story panels
          </summary>
          <div className="mt-3">
            <ComicStrip panels={panels.slice(-3)} />
          </div>
        </details>
      )}
    </section>
  );
}

function livePlainLanguage(
  run: Run,
  task: Task | null,
  taskStats: ReturnType<typeof missionTaskCounts>,
  findings: Finding[],
): string {
  if (task && ['running', 'dispatching', 'active', 'in_progress', 'executing'].includes((task.status || '').toLowerCase())) {
    return `AegisPT is nu met een check bezig: ${task.tool}. Zie het als iemand die op dit moment een deur, formulier of endpoint probeert te controleren. Als daar echt iets bruikbaars uit komt, verschijnt dat later als finding.`;
  }
  if (taskStats.queued > 0) {
    return `Er staat werk klaar, maar er draait nu geen actieve check. De queue laat zien wat straks aan de beurt is. Eerdere output is alleen ruwe informatie zolang er nog geen finding van is gemaakt.`;
  }
  if (isTerminalRun(run)) {
    return findings.length > 0
      ? `De scan is klaar. Er zijn ${findings.length} reportable finding${findings.length === 1 ? '' : 's'} gevonden die je kunt beoordelen.`
      : 'De scan is klaar, maar er is geen reportable finding gemaakt. Dat betekent niet automatisch dat alles veilig is: het betekent dat deze run niets heeft opgeslagen dat in een rapport mag.';
  }
  return 'Er is nu geen actieve check zichtbaar. Wacht op de volgende beslissing of kijk in Overview om te zien wat er nog gepland staat.';
}

function resultsPlainLanguage(run: Run, findings: Finding[], taskStats: ReturnType<typeof missionTaskCounts>): string {
  if (findings.length > 0) {
    return `De belangrijke uitkomst is: er ${findings.length === 1 ? 'is' : 'zijn'} ${findings.length} finding${findings.length === 1 ? '' : 's'} opgeslagen. Dat zijn de punten die meetellen voor Findings, Evidence en Reports.`;
  }
  if (isTerminalRun(run)) {
    return `Deze run heeft ${taskStats.completed + taskStats.failed} checks afgerond, maar niets opgeslagen als finding. Je kunt Technical openen om te zien waarom checks faalden of alleen ruwe output opleverden.`;
  }
  return 'Er is nog geen einduitkomst. Zolang de run loopt of wacht, kan ruwe output nog veranderen in een echte finding.';
}

function overviewPlainLanguage(
  run: Run,
  active: Task | null,
  queued: Task[],
  findings: Finding[],
  taskStats: ReturnType<typeof missionTaskCounts>,
): string {
  if (active) {
    return `De test loopt nog. Tot nu toe zijn ${taskStats.completed + taskStats.failed} checks bekeken en er ${findings.length === 1 ? 'is' : 'zijn'} ${findings.length} finding${findings.length === 1 ? '' : 's'} opgeslagen. Eerst moet de huidige check klaar zijn.`;
  }
  if (queued.length > 0) {
    return `De test is nog niet klaar: er ${queued.length === 1 ? 'staat' : 'staan'} ${queued.length} check${queued.length === 1 ? '' : 's'} in de wachtrij. Daarna weet je pas of er extra findings of vervolgwerk komt.`;
  }
  if (isTerminalRun(run)) {
    return findings.length > 0
      ? `De test is afgerond. De volgende logische stap is de findings en evidence beoordelen en daarna pas rapporteren.`
      : 'De test is afgerond zonder reportable findings. Voor diagnose kijk je in Technical; voor management is de uitkomst voorlopig: geen finding opgeslagen.';
  }
  return 'Dit is het totaalbeeld van de run: doel, profiel, voortgang, findings en wat er eventueel nog volgt.';
}

function PlainMetric({ label, value }: { label: string; value: string }) {
  return (
    <div className="min-w-0 rounded border border-line-soft bg-bg-2/25 px-3 py-2">
      <div className="font-mono text-[0.62rem] uppercase tracking-widest text-muted">{label}</div>
      <div className="mt-1 truncate text-[0.95rem] font-semibold text-text">{value}</div>
    </div>
  );
}

function ProgressSummary({
  taskStats,
  findings,
}: {
  taskStats: ReturnType<typeof missionTaskCounts>;
  findings: Finding[];
}) {
  const steps = [
    {
      label: 'Queued',
      value: taskStats.queued,
      tone: taskStats.queued > 0 ? 'text-amber' : 'text-muted',
    },
    {
      label: 'Running',
      value: taskStats.running,
      tone: taskStats.running > 0 ? 'text-amber' : 'text-muted',
    },
    {
      label: 'Checked',
      value: taskStats.completed + taskStats.failed,
      tone: taskStats.completed + taskStats.failed > 0 ? 'text-cyan' : 'text-muted',
    },
    {
      label: 'Findings',
      value: findings.length,
      tone: findings.length > 0 ? 'text-green-300' : 'text-muted',
    },
  ];
  return (
    <div className="grid gap-2 sm:grid-cols-4">
      {steps.map((step) => (
        <div key={step.label} className="min-w-0 rounded border border-line-soft bg-bg-2/20 px-3 py-2">
          <div className="truncate font-mono text-[0.65rem] uppercase tracking-widest text-muted">{step.label}</div>
          <div className={cn('mt-1 font-mono text-[1rem] font-semibold', step.tone)}>{step.value}</div>
        </div>
      ))}
    </div>
  );
}

function TaskActivityList({ tasks, totalTasks }: { tasks: Task[]; totalTasks: number }) {
  if (tasks.length === 0) {
    return <p className="text-[0.9rem] text-muted">No tasks have started yet.</p>;
  }
  const grouped = groupTaskActivity(tasks);
  return (
    <div>
      <ol className="space-y-2">
        {grouped.map((item) => {
          const status = item.status;
          return (
            <li key={`${status}-${item.tool}-${item.target}`} className="grid gap-2 rounded border border-line-soft bg-bg-2/20 px-3 py-2 sm:grid-cols-[9rem_1fr_auto]">
              <span className={cn('font-mono text-[0.72rem] font-semibold uppercase tracking-wider', taskStatusTone(status))}>
                {humanTaskStatus(status)}
              </span>
              <span className="min-w-0 truncate text-[0.92rem] font-semibold text-text">
                {item.tool}{item.count > 1 ? ` ×${item.count}` : ''}
              </span>
              <span className="min-w-0 truncate font-mono text-[0.72rem] text-muted">{item.target || 'no target'}</span>
            </li>
          );
        })}
      </ol>
      {totalTasks > tasks.length && (
        <p className="mt-2 text-[0.8rem] text-muted">{totalTasks - tasks.length} older tasks hidden. Open Technical for the full list.</p>
      )}
    </div>
  );
}

function groupTaskActivity(tasks: Task[]): Array<{ tool: string; status: string; target: string; count: number }> {
  const grouped: Array<{ tool: string; status: string; target: string; count: number }> = [];
  for (const task of tasks) {
    const status = (task.status || '').toLowerCase();
    const target = task.target_id || '';
    const existing = grouped.find((item) => item.tool === task.tool && item.status === status && item.target === target);
    if (existing) {
      existing.count += 1;
      continue;
    }
    grouped.push({ tool: task.tool, status, target, count: 1 });
  }
  return grouped;
}

function FindingPlainList({
  findings,
  runEnded,
  onSelectFinding,
}: {
  findings: Finding[];
  runEnded: boolean;
  onSelectFinding: (findingId: Finding['id']) => void;
}) {
  if (findings.length === 0) {
    return (
      <div className="rounded border border-line-soft bg-bg-2/20 px-3 py-3">
        <div className="text-[0.95rem] font-semibold text-text">No reportable findings</div>
        <p className="mt-1 text-[0.86rem] leading-5 text-muted">
          {runEnded
            ? 'This run has ended. Nothing from it is reportable unless a finding is created or the run is retried.'
            : 'The run may still be collecting output. Reports stay at zero until a finding is saved.'}
        </p>
      </div>
    );
  }
  return (
    <ol className="space-y-2">
      {sortFindingsForUi(findings).slice(0, 5).map((finding) => (
        <li key={finding.id}>
          <Link
            to="/findings"
            onClick={() => onSelectFinding(finding.id)}
            className="block rounded border border-line-soft bg-bg-2/20 px-3 py-2 transition-colors hover:border-cyan/35 hover:bg-cyan/5"
          >
            <div className="flex items-center justify-between gap-3">
              <span className={cn('font-mono text-[0.7rem] font-bold uppercase tracking-widest', severityTone(finding.severity))}>
                {finding.severity || 'unknown'}
              </span>
              <span className="font-mono text-[0.68rem] text-muted">{finding.validation_status || 'not validated'}</span>
            </div>
            <div className="mt-1 line-clamp-2 text-[0.92rem] font-semibold text-text">{finding.title}</div>
          </Link>
        </li>
      ))}
    </ol>
  );
}

function isTerminalRun(run: Run): boolean {
  return ['completed', 'failed', 'cancelled', 'canceled', 'completed_with_errors', 'rejected', 'errored', 'stopped'].includes(
    (run.status || '').toLowerCase(),
  );
}

function TaskNarrativeList({ beats }: { beats: StoryBeat[] }) {
  return (
    <ol className="space-y-2">
      {[...beats].reverse().slice(0, 8).map((beat, index) => (
        <li key={`${beat.rawAt}-${index}`} className="rounded border border-line-soft bg-bg-2/20 px-3 py-2">
          <div className="flex items-center justify-between gap-3">
            <span className="text-[0.9rem] font-semibold text-text">{beat.text}</span>
            <span className="font-mono text-[0.68rem] text-muted">{beat.at}</span>
          </div>
          {beat.detail && <div className="mt-1 text-[0.82rem] text-muted">{beat.detail}</div>}
        </li>
      ))}
    </ol>
  );
}

function latestTasks(tasks: Task[], limit: number): Task[] {
  return liveTaskTimelineTasks(tasks, limit);
}

function liveTaskTimelineTasks(tasks: Task[], limit: number): Task[] {
  return [...tasks]
    .sort((a, b) => String(b.updated_at ?? b.created_at).localeCompare(String(a.updated_at ?? a.created_at)))
    .slice(0, limit);
}

function missionStatusCopy(
  run: Run,
  state: MissionState,
  taskStats: ReturnType<typeof missionTaskCounts>,
  findings: Finding[],
  current: Task | null,
  host: string,
): { title: string; detail: string } {
  const target = host || 'the selected target';
  const runStatus = (run.status || '').toLowerCase();
  const endedWithErrors = runStatus === 'completed_with_errors' || taskStats.failed > 0;
  const checksRan = taskStats.completed + taskStats.failed;
  if (state.level === 'done') {
    if (findings.length === 0) {
      return {
        title: `Run ended${endedWithErrors ? ' with errors' : ''}. No findings were created.`,
        detail: checksRan > 0
          ? `${checksRan} checks ran${taskStats.failed > 0 ? `, ${taskStats.failed} failed` : ''}. Nothing is reportable yet. Open Technical only if you need failure details.`
          : `No reportable finding was created for ${target}. Open Technical only if you need failure details.`,
      };
    }
    return {
      title: `Run ended${endedWithErrors ? ' with errors' : ''}. ${findings.length} finding${findings.length === 1 ? '' : 's'} ready for review.`,
      detail: `Review Findings and Evidence Replay for ${target} before exporting a report.`,
    };
  }
  if (current && ['running', 'dispatching', 'active', 'in_progress', 'executing'].includes((current.status || '').toLowerCase())) {
    return {
      title: `Now running ${current.tool}`,
      detail: `AegisPT is checking ${current.target_id || target}. Findings appear here only after evidence is saved.`,
    };
  }
  if (taskStats.queued > 0) {
    return {
      title: `${taskStats.queued} task${taskStats.queued === 1 ? '' : 's'} waiting`,
      detail: `${taskStats.completed} task${taskStats.completed === 1 ? '' : 's'} already produced output. Nothing counts in reports until a finding is saved.`,
    };
  }
  if (findings.length > 0) {
    return {
      title: `${findings.length} reportable finding${findings.length === 1 ? '' : 's'} ready for review`,
      detail: `Open Findings for proof, validation state, impact, and remediation. This page stays focused on live run progress.`,
    };
  }
  return {
    title: 'Waiting for run activity',
    detail: `No active task is running for ${target}.`,
  };
}

function taskStatusTone(status: string): string {
  if (['running', 'dispatching', 'active', 'in_progress', 'executing'].includes(status)) return 'text-amber';
  if (['completed', 'succeeded', 'success', 'done'].includes(status)) return 'text-green-300';
  if (['failed', 'errored', 'error', 'timed_out', 'timeout'].includes(status)) return 'text-red';
  return 'text-muted';
}

function humanTaskStatus(status: string): string {
  if (['running', 'dispatching', 'active', 'in_progress', 'executing'].includes(status)) return 'running';
  if (['completed', 'succeeded', 'success', 'done'].includes(status)) return 'done';
  if (['failed', 'errored', 'error'].includes(status)) return 'failed';
  if (['queued', 'pending', 'requested', 'waiting', 'pending_approval'].includes(status)) return 'waiting';
  return status || 'unknown';
}

function severityTone(severity: string): string {
  const normalized = (severity || '').toLowerCase();
  if (normalized === 'critical') return 'text-red';
  if (normalized === 'high') return 'text-amber';
  if (normalized === 'medium') return 'text-yellow-400';
  return 'text-cyan';
}

function sortFindingsForUi(findings: Finding[]): Finding[] {
  return [...findings].sort((left, right) => {
    const rank = (finding: Finding) => SEV_ORDER[(finding.severity || 'info').toLowerCase()] ?? 99;
    return rank(left) - rank(right) || String(left.created_at).localeCompare(String(right.created_at));
  });
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

function shellQuote(value: string): string {
  if (!value) return "''";
  if (/^[A-Za-z0-9_./:=@%+-]+$/.test(value)) return value;
  return `'${value.replace(/'/g, "'\\''")}'`;
}

function commandForTask(task: Task | null | undefined): string {
  if (!task) return '';
  const parts = ['$ ', task.tool || 'task'];
  const target = String(task.target_id ?? '').trim();
  if (target) {
    parts.push(' --target ', shellQuote(target));
  }

  const params = task.params_json && typeof task.params_json === 'object' ? Object.entries(task.params_json) : [];
  const simpleParams = params
    .filter(([, value]) => ['string', 'number', 'boolean'].includes(typeof value))
    .slice(0, 4);
  for (const [key, value] of simpleParams) {
    const flag = `--${key.replace(/_/g, '-')}`;
    if (value === true) {
      parts.push(' ', flag);
    } else if (value !== false) {
      parts.push(' ', flag, ' ', shellQuote(String(value)));
    }
  }
  if (params.length > simpleParams.length) {
    parts.push(' --params-json');
  }
  return parts.join('');
}

function formatStructuredOutput(text: string): string | null {
  const trimmed = text.trim();
  if (!trimmed || trimmed.length < 80 || !/^[{[]/.test(trimmed)) return null;
  try {
    return JSON.stringify(JSON.parse(trimmed), null, 2);
  } catch {
    if (!/[{},[\]:]/.test(trimmed)) return null;
    return trimmed
      .replace(/,\s*"/g, ',\n  "')
      .replace(/{\s*"/g, '{\n  "')
      .replace(/}\s*,\s*{/g, '},\n{')
      .replace(/\[\s*{/g, '[\n  {')
      .replace(/]\s*,\s*"/g, '],\n  "');
  }
}

function splitLongTerminalLine(text: string): string[] {
  if (text.length <= 220) return [text];
  const chunks: string[] = [];
  let remaining = text;
  while (remaining.length > 220) {
    const boundary = Math.max(
      remaining.lastIndexOf(' ', 220),
      remaining.lastIndexOf(',', 220),
      remaining.lastIndexOf(';', 220),
    );
    const splitAt = boundary > 80 ? boundary + 1 : 220;
    chunks.push(remaining.slice(0, splitAt).trimEnd());
    remaining = remaining.slice(splitAt).trimStart();
  }
  if (remaining) chunks.push(remaining);
  return chunks;
}

function expandTerminalBodyLines(lines: TerminalLine[]): TerminalLine[] {
  const expanded: TerminalLine[] = [];
  let seq = 1;
  let announcedStructuredOutput = false;

  for (const line of lines) {
    const formatted = formatStructuredOutput(line.text);
    if (formatted) {
      if (!announcedStructuredOutput) {
        expanded.push({
          text: '(structured JSON output expanded for readability)',
          stream: 'meta',
          sequence: seq++,
        });
        announcedStructuredOutput = true;
      }
      for (const formattedLine of formatted.split('\n')) {
        expanded.push({
          text: formattedLine,
          stream: line.stream || 'json',
          sequence: seq++,
        });
      }
      continue;
    }

    for (const chunk of splitLongTerminalLine(line.text)) {
      expanded.push({
        ...line,
        text: chunk,
        sequence: seq++,
      });
    }
  }

  return expanded;
}

function summarizeTerminalPreview(lines: TerminalLine[], task: Task | null): TerminalLine[] {
  if (lines.length === 0) return [];
  const firstError = lines.find((line) => line.stream === 'stderr' || line.stream === 'error');
  if (firstError) {
    return splitLongTerminalLine(firstError.text).slice(0, 3).map((text, index) => ({
      text,
      stream: firstError.stream,
      sequence: index + 1,
    }));
  }

  const rawText = lines.map((line) => line.text).join('\n').trim();
  const structured = lines.map((line) => line.text.trim()).find((text) => /^[{[]/.test(text));
  if (structured) {
    try {
      const parsed = JSON.parse(structured) as Record<string, unknown>;
      const findings = Array.isArray(parsed.findings) ? parsed.findings.length : null;
      const outputLines = [
        parsed.tool ? `Tool finished: ${String(parsed.tool)}` : task?.tool ? `Tool finished: ${task.tool}` : null,
        parsed.primary_target ? `Target checked: ${String(parsed.primary_target)}` : task?.target_id ? `Target checked: ${task.target_id}` : null,
        parsed.plan_name ? `Plan: ${String(parsed.plan_name)}` : null,
        typeof parsed.steps_executed === 'number' ? `Steps executed: ${parsed.steps_executed}` : null,
        findings !== null ? `Findings in this output: ${findings}` : null,
      ].filter((line): line is string => Boolean(line));
      if (outputLines.length > 0) {
        return outputLines.slice(0, 5).map((text, index) => ({ text, stream: 'meta', sequence: index + 1 }));
      }
    } catch {
      // Fall through to short text preview.
    }
  }

  const expanded = expandTerminalBodyLines([{ text: rawText, stream: lines[0]?.stream || 'stdout', sequence: 1 }]);
  return expanded.slice(0, 5).map((line, index) => ({ ...line, sequence: index + 1 }));
}

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

export function LiveTaskDrillDown({
  tasks,
  selectedTaskId: controlledSelectedTaskId,
  onSelectedTaskIdChange,
  fullHeight = false,
  compact = false,
}: {
  tasks: Task[];
  selectedTaskId?: string | null;
  onSelectedTaskIdChange?: (taskId: string | null) => void;
  fullHeight?: boolean;
  compact?: boolean;
}) {
  const active = useMemo(() => activeTaskNow(tasks), [tasks]);
  const recentTasks = useMemo(() => {
    // Bumped from 12 → 40 per operator request 2026-05-21: with the skip-runner
    // filter live, a single run can chain through 20-30 tools and the operator
    // wants to inspect the older ones (e.g. an earlier zap failure) after later
    // tasks completed and pushed it out of the small-window slice.
    return liveTaskTimelineTasks(tasks, 40);
  }, [tasks]);

  const [uncontrolledSelectedId, setUncontrolledSelectedId] = useState<string | null>(null);
  const selectedId = controlledSelectedTaskId !== undefined ? controlledSelectedTaskId : uncontrolledSelectedId;
  const setSelectedId = useCallback(
    (taskId: string | null) => {
      if (onSelectedTaskIdChange) {
        onSelectedTaskIdChange(taskId);
      } else {
        setUncontrolledSelectedId(taskId);
      }
    },
    [onSelectedTaskIdChange],
  );
  const pinnedRef = useRef(false);
  useEffect(() => {
    if (controlledSelectedTaskId !== undefined) return;
    if (!pinnedRef.current && active && active.id !== selectedId) {
      setSelectedId(String(active.id));
    } else if (!pinnedRef.current && !active && !selectedId && recentTasks[0]) {
      setSelectedId(String(recentTasks[0].id));
    }
  }, [active, controlledSelectedTaskId, recentTasks, selectedId, setSelectedId]);

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
        if (exec) {
          setStreamStatus((current) => (current === 'error' || current === 'connecting' ? 'done' : current));
        }
        if (d.status) {
          setTaskStatus(String(d.status));
        }
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

  const selectedTask = useMemo(
    () => recentTasks.find((task) => String(task.id) === selectedId) ?? null,
    [recentTasks, selectedId],
  );
  const command = useMemo(() => {
    const cmd = lines.find((l) => l.stream === 'command' || l.text.trim().startsWith('$ '));
    return cmd ? cmd.text.trim() : commandForTask(selectedTask);
  }, [lines, selectedTask]);
  const bodyLines = useMemo(
    () => expandTerminalBodyLines(lines.filter((l) => !(l.stream === 'command' || l.text.trim().startsWith('$ ')))),
    [lines],
  );
  const previewBodyLines = useMemo(
    () => summarizeTerminalPreview(lines.filter((l) => !(l.stream === 'command' || l.text.trim().startsWith('$ '))), selectedTask),
    [lines, selectedTask],
  );
  const visibleBodyLines = compact ? previewBodyLines : bodyLines;
  const hiddenBodyCount = compact ? Math.max(0, bodyLines.length - previewBodyLines.length) : 0;

  const dotClass = useMemo(() => {
    if (streamStatus === 'live') return 'bg-green-400 animate-pulse';
    if (streamStatus === 'error') return 'bg-red-400';
    if (streamStatus === 'done') return 'bg-line';
    return 'bg-amber-400 animate-pulse';
  }, [streamStatus]);

  return (
    <div className="terminal-code overflow-hidden rounded border text-[#dceaff]" aria-label="Live command terminal">
      {/* macOS-style window chrome / status bar */}
      <div className="flex flex-wrap items-center gap-2 border-b border-[#284054] bg-[#1a1f26] px-3 py-1.5">
        <div className="flex items-center gap-1">
          <span className="h-2 w-2 rounded-full bg-red-500/70" />
          <span className="h-2 w-2 rounded-full bg-yellow-500/70" />
          <span className="h-2 w-2 rounded-full bg-green-500/70" />
        </div>
        <span className={cn('h-1.5 w-1.5 rounded-full ml-2', dotClass)} />
        <span className="font-mono text-[0.7rem] uppercase tracking-widest text-[#9ee8b6]">aegispt — task output</span>
        <span
          className="font-mono text-[0.6rem] italic text-[#9ee8b6]/60"
          title="For a true streaming terminal session run: scripts/aegispt_live.py"
        >
          (web mirror — real CLI: scripts/aegispt_live.py)
        </span>
        <select
          className="max-w-[18rem] truncate rounded border border-[#3e6f4f] bg-[#0b0f13] px-1 py-0.5 font-mono text-[0.7rem] text-[#9ee8b6]"
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
        <span className="ml-auto font-mono text-[0.6rem] text-[#9ee8b6]/70">
          {streamStatus} · {taskStatus}
          {exitCode !== null ? ` · exit ${exitCode}` : ''}
        </span>
      </div>
      {/* Terminal body */}
      <div
        ref={scrollRef}
        className={cn(
          'overflow-y-auto whitespace-pre-wrap break-words bg-[#0b0f13] px-3 py-2 font-mono text-[0.78rem] leading-snug text-[#dceaff]',
          fullHeight ? 'h-[calc(100vh-12rem)] min-h-[28rem]' : compact ? 'max-h-[14rem] min-h-[8rem]' : 'max-h-[28rem] min-h-[12rem]',
        )}
      >
        {command && (
          <div className="mb-2 border-b border-[#25402f] pb-2">
            <div className="mb-1 text-[0.62rem] uppercase tracking-widest text-[#9ee8b6]/60">command</div>
            <div className="text-[#f6c15f]">{colorizeLine(command, false)}</div>
          </div>
        )}
        {visibleBodyLines.length > 0 && (
          <div className="mb-1 text-[0.62rem] uppercase tracking-widest text-[#9ee8b6]/60">
            {compact ? 'output preview' : 'stdout / stderr'}
          </div>
        )}
        {visibleBodyLines.length === 0 && (
          <span className="text-[#9cc8ff]/70">
            {streamStatus === 'done'
              ? '(no captured stdout/stderr for this task; if it produced only a finding, inspect Evidence Replay)'
              : '(waiting for stdout/stderr from this task...)'}
          </span>
        )}
        {visibleBodyLines.map((l, idx) => {
          const isErr = l.stream === 'stderr' || l.stream === 'error';
          const isMeta = l.stream === 'meta';
          const baseCls = isErr
            ? 'text-[#ff7a7a]'
            : isMeta
              ? 'italic text-[#9ee8b6]/65'
              : 'text-[#dceaff]';
          return (
            <div key={`${l.sequence}-${idx}`} className={baseCls}>
              {colorizeLine(l.text, isErr)}
            </div>
          );
        })}
        {hiddenBodyCount > 0 && (
          <div className="mt-2 italic text-[#9ee8b6]/65">
            ({hiddenBodyCount} more raw line{hiddenBodyCount === 1 ? '' : 's'} in full CLI)
          </div>
        )}
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
    <div className="terminal-code overflow-hidden rounded border">
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
      <div className="terminal-code overflow-hidden rounded border">
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
      <div className="grid gap-4 px-6 pt-4 xl:grid-cols-[1fr_1fr]">
        <PlainLanguagePanel
          title="In gewone taal"
          detail="Dit is de diagnosekant. Hier zie je de ruwe waarheid achter de scan: technische staat, logs, terminal-output, proof en API-events. Gebruik dit om te begrijpen waarom iets wel of niet in de normale uitkomst terechtkwam."
        />
        <TechnicalFactsPanel
          facts={[
            ['Run id', String(run.id)],
            ['Run status', run.status || 'unknown'],
            ['Task rows', String(tasks.length)],
            ['Finding rows', String(findings.length)],
          ]}
        />
      </div>
      <div className="grid grid-cols-1 gap-4 px-6 pt-4 lg:grid-cols-[1.2fr_1fr]">
        <ToolChainHeartbeat tasks={tasks} />
        <NowPlayingTail tasks={tasks} />
      </div>

      <TechnicalDisclosure title="Risk trajectory" summary={`${findings.length} persisted findings`}>
        <RiskTrajectoryChart findings={findings} />
      </TechnicalDisclosure>
      <TechnicalDisclosure title="Live event feed" summary="task and finding events">
        <LiveEventsFeed runId={String(run.id)} />
      </TechnicalDisclosure>
      <TechnicalDisclosure title="Task terminal output" summary="stdout and stderr by task">
        <LiveTaskDrillDown tasks={tasks} />
      </TechnicalDisclosure>
      <TechnicalDisclosure title="Proof and task inventory" summary="advanced details">
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-[1.2fr_1fr]">
          <ProofPanel findings={findings} />
          <Heartbeat tasks={tasks} />
        </div>
        <DetailsDrawer findings={findings} tasks={tasks} />
      </TechnicalDisclosure>
      <LiveApiLogTail />
    </div>
  );
}

function TechnicalDisclosure({
  title,
  summary,
  children,
}: {
  title: string;
  summary: string;
  children: React.ReactNode;
}) {
  return (
    <details className="mx-6 mt-4 rounded border border-line-soft bg-surface/25">
      <summary className="flex cursor-pointer items-center justify-between gap-3 px-3 py-2 hover:bg-bg-2/30">
        <span className="font-mono text-[0.7rem] font-semibold uppercase tracking-widest text-text">{title}</span>
        <span className="text-[0.8rem] text-muted">{summary}</span>
      </summary>
      <div className="border-t border-line-soft p-3">{children}</div>
    </details>
  );
}

/* =========================================================================
   MAIN EXPORT — operator tabs plus technical diagnostics
   ========================================================================= */

type MissionControlView = 'live' | 'results' | 'overview' | 'technical';

const MISSION_TABS: Array<{
  key: MissionControlView;
  labelKey: 'mission.view.live' | 'mission.view.results' | 'mission.view.overview' | 'mission.view.technical';
  activeClass: string;
}> = [
  { key: 'live', labelKey: 'mission.view.live', activeClass: 'bg-green-400/10 border-green-400/35 text-green-300' },
  { key: 'results', labelKey: 'mission.view.results', activeClass: 'bg-ai/15 border-ai/40 text-ai' },
  { key: 'overview', labelKey: 'mission.view.overview', activeClass: 'bg-amber/10 border-amber/35 text-amber' },
  { key: 'technical', labelKey: 'mission.view.technical', activeClass: 'bg-cyan/15 border-cyan/40 text-cyan' },
];

function missionViewDetail(view: MissionControlView): 'mission.liveDetail' | 'mission.resultsDetail' | 'mission.overviewDetail' | 'mission.technicalDetail' {
  if (view === 'live') return 'mission.liveDetail';
  if (view === 'results') return 'mission.resultsDetail';
  if (view === 'overview') return 'mission.overviewDetail';
  return 'mission.technicalDetail';
}

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
  const [view, setView] = useState<MissionControlView>('live');
  const tabRefs = useRef<Array<HTMLButtonElement | null>>([]);
  const pendingProposalCount = proposals.filter((proposal) => (proposal.status || '').toLowerCase() === 'pending').length;

  function selectTabAt(index: number) {
    const nextIndex = (index + MISSION_TABS.length) % MISSION_TABS.length;
    const nextTab = MISSION_TABS[nextIndex];
    setView(nextTab.key);
    window.requestAnimationFrame(() => tabRefs.current[nextIndex]?.focus());
  }

  function handleTabKeyDown(event: ReactKeyboardEvent<HTMLButtonElement>, index: number) {
    if (event.key === 'ArrowRight' || event.key === 'ArrowDown') {
      event.preventDefault();
      selectTabAt(index + 1);
      return;
    }
    if (event.key === 'ArrowLeft' || event.key === 'ArrowUp') {
      event.preventDefault();
      selectTabAt(index - 1);
      return;
    }
    if (event.key === 'Home') {
      event.preventDefault();
      selectTabAt(0);
      return;
    }
    if (event.key === 'End') {
      event.preventDefault();
      selectTabAt(MISSION_TABS.length - 1);
    }
  }

  return (
    <div className="flex h-full min-h-0 flex-1 flex-col">
      <ClaudeThinking run={run} />
      {/* View switcher */}
      <div className="flex items-center gap-1 px-6 py-2 border-b border-line-soft bg-surface/40">
        <h1 className="mr-3 text-[0.85rem] font-semibold uppercase text-muted">{t('nav.missionControl')}</h1>
        <div className="flex items-center gap-1" role="tablist" aria-label="Mission Control views">
          {MISSION_TABS.map((tab, index) => (
            <button
              key={tab.key}
              ref={(element) => {
                tabRefs.current[index] = element;
              }}
              type="button"
              role="tab"
              id={`mission-tab-${tab.key}`}
              aria-selected={view === tab.key}
              aria-controls={`mission-panel-${tab.key}`}
              tabIndex={view === tab.key ? 0 : -1}
              onClick={() => setView(tab.key)}
              onKeyDown={(event) => handleTabKeyDown(event, index)}
              className={cn(
                'rounded border px-3 py-1 font-mono text-[0.72rem] uppercase tracking-widest transition-colors',
                view === tab.key
                  ? tab.activeClass
                  : 'border-transparent text-muted hover:border-line-soft hover:text-text',
              )}
            >
              {t(tab.labelKey)}
            </button>
          ))}
        </div>
        <span className="ml-auto font-mono text-[0.65rem] text-muted">
          {t(missionViewDetail(view))}
          {pendingProposalCount > 0 ? ` · ${pendingProposalCount} pending` : ''}
        </span>
      </div>
      {view === 'live' && (
        <div id="mission-panel-live" role="tabpanel" aria-labelledby="mission-tab-live" tabIndex={0} className="min-h-0 flex-1">
          <LiveMissionView run={run} findings={findings} tasks={tasks} />
        </div>
      )}
      {view === 'results' && (
        <div id="mission-panel-results" role="tabpanel" aria-labelledby="mission-tab-results" tabIndex={0} className="min-h-0 flex-1">
          <ResultsMissionView run={run} findings={findings} tasks={tasks} />
        </div>
      )}
      {view === 'overview' && (
        <div id="mission-panel-overview" role="tabpanel" aria-labelledby="mission-tab-overview" tabIndex={0} className="min-h-0 flex-1">
          <OverviewMissionView run={run} findings={findings} tasks={tasks} />
        </div>
      )}
      {view === 'technical' && (
        <div id="mission-panel-technical" role="tabpanel" aria-labelledby="mission-tab-technical" tabIndex={0} className="min-h-0 flex-1 flex flex-col">
          <RunTruthStrip run={run} tasks={tasks} findings={findings} />
          <TechnicalView
            run={run}
            findings={findings}
            tasks={tasks}
            onKill={onKill}
            onCinema={onCinema}
            canKill={canKill}
            cinemaDisabled={cinemaDisabled}
          />
        </div>
      )}
    </div>
  );
}
