import { Activity, Archive, Command, Eye, FileText, GitBranch, PlayCircle, ShieldAlert } from 'lucide-react';
import type { Finding, InventorySnapshot, Run, Task } from '../api/types';
import { humanizeMissionValue, safeMissionFindingTitle, summarizeMissionTarget } from '../viewModels/missionStory';

type NavigateTarget = '/mission-control' | '/live-cli' | '/evidence' | '/findings' | '/reports';

type ExperienceStage = 'idle' | 'live' | 'evidence' | 'findings' | 'report';
type StageState = 'done' | 'active' | 'waiting';

type MissionExperienceSpineProps = {
  run: Run | null;
  tasks: Task[];
  findings: Finding[];
  inventory: InventorySnapshot | null;
  currentPath?: string;
  onNavigate: (target: NavigateTarget) => void;
};

const terminalStatuses = new Set(['completed', 'completed_with_errors', 'failed', 'cancelled', 'rejected']);
const activeStatuses = new Set(['queued', 'dispatching', 'running', 'pending_approval', 'cancelling']);

export default function MissionExperienceSpine({
  run,
  tasks,
  findings,
  inventory,
  currentPath,
  onNavigate,
}: MissionExperienceSpineProps) {
  if (!run) return null;

  const model = buildMissionExperience(run, tasks, findings, inventory, currentPath);
  const presentation = missionSpinePresentationForPath(currentPath);

  if (presentation.compact) {
    return (
      <CompactMissionExperienceSpine
        model={model}
        variantLabel={presentation.label}
        onNavigate={onNavigate}
      />
    );
  }

  return (
    <section
      className="mission-experience-spine mb-5 rounded-lg border border-cyan/20 bg-panel/92 p-4 shadow-[0_0_2rem_var(--panel-glow)]"
      aria-label="Mission story"
    >
      <div className="grid gap-3 xl:grid-cols-[minmax(18rem,0.9fr),minmax(30rem,1.45fr),minmax(16rem,0.82fr)] xl:items-stretch">
        <button
          type="button"
          onClick={() => onNavigate('/mission-control')}
          aria-label={`You are here: ${model.title}`}
          className="group mission-experience-presence min-w-0 rounded-md border border-cyan/10 bg-bg/20 p-3 text-left transition hover:border-cyan/35 hover:bg-cyan/7"
        >
          <div className="mb-2 flex items-center justify-between gap-2">
            <span className="font-mono text-[0.64rem] uppercase tracking-[0.22em] text-cyan/80">You are here</span>
            <span className="rounded-full border border-cyan/20 bg-cyan/7 px-2 py-0.5 font-mono text-[0.6rem] uppercase tracking-[0.18em] text-cyan/80">
              {model.sceneLabel}
            </span>
          </div>
          <div className="flex items-start gap-3">
            <span className={`mission-experience-orb ${model.stage}`} aria-hidden="true">
              <span />
            </span>
            <div className="min-w-0">
              <div className="line-clamp-2 text-[1.05rem] font-semibold leading-snug text-text group-hover:text-cyan">{model.title}</div>
              <div className="mt-1 line-clamp-2 text-sm text-muted">{model.humanLine}</div>
            </div>
          </div>
          <div className="mt-4 grid grid-cols-3 gap-2">
            {model.situationFacts.map((fact) => (
              <SpineFact key={fact.label} label={fact.label} value={fact.value} />
            ))}
          </div>
        </button>

        <div className="mission-experience-route min-w-0 rounded-md border border-cyan/10 bg-bg/35 p-3" aria-label="Mission route">
          <div className="mb-3 flex items-center justify-between gap-3">
            <div className="flex items-center gap-2">
              <GitBranch size={15} className="text-cyan" />
              <span className="font-mono text-[0.64rem] uppercase tracking-[0.22em] text-cyan/80">Route</span>
            </div>
            <span className="font-mono text-[0.64rem] uppercase tracking-[0.18em] text-muted">{model.progressLabel}</span>
          </div>
          <div className="mission-experience-rail" aria-hidden="true">
            {model.stages.map((stage, index) => (
              <div key={stage.id} className="mission-experience-stage">
                <div className={`mission-experience-dot ${stage.state}`} />
                {index < model.stages.length - 1 && <div className={`mission-experience-line ${stage.state}`} />}
              </div>
            ))}
          </div>
          <div className="mt-2 grid grid-cols-4 gap-2">
            {model.stages.map((stage) => (
              <button
                key={stage.id}
                type="button"
                onClick={() => onNavigate(stage.target)}
                aria-label={`Mission route step ${stage.label}: ${stage.value}`}
                aria-current={stage.state === 'active' ? 'step' : undefined}
                className={`mission-experience-stage-card rounded-md border px-2 py-2 text-left transition-colors ${stage.cardClass}`}
              >
                <div className="flex items-center justify-between gap-2">
                  <div className="font-mono text-[0.62rem] uppercase tracking-[0.18em] text-muted">{stage.label}</div>
                  <span className={`mission-experience-mini-dot ${stage.state}`} aria-hidden="true" />
                </div>
                <div className="mt-1 truncate text-sm font-semibold text-text">{stage.value}</div>
                <div className="mt-1 line-clamp-1 text-[0.72rem] text-muted">{stage.detail}</div>
              </button>
            ))}
          </div>
          <div
            className="mission-experience-meter mt-3"
            role="progressbar"
            aria-label="Mission route progress"
            aria-valuemin={0}
            aria-valuemax={100}
            aria-valuenow={model.progressPercent}
          >
            <div style={{ width: `${model.progressPercent}%` }} />
          </div>
        </div>

        <div className="mission-experience-next min-w-0 rounded-md border border-cyan/10 bg-bg/20 p-3">
          <div className="mb-2 flex items-center gap-2">
            <PlayCircle size={15} className="text-cyan" />
            <span className="font-mono text-[0.64rem] uppercase tracking-[0.22em] text-cyan/80">Your next move</span>
          </div>
          <div className="mb-3 line-clamp-3 text-sm font-medium text-text">{model.nextCue}</div>
          <div className="mb-3 grid grid-cols-3 gap-2">
            {model.decisionFacts.map((fact) => (
              <SpineFact key={fact.label} label={fact.label} value={fact.value} tone={fact.tone} />
            ))}
          </div>
          <div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-1 2xl:grid-cols-2">
            {model.actions.map((action) => (
              <button
                key={action.target}
                type="button"
                onClick={() => onNavigate(action.target)}
                className="inline-flex items-center justify-center gap-2 rounded-md border border-cyan/25 bg-cyan/7 px-3 py-2 text-sm font-semibold text-cyan transition hover:border-cyan/45 hover:bg-cyan/12"
              >
                <action.icon size={15} />
                {action.label}
              </button>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}

type MissionExperienceModel = ReturnType<typeof buildMissionExperience>;

function CompactMissionExperienceSpine({
  model,
  variantLabel,
  onNavigate,
}: {
  model: MissionExperienceModel;
  variantLabel: string;
  onNavigate: (target: NavigateTarget) => void;
}) {
  const primaryAction = model.actions[0];
  const secondaryAction = model.actions[1];

  return (
    <section
      className="mission-experience-spine mb-4 rounded-lg border border-cyan/15 bg-panel/86 p-3 shadow-[0_0_1.4rem_var(--panel-glow)]"
      aria-label="Mission context"
    >
      <div className="flex flex-col gap-3 2xl:flex-row 2xl:items-center">
        <button
          type="button"
          onClick={() => onNavigate('/mission-control')}
          aria-label={`Open Mission Control: ${model.title}`}
          className="group flex min-w-0 flex-1 items-start gap-3 rounded-md border border-cyan/10 bg-bg/20 px-3 py-2.5 text-left transition hover:border-cyan/35 hover:bg-cyan/7"
        >
          <span className={`mission-experience-orb ${model.stage} mt-0.5`} aria-hidden="true">
            <span />
          </span>
          <span className="min-w-0 flex-1">
            <span className="flex items-center gap-2">
              <span className="font-mono text-[0.62rem] uppercase tracking-[0.2em] text-cyan/80">{variantLabel}</span>
              <span className="rounded-full border border-cyan/15 bg-cyan/7 px-2 py-0.5 font-mono text-[0.56rem] uppercase tracking-[0.16em] text-muted">
                {model.sceneLabel}
              </span>
            </span>
            <span className="mt-1 block truncate text-[0.98rem] font-semibold text-text group-hover:text-cyan">{model.title}</span>
            <span className="mt-0.5 block line-clamp-1 text-[0.82rem] text-muted">{model.humanLine}</span>
          </span>
        </button>

        <div className="grid min-w-0 gap-2 sm:grid-cols-3 2xl:w-[28rem]" aria-label="Mission summary">
          {model.situationFacts.map((fact) => (
            <SpineFact key={fact.label} label={fact.label} value={fact.value} />
          ))}
        </div>

        <div className="flex shrink-0 flex-col gap-2 sm:flex-row 2xl:w-[20rem]">
          {primaryAction ? (
            <button
              type="button"
              onClick={() => onNavigate(primaryAction.target)}
              aria-label={`Primary mission action: ${primaryAction.label}`}
              className="inline-flex flex-1 items-center justify-center gap-2 rounded-md border border-cyan/30 bg-cyan/10 px-3 py-2 text-sm font-semibold text-cyan transition hover:border-cyan/50 hover:bg-cyan/15"
            >
              <primaryAction.icon size={15} />
              {primaryAction.label}
            </button>
          ) : (
            <div className="rounded-md border border-cyan/10 bg-bg/25 px-3 py-2 text-sm font-semibold text-muted">Nothing to do</div>
          )}
          {secondaryAction && (
            <button
              type="button"
              onClick={() => onNavigate(secondaryAction.target)}
              aria-label={`Secondary mission action: ${secondaryAction.label}`}
              className="inline-flex flex-1 items-center justify-center gap-2 rounded-md border border-border bg-bg/25 px-3 py-2 text-sm font-semibold text-muted transition hover:border-cyan/35 hover:text-cyan"
            >
              <secondaryAction.icon size={15} />
              {secondaryAction.label}
            </button>
          )}
        </div>
      </div>
    </section>
  );
}

function SpineFact({ label, value, tone = 'neutral' }: { label: string; value: string; tone?: 'neutral' | 'good' | 'warn' | 'risk' }) {
  const toneClass = tone === 'good'
    ? 'border-green-300/20 bg-green-300/7 text-green-300'
    : tone === 'warn'
      ? 'border-amber/20 bg-amber/7 text-amber'
      : tone === 'risk'
        ? 'border-red/20 bg-red/7 text-red'
        : 'border-cyan/10 bg-bg/25 text-text';
  return (
    <div className={`min-w-0 rounded-md border px-2 py-2 ${toneClass}`}>
      <div className="font-mono text-[0.56rem] uppercase tracking-[0.18em] text-muted">{label}</div>
      <div className="mt-1 truncate text-[0.82rem] font-semibold">{value}</div>
    </div>
  );
}

function buildMissionExperience(
  run: Run,
  tasks: Task[],
  findings: Finding[],
  inventory: InventorySnapshot | null,
  currentPath = '',
) {
  const status = String(run.status || '').toLowerCase();
  const isTerminal = terminalStatuses.has(status);
  const running = tasks.filter((task) => ['running', 'dispatching'].includes(String(task.status).toLowerCase()));
  const queued = tasks.filter((task) => ['queued', 'pending_approval'].includes(String(task.status).toLowerCase()));
  const completed = tasks.filter((task) => ['completed', 'done', 'success', 'succeeded'].includes(String(task.status).toLowerCase()));
  const failed = tasks.filter((task) => ['failed', 'error'].includes(String(task.status).toLowerCase()));
  const criticalHigh = findings.filter((finding) => ['critical', 'high'].includes(String(finding.severity).toLowerCase()));
  const reportable = findings.filter((finding) => String(finding.status || '').toLowerCase() !== 'false_positive');
  const topFinding = strongestFinding(reportable);
  const evidenceCount = completed.length + failed.length;
  const currentTool = running[0]?.tool || queued[0]?.tool || completed[completed.length - 1]?.tool || 'mission';
  const target = summarizeTarget(run, inventory);
  const runStage: ExperienceStage = activeStatuses.has(status) || (!isTerminal && (running.length > 0 || queued.length > 0))
      ? 'live'
      : reportable.length > 0
        ? 'report'
        : isTerminal
          ? 'findings'
          : 'evidence';
  const screenContext = screenContextForPath(currentPath, {
    evidenceCount,
    failed: failed.length,
    reportable: reportable.length,
    target,
    topFinding,
  });
  const stage = screenContext?.stage ?? runStage;
  const title = screenContext?.title ?? titleForStage(stage, status, currentTool, reportable.length);
  const humanLine = screenContext?.humanLine ?? humanLineForStage({
    stage,
    target,
    running: running.length,
    queued: queued.length,
    completed: completed.length,
    failed: failed.length,
    reportable: reportable.length,
    criticalHigh: criticalHigh.length,
    topFinding,
  });
  const nextCue = screenContext?.nextCue ?? nextCueForStage(stage, reportable.length, failed.length);

  return {
    stage,
    title,
    humanLine,
    nextCue,
    sceneLabel: sceneLabelForStage(stage),
    progressLabel: `${evidenceCount} checked · ${reportable.length} finding${reportable.length === 1 ? '' : 's'}`,
    progressPercent: progressPercentForStage(stage),
    situationFacts: [
      { label: 'Target', value: target },
      { label: 'Checked', value: `${evidenceCount}/${Math.max(tasks.length, evidenceCount) || 0}` },
      { label: 'Proof', value: reportable.length ? `${reportable.length} saved` : 'none yet' },
    ],
    decisionFacts: [
      {
        label: 'Risk',
        value: riskLabel(topFinding),
        tone: topFinding && ['critical', 'high'].includes(String(topFinding.severity).toLowerCase()) ? 'risk' as const : 'neutral' as const,
      },
      { label: 'Evidence', value: evidenceCount > 0 ? `${evidenceCount} trail${evidenceCount === 1 ? '' : 's'}` : 'waiting', tone: evidenceCount > 0 ? 'good' as const : 'neutral' as const },
      { label: 'Report', value: reportable.length ? 'ready' : 'not yet', tone: reportable.length ? 'good' as const : 'warn' as const },
    ],
    stages: [
      stageModel('Live', liveValue(running.length, queued.length, status), liveDetail(running.length, queued.length), '/mission-control', stageState(stage, 'live')),
      stageModel('Evidence', `${evidenceCount} checked`, evidenceDetail(completed.length, failed.length), '/evidence', stageState(stage, 'evidence')),
      stageModel('Findings', reportable.length ? `${reportable.length} reportable` : 'none yet', findingsDetail(criticalHigh.length), '/findings', stageState(stage, 'findings')),
      stageModel('Report', reportable.length ? 'ready to review' : 'waiting', reportable.length ? 'same proof path' : 'needs finding', '/reports', stageState(stage, 'report')),
    ],
    actions: actionsForStage(stage, reportable.length),
  };
}

function missionSpinePresentationForPath(path = ''): { compact: boolean; label: string } {
  const normalized = path.replace(/^\/app-v2/, '') || '/';
  if (normalized.startsWith('/live-cli')) return { compact: true, label: 'Diagnostics context' };
  if (normalized.startsWith('/intake')) return { compact: true, label: 'Mission setup' };
  if (normalized.startsWith('/packs')) return { compact: true, label: 'Build context' };
  if (normalized.startsWith('/cve-library')) return { compact: true, label: 'Knowledge context' };
  if (normalized.startsWith('/research')) return { compact: true, label: 'Research context' };
  if (normalized.startsWith('/settings')) return { compact: true, label: 'Admin context' };
  return { compact: false, label: 'Mission context' };
}

function screenContextForPath(
  path: string,
  input: {
    evidenceCount: number;
    failed: number;
    reportable: number;
    target: string;
    topFinding: Finding | null;
  },
): { stage: ExperienceStage; title: string; humanLine: string; nextCue: string } | null {
  const normalized = path.replace(/^\/app-v2/, '') || '/';
  const lead = input.topFinding ? safeFindingTitle(input.topFinding) : 'the strongest saved proof';
  if (normalized.startsWith('/intake')) {
    return {
      stage: 'live',
      title: 'You are preparing a mission',
      humanLine: `Define scope and approval before AegisPT starts work on ${input.target}.`,
      nextCue: 'Create a mission only after the target, authorization, and guardrails are clear.',
    };
  }
  if (normalized.startsWith('/live-cli')) {
    return {
      stage: 'live',
      title: 'You are watching raw output',
      humanLine: `This is the technical feed for ${input.target}. Use it when the route needs command-level proof.`,
      nextCue: input.reportable > 0
        ? 'Raw output is available; the next decision still belongs in Findings and Reports.'
        : 'Watch for output, but wait for persistence before treating it as a finding.',
    };
  }
  if (normalized.startsWith('/surface-map')) {
    return {
      stage: 'evidence',
      title: 'You are mapping the surface',
      humanLine: `This view explains what AegisPT saw around ${input.target} before proof was selected.`,
      nextCue: 'Use the surface map to understand entry points, then replay evidence or review findings.',
    };
  }
  if (normalized.startsWith('/evidence')) {
    return {
      stage: 'evidence',
      title: 'You are replaying the proof trail',
      humanLine: `${input.evidenceCount} recorded step${input.evidenceCount === 1 ? '' : 's'} explain how this run moved from test activity to evidence.`,
      nextCue: input.reportable > 0
        ? 'Open the relevant evidence step, then continue to Findings for impact and remediation.'
        : 'Replay the stopped paths before deciding whether this was a dead end.',
    };
  }
  if (normalized.startsWith('/findings') || normalized.startsWith('/problems')) {
    return {
      stage: 'findings',
      title: input.reportable > 0 ? 'You are deciding what counts' : 'You are checking for saved proof',
      humanLine: input.reportable > 0
        ? `Start with ${lead}. Findings are the proof objects that become reportable risk.`
        : 'No saved finding is available yet; use evidence and live output before making a claim.',
      nextCue: input.reportable > 0
        ? 'Review proof, business impact, and remediation before building the report.'
        : 'Return to Evidence Replay or Mission Control to inspect unfinished paths.',
    };
  }
  if (normalized.startsWith('/reports')) {
    return {
      stage: 'report',
      title: input.reportable > 0 ? 'You are turning proof into a report' : 'The report waits for proof',
      humanLine: input.reportable > 0
        ? `${input.reportable} saved finding${input.reportable === 1 ? '' : 's'} can now be phrased for the right audience without inventing facts.`
        : 'Reports stay blocked until evidence becomes a saved finding.',
      nextCue: input.reportable > 0
        ? 'Choose the audience, preview the report, and export only from canonical evidence.'
        : 'Go back to Findings or Evidence Replay before exporting.',
    };
  }
  if (normalized.startsWith('/history')) {
    return {
      stage: 'report',
      title: 'You are reviewing the mission memory',
      humanLine: `History connects the route, evidence, findings, and report trail for ${input.target}.`,
      nextCue: 'Use history to audit what changed, then return to the active decision surface.',
    };
  }
  if (normalized.startsWith('/packs')) {
    return {
      stage: input.reportable > 0 ? 'report' : 'evidence',
      title: 'You are managing test capabilities',
      humanLine: 'Capability packs prepare allowed checks; they do not change a running mission by themselves.',
      nextCue: 'Review pack health, then return to the mission story when runtime evidence is needed.',
    };
  }
  if (normalized.startsWith('/cve-library')) {
    return {
      stage: input.reportable > 0 ? 'report' : 'evidence',
      title: 'You are reviewing custom CVE knowledge',
      humanLine: 'The library keeps reusable vulnerability knowledge separate from this run’s saved proof.',
      nextCue: 'Use CVE knowledge to guide scope, then confirm impact through evidence-backed findings.',
    };
  }
  if (normalized.startsWith('/research')) {
    return {
      stage: input.reportable > 0 ? 'report' : 'evidence',
      title: 'You are curating research context',
      humanLine: 'Research helps explain technology and risk, but reports still depend on saved findings.',
      nextCue: 'Use research as context; use Findings and Evidence Replay for claims about this target.',
    };
  }
  if (normalized.startsWith('/settings')) {
    return {
      stage: input.reportable > 0 ? 'report' : 'evidence',
      title: 'You are configuring the workspace',
      humanLine: 'Settings control operators, providers, and integrations without rewriting mission evidence.',
      nextCue: 'Adjust configuration, then return to the active mission decision surface.',
    };
  }
  return null;
}

function stageModel(label: string, value: string, detail: string, target: NavigateTarget, state: StageState) {
  const cardClass = state === 'active'
    ? 'border-cyan/40 bg-cyan/10'
    : state === 'done'
      ? 'border-emerald/25 bg-emerald/7'
      : 'border-border bg-bg/30 hover:border-cyan/30';
  return {
    id: label.toLowerCase(),
    label,
    value,
    detail,
    target,
    state,
    cardClass,
  };
}

function stageState(current: ExperienceStage, stage: ExperienceStage): StageState {
  const order: ExperienceStage[] = ['live', 'evidence', 'findings', 'report'];
  const currentIndex = order.indexOf(current);
  const stageIndex = order.indexOf(stage);
  if (currentIndex < 0 || stageIndex < 0) return 'waiting';
  if (stageIndex < currentIndex) return 'done';
  if (stageIndex === currentIndex) return 'active';
  return 'waiting';
}

function actionsForStage(stage: ExperienceStage, reportableCount: number) {
  if (stage === 'live') {
    return reportableCount > 0 ? [
      { label: 'Watch live', target: '/mission-control' as const, icon: Activity },
      { label: 'Review findings', target: '/findings' as const, icon: ShieldAlert },
    ] : [
      { label: 'Watch live', target: '/mission-control' as const, icon: Activity },
      { label: 'Open CLI', target: '/live-cli' as const, icon: Command },
    ];
  }
  if (reportableCount > 0) {
    return [
      { label: 'Review findings', target: '/findings' as const, icon: ShieldAlert },
      { label: 'Build report', target: '/reports' as const, icon: FileText },
    ];
  }
  return [
    { label: 'Replay evidence', target: '/evidence' as const, icon: Archive },
    { label: 'See results', target: '/mission-control' as const, icon: Eye },
  ];
}

function titleForStage(stage: ExperienceStage, status: string, tool: string, reportable: number): string {
  if (stage === 'live') return `Testing ${humanize(tool)}`;
  if (stage === 'report') return reportable === 1 ? 'Ready for review: 1 result' : `Ready for review: ${reportable} results`;
  if (stage === 'findings' && terminalStatuses.has(status)) return 'Run ended without reportable proof';
  return 'Evidence is being assembled';
}

function humanLineForStage(input: {
  stage: ExperienceStage;
  target: string;
  running: number;
  queued: number;
  completed: number;
  failed: number;
  reportable: number;
  criticalHigh: number;
  topFinding: Finding | null;
}): string {
  if (input.stage === 'live') {
    return `${input.running || input.queued || 1} task moving on ${input.target}. Saved findings become the report story.`;
  }
  if (input.reportable > 0) {
    const finding = input.topFinding ? safeFindingTitle(input.topFinding) : 'the strongest finding';
    return `Lead: ${finding}. ${input.criticalHigh} high-priority item(s) need review.`;
  }
  if (input.failed > 0) {
    return `${input.completed} checks finished; ${input.failed} path(s) stopped. Replay evidence before deciding next steps.`;
  }
  return `${input.completed} checks have evidence. No saved finding yet, so this is still a review point.`;
}

function liveValue(running: number, queued: number, status: string): string {
  if (running > 0) return `${running} running`;
  if (queued > 0) return `${queued} waiting`;
  return humanize(status || 'idle');
}

function liveDetail(running: number, queued: number): string {
  if (running > 0) return 'system moving';
  if (queued > 0) return 'waiting turn';
  return 'no task now';
}

function evidenceDetail(completed: number, failed: number): string {
  if (failed > 0) return `${failed} stopped`;
  if (completed > 0) return 'linked output';
  return 'no trail yet';
}

function findingsDetail(criticalHigh: number): string {
  if (criticalHigh > 0) return `${criticalHigh} high risk`;
  return 'review state';
}

function riskLabel(finding: Finding | null): string {
  if (!finding) return 'none';
  const severity = String(finding.severity || 'info').toLowerCase();
  if (severity === 'critical') return 'critical';
  if (severity === 'high') return 'high';
  if (severity === 'medium') return 'medium';
  return severity;
}

function strongestFinding(findings: Finding[]): Finding | null {
  const rank: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  return [...findings].sort((a, b) => (rank[a.severity?.toLowerCase()] ?? 9) - (rank[b.severity?.toLowerCase()] ?? 9))[0] ?? null;
}

function sceneLabelForStage(stage: ExperienceStage): string {
  if (stage === 'live') return 'live';
  if (stage === 'report') return 'outcome';
  if (stage === 'findings') return 'review';
  return 'evidence';
}

function nextCueForStage(stage: ExperienceStage, reportableCount: number, failedCount: number): string {
  if (stage === 'live' && reportableCount > 0) return 'The scan is still moving. Keep the live route open while reviewing saved proof.';
  if (stage === 'live') return 'Watch the live route or open the raw CLI only when you need technical detail.';
  if (reportableCount > 0) return 'Review the finding story, then build the report from the same canonical evidence.';
  if (failedCount > 0) return 'Replay the stopped paths and decide whether the test needs another route.';
  return 'Check evidence replay first; no customer-facing claim exists until a finding is saved.';
}

function progressPercentForStage(stage: ExperienceStage): number {
  if (stage === 'live') return 28;
  if (stage === 'evidence') return 52;
  if (stage === 'findings') return 74;
  if (stage === 'report') return 100;
  return 8;
}

function safeFindingTitle(finding: Finding): string {
  return safeMissionFindingTitle(finding);
}

function summarizeTarget(run: Run, inventory: InventorySnapshot | null): string {
  return summarizeMissionTarget(run, inventory);
}

function humanize(value: string): string {
  return humanizeMissionValue(value);
}
