import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  Clock3,
  Database,
  GitBranch,
  Radar,
} from 'lucide-react';
import { useMemo } from 'react';
import type { LucideIcon } from 'lucide-react';
import type { Finding, Run, Task } from '../api/types';
import { buildRunTruthModel, type RunTruthStage, type RunTruthStageKey, type RunTruthTone } from '../viewModels/runTruth';

export default function RunTruthStrip({
  run,
  tasks,
  findings,
}: {
  run: Run;
  tasks: Task[];
  findings: Finding[];
}) {
  const model = useMemo(() => buildRunTruthModel(run, tasks, findings), [run, tasks, findings]);
  const AttentionIcon = model.attention.tone === 'complete' ? CheckCircle2 : AlertTriangle;
  const stages = useMemo(
    () => Object.fromEntries(model.stages.map((stage) => [stage.key, stage])) as Record<RunTruthStageKey, RunTruthStage>,
    [model.stages],
  );
  const workStage = stages.running.tone === 'active' ? stages.running : stages.queued.tone === 'active' ? stages.queued : stages.running;
  const compactStages = [
    { label: 'Work', stage: workStage, icon: workStage.key === 'queued' ? Clock3 : Activity },
    { label: 'Output', stage: stages.observed, icon: Radar },
    { label: 'Findings', stage: stages.persisted, icon: Database },
    { label: 'Attention', stage: stages.blocked, icon: AttentionIcon },
  ];

  return (
    <section
      aria-label="Run truth"
      data-testid="run-truth-strip"
      className="shrink-0 border-b border-line-soft bg-bg/90 px-6 py-3"
    >
      <div className="flex flex-col gap-3 xl:flex-row xl:items-start xl:justify-between">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <span className="inline-flex items-center gap-2 rounded border border-cyan/25 bg-cyan/10 px-2.5 py-1 font-mono text-[0.72rem] font-semibold uppercase tracking-widest text-cyan">
              <GitBranch size={14} aria-hidden="true" />
              {model.scopeLabel}
            </span>
            <span className="font-mono text-[0.72rem] text-muted">{model.sourceDetail}</span>
          </div>
          <p className="mt-2 max-w-5xl text-[1rem] font-semibold leading-snug text-text">
            {model.summaryHeadline}
          </p>
          <p className="mt-1 max-w-5xl text-[0.82rem] leading-snug text-muted">
            {model.summaryDetail}
          </p>
          <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-[0.78rem] text-soft">
            <span>{model.statusLabel}</span>
            {model.phaseLabel && (
              <>
                <span className="text-muted">/</span>
                <span>{model.phaseLabel}</span>
              </>
            )}
          </div>
        </div>

        <div
          data-testid="run-truth-canonical-score"
          className="flex min-w-[220px] items-start gap-2 rounded border border-line-soft bg-surface/35 px-3 py-2"
        >
          <Database size={16} className="mt-0.5 shrink-0 text-cyan" aria-hidden="true" />
          <div className="min-w-0">
            <div className="font-mono text-[0.63rem] uppercase tracking-widest text-muted">Canonical score</div>
            <div className="font-mono text-[0.9rem] font-semibold text-text">{model.canonicalScore}</div>
            <div className="text-[0.72rem] leading-snug text-muted">{model.canonicalScoreDetail}</div>
          </div>
        </div>
      </div>

      <div className="mt-3 grid gap-2 md:grid-cols-4">
        {compactStages.map((item) => (
          <TruthChip key={item.label} label={item.label} stage={item.stage} icon={item.icon} />
        ))}
      </div>

      <div className="mt-3 flex flex-col gap-2 xl:flex-row xl:items-center xl:justify-between">
        <div className="flex flex-wrap gap-2">
          <span
            data-testid="run-truth-run-local-summary"
            className="inline-flex items-center rounded border border-line-soft bg-bg-2/40 px-2.5 py-1 font-mono text-[0.72rem] text-soft"
          >
            Run-local summary: {model.runLocalSummary}
          </span>
          {model.truthGapText && (
            <span
              data-testid="run-truth-gap"
              className="inline-flex items-center gap-1.5 rounded border border-amber/35 bg-amber/10 px-2.5 py-1 text-[0.72rem] text-amber"
            >
              <AlertTriangle size={13} aria-hidden="true" />
              {model.truthGapText}
            </span>
          )}
        </div>

        <div
          data-testid="run-truth-blocked-reason"
          className={`inline-flex max-w-full items-start gap-1.5 rounded border px-2.5 py-1 text-[0.72rem] ${attentionClasses(model.attention.tone)}`}
        >
          <AttentionIcon size={13} className="mt-0.5 shrink-0" aria-hidden="true" />
          <span className="min-w-0">
            <span className="font-semibold">{model.attention.label}:</span> {model.attention.detail}
          </span>
        </div>
      </div>
    </section>
  );
}

function TruthChip({ label, stage, icon: Icon }: { label: string; stage: RunTruthStage; icon: LucideIcon }) {
  return (
    <div className={`min-h-[62px] rounded border px-2.5 py-2 ${stageClasses(stage.tone)}`}>
      <div className="flex items-center gap-2 text-[0.68rem]">
        <Icon size={14} className="shrink-0" aria-hidden="true" />
        <span className="font-mono uppercase tracking-widest">{label}</span>
      </div>
      <div className="mt-1 font-mono text-[0.85rem] font-semibold text-text">{stage.value}</div>
      <div className="mt-0.5 line-clamp-2 text-[0.7rem] leading-snug text-muted">{stage.detail}</div>
    </div>
  );
}

function stageClasses(tone: RunTruthTone): string {
  if (tone === 'complete') return 'border-green-400/25 bg-green-400/5 text-green-300';
  if (tone === 'active') return 'border-amber/30 bg-amber/10 text-amber';
  if (tone === 'warning') return 'border-amber/35 bg-amber/10 text-amber';
  if (tone === 'blocked') return 'border-red/35 bg-red/10 text-red';
  return 'border-line-soft bg-surface/25 text-muted';
}

function attentionClasses(tone: RunTruthModelAttentionTone): string {
  if (tone === 'complete') return 'border-green-400/25 bg-green-400/5 text-green-300';
  if (tone === 'warning') return 'border-amber/35 bg-amber/10 text-amber';
  return 'border-red/35 bg-red/10 text-red';
}

type RunTruthModelAttentionTone = 'complete' | 'warning' | 'blocked';
