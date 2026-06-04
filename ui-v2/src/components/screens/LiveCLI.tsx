import { useMemo } from 'react';
import { useAegisStore } from '../../store';
import { useI18n } from '../../i18n';
import { LiveTaskDrillDown, LiveEventsFeed } from './MissionControlV3';

/**
 * LIVE CLI — dedicated full-screen view of the actual shell-level activity.
 *
 * Operator request 2026-05-27: the existing Mission Control "CLI" panel
 * is mostly an API-call log. This screen surfaces the REAL CLI — the
 * tool commands (nmap, sqlmap, custom python attack scripts, ...) and
 * their live stdout/stderr — as the dominant view, so an operator can
 * watch the agent work like watching an attacker share their terminal.
 *
 * Backing data:
 * - Task stdout SSE stream: /api/v1/tasks/{id}/stdout/events
 *   (snapshot + incremental update events; same source the Mission
 *   Control inline terminal uses).
 * - Run-level diff feed: /api/v1/runs/{id}/events
 *   (state diffs surface as "task added", "status changed", "finding
 *   confirmed" event lines — picker decisions and runner lifecycle.)
 *
 * Both components are re-used as-is from MissionControlV3; this screen
 * just gives them the full canvas instead of one quadrant of Mission
 * Control.
 */
export default function LiveCLIScreen() {
  const { t } = useI18n();
  const tasks = useAegisStore((state) => state.tasks);
  const selectedRun = useAegisStore((state) => state.selectedRun);
  const runId = selectedRun?.id ? String(selectedRun.id) : '';

  const noRun = !runId;
  const taskCount = useMemo(() => tasks.length, [tasks]);

  return (
    <div className="flex flex-col gap-4 p-4 min-h-[calc(100vh-4rem)]">
      <div className="flex items-baseline gap-3 flex-wrap">
        <h1 className="font-mono text-lg uppercase tracking-widest text-green-300">
          {t('liveCli.title')}
        </h1>
        <span className="font-mono text-xs text-muted">
          {t('liveCli.subtitle')}
        </span>
        {selectedRun && (
          <span className="ml-auto font-mono text-xs text-amber">
            run {String(selectedRun.id).slice(0, 8)} · {taskCount} task(s)
          </span>
        )}
      </div>

      {noRun && (
        <div className="rounded border border-line-soft bg-surface/30 p-6 text-center">
          <p className="text-muted">
            {t('liveCli.noRun')}
          </p>
        </div>
      )}

      {!noRun && (
        <div className="grid grid-cols-1 xl:grid-cols-[2fr_1fr] gap-4 flex-1 min-h-0">
          {/* MAIN: the actual shell terminal — picks the most recently active
              task and streams its stdout/stderr. Operator can drop down to
              any of the last 40 tasks via the dropdown inside the panel. */}
          <div className="min-h-0">
            <LiveTaskDrillDown tasks={tasks} fullHeight />
          </div>

          {/* SIDE: run-level diff stream — picker decisions, status
              transitions, findings — so the operator sees the agent's
              moves alongside the underlying CLI output. */}
          <div className="min-h-0">
            <LiveEventsFeed runId={runId} />
          </div>
        </div>
      )}
    </div>
  );
}
