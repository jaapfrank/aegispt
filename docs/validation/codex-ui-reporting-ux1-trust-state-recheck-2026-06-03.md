# Codex UI/Reporting UX1 Trust-State Recheck

Date: 2026-06-03
Owner: Codex
Lane: UI/reporting, worklist-only

## Reason

The operator asked to start again from UX1 trust-breaking state repair. UX1 was
already marked complete, so this pass re-verified the repaired behavior after
later UX2-UX8 changes, including light-mode tokenization.

## Result

No new UX1 code repair was required.

Verified states:

- Research masks raw `500` / diagnostic API failures and keeps recovery copy
  visible.
- Report Center masks raw provider/billing briefing failures while preserving
  canonical report facts and export readiness.
- History explains filtered empty states and exposes reset/refresh recovery.
- Dashboard sparse payload recovery does not crash.
- Dashboard, Mission Control, Findings, Evidence Replay, and Reports remain
  aligned through the canonical consistency fixture.

## Screenshot Proof

Screenshots were refreshed by the focused UX1 capture run:

- `docs/validation/codex-ui-reporting-ux1-report-provider-mask-1536x864.png`
- `docs/validation/codex-ui-reporting-ux1-research-safe-error-1536x864.png`
- `docs/validation/codex-ui-reporting-ux1-history-filter-empty-1536x864.png`
- `docs/validation/codex-ui-reporting-ux1-history-filter-reset-1536x864.png`

## Validation

- `cd ui-v2 && AEGISPT_CAPTURE_UX1_TRUST_REPAIR=1 npx playwright test tests/react-v2-critical-paths.spec.ts -g "Report Center masks raw provider briefing failures|Research masks raw API failures|History explains filtered empty states|Dashboard survives sparse dashboard payloads|Report Center shows canonical report truth|Canonical consistency fixture"` (`6` passed, screenshots refreshed)
- `git diff --check`
- `git diff --name-only -- NEXT_TASK.md TASK_QUEUE.md api/app/services/assessment_loop.py api/app/services/assessment_loop_internals/guards.py api/app/services/m2_verdict_gate.py workers/orchestration/tasks.py workers/runners/interactive_exploit` produced no output
