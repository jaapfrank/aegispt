# Codex UI/Reporting UX1 Trust-State Recheck

Date: 2026-06-04
Owner: Codex
Lane: UI/reporting, worklist-only

## Reason

The operator asked to restart the Codex UI/reporting lane from UX1:
trust-breaking state repair. UX1 was already complete, so this pass re-ran the
focused regression set against the current worktree and refreshed screenshots
instead of relying on the earlier 2026-06-03 proof.

## Result

No UX1 code repair was required.

Verified behavior:

- Research masks raw `500` / diagnostic API failures and keeps safe recovery
  copy visible.
- Report Center masks raw AI provider/billing briefing failures while keeping
  canonical report facts and export readiness available.
- History explains filtered-empty states and offers reset/refresh recovery.
- Dashboard sparse payload recovery does not enter crash recovery.
- Dashboard, Mission Control, Findings, Evidence Replay, and Reports remain
  aligned through the canonical consistency fixture.

## Screenshot Review

The focused Playwright run refreshed these UX1 screenshots on 2026-06-04, and
Codex visually reviewed the key trust-state screens:

- `docs/validation/codex-ui-reporting-ux1-report-provider-mask-1536x864.png`
- `docs/validation/codex-ui-reporting-ux1-research-safe-error-1536x864.png`
- `docs/validation/codex-ui-reporting-ux1-history-filter-empty-1536x864.png`
- `docs/validation/codex-ui-reporting-ux1-history-filter-reset-1536x864.png`

## Validation

- `cd ui-v2 && AEGISPT_CAPTURE_UX1_TRUST_REPAIR=1 npx playwright test tests/react-v2-critical-paths.spec.ts -g "Report Center masks raw provider briefing failures|Research masks raw API failures|History explains filtered empty states|Dashboard survives sparse dashboard payloads|Report Center shows canonical report truth|Canonical consistency fixture"` (`6` passed, screenshots refreshed)
- `python3 scripts/validate_backlog_tasks.py`
- `git diff --check`
- `git diff --name-only -- NEXT_TASK.md TASK_QUEUE.md api/app/services/assessment_loop.py api/app/services/assessment_loop_internals/guards.py api/app/services/m2_verdict_gate.py workers/orchestration/tasks.py workers/runners/interactive_exploit` reported `workers/runners/interactive_exploit/runner.py` as an existing/concurrent score-lane change. Codex did not edit that file.

## Repeat Verification

The operator repeated the same UX1 launcher prompt later on 2026-06-04. Codex
re-ran the focused UX1 Playwright set and refreshed screenshots again. No UX1
code repair was required.

- `cd ui-v2 && AEGISPT_CAPTURE_UX1_TRUST_REPAIR=1 npx playwright test tests/react-v2-critical-paths.spec.ts -g "Report Center masks raw provider briefing failures|Research masks raw API failures|History explains filtered empty states|Dashboard survives sparse dashboard payloads|Report Center shows canonical report truth|Canonical consistency fixture"` (`6` passed, screenshots refreshed again)
- visual review repeated for Report Center provider masking and History
  filtered-empty recovery

The same UX1 launcher prompt was repeated again later on 2026-06-04. Codex
re-ran the focused UX1 Playwright set, refreshed the same screenshots, and
confirmed the trust-state repair still required no code change.

- `cd ui-v2 && AEGISPT_CAPTURE_UX1_TRUST_REPAIR=1 npx playwright test tests/react-v2-critical-paths.spec.ts -g "Report Center masks raw provider briefing failures|Research masks raw API failures|History explains filtered empty states|Dashboard survives sparse dashboard payloads|Report Center shows canonical report truth|Canonical consistency fixture"` (`6` passed, screenshots refreshed again)
- visual review repeated for Report Center provider masking and History
  filtered-empty recovery
