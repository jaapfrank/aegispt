# Codex UI/reporting truth audit

Date: 2026-06-01
Owner: Codex UI/reporting lane
Worklist item: W0 - UI truth audit and source map

## Scope

This audit maps the current React v2 UI, report APIs, and evidence/detail
surfaces before making behavior changes. It intentionally stays outside the
active score-lane files in `NEXT_TASK.md`.

Files inspected:

- `ui-v2/src/App.tsx`
- `ui-v2/src/store/index.ts`
- `ui-v2/src/api/client.ts`
- `ui-v2/src/components/screens/Dashboard.tsx`
- `ui-v2/src/components/screens/MissionControl.tsx`
- `ui-v2/src/components/screens/MissionControlV3.tsx`
- `ui-v2/src/components/screens/FindingsTheater.tsx`
- `ui-v2/src/components/screens/EvidenceReplay.tsx`
- `ui-v2/src/components/screens/ReportCenter.tsx`
- `ui-v2/src/components/screens/History.tsx`
- `ui-v2/src/components/screens/ProblemsCenter.tsx`
- `ui-v2/src/components/screens/SurfaceMap.tsx`
- `api/app/routers/runs.py`
- `api/app/routers/findings.py`
- `api/app/routers/tasks.py`
- `api/app/services/reports.py`
- `api/app/services/finding_views.py`
- `api/app/schemas/report_center.py`
- `ui-v2/tests/react-v2-critical-paths.spec.ts`
- `ui-v2/tests/i18n.spec.ts`

## Previous Codex item check

The previous Codex-owned item was coordination/documentation only:

- `docs/strategy/codex-ui-reporting-worklist-2026-06-01.md`
- `docs/strategy/codex-universal-execution-contract.md`

No product runtime behavior was supposed to change. The files exist and the
state/docs already identify the separate Codex lane. That item is behaviorally
complete as a setup artifact, so this audit starts W0 from the worklist.

## Current Source Map

| Surface | Primary source of truth | Notes |
|---|---|---|
| App shell bootstrap | `GET /api/v1/engagements`, `GET /api/v1/settings` via `getEngagements`/`getSettings` | Loaded in `App.tsx` before route content renders. |
| Engagement runs | `GET /api/v1/engagements/{engagement_id}/runs` via `getRunsForEngagement` | Stored in Zustand as `runs`; first available run becomes selected. |
| Selected run detail | `GET /api/v1/runs/{run_id}` via `getRun` | Stored as `selectedRun`. `RunRead.findings` is built from `sorted_findings(run)` on that run. |
| Selected run tasks | `getTasksForRunContext(run)` | Chain-aware in `client.ts`: uses `/assessment-chains/{chain_id}/tasks` when `run.assessment_chain.id` exists. |
| Selected run findings | `getFindingsForRunContext(run)` | Chain-aware in `client.ts`: uses `/assessment-chains/{chain_id}/findings` when `run.assessment_chain.id` exists. |
| Inventory | `getInventoryForRun(run)` or latest engagement inventory | Selected-run inventory prefers `source_inventory_snapshot_id`; Surface Map uses latest engagement inventory. |
| AI insights | `getAiInsightsForRunContext(run, runs)` | Chain-aware aggregation is implemented client-side by fetching sibling run insights. |
| Dashboard | `GET /api/v1/dashboard?engagement_id=...` plus store fallback data | Several widgets mix dashboard payload with selected-run store findings/runs. |
| Mission Control | Zustand `selectedRun`, `tasks`, `findings`, `aiInsights` | Mission state is derived in `MissionControlV3` from selected run plus currently loaded findings/tasks. |
| Findings Theater list | `getFindingsForRunContext(selectedRun)` | Chain-aware finding list. Detail drawer uses per-finding theater and evidence endpoints. |
| Finding detail | `GET /api/v1/findings/{finding_id}/theater` and `/evidence` | Built by `finding_views.py`; verification labels derive from `validation_status` and replay evidence presence. |
| Evidence Replay | `GET /api/v1/runs/{run_id}` then `GET /api/v1/tasks/{task_id}` for each `run.tasks` | Not chain-aware today; it reads only tasks embedded in the selected run payload. |
| Report Center catalog | `GET /api/v1/runs/{run_id}/reports` | Backend uses `report_context_for_run(run, session=...)`, which aggregates assessment-chain runs when a chain has multiple runs. |
| Report Center preview/export | `GET /api/v1/runs/{run_id}/report?...` | Markdown/HTML/PDF use the same report context as the catalog. |
| Report Center briefing | direct `fetch('/api/v1/runs/{run_id}/briefing')` | Bypasses the shared API helper and tenant header handling. |
| Management NL export | direct `fetch('/api/v1/runs/{run_id}/report?...management_nl')` | Bypasses the shared API helper and tenant header handling. |
| History | `GET /api/v1/portfolio/runs`, falling back to engagement fan-out if needed | Displays `RunRead.findings` summary counts from each run row. |
| Problems Center | `GET /api/v1/problems`, `PATCH /api/v1/problems/bulk` | Cross-engagement lifecycle view keyed to finding IDs. |
| Surface Map | latest engagement inventory, selected-run store findings, optional simulation endpoint | Inventory and selected-run findings can be different scopes by design. |

## Confirmed Truth Gaps

1. Chain-aware findings vs per-run summaries can diverge.

   The app shell loads selected findings through `getFindingsForRunContext`,
   which becomes `/assessment-chains/{chain_id}/findings` for chained runs.
   `RunRead.findings` is still built from only `sorted_findings(run)`.
   Any UI using `findings.length` can disagree with a widget using
   `selectedRun.findings.finding_count`.

   Affected surfaces:

   - sidebar findings badge
   - Findings Theater count
   - Report Center severity chart
   - History finding summary
   - Report Center dossier finding summary

2. Report Center can show a report catalog whose counts do not match its own
   severity chart.

   `build_report_catalog()` uses `report_context_for_run()`, which aggregates
   sibling assessment-chain runs when there is more than one chain run. The
   chart next to the selected report uses `run.findings.findings_by_severity`
   from the selected run object instead of `report.included_findings`.

   Result: for assessment chains, the exported report can include more findings
   than the chart beside it claims.

3. Evidence Replay omits chain-level evidence.

   Evidence Replay loads `getRun(runId)` and then iterates `runPayload.tasks`.
   It does not use `getTasksForRunContext()`, even though the app shell and
   reports already have a chain-aware task path. For assessment-chain runs,
   Evidence Replay can omit sibling phase task executions that Findings Theater
   and Report Center rely on.

4. Report Center direct fetches bypass shared API headers and error handling.

   The briefing call and the Dutch management report downloads use direct
   `fetch()` calls. The PDF/Markdown management calls set `X-Actor` but not
   `X-Tenant-ID`; the briefing call sets neither explicitly. This can make
   Report Center tenant behavior differ from all `api()`/`apiBlob()` calls.

5. "Evidence hash: verified" overstates what the UI knows.

   Report Center displays `Evidence hash: verified` next to
   `report.content_sha256`. The schema says this is the report content hash,
   not an evidence-integrity verification result. The label should be changed
   before operators treat it as proof that finding evidence was hash-verified.

6. Dashboard "Open Problems" can fall back to selected-run findings.

   When dashboard `open_problems.total` is sparse or missing, Dashboard falls
   back to `findings.filter(status === 'open').length`, which is the selected
   run or selected assessment-chain context. That can make a portfolio widget
   display selected-run scope without saying so.

7. Current tests prove route rendering, not cross-surface truth consistency.

   `react-v2-critical-paths.spec.ts` verifies primary screens render with
   fixtures and no unhandled route errors. It does not assert that run summary,
   Findings Theater, Evidence Replay, Report Center catalog, and exported
   report counts agree for the same run or assessment chain.

## Product-Truth Priorities For Next Work

1. W1 should introduce a run truth strip/view-model that explicitly distinguishes
   run-local and assessment-chain aggregate counts.

2. Report Center should render chart/count summaries from the same
   `RunReportCatalogItem.included_findings` and `evidence_status` payload that
   controls the report preview/export.

3. Evidence Replay should use `getTasksForRunContext()` for the selected run
   and label whether evidence is run-local or chain-aggregate.

4. Direct Report Center fetches should move through shared API helpers or an
   equivalent header helper so actor and tenant behavior is consistent.

5. The report hash label should say "Report content hash" unless evidence
   integrity status is actually present and verified.

6. A follow-up validation should add a named chain fixture where:

   - run-local findings = 1
   - chain aggregate findings = 2
   - report catalog included findings = 2
   - Evidence Replay task count = chain aggregate task count

   That fixture should fail whenever any surface silently reverts to the wrong
   source.

## W0 Result

W0 is complete as a source-backed audit artifact. No runtime code changed.
The next Codex-owned work item should be W1: Live run truth strip and operator
state model, starting with a canonical UI view-model for run-local vs
assessment-chain aggregate state.

## Validation

- `python3 scripts/validate_backlog_tasks.py` passed: 391 queued task packages
  mapped one-to-one, and `NEXT_TASK.md` contains exactly one active task.
- `git diff --check` passed.
- No UI or backend code files were changed for W0, so ruff/eslint were not
  applicable to touched files.
