# Codex UI/Reporting UX7 - Management Report Export Proof

Date: 2026-06-03
Owner: Codex
Lane: UI/reporting worklist, not promoted to `NEXT_TASK.md`

## Scope

UX7 improves Report Center trust before management export. The change keeps the
backend report renderer as the canonical source for Markdown/PDF management
content and adds a deterministic React proof surface that shows why the selected
report is management-ready.

## Implemented

- Added `ui-v2/src/viewModels/managementReportProof.ts` to derive a
  management-report proof model from the selected report catalog entry,
  canonical findings, report truth model, and selected run.
- Added a Report Center "Management proof" panel with:
  - attack-map preview from scope to discovery, techniques, proof, and decision
  - standards badges for `[PTES]`, `[WSTG]`, `[NIST]`, and `[ASVS]`
  - plain-language technique explanations
  - Management, Engineering, and IT/Ops remediation ownership
  - evidence-basis and not-claimed statements before export
- Kept provider/billing safety in Report Center through the shared safe-message
  helper; raw provider diagnostics remain masked in the existing UX1 regression.
- Updated the Report Center Playwright fixture so the executive report catalog
  mirrors the backend standards basis.

## Evidence

Screenshot:

- `docs/validation/codex-ui-reporting-ux7-management-report-proof-1536x864.png`

Validated behavior:

- Report Center shows canonical report truth and export scope.
- The management proof panel displays attack-map preview, all four standards
  badges, plain-language techniques, team remediation ownership, tested scope,
  and evidence basis.
- Existing provider-error masking remains covered by the React v2 critical-path
  suite.
- Backend management report tests continue to prove Markdown/PDF output contains
  standards, attack map, techniques, remediation, and evidence basis without
  "see technical report" placeholders.

## Validation

- `cd ui-v2 && npx eslint src/components/screens/ReportCenter.tsx src/viewModels/managementReportProof.ts tests/react-v2-critical-paths.spec.ts`
- `cd ui-v2 && npx tsc -b --pretty false`
- `cd ui-v2 && AEGISPT_CAPTURE_UX7_REPORT_PROOF=1 npx playwright test tests/react-v2-critical-paths.spec.ts -g "Report Center shows canonical report truth"` (`1` passed, screenshot captured)
- `cd ui-v2 && npm test` (`37` passed, including i18n key parity)
- `if [ -x .venv/bin/pytest ]; then .venv/bin/pytest api/tests/test_reports.py -q -k "management_reports_rewrite_internal_runner_language or ai_report_draft"; else python -m pytest api/tests/test_reports.py -q -k "management_reports_rewrite_internal_runner_language or ai_report_draft"; fi` (`6` passed)
- `cd ui-v2 && npm run build` (passed; existing Vite chunk-size warning remains)
- `python3 scripts/validate_backlog_tasks.py` (passed)
- `git diff --check` (passed)
- `git diff --name-only -- NEXT_TASK.md TASK_QUEUE.md api/app/services/assessment_loop.py api/app/services/assessment_loop_internals/guards.py api/app/services/m2_verdict_gate.py workers/orchestration/tasks.py workers/runners/interactive_exploit` (no output)

## Non-overlap

No Claude-owned active score-lane files were edited or promoted. `NEXT_TASK.md`
and `TASK_QUEUE.md` were left untouched.
