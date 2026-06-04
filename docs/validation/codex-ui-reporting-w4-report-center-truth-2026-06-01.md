# Codex UI/reporting W4 - Report Center truth overhaul

Date: 2026-06-01
Owner: Codex UI/reporting lane
Worklist item: W4 - Report Center overhaul

## Scope

W4 rebuilds the React v2 Report Center around canonical report truth without
touching Claude-owned score-lane files, solver runtime, or report backend
generation services.

The screen now uses the same Dashboard/Mission Control blue visual language:
`neon-panel`, blue surface backgrounds, cyan borders, and semantic status
colors. At 150%-style layouts the report package stays single-column so the
path does not compress into unreadable cards.

## Behavior Proven

Report Center now starts with a compact report package flow:

- evidence
- scope
- findings
- variant
- export

Each step is clickable and updates a detail panel with plain-language meaning
and technical facts. Report variants are separated by audience, and the action
panel keeps preview/export controls outside the main truth cards.

Counts and charts are now based on `getFindingsForRunContext(run)`, not the
selected run's local summary. The selected report catalog count is compared
against the canonical finding list before export. Mismatches are labelled as
such instead of being hidden in a chart.

The page now makes report boundaries explicit:

- what will be included
- what is not claimed
- evidence verification state from the report catalog
- customer-copy check for internal benchmark/lab/fixture/smoke/debug markers
- report content hash labelled as report content, not evidence-integrity proof

Dutch management PDF/Markdown actions now use the shared API client helpers
instead of direct `fetch()` calls, so actor and tenant headers follow the same
path as the rest of the React v2 app.

## Fixture Proof

`ui-v2/tests/react-v2-critical-paths.spec.ts` now includes three report variants:

- executive summary
- technical evidence
- proof package

The fixture intentionally keeps the selected run-local summary at one finding
while the canonical report context contains two findings. The Report Center
test proves the UI displays the canonical count, verifies the selected report
count matches it, shows included/excluded scope, opens a different variant, and
generates a Markdown preview from the selected report action.

## Visual Review

Manual Playwright screenshots were generated from the mocked API fixture:

- `/tmp/aegispt-report-center-w4-1280x720.png`
- `/tmp/aegispt-report-center-w4-1536x864.png`
- `/tmp/aegispt-report-center-w4-1600x900.png`

The 1280px screenshot confirmed the two-column layout was too cramped for
150%-style scaling. The breakpoint was moved to `2xl`, leaving the report
package readable as a single-column flow on narrower desktop viewports.

## Validation

Commands run from `ui-v2/` unless noted:

- `npx eslint src/api/client.ts src/components/screens/ReportCenter.tsx tests/react-v2-critical-paths.spec.ts`
- `npm run build`
- `npx playwright test tests/react-v2-critical-paths.spec.ts --grep "Report Center"`

Additional full-suite validation was run after docs/state updates:

- `node scripts/check-i18n.mjs`
- `npm test`
- `python3 scripts/validate_backlog_tasks.py` from repo root
- `git diff --check`

Notes:

- `npm run build` emits the existing Vite chunk-size warning only.
- W4 did not change report generation services. Backend composition/export
  wording remains in the later W5/W6 workstreams.
