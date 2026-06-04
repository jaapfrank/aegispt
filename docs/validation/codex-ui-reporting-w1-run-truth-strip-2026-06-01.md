# Codex W1 run truth strip validation

Date: 2026-06-01
Owner: Codex UI/reporting lane
Worklist item: W1 - Live run truth strip and operator state model

## Scope

W1 adds a canonical Mission Control strip that tells the operator which run
truth is currently being displayed and separates these states:

- queued
- running
- observed
- verified
- persisted
- blocked / incomplete

Operator follow-up on 2026-06-01 clarified that the full Mission Control page
was still too cluttered and too hard to follow, especially for non-pentest
users. The repair therefore also covers the default Mission Control page, not
only the truth strip.

The implementation intentionally stays inside the Codex-owned UI/reporting
lane. It does not change assessment runtime, scoring, orchestration, solver, M2
gate, `NEXT_TASK.md`, or `TASK_QUEUE.md`.

## Behavior

Added:

- `ui-v2/src/viewModels/runTruth.ts`
- `ui-v2/src/components/RunTruthStrip.tsx`

Wired:

- `MissionControlV3` now renders the strip in the Technical view only.
- The default view is `Live` and no longer shows canonical score, run-local
  truth cards, or raw diagnostic feeds in the first viewport.

The strip uses the already-loaded selected-run context from the React shell:

- `tasks` from `getTasksForRunContext(run)`
- `findings` from `getFindingsForRunContext(run)`
- `run.findings` only as a labelled run-local summary

For assessment-chain runs, the canonical score summary is therefore the
chain-aware persisted finding list, not the selected run's local summary.

## Proven Cases

### Chain aggregate vs run-local mismatch

The React critical-path fixture now intentionally models the W0 truth gap:

- run-local summary: 1 finding / 1 high+
- assessment-chain aggregate: 2 persisted findings / 2 high+

The W1 test asserts that Mission Control shows:

- `Assessment chain aggregate`
- `2 persisted / 2 high+`
- `Run-local summary: 1 total / 1 high+`
- `Run-local summary differs: 1 run-local, 2 aggregate`
- blocked/incomplete reason from `completed_with_gaps` and the failed task

### Observed output is not persisted truth

A second fixture models completed task output with zero persisted findings:

- run-local truth
- 2 completed task output items
- 0 persisted findings

The W1 test asserts that Mission Control shows:

- `Observed task output only`
- `No persisted findings yet`
- `0 persisted / 0 high+`
- blocked/incomplete reason: observed output has not been persisted as findings

## Supporting Cleanup

The full UI build was blocked by stale Live CLI translation calls that passed a
fallback string where the typed `t()` helper expects interpolation params. W1
removed those fallback arguments and added the missing German/French `liveCli`
locale keys so i18n parity remains clean.

The CSS font import was moved before Tailwind directives to remove Vite's
import-order warning during build and Playwright startup.

Existing Mission Control tests were updated to follow the actual operator path:
Live view loads first; Cinema and Kill controls live in Technical view.

## Clarity Repair

Reference patterns reviewed before the repair:

- Burp Dashboard separates automated tasks, issue activity, and event logs so
  operators can monitor tasks without reading raw log streams first.
- Tenable/Nessus scan results separate dashboard, hosts, vulnerabilities, and
  compliance views instead of mixing every evidence type into one panel.
- Metasploit Pro separates real-time statistics from the task log in the
  Findings window.
- ZAP keeps essential views such as Sites, History, Alerts, and Active Scan as
  distinct tabs.

Applied product rule:

- Mission Control is split into `Live`, `Results`, `Overview`, and `Technical`.
- `Live` shows a visual branching timeline with proof/dead-end routes,
  done/now/next story board, progress/severity chart, compact queue,
  selected-task CLI output, and live events.
- `Results` shows what happened, what is reportable, latest activity, findings,
  and scan timeline.
- `Overview` shows total target/profile/run state, progress, recent scan path,
  and what is coming next.
- `Technical` keeps the truth strip, risk trajectory, raw event feed, task
  terminal output, proof inventory, and raw API logs.
- The run truth strip is available only in Technical and is compact: Work,
  Output, Findings, Attention.
- Tool output is labelled as review-only until a finding is saved.
- Queue/activity rows are interactive and can select the task shown in the CLI
  output panel.
- Findings link into Findings/Evidence; Overview links into Surface Map,
  History, and Reports.
- Operator-facing tabs pair plain-language Jip-en-Janneke explanations with
  technical facts.
- Overview includes a compact AI story panel backed by ChatGPT narrator panels
  when available, with History/Evidence Replay links for follow-up.
- Long plain-language and technical explanation panels are collapsed by default
  in Live so the first viewport is visually led rather than prose-led.
- Repeated queue rows are grouped before rendering.
- The timeline, story, run-picture, and queue panels use Dashboard's blue
  `neon-panel`/cyan-accent visual language.
- Cinema Mode command clicks pause replay while focusing the selected command,
  so the selected context remains visible.

New proof fixture:

- run status: `queued`
- tasks: 3 completed output-producing tasks, 1 queued task
- findings: 0 persisted findings

The test asserts that Mission Control says the run is waiting/output-only, not
hard-blocked, and that the old `Reconnaissance in progress` headline no longer
appears for this state.

Additional visual proof:

- Live renders `Mission path`, `Decision`, `The test story`, and `Run picture`
  before raw CLI/log details.
- The main `Mission path` card shows only the current route so the first
  viewport remains readable at 125%/150% scaling.
- `Open full map` renders a true viewport-level dialog through a React portal
  on `document.body`; the dialog is not trapped inside the Mission Control
  scroll panel, locks page scroll, and closes on Escape.
- The full map has `Back`, `Next`, `Play`, `Reset`, and `Show all` replay
  controls. The `Replay` button opens the full map directly at step 1.
- The full map has `Zoom out`, `Zoom in`, and `Fit` controls.
- The full map uses readable spacing rather than stacking every label: Layer 1
  contains discovery/decision/dead-end work, Layer 2 contains proof/outcome,
  edge labels are reserved for branch/proof transitions, and multiple findings
  collapse into the strongest proof node with `+N more`.
- Every edge renders as a visible line; small arrowheads are reserved for
  live/failed/proof direction changes, not routine completed steps.
- Selecting a full-map node opens a side event panel with a plain-language
  explanation, technical metadata, and an `Open linked view` action into Live
  CLI, Findings, Surface Map, or Reports.
- Overview reuses the compact `Mission path` entry point and keeps the AI story
  panel as a compact follow-up surface.

Additional terminal-error proof fixture:

- run status: `completed_with_errors`
- tasks: 12 checked tasks, including repeated failed `exec-plan` tasks
- findings: 0 persisted findings

The test asserts that the Results view:

- hides the technical run truth strip and canonical score card
- says `Run ended with errors. No findings were created.`
- shows `Last task`
- groups repeated failed rows as `exec-plan x5`
- says `No reportable findings`
- does not use `signals` copy on the default page

## Validation

Commands run:

- `npm run build`
- `npx eslint src/components/CinemaMode.tsx src/components/RunTruthStrip.tsx src/viewModels/runTruth.ts src/components/screens/MissionControlV3.tsx src/components/screens/LiveCLI.tsx tests/react-v2-critical-paths.spec.ts`
- `node scripts/check-i18n.mjs`
- `npx playwright test tests/react-v2-critical-paths.spec.ts --grep "Mission Control truth strip|Mission Control renders V3|Mission Control Technical"`
- `npm test`
- `python3 scripts/validate_backlog_tasks.py`
- `git diff --check`

Additional clarity-repair commands:

- `npm run build`
- `npx eslint src/components/CinemaMode.tsx src/viewModels/runTruth.ts src/components/RunTruthStrip.tsx src/components/screens/MissionControlV3.tsx tests/react-v2-critical-paths.spec.ts`
- `node scripts/check-i18n.mjs`
- `npx playwright test tests/react-v2-critical-paths.spec.ts --grep "Cinema Mode|Mission Control"`
- `npm test`
- `python3 scripts/validate_backlog_tasks.py`
- `git diff --check`

Additional path-map/replay repair commands:

- `npx eslint src/components/screens/MissionControlV3.tsx tests/react-v2-critical-paths.spec.ts`
- `npx playwright test tests/react-v2-critical-paths.spec.ts --grep "Mission Control renders interactive"`
- Playwright screenshot smoke checks at `1280x720` and `1024x576` confirmed the
  full map dialog bounds fill the viewport and that replay opens at `step 1`.
- A richer mocked run screenshot at `1280x720` was reviewed manually to verify
  branch/dead-end lanes, stronger arrows, uncluttered labels, primary-proof
  summarization, and visible Report outcome placement.
- A follow-up live screenshot at `1280x720` verified zoom controls, the side
  event detail panel, visible connecting lines, and reduced arrowhead usage.

Results:

- UI build passed.
- Touched TypeScript/TSX lint passed with no errors or warnings.
- i18n parity passed: 90 keys across en, nl, de, fr.
- Targeted Mission Control proof passed: 4 tests.
- Full UI test command passed: 15 tests.
- Backlog validation passed: 391 queued task packages mapped one-to-one, and
  `NEXT_TASK.md` contains exactly one active task.
- `git diff --check` passed.
- Clarity-repair Mission Control/Cinema proof passed: 7 tests.
- Full UI suite passed: 21 tests.

Remaining note:

- Vite still emits its standard large-bundle advisory for the existing React v2
  bundle size. That is not a W1 regression and is not a functional failure.
