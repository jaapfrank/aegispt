# Codex UI + Reporting Worklist (Non-Conflicting)

Date: 2026-06-01
Owner: Codex
Status: W1-W8 complete; W6A operator-presence spine, context-aware spine, Mission Control operator deck, attack-map visible timing, attack-map pan/zoom, selected-run binding, full-path findings, live-activity, Live CLI command-output, and Mission Control 4k/125 single-Live-CLI density repairs complete; M1 app shell split complete; M2 store slice split complete; M3 API domain client split complete; M4 report truth view-model adapter complete; M5 report render-utils, lifecycle, metadata, and model-utils extraction slices complete; M6 management decision facts, attack-map/technique story, management report story/remediation, and report-draft payload complete; M8 cross-surface consistency checker complete; UX1 trust-breaking state repair, UX2 shared page experience contract, UX3 Mission Control living cockpit, UX4 attack path truth map v2, UX5 Evidence Replay timeline, UX6 Findings/Problems triage board, UX7 Management report export proof, UX8 light mode/theme tokenization, UX8 readability repair, UX1 post-UX8 trust-state recheck, UX1 2026-06-04 trust-state recheck, and Mission Control 4k/125 single-Live-CLI density repair complete; UX8 remains worklist-only and is not promoted to `NEXT_TASK.md`

## Purpose

This worklist is Codex's separate lane for product-truth UI, accessibility,
reporting, and evidence presentation improvements. It intentionally lives
outside the active Claude score-lane task so both agents can work without
stepping on each other's files or queue state.

This is a coordination document, not the active repo task. Do not promote it
into `NEXT_TASK.md` unless the operator explicitly asks for that handoff.

## North-star for this lane

Build an operator UI and report stack that is:

- truthful live
- accessible and calm to work in
- clear about process and validation state
- strict about canonical score/finding/report consistency
- evidence-first in both UI and exported reports
- LLM-assisted only for wording, never for inventing facts
- experience-led across the product, so Mission Control, evidence, findings,
  reports, and supporting screens feel like drilldowns from one mission story
  instead of disconnected pages

## Non-overlap contract with Claude

### Claude-owned active lane (do not touch unless operator explicitly approves overlap)

- `NEXT_TASK.md`
- `TASK_QUEUE.md`
- `api/app/services/assessment_loop.py`
- `api/app/services/assessment_loop_internals/guards.py`
- `api/app/services/m2_verdict_gate.py`
- `workers/orchestration/tasks.py`
- `workers/runners/interactive_exploit/**`
- active score-lane validation artifacts under `docs/validation/` that are tied
  to XBEN / focused-assessment / solver throughput

### Codex-owned lane for this worklist

- `ui-v2/src/**`
- `ui-v2/tests/**`
- `ui/index.html` only if legacy UI truth gaps must be patched during the same lane
- `api/app/services/reports.py`
- `api/app/services/report_pdf.py`
- `api/app/schemas/report_center.py`
- `api/app/routers/runs.py` for report/export/read-model wiring only
- report- and evidence-centered docs under `docs/strategy/` and `docs/validation/`

### If overlap becomes necessary

If a required fix crosses into Claude-owned files:

1. stop before editing the overlapping file
2. record the exact blocker and file in `DONE_LOG.md`
3. either wait for operator approval or prepare a narrow handoff note

Do not silently merge work into the active score-lane files.

## Git hygiene rules for parallel work

Before each Codex session in this lane:

1. read `CURRENT_STATE.md`, `NEXT_TASK.md`, `DECISIONS.md`
2. run `git status --short`
3. confirm changed files stay inside the Codex-owned lane above
4. if unrelated dirty files exist, leave them alone
5. never clean up Claude's worktree by reverting or reformatting shared files

Before stopping:

1. update `DONE_LOG.md`
2. update `CURRENT_STATE.md`
3. update `DECISIONS.md` if a durable UI/reporting decision was made
4. run relevant lint/tests for touched files
5. run `git diff --check`
6. leave a narrow, understandable diff

## Canonical product rules for this lane

These rules govern every task below:

1. The UI must show one canonical truth for run status, findings, validation,
   report readiness, and score.
2. A finding shown as "verified" in the UI must be backed by the same truth
   source used by the report builder.
3. A management report may only discuss tested scope and evidence-backed
   outcomes.
4. LLM-generated report text may summarize and phrase, but may not invent
   findings, scope, business impact, tested components, or remediation facts.
5. The report stack must clearly separate:
   - management summary
   - technical detail
   - raw evidence / proof export
6. The UI must make process state obvious:
   - queued
   - running
   - observed
   - verified
   - persisted
   - blocked / failed
7. The app must carry the operator through the assessment. Attack maps, Cinema
   Mode, reports, and ordinary pages should share the same story spine: what is
   happening now, what path was taken, what proof exists, what outcome is ready,
   and what the next meaningful click is. Raw terminal/detail views remain
   available, but they are drilldowns rather than the default emotional model.

2026-06-03 repair note: W6A now includes a Mission Control operator-deck pass.
The Live first viewport starts with `You are here`, role/system/evidence facts,
clickable route stages, lead proof, impact, and direct actions; detailed story,
run-picture, queue, CLI, and technical facts remain in drilldown layers.

2026-06-03 follow-up repair note: W6A now also includes a context-aware global
mission spine pass. The spine changes its `You are here` copy and active route
stage based on the current page, so Evidence Replay, Findings, Reports, Live
CLI, Surface Map, Problems, and History feel like mission-story drilldowns
rather than isolated screens.

2026-06-03 follow-up repair note: W6A now also includes a full attack-map
pan/zoom pass. The map popout is a real viewport with mouse-wheel zoom,
drag-to-pan, keyboard zoom, and bounds-based Fit that centers the whole route.
Node click-through detail remains mandatory and must not be broken by panning.

2026-06-03 follow-up repair note: W6A now also includes an attack-map
selected-run binding pass. The map visualizes the selected run's route using
`selectedRun.tasks` and findings whose `run_id` matches the selected run,
instead of reusing the full assessment-chain output for every mission/run.

2026-06-03 follow-up repair note: W6A now also includes an attack-map
full-path findings pass. Multiple persisted findings must render as individual
proof milestones in the full attack path, with timing/source facts on each
milestone and severity totals summarized only at the report/outcome node. The
full map should draw what happened before proof, what enabled progress, when
proof was reached, and where the operator can drill into each event.

2026-06-03 follow-up repair note: W6A now also includes a Mission Control
live-activity pass. Motion in the cockpit is tied to real status attributes:
running work, queued handoff, proof ready for review, queue activity, route
activity, and compact-path activity. These cues should make the system feel
alive without becoming decorative noise, and they must honor reduced-motion
preferences.

2026-06-03 follow-up repair note: W6A now also includes a Live CLI
command-output pass. The Live CLI is the command-following surface: selected
tasks must show a command-style `$ tool --target ...` line, captured
stdout/stderr, readable structured JSON output, and explicit no-output states.
Findings decide reportability, but ordinary task output should still be visible
when the backend has captured it.

2026-06-04 follow-up repair note: W6A now also includes a Mission Control
4k/125 density pass. Mission Control must stay scan-friendly for an effective
`2048x1152` dark-mode viewport representing a 15-inch 4k display at 125%
scaling: the cockpit snapshot stays bounded, command/output appears once in
Live CLI, Queue stays visible beside it, and attack-path/story/live-event/
technical detail stays behind a drilldown until the operator opens it.

2026-06-04 follow-up repair note: W6A now also includes a Queue/Live CLI
task-instance consistency pass. Mission Control Queue rows must use the same
selected-run task timeline as the Live CLI selector, without grouping repeated
tools or applying a different status filter. Clicking a queue row should select
that exact task output in Live CLI.

2026-06-04 follow-up repair note: W6A now also includes a compact inline CLI
preview pass. Mission Control keeps the command visible in the first viewport,
but structured JSON/raw stdout is summarized there; the dedicated Live CLI
remains the full raw command-output surface.

2026-06-03 recheck note: UX1 trust-breaking state repair was re-run after the
UX8 light-mode readability repair. Research raw API failures, Report Center
provider/billing masking, History filtered-empty recovery, Dashboard sparse
payload recovery, and cross-surface canonical consistency remained green, with
refreshed light-mode screenshot review.

2026-06-04 recheck note: UX1 was re-run again at the operator's request.
Research raw `500` recovery, Report Center provider/billing masking, History
filtered-empty recovery, Dashboard sparse payload recovery, and canonical
Dashboard/Mission/Findings/Evidence/Reports consistency remained green with
fresh screenshots.

2026-06-04 repeat recheck note: the same UX1 launcher prompt was repeated later
the same day. Codex re-ran the focused UX1 Playwright set; the trust-state
repair remained green and no UI code repair was required. A second same-day
repeat prompt was handled the same way, with the focused UX1 set green again.

## Workstreams

### W0 — UI truth audit and source map

Goal:
Build a concrete truth map for current UI surfaces, report variants, and
evidence/detail views.

Deliverables:

- inventory of current UI truth gaps
- screen-by-screen mapping of which API/source drives each displayed state
- list of contradictory or stale values

Likely touched files:

- `docs/validation/*ui*`
- `docs/strategy/*ui*`
- maybe small read-only test fixtures

Proof:

- a repo artifact documenting the truth map and mismatch list

### W1 — Live run truth strip and operator state model

Status: Complete on 2026-06-01, with clarity repair on 2026-06-01.

Validation artifact:

- `docs/validation/codex-ui-reporting-w1-run-truth-strip-2026-06-01.md`

Goal:
Make the operator-facing run state clear, stable, and live.

Scope:

- mission/run status surfaces
- validation/proof state
- persistence state
- canonical score summary

Requirements:

- no mixed or vague statuses
- clearly show whether a solve is merely observed or fully persisted
- surface "why this is blocked" when the truth chain is incomplete

Likely touched files:

- `ui-v2/src/**`
- `ui-v2/tests/**`
- read-only API wiring if required in `api/app/routers/runs.py`

Proof:

- UI tests showing the real state progression
- screenshots or validation artifacts for the affected views

Clarity repair note:

- Mission Control must be split into three non-technical operator screens:
  `Live` for what is happening now, queue, CLI output, and live events;
  `Results` for what happened and what counts; and `Overview` for the whole
  test, progress, and upcoming work. `Technical` remains the diagnostics tab.
- Operator screens must be interactive: queue/activity rows should drill into
  task output, findings should link to Findings/Evidence, and overview actions
  should link to Surface Map, History, Reports, or Technical as appropriate.
- Each information panel should pair plain-language Jip-en-Janneke explanation
  with technical facts so non-specialists understand the story while technical
  users can still inspect proof. `Overview` should also include a compact AI
  story panel that uses ChatGPT narrator panels when available and links back
  into History/Evidence Replay.
- The `Live` first viewport should be visually led instead of prose-led:
  branching timeline with proof/dead-end routes, done/now/next board, and
  progress/severity chart come before raw CLI/log detail.
- The `Live` first viewport should reuse Dashboard's blue visual language:
  `neon-panel`, blue surface backgrounds, cyan borders/glow accents, and
  status colors only where they carry meaning.
- Dense attack-path detail must not be squeezed into the main screen. The main
  `Mission path` shows the current route only; the full attack map opens as a
  viewport-level popout with replay controls, zoom controls, a severity legend,
  event detail panel, readable spacing, branch/dead-end lanes, and a separate
  proof/outcome layer. Multiple findings should be summarized by strongest
  proof plus a count instead of stacked into overlapping cards. Edges need
  visible connecting lines; small arrowheads should appear only on meaningful
  live/failed/proof direction changes, not on every routine completed step.
- Queued/running output-only states must say waiting/running and make clear
  that tool output does not count as a finding until persistence creates one.
- The default `Live` view must not render the technical run-truth strip or
  canonical score card. Those stay in `Technical`. Terminal error/no-finding
  runs must group repeated failures, show `Last task`, and say no reportable
  finding was created.

### W2 — Findings Theater truth pass

Status: Complete on 2026-06-01.

Validation artifact:

- `docs/validation/codex-ui-reporting-w2-findings-theater-truth-2026-06-01.md`

Goal:
Make Findings Theater reflect evidence, validation, and business meaning
without theater or ambiguity.

Requirements:

- finding status visible and canonical
- evidence summary separate from business impact summary
- remediation and next-step language only from supported data
- no raw exploit-runner labels as primary operator copy if a better normalized
  title exists

Likely touched files:

- `ui-v2/src/**`
- `ui-v2/tests/**`

Proof:

- theater view tests for verified vs observed vs blocked findings
- artifact demonstrating that a known finding shows the correct truth chain

### W3 — Evidence Replay clarity pass

Status: Complete on 2026-06-01.

Validation artifact:

- `docs/validation/codex-ui-reporting-w3-evidence-replay-clarity-2026-06-01.md`

Goal:
Turn evidence surfaces into something an operator can actually trust and scan.

Requirements:

- run-level executions, artifacts, and provenance linked clearly
- evidence state separated from conclusion state
- transcript/provenance visible without forcing the user to infer too much

Likely touched files:

- `ui-v2/src/**`
- `ui-v2/tests/**`

Proof:

- UI validation for evidence layout, live detail loading, and provenance labels

### W4 — Report Center overhaul

Status: Complete on 2026-06-01.

Validation artifact:

- `docs/validation/codex-ui-reporting-w4-report-center-truth-2026-06-01.md`

Goal:
Make Report Center truthful, readable, and operationally useful.

Requirements:

- clear separation between report variants
- preview tied to canonical run context
- visible "what will be included" and "what is excluded/not tested"
- no internal benchmark/lab junk in customer-facing variants
- report counts must match canonical findings truth

Likely touched files:

- `ui-v2/src/**`
- `ui-v2/tests/**`
- `api/app/services/reports.py`
- `api/app/services/report_pdf.py`
- `api/app/routers/runs.py`

Proof:

- exported report samples
- UI preview tests
- consistency checks between report contents and canonical findings

### W5 — Evidence-backed LLM report composition

Status: Complete on 2026-06-01.

Validation artifact:

- `docs/validation/codex-ui-reporting-w5-evidence-backed-llm-drafts-2026-06-01.md`

Goal:
Use an LLM to draft report language only from structured, evidence-backed
report payloads.

Requirements:

- input payload contains only tested scope and supported findings
- explicit field for "not tested / not verified" content
- LLM output is review-only phrasing, not canonical fact generation
- management report and technical report use different templates and constraints
- raw proof export remains non-LLM and deterministic

Likely touched files:

- `api/app/services/reports.py`
- `api/app/schemas/report_center.py`
- `api/app/routers/runs.py`
- `ui-v2/src/**` if preview/explanation changes are needed
- `ui-v2/tests/**`

Must not do:

- no silent widening of scope in report text
- no unsupported claim generation
- no report section for untested targets

Proof:

- structured payload snapshot
- before/after report artifact
- tests showing only included tested components appear in the final draft

### W6A — Mission experience spine and product narrative continuity

Status: Complete on 2026-06-01, with cohesion and snapshot repairs on 2026-06-02.

Validation artifact:

- `docs/validation/codex-ui-reporting-w6-mission-experience-spine-2026-06-01.md`
- `docs/validation/codex-ui-reporting-w6a-cohesion-repair-2026-06-02.md`
- `docs/validation/codex-ui-reporting-w6a-snapshot-repair-2026-06-02.md`

Goal:
Carry the selected mission story across the whole React v2 shell so every page
feels connected to the same live/evidence/findings/report journey.

Requirements:

- global app-shell spine for selected runs with `Now`, `Route`, and `Next`
- use selected run plus chain-aware tasks/findings/inventory as truth inputs
- terminal runs with stale queued rows must not look live
- plain-language state first, technical pages as drilldowns
- click-through actions into Mission Control, Live CLI, Evidence Replay,
  Findings, and Reports
- dashboard-blue visual language and readable responsive layout at 1536 and
  1280 widths
- accessible names scoped so global story controls do not collide with
  page-local buttons/tabs

Likely touched files:

- `ui-v2/src/App.tsx`
- `ui-v2/src/components/MissionExperienceSpine.tsx`
- `ui-v2/src/index.css`
- `ui-v2/tests/react-v2-critical-paths.spec.ts`

Proof:

- app-shell Playwright test for story content and report navigation
- full React v2 critical-path suite
- visual screenshots at 1536x864 and 1280x720

### W6B — Management-report rewrite rules

Goal:
Make management reports read like customer-ready management documents instead
of internal proof exports.

Requirements:

- customer/scope header must be clean
- internal run labels, benchmark IDs, loop labels, raw flags, and raw exploit
  markers stay out of the management-facing title layer
- business impact must be phrased in business language
- remediation recommendations must be cluster-specific, not generic filler

Likely touched files:

- `api/app/services/reports.py`
- `api/app/services/report_pdf.py`
- report validation artifacts

Proof:

- one before/after management-report comparison
- explicit review checklist for executive readability and truthfulness

### W7 — Accessibility and usability pass

Status: Complete on 2026-06-02.

Validation artifact:

- `docs/validation/codex-ui-reporting-w7-accessibility-usability-pass-2026-06-02.md`

Goal:
Make the UI accessible and calmer for actual operators.

Requirements:

- semantic labels
- keyboard navigation
- focus states
- readable hierarchy
- contrast and status clarity
- information density without chaos

Likely touched files:

- `ui-v2/src/**`
- `ui-v2/tests/**`
- `ui-v2/src/index.css`
- `ui-v2/src/App.css`

Proof:

- accessibility-focused UI checks
- screenshot proofs at key surfaces

### W8 — End-to-end report/evidence consistency validation

Status: Complete on 2026-06-02.

Validation artifact:

- `docs/validation/codex-ui-reporting-w8-e2e-report-evidence-consistency-2026-06-02.md`

Goal:
Prove the UI, report preview, exported reports, and evidence surfaces all tell
the same story.

Requirements:

- one named run used as consistency fixture
- same finding counts/statuses across:
  - run summary
  - findings theater
  - evidence replay
  - report center
  - exported report
- mismatches fail the task

Likely touched files:

- `ui-v2/tests/**`
- `api/app/services/reports.py`
- `api/app/routers/runs.py`
- validation artifacts under `docs/validation/`

Proof:

- a durable validation artifact showing the cross-surface consistency check

## Working order

The recommended order for Codex in this lane is:

1. W0 — UI truth audit
2. W1 — live run truth strip
3. W2 — Findings Theater truth pass
4. W3 — Evidence Replay clarity
5. W4 — Report Center overhaul
6. W5 — evidence-backed LLM report composition
7. W6A — mission experience spine and product narrative continuity
8. W6B — management-report rewrite rules
9. W7 — accessibility pass
10. W8 — end-to-end consistency validation

## Progress

### 2026-06-03 - M5 report helper extraction complete

Artifact:

- `docs/validation/codex-ui-reporting-m5-report-render-utils-extraction-2026-06-03.md`
- `docs/validation/codex-ui-reporting-m5-report-lifecycle-extraction-2026-06-03.md`
- `docs/validation/codex-ui-reporting-m5-report-metadata-extraction-2026-06-03.md`
- `docs/validation/codex-ui-reporting-m5-report-model-utils-extraction-2026-06-03.md`

Summary:

- started M5 by adding the report-only helper package
  `api/app/services/reporting/`
- moved generic report render helpers out of `api/app/services/reports.py`:
  JSON block formatting, humanized labels/values, key/value Markdown and HTML
  rendering, and target-summary rendering
- moved report lifecycle and availability helpers out of `reports.py` into
  `api/app/services/reporting/lifecycle.py`
- moved report variant labels, descriptions, aliases, primary variant order,
  and compliance framework selection into
  `api/app/services/reporting/metadata.py`
- moved report model ordering and display helpers into
  `api/app/services/reporting/model_utils.py`
- preserved the old helper names in `reports.py` through imports so report
  callsites, PDF titles, catalog labels, and exported behavior remain stable
- validation: `.venv` ruff passed for touched report files, full
  `api/tests/test_reports.py` passed, collection shows `24` report tests,
  lifecycle, metadata, and model-utils extraction reran the same touched-file
  ruff and report tests, backlog validation passed, and `git diff --check` is
  clean
- initial validation through system Python failed because `python` is not
  installed as an alias and system Python lacks `pypdf`; reran successfully via
  the repo `.venv`
- no Claude score-lane files, `NEXT_TASK.md`, `TASK_QUEUE.md`,
  assessment-loop/runtime files, worker runner files, scoring code, or active
  XBEN validation artifacts were changed

### 2026-06-03 - W6A Live CLI command-output repair complete

Artifact:

- `docs/validation/codex-ui-reporting-w6a-live-cli-command-output-2026-06-03.md`

Summary:

- repaired Live CLI after operator feedback that the page did not make command
  output easy to follow like a terminal
- made the dedicated Live CLI use the shared task terminal in full-height mode
- updated `LiveTaskDrillDown` so every selected task has a command-style line,
  labelled stdout/stderr, readable structured JSON output, explicit no-output
  state, and better line wrapping
- added a regression fixture with `target-intel` structured JSON output and a
  screenshot proof at 1536x864
- validation: touched-file ESLint, TypeScript build, focused Playwright
  (1 passed), screenshot Playwright (1 passed), full `npm test` (28 passed,
  including i18n key parity), production build, backlog validation, and
  `git diff --check` are green
- no Claude score-lane files, `NEXT_TASK.md`, `TASK_QUEUE.md`,
  assessment-loop/runtime files, worker runner files, scoring code, or active
  XBEN validation artifacts were changed

### 2026-06-03 - M3 API domain client split complete

Artifact:

- `docs/validation/codex-ui-reporting-m3-api-domain-clients-2026-06-03.md`

Summary:

- split `ui-v2/src/api/client.ts` into focused domain clients while preserving
  `client.ts` as the compatibility barrel used by existing screens
- moved shared transport behavior into `ui-v2/src/api/transport.ts`, including
  actor/tenant headers, base URL normalization, JSON/body handling, blob
  downloads, and `ApiError`
- added domain modules for engagements, runs, findings, reports, inventory,
  settings/auth, schedules, problems, packs, custom vulnerabilities, research,
  and deception
- validation: touched-file ESLint, TypeScript build, focused i18n Playwright
  (3 passed), focused cross-screen API Playwright (5 passed), full `npm test`
  (27 passed, including i18n key parity), production build, backlog
  validation, and `git diff --check` are green
- no Claude score-lane files, `NEXT_TASK.md`, `TASK_QUEUE.md`,
  assessment-loop/runtime files, worker runner files, scoring code, or active
  XBEN validation artifacts were changed

### 2026-06-03 - M2 store slice split complete

Artifact:

- `docs/validation/codex-ui-reporting-m2-store-slices-2026-06-03.md`

Summary:

- split `ui-v2/src/store/index.ts` into focused Zustand slices while preserving
  the public `useAegisStore` hook, actor storage-key exports, and existing
  state/action names
- added shared store types, actor persistence helpers, engagement/run
  selection slice, evidence/finding/inventory/insight slice, operator/settings
  slice, and runtime loading/error/run-stream slice
- kept `ui-v2/src/store/index.ts` as the composition root so existing screen
  imports do not change
- validation: touched-file ESLint, TypeScript build, focused i18n Playwright
  (3 passed), focused app-shell/Mission Control Playwright (2 passed), full
  `npm test` (27 passed, including i18n key parity), production build, backlog
  validation, and `git diff --check` are green
- no Claude score-lane files, `NEXT_TASK.md`, `TASK_QUEUE.md`,
  assessment-loop/runtime files, worker runner files, scoring code, or active
  XBEN validation artifacts were changed

### 2026-06-03 - W6A operator-presence spine repair complete

Artifact:

- `docs/validation/codex-ui-reporting-w6a-operator-presence-spine-2026-06-03.md`

Summary:

- repaired the global React v2 mission spine after operator feedback that the
  product still felt like disconnected screens instead of one system carrying
  the operator through the assessment
- redesigned the shell spine around `You are here`, `Route`, and `Your next
  move`, preserving canonical selected-run, chain-aware task/finding, and
  inventory truth
- added compact cockpit facts for target, checked progress, proof count, risk,
  evidence trails, and report readiness
- added one-line route-step context for Live, Evidence, Findings, and Report so
  each deep screen feels like a drilldown from the same story
- aligned visual treatment with a single blue instrument surface, live/status
  orb, active route cards, compact status dots, semantic status accents, and
  zero base letter-spacing
- reviewed and applied UI 101 references: Nielsen Norman heuristics, Fluent
  hierarchy/plain-language/semantic-color guidance, Carbon status indicators,
  and OWASP WSTG entry-point/execution-path mapping guidance
- validation: touched-file ESLint, TypeScript build, focused spine Playwright
  (1 passed), full `npm test` (25 passed, including i18n key parity),
  production build, backlog validation, and `git diff --check` are green
- no Claude score-lane files, `NEXT_TASK.md`, `TASK_QUEUE.md`,
  assessment-loop/runtime files, worker runner files, scoring code, or active
  XBEN validation artifacts were changed

### 2026-06-03 - W6A attack-map visible timing repair complete

Artifact:

- `docs/validation/codex-ui-reporting-w6a-attack-map-visible-timing-2026-06-03.md`

Summary:

- repaired Mission Control's compact current path and full attack-map node
  cards after operator feedback that the map still did not show when the attack
  was done/succeeded or how long AegisPT spent reaching proof
- added visible timing chips for run start, elapsed route time, task
  completion/failure time, task duration, proof persisted time,
  elapsed-from-start, and source-task duration
- updated route end-time calculation to include persisted finding timestamps
  as well as task timestamps
- extended the Mission Control Playwright fixture with a timed run and
  assertions that prove both compact path and full-map proof node expose clock
  time plus `after 8m` and `source took 1m`
- validation: touched-file ESLint, TypeScript build, focused Mission Control
  Playwright (1 passed), full `npm test` (25 passed, including i18n key
  parity), production build, backlog validation, and `git diff --check` are
  green
- no Claude score-lane files, `NEXT_TASK.md`, `TASK_QUEUE.md`,
  assessment-loop/runtime files, worker runner files, scoring code, or active
  XBEN validation artifacts were changed

### 2026-06-02 - W6A attack-map truth/timing repair complete

Artifact:

- `docs/validation/codex-ui-reporting-w6a-attack-map-truth-timing-repair-2026-06-02.md`

Summary:

- repaired Mission Control's attack map after operator feedback that it did not
  match actual findings/scan path and lacked timing context
- route nodes now come from real run task groups, preserve recent task order,
  and keep failed/dead-end branches separate from persisted proof
- persisted proof is linked to the best completed/matching source task, so a
  later queued task no longer appears to have produced existing findings
- proof nodes now use actual persisted finding titles with only sensitive token
  or benchmark-id redaction, instead of generic management categories
- full-map detail panels now include task start/update time, task duration,
  finding persisted time, elapsed time from run start, and source-task duration
- validation: touched-file ESLint, TypeScript build, focused Mission Control
  Playwright (1 passed), full `npm test` (25 passed, including i18n key
  parity), production build, backlog validation, and `git diff --check` are
  green
- no Claude score-lane files, `NEXT_TASK.md`, `TASK_QUEUE.md`,
  assessment-loop/runtime files, worker runner files, scoring code, or active
  XBEN validation artifacts were changed

### 2026-06-02 - M1 app shell split complete

Artifact:

- `docs/validation/codex-ui-reporting-m1-app-shell-split-2026-06-02.md`

Summary:

- split `ui-v2/src/App.tsx` into a thin provider/route tree plus dedicated
  route-shell modules under `ui-v2/src/components/app-shell/`
- moved shell bootstrap, selected engagement/run loading, selected-run scoped
  loading, topbar/workspace layout, route transitions, and error-boundary
  wrapping into `AppShell.tsx`
- extracted navigation config/rendering, command palette item building and UI,
  toast viewport, shared shell utilities, and workspace skeleton
- moved the intake route wrapper into
  `ui-v2/src/components/screens/IntakeScreen.tsx`
- validation: touched-file ESLint, TypeScript build, focused shell/intake
  Playwright (2 passed), standalone full `npm test` (25 passed, including i18n
  key parity), production build, backlog validation, and `git diff --check`
  are green
- an earlier full `npm test -- --run` was started in parallel with another
  Playwright devserver and failed with Vite connection refusals/resets; the
  standalone rerun passed
- no Claude score-lane files, `NEXT_TASK.md`, `TASK_QUEUE.md`,
  assessment-loop/runtime files, worker runner files, scoring code, or active
  XBEN validation artifacts were changed

### 2026-06-02 - M8 cross-surface consistency checker complete

Artifact:

- `docs/validation/codex-ui-reporting-m8-cross-surface-consistency-checker-2026-06-02.md`

Summary:

- added `ui-v2/src/viewModels/crossSurfaceConsistency.ts` as a shared
  view-model helper for comparing canonical findings, run-local summaries,
  report catalog counts, markdown preview claims, and evidence-link
  availability
- Report Center now renders a compact `Truth consistency` panel showing
  canonical, run-local, catalog, evidence, and preview state before export
- stale run-local summaries are treated as visible review caveats while
  report/customer truth stays anchored to canonical chain-aware findings
- extended the Report Center and canonical consistency Playwright tests so the
  deliberate fixture mismatch (`1` run-local vs `2` canonical) stays visible
  while findings/evidence/reports/preview stay aligned
- validation: targeted eslint, TypeScript build, focused Playwright grep
  (2 passed), production build, and full `npm test` (25 passed, including i18n
  key parity), backlog validation, and `git diff --check` are green
- no Claude score-lane files, `NEXT_TASK.md`, `TASK_QUEUE.md`,
  assessment-loop/runtime files, worker runner files, scoring code, or active
  XBEN validation artifacts were changed

### 2026-06-02 - M6 management attack-map and technique story complete

Artifact:

- `docs/validation/codex-ui-reporting-m6-management-attack-map-techniques-2026-06-02.md`

Summary:

- continued M6 by making management-facing reports explain what was tested,
  how the assessment moved from scope to evidence, and which techniques were
  used in plain language
- added deterministic management story facts in `api/app/services/reports.py`:
  a five-step attack map, a tested-scope story, and management-safe technique
  categories derived from stored task evidence
- English management Markdown/HTML/PDF now include `Attack Map`, `What Was
  Tested`, and `Techniques Used in Plain Language`
- Dutch management Markdown/PDF now include `Aanvalskaart`, `Wat is er precies
  getest?`, and `Gebruikte technieken in gewone taal`
- management outputs still suppress raw runner/tool/lab labels such as
  `interactive-exploit`, `sqlmap`, `nmap`, `nuclei`, `httpx`, XBEN/XBOW
  markers, flags, and HTTP baseline titles
- management report-draft payloads now expose the same facts as
  `management_story` in `RunReportDraftRead`, `structured_payload`,
  `draft_contract.allowed_input_facts`, and `source_data_categories` as
  `report_draft.management_story`; technical draft variants keep it empty
- validation: compileall, ruff, focused management/draft pytest (6 passed),
  full `api/tests/test_reports.py` (24 passed), backlog validation, and
  `git diff --check` are green
- no Claude score-lane files, `NEXT_TASK.md`, `TASK_QUEUE.md`,
  assessment-loop/runtime files, worker runner files, scoring code, or active
  XBEN validation artifacts were changed

### 2026-06-02 - M6 management report story/remediation repair complete

Artifact:

- `docs/validation/codex-ui-reporting-m6-management-report-story-remediation-2026-06-02.md`

Summary:

- continued M6 after operator review showed the management PDF still lacked a
  convincing business story, attacker path, role-specific remediation,
  standards badges, and clear explanation of how the test was grounded
- added deterministic management facts in `api/app/services/reports.py` for
  attacker paths, Engineering and IT/Ops remediation tracks, standards badges,
  risk-picture chart rows, and test-origin explanation
- English summary Markdown/HTML/PDF and Dutch management Markdown/PDF now
  include `Why This Matters` / `Waarom dit ernstig is`, attacker-path,
  Engineering/IT remediation, test-origin, and standards-badge sections
- management draft payloads now expose `attacker_story`,
  `remediation_tracks`, and `standards_badges` inside `management_story`;
  technical draft variants keep those management-only facts empty
- validation: py_compile, focused management/PDF pytest, focused report-draft
  pytest, full `api/tests/test_reports.py`, ruff, backlog validation, and
  `git diff --check` are green
- no Claude score-lane files, `NEXT_TASK.md`, `TASK_QUEUE.md`,
  assessment-loop/runtime files, worker runner files, scoring code, or active
  XBEN validation artifacts were changed

### 2026-06-02 - M6 report draft management payload complete

Artifact:

- `docs/validation/codex-ui-reporting-m6-report-draft-management-payload-2026-06-02.md`

Summary:

- continued M6 by carrying deterministic management decision facts into the
  AI-assisted report-draft structured payload
- added `management_decision` to `RunReportDraftRead`
- management draft variants now expose the object in `structured_payload`, the
  top-level API response, `draft_contract.allowed_input_facts`, and
  `source_data_categories` as `report_draft.management_decision`
- technical draft variants keep `management_decision` empty and do not include
  it in allowed input facts
- ChatGPT OAuth draft instructions now state that management variants must use
  `management_decision` as the canonical verdict/decision/action source
- validation: compileall, ruff, focused AI draft pytest (5 passed), full
  `api/tests/test_reports.py` (24 passed), backlog validation, and
  `git diff --check` are green
- no Claude score-lane files, `NEXT_TASK.md`, `TASK_QUEUE.md`,
  assessment-loop/runtime files, worker runner files, scoring code, or active
  XBEN validation artifacts were changed

### 2026-06-02 - M6 management decision facts complete

Artifact:

- `docs/validation/codex-ui-reporting-m6-management-decision-facts-2026-06-02.md`

Summary:

- continued in the Codex UI/reporting lane with a narrow M6 step after the
  report/view-model adapter work
- added deterministic management decision facts in `api/app/services/reports.py`
  so management report renderers and AI drafting share the same canonical
  verdict, decision, first actions, evidence basis, tested-scope summary,
  not-certified/not-claimed caveats, methodology references, and task coverage
  counts
- Dutch management Markdown/PDF now include `Besluit in een oogopslag`; English
  management summary Markdown/HTML/PDF now include `Management Decision`
- the ChatGPT-backed Dutch management draft prompt receives the same structured
  facts as fixed input before phrasing
- validation: compileall, ruff, focused management/PDF pytest, full
  `api/tests/test_reports.py` (24 passed), backlog validation, and
  `git diff --check` are green
- no Claude score-lane files, `NEXT_TASK.md`, `TASK_QUEUE.md`,
  assessment-loop/runtime files, worker runner files, scoring code, or active
  XBEN validation artifacts were changed

### 2026-06-02 - M4 report truth view-model adapter complete

Artifact:

- `docs/validation/codex-ui-reporting-m4-report-truth-viewmodel-2026-06-02.md`

Summary:

- continued with the first safe modularization item after W1-W8 completion
- added `ui-v2/src/viewModels/reportTruth.ts`
- moved Report Center's canonical report truth calculations out of
  `ReportCenter.tsx` into the adapter: count status, status tones, stage detail
  copy, included/excluded bullets, evidence-status checks, customer-copy warning
  checks, severity chart data, and report-catalog count parsing
- kept product behavior unchanged: Report Center still uses chain-aware
  findings, compares catalog included counts against canonical findings, and is
  still covered by W8's mismatch-sensitive consistency fixture
- validation: touched-file ESLint, TypeScript build, Vite production build,
  focused Report Center/W8 Playwright (2 passed), and standalone `npm test`
  (25 passed), backlog validation, and `git diff --check` are green
- no Claude score-lane files, `NEXT_TASK.md`, `TASK_QUEUE.md`, runtime runner
  files, backend report code, or active XBEN validation artifacts were changed

### 2026-06-02 - W8 end-to-end report/evidence consistency validation complete

Artifact:

- `docs/validation/codex-ui-reporting-w8-e2e-report-evidence-consistency-2026-06-02.md`

Summary:

- added a named React v2 consistency fixture proving Mission Control, Findings
  Theater, Evidence Replay, Report Center, report preview, and exported
  markdown share the same canonical finding truth
- kept the fixture intentionally mismatch-sensitive: selected-run local summary
  remains `1 total / 1 high+`, while chain-aware canonical findings contain
  two open high-or-critical findings
- made React report fixture catalog/markdown helpers derive included counts,
  severity totals, status totals, and evidence refs from active fixture findings
  instead of static report payloads
- added backend report coverage for `/reports`, management markdown, technical
  markdown, and evidence markdown so report exports preserve the same
  two-finding truth in their appropriate layers
- validation: Python compileall, ruff, touched-file ESLint, Vite production
  build, focused W8 Playwright, focused backend W8 pytest, full React v2
  critical-path suite (22 passed), `npm test` (25 passed), and full
  `api/tests/test_reports.py` (24 passed), backlog validation, and
  `git diff --check` are green
- Codex UI/reporting worklist W1-W8 is complete; `NEXT_TASK.md` and
  `TASK_QUEUE.md` remain untouched because the active task file belongs to
  Claude's score lane

### 2026-06-02 - W7 accessibility/usability pass complete

Artifact:

- `docs/validation/codex-ui-reporting-w7-accessibility-usability-pass-2026-06-02.md`

Summary:

- added translated skip-to-workspace navigation plus named shell landmarks for
  workspace, primary navigation, and operator menu
- expanded focus-visible styling across the topbar, sidebar, workspace, tab
  panels, and interactive regions
- improved command palette combobox/listbox semantics and command result labels
- exposed mission-spine active route step and progressbar semantics
- converted Mission Control view switching to a real tablist with selected tab
  state, tab panels, and Arrow/Home/End keyboard navigation
- improved the full attack map dialog with labelled title/help text, initial
  focus, Escape close, focus return to opener, keyboard zoom shortcuts, and
  accessible map-node names
- captured visual proof for Mission Control at 1536x864 and 1280x720 plus the
  full attack map overlay at 1536x864
- validation: touched-file ESLint, Vite production build, focused W7
  Playwright checks (2 passed), full React v2 critical-path suite (21 passed),
  `npm test` (24 passed, including i18n key parity), backlog validation, and
  `git diff --check` are green
- next Codex-owned implementation target is W8: end-to-end report/evidence
  consistency validation

### 2026-06-02 - W6B management PDF plain-language repair complete

Artifact:

- `docs/validation/codex-ui-reporting-w6b-management-pdf-plain-language-repair-2026-06-02.md`

Summary:

- operator feedback showed that management PDF/NL PDF output still exposed raw
  runner labels, FastAPI/OpenAPI technical titles, generic business impact, and
  no explicit standards section
- added management-safe categories for confirmed attack paths, public API
  documentation exposure, and informational connectivity baselines
- expanded management technical-title filtering to cover FastAPI, OpenAPI,
  Swagger, auto-docs, HTTP status, and baseline labels
- added explicit methodology sections to Dutch management output and English
  management summary PDF for PTES, OWASP WSTG, NIST SP 800-115, and optional
  OWASP ASVS
- clarified the management report is not certification, but evidence-first
  assessment output aligned to those references
- cleaned Dutch management target/date rendering
- validation: compileall, ruff, focused management/PDF regression, and full
  report suite (23 passed) are green
- next Codex-owned implementation target remains W7: Accessibility and
  usability pass

### 2026-06-02 - W6A Mission Control snapshot repair complete

Artifact:

- `docs/validation/codex-ui-reporting-w6a-snapshot-repair-2026-06-02.md`

Summary:

- operator feedback showed that Mission Control still looked crowded and did
  not answer the mission state in one glance
- hid the global app-shell mission spine on `/mission-control` to avoid
  duplicate route/story layers on the page that already owns the live cockpit
- added a dominant `Mission snapshot` panel to the Mission Control Live view
  with outcome headline, target, checked count, next action, five-step route,
  lead proof, and impact/severity gauge
- moved story cards, run picture, plain explanation, and technical facts behind
  one expandable details section
- kept attack map, queue, Live CLI, and live events as lower drilldowns instead
  of first-viewport competitors
- captured visual proof at 1536x864 and 1280x720
- validation: touched-file ESLint, Vite production build, focused Mission
  Control Playwright, full React v2 critical-path Playwright suite (20 passed),
  and `npm test` (23 passed, including i18n key parity) are green
- next Codex-owned implementation target remains W7: Accessibility and
  usability pass

### 2026-06-02 - W6A cohesion repair complete

Artifact:

- `docs/validation/codex-ui-reporting-w6a-cohesion-repair-2026-06-02.md`

Summary:

- operator feedback showed that Mission Control, Run Picture, and Evidence
  Replay still felt like separate blocks even after the first mission spine
  pass
- added a shared mission-story view model for route phases, safe finding
  titles, target summaries, task journey titles, and plain-language
  explanations
- aligned Mission Control, the global spine, Run Picture, and Evidence Replay
  around the same route phases: map surface, inspect behavior, test routes,
  prove impact, and tell outcome
- Evidence Replay now leads with a clickable `Mission evidence path` and lets
  operators filter task provenance by phase before opening transcript/artifact
  details
- Mission Control proof/outcome labels now use safe mission themes as primary
  copy while keeping raw tool/target/provenance metadata available as secondary
  detail
- visual proof screenshots captured for Mission Control, Evidence Replay, and
  an Evidence Replay task-list row
- validation: touched-file ESLint, Vite production build, full React v2
  critical-path Playwright suite (20 passed), and `npm test` (23 passed,
  including i18n key parity) are green
- next Codex-owned implementation target remains W7: Accessibility and
  usability pass

### 2026-06-02 - W6B complete

Artifact:

- `docs/validation/codex-ui-reporting-w6b-management-report-rewrite-2026-06-02.md`

Summary:

- added dedicated management-report header/finalization for summary Markdown so
  customer-facing title/header copy no longer includes run IDs
- added management-safe text, scope, title, business-impact, remediation, and
  clustering helpers for report output
- rewrote executive summary Markdown around evidence boundary, exposure score,
  business risk themes, tested/not-tested summary, and cluster-specific next
  steps
- rewrote Dutch management Markdown and the ChatGPT management prompt inputs to
  use the same safe scope/title/impact/action rules
- changed summary HTML so technical-only panels stay out of management output
  while remaining available in technical/evidence variants
- added a regression test proving raw benchmark, runner, flag, tool, and run
  labels are absent from management Markdown, Dutch management Markdown, and
  HTML summary output
- validation: `ruff check api/app/services/reports.py api/tests/test_reports.py`
  and `python -m pytest api/tests/test_reports.py` are green
- next Codex-owned implementation target is W7: Accessibility and usability
  pass

### 2026-06-01 - W6A complete

Artifact:

- `docs/validation/codex-ui-reporting-w6-mission-experience-spine-2026-06-01.md`

Summary:

- operator clarified that the missing product value was broader than reports:
  the UI must guide the operator through the assessment instead of feeling like
  disconnected screens
- added a global React v2 app-shell `MissionExperienceSpine` for selected runs
  with `Now`, `Route`, and `Next` zones
- uses selected-run plus chain-aware tasks, findings, and inventory as truth
  inputs
- terminal runs with stale queued task rows stay in review/outcome state rather
  than appearing live
- links the route and next actions into Mission Control, Live CLI, Evidence
  Replay, Findings, and Reports
- added route dots, connecting line, progress meter, and dashboard-blue surface
  styling in `ui-v2/src/index.css`
- scoped accessible names so global story controls do not collide with
  page-local Mission Control tabs or finding buttons
- added Playwright coverage and visual screenshots at 1536x864 and 1280x720
- next Codex-owned report-specific implementation target is W6B:
  Management-report rewrite rules

### 2026-06-01 - W5 complete

Artifact:

- `docs/validation/codex-ui-reporting-w5-evidence-backed-llm-drafts-2026-06-01.md`

Summary:

- added an inspectable AI report draft payload contract with
  `draft_contract`, `variant_contract`, `tested_scope`, `supported_findings`,
  `not_tested`, `not_verified`, and `raw_proof_export_non_llm`
- constrained ChatGPT OAuth report-draft input to the structured payload only;
  raw top-level `findings` and `tasks` arrays are no longer sent to the LLM
- routed findings without evidence refs, contradicted statuses, or excluded
  validation states into `not_verified` instead of positive supported claims
- separated completed-task tested targets from authorized-but-unexecuted scope
  and incomplete tasks through explicit `not_tested` payload entries
- split management, technical, compliance, and retest report draft contracts by
  audience/template constraints
- made the `evidence` variant return `not_applicable` for AI drafting because
  proof/evidence exports remain deterministic and non-LLM
- changed draft context loading to `report_context_for_run(run, session=session)`
  so drafts stay aligned with chain-aware report truth
- added backend tests for deterministic drafts, ChatGPT OAuth payload shape,
  management/technical contract separation, evidence-export non-LLM boundary,
  and unchanged canonical reports before/after drafting
- next Codex-owned implementation target is W6: Management-report rewrite rules

### 2026-06-01 - W4 complete

Artifact:

- `docs/validation/codex-ui-reporting-w4-report-center-truth-2026-06-01.md`

Summary:

- rebuilt Report Center around a compact report package flow: evidence, scope,
  findings, variant, and export
- made each package step clickable with plain-language and technical detail
  rather than forcing users through a text-heavy preview pane
- moved report counts and charts to the chain-aware canonical findings context
  via `getFindingsForRunContext(run)`
- compare the selected catalog report count against canonical findings before
  export and label mismatches explicitly
- show "what will be included" and "what is not claimed" as first-class panels
- label the hash as a report content hash instead of an evidence-integrity
  verdict
- replaced Report Center direct `fetch()` calls for briefing and Dutch
  management exports with shared API client helpers
- added report variant/preview Playwright coverage and manual screenshots at
  1280, 1536, and 1600 px; the layout breakpoint was moved to `2xl` so
  150%-style scaling keeps the report path readable
- next Codex-owned implementation target is W5: Evidence-backed LLM report
  composition

### 2026-06-01 - W3 complete

Artifact:

- `docs/validation/codex-ui-reporting-w3-evidence-replay-clarity-2026-06-01.md`

Summary:

- made Evidence Replay load task evidence through the chain-aware run context
  helper, so assessment-chain sibling task evidence is no longer omitted
- added a small Evidence Replay view-model for evidence scope, evidence state,
  provenance, transcript, artifact, and conclusion-state copy
- exposed execution ids, runner digests, task ids, stdout/stderr transcript
  labels, artifact hashes, timestamp/redaction/hash state, and artifact download
  labels in expanded task rows
- explicitly separated execution evidence from finding verdicts and business
  conclusions
- added UI tests for an assessment-chain evidence fixture where the selected run
  has one local task but the chain has two task evidence records
- next Codex-owned implementation target is W4: Report Center overhaul

### 2026-06-01 - W2 complete

Artifact:

- `docs/validation/codex-ui-reporting-w2-findings-theater-truth-2026-06-01.md`

Summary:

- added a Findings Theater truth view-model for canonical proof, evidence,
  validation, workflow, source, business impact, and remediation state
- normalized raw exploit-runner/flag titles as primary operator copy while
  preserving the stored title as drawer metadata
- split evidence summary, technical evidence, business impact, AI enrichment,
  and remediation into distinct drawer sections
- removed generic remediation/next-step fallbacks when no supported payload data
  exists
- added UI tests for verified, observed, and blocked finding truth chains
- repaired the W1 Mission Control heading contract so all-screen smoke tests have
  a stable `Mission Control` h1
- next Codex-owned implementation target is W3: Evidence Replay clarity pass

### 2026-06-01 - W1 complete

Artifact:

- `docs/validation/codex-ui-reporting-w1-run-truth-strip-2026-06-01.md`

Summary:

- added a Mission Control run truth strip with a canonical UI view-model for
  queued, running, observed, verified, persisted, and blocked/incomplete state
- split Mission Control into `Live`, `Results`, `Overview`, and `Technical`
  tabs, with the run truth strip visible only in `Technical`
- added interactive drilldowns: queue rows select CLI output, findings link to
  Findings/Evidence, overview cards link to Surface Map/History/Reports
- added plain-language explanation panels paired with technical fact panels
- added a compact AI story panel backed by ChatGPT narrator panels when
  available, with History/Evidence Replay links
- added visual first-viewport storytelling: Mission path branching timeline
  with a decision node, proof/dead-end routes, done/now/next board,
  progress/severity chart, collapsed explanation panels, and grouped queue rows
- aligned Mission Control first-viewport panels with Dashboard's blue
  `neon-panel`/cyan-accent visual language
- made assessment-chain aggregate findings/tasks the canonical Mission Control
  score source while keeping run-local summaries visibly labelled
- added UI tests for the W0 mismatch fixture: 1 run-local finding vs 2 aggregate
  persisted findings
- added UI tests proving observed task output with zero persisted findings is
  not displayed as a fully persisted solve
- added UI tests proving completed-with-errors/no-finding runs group repeated
  failures and avoid debug vocabulary on the default page
- cleaned related UI build/test drift in Live CLI i18n, locale parity, CSS
  import order, and Mission Control test navigation
- next Codex-owned implementation target is W2: Findings Theater truth pass

### 2026-06-01 - W0 complete

Artifact:

- `docs/validation/codex-ui-reporting-truth-audit-2026-06-01.md`

Summary:

- mapped the current React v2 run, finding, evidence, and report sources
- identified the main truth split between run-local summaries and
  assessment-chain aggregate findings/tasks
- identified Report Center labels and direct fetches that can misstate evidence
  or tenant/header behavior
- set W1 as the next Codex-owned implementation target

## Safe modularization work inside the Codex lane

The repo is not yet truly modular in the UI/reporting layer. These are the
modularization tasks Codex can do safely without crossing into the active
solver/orchestration lane.

### M1 — Split `ui-v2/src/App.tsx` into route-shell modules

Status: Complete on 2026-06-02.

Validation artifact:

- `docs/validation/codex-ui-reporting-m1-app-shell-split-2026-06-02.md`

Current state:

- `ui-v2/src/App.tsx` is a thin composition root for the `I18nProvider` and
  route tree.
- Shell bootstrap, loading, command palette, navigation, toasts, route-state
  loading, and run-selection helpers live under
  `ui-v2/src/components/app-shell/`.

Safe target:

- keep one thin `App.tsx`
- extract:
  - `AppShell`
  - navigation config / nav rendering
  - command palette
  - toast viewport
  - bootstrap hooks
  - run-selection helpers

Why safe:

- touches only the Codex-owned UI lane
- improves readability and testability without touching solver logic

### M2 — Split `ui-v2/src/store/index.ts` into state slices

Status: Complete on 2026-06-03.

Validation artifact:

- `docs/validation/codex-ui-reporting-m2-store-slices-2026-06-03.md`

Current state:

- `ui-v2/src/store/index.ts` is a thin Zustand composition root.
- engagement/run selection, findings/evidence selection, operator/settings, and
  runtime loading/error/run-stream state live in focused slice files under
  `ui-v2/src/store/`.

Safe target:

- extract slices:
  - engagement/run selection
  - findings/evidence selection
  - settings/actor
  - loading/error
  - live run stream

Why safe:

- preserves current UI data model
- reduces accidental coupling across screens

### M3 — Split `ui-v2/src/api/client.ts` into domain clients

Status: Complete on 2026-06-03.

Validation artifact:

- `docs/validation/codex-ui-reporting-m3-api-domain-clients-2026-06-03.md`

Current state:

- `ui-v2/src/api/client.ts` is a compatibility barrel.
- shared transport/error behavior lives in `ui-v2/src/api/transport.ts`.
- domain helpers live in focused API modules for runs, findings, reports,
  settings/auth, packs, and adjacent product domains.

Safe target:

- extract domain clients:
  - `api/runs.ts`
  - `api/findings.ts`
  - `api/reports.ts`
  - `api/settings.ts`
  - `api/packs.ts`
  - shared transport/error helper remains central

Why safe:

- reduces UI integration confusion
- makes report/evidence work much easier without touching runtime behavior

### M4 — Add report/view-model adapters

Status: Partially complete on 2026-06-02 for Report Center report-truth adapter.

Validation artifact:

- `docs/validation/codex-ui-reporting-m4-report-truth-viewmodel-2026-06-02.md`

Current state:

- screens likely consume raw API shapes too directly

Safe target:

- create UI-facing adapters/view-model builders for:
  - run truth strip
  - finding truth badge/state
  - evidence replay summary
  - report preview metadata

Why safe:

- lets UI truth become canonical at the presentation boundary
- avoids screen components each re-inventing status logic

### M5 — Split `api/app/services/reports.py` by concern

Status: Started on 2026-06-03 with report render-utils, lifecycle, metadata, and model-utils extraction.

Validation artifact:

- `docs/validation/codex-ui-reporting-m5-report-render-utils-extraction-2026-06-03.md`
- `docs/validation/codex-ui-reporting-m5-report-lifecycle-extraction-2026-06-03.md`
- `docs/validation/codex-ui-reporting-m5-report-metadata-extraction-2026-06-03.md`
- `docs/validation/codex-ui-reporting-m5-report-model-utils-extraction-2026-06-03.md`

Current state:

- `reports.py` is ~7.6k lines and mixes context building, variant rendering,
  Dutch management rendering, HTML/Markdown assembly, report catalog logic,
  draft generation, and LLM drafting payload work
- first slice extracted generic report render helpers into
  `api/app/services/reporting/render_utils.py` while preserving current report
  behavior through existing report tests
- second slice extracted report lifecycle and availability helpers into
  `api/app/services/reporting/lifecycle.py` while preserving catalog behavior
  through existing report tests
- third slice extracted report variant metadata and normalization into
  `api/app/services/reporting/metadata.py` while preserving PDF/catalog report
  titles, descriptions, aliases, and compliance framework selection
- fourth slice extracted report model ordering and display helpers into
  `api/app/services/reporting/model_utils.py` while preserving report context,
  finding-view artifact links, and renderer behavior

Safe target:

- extract modules under a report package by concern, for example:
  - context building
  - catalog / lifecycle helpers
  - management NL rendering
  - technical/evidence rendering
  - draft payload shaping
  - LLM phrasing adapters

Why safe:

- stays within the reporting lane
- directly supports the evidence-backed report overhaul

### M6 — Separate canonical report facts from LLM phrasing

Status: Partially complete on 2026-06-02 for management decision facts, management attack-map/technique story, and report-draft structured payload.

Validation artifact:

- `docs/validation/codex-ui-reporting-m6-management-decision-facts-2026-06-02.md`
- `docs/validation/codex-ui-reporting-m6-report-draft-management-payload-2026-06-02.md`
- `docs/validation/codex-ui-reporting-m6-management-attack-map-techniques-2026-06-02.md`
- `docs/validation/codex-ui-reporting-m6-management-report-story-remediation-2026-06-02.md`

Current state:

- management-report logic had mixed factual selection and drafted wording in
  the management decision layer
- a deterministic management decision facts helper now exists for management
  verdict, decision, first actions, evidence basis, tested-scope summary,
  not-certified/not-claimed caveats, methodology references, and task coverage
  counts
- the AI report-draft API now exposes those facts as `management_decision` for
  management variants, while technical variants keep that field empty
- management reports now include deterministic `management_story` facts:
  attack-map route, tested-scope story, and management-safe technique
  categories grounded in task evidence
- the AI report-draft API exposes those story facts as `management_story` for
  management variants, while technical variants keep that field empty
- management reports now also carry deterministic attacker-path,
  Engineering/IT remediation, standards-badge, risk-picture, and test-origin
  facts so management output can explain why the risk matters, what an attacker
  would do, what teams should do next, which standards were used, and how the
  test reached its conclusion

Safe target:

- explicit structured report payload layer
- separate deterministic fact selection from optional LLM phrasing

Why safe:

- this is one of the most important product-truth separations
- it improves correctness without touching assessment runtime logic

### M7 — Add report/evidence fixture pack for UI tests

Current state:

- UI/report tests use fixtures, but consistency-focused named scenarios should
  be made first-class

Safe target:

- add a named fixture matrix for:
  - observed but unverified
  - verified but not persisted
  - verified and persisted
  - blocked / contradictory score state
  - management-report exclusion of untested scope

Why safe:

- lets us harden truth behavior before touching broad product flows

### M8 — Build a cross-surface consistency checker

Status: Complete on 2026-06-02 for Report Center consistency view-model and UI proof.

Validation artifact:

- `docs/validation/codex-ui-reporting-m8-cross-surface-consistency-checker-2026-06-02.md`

Current state:

- Report Center now has a shared cross-surface consistency view-model helper
  and panel that compares canonical findings, run-local summaries, catalog
  counts, preview claims, and evidence-link availability.
- The named canonical consistency fixture proves stale run-local truth remains
  visible as a caveat while customer/report surfaces use canonical findings.

Safe target:

- one validation helper that compares:
  - run summary counts
  - findings list counts
  - report catalog/export counts
  - evidence-linked finding availability

Why safe:

- this is a UI/reporting invariant, not a solver/orchestration change

## Modularization order inside the Codex lane

Recommended modularization order:

1. M4 — report/view-model adapters
2. M8 — cross-surface consistency checker
3. M1 — `App.tsx` split
4. M2 — store slices
5. M3 — API domain clients
6. M6 — canonical report facts vs LLM phrasing
7. M5 — `reports.py` extraction
8. M7 — fixture matrix hardening

## UX system follow-up queue from 2026-06-03 audit

Validation source:

- `docs/validation/codex-ui-reporting-ui-system-audit-2026-06-03.md`

These are Codex-owned UI/reporting work items. They intentionally remain in
this worklist until the operator explicitly asks to promote one into the active
repo task queue.

### UX1 — Trust-breaking state repair

Status: Complete on 2026-06-03.

Validation artifact:

- `docs/validation/codex-ui-reporting-ux1-trust-breaking-state-repair-2026-06-03.md`

Screenshot evidence:

- `docs/validation/codex-ui-reporting-ux1-report-provider-mask-1536x864.png`
- `docs/validation/codex-ui-reporting-ux1-research-safe-error-1536x864.png`
- `docs/validation/codex-ui-reporting-ux1-history-filter-empty-1536x864.png`
- `docs/validation/codex-ui-reporting-ux1-history-filter-reset-1536x864.png`

Goal:
Remove raw, confusing, or contradictory states that make the product feel
untrustworthy before further visual polish.

Scope:

- Research raw `500` / no-engagement recovery state
- Report Center raw AI provider/billing error handling
- History empty-state/filter recovery
- Dashboard/Mission risk and active-run truth checks

Acceptance:

- no customer-facing page exposes raw provider, stack, or generic API errors
- every empty state explains what happened and gives a clear recovery action
- Dashboard, Mission Control, Findings, and Reports agree on selected run,
  findings, risk, and report readiness
- screenshot proof exists for repaired states

2026-06-03 verification note: UX1 was rechecked after the later UX2-UX8
passes. Research, Report Center, History, Dashboard sparse recovery, Report
Center truth, and the canonical cross-surface fixture remain green. No new
repair was required. Validation artifact:
`docs/validation/codex-ui-reporting-ux1-trust-state-recheck-2026-06-03.md`.

Likely touched files:

- `ui-v2/src/components/screens/ResearchScreen.tsx` or adjacent research screen
- `ui-v2/src/components/screens/ReportCenter.tsx`
- `ui-v2/src/components/screens/HistoryScreen.tsx`
- `ui-v2/src/components/MissionExperienceSpine.tsx`
- `ui-v2/src/viewModels/**`
- `ui-v2/tests/**`

### UX2 — Shared page experience contract

Status: Complete on 2026-06-03.

Validation artifact:

- `docs/validation/codex-ui-reporting-ux2-shared-page-experience-contract-2026-06-03.md`

Screenshot evidence:

- `docs/validation/codex-ui-reporting-ux2-admin-compact-spine-1536x864.png`
- `docs/validation/codex-ui-reporting-ux2-diagnostics-compact-spine-1280x720.png`

Goal:
Make every route follow one understandable pattern: primary answer, primary
action, evidence summary, and drilldown.

Scope:

- define reusable page header/context variants for active assessment, review,
  outcome, admin/build, and diagnostics pages
- compact the global mission spine on secondary/admin pages
- reduce first-viewport text and repeated labels

Acceptance:

- every primary route answers "what is this page for?" in the first viewport
- every route has one obvious next action or an explicit "nothing to do" state
- admin/build pages no longer carry the full active-assessment cockpit weight
- screenshots at 1536x864 and 1280x720 show no cramped first viewport

Likely touched files:

- `ui-v2/src/components/MissionExperienceSpine.tsx`
- `ui-v2/src/components/app-shell/**`
- `ui-v2/src/components/screens/**`
- `ui-v2/src/i18n/locales/**`
- `ui-v2/tests/**`

### UX3 — Mission Control living cockpit

Status: Complete on 2026-06-03.

Validation artifact:

- `docs/validation/codex-ui-reporting-ux3-living-cockpit-command-stream-2026-06-03.md`

Screenshot evidence:

- `docs/validation/codex-ui-reporting-ux3-living-cockpit-command-stream-1536x864.png`

Goal:
Make Mission Control feel alive and immediately followable during a run.

Scope:

- active route animation tied to real task/run status
- current command/output strip in the cockpit
- event pulse and newest-event sequencing
- elapsed timing and waiting/running reason
- queue handoff state
- reduced-motion-safe behavior

Acceptance:

- running, queued, proof-ready, completed, failed, and waiting states each have
  a distinct live presentation
- the active task's command/output can be followed without opening full CLI
- animations are state-driven, not decorative, and honor reduced motion
- Playwright screenshots and interaction tests prove the live cockpit states

Likely touched files:

- `ui-v2/src/components/screens/MissionControlV3.tsx`
- `ui-v2/src/components/CinemaMode.tsx`
- `ui-v2/src/components/MissionExperienceSpine.tsx`
- `ui-v2/src/viewModels/**`
- `ui-v2/tests/react-v2-critical-paths.spec.ts`

### UX4 — Attack path truth map v2

Status: Complete on 2026-06-03.

Validation artifact:

- `docs/validation/codex-ui-reporting-ux4-attack-path-truth-map-v2-2026-06-03.md`

Screenshot evidence:

- `docs/validation/codex-ui-reporting-ux4-attack-path-truth-map-1536x864.png`

Goal:
Make the full attack map draw the actual selected run: all meaningful steps,
branches, dead ends, proof milestones, timestamps, durations, and finding links.

Scope:

- selected-run task/finding binding
- one node per meaningful task/proof event instead of grouped cards that hide
  individual findings
- branch/dead-end rendering with readable edges and small directional markers
- wheel zoom, drag pan, fit-to-route, keyboard zoom, and detail click-through
- severity legend and evidence/finding links

Acceptance:

- attack-map nodes match the selected mission/run and do not reuse stale output
- reportable finding count and proof nodes do not contradict each other
- map shows when each important step happened and how long it took
- map remains usable at 125% and 150% browser scaling

Likely touched files:

- `ui-v2/src/components/screens/MissionControlV3.tsx`
- `ui-v2/src/components/CinemaMode.tsx`
- `ui-v2/src/viewModels/**`
- `ui-v2/tests/**`

### UX5 — Evidence Replay timeline

Status: Complete on 2026-06-03.

Validation artifact:

- `docs/validation/codex-ui-reporting-ux5-evidence-replay-timeline-2026-06-03.md`

Screenshot evidence:

- `docs/validation/codex-ui-reporting-ux5-evidence-replay-timeline-1536x864.png`

Goal:
Turn Evidence Replay from a dense fact list into a clear replay of what was
attempted, observed, stored, and used in findings/reports.

Scope:

- chronological evidence timeline
- task output, artifact, transcript, and provenance drilldowns
- "this evidence proves / does not prove" summaries
- links from evidence steps to findings and report statements

Acceptance:

- first viewport shows the evidence path and current selected step, not long
  prose/list walls
- every finding-linked evidence item can be traced back to task/artifact facts
- unproven or missing evidence is clearly labelled without implying findings

Likely touched files:

- `ui-v2/src/components/screens/EvidenceReplay.tsx`
- `ui-v2/src/viewModels/**`
- `ui-v2/tests/**`

### UX6 — Findings and Problems triage board

Status: Complete on 2026-06-03.

Validation artifact:

- `docs/validation/codex-ui-reporting-ux6-findings-problems-triage-board-2026-06-03.md`

Screenshot evidence:

- `docs/validation/codex-ui-reporting-ux6-findings-triage-board-1536x864.png`

Goal:
Make review and remediation decision-making clear for both operators and
managers.

Scope:

- finding grouping/deduplication
- severity priority lanes
- business impact and proof strength
- remediation owner and next action
- Problems Center urgent/due/owner/SLA board

Acceptance:

- repeated findings are grouped without hiding individual evidence
- the first viewport answers what must be fixed first and why
- findings show plain-language impact plus technical proof and remediation
- Problems Center starts with the small set of decisions needed today

Likely touched files:

- `ui-v2/src/components/screens/FindingsTheater.tsx`
- `ui-v2/src/components/screens/ProblemsCenter.tsx`
- `ui-v2/src/viewModels/**`
- `ui-v2/tests/**`

### UX7 — Management report experience and export proof

Goal:
Make the report workflow and exported management PDFs convincing,
plain-language, evidence-backed, and standards-aware.

Scope:

- deterministic fallback management brief when AI drafting fails
- safe provider-error handling
- standards badges/icons for PTES, OWASP WSTG, NIST SP 800-115, and optional
  ASVS mappings
- actual attack-map preview and report export inclusion
- management, engineering, and IT/operations remediation sections
- "tested / not tested / not proven" sections
- evidence citations for report claims

Acceptance:

- management report explains what was tested, how the test was built, which
  standards informed it, what a hacker could do, and what teams must fix
- Dutch and English management outputs avoid "see technical report" placeholders
- report UI never shows raw provider billing/API errors
- report preview/export uses the same canonical evidence and attack path
- PDF/text tests prove standards, attack map, techniques, remediation, and
  evidence basis are present

Likely touched files:

- `ui-v2/src/components/screens/ReportCenter.tsx`
- `ui-v2/src/viewModels/managementReportProof.ts`
- `api/app/services/reports.py`
- `api/app/services/report_pdf.py`
- `api/app/services/reporting/**`
- `api/app/schemas/report_center.py`
- `api/tests/test_reports.py`
- `ui-v2/tests/**`

2026-06-03 completion note: UX7 is complete. Report Center now has a
deterministic Management proof panel before preview/export, derived from the
selected report catalog entry, canonical findings, report truth, and selected
run. It shows the route from scope to proof/decision, standards badges
(`[PTES]`, `[WSTG]`, `[NIST]`, `[ASVS]`), plain-language techniques, evidence
basis, not-claimed boundaries, and Management/Engineering/IT-Ops ownership.
Validation artifact:
`docs/validation/codex-ui-reporting-ux7-management-report-proof-2026-06-03.md`.

### UX8 — Light mode and theme tokenization

Goal:
Add a reliable light mode only after hardcoded dark surfaces are moved into
semantic design tokens.

Scope:

- `data-theme` and persisted preference
- system preference fallback
- semantic tokens for panels, terminals, charts, severity colors, attack-map
  edges, focus rings, and disabled states
- replace hardcoded dark colors in Mission Control, Dashboard, Reports, SVG
  maps, charts, terminal panels, and legacy app CSS

Acceptance:

- dark and light themes both pass contrast/focus/reflow checks
- screenshots at 1536x864, 1280x720, and 125%/150% scaling are readable
- terminal and attack-map surfaces remain legible in both modes
- theme preference persists and does not break localized UI

Likely touched files:

- `ui-v2/src/index.css`
- `ui-v2/tailwind.config.*`
- `ui-v2/src/components/**`
- `ui-v2/src/viewModels/reportTruth.ts`
- `ui-v2/tests/**`

2026-06-03 completion note: UX8 is complete. React v2 now applies a persisted
`data-theme` preference, falls back to system preference when no stored
preference exists, and exposes a localized theme toggle in the App shell.
Dashboard, Mission Control, and Live CLI are proven in light mode at 1536x864,
1280x720, and a constrained 1024x576 viewport. Live CLI remains a deliberate
dark terminal surface with fixed terminal contrast. Validation artifact:
`docs/validation/codex-ui-reporting-ux8-light-mode-theme-tokenization-2026-06-03.md`.

2026-06-03 repair note: UX8 received an additional light-mode readability
repair after operator feedback showed unreadable hardcoded dark panels still
existed in secondary surfaces. Normal product panels in Report Center, Evidence
Replay, Findings Theater, Problems Center, Intake, and Mission Control now use
theme-safe surfaces. Deliberately dark attack-map, terminal, Cinema Mode, and
crash/code surfaces are explicitly scoped with fixed contrast classes. The
Playwright suite now rejects unscoped dark-only panels in light-mode primary
screens. Validation artifact:
`docs/validation/codex-ui-reporting-ux8-light-mode-readability-repair-2026-06-03.md`.

## Explicitly out of scope for this worklist

- XBEN score-lane execution changes
- exploit-loop planner changes
- interactive-exploit runtime heuristics
- provider bakeoffs
- focused-assessment throughput tuning
- verdict-gate persistence fixes in the active score lane
- broad architecture rewrites not tied to UI/reporting truth

## Definition of success for this Codex lane

This lane is successful when:

1. the UI shows live, canonical, operator-trustworthy truth
2. findings/evidence/report surfaces agree with each other
3. management reports only say what was actually tested and proven
4. the LLM is constrained to wording, not fact invention
5. the work stays isolated enough that Claude's score-lane can continue cleanly
