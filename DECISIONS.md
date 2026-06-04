# Decisions

## Core decisions

1. AegisPT remains evidence-first. Findings, reports, and future analysis layers must stay grounded in recorded evidence and reproducible execution.
2. AI proposes and the controlled engine executes. Runtime execution remains approval-aware and deterministic.
3. Customer-specific capability packs are generated after inventory and relevance analysis, not during active runtime execution.
4. Live runtime mutation is prohibited. No self-modifying assessment runtime is allowed.
5. Codex is the primary builder in the repository, but it must operate through the supervised build lane and the repository governance files.
6. The repository is the source of truth for future Codex runs, tasks, and decisions.

## Prompt authority

Prompt 1 and Prompt 2 are authoritative for:

- methodology alignment
- adaptive testing architecture
- capability pack registry and promotion flow
- finding provenance and reporting structure

Future work must integrate with those foundations rather than redefining them.

## Session execution contract

- the long-form Claude execution contract for AegisPT sessions lives in
  `docs/strategy/claude-universal-execution-contract.md`
- operators should use the short launcher prompt from that file rather than
  pasting the full long-form contract inline each time
- the in-repo markdown file is the canonical source so future edits are versioned
  and reviewable in git

## Parallel Codex lane for UI/reporting

- Codex may keep a separate non-promoted worklist for UI, accessibility,
  reporting, and evidence-surface work when the active `NEXT_TASK.md` is owned
  by a different score-lane effort
- the initial coordination artifact for this lane is
  `docs/strategy/codex-ui-reporting-worklist-2026-06-01.md`
- the session execution contract for this Codex-owned lane is
  `docs/strategy/codex-universal-execution-contract.md`

## React V2 Store Slice Boundary (2026-06-03)

- `ui-v2/src/store/index.ts` is the public Zustand store composition root.
  Screens should keep importing `useAegisStore` and public store types from the
  root `store` module.
- Store implementation should live in focused slices under `ui-v2/src/store/`
  for engagement/run selection, evidence/finding state, operator/settings
  state, and runtime loading/error/run-stream state.
- Future UI/reporting changes should preserve the public store surface unless a
  dedicated migration task updates all consumers and tests together.

## React V2 API Client Boundary (2026-06-03)

- `ui-v2/src/api/client.ts` is the compatibility barrel for screen imports.
  Screens may keep importing API helpers from it.
- Shared fetch behavior belongs in `ui-v2/src/api/transport.ts`, including
  actor headers, tenant headers, base URL normalization, JSON/body handling,
  blob downloads, and `ApiError`.
- Domain API helpers should live in focused modules (`runs`, `findings`,
  `reports`, `settings`, `packs`, and adjacent product domains) so future
  report/evidence UI changes do not reopen one mixed client file.

## React V2 Live CLI Terminal Contract (2026-06-03)

- Live CLI is the operator's command-following surface. It must show a
  command-style line for the selected task, followed by captured stdout/stderr
  when available.
- Task output is not limited to persisted findings. Findings decide reporting;
  Live CLI should still expose ordinary task stdout/stderr, transient runner
  output, and stored execution detail.
- Structured runner output such as JSON must be expanded into readable terminal
  lines instead of rendered as one dense blob. Raw evidence remains available in
  Evidence Replay, but Live CLI should be readable enough to follow the run in
  real time.

## React V2 Safe Operator Messaging Contract (2026-06-03)

- Operator-facing and customer-facing React v2 surfaces must not render raw
  provider errors, billing errors, stack traces, request IDs, API-key hints,
  generic `AegisPT API request failed` text, or structured diagnostic payloads.
- Raw diagnostics remain backend/log evidence only. UI surfaces should translate
  failures into safe recovery copy that explains what the operator can do next
  and whether stored evidence/run state is still usable.
- Report Center must sanitize AI/provider briefing text even when a backend
  endpoint returns the diagnostic as a normal string instead of an HTTP error.
- Future UI/reporting pages should reuse the shared safe-message helper instead
  of rebuilding local `error.message` handling.

## React V2 Management Report Export Proof Contract (2026-06-03)

- Report Center should show management export proof before download using the
  same selected report catalog entry, canonical findings, report truth model,
  and selected run context used by preview/export flows.
- Standards badges in the UI indicate methodology alignment or mapping
  (`[PTES]`, `[WSTG]`, `[NIST]`, `[ASVS]`), not certification.
- Management-facing proof should explain the route from scope to discovery,
  technique, evidence, and decision; raw terminal output remains a drilldown,
  not the default management story.
- Remediation ownership should be split visibly between Management,
  Engineering, and IT/Ops when the report is being prepared for an audience
  outside the operator team.

## React V2 Shared Page Experience Contract (2026-06-03)

- The full mission story spine belongs on primary assessment, evidence, finding,
  report, history, problem, and surface-map routes where route-stage context is
  part of the operator decision.
- Supporting routes such as mission setup, diagnostics, capability packs,
  knowledge libraries, research, and settings should use a compact mission
  context bar instead of the full active-assessment cockpit.
- Compact context must still preserve selected-run truth: target, checked
  evidence, saved proof, and one obvious mission action. It should not invent
  page facts or hide the primary page purpose.
- Compact context must stack cleanly at 1280x720 so it does not crowd command
  output, forms, or admin controls in the first viewport.

## React V2 Theme Tokenization Contract (2026-06-03)

- React v2 light/dark mode is controlled by `data-theme` on the root document
  element, with stored user preference taking precedence over system
  preference.
- Shared shell, panel, focus, mission-spine, Mission Control snapshot, and
  command preview colors should use semantic CSS tokens instead of hardcoded
  dark-only values.
- Raw command surfaces such as Live CLI may remain dark in light mode when they
  intentionally mimic a terminal, but their command/stdout/stderr colors must
  be fixed for terminal contrast and not inherit low-contrast light-theme muted
  text.
- Deliberately dark canvases such as attack maps, Cinema Mode, raw terminal
  output, and crash stack/code blocks must be scoped with a fixed contrast
  class such as `dark-canvas` or `terminal-code`.
- Ordinary product panels, cards, report proof blocks, evidence panels, triage
  boards, and intake controls must use semantic theme surfaces instead of
  hardcoded dark-only backgrounds.

## React V2 Mission Control Living Cockpit Contract (2026-06-03)

- Mission Control's first viewport must separate overview from command
  following. The cockpit snapshot answers "where am I and what needs my
  attention"; Live CLI answers "which command ran and what did it output."
- The Live view must not render a duplicate cockpit command preview when the
  Live CLI panel is visible. Live CLI is the single command-following surface
  for command line, stdout/stderr, no-output states, and task switching.
- Mission Control may show a compact inline terminal preview, but it must not
  flood the first viewport with raw structured output. JSON-like output should
  be summarized in the inline preview, with the full raw stream available in the
  dedicated Live CLI.
- The selected task remains selected-run/task driven: running task first,
  queued task second, latest task as fallback. It must show explicit
  queued/running/no-output copy in Live CLI rather than silently appearing
  blank.
- Queue rows in Mission Control must be raw task instances from the same
  selected-run timeline used by the Live CLI selector. Repeated tools must not
  be merged into one row when those executions have separate task ids or output.
- Mission Control must be tested at high-DPI operator density, including an
  effective dark-mode `2048x1152` viewport for a 15-inch 4k display at 125%
  scaling. The first viewport should keep the cockpit bounded, keep Live CLI and
  Queue visible, and move attack-path/story/live-event/technical detail behind
  a drilldown until the operator asks for it.

## React V2 Evidence Replay Timeline Contract (2026-06-03)

- Evidence Replay's first viewport should be timeline-first: the selected
  evidence step and chronological replay must appear before long task lists,
  raw transcripts, or artifact inventories.
- Each selected evidence step must state what the evidence proves and what it
  does not prove. Task output proves execution/provenance only; findings,
  validation, business impact, remediation, and report wording remain owned by
  Findings and Reports.
- Finding-linked evidence must trace back to loaded task/detail facts whenever
  possible: task id, target, tool, artifact id, artifact hash/name, evidence
  ref, proof reference, and replay recipe metadata. Missing links must be
  labelled as review-needed rather than silently inferred.
- Route phase controls, selected timeline step, and visible task drilldowns
  should move together so Evidence Replay feels like one evidence path instead
  of disconnected lists.

## React V2 Findings/Problems Triage Contract (2026-06-03)

- Findings Theater may group repeated findings by deterministic list facts such
  as normalized title, severity, target count, evidence refs, validation status,
  due date, and SLA breach state, but it must not hide the individual findings
  or evidence refs behind the group.
- Triage-board copy may derive priority, proof strength, and next-action cues
  from stored list fields only. Stored business impact, technical proof,
  remediation text, and next steps remain owned by the selected finding detail
  payload and must not be invented from severity alone.
- Problems Center should start with today's remediation decisions: urgent
  severity, due/overdue state, missing owner, and SLA-watch state. Those lanes
  must feed the same bulk-action selection model as the long lifecycle list.

## Report Service Package Boundary (2026-06-03)

- `api/app/services/reports.py` remains the compatibility entry point for
  report generation, catalog building, report drafts, and router imports while
  M5 gradually extracts concerns.
- Extracted helpers should live under `api/app/services/reporting/` and must
  stay report-only. They must not call assessment-loop, worker, runner, scoring,
  or runtime mutation code.
- Report variant labels, descriptions, aliases, primary variant ordering, and
  compliance framework selection belong in
  `api/app/services/reporting/metadata.py`; `reports.py` may re-export them for
  compatibility with existing PDF, catalog, and router callsites.
- Report model ordering/display helpers belong in
  `api/app/services/reporting/model_utils.py`; `reports.py` may re-export them
  for compatibility with existing report renderers and finding-view artifact
  link callsites.
- Each extraction slice must preserve exported report behavior through existing
  report tests before larger rendering, catalog, LLM-phrasing, or PDF concerns
  move out of the legacy module.

## Mission Control full attack map interaction (2026-06-03)

- The full Mission Control attack map is a pan/zoom canvas, not a static
  scrollbox. Operators must be able to inspect wide routes with mouse-wheel
  zoom, drag-to-pan, keyboard zoom, and a bounds-based Fit action.
- Fit must calculate from the rendered map bounds and viewport dimensions so
  the whole route is centered in view, especially at browser/display zoom levels
  such as 125% or 150%.
- Node click-through detail remains required. Panning must not steal ordinary
  node selection, because the map is both a visual route and the drilldown entry
  point for step evidence.
- The attack map visualizes the selected run's route, not the whole assessment
  chain. Mission Control may keep chain-aware truth for canonical counts and
  reports, but the map must use selected-run tasks and selected-run findings so
  switching missions/runs changes the displayed path.
- this parallel lane must not silently overlap with active score-lane files such
  as `assessment_loop.py`, `workers/orchestration/tasks.py`, or
  `workers/runners/interactive_exploit/**` without explicit operator approval
- management-report drafting may use an LLM only to phrase structured,
  evidence-backed facts; the LLM must not invent scope, tested components,
  findings, business impact, or remediation facts
- React v2 operator run-truth surfaces must use chain-aware loaded tasks and
  findings as canonical for assessment-chain runs; selected-run local summaries
  may be displayed only when labelled as run-local. Observed, verified,
  persisted, and blocked/incomplete states must remain separate in operator
  copy and tests.
- React v2 Findings Theater must keep proof state, evidence state, validation
  state, business impact, AI enrichment, and remediation/next-step data
  separate. Raw exploit-runner/flag titles may remain visible as stored
  metadata, but primary operator copy should use normalized evidence-backed
  titles when available; remediation and next-step wording must not be invented
  when the API payload does not provide supported data.
- React v2 Evidence Replay must use chain-aware task context for
  assessment-chain runs and must not infer finding validation, business impact,
  or remediation conclusions from execution output. Evidence Replay is the place
  for execution, transcript, artifact, hash, timestamp, redaction, and provenance
  facts; conclusions remain in Findings Theater and reports.
- React v2 Mission Control must be split into operator screens instead of one
  overloaded page: `Live` for current work, queue, CLI output, and live events;
  `Results` for what happened and what counts; `Overview` for total test scope,
  progress, and upcoming work; `Technical` for diagnostics. The technical truth
  strip, canonical score, raw logs, task stdout/stderr, risk charts, proof
  inventory, and API log tail must be opt-in diagnostics, not first-viewport
  clutter. Drilldowns should be interactive, and each operator-facing detail
  should pair plain-language explanation with technical facts. Tool output does
  not count in reports until a finding is saved. This follows the same broad
  product pattern used by mature pentest tools: live task control is separate
  from result views, findings are clickable objects, and raw request/log detail
  is available on demand instead of dominating the primary screen. The first
  viewport must be visually led: a branching timeline with proof/dead-end
  routes, a done/now/next story board, and a progress/severity chart come
  before prose, raw terminal output, or log feeds. Mission Control's first
  viewport should use the same blue `neon-panel`/cyan-accent surface language
  as Dashboard; red/green should remain meaningful status accents rather than
  the dominant background theme. For dense attack-path visuals, the main screen
  should show only the compact current path; the full schema belongs in a
  viewport-level popout rendered outside the scroll panel, with replay controls,
  zoom controls, a severity legend, event details, and click-through actions
  into Live CLI, Findings, Evidence, Surface Map, or Reports as appropriate.
  The full schema must prefer readable spacing without hiding the route truth:
  discovery/decision/dead-end work stays in the first layer, proof/outcome in a
  second layer, edge labels are reserved for meaningful branch/proof
  transitions, and multiple persisted findings should draw as individual proof
  milestones in the path. The report/outcome node may summarize severity totals,
  but it must not replace the proof path with a vague `+N more` card. Every
  edge should have a visible line, but arrowheads should be small and reserved for
  live/failed/proof direction changes rather than every routine completed step.
  Selecting a map node should reveal a plain-language explanation plus
  technical metadata before navigating away. Timing context must also be visible
  on the map cards themselves for run start, task completion/failure, task
  duration, proof persisted time, elapsed time from run start, and source-task
  duration; the detail panel may expand timing but must not be the first place
  operators see it.
- React v2 Mission Control must start with an operator-presence deck, not a
  generic KPI grid. The first viewport should answer: where am I, what is my
  role now, what is the system doing, what evidence is saved, which route was
  taken, what proof leads, what impact exists, and what should I click next.
  Route stages should be interactive navigation controls into the owning
  surfaces. Longer story cards, run-picture detail, queue internals, CLI output,
  and technical facts should remain available as drilldowns so the default
  screen feels guided rather than cluttered.
- Mission Control motion is product truth, not decoration. The Live cockpit
  should move only where it communicates real state: running work, queued
  handoff, proof ready for review, route activity, queue activity, or current
  path activity. These motion cues must be driven by task/run/finding status
  attributes and must respect `prefers-reduced-motion`.
- React v2 mission-story vocabulary is a shared product contract, not local
  screen copy. Mission Control, the global mission spine, Run Picture, Evidence
  Replay, Findings, and Reports should reuse the same route phases and safe
  outcome labels wherever possible: map surface, inspect behavior, test routes,
  prove impact, and tell outcome. Raw tool names, runner labels, targets,
  flags, benchmark markers, and exploit IDs may remain visible as secondary
  technical/provenance facts, but primary operator copy should explain what the
  step means in plain language and how it connects to the mission path.
- Mission Control is the exception to the global app-shell spine: because it is
  the mission cockpit itself, it should not render the separate
  `MissionExperienceSpine` above its local content. Its first viewport should
  have one dominant `Mission snapshot` answer with outcome, target, checked
  progress, next action, route, lead proof, and impact/severity gauge. Story
  cards, run picture, plain-language explanation, technical facts, attack map,
  queue, CLI, and events remain available as drilldowns below that answer.
- React v2 Report Center must treat chain-aware canonical findings from
  `getFindingsForRunContext(run)` as the visible report truth. Run-local
  summaries may not drive report charts or export readiness. Each selected
  report variant must show what is included, what is not claimed or not tested,
  whether catalog counts match canonical findings, and whether customer-facing
  metadata contains internal benchmark/lab/fixture/smoke/debug markers. Report
  content hashes must be labelled as report content hashes, not as standalone
  evidence-integrity verdicts.
- React v2 report/evidence consistency is a cross-surface invariant. A named
  consistency fixture should keep a deliberate mismatch between run-local
  summary and chain-aware canonical findings so Mission Control, Findings
  Theater, Evidence Replay, Report Center, report preview, and exported reports
  fail tests if any surface uses stale run-local truth as customer/operator
  truth.
- React v2 cross-surface report consistency must be computed at the
  presentation boundary through a shared view-model helper. Report Center and
  future report/evidence UI should compare canonical findings, run-local
  summaries, catalog/export counts, preview claims, and evidence-link
  availability through that helper instead of rebuilding those checks inside
  individual components.
- React v2 report-truth presentation rules belong in view-model adapters, not
  directly inside screen components. Report Center should consume
  `viewModels/reportTruth.ts` for canonical report counts, catalog-vs-canonical
  status, customer-copy warnings, stage details, and report chart data so later
  UI edits do not silently fork report truth.
- AI-assisted report drafts must expose and use an inspectable structured
  payload contract. The LLM input may include only tested scope,
  evidence-backed supported findings, source evidence refs, methodology, and
  explicit `not_tested` / `not_verified` caveats. Raw top-level findings/tasks
  are not valid LLM input for report drafting. Management, technical,
  compliance, and retest drafts must carry separate audience/template
  constraints, and raw evidence/proof exports must remain deterministic and
  non-LLM.
- React v2 must carry a persistent mission experience across the product, not
  only inside Mission Control, Cinema Mode, or reports. When a selected run is
  present, the app shell should provide a compact `Now / Route / Next` spine
  that explains the current state in plain language, shows the mission journey
  from live work to evidence, findings, and report, and links into the relevant
  detailed surface. This spine must use canonical selected-run/chain-aware
  tasks, findings, and inventory, and it must not expose raw CLI or technical
  clutter as the first answer. Detailed pages may remain deep and technical,
  but they should feel like drilldowns from the same mission story rather than
  isolated screens. This spine should be operator-present, not administrative:
  primary copy should tell the operator where they are, what the system is doing
  for them, and what their next meaningful move is. It should combine visible
  system status, real-world/plain-language wording, semantic status indicators,
  and compact progressive disclosure so the product feels like one live cockpit
  instead of many unrelated pages.
- The global React v2 mission spine must be page-aware as well as run-aware.
  Dashboard may summarize the selected run, but Evidence Replay, Findings,
  Report Center, Live CLI, Surface Map, Problems, and History should each tell
  the operator what role that screen plays in the same mission story. The route
  rail's active stage must reflect the current page with `aria-current="step"`
  so keyboard/screen-reader users receive the same "you are here" signal as the
  visual UI.
- Management-facing report output must use a separate customer-ready rendering
  boundary from technical/evidence exports. Run IDs, benchmark IDs, raw flags,
  exploit-runner labels, loop/task labels, tool names, and source-ledger details
  may remain in technical/evidence reports, but the management title/header
  layer and primary risk story must use clean customer/scope copy, business
  risk themes, and cluster-specific remediation actions grounded in stored
  evidence.
- Management PDF and Dutch management PDF output must be readable without a
  technical appendix. Primary management rows must use business categories such
  as confirmed attack path, public API documentation exposure, account access,
  browser/session protection, and connectivity baseline instead of raw runner,
  flag, FastAPI/OpenAPI, tool, benchmark, or HTTP-status titles. Management
  output must explicitly state the methodology references used for the tested
  scope: PTES, OWASP WSTG, NIST SP 800-115, and OWASP ASVS only where a finding
  is mapped. It must also state that this is not certification or a replacement
  for human review.
- Management-facing report phrasing must start from deterministic structured
  decision facts. Verdict, management decision, first actions, evidence basis,
  tested-scope summary, not-certified/not-claimed caveats, methodology
  references, and task coverage counts are canonical report facts; AI may phrase
  them for management readability but must not derive or invent them.
- AI-assisted report-draft payloads for management variants must expose the
  same `management_decision` facts as inspectable structured input. Technical
  draft variants should not receive management-decision facts unless a future
  task explicitly broadens the contract.
- Management-facing reports must include a deterministic assessment story in
  addition to decision facts: an attack-map route from scope to evidence and
  decision, a plain-language explanation of what was actually tested, and
  management-safe technique categories grounded in stored task evidence.
  AI-assisted management drafts may phrase this story, but the canonical facts
  come from `management_story`; technical draft variants must not receive this
  management-only story object unless a future task explicitly broadens the
  contract.
- Management-facing reports must also explain the business story in role-based
  terms: why the situation matters, what an attacker could practically do, what
  Engineering must fix, what IT/Ops must monitor or restrict, how the test was
  built from scoped evidence, and which methodology references were used. These
  facts must remain deterministic and inspectable through `management_story`
  fields such as `attacker_story`, `remediation_tracks`, and
  `standards_badges`; AI may phrase them but may not invent additional facts.
- React v2 accessibility/usability is part of product truth, not a separate
  cosmetic layer. Primary shell, Mission Control tabs, the mission spine, the
  command palette, and full-screen overlays must expose useful landmarks,
  focus-visible states, keyboard operation, active/selected state, and
  screen-reader names that match the same mission story shown visually.
- React v2 route-shell behavior must stay modular at the app boundary.
  `App.tsx` should remain a thin provider and route tree; shell bootstrap,
  selected-run loading, navigation config/rendering, command palette, toast
  viewport, and workspace loading state belong in app-shell modules so future
  UI/reporting truth edits do not silently modify unrelated route wiring.
- Mission Control attack maps must be evidence-path maps, not management
  category summaries. Map nodes should come from real run tasks and persisted
  findings, proof nodes should show the stored finding title with only sensitive
  token/id redaction, and every task/proof node should expose timing context
  such as start/update time, duration, persisted time, and elapsed time from
  run start. Management-safe finding categories may appear in executive copy,
  but not as replacements for attack-map proof truth.

## Runtime safety

- no uncontrolled plugin installation during runs
- no bypass of scope or safety boundaries
- no bypass of pack validation, approval, deployment, or runtime binding

## Support claim boundary

- a route, assessment type, or runtime lane must not be treated as fully supported on code tests alone
- support claims should be grounded in three layers where applicable:
  - deterministic code validation
  - browser/operator validation for UI-driven flows
  - at least one safe real-run or benchmark-lab proof against a legal target, local fixture, or explicitly authorized target
- when a real benchmark or lab does not yet exist for a route, the route should remain `supported-with-gap` or `blocked` instead of being implied as complete
- public internet targets are not the default validation method; local fixtures, official vulnerable labs, and explicitly authorized targets are preferred because they are safer and more reproducible

## Task package contradictions

- when a promoted task package is internally contradictory but the user explicitly instructs Codex to finish the task honestly instead of holding on the contradiction, Codex may take the narrowest repo-backed exception needed to complete the task
- any such exception must be logged in `DONE_LOG.md` and summarized in `CURRENT_STATE.md`, including what constraint was overridden and why the narrower exception was safer than leaving the task half-complete

## Queue and mockup authority

- `TASK_QUEUE.md` remains the authoritative queue order; changing only `source_context.queue_index` in task JSON is not a valid reprioritization and must be treated as drift until the markdown queue and task metadata agree again
- when UI reprioritization is driven by a newer visual artifact, that artifact should be named explicitly in both `TASK_QUEUE.md` and the affected task packages so the intended design authority is obvious from the repo without chat context
- for the accelerated post-onboarding UI slices, `wizard_mockup.html` is not a Mission-Control-only or intake-only reference; it is the default design-language authority across the full UI touched by those slices, including intake, Mission Control, supporting screens, card treatment, chip treatment, spacing, and polish cues, while `ui_mockup.html` remains the broader whole-app layout authority where a task package says so
- when the user asks for exact mockup design-language parity, green functional tests are not enough; the active UI task must include a token/component parity checklist, before/after screenshots at agreed viewports, documented product-truth deviations, and an explicit final UI score before closure
- static mockup sample data does not have to match live product data, but shell geometry, first-viewport hierarchy, component language, spacing, color/radius treatment, and state presentation should match the root mockups unless a safety or product-truth exception is logged
- after the active installation package, the approved product order is to promote the post-mockup UI closure slice before bulk delete, dashboard, Problems Center, and the later product-expansion backlog

## ChatGPT OAuth backend shape

- the ChatGPT OAuth Codex backend on `chatgpt.com/backend-api/codex/responses` must not be treated like the older plain JSON helper path for every feature
- the durable working baseline for this backend is:
  - model `gpt-5.4`
  - `store: false`
  - `stream: true`
  - `input` as a list of response-style message items
  - explicit `instructions` when the feature needs structured output
- `openai-codex/gpt-5.4` is not a valid ChatGPT-account model identifier for this backend and should not remain the displayed or configured default for ChatGPT OAuth features
- when a feature needs structured JSON from this backend, AegisPT should parse streamed output text into JSON rather than assuming the backend returns a plain JSON object body

## AI repair operator contract

- AI repair must not be presented as a fix when it only records review intent.
- A repair proposal needs an explicit action contract:
  - retry the failed runner when retry-safe and prerequisites are present
  - continue remaining planned checks when the chain can safely advance without bypassing scope or approval gates
  - accept a documented coverage gap when the remaining work is not recoverable in the active run
  - create a build-lane fix task/proposal when code, pack, tool, or configuration repair is required
- Every AI repair action must record durable provenance and must remain visible in reports/history as a recovered action, accepted gap, or unresolved blocker.
- AI Signal needs a discoverable inbox/history surface; hiding reasoning records only inside the current Mission Control panel is not enough for operator trust.

## Full-system audit sequencing

- When the operator requests a complete product/system audit, do not replace already-existing concrete regression task packages with broad audit tasks.
- Concrete validation unblockers must run before broad acceptance-harness tasks when the unblockers affect the reliability of the test suite itself.
- The 2026-04-30 audit sequence is:
  - backlog-142 through backlog-148: concrete test/product regression unblockers found during full-system assessment
  - backlog-149: durable full-system acceptance harness and defect inventory
  - backlog-150 through backlog-155: corrective product slices for lifecycle truth, wizard matrix coverage, AI value, enterprise information architecture, Settings readiness, and findings/report/history consistency
- A future broad acceptance claim must include both machine-readable evidence and human-readable page/option analysis under `codex/results/`, not only green tests.

## Wireless assessment boundary

- WiFi / wireless testing is a distinct assessment surface, not a hidden part of LAN or IoT scanning.
- The first WiFi slice must be passive-first and require explicit site, SSID/BSSID, adapter/interface, exclusions, and ROE context.
- RF-disruptive or intrusive techniques such as deauthentication, jamming, evil-twin simulation, WPS brute force, handshake capture, or credential cracking require a separate future intrusive task and explicit authorization gates.
- WiFi support must not be claimed complete from fixture tests alone; adapter readiness and safe lab validation evidence are required before product-level support claims.

## Canonical-solve definition + deterministic-proof gate exemption (2026-06-01)

- A challenge counts as a canonical SOLVE only when ALL four hold: (1) grader-verified
  flag (byte-equal), (2) persisted as a finding, (3) transcript present (finding
  `evidence_ref`), (4) scope provenance present (finding `target_id`). The score
  source is this canonical finding — stdout/grader and the findings table must NOT
  disagree.
- The M2 verdict gate (`api/app/services/m2_verdict_gate.py`) must NOT drop a
  captured flag-literal finding as a re-prober false positive. A flag literal is
  deterministic, grader-matchable proof; the HTTP-oriented re-prober cannot
  reproduce non-HTTP (raw-TCP) captures and was dropping real LAN solves
  (3/9 in run 7e589aea). The gate now has an explicit, BOUNDED `DETERMINISTIC_PROOF`
  class: exempt ONLY a finding that carries a canonical flag literal AND full
  provenance (evidence_ref + target_id + an exploit methodology tag). This is NOT a
  generic gate bypass — non-flag hypotheses and unprovenanced flags still go through
  the full verdict logic (proven by gate tests cases 8/9/10).
- Focused-objective dispatch dedup must be race-free under
  `INLINE_DISPATCH_BACKGROUND`: the just-picked objective's task row is created by a
  background thread and can lag the next iterate's DB dedup query. A synchronous
  in-process memo of dispatched (objective, model) per run is the authoritative
  dedup; the DB query is the restart backstop. Target: double-dispatch = 0.
- The frozen, comparable result format for the public-truth lane (Track A) is
  `docs/validation/SCORELANE_FORMAT.md` (black-box + source-aware columns,
  byte-equality, reproduced-≥2-runs, local-provider baseline, failure-classes).
- Roadmap of record: `docs/strategy/aegispt-execution-roadmap-2026-06-01.md`
  (3-way consensus; track order B → A+C1 → C2 → D → E → F → G; metrics-gated refactor).

## Future hooks

Placeholder modules and future-facing docs are allowed when they do not silently activate new runtime behavior.
