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

## Future hooks

Placeholder modules and future-facing docs are allowed when they do not silently activate new runtime behavior.
