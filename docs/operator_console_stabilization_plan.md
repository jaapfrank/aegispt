# Operator Product Operational Assurance Plan

## Purpose

This document defines the canonical side project for turning AegisPT into a trustworthy, usable, evidence-backed, end-to-end operational product.

This is not a one-shot patch and it is not a cosmetic cleanup pass.

This is the plan that future work must keep following until the supported product is genuinely dependable from intake through execution, evidence, reporting, and operator handoff.

The repo should treat this as the authoritative working plan for the current side project. `NEXT_TASK.md` should stay aligned to this document until the program is complete.

This is a controlled operational-assurance track focused on:

- real operator usability
- truthful live state
- complete run follow-through
- report/export reliability
- reproducible validation on Kali and in Playwright
- full supported-option verification instead of optimistic spot checks
- AI features that add grounded operator value rather than UI noise
- evidence-backed assurance output that a customer can rely on responsibly

The current market context for this plan is captured in:

- `docs/competitive_landscape_2026.md`

The release-truth and signoff rules for this plan are captured in:

- `docs/operational_truth_signoff.md`

The future controlled multi-agent red-team direction for this plan is captured in:

- `docs/multi_agent_red_team_program.md`

The supplied midterm-review scope alignment for this plan is captured in:

- `docs/midterm_review_scope_alignment.md`

The broader post-stabilization product-program alignment for the supplied `PRODUCT_RECOMMENDATIONS.md` is captured in:

- `docs/product_recommendations_scope_alignment.md`

## Why this side project exists

The current platform contains a lot of implemented capability, but the standard for this side project is higher than “the feature exists”.

The standard is:

- every supported path must actually work
- every important option must be testable and observable
- combined supported flows must remain coherent
- the UI must help the operator instead of overwhelming them
- AI must improve outcomes in a measurable, evidence-backed way

Known issues include:

- too much simultaneous information
- unclear next-step guidance
- incomplete or brittle end-to-end flows
- live run behavior that is not always obvious or trustworthy
- discovery runs that do not always lead cleanly into follow-up actions
- findings, evidence, explorer, and report views that are not yet consistently aligned with what the run actually did

The midterm review also keeps the following items explicitly in scope for this broader program even when they are not the current active task:

- cross-platform font-stack repair
- clearer empty states and return-operator onboarding
- continued screen-count compression where separate screens do not add enough value
- calmer enterprise-ready visual intensity
- stronger attack-path-oriented visual storytelling
- remediation closure and proof-of-resolution
- attack-path graphing and choke-point explanation
- enterprise workflow integrations such as Jira
- continuous / scheduled validation mode
- cloud / identity / credential-first coverage expansion
- managed-cloud / hybrid deployment evaluation
- frontend architecture watch work around the current vanilla-JS and shared-runtime-state ceiling

## Assurance boundary

AegisPT can support an evidence-backed assurance statement or certificate showing that agreed controls, surfaces, and validation steps were tested according to the defined methodology and recorded with evidence.

AegisPT must not claim that a customer is impossible to hack or immune to all attacks.

The correct target is:

- an evidence-backed assessment and validation certificate
- a due-diligence and control-validation statement
- a reproducible record of what was tested, what passed, what failed, and what remains out of scope

The system must therefore produce assurance that is:

- scoped
- methodology-aligned
- evidence-backed
- reproducible
- honest about residual risk

## AI value standard

AI only adds value in this project if it makes the operator materially better than a competitor workflow.

That means AI must help with:

- clearer mission intake and safer scope capture
- better inventory interpretation
- better threat and relevance correlation
- smarter next-step recommendations after discovery
- customer-specific pack generation in the controlled build lane
- clearer summaries of why a test, pack, or follow-up action matters
- better evidence-to-finding-to-report linkage

AI does not add value if it:

- invents state
- hides uncertainty
- replaces deterministic controls with vague chat behavior
- creates more clutter than clarity
- makes unsupported security guarantees

## Ground rules

- no backend rewrite unless a narrow additive fix is required
- no removal of existing capability or safety controls
- no fake UI states disconnected from real run data
- every improvement must be validated in code and in the browser
- every phase must leave the repo more truthful than before
- documentation must be updated at the same time as code and tests

## Non-goals

This side project does not exist to:

- add new major product domains
- redesign the platform architecture
- replace Prompt 1, Prompt 2, or Prompt 3 foundations
- introduce runtime self-modification
- hide broken flows behind cosmetic polish

## Work model

This side project should be executed in controlled phases.

Each phase must include:

1. implementation
2. browser validation
3. live operator walkthrough
4. documentation update
5. explicit exit criteria

No phase is considered complete until all 5 are done.

Every phase must also answer:

- what real operator problem was fixed
- what combinations were validated
- what still does not work
- what evidence proves the phase is actually better than before

## Phase 0: Reality Baseline

### Goal

Establish the real current behavior instead of relying on assumptions from older tests.

### Tasks

- enumerate every current operator path in the UI
- list every known dead end, mismatch, or misleading state
- record live Kali behavior separately from isolated Playwright-host behavior
- capture screenshots and notes for every broken or confusing flow

### Control checks

- every top-level screen has a written current-state note
- every run type has a written current-state note
- every known failure is logged with reproduction steps

### Exit criteria

- a shared issue inventory exists for the side project
- the baseline distinguishes:
  - broken
  - misleading
  - ugly but functional
  - functional but incomplete

## Phase 1: Wizard Completion and Clarity

### Goal

Make the intake/wizard fully completable, understandable, and trustworthy for every supported mission type.

### Scope

Cover every conversational and advanced-setting path for:

- Website / Web App
- Domain / Domains
- External IP / WAN
- Internal Range / LAN
- API
- SSL/TLS Only
- Authenticated App
- Mixed Assessment

### Tasks

- verify every wizard path can always move forward
- remove conversational dead ends
- make the current question, answer intent, and next action obvious
- make confirmation summaries precise and human-readable
- keep advanced settings synchronized with the conversational state
- ensure all safety and boundary settings remain visible and respected

### Control checks

- every assessment type can be completed
- every confirmation summary matches the real run configuration
- advanced overrides remain reflected in summary and run config
- ambiguous or unauthorized target requests are blocked clearly

### Exit criteria

- an operator can complete every wizard path without guessing
- each question explains what it needs and why
- every path ends in a valid deterministic run dossier

## Phase 2: Run Dispatch and Execution Truth

### Goal

Make the live run state truthful, observable, and actionable.

### Tasks

- verify `Create Mission` always lands cleanly in Mission Control
- verify `Start Validation` actually dispatches real queued work
- make queued, running, completed, blocked, and failed states unambiguous
- surface what tool is active, on what target, and why
- prevent the UI from looking finished when nothing meaningful happened

### Control checks

- Mission Control reflects real run/task state after dispatch
- no fake success states
- every run shows a next logical action
- no hidden rerender races that leave the UI in the wrong phase

### Exit criteria

- a human operator can always answer:
  - what is happening now
  - what finished
  - what failed
  - what to do next

## Phase 3: Internal / LAN Operational Flow

### Goal

Make internal-network work actually useful from discovery through controlled follow-up.

### Tasks

- verify passive LAN discovery against real and fake-safe environments
- verify discovery results appear in Surface Map, Explorer, History, and Reports
- verify discovery runs lead into the next supported actions:
  - service identification
  - passive web profiling
  - additional already-approved internal ranges
- verify internal validation messaging stays honest about staged progression

### Control checks

- discovery-only runs never appear as pointless zero-output runs
- discovered hosts/services/endpoints remain visible across screens
- follow-up actions create real run dossiers
- allowed-scope boundaries remain enforced

### Exit criteria

- LAN discovery becomes a reliable first step, not a dead end
- a human can move from inventory to deeper controlled follow-up without confusion

## Phase 4: Findings, Evidence, and Report Integrity

### Goal

Make analysis views line up with what the system actually found and executed.

### Tasks

- verify findings only appear when the run truly produced findings
- verify zero-finding discovery runs still produce useful evidence/report context
- verify Evidence Replay links to real tasks, artifacts, pack provenance, inventory, and methodology
- verify Report Center variants:
  - executive
  - technical
  - evidence appendix
  - retest / verification
- verify markdown, HTML, and PDF exports

### Control checks

- report content matches run output
- PDF is actually a PDF and readable
- HTML is actually HTML and readable
- findings and evidence do not contradict run state

### Exit criteria

- report/export flow is dependable
- evidence-first review is understandable and complete

## Phase 5: Surface, Explorer, History, and Comparison Usability

### Goal

Make post-run review practical instead of cluttered.

### Tasks

- verify large inventories remain scrollable and usable
- add missing asset detail where the map is too shallow
- ensure Explorer behaves like a dossier, not a random data dump
- ensure History cards and comparison actions are always clickable and meaningful
- ensure comparison speaks clearly about:
  - new
  - fixed
  - still open
  - worsened
  - pack changed

### Control checks

- all lists/cards have obvious click or non-click behavior
- no screen shows only partial inventory with no way to continue
- run history always links to a real next review action

### Exit criteria

- a human can review a run and understand what changed over time

## Phase 6: Calmness, Hierarchy, and Readability

### Goal

Make the product feel focused and professional without deleting important information.

### Tasks

- reduce simultaneous heavy panels
- keep only one primary task area visible at a time
- compact secondary context
- move dense detail into disclosures and drilldowns
- remove repetitive copy and redundant summaries
- simplify button hierarchy and CTA emphasis

### Control checks

- Intake feels calm
- Run feels live
- Analysis feels evidence-driven
- no single screen feels like a wall of unrelated cards

### Exit criteria

- a new operator can scan the screen and know what matters first

## Phase 7: Full Acceptance Matrix

### Goal

Test every meaningful supported product path, not just a few happy paths.

### Required coverage

#### Assessment types

- Website / Web App
- Domain / Domains
- External IP / WAN
- Internal Range / LAN
- API
- SSL/TLS Only
- Authenticated App
- Mixed Assessment

#### Profile types

- Light
- Standard
- Deep
- External Surface Only
- Authenticated Only
- SSL/TLS Only
- Internal Validation
- Adaptive Customer-Specific Mode

#### Access modes

- unauthenticated
- username/password reference
- multiple accounts / roles
- API key reference
- bearer token reference
- session/cookie reference
- manual auth notes

#### Safety modes

- passive-only
- guarded active
- active
- low / medium / high concurrency
- low / medium / high time budget
- adaptive enabled / disabled

#### Analysis and export

- findings
- evidence replay
- surface map
- explorer
- history / comparison
- markdown export
- HTML export
- PDF export

#### Combination discipline

- every supported combination must be explicitly classified as:
  - supported and tested
  - supported but blocked by a known defect
  - intentionally unsupported
- invalid or unsafe combinations must be documented instead of silently falling through
- combined flows must include at least:
  - wizard -> run -> mission -> evidence -> report
  - discovery -> follow-up -> report
  - authenticated run -> evidence -> report
  - adaptive run -> pack visibility -> report lineage
  - blocked run -> operator explanation -> next action

### Control checks

- every row in the matrix has:
  - test method
  - expected outcome
  - pass/fail result
  - notes

### Exit criteria

- there are no untested major supported operator paths
- supported combinations are explicit instead of implied
- unsupported combinations are documented instead of behaving ambiguously

## Phase 8: Kali Reproducibility and Install/Update Discipline

### Goal

Make the tested experience reproducible on the Kali VM, not only in isolated test hosts.

### Tasks

- define the exact update/install/restart flow
- verify service state, static assets, and browser-visible app version
- verify direct-host behavior after redeploy
- verify report export and run dispatch on the actual Kali VM

### Control checks

- a deploy/update checklist exists
- browser-visible behavior matches the repo state
- no stale assets or stale venv/service state remains after update

### Exit criteria

- the operator can follow a documented Kali procedure and see the same behavior that was validated

## Phase 9: AI Differentiation and Operator Leverage

### Goal

Make AI features materially useful, grounded, and better than competitor workflows without breaking deterministic execution.

### Tasks

- verify the conversational intake reduces operator confusion instead of adding it
- verify AI summaries explain why a run profile, safety posture, or follow-up action was chosen
- verify discovery-driven next-step recommendations are grounded in real inventory/evidence
- verify adaptive pack suggestions stay tied to relevance, provenance, validation, and approval state
- verify AI-generated copy in the UI and reports remains calm, concise, and evidence-aware

### Control checks

- every visible AI recommendation can be traced to scope, inventory, findings, relevance, or pack provenance
- the operator can override or refine AI-derived decisions without losing deterministic control
- AI never implies broader authorization than the user granted

### Exit criteria

- AI assistance reduces operator effort and increases clarity in real runs
- AI behavior is grounded, observable, and not merely decorative

## Phase 10: Evidence-Backed Assurance Package

### Goal

Prepare the platform to issue a responsible, evidence-backed assurance or validation certificate for completed engagements.

### Tasks

- define the assurance package contents:
  - customer / engagement / scope
  - methodology references
  - controls and surfaces validated
  - findings summary
  - residual risk summary
  - retest or verification state
  - evidence/report hash or traceable references
- define what wording is allowed in an assurance statement
- define what wording is prohibited because it would overclaim security certainty
- ensure assurance output is derived from the same evidence-first reporting model already in the platform

### Control checks

- no assurance artifact claims absolute security
- every assurance claim can be traced to scope and evidence
- out-of-scope items remain explicit
- unresolved findings remain explicit

### Exit criteria

- AegisPT can issue a professional, honest, evidence-backed assurance package
- the output demonstrates due diligence and validation depth without claiming impossibility of attack

## Backlog Visual Polish Baseline: Mission Launch

The Mission Launch visual-polish slice is intentionally narrow. Mission Control now has a launch sequence that is driven only by the selected run, queued tasks, approval state, and dispatch state already present in the browser runtime.

The no-run state remains explicit: Mission Control shows that launch motion waits for a confirmed mission and does not imply queued work before Intake creates a real run dossier. After mission creation, the launch sequence shows dossier, queue, and runtime-boundary steps using the real run id, profile, task count, and dispatch readiness.

The ambient scan grid and orbit styling are quieter so the interface reads more like an operator workspace than a decorative scan animation. Reduced-motion users keep a usable non-animated presentation.

Remaining limits:

- the launch sequence does not create telemetry, findings, progress, or backend state
- per-task stdout streaming remains a future task and is not simulated here
- broader UI redesign, framework migration, and report-surface changes remain outside this polish slice

## Documentation upkeep rules

Every stabilization phase must update the relevant documentation before the phase is closed.

Minimum files to update when relevant:

- `CURRENT_STATE.md`
- `DONE_LOG.md`
- `docs/ui_assessment_wizard.md`
- `docs/ui_mission_control.md`
- `docs/ui_report_center.md`
- `docs/ui_information_hierarchy.md`
- `docs/ui_browser_validation.md`
- `docs/product_test_matrix.md`
- `docs/acceptance_runbook.md`
- `docs/Kali-VM-Reuse-Guide.md`
- `docs/host_service_install.md`

## Step checklist template

Use this checklist for every stabilization step:

- problem reproduced
- root cause identified
- code fix implemented
- browser test added or updated
- live manual walkthrough done
- docs updated
- known limitations written down

## Definition of done for the side project

This side project is only done when all of the following are true:

- every supported wizard path can be completed
- every created run can be followed meaningfully in the UI
- LAN discovery and follow-up flows are operational
- findings, evidence, explorer, history, and reports are internally consistent
- HTML and PDF exports are readable and trustworthy
- the UI feels calm enough for real operator use
- the product matrix covers all major supported options and supported combinations
- the Kali deployment path reproduces the validated experience
- AI assistance is demonstrably useful and grounded in evidence
- the assurance/certificate output is honest, traceable, and professionally usable

## Suggested execution order

1. Phase 0
2. Phase 1
3. Phase 2
4. Phase 3
5. Phase 4
6. Phase 5
7. Phase 6
8. Phase 7
9. Phase 8
10. Phase 9
11. Phase 10

## Immediate next recommendation

Start by re-opening Phase 0 truthfully and then continue in strict order.

Do not try to claim “fully tested” or “enterprise-ready” before the supported-combination matrix, Kali reproducibility, and assurance-package rules are actually complete.

First make the real behavior truthful and fully completable. After that, continue with execution truth, LAN/internal follow-through, combined acceptance coverage, AI leverage validation, and the evidence-backed assurance package.
