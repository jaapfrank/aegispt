# Product Recommendations Scope Alignment

## Purpose

This document absorbs `PRODUCT_RECOMMENDATIONS.md` into the repository-backed project scope and backlog.

Its purpose is to ensure the supplied product review stops being a standalone reference and becomes explicit project work with ordering, guardrails, and honest status.

## Source inputs

This alignment is derived from:

- `PRODUCT_RECOMMENDATIONS.md`
- `docs/competitive_landscape_2026.md`
- `docs/midterm_review_scope_alignment.md`
- `docs/operator_console_stabilization_plan.md`
- the current active implementation task in `NEXT_TASK.md`

## What this changes

- the supplied product recommendations are now an explicit broader-program input for the repo
- the recommendations now map to the ordered backlog in `TASK_QUEUE.md`
- that broader backlog is now decomposed into one-to-one repo-backed first-slice task packages under `codex/tasks/backlog-*.json`
- the current active implementation task in `NEXT_TASK.md` remains authoritative until it is actually completed
- future work should reuse the existing placeholder and planning docs where they already exist instead of inventing a second roadmap

## What this does not change

Absorbing the recommendations into repo scope does not:

- replace Prompt 1, Prompt 2, or Prompt 3 foundations
- authorize live runtime mutation
- authorize uncontrolled plugin installation
- declare queued features already implemented
- replace the current active conversational-intake work in `NEXT_TASK.md`
- justify a frontend rewrite before the current architecture actually blocks the next approved slice

## Strengths to preserve

The product review confirms several strengths that should remain protected while the backlog expands:

- evidence-first findings, artifacts, and provenance
- supervised AI build-lane generation with validation and approval gates
- per-finding methodology alignment
- open tool-stack transparency
- one operator flow from intake through evidence and reporting

## Approved broader workstreams

### 1. Commercial-viability UI and operator-polish slice

This is the first broader slice after the current active intake task completes.

Scope includes:

- cross-platform font-stack repair
- first-run onboarding and stronger empty states
- calmer ambient styling and further navigation compression
- better discovery-first storytelling in Surface Map
- host-card fallback rendering before a heavier graph view exists
- lower-friction findings/evidence review, including consolidation where separate screens are not pulling their weight
- richer finding presentation and more operator-native evidence display
- lighter data-fetch behavior where the UI currently over-polls or over-fetches

This slice should stay mostly additive and browser-validated.

### 2. Remediation closure and proof-of-resolution

This slice turns AegisPT from "finding generator" into "fix verification" tooling.

Scope includes:

- a per-finding remediation state progression
- linked retest runs scoped back to the original finding or surface
- proof-of-resolution report output
- operator-visible remediation notes and verified timestamps

This must reuse the existing finding, evidence, report, and provenance structures additively instead of redefining them.

### 3. Live operations experience

This slice closes the gap between a real active run and the current low-frequency polling feel.

Scope includes:

- background-safe inline dispatch handoff where needed
- SSE run-status streaming
- task stdout streaming
- task swimlanes, live counters, and activity-log deltas grounded in actual run state
- stronger active-scan visual storytelling without inventing fake live state

### 4. Enterprise workflow integrations

This slice turns findings into enterprise workflow objects instead of leaving them trapped in the console.

Scope includes:

- Jira as the first bidirectional integration
- Slack, Teams, and generic webhook follow-ons
- later ServiceNow expansion

This should build on `docs/integrations.md` and must not become a shadow runtime path.

### 5. Attack-path intelligence and choke-point explanation

This slice turns inventory and findings into path-oriented operator guidance.

Scope includes:

- attack-graph construction from existing runs, findings, inventory, and later identity context
- choke-point identification
- path explanation tied back to evidence and findings
- Surface Map or adjacent graph views that explain relationships instead of only listing assets

This should build on `docs/attack_path_engine.md` and the existing placeholder service instead of inventing a separate model lane.

### 6. Continuous / scheduled validation mode

This slice moves AegisPT from one-off operator launches toward recurring validation.

Scope includes:

- schedule configuration on existing engagement-centered flows
- recurring dispatch through the existing task pipeline
- trend, drift, and delta reuse on top of current runs, findings, and reports

This should build on `docs/continuous_mode.md` and remain approval-aware.

### 7. Compliance packaging

This slice converts the existing methodology-rich reporting into buyer-facing framework packages.

Scope includes:

- SOC 2 first
- ISO 27001 and PCI DSS next
- control-grouped report variants
- explicit tested-control coverage and residual-remediation summary

This should reuse the current methodology and report layers rather than invent a parallel reporting model.

### 8. Cloud, identity, AD, and LLM-application expansion

This slice expands surface coverage once the nearer commercial gaps are closed.

Scope includes:

- read-only cloud configuration discovery
- identity- and LDAP-aware read-only enumeration
- AD-oriented inventory and finding generation
- LLM-application probing for prompt-injection, leakage, and unsafe-agent behavior

This should build on `docs/identity_model.md` and keep active or higher-risk behaviors behind explicit approval gates.

### 9. AI leverage and MCP surfaces

This slice adds specific AI leverage rather than vague chat veneer.

Scope includes:

- AI-assisted finding enrichment
- AI mission-planning suggestions grounded in the deterministic run model
- threat-actor mapping
- AI-assisted report drafting
- MCP read tools first, then carefully scoped write/action tools

This must remain evidence-backed, operator-reviewable, and measurably useful.

### 10. Frontend state-architecture watch

This is a guardrail slice rather than a standalone product launch.

Before remediation, attack-path, and richer live-ops surfaces significantly expand the UI, the repo should re-evaluate the shared mutable runtime-state pattern.

The approved watch direction is:

- favor a small observable store or event-bus pattern first
- evaluate a lightweight reactive layer only if the current DOM/state model becomes the blocking constraint
- do not start with a React rewrite

## Execution order

The broader backlog should now be read in this order:

1. complete the current active conversational-intake task in `NEXT_TASK.md`
2. ship the commercial-viability UI and operator-polish slice
3. ship remediation closure and proof-of-resolution
4. ship live operations streaming and active-run visibility
5. ship Jira-first enterprise integrations
6. ship attack-path intelligence and choke-point explanation
7. ship continuous / scheduled validation
8. ship compliance packaging
9. ship cloud / identity / AD / LLM-application expansion
10. ship AI leverage and MCP surfaces
11. address the frontend state-architecture watch before the next major UI-surface jump if the current runtime model shows real strain

`TASK_QUEUE.md` should mirror that order through one-to-one references to queued task packages while `NEXT_TASK.md` continues to hold exactly one active implementation task.

The first queue-backed executable slices are intentionally narrower than the broader workstreams above so each queued package stays implementable without hidden product decisions.

## Existing design anchors to reuse

Future work should preferentially reuse the existing repo planning anchors:

- `docs/attack_path_engine.md`
- `docs/integrations.md`
- `docs/continuous_mode.md`
- `docs/identity_model.md`
- `docs/competitive_landscape_2026.md`
- `docs/operator_console_stabilization_plan.md`

## Explicit non-goals carried forward

The supplied product recommendations also reinforce several things the repo should not build as near-term distractions:

- a proprietary scanner instead of the current auditable tool stack
- a fully autonomous runtime that bypasses approval gates
- generic AI chat over findings as a substitute for concrete workflows
- extra screens for every feature instead of stronger integration into the existing product flow
- hosted or multi-tenant expansion before the operator experience and direct-host story are genuinely dependable
