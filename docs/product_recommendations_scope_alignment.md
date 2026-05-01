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
- `AI_PENTESTING_AGENT.md`
- `docs/ai_pentesting_agent_scope_alignment.md`
- `LIVING_SYSTEM_EXPERIENCE.md`
- `UI_REDESIGN_SPEC.md`
- `docs/living_system_experience_scope_alignment.md`
- the current active implementation task in `NEXT_TASK.md`

## What this changes

- the supplied product recommendations are now an explicit broader-program input for the repo
- the recommendations now map to the ordered backlog in `TASK_QUEUE.md`
- that broader backlog is now decomposed into one-to-one repo-backed first-slice task packages under `codex/tasks/backlog-*.json`
- the 2026-04-21 coverage audit extended the task-package mapping through backlog items 23-38 so concrete recommendations are not only implied by broad workstreams
- the current active implementation task in `NEXT_TASK.md` remains authoritative until it is actually completed
- future work should reuse the existing placeholder and planning docs where they already exist instead of inventing a second roadmap

## What this does not change

Absorbing the recommendations into repo scope does not:

- replace Prompt 1, Prompt 2, or Prompt 3 foundations
- authorize live runtime mutation
- authorize uncontrolled plugin installation
- declare queued features already implemented
- replace the current active task in `NEXT_TASK.md`
- justify a frontend rewrite before the current architecture actually blocks the next approved slice

## Coverage audit status

The first backlog hardening pass captured the main workstreams from `PRODUCT_RECOMMENDATIONS.md`, but a later coverage audit found several concrete recommendations were still only implicit or intentionally deferred inside earlier packages.

Those recommendations now have explicit queued task packages:

- UI navigation consolidation: `codex/tasks/backlog-23-ui-navigation-consolidation-foundation.json`
- mission-launch and visual-polish work: `codex/tasks/backlog-24-mission-launch-visual-polish-foundation.json`
- UI fetch-performance hardening: `codex/tasks/backlog-25-ui-fetch-performance-foundation.json`
- task stdout streaming: `codex/tasks/backlog-26-task-stdout-streaming-foundation.json`
- active target scan map: `codex/tasks/backlog-27-active-target-scan-map-foundation.json`
- scheduled-validation trend and delta output: `codex/tasks/backlog-28-continuous-trend-delta-foundation.json`
- ISO 27001 and PCI DSS packaging: `codex/tasks/backlog-29-compliance-framework-expansion-foundation.json`
- cloud IAM and Kubernetes analysis: `codex/tasks/backlog-30-cloud-iam-kubernetes-analysis-foundation.json`
- LLM-application testing: `codex/tasks/backlog-31-llm-application-testing-foundation.json`
- threat-actor or threat-context mapping: `codex/tasks/backlog-32-threat-actor-mapping-foundation.json`
- AI-assisted report drafting: `codex/tasks/backlog-33-ai-assisted-report-drafting-foundation.json`
- detection-engineering assistant output: `codex/tasks/backlog-34-detection-engineering-assistant-foundation.json`
- controlled MCP action tools: `codex/tasks/backlog-35-controlled-mcp-action-tools-foundation.json`
- MSSP and multi-tenant readiness: `codex/tasks/backlog-36-mssp-multitenant-readiness-foundation.json`
- remediation SLA and portfolio workflow: `codex/tasks/backlog-37-remediation-portfolio-sla-foundation.json`
- Slack, Teams, ServiceNow, and webhook integration expansion: `codex/tasks/backlog-38-integration-portfolio-expansion-foundation.json`

These packages are queued, not implemented. They preserve the rule that `NEXT_TASK.md` remains the only active work contract.

A later AI-agent source alignment absorbed `AI_PENTESTING_AGENT.md` without activating runtime AI behavior. That alignment keeps already completed first slices intact and adds backlog items 39-50 for the missing AI-agent program: reasoning/proposal ledgers, post-task analysis, operator proposal review, chain detection, feed-backed threat-intel badges, contextual remediation and exploitability intelligence, attack narrative generation, LLM-assisted intake, AI-augmented attack-path inference, local assessment patterns, and controlled multi-agent orchestration preparation.

The AI-agent alignment is intentionally decomposed into separate packages because the full reasoning loop is too large and safety-sensitive to implement as one broad task.

A later living-system experience alignment absorbed `LIVING_SYSTEM_EXPERIENCE.md` and the authoritative `UI_REDESIGN_SPEC.md` without activating UI behavior. That alignment records the animation philosophy, spider/web metaphor, scan-map concept, AI Signal presentation pattern, micro-interaction inventory, sound-design opt-in boundary, and implementation order. It maps the next approved backlog items 51-62 into governed slices for structural redesign, ambient animation, scan-map and launch ceremony, AI Signal presentation, ChatGPT OAuth provider work, operator settings, free navigation, screen consolidation, autonomous mode, AutoFix, and repository integrations.

Those packages remain controlled work items. They do not authorize opportunistic CSS animation, JavaScript animation logic, SVG scan maps, sound design, AI provider wiring, autonomous dispatch, code patch generation, or repository write integration until each package is the single active task in `NEXT_TASK.md`.

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

Current remediation portfolio first-slice status:

- `GET /api/v1/engagements/{engagement_id}/remediation/portfolio` now exposes engagement-level remediation queue visibility using existing findings, additive remediation records, linked single-finding retest runs, and run/profile context
- portfolio SLA labels are configurable request-time planning signals (`sla_days` and `due_soon_days`), not contractual enforcement or a customer SLA engine
- operators can distinguish overdue, due-soon, blocked, verified, retest-pending, proof-ready, and eligible-for-retest items without changing canonical finding fields
- `POST /api/v1/engagements/{engagement_id}/remediation/retest-plan` returns a planning-only batch retest grouping with approval counts from the existing run profile policy; it does not create runs, queue tasks, grant approvals, deploy packs, or bind runtime packs
- Finding Theater now shows the portfolio summary and planning-only retest groups beside the existing single-finding remediation and proof-of-resolution flow

Still out of scope for this first slice:

- automatic batch retest dispatch
- ticketing background workers
- contractual SLA enforcement
- changing finding schema fields
- bypassing approval, pack validation, deployment, or runtime binding gates

### 3. Live operations experience

This slice closes the gap between a real active run and the current low-frequency polling feel.

Scope includes:

- background-safe inline dispatch handoff where needed
- SSE run-status streaming
- task stdout streaming
- task swimlanes, live counters, and activity-log deltas grounded in actual run state
- stronger active-scan visual storytelling without inventing fake live state

Current implementation note: the first task stdout streaming slice exposes a bounded selected-task stdout endpoint and Mission Control terminal panel. It streams from the in-process runner buffer where that buffer is available and otherwise falls back to stored execution stdout after completion; it does not invent live terminal lines or expose stderr in the stdout panel.

Current implementation note: the first active target scan-map slice renders selected-run target cards inside Mission Control from existing task `target_id`, task status, task timestamps, and stored selected-run findings. It uses explicit live, static, completed, and blocked states, but it does not add fake scan paths, attack-path inference, risk scoring, worker execution changes, or new finding semantics.

### 4. Enterprise workflow integrations

This slice turns findings into enterprise workflow objects instead of leaving them trapped in the console.

Scope includes:

- Jira as the first bidirectional integration
- Slack, Teams, and generic webhook follow-ons
- later ServiceNow expansion

This should build on `docs/integrations.md` and must not become a shadow runtime path.

## UI fetch-performance baseline

The 2026-04-22 UI fetch-performance slice inspected the operator-console refresh
path before changing it:

- shell refresh loads engagements, run profiles, Codex tasks, and internal-validation scenarios
- selected engagement refresh loads scope, inventory, relevance, packs, runs, internal validations, and Codex tasks
- before this slice, selected engagement refresh then fetched `/runs/{run_id}/findings` for every run in the engagement before loading the selected run detail, reports, attack-path summary, selected finding theater, and selected finding evidence
- after this slice, selected engagement refresh preserves cached non-selected run findings, fetches fresh findings for the selected run, and only fetches the comparison baseline when History or Report Center needs that comparison context

Remaining frontend state ceiling:

- non-selected run finding details are cache/lazy data, not a guaranteed full engagement finding list after every refresh
- run-level finding counts and severity summaries still come from the refreshed run list, while detailed all-runs finding cards depend on selected, previously loaded, or comparison-loaded run detail
- this intentionally avoids a backend pagination or frontend framework rewrite; a later task can introduce a stronger client state model if all-runs detailed finding review becomes a primary performance path

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

Current first-slice status:

- `active-llm-application-probe` now provides an approval-gated, bounded `llm-probe` lane for explicitly authorized LLM API endpoints only
- the runner covers safe prompt-injection, data-leakage, unsafe-tool-use, and excessive-refusal checks with deterministic fake-provider test coverage and bounded evidence excerpts
- provider credentials are configured by environment-variable names in task params, not raw secret values in run output
- shadow AI discovery, secret extraction, uncontrolled tool execution, autonomous exploit chaining, arbitrary customer-data probing, and broader endpoint discovery remain outside the supported boundary

### 9. AI leverage and MCP surfaces

This slice adds specific AI leverage rather than vague chat veneer.

Scope includes:

- AI-assisted finding enrichment
- AI mission-planning suggestions grounded in the deterministic run model
- threat-actor mapping
- AI-assisted report drafting
- MCP read tools first, then carefully scoped write/action tools

This must remain evidence-backed, operator-reviewable, and measurably useful.

Current threat-context first-slice status:

- Finding Theater can show optional `threat_context` derived from stored finding evidence, methodology tags, and CWE/CVE references where present
- the source is a static `AegisPT curated threat-context mapping`, not a live threat-intelligence feed
- output is technique-style relevance only and explicitly does not claim actor attribution, breach likelihood, severity changes, or autonomous prioritization

Current MCP action-tool first-slice status:

- read-only MCP context remains unchanged through `GET /api/v1/mcp/resources` and `GET /api/v1/mcp/engagements/{engagement_id}/context`, with no tools, no write methods, no secret access, and no artifact-content exposure
- controlled action-tool discovery now lives behind `GET /api/v1/mcp/tools` and requires an explicit `X-Actor` header before the action surface is exposed
- the only enabled first-slice tool is `finding.retest.proposal`, which drafts an operator-reviewable proposal for the existing `POST /api/v1/findings/{finding_id}/retest` endpoint without creating a run, queuing tasks, dispatching work, changing finding state, approving anything, deploying packs, binding runtime packs, or exposing secrets
- the state-changing `finding.webhook.handoff.request` boundary is advertised as disabled and confirmation-gated, so the manifest documents the intended operator-confirmation contract without delivering external handoffs in this slice
- forbidden MCP action classes remain scan launch, run dispatch or cancellation, approval decisions, pack approval/deployment/rollback/mutation, secret access, artifact content reads, runtime mutation, and uncontrolled plugin installation

Current detection-engineering first-slice status:

- Finding Theater can show optional advisory detection-engineering suggestions derived from stored finding evidence, methodology tags, source tool context, and mapped attack-scenario context where present
- the source is a static `AegisPT curated detection-engineering mapping`, not a SIEM/EDR integration or customer-environment telemetry connector
- output is explicitly a non-production draft: it does not deploy rules, modify customer systems, claim detection effectiveness, or change canonical finding fields
- sparse findings and findings without a curated detection mapping fall back to unsupported guidance rather than fabricated rule logic, and unsupported telemetry is called out for operator review

Current assessment-pattern and pack-effectiveness first-slice status:

- `GET /api/v1/engagements/{engagement_id}/assessment-patterns` summarizes local stored runs, findings, remediation records, proposals, and capability packs for one engagement at a time
- the output is explicitly `local_advisory`, tenant-scoped through the existing `X-Tenant-ID` engagement boundary, and records that no customer data is exported, no third-party analytics are used, and no external model training is performed
- finding patterns distinguish persistent, remediated, recurring, and new signals, while stating that remediation records do not guarantee risk reduction and recurring is a frequency signal that can overlap other posture states
- pack-effectiveness summaries include validation outcomes, approval outcomes, deployment outcomes, proposal outcomes, generated-finding counts, and quality signals without promoting, approving, deploying, mutating, validating, or runtime-binding packs automatically
- sparse datasets return explicit sparse-data limitations rather than fabricated learning claims

### 10. Commercial scaling and MSSP readiness

This slice prepares AegisPT for managed-service and multi-tenant evaluation without claiming hosted SaaS readiness.

Scope includes:

- tenant-boundary mapping across engagements, runs, findings, reports, secrets, artifacts, packs, MCP, and Codex results
- a narrow tenant-isolation foundation where the current model supports it safely
- explicit hosted-SaaS, billing, tenant-portal, and broad-RBAC gaps

Current MSSP/multi-tenant first-slice status:

- `docs/mssp_multitenant_readiness.md` now maps the required tenant isolation boundaries and remaining hosted/SaaS gaps
- engagements can carry an optional `tenant_id`, and `X-Tenant-ID` can narrow engagement, scope, schedule, run, report, finding, inventory, task, and evidence-artifact content APIs
- absent `X-Tenant-ID` preserves the current local single-operator workflow, so this is not yet an authentication or RBAC system
- cross-tenant API access returns `404`, invalid tenant ids return `400`, and create-time tenant header/payload mismatches return `409`
- the operator console can forward `X-Tenant-ID` when deployment glue sets `state.tenantId`, but there is no visible tenant switcher, MSSP portal, billing, SSO, tenant membership, or cross-tenant reporting in this slice

### 11. Frontend state-architecture watch

This is a guardrail slice rather than a standalone product launch.

Before remediation, attack-path, and richer live-ops surfaces significantly expand the UI, the repo should re-evaluate the shared mutable runtime-state pattern.

The approved watch direction is:

- favor a small observable store or event-bus pattern first
- evaluate a lightweight reactive layer only if the current DOM/state model becomes the blocking constraint
- do not start with a React rewrite

## Execution order

The broader backlog should now be read in this order:

1. work only from the single active task in `NEXT_TASK.md`
2. promote queued task packages from `TASK_QUEUE.md` one at a time after the active task is actually closed
3. keep commercial-viability UI, remediation closure, live operations, integrations, attack-path intelligence, continuous mode, compliance packaging, cloud/identity/LLM expansion, AI/MCP surfaces, and frontend-state watch work in the explicit task packages rather than chat memory
4. add any newly discovered future work as a repo-backed task package before it can be promoted

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
