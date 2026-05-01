# Living System Experience Scope Alignment

## Purpose

This document absorbs `LIVING_SYSTEM_EXPERIENCE.md` into governed AegisPT project scope.

The source document is accepted as product-experience direction, not as direct permission to change runtime behavior. Implementation must still proceed one promoted backlog package at a time through `NEXT_TASK.md`.

## Source Inputs

- `LIVING_SYSTEM_EXPERIENCE.md`
- `UI_REDESIGN_SPEC.md`
- `docs/product_recommendations_scope_alignment.md`
- `docs/ui_mission_control.md`
- `docs/ui_phase_architecture.md`
- `CURRENT_STATE.md`
- `DECISIONS.md`

`UI_REDESIGN_SPEC.md` is authoritative for structural UI direction where it conflicts with older visual notes: fixed 48px topbar, dark 180px sidebar, light content area, flat free navigation, enterprise radius, no hero block, no scan-grid background, and no phase-locked navigation.

## Guardrail Interpretation

The living-system direction is allowed only when it remains:

- grounded in persisted run, task, finding, inventory, evidence, and AI proposal records
- additive to existing operator surfaces unless a promoted UI redesign task explicitly consolidates them
- respectful of `prefers-reduced-motion`
- deterministic when no AI provider is enabled
- review-only for AI proposals until existing approval and dispatch controls are used
- separate from worker execution semantics and pack lifecycle gates

The source document does not authorize:

- synthetic telemetry or fake scan events
- runtime self-modification
- uncontrolled plugin installation
- new execution lanes outside the existing run/task lifecycle
- bypassing scope, approval, pack validation, deployment, or runtime binding
- mutation of canonical finding schema fields
- automatic exploit execution, automatic task dispatch, or automatic proposal approval
- sound cues without explicit opt-in settings and a future approved implementation task

## Animation Philosophy

The central principle is: motion must communicate state, not decoration.

Allowed future motion should map to real state changes such as:

- a task moving from queued to running
- a persisted task completing
- a finding count increasing
- a critical finding appearing
- the run stream connecting, falling back, or completing
- an AI proposal or observation becoming available
- an operator switching engagement or selected run context

Decorative motion that does not encode a real state change should be avoided, especially if it competes with evidence review. The interface must still work without animation.

## Spider Metaphor Design Language

The spider/web metaphor is accepted as a design language for live operations, not as a new runtime model.

Mapped concepts:

- Tools are the active agents at the edge of the web.
- Targets are nodes in the environment.
- Task-to-target relationships are threads.
- Findings are meaningful catches on a node or thread.
- Critical findings are high-attention events that should be visibly distinct.
- AI reasoning is the spider's awareness, surfaced as transparent observations and proposals.
- Run completion is the web settling into a reviewable map.

The metaphor must never obscure factual evidence. Labels, accessible text, stored provenance, and explicit fallback states remain required.

## Living Scan Map Concept

The source document's scan map concept describes an SVG-based Mission Control view where tools connect to target nodes through visual threads.

Future implementation constraints:

- source all nodes from selected-run tasks, targets, findings, and inventory already persisted by the API
- distinguish queued, running, completed, blocked, failed, and finding-bearing states from recorded data
- keep active scan motion tied to run-level SSE or persisted polling snapshots
- show static or fallback states honestly when live events are unavailable
- avoid attack-path inference, risk scoring, lateral movement, or hidden scan expansion unless a later promoted task explicitly adds that logic
- preserve the existing run/task/finding evidence trail outside the visualization

The scan map is a presentation layer. It is not a graph database, planner, executor, or autonomous runtime.

## AI Signal Panel Pattern

The AI Signal concept is accepted as a Mission Control presentation pattern for grounded, time-ordered observations.

Allowed future entry sources:

- stored task completion summaries
- persisted findings and severity changes
- deterministic AI mission guidance
- stored AI reasoning records
- stored AI proposal records
- threat-intel or vulnerability-chain context already persisted by approved slices
- run-stream connection and fallback truth

Required boundaries:

- provider-disabled and provider-failure states must remain visible
- AI observations must be marked as advisory when they are not direct tool evidence
- proposal approval in the feed may record operator review only unless a later task explicitly connects it to the existing task creation and approval flow
- no AI Signal entry may broaden scope, grant approval, dispatch tools, mutate findings, deploy packs, or bind runtime packs by itself

Typing effects and thinking indicators are future UI behavior only. They are not implemented by this alignment slice.

## Micro-Interaction Inventory

The source document identifies a future inventory of interaction moments:

- task-running shimmer
- queued/running/completed/failed task transitions
- finding-count increment emphasis
- critical-finding pulse
- severity bar growth
- terminal line arrival and critical-line emphasis
- mission-created ceremony
- run-complete settlement and summary reveal
- finding-card opening treatment
- risk-gauge and methodology-chain reveal
- active-run indicator
- button press feedback
- card hover feedback
- engagement-switch reload feedback
- empty-state breathing

These are implementation candidates only. They must be delivered through specific promoted tasks and tested against the authoritative UI redesign direction, not introduced opportunistically.

## Sound Design Boundary

Sound design is optional and high risk for enterprise environments.

Any future sound implementation must:

- default to off
- require explicit operator opt-in
- offer at least a subtle mode and an off mode
- avoid external audio files and network requests
- map sounds only to meaningful state changes
- respect accessibility and operator environment constraints
- never be required to understand critical state

No Web Audio API usage, settings toggle, or sound event is implemented by this alignment slice.

## Implementation Priority

The source document's priority order is retained as future sequencing guidance, adapted to the now-authoritative `UI_REDESIGN_SPEC.md`:

1. Governed source alignment before implementation.
2. Structural UI foundation: topbar, sidebar, free navigation, enterprise radius, no hero/scan-grid shell.
3. Ambient animation foundation: task shimmer, severity transitions, badge/counter feedback, critical pulse, micro-interactions, and reduced-motion handling.
4. Scan map SVG and mission launch ceremony from real task/target/finding state.
5. AI Signal panel typing effect and proposal feed presentation.
6. Provider and settings foundations required for operator-controlled AI configuration.
7. Free navigation and screen consolidation so the experience remains enterprise-usable rather than theatrical clutter.
8. Later autonomous, AutoFix, and repository-integration slices only after the safety and review boundaries are proven.

Backlog items 52-62 now represent these implementation slices. They remain queued until promoted through `NEXT_TASK.md`.

## Current Boundary

This alignment does not implement UI changes, CSS animation, JavaScript animation logic, SVG scan maps, sound design, AI provider wiring, backend behavior, worker behavior, or schema changes.

It records the product-experience direction and keeps future implementation tied to validated, repo-backed task packages.
