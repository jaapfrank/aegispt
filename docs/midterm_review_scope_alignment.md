# Midterm Review Scope Alignment

## Purpose

This document records the supplied midterm review of AegisPT and maps each major point into the repository scope.

Its purpose is to prevent the review from becoming "known but unofficial".

If a review item matters strategically, commercially, operationally, or architecturally, it should appear somewhere explicit in repo scope rather than living only in chat history.

## Confirmed strengths to preserve

The review positively confirms several foundations that should remain protected:

- evidence-first findings, artifacts, and provenance are a real differentiator
- the supervised AI build lane is a product strength because AI is gated, reviewable, and not a runtime black box
- methodology alignment per finding is commercially valuable and should remain structural
- the conversational wizard is the strongest UX decision in the current product and should remain a first-class surface
- the open tool stack is a trust differentiator because operators can understand what is actually executing
- the single operator flow from mission definition through evidence and reporting is strategically correct

These strengths are already part of the project scope and should not be regressed while addressing the remaining gaps below.

## UI and operator-experience items now explicitly in scope

The review raises several UI/operator concerns that should remain inside the active product scope:

- cross-platform font-stack repair
  - the current Windows-heavy stack is not acceptable as the long-term identity because it degrades on Linux and macOS
  - this stays in scope as a UI hygiene and professionalism issue
- clearer empty states and return-operator onboarding
  - the console should not rely on the first-run wizard alone
  - operators who arrive with no active engagement or no selected run need explicit orientation
- continued navigation compression
  - the current screen count is still a usability concern for first operators
  - the scope includes evaluating whether Evidence Replay and Explorer should remain standalone or move behind stronger parent surfaces
- calmer visual intensity
  - the scan-grid / ambient-light language should remain subordinate to clarity and enterprise credibility
  - the quieter hierarchy direction already in the repo should continue
- more visually convincing attack-path or connected-surface storytelling
  - the existing surface view should evolve beyond a minimal map so the product can explain relationships, not only list assets

These items belong primarily to:

- `docs/operator_console_stabilization_plan.md`
- current UI hierarchy work
- future operator-console refinement tasks

## Competitive and product gaps now explicitly in scope

The review also reaffirms several strategic product gaps that are already partially recognized and now remain explicitly in scope:

- remediation loop and proof-of-resolution workflow
  - finding status progression
  - retest flow
  - proof-of-resolution output
- attack-path graph and choke-point intelligence
  - visually explain how findings, hosts, credentials, and reachable paths connect
- enterprise workflow integrations
  - especially Jira as the first concrete integration
  - followed by ServiceNow, Slack, Teams, GitHub, and similar handoff systems
- continuous / scheduled validation mode
  - recurring assessments on existing engagements
- cloud / identity / credential-first coverage expansion
  - AWS/Azure/GCP attack-path thinking
  - IAM and directory abuse surfaces
  - identity-centric movement analysis
- managed-cloud / hybrid deployment evaluation
  - the repo must keep acknowledging that a Kali-only deployment model limits market reach

These items belong primarily to:

- `docs/competitive_landscape_2026.md`
- the broader product program after the current operator-intake stabilization work
- future approved roadmap phases rather than the current narrow active task

## Architecture watch items now explicitly in scope

The review flags two architecture watch items that should remain visible in scope:

- the current vanilla-JS module architecture has a ceiling as the number of shared, stateful surfaces grows
- the shared mutable runtime-state pattern should be re-evaluated before remediation, attack-path, and richer real-time surfaces are added

This does not force an immediate framework migration.

It does mean the repo should explicitly keep the following options open:

- a small event-bus or store pattern around shared state
- a lightweight reactive framework evaluation such as Preact, Vue, or Svelte if the surface grows beyond what the current DOM-management model handles cleanly

This remains an architecture watch item, not an active forced rewrite.

## Priority order captured from the review

The review recommends the following order of impact:

1. remediation loop
2. font-stack repair
3. one real Jira integration
4. attack-path graph
5. continuous mode
6. navigation compression

The repo should preserve that ranking as a commercial signal, while still respecting the current active task and build-lane truth rules.

## Scope mapping

To avoid ambiguity, the supplied review maps into repo scope as follows.

### In current active operator-console scope

- font-stack hardening
- empty states and onboarding guidance
- calmer ambient styling and visual intensity control
- navigation compression and surface consolidation decisions
- stronger attack-path-oriented visual storytelling on existing review surfaces

### In broader product-program scope, but not the current active task

- remediation closure and proof-of-resolution
- full attack-path intelligence
- enterprise workflow integrations
- continuous/scheduled validation
- cloud/identity expansion
- managed-cloud or hybrid deployment model work

### In architecture watch scope

- store/event-bus evaluation around `runtime.js`
- lightweight reactive-framework evaluation before the next major UI surface expansion

## What this does not change

This review does not, by itself:

- complete the current active task in `NEXT_TASK.md`
- authorize a backend rewrite
- authorize uncontrolled scope expansion
- declare that remediation, attack-path, integrations, continuous mode, cloud/identity, or hosted deployment are already implemented

It only makes those items explicitly part of project scope and planning truth.
