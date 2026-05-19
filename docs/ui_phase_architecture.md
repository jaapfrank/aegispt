# UI Phase Architecture

## Purpose

The operator console now uses a 3-phase shell so the product stays calm and phase-driven without dropping any existing capability.

## Phase model

### Intake

- primary task: define mission scope, access, safety, and confirmation
- primary screen: conversational intake
- secondary support: compact live mission summary and advanced configuration drawer
- intentionally hidden: mission timeline, findings, evidence, reports, explorer, history, persistent live feed wall

### Execution

- primary task: monitor the active run
- primary screens:
  - Mission Control
  - Surface / Attack Map
- secondary support: compact context strip, recent feed, and compatibility access to Adaptive Packs when the operator explicitly needs pack lifecycle review
- intentionally hidden: intake conversation as a main surface, analysis-heavy report/history views
- Surface / Attack Map can render attack-path relationship chains from the existing attack-path API output, but this remains an execution-phase visualization layer only:
  - no new attack-path backend model
  - no identity-aware or cloud-aware inference
  - no graph library dependency in the first visualization slice
  - no risk scoring or remediation-impact scoring

### Analysis

- primary task: review what happened and what to do next
- primary screens:
  - Findings + Evidence
  - Reports + Dossier
  - History / Comparison
- compatibility routes:
  - Evidence Replay for legacy deep replay and run-level artifact inspection
  - Explorer for legacy customer/engagement browsing and deeper dossier inspection
- intentionally hidden: conversational intake and heavy live-operation controls as the main surface

## Main rule

Only one primary phase is visible at a time.

The operator can still move between phases, but the shell only renders one major workflow area as the active central workspace. Cross-phase information is preserved through:

- the persistent context strip
- contextual sub-navigation
- drilldowns inside the active phase

## Runtime Store Seam

The phase shell keeps the existing deterministic JavaScript modules, but shared state now has a thin supported seam in `ui/assets/modules/runtime.js`:

- `getState()` returns the current shared runtime state for read-side callers that should not import the raw object directly in future slices.
- `patchState(patch, reason)` is the supported mutation path for cross-screen state changes.
- `subscribe(callback)` gives future UI work a single notification hook without introducing a second framework, workflow, or runtime lane.

This is intentionally not a React, Vue, Preact, or full-shell rewrite. The first migrated paths are the mutation-heavy mission creation handoff, advanced wizard account controls, Mission Control dispatch state, and Surface Map selection/filter state. Remaining direct mutations are legacy/internal module details until a future approved task narrows another slice.

Exit criteria before considering any broader reactive-layer migration:

- wizard-to-Mission-Control handoff and Mission Control run/surface state updates consistently use `patchState`
- DOM ids, test ids, and existing operator workflows stay stable under browser validation
- no product feature, attack-path delivery, live-ops surface, or framework dependency is bundled into the migration
- `runtime.js` remains the single shared-state seam rather than parallel stores emerging in feature modules

## Always visible

The shell keeps only quiet, high-value context persistent across phases:

- selected engagement
- topbar engagement dossier orientation with customer, ROE, and run-count context
- refresh control
- current next actions for the active phase only
- mission context strip with targets, profile, modules, safety, ETA, and AI state
- phase-aware left rail with 6 primary screens plus a smaller compatibility section for legacy routes
- the recent-feed shell card only during the Run phase

## Why this reduces clutter

- the old shell exposed too many destinations at once
- lifecycle, dossier, feed, wizard, and drilldowns all competed for attention on the same screen
- the new shell moves detail into the right phase instead of deleting it
- Phase 6 further reduces visual competition by:
  - shrinking shell chrome
  - collapsing older intake context and revision controls
  - grouping Mission Control support detail into quieter secondary panels

## Test coverage

Browser validation now checks:

- phase switching
- phase-specific sub-navigation
- the 6-screen primary navigation baseline and secondary compatibility routes
- Findings Theater inline evidence access before the legacy Evidence Replay route
- Report Center dossier-tab access without requiring an Explorer hop first
- hidden intake clutter outside Intake
- hidden execution clutter outside Execution
- hidden analysis clutter outside Analysis
- persistent context strip accuracy during phase changes
- feed-card visibility rules by phase
