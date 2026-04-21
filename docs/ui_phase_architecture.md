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
  - Pack Status
- secondary support: compact context strip and recent feed
- intentionally hidden: intake conversation as a main surface, analysis-heavy report/history views

### Analysis

- primary task: review what happened and what to do next
- primary screens:
  - Findings Theater
  - Evidence Replay
  - Report Center
  - Explorer
  - History / Comparison
- intentionally hidden: conversational intake and heavy live-operation controls as the main surface

## Main rule

Only one primary phase is visible at a time.

The operator can still move between phases, but the shell only renders one major workflow area as the active central workspace. Cross-phase information is preserved through:

- the persistent context strip
- contextual sub-navigation
- drilldowns inside the active phase

## Always visible

The shell keeps only quiet, high-value context persistent across phases:

- selected engagement
- refresh control
- current next actions for the active phase only
- mission context strip with targets, profile, modules, safety, ETA, and AI state
- phase-aware left rail with only relevant sub-navigation
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
- hidden intake clutter outside Intake
- hidden execution clutter outside Execution
- hidden analysis clutter outside Analysis
- persistent context strip accuracy during phase changes
- feed-card visibility rules by phase
