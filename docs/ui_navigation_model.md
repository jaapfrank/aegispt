# UI Navigation Model

## Top-level navigation

The top strip is now phase-first:

- Intake
- Run
- Analysis

These buttons are the primary navigation model for the product shell.

## Contextual sub-navigation

The left rail no longer shows every destination at once. It only shows screens that belong to the active phase.

### Intake sub-navigation

- Conversational Intake
- Advanced Settings

### Run sub-navigation

- Mission Control
- Surface / Attack Map
- Pack Status

### Analysis sub-navigation

- Findings
- Evidence
- Reports
- Explorer
- History / Comparison

## Navigation rules

- the top strip changes the active phase
- phase switching selects the most sensible default screen for that phase
- sub-navigation changes screens only inside the active phase
- the top action row only shows actions relevant to the active phase
- follow-up actions inside cards can still deep-link to another relevant screen
- no duplicate screens are introduced just to satisfy the phase model

## Default screen behavior

- Intake defaults to `wizard`
- Run defaults to `mission-control`
- Analysis defaults to:
  - `findings-theater` when findings are already selected
  - otherwise `report-center`

## Persistent context strip

The strip above the workspace is not a second dashboard. It exists to answer:

- which mission is selected
- which phase is active
- what scope/profile/modules/safety posture are in effect
- what the current ETA or final duration is
- whether the run is deterministic baseline or adaptive/Codex-linked

## Live feed behavior

- Intake: hidden as a persistent block
- Run: compact recent signals
- Analysis: hidden as a shell block and available only as contextual event history
