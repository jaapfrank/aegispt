# Frontend Modularization

## Purpose

The operator console originally relied on one large `ui/assets/app.js` controller. This hardening pass reduces maintenance risk by moving screen logic into focused native ES modules while preserving the current UX and backend contracts.

## Current structure

- `ui/assets/app.js`
  - shell orchestration
  - state refresh
  - navigation
  - lifecycle strip and global status feed
- `ui/assets/modules/constants.js`
  - shared static option lists and severity ordering
- `ui/assets/modules/runtime.js`
  - shared runtime state, DOM references, and action registry
- `ui/assets/modules/shared.js`
  - reusable formatting and rendering helpers
- `ui/assets/modules/api.js`
  - fetch wrapper with actor propagation
- `ui/assets/modules/wizard.js`
  - mandatory assessment wizard
- `ui/assets/modules/mission-control.js`
  - Mission Control and Surface / Attack Map rendering
- `ui/assets/modules/findings.js`
  - Findings Theater and Evidence Replay
- `ui/assets/modules/packs.js`
  - Pack Forge actions and Codex task wiring
- `ui/assets/modules/reports.js`
  - Report Center preview/export workflow
- `ui/assets/modules/explorer-history.js`
  - Explorer dossier and history/comparison flow

## Design rules

- keep the current product flow intact
- do not add a heavy frontend framework just for modularity
- keep screen modules additive and backend-contract aware
- centralize cross-screen state in `runtime.js`
- prefer explicit imports over hidden globals

## Operator-trust additions in this pass

- wizard submission now resets cleanly on failure
- report preview shows a loading state while rendering
- evidence selection shows loading feedback
- pack actions expose an explicit in-progress state
- protected secret bindings remain visible as metadata without exposing raw values
