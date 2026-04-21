# UI Screen Mapping

## Purpose

This mapping preserves the existing UI surfaces but places each one inside the correct workflow phase.

## Intake phase

| Existing Screen | New Phase Placement | Notes |
| --- | --- | --- |
| Conversational Mission Intake | Intake | Mandatory start of the flow |
| Advanced Configuration Drawer | Intake | Power-user controls stay available without dominating the screen |
| Live Mission Summary | Intake | Secondary summary only, led by current essentials / still-needed / mission brief before deeper disclosures |

## Execution phase

| Existing Screen | New Phase Placement | Notes |
| --- | --- | --- |
| Mission Control | Run | Default execution home with `Current Activity`, `Run Activity`, grouped `Operational Snapshot`, and grouped `Supporting Context` |
| Surface / Attack Map | Run | Execution-time estate and hotspot review with searchable asset browser and selected-asset context |
| Pack Forge / Pack Status | Run | Adaptive pack state during active work |

## Analysis phase

| Existing Screen | New Phase Placement | Notes |
| --- | --- | --- |
| Findings Theater | Analysis | Primary finding review surface |
| Evidence Replay | Analysis | Evidence-first validation view |
| Report Center | Analysis | Reporting and export workflow |
| Explorer | Analysis | Dossier-style run review with a compact summary layer before the deep detail blocks |
| History / Comparison | Analysis | Run delta, trend, searchable history, and next-step review |

## Shared but not duplicated

These elements remain available across phases without becoming full screens everywhere:

- persistent context strip
- phase-aware next actions filtered to the current phase
- compact recent feed during Run only
- engagement selector

## Intentional non-mapping

The following are intentionally not separate top-level screens anymore:

- old always-visible lifecycle strip as a pseudo-dashboard
- always-expanded dossier rail
- always-expanded live feed panel

Their information remains available, but now appears in the correct phase and level of detail.
