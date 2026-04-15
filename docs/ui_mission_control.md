# UI Mission Control

## Purpose

Mission Control is the operational home screen after the Assessment Wizard. It should let an operator understand the current mission state in a few seconds and move directly into the right drilldown without hunting through the UI.

## Final hierarchy

1. Current Activity
2. Mission Timeline
3. Going Well / Issues / Unknown
4. ETA Intelligence
5. Findings Pulse
6. AI Signal
7. Pack Forge Status
8. Active Scope and Profile

## Behavior

- Current Activity is the first panel and always states:
  - what the platform is doing now
  - whether the mission is healthy, blocked, or standing by
  - what the operator should do next
- loading and empty states should stay explicit rather than leaving panels blank
- ETA is always visible and uses a blended model:
  - original wizard estimate
  - current phase completion
  - run age
- Findings Pulse links naturally into Findings Theater and Evidence Replay.
- Pack Forge Status links naturally into adaptive pack review and promotion workflows.
- The global context strip above the workspace keeps the product flow coherent:
  - Wizard
  - Mission Control
  - Drilldowns
  - Reports
  - History

## Data sources

- engagement and scope
- selected mission record
- inventory snapshots
- relevance decisions
- capability packs and deployments
- findings and evidence linkage
- report catalog metadata

## UX rules

- prioritize readability over density
- no dead-end panels
- every high-signal panel should suggest the next logical screen
- keep this screen operational, not administrative
