# UI Mission Control

## Purpose

Mission Control is the operational home screen after the Assessment Wizard. It should let an operator understand the current mission state in a few seconds and move directly into the right drilldown without hunting through the UI.

## Final hierarchy

1. Current Activity
2. Run Activity
3. Mission Timeline
4. Operational Snapshot
5. Supporting Context

`Operational Snapshot` now groups:

- ETA Intelligence
- Findings Pulse
- Going Well / Issues / Unknown

`Supporting Context` now groups:

- AI Signal
- Pack Forge Status
- Active Scope and Profile

## Behavior

- Current Activity is the first panel and always states:
  - what the platform is doing now
  - whether the mission is healthy, blocked, or standing by
  - what the operator should do next
- when a run has queued tasks but has not been dispatched yet, Current Activity must expose an explicit `Start Validation` action
- the lifecycle strip should also surface `Start Validation` as a top-level next action so the operator does not need to hunt inside the larger Mission Control panel first
- when a run is `pending_approval`, Current Activity and Run Activity must not fall back to generic "no tasks queued yet" copy:
  - Current Activity must state that run launch is blocked pending approval
  - Run Activity must show required, granted, and pending approval counts
  - `Start Validation` must stay hidden until the approval gate actually clears
- if a host accepts dispatch in `manual` mode while no worker is attached, Mission Control must stop treating `Start Validation` like a normal runnable action and instead surface a clear blocked-state explanation:
  - why the queued checks did not start
  - that direct-host installs are expected to run `inline`
  - that the operator should switch `TASK_DISPATCH_MODE=inline` or attach a worker before retrying
- Run Activity must make execution visible without requiring a finding to exist first:
  - queued task counts
  - running task counts
  - completed or failed task counts
  - recent tool and target activity
- Run Activity now also includes a selected-check focus block so the operator can inspect:
  - tool
  - target
  - target type
  - execution lane
  - last change time
  - latest execution result and artifact count
- inventory-only runs must not look empty just because findings stay at zero:
  - Mission Control should explicitly say when discovery is launching
  - once the discovery snapshot is stored, Current Activity should switch to an inventory-complete summary with host/service counts
  - the operator should be pointed directly to `Surface Map` and `Explorer`
- internal-LAN missions that use the `Internal Validation` operator profile should still start with discovery-first copy in Mission Control, so the operator can see that the first run is building the estate map rather than already producing findings
- once inventory is ready, Mission Control should also expose concrete next-step follow-up actions rather than stopping at visibility only:
  - service identification on discovered hosts
  - passive web profiling on discovered web-capable targets
  - additional range discovery only for already-approved internal CIDRs that were not scanned yet
- for staged internal-LAN validation, the first follow-up recommendation should make it clear that service identification is the next controlled step before deeper validation
- follow-up actions must create real run dossiers and reuse the existing run/dispatch flow; they must not mutate the active runtime silently
- when a follow-up run finishes with enriched inventory but zero findings, Mission Control should present it as a useful completed follow-up stage:
  - strategy label
  - rationale
  - source discovery context
  - direct actions into Surface Map and Explorer
- secondary execution detail should not compete with Current Activity and Mission Timeline at equal visual weight:
  - ETA, findings pulse, and status lanes now live inside `Operational Snapshot`
  - AI, pack, and scope context now live inside `Supporting Context`
- the left-rail status area now keeps one focused current item visible and moves older feed entries into `Recent Feed History`
- the phase feed is only rendered as a persistent shell block during the Run phase
- loading and empty states should stay explicit rather than leaving panels blank
- automatic refresh is now more aggressive while a selected run is queued, dispatching, or running, then relaxes again during idle dossier review
- ETA is always visible and uses a blended model:
  - original wizard estimate
  - current phase completion
  - run age
- Findings Pulse links naturally into Findings Theater and Evidence Replay.
- Pack Forge Status links naturally into adaptive pack review and promotion workflows.
- Active Scope and Profile now show both:
  - operator-selected coverage intent
  - enforced execution lane and planned tools
- dense pack, scope, and secondary activity detail should prefer disclosures over permanently expanded cards
- wizard-seeded inventory is labeled as seeded input instead of being presented as confirmed discovery telemetry
- discovery-first runs may auto-shift the operator into `Surface Map` after dispatch completes so the discovered estate is visible immediately
- run-level inventory shown in Mission Control and Surface Map must aggregate all inventory snapshots derived from the same run instead of only the latest task snapshot
- acceptance-created runs can surface safe-scenario context without turning Mission Control into a QA dashboard
- The global context strip above the workspace keeps the product flow coherent:
  - Wizard
  - Mission Control
  - Drilldowns
  - Reports
  - History
- the lifecycle strip should behave like real navigation rather than decorative labels

## Data sources

- engagement and scope
- selected mission record
- inventory snapshots
- relevance decisions
- capability packs and deployments
- findings and evidence linkage
- report catalog metadata
- run profile metadata already loaded from the backend

## UX rules

- prioritize readability over density
- no dead-end panels
- every high-signal panel should suggest the next logical screen
- keep this screen operational, not administrative
- if a run has started, the operator should be able to answer "what is executing right now?" without leaving Mission Control
- if execution finished with failures or with thin/no reviewable output, Mission Control should say that explicitly instead of quietly presenting the run like a clean success
- Current Activity and Run Activity should remain the first scan targets; grouped secondary panels should support, not compete with, those answers
- if execution was a controlled discovery follow-up, Mission Control should also answer:
  - what follow-up strategy ran
  - what discovery output it came from
  - what review step is now most useful
