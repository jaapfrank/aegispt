# UI Information Hierarchy

## Purpose

The operator console keeps all existing information, but now reveals it through a calmer 3-phase structure instead of showing multiple workflow layers at the same time.

## Core rules

- primary task first
- secondary context second
- dense detail behind disclosures or drilldowns
- one primary phase visible at a time
- no meaningful information removed
- typography must use the repo-local cross-platform stack declared in `ui/assets/styles.css`; do not reintroduce Windows-only primary fonts or remote font fetches for the operator shell or report-preview placeholders

## Persistent hierarchy

The following stays visible across phases in compact form:

- engagement / customer context
- selected run context
- target summary
- profile
- enabled modules
- safety posture
- ETA or final duration
- AI / adaptive state

This context now lives in the top context strip instead of being repeated as large left-rail cards.
The strip also keeps only current-phase next actions visible, so the shell does not ask the operator to think about Intake, Run, and Analysis at the same time.

## Intake hierarchy

Intake should feel guided and quiet.

### Primary

- conversational intake
- one active question
- first-run, no-engagement state that explicitly tells the operator to answer the first intake question before execution or analysis unlocks
- concise recent conversation history
- a compact confirmation-ready summary when enough context is known
- confirmation and revision actions

### Secondary

- live summary with:
  - confirmed
  - inferred
  - still needed
- advanced configuration drawer

### Quieting rules

- only the newest conversation turns stay visible inline
- older thread context moves into `Earlier Intake Context`
- revision buttons move into `Revise Earlier Topic`
- target/access, coverage, and ETA detail stay behind disclosures until needed
- inferred output-style defaults stay out of mandatory still-needed prompts while the main goal is still being resolved
- Access Detail copy should not repeat the broader Access decision wording, so operators and browser validation can distinguish strategy choice from credential/token/session detail

### Hidden during Intake

- mission timeline as a main panel
- findings
- evidence
- reports
- history / comparison
- large persistent live feed

## Execution hierarchy

Execution should answer what is happening now.

### Primary

- Current Activity
- Run Activity
- Mission Timeline
- Operational Snapshot

### Operational Snapshot

- ETA
- Findings Pulse
- Status Board:
  - Going Well
  - Issues / Failures
  - Under Investigation

### Secondary

- Supporting Context:
  - AI narrative
  - pack status
  - scope/profile strip
- compact recent signals
- Surface / Attack Map browser controls for search, filter, and selected-asset context once inventory exists
- when no inventory exists, Surface / Attack Map must point the operator back to Intake or Mission Control instead of implying the map is simply empty
- when inventory contains hosts, Surface / Attack Map must render explicit host-card fallback content from the existing normalized inventory before any heavier graph implementation is introduced

### Hidden during Execution

- conversational intake as a main workspace
- history / comparison as a main workspace
- report center as a main workspace

## Analysis hierarchy

Analysis should answer what happened, what evidence exists, and what comes next.

### Primary

- Findings Theater
- Evidence Replay
- Report Center
- Explorer
- History / Comparison

### Secondary

- compact event history
- run context strip
- recent feed remains contextual, not persistent shell noise
- no-run empty panels must point the operator back to Conversational Intake or run creation instead of only saying that data will appear later

### Hidden during Analysis

- wizard conversation
- setup-first controls
- Mission Control as the central screen

## Discovery-first handling

Discovery-only runs keep their information, but the hierarchy explains it better:

- findings stay empty without pretending nothing happened
- Surface / Attack Map becomes the operational review surface
- the Surface / Attack Map browser now supports targeted search and filter so larger inventories do not collapse into an unreadable scroll wall
- Explorer shows the run dossier
- Explorer now opens with a compact dossier summary before the deeper task/configuration blocks
- Report Center explains inventory output even when findings remain zero
- history and next-step actions guide the operator toward controlled follow-up runs
- once a controlled follow-up run exists, Mission Control, Explorer, History, and Report Center surface the source-discovery lineage instead of making the operator reconstruct that relationship manually
- Evidence Replay now also supports a run-level posture for zero-finding discovery and follow-up runs, so it no longer collapses into a useless empty panel when task and inventory evidence still exist
- History / Comparison now exposes search and inventory delta so repeated discovery and follow-up runs stay understandable over time

## Non-goals

This hierarchy refactor does not:

- remove methodology data
- remove provenance or evidence
- change report semantics
- create a second UI
- rewrite backend models
