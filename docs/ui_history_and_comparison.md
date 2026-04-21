# UI History and Comparison

## Purpose

History and comparison help operators answer what changed between runs and what follow-up work remains.

## Comparison outputs

- new findings
- fixed findings
- still-open findings
- worsened findings
- pack version changes
- inventory delta across hosts, services, and endpoints
- trend over time

## Next-step queue

The UI presents a structured queue using current findings and status:

- remediation priority
- recommended follow-up action
- current status
- retest expectation

When a run is inventory-only and therefore has no findings yet, the queue now switches to discovery guidance instead of showing an empty dead end. It points the operator toward:

- Surface / Attack Map
- Explorer
- Mission Control

When a run is a discovery-derived follow-up and still has zero findings, the queue should switch again to follow-up guidance rather than pretending the run is empty. It now explains whether the selected run was:

- service identification
- web profiling
- additional approved-range discovery

and it points the operator toward the correct next review surface.

## Run history interaction

Run history cards are now explicitly actionable:

- click the card to load that run into the operator views
- use `Load Run` to make it the active run
- use `Set Baseline` to anchor comparison
- use `Open Surface` to jump directly into discovered assets for that run
- follow-up runs now also expose `Trace Origin` so the operator can move back to the source discovery run quickly
- use the history search box to narrow runs by profile, status, target summary, or follow-up lineage without losing those actions

## Explorer dossier behavior

When a run was generated as an inventory follow-up, Explorer now shows a dedicated lineage card with:

- follow-up strategy
- source run
- source inventory snapshot
- rationale
- direct actions to load the source run or open the source surface

Explorer now also opens with a compact dossier summary for the selected run before the deeper detail blocks. That summary keeps the first operator questions visible:

- how much inventory is attached
- how much execution/evidence exists
- whether reports are ready
- what the next practical review action is

## Data model

The current UI computes comparison from existing run and finding records. No new comparison-only persistence layer is introduced.
