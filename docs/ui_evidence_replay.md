# UI Evidence Replay

## Purpose

Evidence Replay is the operator surface for understanding what a run actually executed and what evidence exists to support analyst conclusions.

It should work in two honest modes:

- finding-linked replay
- run-level evidence posture when no finding exists yet

## Finding-linked behavior

When a selected finding exists, Evidence Replay should show:

- finding title, severity, status, and origin
- evidence reference
- methodology references
- related executions
- related artifacts
- pack, inventory, and relevance lineage

## Zero-finding behavior

When the selected run has no findings but still produced useful run output, Evidence Replay should not fall back to an empty dead end.

Instead it should show a run-level evidence posture with:

- run status
- task count
- selected task execution detail
- artifact availability
- linked inventory counts
- report/methodology context
- follow-up lineage when applicable

This applies especially to:

- discovery-only inventory runs
- inventory-derived follow-up runs such as service identification or web profiling

## Lineage rules

If the selected run is a controlled follow-up, Evidence Replay should surface:

- follow-up strategy
- source run
- source inventory snapshot
- rationale

The operator should be able to move from this view into:

- Mission Control
- Report Center
- Explorer
- Surface Map
- History

## Non-goals

This screen does not:

- invent findings for zero-finding runs
- create a second evidence model
- replace the existing finding-linked evidence API

It only makes the existing run/task/inventory/report context usable when a human operator needs to review what happened.
