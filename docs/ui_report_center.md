# UI Report Center

## Purpose

The Report Center turns exported outputs into a first-class operator workflow rather than a raw download endpoint.

## Supported report variants

- Executive Report
- Technical Report
- Evidence Appendix
- Retest / Verification Report

## UI workflow

- list report variants for the selected run
- show metadata, selected run context, source scope/profile, methodology references, and hash
- show discovery-aware inventory totals alongside findings totals so inventory-first runs do not look empty when they mapped assets but produced no vulnerability findings yet
- show the enforced execution lane and planned runtime tools for the selected run alongside the report metadata
- when the selected run is a controlled discovery follow-up, show lineage metadata for:
  - follow-up strategy
  - source run
  - source inventory snapshot
  - rationale
- generate preview on demand
- export Markdown, HTML, or PDF directly against the selected run dossier
- make it clear that export links always apply to the currently selected run so stale URLs from another environment are easier to spot
- compare report posture against a baseline run

## Backend integration

The UI reuses the existing run report endpoint and adds:

- report variant selection
- report catalog metadata for the run

## Constraint

This layer does not replace the reporting model from Prompt 1. It only packages it into a stronger product workflow.

## Discovery-first behavior

- if a run has zero findings but linked inventory, the Report Center must say that clearly instead of implying the run had no value
- technical/executive/evidence/retest variants should still surface the mapped inventory counts and discovery summary
- direct export links remain valid for the currently selected run only, so operators should prefer launching downloads from the active dossier instead of reusing stale URLs
- follow-up reports should also make it clear when the current run came from a prior discovery run so the operator can trace that lineage without leaving the report workflow first
- the evidence appendix should stay useful even when the run has zero findings, because task evidence and discovery/follow-up inventory context can still be reviewable outputs
