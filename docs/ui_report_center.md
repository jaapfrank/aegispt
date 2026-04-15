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
- show metadata, source scope/profile, methodology references, and hash
- generate preview on demand
- export Markdown or HTML
- use HTML output as the current PDF hand-off path
- compare report posture against a baseline run

## Backend integration

The UI reuses the existing run report endpoint and adds:

- report variant selection
- report catalog metadata for the run

## Constraint

This layer does not replace the reporting model from Prompt 1. It only packages it into a stronger product workflow.
