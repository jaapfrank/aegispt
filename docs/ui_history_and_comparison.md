# UI History and Comparison

## Purpose

History and comparison help operators answer what changed between runs and what follow-up work remains.

## Comparison outputs

- new findings
- fixed findings
- still-open findings
- worsened findings
- pack version changes
- trend over time

## Next-step queue

The UI presents a structured queue using current findings and status:

- remediation priority
- recommended follow-up action
- current status
- retest expectation

## Data model

The current UI computes comparison from existing run and finding records. No new comparison-only persistence layer is introduced.
