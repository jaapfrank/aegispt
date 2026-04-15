# Risk Scoring Model

## Purpose

This document prepares a future risk scoring layer without replacing the existing finding severity model.

## Inputs

Future risk scoring should consider:

- severity
- exploitability
- business impact
- exposure
- environmental context
- evidence confidence

## Placeholder code

Prompt 3 adds:

- `api/app/services/risk_scoring.py`

with placeholder interface:

- `calculate_risk(finding)`

## Design rule

Risk scoring must layer on top of existing Prompt 1 and Prompt 2 finding metadata. It must not rewrite or remove the current severity or provenance fields.

## Future output

A later scoring response may include:

- component scores
- overall risk score
- scoring rationale
- trend deltas across runs
