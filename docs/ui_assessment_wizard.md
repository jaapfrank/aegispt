# UI Assessment Wizard

## Purpose

The Assessment Wizard is the mandatory start of the product flow. It creates trust in what will happen next by turning operator input into a clear mission record before Mission Control opens.

## Final step model

1. Assessment Type
2. Scope Input
3. Credentials / Access
4. Test Profile
5. Test Modules
6. Safety / Limits
7. Review / Confirm

## Final UX behavior

- every step begins with a short operator-facing guidance note
- only relevant scope fields are shown for the chosen assessment type
- validation errors remain inline and specific
- submission shows an explicit in-progress state instead of leaving the operator guessing
- a live summary panel is always visible
- the summary includes readiness, targets, access context, enabled modules, safety settings, and ETA
- the confirmation step explains exactly what will be created next

## Source of truth

On confirmation, the wizard:

- creates or reuses the engagement
- records scope through the existing scope endpoint
- seeds inventory from reviewed wizard input
- creates the mission record using the existing run model with `configuration_json`

The configuration stored on the run includes:

- assessment type
- target inputs
- access context references
- selected profile
- enabled modules
- safety settings
- ETA estimate

## UX rules

- plain operator language first
- smart defaults are allowed, hidden assumptions are not
- the operator should always understand impact, depth, and likely next step
- the wizard should reduce ambiguity, not introduce it

## Security note

The wizard accepts credential and session inputs for practical operator workflows, but normal run state should surface protected secret bindings instead of raw values after run creation. This remains a baseline, not a full vault product.
