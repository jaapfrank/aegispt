# UI ETA Model

## Purpose

The ETA model provides operator guidance, not execution guarantees.

## Inputs

Wizard ETA uses:

- target count
- enabled module count
- selected profile
- access-context count
- adaptive generation setting
- safety limits

Mission Control ETA also considers:

- elapsed time since run creation
- current phase completion
- approval gates
- pack promotion state

## Output

The UI displays:

- elapsed minutes
- estimated remaining minutes
- estimated total duration
- confidence level

## Notes

- ETA is intentionally explainable and simple
- it is stored with the run configuration for consistency across UI and reports
- it must never be presented as proof of runtime completion or tool success
