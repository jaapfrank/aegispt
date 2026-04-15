# UI Customer Project Run Model

## Purpose

The explorer presents AegisPT as a dossier system.

## Hierarchy

- Customer: derived from `engagement.client`
- Project / Engagement: existing engagement record
- Run: existing run record with configuration, findings, reports, and pack binding

## Run dossier contents

Each run view should expose:

- inventory basis
- wizard-defined configuration
- bound capability pack
- findings summary
- evidence access
- report variants
- approvals and decisions

## Constraint

The UI must reuse the existing engagement and run models. It does not introduce a second customer or project store.
