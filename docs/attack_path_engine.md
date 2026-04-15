# Attack Path Engine

## Purpose

This document prepares a future attack path engine without implementing a full system today.

## Planned inputs

- inventory snapshots
- findings and their provenance
- pack bindings and pack-derived context
- future identity and privilege context

## Planned outputs

- attack graph nodes and edges
- candidate attack paths
- path explanations tied to existing evidence
- future UI graph views

## Placeholder code

Prompt 3 adds:

- `api/app/services/attack_paths.py`

with placeholder interfaces:

- `build_attack_graph(run_id)`
- `evaluate_paths(run_id)`

## UI direction

Later UI work may visualize:

- path nodes by host, identity, asset, or finding
- path edges by trust relationship, auth dependency, or exploit step
- path strength by future risk scoring

## Non-goal

No attack graph persistence, scoring engine, or heavy implementation is introduced in Prompt 3.
