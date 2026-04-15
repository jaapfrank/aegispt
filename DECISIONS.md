# Decisions

## Core decisions

1. AegisPT remains evidence-first. Findings, reports, and future analysis layers must stay grounded in recorded evidence and reproducible execution.
2. AI proposes and the controlled engine executes. Runtime execution remains approval-aware and deterministic.
3. Customer-specific capability packs are generated after inventory and relevance analysis, not during active runtime execution.
4. Live runtime mutation is prohibited. No self-modifying assessment runtime is allowed.
5. Codex is the primary builder in the repository, but it must operate through the supervised build lane and the repository governance files.
6. The repository is the source of truth for future Codex runs, tasks, and decisions.

## Prompt authority

Prompt 1 and Prompt 2 are authoritative for:

- methodology alignment
- adaptive testing architecture
- capability pack registry and promotion flow
- finding provenance and reporting structure

Future work must integrate with those foundations rather than redefining them.

## Runtime safety

- no uncontrolled plugin installation during runs
- no bypass of scope or safety boundaries
- no bypass of pack validation, approval, deployment, or runtime binding

## Future hooks

Placeholder modules and future-facing docs are allowed when they do not silently activate new runtime behavior.
