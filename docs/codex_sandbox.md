# Codex Sandbox

## Purpose

Codex must operate in a controlled build environment, not against production or active assessment runtime state.

## Sandbox principles

- use a container-based or disposable development environment
- keep runtime execution separate from build-lane refinement
- log planned commands and validation handoff
- use safe wrappers for common build-lane operations

## Current safe wrappers

- `scripts/export_codex_pack_workspace.sh`
- `scripts/validate_codex_pack.sh`

These wrappers operate against the existing API and pack lifecycle. They do not inject logic into active runs.

## Command logging

For Prompt 3, command preparation is captured through:

- `codex/results/*.json`
- `DONE_LOG.md`
- operator notes inside exported workspaces

## No direct production execution

Codex build-lane tasks must not:

- execute against production targets directly
- mutate runtime during active assessments
- side-load unvalidated tooling into execution paths

## Future wrapper direction

Future work may add:

- sandbox container launchers
- stricter command allowlists
- richer command transcripts

Those additions should remain separate from the active runtime and from the existing promotion pipeline.
