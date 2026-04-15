# Codex Repo Working Conventions

## Purpose

This document defines how Codex or ChatGPT-assisted refinement work happens around adaptive packs without changing the existing runtime, methodology layer, pack registry, or promotion pipeline.

## Authoritative base

The following remain authoritative and are reused as-is:

- methodology metadata from Prompt 1
- inventory, threat-intel, relevance, capability pack, registry, and promotion flow from Prompt 2
- evidence-first reporting and provenance structures already present in the platform

Prompt 3 adds working conventions around those existing layers. It does not redefine them.

## Scope of Codex work

Codex is allowed to help with:

- refinement of exported pack artifacts
- review notes and change summaries
- controlled repo-side helper scripts
- validation handoff steps
- operator-facing visibility around generated changes

Codex is not allowed to:

- mutate a live assessment runtime
- bypass validation, approval, or deployment gates
- install uncontrolled runtime plugins during active assessments
- redefine methodology, pack, registry, or reporting foundations already present

## Recommended working pattern

1. Generate or retrieve a capability pack through the existing APIs.
2. Export a supervised workspace with `scripts/export_codex_pack_workspace.sh`.
3. Refine only the exported artifacts and accompanying review notes.
4. Run `scripts/validate_codex_pack.sh` to hand the pack back into the existing validation lane.
5. Review validation blockers, approval history, and deployment readiness in the existing pack lifecycle.
6. Approve and deploy only through the current API gates.

## Branch and workspace conventions

Suggested branch form:

- `codex/pack-<short-pack-id>-<version>`

Suggested local workspace form:

- `codex-workspaces/<pack-name>-<version>/`

Suggested workspace files:

- `artifacts/`
- `codex-review-bundle.json`
- `codex-context.json`
- `operator-notes.md`
- `codex-change-summary.md`

## Change boundaries

When Codex is refining a pack workspace:

- keep methodology tags, inventory references, and threat-intel references intact unless the operator explicitly corrects them
- keep provenance visible in notes and summaries
- prefer additive artifact edits over restructuring surrounding platform code
- treat exported workspaces as review material, not as direct runtime state

## Validation handoff

The build lane must reuse the current pack lifecycle:

- `POST /api/v1/packs/{id}/validate`
- `POST /api/v1/packs/{id}/approve`
- `POST /api/v1/packs/{id}/deploy`

This preserves:

- recorded validation output
- explicit operator approval
- deterministic runtime binding
- rollback compatibility

## Non-goals

These conventions do not introduce:

- a second promotion pipeline
- a second pack registry
- a second methodology layer
- live runtime self-modification
- hidden autonomous execution behavior
