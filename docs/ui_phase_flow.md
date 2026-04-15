# UI Phase Flow

## Purpose

The UI uses a stable product-level phase model so operators can see progress even when the underlying evidence comes from multiple existing subsystems.

## Visible phases

1. Recon
2. Surface Mapping
3. Auth Access
4. Deep Analysis
5. Adaptive Testing
6. Verification
7. Reporting

## Mapping logic

- Recon and Surface Mapping draw from scope and inventory
- Auth Access draws from wizard access context and auth-relevant mission setup
- Deep Analysis draws from run tasks and approvals
- Adaptive Testing draws from relevance decisions, packs, and Codex-supervised refinement
- Verification draws from findings and replay readiness
- Reporting draws from report catalog availability

## Status model

Each phase exposes:

- pending
- active
- complete
- blocked

Progress values are UI-level heuristics built from current backend state. They do not replace evidence, approvals, or actual task results.
