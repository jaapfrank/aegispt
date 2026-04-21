# Conversational Intake Closure Audit

## Purpose

This document is a closure guard for the active `NEXT_TASK.md` item:

`Broader conversational-intake intent coverage and richer operator edit/revision controls`.

It does not create a second active task. Its job is to stop the active task from expanding into more parser breadth, UX polish, or future backlog work before the current intake/revision scope is either closed or explicitly left open.

## Closure Alignment

At closure time, the conversational-intake task stayed aligned with the repo guardrails:

- `NEXT_TASK.md` remains the only active task source.
- `TASK_QUEUE.md` remains ordered queue context only.
- `scripts/validate_backlog_tasks.py` confirms the queue maps one-to-one to `codex/tasks/backlog-*.json`.
- Prompt 1, Prompt 2, Prompt 3, the deterministic run model, runtime safety controls, pack validation, approval, deployment, and runtime binding remain authoritative.
- No queued commercial, remediation, live-ops, integration, attack-path, continuous-mode, compliance, identity, AI-enrichment, or frontend-state work was active during the closure audit.
- After the closure gates passed, exactly one next package was promoted into `NEXT_TASK.md`: `Commercial-Viability UI Foundation`.

## Evidence Already In Scope

The active intake task now has evidence across these proof clusters:

- Supported assessment-type completion and created-run dossier parity.
- Explicit safety and boundary stops for routes that previously inferred guardrails.
- Internal and external CIDR discovery-first staging for rich goals and authenticated intent.
- Authenticated-to-unauthenticated downgrades and stale access clearing.
- Advanced-drawer realignment when profile, scope, safety, or access changes invalidate confirmation.
- Multi-role protected access, manual-auth, session, API-token, and shared no-account access contexts.
- Topic-jump commands for goal/profile/depth, scope/target, access/auth/credential/token/session, safety synonyms, and boundary synonyms.
- Last-answer and visible `Previous Topic` revision routes.
- Confirmation, inline-history, stepper, and typed-command revision routes for shared no-account access notes.
- Output-style commands and aliases, including `Change Output` from both confirmation and mid-intake states.
- Output-style run-dossier persistence through API-backed `configuration_json` checks.
- Documentation and matrix drift guards tying parser-supported commands, expected-output anchors, normalized examples, browser proof, and operator docs together.

## Closure Gates

The active task may be closed only when all gates below are true.

1. Matrix and documentation parity stays green.
   - `codex/tasks/ui_acceptance_matrix.json` remains valid JSON.
   - All canonical revision commands in the matrix are represented in `docs/ui_conversational_intake.md` and `docs/product_test_matrix.md`.
   - Normalized example commands remain documented but do not become separate canonical matrix commands.
   - Expected-output anchors remain documented in `docs/product_test_matrix.md`.

2. Parser and browser proof stay connected.
   - The static product-matrix guards still prove parser-supported command coverage.
   - The normalized-command guards still prove browser evidence, canonical resolution, and parser-shape alignment.
   - Documentation-overclaim guards still prevent docs from advertising unsupported canonical commands.

3. Run-dossier truth is explicit for every newly claimed persisted route.
   - Any route claiming persisted mission truth must assert the relevant `configuration_json` fields.
   - If a route is UI-only by design, that limitation must be called out and must not be described as run-dossier proof.

4. Live-host proof is required only for new behavior claims.
   - If the closure pass changes no runtime or UI behavior, existing supported-host evidence may stand.
   - If a new route, alias, control, or persisted behavior is claimed, fresh supported-host evidence is required before closure.

5. Repo truth is updated without promotion drift.
   - `DONE_LOG.md` records the closure pass and validation commands.
   - `CURRENT_STATE.md` records that the active task is in closure mode.
   - `NEXT_TASK.md` is changed only to narrow or close the active task.
   - The next queue item is promoted only after the active task is actually closed.

## Stop Rules

Do not add more breadth to this active task unless it repairs a demonstrated contradiction in the current claimed scope.

- Do not add new synonym families just because the parser could support them.
- Do not add new product domains.
- Do not start commercial UI, remediation, live ops, integrations, attack paths, continuous mode, compliance, LDAP/AD, AI enrichment, or runtime-store work.
- Do not move the queue forward while any closure gate above is still open.
- Do not claim "complete" from memory; use the validation packet.

## Current Closure Substep

The next substep inside the active task is a compact evidence reconciliation, not more feature work:

1. Run the targeted static/matrix validation cluster.
2. Run the smallest representative browser/API cluster needed to prove no closure guard drift.
3. If those pass and no unsupported route is being claimed, close the active task.
4. If a gap appears, fix only that gap and rerun the same closure cluster.

Recommended targeted validation cluster:

```bash
.venv/bin/python -m json.tool codex/tasks/ui_acceptance_matrix.json >/dev/null
PLAYWRIGHT_BROWSERS_PATH="$PWD/.playwright-browsers" .venv/bin/python -m pytest --capture=no ui/tests/test_product_feature_matrix_e2e.py -k 'revision_alias_matrix_matches_parser_supported_commands or revision_alias_matrix_matches_proven_typed_command_coverage or revision_alias_docs_do_not_claim_unsupported_canonical_commands or revision_alias_matrix_commands_are_documented_in_product_matrix or revision_alias_matrix_commands_are_documented_for_operators or revision_alias_matrix_outputs_are_documented_in_product_matrix or revision_alias_matrix_records_normalized_command_outputs or normalized_revision_command_browser_tests_are_documented or normalized_revision_command_examples_are_documented or normalized_revision_command_examples_match_browser_proof or normalized_revision_command_examples_resolve_to_canonical_commands or normalized_revision_command_canonicalizer_matches_wizard_parser_shape'
python3 scripts/validate_backlog_tasks.py
git diff --check
```

Representative browser/API proof should be added or rerun only if the reconciliation finds a behavior claim that is not already covered by the existing active-task evidence.
