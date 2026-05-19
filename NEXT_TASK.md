# Active Task

## Title

target_intel emit observed_paths + concrete attack_candidates; REMOVE _STACK_*_REGISTRY anti-patterns from #337/#338 (sprint mythos-foundation, task 1 of 5)

## Goal

Make target_intel the source of dynamic, per-target attack candidates instead of a stack-string identifier that downstream consumers re-classify via hand-built registries. target_intel's Claude prompt is extended to emit `attributes_json` carrying (a) `observed_paths` — concrete URL paths seen in response body / links / sitemap / robots / forms with provenance + plausible vuln-class, and (b) `attack_candidates` — a ranked list of (path, vuln_class, evidence_basis, suggested_primitive) tuples derived from those observations.

Per `feedback_live_proof_must_be_diverse_real_targets` (2026-05-19), the per-stack path tables added in #337 (`_STACK_REGISTER_PATHS` / `_STACK_LOGIN_PATHS`) and #338 (`_STACK_PATH_REGISTRY` / `_STACK_KEYWORD_HINTS`) are **deleted in the same task** — they encode per-app knowledge that does not generalize beyond the targets in the table. Downstream consumers (5 #328 probes, auth_discoverer) read target_intel's emitted fields directly.

## Scope

Three coordinated edits:

1. **`workers/runners/target_intel/runner.py`** — Claude prompt asks for JSON shape `{observed_paths: [{url, source, hypothesis, confidence}], attack_candidates: [{path, vuln_class, evidence_basis, suggested_runner_or_primitive}], technology_stack: [string]}`. Existing technology_stack output preserved for backward-compat readers.
2. **`workers/runners/_path_augmentation.py`** — REMOVE `_STACK_PATH_REGISTRY`, `_STACK_KEYWORD_HINTS`, `paths_for_stack`, `stack_hints_from_observations`. Replace with `attack_candidates_for_run(session, run_id) -> list[dict]` that reads target_intel's emitted `attack_candidates` from EvidenceObservation.
3. **`api/app/services/auth_discoverer.py`** — REMOVE `_STACK_REGISTER_PATHS`, `_STACK_LOGIN_PATHS`, `_stack_specific_paths` and the `stack_hints` kwarg behavior on `fetch_auth_pages`. `fetch_auth_pages` accepts a new `candidate_paths: list[str] | None = None` kwarg that the caller fills from target_intel's `observed_paths` of source==register-link / source==login-link.

Probe runners (#328 set) keep their `stack_hints` kwarg signature backward-compat for one release; internally route via `attack_candidates_for_run`. Tests for the removed registries are deleted; new tests assert target_intel output schema + downstream consumption.

## Constraints

- Per `feedback_live_proof_must_be_diverse_real_targets`: NO new per-stack tables. NO seeded app paths in code. target_intel's Claude prompt MUST NOT seed app-specific paths (no `/dump.gtl`, no `/elmah.axd` in prompt). Greppable check: no app-specific path literals introduced anywhere in the diff.
- Per `feedback_no_prescriptive_recipes`: target_intel may name generic vuln-classes (info-leak, stored-XSS, auth-bypass) but no app-specific payloads.
- Per `feedback_live_proof_before_done`: DONE only when validation harness (backlog-406) shows the promised effect on ≥2 of the 5 chosen real-world targets.
- Scope creep guard: 3 coordinated edits only — do NOT change probe detection heuristics, do NOT touch the picker call, do NOT change evidence_ingest entity types.

## Source Package

`codex/tasks/backlog-402-target-intel-emit-observed-paths.json`

## Reference

- Live run `3e2cfa5b-d74d-4089-b01c-1730a592afbb` — empirical evidence of the 0-exec-plan-picks gap
- DONE_LOG.md 2026-05-19 entry on registry-failure normalization
- Memory: [[feedback_live_proof_must_be_diverse_real_targets]], [[feedback_no_prescriptive_recipes]], [[feedback_live_proof_before_done]]
- Queue-blocked sibling: backlog-401 (BLOCKED-PENDING-#344-backlog-406; closed-as-subsumed if this task's emergent target_intel output covers what #401's keyword broadening was meant to fix)
- Subsumes design rationale of: backlog-401

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `.venv/bin/pytest api/tests/test_auth_discoverer.py workers/tests/test_target_intel_runner.py workers/tests/test_info_disclosure_probe.py workers/tests/test_stored_xss_probe.py workers/tests/test_file_upload_probe.py workers/tests/test_param_pollution_probe.py workers/tests/test_cookie_tamper_probe.py`
- `python3 -m compileall -q workers api`
- `.venv/bin/ruff check workers/ api/`
- `git diff --check`
- `git grep -nE '_STACK_PATH_REGISTRY|_STACK_KEYWORD_HINTS|_STACK_REGISTER_PATHS|_STACK_LOGIN_PATHS' -- workers/ api/` must return empty
- Live re-test via backlog-406 harness on ≥2 of the 5 chosen targets (Mantis BT 2.21, MediaWiki 1.34, Roundcube 1.4, Gitea 1.13, Etherpad-lite 1.8.5): target_intel emits attributes_json with target-specific observed_paths + attack_candidates; ≥1 probe consumes a dynamic path.
