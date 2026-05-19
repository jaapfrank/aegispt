# Active Task

## Title

target_intel emit observed_paths + concrete attack_candidates; REMOVE _STACK_*_REGISTRY anti-patterns from #337/#338 (sprint mythos-foundation, task 2 of 5)

## Goal

Make target_intel the source of dynamic, per-target attack candidates instead of a stack-string identifier that downstream consumers re-classify via hand-built registries. target_intel's Claude prompt is extended to emit `attributes_json` carrying (a) `observed_paths` — concrete URL paths seen in response body / links / sitemap / robots / forms with provenance + plausible vuln-class, and (b) `attack_candidates` — a ranked list of (path, vuln_class, evidence_basis, suggested_primitive) tuples derived from those observations.

Per `feedback_live_proof_must_be_diverse_real_targets` (2026-05-19), the per-stack path tables added in #337 (`_STACK_REGISTER_PATHS` / `_STACK_LOGIN_PATHS`) and #338 (`_STACK_PATH_REGISTRY` / `_STACK_KEYWORD_HINTS`) are **deleted in the same task** — they encode per-app knowledge that does not generalize beyond the targets in the table. Downstream consumers (5 #328 probes, auth_discoverer) read target_intel's emitted fields directly.

## Baseline anchor

backlog-406 baseline (2026-05-19) on 5 real-world OSS targets shows **0/0/0/0/0/0 on every metric**. The sprint's job is to move those numbers off zero by making the AI loop *reason* instead of *templated-pick*. This task is the first lever: give target_intel a real planning role instead of a stack-name role.

## Scope

Three coordinated edits:

1. **`workers/runners/target_intel/runner.py`** — Claude prompt asks for JSON shape `{observed_paths: [{url, source, hypothesis, confidence}], attack_candidates: [{path, vuln_class, evidence_basis, suggested_runner_or_primitive}], technology_stack: [string]}`. Existing technology_stack output preserved for backward-compat readers.
2. **`workers/runners/_path_augmentation.py`** — REMOVE `_STACK_PATH_REGISTRY`, `_STACK_KEYWORD_HINTS`, `paths_for_stack`, `stack_hints_from_observations`. Replace with `attack_candidates_for_run(session, run_id) -> list[dict]` that reads target_intel's emitted `attack_candidates` from EvidenceObservation.
3. **`api/app/services/auth_discoverer.py`** — REMOVE `_STACK_REGISTER_PATHS`, `_STACK_LOGIN_PATHS`, `_stack_specific_paths` and the `stack_hints` kwarg behavior on `fetch_auth_pages`. `fetch_auth_pages` accepts a new `candidate_paths: list[str] | None = None` kwarg that the caller fills from target_intel's `observed_paths` of source==register-link / source==login-link.

Probe runners (#328 set) keep their `stack_hints` kwarg signature backward-compat for one release; internally route via `attack_candidates_for_run`. Tests for the removed registries are deleted; new tests assert target_intel output schema + downstream consumption.

## Constraints

- Per `feedback_live_proof_must_be_diverse_real_targets`: NO new per-stack tables. NO seeded app paths in code. target_intel's Claude prompt MUST NOT seed app-specific paths (no `/dump.gtl`, no `/elmah.axd` in prompt). Greppable check: no app-specific path literals introduced anywhere in the diff. The backlog-406 grep-guard test additionally enforces no target hostname literals.
- Per `feedback_no_prescriptive_recipes`: target_intel may name generic vuln-classes (info-leak, stored-XSS, auth-bypass) but no app-specific payloads.
- Per `feedback_live_proof_before_done`: DONE only when validation harness (backlog-406) `--phase after-402` shows a measurable delta off the 0/0/0/0/0/0 baseline on ≥1 of the 5 real-world targets (target_intel emits ≥3 observed_paths + ≥1 attack_candidate; downstream probe consumes the path).
- Scope creep guard: 3 coordinated edits only — do NOT change probe detection heuristics, do NOT touch the picker call, do NOT change evidence_ingest entity types.

## Source Package

`codex/tasks/backlog-402-target-intel-emit-observed-paths.json`

## Reference

- Backlog-406 baseline report: `docs/validation/sprint-2026-mythos-foundation-2026-05-19-baseline.md` (5 targets all at 0/0/0/0/0/0)
- Live run `3e2cfa5b-d74d-4089-b01c-1730a592afbb` — pre-sprint empirical baseline on Gruyere (training target)
- Memory: [[feedback_live_proof_must_be_diverse_real_targets]], [[feedback_no_prescriptive_recipes]], [[feedback_live_proof_before_done]]
- Queue-blocked sibling: backlog-401 (BLOCKED-PENDING; will be CLOSED-AS-SUBSUMED iff this task's emergent target_intel output covers what #401's keyword broadening was meant to fix, verified via after-402 harness run)

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `.venv/bin/pytest api/tests/test_auth_discoverer.py workers/tests/test_target_intel_runner.py workers/tests/test_info_disclosure_probe.py workers/tests/test_stored_xss_probe.py workers/tests/test_file_upload_probe.py workers/tests/test_param_pollution_probe.py workers/tests/test_cookie_tamper_probe.py`
- `python3 -m compileall -q workers api`
- `.venv/bin/ruff check workers/ api/`
- `git diff --check`
- `git grep -nE '_STACK_PATH_REGISTRY|_STACK_KEYWORD_HINTS|_STACK_REGISTER_PATHS|_STACK_LOGIN_PATHS' -- workers/ api/` must return empty
- `.venv/bin/pytest tests/test_multi_target_validation_grep_guard.py` (backlog-406 sentinel must still pass)
- Live re-test via backlog-406 harness with `--phase after-402` on the 5 targets: target_intel emits attributes_json with target-specific observed_paths + attack_candidates; ≥1 probe consumes a dynamic path; ≥1 target shows non-zero on observed_paths or captured_values count (delta off baseline).
