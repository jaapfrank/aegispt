# Active Task

## Title

Multi-target validation harness on 5 real-world OSS apps — sprint baseline + per-task incremental gate + sprint-final gate (sprint mythos-foundation, task 1 of 5)

## Goal

Provide a reproducible validation harness against 5 unrelated real-world OSS apps that AegisPT has NOT been tuned for (per `feedback_live_proof_must_be_diverse_real_targets`):

1. **Mantis Bug Tracker 2.21** (PHP/MySQL) — CVE-2020-25288 SQLi, CVE-2017-6798 XSS
2. **MediaWiki 1.34** (PHP wiki framework) — CVE-2020-25869 CSRF, CVE-2020-25812 XSS
3. **Roundcube 1.4.0** (PHP + IMAP backend) — CVE-2020-12625, CVE-2020-15562 XSS
4. **Gitea 1.13** (Go git hosting) — CVE-2020-14144 SSRF, CVE-2021-28378 stored XSS
5. **Etherpad-lite 1.8.5** (Node.js real-time collab) — CVE-2021-46709 path traversal, CVE-2020-6837 XSS

This task lands FIRST in the mythos-foundation sprint so it functions as:
- **BASELINE** on raw HEAD before any sprint fix lands
- **INCREMENTAL VALIDATION** after each of backlog-402/403/404/405 lands
- **FINAL sprint-gate** that closes the cohort (PASS on ≥2 targets at the after-405 run)

Baseline and incremental runs are observational, not pass/fail. PASS gate evaluation happens at the after-405 run only.

## Scope

New `scripts/multi_target_validation.py` (~300 lines, Python):

1. **docker-compose generation** for the 5 targets — all from public Docker Hub, no app-specific config beyond enabling external HTTP access.
2. **Per target lifecycle**: bring up container, wait for health, register an engagement + scope in AegisPT, kick off an `autonomous-intrusive` run with profile `autonomous-web`, poll for 20 advances or `stuck_no_new_signals`, capture 7 metrics: `claude_picks, exec_plan_dispatches, exec_plan_successful, captured_values_emitted, chain_findings, high_or_critical_findings, runtime_minutes`. Tear down container on success and on any exception path.
3. **Report output**: `docs/validation/sprint-2026-mythos-foundation-{YYYY-MM-DD}-{phase}.md` where phase ∈ `{baseline, after-402, after-403, after-404, after-405}`.
4. **Sprint-gate predicate** (evaluated only at after-405): PASS when on ≥2 of the 5 targets, `exec_plan_successful ≥ 1` AND `chain_findings ≥ 1` (a finding whose evidence references ≥2 distinct task outputs).
5. **Grep-guard test** at `tests/test_multi_target_validation_grep_guard.py`: asserts no `mantis|mediawiki|roundcube|gitea|etherpad` (case-insensitive) literals in `workers/runners/` or `api/app/services/` production source.

## Constraints

- Per `feedback_live_proof_must_be_diverse_real_targets`: 5 targets are immutable for this sprint. NO production code change may add per-target conditionals. If a fix is required, it MUST be generic (work across all 5).
- Per `feedback_no_prescriptive_recipes`: no app-specific paths (`/admin.php`, `/api/wiki`, etc.) seeded in any AegisPT production code as a result of this validation run. The system must find them via target_intel's emergent discovery.
- Per `feedback_live_proof_before_done`: THIS task's DONE = harness exists, runs, baseline report produced. PASS gate evaluation is NOT this task's responsibility (that's the after-405 run).
- Scope creep guard: Harness script + grep-guard test + docs/validation/ directory only. Do NOT modify `api/app/services/*` or `workers/*` (those are touched by 402/403/404/405).

## Source Package

`codex/tasks/backlog-406-multi-target-validation-harness.json`

## Reference

- Live run `3e2cfa5b-d74d-4089-b01c-1730a592afbb` — pre-sprint empirical baseline on Gruyere (training target, not in this harness)
- DONE_LOG.md 2026-05-19 entries on #336/#337/#338 + filing backlog-401/402..406
- Memory: [[feedback_live_proof_must_be_diverse_real_targets]], [[feedback_live_proof_before_done]], [[feedback_no_prescriptive_recipes]], [[feedback_self_validation]]
- Subsumes backlog-397 (Empirical Phase-3 live validation, never executed)
- Sibling tasks pending this baseline: backlog-402 (#341), backlog-403 (#342), backlog-404 (#343), backlog-405 (#344)

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `python3 -m compileall -q scripts`
- `.venv/bin/ruff check scripts/multi_target_validation.py`
- `.venv/bin/pytest tests/test_multi_target_validation_grep_guard.py`
- `git diff --check`
- `git grep -inE 'mantis|mediawiki|roundcube|gitea|etherpad' -- workers/runners/ api/app/services/` must return empty (only scripts/, tests/, docs/ may match)
- Live: `python3 scripts/multi_target_validation.py --target all --phase baseline` produces baseline report at `docs/validation/sprint-2026-mythos-foundation-{date}-baseline.md`. If a specific target's docker image is unavailable, the report marks it skipped-with-reason rather than failing the whole run.
