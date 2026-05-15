# Active Task

## Title

Auth Discoverer: HTML Form Detection and Application Fingerprint

## Goal

Implement a shared service that fetches a target's registration / login page, parses the HTML form structure (action URL, method, field names, hidden inputs), and emits a normalized application fingerprint suitable for use as a cache key and as input to the AI recipe builder (task #326).

## Scope

- Create `api/app/services/auth_discoverer.py` with two pure functions:
  - `fetch_auth_pages(base_url, scope_allowlist)` — probes common register/login paths
  - `fingerprint_application(html_documents)` — parses HTML forms and returns normalized fingerprint dict
- Reuse existing scope check helpers
- No AI calls in this task (that is #326)
- Pure HTML parsing + heuristic stack detection

## Constraints

- Form detection + fingerprint only. No AI calls in this task. No cache logic (that is #327). No probe migration (that is #328).
- All HTTP requests must respect the passed scope_allowlist via `web_target_value_is_allowed_with_path`.
- Fingerprint must be deterministic for identical inputs.

## Source Package

`codex/tasks/backlog-375-auth-discoverer-form-detection.json`

## Reference

- `docs/evidence_graph_adoption_plan.md`
- `workers/runners/xss_proof/runner.py` (`_try_register_with_ai` reference implementation)
- `docs/checkpoints/2026-mythos-phase1-review.md` (Phase 1 GO decision context)

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `.venv/bin/pytest api/tests/test_auth_discoverer.py`
- `python3 -m compileall -q api`
- `.venv/bin/ruff check api/app/services/auth_discoverer.py`
- `git diff --check`
