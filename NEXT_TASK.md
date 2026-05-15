# Active Task

## Title

Auth Discoverer: AI-Driven Recipe Builder from Fingerprint

## Goal

Add an AI-driven function that takes the fingerprint from task #325 and produces an executable auth recipe (sequence of HTTP requests with field mappings, expected status codes, and a verification step that confirms a session was established).

## Scope

- Extend `api/app/services/auth_discoverer.py` with `build_recipe(fingerprint) -> AuthRecipe`.
- Uses Claude Haiku (cheap) for recipe synthesis.
- Recipe is a structured object that any runner can execute via existing HTTP primitives.
- No probe-side migration in this task.

## Constraints

- Recipe builder only. Do NOT add caching (task #327). Do NOT migrate probes (task #328). Do NOT touch the picker.
- Use `claude-haiku-4-5-20251001` for cost efficiency. Single short prompt. No tool use loop.
- No recipes seeded in code per `feedback_no_prescriptive_recipes` memory. AI must derive recipes from the fingerprint at runtime.

## Source Package

`codex/tasks/backlog-376-auth-discoverer-ai-recipe-builder.json`

## Reference

- `api/app/services/auth_discoverer.py` (#325 output — fingerprint shape)
- `workers/runners/xss_proof/runner.py` (`_ai_analyze_auth` reference)
- `docs/evidence_graph_adoption_plan.md` Section 6.2

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `.venv/bin/pytest api/tests/test_auth_discoverer_recipe.py`
- `python3 -m compileall -q api`
- `.venv/bin/ruff check api/app/services/auth_discoverer.py`
- `git diff --check`
