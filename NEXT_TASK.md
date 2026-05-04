# Active Task

## Title

Backend security hardening: add CORS configuration, basic rate limiting, and enforce DB encryption key at startup

## Promoted From

`codex/tasks/backlog-197-backend-cors-rate-limit-db-enforcement.json`

## Goal

Add the backend hardening slice from the active task package: explicit CORS configuration, basic rate limiting on sensitive endpoints, and production startup enforcement for the database encryption key.

## Scope

Implement the active backlog package `codex/tasks/backlog-197-backend-cors-rate-limit-db-enforcement.json`.

Expected slice:

- add FastAPI CORSMiddleware in `api/app/main.py` with allowed origins from `AEGISPT_ALLOWED_ORIGINS`
- default allowed origins to `http://localhost:8000` and `http://127.0.0.1:8000`
- add basic per-IP rate limiting for:
  - `POST /api/v1/auth/keys` at 5 requests/minute
  - `POST /api/v1/engagements/{id}/runs` at 10 requests/minute
  - `POST /api/v1/auth/chatgpt/*` at 3 requests/minute
- enforce `AEGISPT_DB_KEY` at startup in production-style environments while keeping development/test behavior permissive

## Constraints

- Keep Prompt 1 and Prompt 2 intact.
- Do not change authentication logic.
- Do not change endpoint signatures or response models.
- Do not change database schema.
- Do not change frontend code.
- Do not bypass approval gates, pack lifecycle, deployment, runtime binding, scope enforcement, credential gates, or kill switch behavior.
- No runtime self-modification.
- Do not install uncontrolled plugins.
- Do not run live target actions.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `source .venv/bin/activate && python -m pytest api/tests/ -q`
- `git diff --check`

## Acceptance

- CORSMiddleware is present in `api/app/main.py` with configurable allowed origins.
- `POST /api/v1/auth/keys` is rate-limited to 5 requests/minute per IP.
- `POST /api/v1/engagements/{id}/runs` is rate-limited to 10 requests/minute per IP.
- `POST /api/v1/auth/chatgpt/*` is rate-limited to 3 requests/minute per IP.
- Startup raises `RuntimeError` when `AEGISPT_ENV=production` and `AEGISPT_DB_KEY` is absent.
- Existing API tests pass.
- Development/test behavior is unchanged.
