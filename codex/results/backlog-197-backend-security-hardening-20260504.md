# backlog-197 Backend Security Hardening Validation

## Result

Completed. AegisPT now has explicit CORS configuration, basic in-memory rate limiting for the selected sensitive POST routes, and a production-style startup guard for missing `AEGISPT_DB_KEY`.

## Product Truth

- `api/app/main.py` installs `CORSMiddleware` with `AEGISPT_ALLOWED_ORIGINS`.
- Default allowed origins are `http://localhost:8000` and `http://127.0.0.1:8000`.
- A new in-memory per-IP rate limiter protects:
  - `POST /api/v1/auth/keys`: 5 requests/minute.
  - `POST /api/v1/engagements/{id}/runs`: 10 requests/minute.
  - `POST /api/v1/auth/chatgpt/*`: 3 requests/minute.
- Current ChatGPT OAuth routes in the repo are `GET` routes. The literal task requirement named `POST /api/v1/auth/chatgpt/*`, so this slice limits that POST prefix without changing existing GET endpoint signatures or OAuth flow behavior.
- Startup now raises `RuntimeError` when `AEGISPT_ENV`/`APP_ENV` is production-like or `AUTO_CREATE_TABLES=false` and `AEGISPT_DB_KEY` is absent.
- Development/test startup remains permissive when `AUTO_CREATE_TABLES=true`.
- The safe-local restore API verification now uses testing mode with `AUTO_CREATE_TABLES=true`; this keeps the restored API read-path proof compatible with the new production-style DB-key guard without adding a fake SQLCipher key to a plaintext fixture database.

## Files Changed

- `.env.example`
- `api/app/config.py`
- `api/app/main.py`
- `api/app/services/rate_limit.py`
- `api/tests/test_backend_security_hardening.py`
- `api/tests/test_database_encryption.py`
- `scripts/verify_restore.py`
- `CURRENT_STATE.md`
- `DONE_LOG.md`
- `NEXT_TASK.md`

## Validation

- `python3 scripts/validate_backlog_tasks.py` passed before implementation with exactly one active task.
- `source .venv/bin/activate && python -m pytest api/tests/test_backend_security_hardening.py -q` passed.
- `source .venv/bin/activate && python -m pytest api/tests/test_backup_restore.py::test_safe_local_restore_drill_preserves_evidence_and_audit api/tests/test_database_encryption.py api/tests/test_backend_security_hardening.py -q` passed.
- `source .venv/bin/activate && python -m pytest api/tests/ -q` passed.
- `python3 scripts/validate_backlog_tasks.py` passed after implementation before promotion.
- `git diff --check` passed.
- `curl --fail --silent --max-time 5 http://127.0.0.1:8000/health/live` passed against the running local host.

## Remaining Risk

- The limiter is process-local memory, not a distributed/load-balanced rate limiter.
- The running local host was not restarted onto this code during the build-lane task; live validation was read-only health only.
- Existing ChatGPT OAuth GET routes remain unchanged because the active task specifically named the POST prefix and endpoint signatures were out of scope.
