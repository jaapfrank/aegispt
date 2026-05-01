# Live Mission and GitHub CI Check - 2026-05-01

## GitHub CI

- PR CI failure cause: GitHub runner missed the Playwright Chromium executable before `pytest`.
- Fix applied: `.github/workflows/ci.yml` now runs `python -m playwright install --with-deps chromium` after dev dependency install and before tests.
- Local validation:
  - `git diff --check` passed.
  - `python3 scripts/validate_backlog_tasks.py` passed with `187` queued task packages mapped one-to-one and exactly one active task.
- Remaining risk: GitHub Actions must run on the pushed commit before CI can be called green.

## Live Mission Read-Only Check

- `curl --max-time 5 -fsS http://127.0.0.1:8000/health/live` timed out with no bytes returned.
- Two `uvicorn` processes were present; the listener on `127.0.0.1:8000` was PID `97853` and consumed about one full CPU during inspection.
- Current run:
  - run id: `d4a4d2c13f0c458c9d7c528a2187e2d9`
  - engagement: `10.0.20.0/24 Deep Assessment`
  - engagement id: `b3e01ae83ffb46648c3bfdf36b50bc5a`
  - status: `running`
  - chain id: `2fcd9f53e20048d7b31f1ca5ac52423a`
  - chain status: `active`
  - phase index / step index: `2 / 0`
  - auto-advance: enabled
- Task state for the current run:
  - `4` completed tasks
  - `4` running tasks
  - `273` queued tasks
- Running task issue:
  - running `smart-home` tasks for targets `10.0.20.102`, `10.0.20.103`, `10.0.20.104`, and `10.0.20.105` had no persisted `tool_executions` rows and no stdout/stderr at inspection time.
- AI signal:
  - one live AI signal for completed task `6b31994dc5574d698af88a5585b255c8` succeeded.
  - multiple `post_task_analysis` rows failed with `invalid literal for int() with base 10: 'high'`.

## Operator Impact

The mission appears stuck or degraded from the operator perspective: the control plane is partly responsive in logs, but health checks time out, the listener is CPU saturated, and the current run has running tasks without execution records. No restart, kill, or database mutation was performed during this check because the mission may still have in-flight state.
