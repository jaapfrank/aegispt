# Active Task

## Title

Local runtime liveness and audit harness resilience

## Promoted From

`codex/tasks/backlog-181-local-runtime-liveness-and-audit-resilience.json`

## Goal

Make the local control plane reliable enough for enterprise acceptance testing: health checks must not hang, restart helpers must fully replace draining processes, and audit tools must write partial evidence when the app is unhealthy.

## Scope

Implement the active backlog package `codex/tasks/backlog-181-local-runtime-liveness-and-audit-resilience.json`.

Expected slice:

- detect and terminate stuck draining inline hosts before restart helpers declare success
- make `/health/live` respond or fail fast with actionable diagnostics under audit load
- make full-system and IA audit scripts write partial evidence when health or page navigation fails
- avoid Playwright audit dependence on perpetual `networkidle` when the app legitimately polls
- surface healthy, degraded, shutting-down, and unreachable local runtime states where relevant

## Constraints

- Keep Prompt 1 and Prompt 2 intact.
- Do not bypass pack registry, validation, approval, deployment, runtime binding, scope enforcement, credential gates, or kill switch behavior.
- No runtime self-modification.
- Do not install uncontrolled plugins.
- Only fix local runtime health, restart, and audit resilience.
- Do not change assessment runner dispatch semantics.
- Do not run live customer or intrusive targets.
- Do not add new live-target behavior.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `source .venv/bin/activate && python -m pytest api/tests/test_health.py -q`
- `AEGISPT_LOCAL_ENSURE_ZAP=0 bash scripts/restart_local_inline_host.sh`
- `curl --max-time 5 -fsS http://127.0.0.1:8000/health/live`
- `python3 scripts/run_full_system_acceptance_audit.py --base-url http://127.0.0.1:8000 --output-json codex/results/backlog-181-full-system-audit.json --output-md codex/results/backlog-181-full-system-audit.md --max-seconds 180`
- `python3 scripts/run_enterprise_ia_audit.py --base-url http://127.0.0.1:8000 --output-json codex/results/backlog-181-ia-audit.json --output-md codex/results/backlog-181-ia-audit.md --screenshot-dir codex/results/backlog-181-ia-screenshots`
- `git diff --check`

## Acceptance

- A stuck old host cannot make restart report success.
- Audit scripts leave a durable defect artifact even when health or navigation fails.
- The local app remains reachable at `/app/` and `/health/live` after audit execution.
