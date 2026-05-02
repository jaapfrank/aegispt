# Backlog 181 Runtime Liveness Validation

- Task: `backlog-181-local-runtime-liveness-and-audit-resilience`
- Date: `2026-05-02`
- Live environment: `http://127.0.0.1:8000`
- Live environment relevance: relevant; this task validates local host restart, `/health/live`, `/app/`, and audit harness behavior.

## Implementation Evidence

- Restart helpers now inspect TCP listeners on the configured port, wait for release, terminate draining AegisPT uvicorn hosts, refuse to replace non-AegisPT listeners, and use bounded health curl timeouts before declaring success.
- `/health/live` now returns `runtime_state`, `checked_at`, and diagnostics while preserving the existing healthy `status=ok` / `detail=service is running` contract.
- Settings readiness now exposes the local runtime state vocabulary: `healthy`, `degraded`, `shutting_down`, `unreachable`.
- Full-system and enterprise IA audit scripts now write partial JSON/Markdown evidence when health or browser navigation fails.
- Enterprise IA audit navigation now waits for `domcontentloaded` instead of perpetual `networkidle`.
- Pytest default capture is disabled in `pyproject.toml` to avoid the local WSL/Windows temp-file capture teardown failure during required build-lane validation.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
  - Result: passed; 193 queued task packages mapped one-to-one and `NEXT_TASK.md` contained exactly one active task.
- `source .venv/bin/activate && python -m pytest api/tests/test_health.py -q`
  - Result: passed; 5 tests passed after repo-level pytest capture hardening.
- `AEGISPT_LOCAL_ENSURE_ZAP=0 bash scripts/restart_local_inline_host.sh`
  - Result: passed; inline host restarted and reported `Health: http://127.0.0.1:8000/health/live`.
- `curl --max-time 5 -fsS http://127.0.0.1:8000/health/live`
  - Result: passed; returned `status=ok`, `runtime_state=healthy`, and diagnostics.
- `python3 scripts/run_full_system_acceptance_audit.py --base-url http://127.0.0.1:8000 --output-json codex/results/backlog-181-full-system-audit.json --output-md codex/results/backlog-181-full-system-audit.md --max-seconds 180`
  - Result: passed; wrote JSON/Markdown, visited 14/14 screens, recorded 23 product defects for existing backlog/triage tracking.
- `python3 scripts/run_enterprise_ia_audit.py --base-url http://127.0.0.1:8000 --output-json codex/results/backlog-181-ia-audit.json --output-md codex/results/backlog-181-ia-audit.md --screenshot-dir codex/results/backlog-181-ia-screenshots`
  - Result: passed; wrote JSON/Markdown/screenshots, checked 28 pages, average/minimum score 10.0, `partial=false`.
- Post-audit acceptance checks:
  - `/health/live`: passed; `runtime_state=healthy`.
  - `/app/`: passed; `HTTP/1.1 200 OK`.
- `git diff --check`
  - Result: passed before administration updates.

## Remaining Risks

- The full-system audit still records 23 product defects; backlog-181 made the audit durable and non-hanging, but did not fix unrelated product/UI defects.
- The restart helper refuses to replace a non-AegisPT listener on the configured port; that is intentional safety behavior and requires operator intervention if another service owns port 8000.
- No live customer target, intrusive target, pack registry bypass, runtime binding bypass, or assessment runner dispatch change was performed.
