# Active Task

## Title

Insufficient logging and monitoring detection: verify security events are logged and error handling does not leak information

## Promoted From

`codex/tasks/backlog-231-insufficient-logging-detection.json`

## Goal

Add the queued insufficient logging and monitoring detection capability described in `codex/tasks/backlog-231-insufficient-logging-detection.json`.

## Scope

Implement the active backlog package `codex/tasks/backlog-231-insufficient-logging-detection.json`.

Expected slice:

- add a `logging-probe` runner for approved web/API roots
- detect stack traces, internal file paths, database/framework errors, internal IP disclosure, verbose error mode, exposed admin/debug paths, and Spring Actuator-style exposures
- represent CRLF/log-format/Log4Shell-style injection patterns as detection-only probes without exploitation or callback chaining
- add the `passive-web-logging-probe` run profile and required operator surfaces
- wire the profile into Full External Web Phase 1 and the wizard surfaces required by the task package
- keep evidence, findings, methodology tags, provenance, reports, approvals, scope, and runtime dispatch paths aligned with existing models and flows

## Constraints

- Keep Prompt 1 and Prompt 2 intact.
- Add only the insufficient logging and monitoring capability from the task package.
- Do not bypass local provenance, scope, ROE, validation, approval, deployment, runtime binding, credential gates, or kill switch.
- No runtime self-modification.
- No uncontrolled plugin installation.
- Error and path probing only.
- Log4Shell-style probing must stay detection-only and must not perform actual JNDI exploitation or callback-chain exploitation.
- Do not take over admin panels or chain exposed debug endpoints.
- Do not change existing Nuclei runner or ZAP configuration unless the package explicitly requires an integration point.
- No live target actions outside safe/local/expliciet geautoriseerde validatie.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `source .venv/bin/activate && python -m pytest api/tests/ -q`
- `git diff --check`

## Acceptance

- `logging-probe` is registered in supported tools.
- Stack trace leakage detection is proven on a deterministic vulnerable fixture.
- Spring Actuator/admin/debug path exposure checks are represented safely.
- Log injection probes cover CRLF and log format strings without exploitation.
- `passive-web-logging-probe` exists and is reachable through the wizard for web tiles.
- Existing runner/API tests do not regress.
