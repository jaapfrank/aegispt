# backlog-210 Email, Slack, and Teams Notification Evidence

## Task

- Active task: `backlog-210-email-slack-teams-notification`
- Package: `codex/tasks/backlog-210-email-slack-teams-notification.json`
- Scope: optional SMTP email, Slack webhook, and Teams Adaptive Card notifications for critical findings, run completion, and phase approval-needed events.

## Implementation Proof

- Added `api/app/services/notification_delivery.py`.
- Delivery is optional and returns no receipts when no channels are configured.
- SMTP uses encrypted `notifications.smtp_password` plus plain host/port/from/to settings.
- Slack and Teams reuse encrypted settings keys `integrations.slack_webhook_url` and `integrations.teams_webhook_url`.
- Teams delivery uses Adaptive Card payloads with `application/vnd.microsoft.card.adaptive`.
- Worker completion flow calls notification delivery next to the existing SIEM delivery calls without changing SIEM logic or existing webhook handoff formats.
- Phase approval-needed notification is triggered after assessment-chain advancement when the chain enters `pending_phase_approval`.

## Validation

- `python3 scripts/validate_backlog_tasks.py` passed before implementation and after implementation.
- `python3 -m py_compile api/app/services/notification_delivery.py workers/orchestration/tasks.py api/app/services/settings.py api/app/config.py api/tests/test_notification_delivery.py` passed.
- `node --input-type=module --check < ui/assets/modules/settings.js` passed.
- `source .venv/bin/activate && python -m pytest api/tests/test_notification_delivery.py api/tests/test_settings.py -q` passed.
- `source .venv/bin/activate && python -m pytest ui/tests/test_operator_console_smoke_e2e.py::test_settings_collapsed_sections_show_status_summaries_and_still_toggle -q` passed.
- Required `source .venv/bin/activate && python -m pytest api/tests/ -q` passed with warnings only from existing Alembic deprecation notices.
- Full `source .venv/bin/activate && python -m pytest ui/tests/test_operator_console_smoke_e2e.py -q` passed as extra UI coverage.
- `git diff --check` passed before task-close documentation.

## Safe Acceptance

- `http://127.0.0.1:8000` was relevant for Settings/browser validation, but it served stale code: `/api/v1/settings` did not include the new SMTP or phase approval notification settings.
- Current-code acceptance used temporary local port `8023` with an isolated SQLite database.
- Temporary `/health/live` returned `status=ok`, `runtime_state=healthy`, and `public_base_url=http://127.0.0.1:8023`.
- Browser/API acceptance on `8023` returned:

```json
{
  "api_configured": {
    "phase_approval": true,
    "slack": true,
    "smtp_password": true,
    "teams": true
  },
  "base": "http://127.0.0.1:8023",
  "browser_fields_visible": true,
  "patch_status": 200,
  "secret_plaintext_absent": true,
  "summary": "Alerts: email/Slack/Teams \u00b7 completion on"
}
```

## Boundaries

- No SIEM push logic changed.
- No existing webhook handoff format changed.
- No finding severity model changed.
- No live external target, Gruyere, WebGoat, customer, or public internet scan was run.
- No runtime self-modification, uncontrolled plugin install, scope bypass, ROE bypass, approval bypass, deployment bypass, runtime-binding bypass, credential bypass, or kill-switch bypass was introduced.

## Remaining Risks

- Real SMTP, Slack, and Teams delivery depends on operator-provided reachable endpoints and network egress.
- The acceptance proof used mock/local webhook and SMTP verification, not a real enterprise mail/chat tenant.
- The already-running `:8000` process remains stale relative to this build-lane commit until explicitly restarted or redeployed outside this task.
