# Active Task

## Title

Email, Slack, and Teams notifications: alert operators on critical findings, phase completions, and run results

## Promoted From

`codex/tasks/backlog-210-email-slack-teams-notification.json`

## Goal

AegisPT has SIEM push and generic webhooks, but enterprise operators still lack first-class email, Slack, and Microsoft Teams notifications for urgent assessment events. Add optional notification delivery for critical findings, run completion, and phase completion / phase-approval-needed events using existing integration and credential-storage patterns.

## Scope

Implement the active backlog package `codex/tasks/backlog-210-email-slack-teams-notification.json`.

Expected slice:

- add email delivery via SMTP for critical findings, run completion, and phase approval-needed events
- add Slack webhook notification delivery for the same events
- add Microsoft Teams webhook delivery using Adaptive Card format
- add Settings configuration surfaces for SMTP, Slack webhook URL, and Teams webhook URL
- keep all notification channels optional so the system works when none are configured
- store credentials/secrets encrypted using the existing Jira/SIEM integration pattern
- trigger from existing event locations without changing SIEM push logic or existing webhook formats

## Constraints

- Do not change SIEM push logic.
- Do not change existing webhook format.
- Do not change finding severity model.
- Keep all channels optional.
- Use existing encrypted credential/integration storage patterns.
- Do not bypass scope, ROE, approval, validation, deployment, runtime binding, credentials, or kill switch.
- No runtime self-modification.
- No uncontrolled plugin installation.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `source .venv/bin/activate && python -m pytest api/tests/ -q`
- `git diff --check`

## Acceptance

- Email alert sends on critical finding with mock SMTP verification.
- Slack webhook is called on critical finding.
- Teams webhook is called on critical finding using Adaptive Card format.
- Run completion and phase-approval-needed events trigger configured channels.
- No crash or failure when no notification channels are configured.
- Credentials are stored encrypted.
- Settings screen exposes email, Slack, and Teams configuration panels.
- Existing tests do not regress.
