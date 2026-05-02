# Active Task

## Title

Replace editable actor text input in topbar with a proper identity display pill

## Promoted From

`codex/tasks/backlog-170-actor-input-identity-display.json`

## Goal

Replace the live-editable topbar actor input with a read-only identity display while keeping actor identity changes routed through Settings.

## Scope

Implement the active backlog package `codex/tasks/backlog-170-actor-input-identity-display.json`.

Expected slice:

- find the topbar actor input/display path in `ui/index.html`, `ui/assets/app.js`, or `ui/assets/modules/settings.js`
- replace the topbar editable actor input with read-only actor name and role display
- make the avatar initial reflect the current actor name instead of a hardcoded value
- preserve actor persistence and x_actor_fallback behavior
- route operator-visible actor-name changes through Settings > Instance / shell identity

## Constraints

- Keep Prompt 1 and Prompt 2 intact.
- Do not bypass approval gates, pack registry, validation, deployment, or runtime binding.
- No runtime self-modification.
- Do not install uncontrolled plugins.
- Do not implement full authentication/login or RBAC backend enforcement.
- Do not change approval gate logic.
- Do not remove the API actor header mechanism.
- Do not make the topbar actor area editable.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `source .venv/bin/activate && python -m pytest api/tests/test_health.py -q`
- `git diff --check`
- Focused UI/E2E coverage proving no topbar actor input remains and the read-only display/role badge/avatar initial render correctly
- Settings coverage proving actor name can be changed from Settings > Instance / shell identity and the topbar updates
- Actor-dependent approval gate regression coverage where relevant
- Browser/safe acceptance where relevant

## Acceptance

- No `<input>` element remains in the topbar actor area.
- Topbar actor name and role badge are readable, non-editable, and correct.
- Avatar initial updates from the current actor name.
- Actor name remains changeable from Settings > Instance / shell identity.
- x_actor_fallback and actor-dependent approval gate behavior do not regress.
