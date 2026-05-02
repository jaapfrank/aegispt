# Active Task

## Title

Scope 'Complete Assessment Wizard' CTA: only show when there is no active engagement or the wizard is genuinely incomplete

## Promoted From

`codex/tasks/backlog-168-complete-assessment-wizard-cta-scoping.json`

## Goal

Make the `Complete Assessment Wizard` CTA visible only when it is useful, so operators are not pushed back to intake while a mission is already queued, running, or complete.

## Scope

Implement the active backlog package `codex/tasks/backlog-168-complete-assessment-wizard-cta-scoping.json`.

Expected slice:

- find the render condition for the `Complete Assessment Wizard` CTA in `ui/assets/app.js`, `ui/assets/modules/runtime.js`, or `ui/index.html`
- keep the wizard/intake path reachable through the sidebar `Intake` navigation
- keep the CTA visible when no engagement/run exists and the operator needs to start or finish intake
- hide the CTA on Mission Control, Findings, Reports, and History when a run is queued, running, or complete
- avoid redesigning the topbar or navigation structure

## Constraints

- Keep Prompt 1 and Prompt 2 intact.
- Do not bypass approval gates, pack registry, validation, deployment, or runtime binding.
- No runtime self-modification.
- Do not install uncontrolled plugins.
- Do not change wizard step logic.
- Do not change run dispatch or cancellation.
- Do not change backend APIs.
- Do not redesign the topbar or navigation.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `source .venv/bin/activate && python -m pytest api/tests/test_health.py -q`
- `git diff --check`
- Focused UI/E2E coverage proving the CTA visibility is scoped correctly
- Browser/safe acceptance where relevant

## Acceptance

- With an active queued or running run, the CTA is hidden on Mission Control, Findings, Reports, and History.
- With no engagements or no runs, the CTA is visible on Dashboard and the Wizard screen.
- The wizard remains reachable via sidebar `Intake` navigation regardless of CTA visibility.
- No regression in wizard flow tests.
