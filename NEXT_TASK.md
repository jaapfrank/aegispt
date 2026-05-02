# Active Task

## Title

Settings accordion: add one-line summary text to collapsed sections so operators know what each section contains

## Promoted From

`codex/tasks/backlog-176-settings-accordion-section-summaries.json`

## Goal

Add concise status or description text to collapsed Settings accordion headers so operators can identify configured versus unconfigured sections without opening every panel.

## Scope

Implement the active backlog package `codex/tasks/backlog-176-settings-accordion-section-summaries.json`.

Expected slice:

- update Settings accordion header rendering in `ui/assets/modules/settings.js`
- show one-line section summary/status text for each collapsible Settings section
- prefer actual configured state where it is available in existing JS settings state
- use brief descriptive text for unconfigured sections
- preserve expand/collapse behavior

## Constraints

- Keep Prompt 1 and Prompt 2 intact.
- Do not bypass approval gates, pack registry, validation, deployment, or runtime binding.
- No runtime self-modification.
- Do not install uncontrolled plugins.
- Only add summary/status text to collapsed Settings section headers.
- Do not redesign Settings layout.
- Do not add new settings fields.
- Do not change Settings data model, backend settings API, or Settings save/load logic.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `source .venv/bin/activate && python -m pytest api/tests/test_health.py -q`
- `git diff --check`
- Focused Settings UI/E2E coverage proving collapsed section summaries and expand/collapse behavior
- Browser/safe acceptance where relevant

## Acceptance

- All collapsed Settings panels show a one-line status or description.
- Status text reflects actual configured state where available.
- Unconfigured sections show brief control descriptions.
- Expanding/collapsing sections still works as before.
- No Settings E2E regressions.
