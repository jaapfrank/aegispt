# Codex UI/Reporting W6A - Live CLI Command Output Repair

Date: 2026-06-03
Owner: Codex

## Operator Problem

The dedicated Live CLI screen still did not feel like following a command
prompt. Captured task output could render as one long structured blob, making
it unclear whether the system was streaming commands, stdout/stderr, or only
showing output when a finding was created.

## Changes

- The Live CLI page now opens the task terminal in full-height mode.
- `LiveTaskDrillDown` now always shows a command-style line for the selected
  task, even when the backend stream does not expose an explicit `$ ...`
  command line.
- Captured structured JSON output is expanded into readable stdout/stderr lines
  instead of one dense wrapped blob.
- Long terminal lines are split at readable boundaries rather than forced into
  hard `break-all` wrapping.
- The terminal distinguishes:
  - command
  - stdout/stderr
  - no captured stdout/stderr yet
  - structured JSON output expanded for readability
- If live SSE is unavailable but persisted execution stdout/stderr is loaded
  from task detail, the terminal status no longer remains stuck as an error.

## Proof

- Screenshot:
  `docs/validation/codex-ui-reporting-w6a-live-cli-command-output-1536x864.png`
- Focused regression:
  `cd ui-v2 && AEGISPT_CAPTURE_LIVE_CLI_COMMAND=1 npx playwright test tests/react-v2-critical-paths.spec.ts -g "Live CLI renders command-style stdout"`
- Full regression:
  `cd ui-v2 && npm test` (28 passed, including i18n key parity)
- Production build:
  `cd ui-v2 && npm run build` (passed; existing Vite chunk-size warning remains)
- Repo checks:
  `python3 scripts/validate_backlog_tasks.py` and `git diff --check`

The screenshot proves a selected `target-intel` task renders as:

- `$ target-intel --target ...`
- labelled `stdout / stderr`
- expanded structured JSON with visible `test_plan` and nested tool data

## Non-Overlap

No Claude score-lane files, `NEXT_TASK.md`, `TASK_QUEUE.md`,
assessment-loop/runtime files, worker runner files, scoring code, or active
XBEN validation artifacts were changed by this repair.
