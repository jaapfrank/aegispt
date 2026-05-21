# Active Task

> **Read FIRST:** [`ANTI_DRIFT.md`](ANTI_DRIFT.md) (repo root) — 5 hard rules + pre-commit checklist + strenger DONE-definitie.
>
> **Read SECOND:** [`SESSION_PROMPT.md`](SESSION_PROMPT.md) — kickoff discipline voor AegisPT sessies.

## Title

Picker A/B comparison harness — Claude vs ChatGPT-OAuth

## Goal

Build an evidence-first harness that compares Claude and ChatGPT-OAuth picker decisions on the same target, same evidence, and same safety constraints, then emits a side-by-side report.

## Delta-doelstelling

The provider-path work from backlog-436 is now structurally enabled. This task measures whether the two picker providers make different decisions on matched evidence. The metric is a generated comparison report with matched picker decision logs, finding counts, canary/proof deltas, and explicit failure reasons. No winner may be claimed without measured comparable results.

## Scope

- Create a controlled validation script that provisions or simulates two comparable runs.
- Configure one run for the Anthropic picker and one run for ChatGPT-OAuth.
- Drive both through the same benchmark, authorized target harness, or dry-run fixture.
- Collect matched picker decision logs, finding counts, canary/proof deltas, and failure reasons.
- Emit a side-by-side report.

## Constraints

- Validation harness only.
- Do not change production picker decision logic.
- Do not change runner behavior, approval gates, scope gates, finding schema, prompt foundations, capability pack registry, approval flow, deployment flow, or runtime binding.
- Dry-run or fixture mode must be available so report generation can be tested without live target access.
- State limitations explicitly; do not infer model superiority from structure-only checks.

## Source Package

`codex/tasks/backlog-437-picker-ab-claude-vs-chatgpt-oauth.json`

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `python3 -m compileall -q api scripts`
- `.venv/bin/ruff check scripts/picker_ab.py`
- `.venv/bin/pytest <focused picker A/B tests>`
- `git diff --check`
