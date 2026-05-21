# Active Task

> **Read FIRST:** [`ANTI_DRIFT.md`](ANTI_DRIFT.md) (repo root) — 5 hard rules + pre-commit checklist + strenger DONE-definitie.
>
> **Read SECOND:** [`SESSION_PROMPT.md`](SESSION_PROMPT.md) — kickoff discipline voor AegisPT sessies.

## Title

Wire ChatGPT-OAuth as a picker provider

## Goal

Extend the picker provider path so a run configured for the existing ChatGPT OAuth backend can request structured picker decisions through the already-governed OAuth streaming JSON helper instead of silently skipping non-Anthropic providers.

## Delta-doelstelling

Picker provider coverage moves from Anthropic-only decision calls to Anthropic plus ChatGPT-OAuth configured runs. The measurable metric is that ChatGPT-OAuth configured picker calls no longer return `None` solely because the provider is non-Anthropic, while Anthropic picker behavior remains unchanged.

## Scope

- Add a provider branch in the picker decision path for ChatGPT-OAuth configured runs.
- Reuse the existing `send_chatgpt_backend_streaming_json_request` helper and the same picker schema/safety boundaries.
- Preserve Anthropic behavior.
- Keep approval, scope, runner, capability pack, finding schema, and runtime binding behavior unchanged.

## Constraints

- Do not implement until explicitly requested.
- No runner behavior, approval gate, scope gate, finding schema, or capability pack flow changes.
- No claim that ChatGPT-OAuth makes better picker decisions; that belongs to the A/B harness task after this one.

## Source Package

`codex/tasks/backlog-436-picker-chatgpt-oauth-provider.json`

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `python3 -m compileall -q api`
- `.venv/bin/ruff check api/app/services/assessment_loop.py api/app/services/chatgpt_oauth.py`
- `.venv/bin/pytest <focused picker/chatgpt oauth tests>`
- `git diff --check`
