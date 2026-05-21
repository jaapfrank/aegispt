# Active Task

> **Read FIRST:** [`ANTI_DRIFT.md`](ANTI_DRIFT.md) (repo root) — 5 hard rules + pre-commit checklist + strenger DONE-definitie. Overschrijft SESSION_PROMPT §5.
>
> **Read SECOND:** [`SESSION_PROMPT.md`](SESSION_PROMPT.md) — kickoff discipline voor AegisPT sessies.

## Title

Multi-LLM abstraction via LiteLLM — provider-agnostic brain (Claude / GPT-4o / Gemini / DeepSeek selectable) — **Sprint mythos-exploitation-foundation, task 11 of 15**

## Goal

Brain becomes provider-agnostic. `_claude_select_next_action` wordt `_picker_select_next_action(provider)`. Default Claude Opus 4.7 (huidige prompts daarvoor getuned), maar Gemini 2.5 / GPT-4o / DeepSeek V3 selecteerbaar per run-config. Klanten kunnen eigen API key voor voorkeurs-provider gebruiken.

## Sprint context

Task 11 van 15. backlog-416 DONE — external knowledge providers ingeladen. Tijd om de LLM-laag zelf provider-agnostisch te maken. LiteLLM is de standaard abstraction in de pentest-AI ruimte (OpenClaw, PentAGI, Cyber-AutoAgent).

## Delta-doelstelling

> Deze task levert `api/app/services/llm_provider.py` met `LLMProvider` interface wrapping LiteLLM + provider-selectie via `run.configuration_json['llm_provider']` (default `claude-opus-4-7`). `_claude_select_next_action` + `exploit_developer.compose_exploit_recipe` + `MetaCoordinator` route door deze abstractie. Delta-metric: XBOW score met non-Claude provider ≥70% van Claude score (sanity check dat abstraction geen signal degradeert).

## Scope

(1) `requirements/base.txt`: add `litellm>=1.50`.

(2) `api/app/services/llm_provider.py`:
- `LLMProviderConfig`: model, api_key_env, temperature, max_tokens.
- `LLMProvider(config)` met `chat(system, messages, output_schema=None, timeout=...)` die LiteLLM aanroept en response naar standaard shape normaliseert (text + tool_calls + usage).
- Standaard providers: `claude-opus-4-7` (huidig), `gpt-4o`, `gemini-2.0-pro`, `deepseek-v3`.
- Default falls back naar Anthropic direct call wanneer LiteLLM niet geinstalleerd (graceful degradation).

(3) Refactor existing direct-anthropic calls in:
- `api/app/services/assessment_loop.py::_claude_select_next_action` (huidige hot path)
- `api/app/services/exploit_developer.py::_claude_compose`
- (workers/runners/target_intel/runner.py reads `ANTHROPIC_API_KEY` directly — that's intentionally separate; consumers can pick to migrate later, not in this slice)

(4) Tests `api/tests/test_llm_provider.py`: provider selection, normalized response shape, LiteLLM-unavailable fallback, OTEL cost telemetry attribute.

## Constraints (per ANTI_DRIFT.md)

- Per Rule 1: capability task. Delta-metric = "non-Claude provider produces ≥70% of Claude XBOW score on identical subset" — sanity, not target.
- Per Rule 2: LLMProvider invoked from at least the picker hot path + exploit_developer in same commit.
- Per Rule 3: old direct `anthropic.Anthropic(...)` calls REMOVED from those two sites — no parallel paths.
- Per Rule 4: live verification — picker call with `llm_provider=claude-opus-4-7` still works end-to-end.
- Per `feedback_no_prescriptive_recipes`: provider abstraction is mechanical; no per-provider prompt forks.

## Source Package

`codex/tasks/backlog-417-multi-llm-abstraction-litellm.json`

## Validation (ANTI_DRIFT.md pre-commit checklist)

- [ ] Code INVOKED: LLMProvider called from picker + exploit_developer
- [ ] Delta-metric: live picker call via LLMProvider succeeds (cite trace)
- [ ] Removed code: direct anthropic.Anthropic() in 2 call sites removed
- [ ] Geen scope creep: provider module + 2 refactored sites + tests + requirements bump
- [ ] Follow-ups gefiled: <refs OR "none">
- [ ] Live test geslaagd: API restart + picker advance via provider

Plus required checks:
- `python3 scripts/validate_backlog_tasks.py`
- `.venv/bin/pytest api/tests/test_llm_provider.py`
- `python3 -m compileall -q api`
- `.venv/bin/ruff check api/app/services/llm_provider.py`
- `git diff --check`
- Live: ≥1 picker advance via LLMProvider in the running batch.
