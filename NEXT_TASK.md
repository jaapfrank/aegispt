# Active Task

> **Read FIRST:** [`ANTI_DRIFT.md`](ANTI_DRIFT.md) (repo root) — 5 hard rules + pre-commit checklist + strenger DONE-definitie. Vanaf 2026-05-20 verplicht voor ELKE capability-task. Overschrijft SESSION_PROMPT §5.
>
> **Read SECOND:** [`SESSION_PROMPT.md`](SESSION_PROMPT.md) — kickoff discipline voor AegisPT sessies.

## Title

Observability stack — OpenTelemetry + Langfuse instrumentation (TRACING ONLY, no agent logic changes) — **Sprint mythos-exploitation-foundation, task 1 of 15**

## Goal

Instrument every picker call, runner dispatch, memory operation, validator decision, and tool execution with OpenTelemetry traces sent to Langfuse. **Per Codex refinement: TRACING ONLY** — zero changes to agent logic, dispatch, or runner behavior in this task. Establishes the cockpit's speedometer before subsequent tasks build the engine.

## Sprint context

Deze taak is task 1 van 15 in sprint `mythos-exploitation-foundation`, opvolger van `mythos-foundation` na empirische drift (10 commits + 24 claude_picks + 6 high+crit findings MAAR 0 chain_findings + 0 daadwerkelijke penetraties op 5 real-world targets).

Per [Codex review 2026-05-20](docs/) + user feedback: 6-layer architectuur (Governance / Coordinator / Attack State / Memory+Knowledge / Primitives + cross-cutting Evaluation Gates). Deze task implementeert de Evaluation Gates observability laag.

Per [ANTI_DRIFT.md](ANTI_DRIFT.md) Rule 1: dit task is GEEN capability task; delta-metric is observational (% van agent decisions met traceable rationale, target ≥90%).

## Delta-doelstelling (verplicht per SESSION_PROMPT §1)

> Deze task verhoogt **traceable_agent_decisions** van 0% (huidige staat — geen OTEL) naar **≥90%** binnen een 20-advance test run. Tweede metric: **untraced agent decisions count** → **0**. Live verificatie via Langfuse trace view.

## Scope

Drie ADDITIEVE code changes (zero behavioral changes per ANTI_DRIFT Rule 2):

1. `pip install opentelemetry-api opentelemetry-sdk opentelemetry-instrumentation-fastapi opentelemetry-instrumentation-sqlalchemy langfuse` toegevoegd aan `api/requirements.txt` + `workers/requirements.txt`
2. Nieuwe `api/app/observability/tracing.py` module die OTEL TracerProvider initialiseert met Langfuse OTLP exporter (env vars LANGFUSE_HOST + LANGFUSE_PUBLIC_KEY + LANGFUSE_SECRET_KEY)
3. Decorator-based instrumentation alleen op boundaries:
   - `@traced('picker.advance')` op `advance_assessment_loop`
   - `@traced('picker.claude_call')` op `_claude_select_next_action`
   - `@traced('runner.dispatch')` op `dispatch_runner`
   - `@traced('memory.read'/'memory.write')` op memory_backend public functions

Elke trace draagt span attributes: `run_id`, `task_id`, `engagement_id`. Cost/latency tokens automatisch capture'd uit Anthropic SDK response metadata.

## Constraints (per task package + ANTI_DRIFT.md)

- **TRACING ONLY** — NUL changes aan agent logic, dispatch, runner behavior, prompts, decision-making code paths
- **Per ANTI_DRIFT Rule 2 (no dead code)**: decorator op functie = invoked vanaf eerste API call → satisfied
- **Per ANTI_DRIFT Rule 3 (no backward-compat creep)**: pure additive; geen oude code te vervangen
- **No secrets in traces**: redact target URLs / response bodies / credentials
- **Graceful degradation**: Langfuse down → app continues normally (NO impact on agent runtime)
- Active task gate: ANTI_DRIFT.md + SESSION_PROMPT.md geladen als session context

## Source Package

`codex/tasks/backlog-407-observability-stack-otel-langfuse.json`

## Validation (per ANTI_DRIFT.md sectie "Pre-commit checklist")

Vóór DONE-commit verplicht ingevuld in commit message:

```
- [ ] Mijn code is INVOKED in production path (call site: assessment_loop.py:<line>, workers/orchestration/tasks.py:<line>)
- [ ] Delta-metric bewoog: traceable_agent_decisions van 0% naar X% in 20-advance test
- [ ] Removed code I replaced: no removal needed (additive only — verified via git diff --stat)
- [ ] Geen scope creep: alle changes binnen scope (decorator additions + new tracing module + requirements.txt)
- [ ] Follow-ups gefiled voor blocked items: <refs OR "none">
- [ ] Live test geslaagd: <link to Langfuse trace tree OR OTLP collector log>
```

Plus standard checks:

- `python3 scripts/validate_backlog_tasks.py`
- `.venv/bin/pytest api/tests/test_observability_tracing.py`
- `python3 -m compileall -q api workers`
- `.venv/bin/ruff check api/app/observability/tracing.py`
- `.venv/bin/pytest tests/test_multi_target_validation_grep_guard.py`
- `git diff --check`
- `git diff --stat api/app/services/assessment_loop.py workers/orchestration/tasks.py api/app/services/memory_backend.py` → moet additive-only show (sentinel)
