# Active Task

> **Read FIRST:** [`ANTI_DRIFT.md`](ANTI_DRIFT.md) (repo root) — 5 hard rules + pre-commit checklist + strenger DONE-definitie. Overschrijft SESSION_PROMPT §5.
>
> **Read SECOND:** [`SESSION_PROMPT.md`](SESSION_PROMPT.md) — kickoff discipline voor AegisPT sessies.

## Title

Exploit Developer agent + meta-tooling (runtime custom script generation) — **Sprint mythos-exploitation-foundation, task 8 of 15**

## Goal

Per Codex 6-layer architectuur Layer 4: a dedicated agent (separate prompt from the picker) whose ONLY job is to compose multi-step exploit recipes (Python-style or exec_plan JSON) when the picker hits a hypothesis that no generic runner covers. The agent owns the recipe + expected_markers pair so backlog-413's deterministic validator can verify the result and backlog-413's PoC artifact generator can emit a runnable script.

## Sprint context

Task 8 van 15 in sprint `mythos-exploitation-foundation`. backlog-413 DONE — validator + PoC ready; foothold transitions gated on validator verdict. The bottleneck for flag capture has consistently been: picker recognizes "I should exploit this" but exec_plan is one-shot and doesn't compose multi-step payload chains. backlog-414 adds the dedicated exploit-developer agent that builds those chains end-to-end with `expected_markers` so validator can verify.

## Delta-doelstelling (verplicht per SESSION_PROMPT §1)

> Deze task levert `api/app/services/exploit_developer.py` met `compose_exploit_recipe(finding, target_context)` die een multi-step recipe genereert met `expected_markers`. Een nieuwe `exploit-developer-agent` runner-tool (`workers/runners/exploit_developer_agent/`) zodat de picker hem expliciet kan picken. Delta-metric: ≥1 XBOW challenge produceert een verified-exploited finding via een door dit agent gegenereerd recipe — gevalideerd door backlog-413's `validate_exploit`.

## Scope

(1) `api/app/services/exploit_developer.py`:
- `compose_exploit_recipe(finding, target_context, hypothesis)` — calls a Claude-Opus-4.7 prompt SPECIFIC to multi-step exploit composition (separate system prompt from the picker; tighter scope).
- Output structure: `{steps: [...], expected_markers: [...], target: "...", rationale: "..."}`. Same shape `validate_exploit` consumes.
- The agent has access ONLY to the captured context (request/response history, target URL, finding title/severity) — no arbitrary http_fetch (that's the picker's tool).

(2) New runner `workers/runners/exploit_developer_agent/runner.py`:
- Wraps `compose_exploit_recipe` in the standard `RunnerExecution` contract.
- Dispatches the produced recipe through the existing `exec_plan` runner so the validator can verify.
- Emits a finding with `replay_recipe_json` populated so backlog-413 can verify + build_executable_poc.

(3) Picker prompt gains an explicit recommendation: when the picker reaches a hypothesis that needs ≥3 chained steps, pick `exploit-developer-agent` instead of writing inline exec_plan JSON.

(4) Tests `api/tests/test_exploit_developer.py`:
- Schema validation of generated recipes.
- Roundtrip: developer-agent recipe → validator verdict (mocked transport).
- Picker prompt grep-sentinel that the new tool name appears in the system prompt.

## Constraints (per ANTI_DRIFT.md)

- Per Rule 1: capability task. Delta-metric = "≥1 verified-exploited finding emitted via exploit-developer-agent during a live XBOW run".
- Per Rule 2: runner registered + dispatchable; picker prompt invites it.
- Per Rule 3: where the picker previously inlined multi-step exec_plan, those calls move to the new agent. Cite diff.
- Per Rule 4: live verification via XBOW — ≥1 verified-exploited finding traced end-to-end.
- Per `feedback_no_prescriptive_recipes`: the agent generates recipes emergently from observed context, not from pre-seeded per-app templates.

## Source Package

`codex/tasks/backlog-414-exploit-developer-agent-meta-tooling.json`

## Validation (ANTI_DRIFT.md pre-commit checklist)

- [ ] Code INVOKED: exploit-developer-agent dispatch in live XBOW advance
- [ ] Delta-metric: ≥1 verified-exploited finding (validator verdict) via this agent
- [ ] Removed code: cite inline multi-step exec_plan paths that moved to agent
- [ ] Geen scope creep: developer agent + runner + 1 picker-prompt section + tests
- [ ] Follow-ups gefiled: <refs OR "none">
- [ ] Live test geslaagd: link/trace to verified-exploited finding

Plus required checks:
- `python3 scripts/validate_backlog_tasks.py`
- `.venv/bin/pytest api/tests/test_exploit_developer.py`
- `python3 -m compileall -q api workers`
- `.venv/bin/ruff check api/app/services/exploit_developer.py workers/runners/exploit_developer_agent/runner.py`
- `git diff --check`
- Live: XBOW run produces ≥1 verified-exploited finding via exploit-developer-agent.
