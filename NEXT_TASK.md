# Active Task

> **Read FIRST:** [`ANTI_DRIFT.md`](ANTI_DRIFT.md) (repo root) — 5 hard rules + pre-commit checklist + strenger DONE-definitie. Overschrijft SESSION_PROMPT §5.
>
> **Read SECOND:** [`SESSION_PROMPT.md`](SESSION_PROMPT.md) — kickoff discipline voor AegisPT sessies.

## Title

Picker becomes real agent — Bash / file / web_search / web_fetch / code_exec / subagent tools (Claude-Code-equivalent) — **Sprint mythos-exploitation-foundation, task 14 of 15**

## Goal

Close de "AegisPT picker IS Mythos" capability gap. Currently picker heeft tool-pick-from-list affordances. Give the picker dezelfde agentic toolset die Claude in interactive sessies heeft: Bash exec (sandboxed via backlog-409 sandbox_runner), file r/w (scope-bounded via backlog-409 GovernanceControlPlane), web_search + web_fetch (read-only), code execution (Python sandbox), subagent spawn (via backlog-415 MetaCoordinator).

Per user: "R&D budget van Mythos heb jij al in je — jij bent Mythos. Same model, different scaffolding."

## Sprint context

Task 14 van 15. Release gate (backlog-419) DONE met empirisch 0/25 baseline; foundation infrastructure is in maar de picker zelf heeft nog steeds beperkte agentic affordances. Deze task geeft de picker de Claude-Code-equivalente toolset zodat de model-capacity die hij heeft echt benut wordt.

## Delta-doelstelling

> Deze task levert `api/app/agents/agent_tools/` met 6 nieuwe tool-use schemas die de picker via de Anthropic Messages API kan aanroepen: BashTool, FileReadTool, FileWriteTool, WebSearchTool, WebFetchTool (uitgebreid t.o.v. bestaande http_fetch), CodeExecTool (Python sandbox), SubagentSpawnTool (delegeert naar MetaCoordinator). Elke tool routes door `GovernanceControlPlane.authorize_*` (Layer 0) + `sandbox_runner` (waar applicable) + emit OTEL spans. Delta-metric: ≥3 XBOW challenges solved via agentic tools (Bash/web/code) — measured by post-417-prompt-population re-baseline.

## Scope

(1) `api/app/agents/agent_tools/`:
- `__init__.py` exports tool registry
- `bash.py`: `BashTool` — wraps `sandbox_runner.run_step_in_sandbox` with a curl-style image; passes through Layer 0 `authorize_external_network` for any network egress.
- `file_io.py`: `FileReadTool` + `FileWriteTool` — scope-bounded under `AEGISPT_MEMORY_ROOT` (matches benchmark-isolation rule from backlog-408).
- `web.py`: `WebSearchTool` (delegates to backlog-416 external_knowledge lookups) + `WebFetchTool` (uses existing http_fetch_backend, extends to JS-rendered pages via playwright_web).
- `code_exec.py`: `CodeExecTool` — Python sandbox via `sandbox_runner` with `python:3.12-slim` image, network=none, 60s timeout.
- `subagent.py`: `SubagentSpawnTool` — wraps `MetaCoordinator.delegate(specialist, ...)`.
- Anthropic tool-use schemas exported as `ALL_TOOL_SCHEMAS` list.

(2) Wire-in `_claude_select_next_action`: pass `ALL_TOOL_SCHEMAS` in `tools=` to the Messages API. Per Layer 0: every tool invocation MUST call `control_plane.authorize_dispatch` (already done for runner dispatch; extend to these agent tools).

(3) Tests `api/tests/test_agent_tools.py`: tool-schema shape validation, Layer 0 enforcement on each tool (deny outside scope), sandbox isolation for Bash/CodeExec.

(4) Picker prompt section explaining the new tools.

## Constraints (per ANTI_DRIFT.md)

- Per Rule 1: capability task. Delta-metric = ≥3 XBOW challenges solved via agentic tools (with PoC artifacts) after this lands + 415-slice-2 + 414-wire-in.
- Per Rule 2: tools called from picker hot path in same commit.
- Per Rule 4: live verification via XBOW re-baseline — ≥1 XBEN run uses Bash/web_fetch tool live + reaches a verified-exploited finding.
- Per `no_runtime_self_modification`: SubagentSpawnTool delegates to existing MetaCoordinator; no new agent-self-rewrite path.
- Per `feedback_no_prescriptive_recipes`: tools are general-purpose primitives, no per-app exploit logic seeded in the tool wrapper.

## Source Package

`codex/tasks/backlog-422-picker-as-real-agent-claude-code-equivalent.json`
