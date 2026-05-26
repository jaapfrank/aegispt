# OpenAI Agents SDK vs AegisPT — feature-by-feature comparison

Date: 2026-05-26
Goal: prove or disprove that AegisPT's hand-built agentic core is at least as good as the OpenAI Agents SDK primitives, and surface concrete improvements we should adopt regardless of whether we ever migrate.

Sources read:
- [Agent class API](https://openai.github.io/openai-agents-python/agents/)
- [Handoffs](https://openai.github.io/openai-agents-python/handoffs/)
- [Guardrails](https://openai.github.io/openai-agents-python/guardrails/)
- [Tracing](https://openai.github.io/openai-agents-python/tracing/)

## Verdict summary

| Area | SDK has | AegisPT has | Verdict |
|---|---|---|---|
| Static system prompt | yes | yes | parity |
| Dynamic instructions (callable receives context) | yes | **NO** | **GAP** |
| Per-agent model_settings (temperature, top_p, tool_choice) | yes | provider per RUN, not per specialist | **GAP** |
| Output structured type | Pydantic auto-strict | JSON schema dict | parity |
| Tools (function-call) | yes | yes (runner registry) | parity |
| MCP server integration | yes | **NO** | **GAP** (planned via HexStrike note) |
| Lifecycle hooks (on_agent_start/end, on_llm_start/end, on_tool_start/end, on_handoff) | yes | **NO** structured hooks | **GAP** |
| Tool use behavior (run_llm_again / stop_on_first_tool / StopAtTools) | yes | sequential-dispatch only | different pattern |
| Handoff with full conversation transfer | yes | partial (script_critic dispatch) | **PARTIAL** |
| Handoff filtered/summarised (nest_handoff_history) | yes (beta) | **NO** | **GAP** |
| LLM-decides-when-to-handoff | yes (handoff as a tool call) | **NO** (operator-code decides) | **GAP** |
| Input guardrails (decorator + tripwire) | yes | `_scan_for_prompt_injection` (silent filter, no tripwire) | **GAP on tripwire** |
| Output guardrails (decorator + tripwire) | yes | M2 verdict gate (filter, no tripwire) | **GAP on tripwire** |
| Tool input/output guardrails (per-tool) | yes | **NO** | **GAP** |
| Built-in guardrails (PII, prompt injection, brand safety) | NONE in SDK | partial (`_scan_for_prompt_injection`) | **WE LEAD** |
| Sessions (conversation history mgmt within one run) | yes | `loop_state.iterations` + `hypothesis_queue` | parity |
| Sessions cross-run (semantic recall of prior episodes) | **NO** | **YES (M5 recall)** | **WE LEAD** |
| Tracing -- typed spans (agent/llm/tool/handoff/guardrail) | yes | OTEL spans (generic) + PROOF_EXEC markers (handmade) | **GAP on typed spans** |
| Tracing -- custom_span context manager | yes | partial (OTEL `with tracer.start_as_current_span(...)`) | parity-ish |
| Tracing -- backend dashboard | OpenAI Traces (auto) | OTEL collector required | parity-ish |
| Multi-provider support | OpenAI only | Claude + ChatGPT-OAuth + Gemini + local-qwen | **WE LEAD** |

## Honest scoring

- **GAPS where SDK is better**: 8 items (dynamic instructions, per-agent model_settings, MCP, lifecycle hooks, handoff filters, LLM-driven handoffs, tripwire pattern, per-tool guardrails, typed spans).
- **PARITY**: 5 items.
- **WHERE WE LEAD**: 3 items (cross-run M5 recall, partial built-in injection guardrail, multi-provider support).

If we count by structural primitive impact:
- SDK ahead on **dev ergonomics** (cleaner abstractions, less boilerplate).
- AegisPT ahead on **operational reach** (multi-provider, cross-run memory).

We are NOT clearly worse. We are differently optimised: SDK for "build an agent fast on OpenAI", us for "multi-provider production pentest with audit trail".

## Concrete improvements to adopt WITHOUT migrating

Ordered by ROI (impact / effort):

### A1 -- Dynamic instructions (low effort, medium impact)

Replace static `VULN_XSS_PROMPT = "..."` with a callable that takes `(run_context) -> str`. Lets us inject per-run hints (e.g. "CPG surfaced phantomjs import; lean into headless-callback hypothesis") without post-hoc string concatenation in the orchestrator.

Concrete change: `picker_specialists/vuln_*.py` exports both `VULN_*_PROMPT` (constant) and `vuln_*_prompt(ctx)` (callable). The orchestrator picks the callable when present, falls back to the constant. ~30 lines per specialist; no behaviour change for callers that don't use the callable.

### A2 -- Tripwire-exception guardrail pattern (low effort, medium impact)

Today `_scan_for_prompt_injection` returns silently-redacted text. A debugger seeing "REDACTED" mid-prompt has no easy way to tell whether (a) the target said REDACTED literally or (b) the guardrail tripped. SDK's exception pattern (`InputGuardrailTripwireTriggered`) is loud-by-default.

Concrete change: when redaction count > 0, log a `PROOF_EXEC_GUARDRAIL_TRIPWIRE_2026052616` marker AND raise an in-process structured event. Caller can decide to propagate or swallow. ~15 lines in `_scan_for_prompt_injection` + 1 catch site at the caller.

### A3 -- Typed OTEL spans (low effort, medium impact)

Our OTEL spans are generic. Filtering "all LLM calls" vs "all tool calls" in the trace dashboard requires per-call attribute parsing. SDK's typed spans (agent_span vs generation_span vs function_span vs handoff_span vs guardrail_span) make this filter free.

Concrete change: extend our existing OTEL helper to set `span.kind` attribute via a small enum (AGENT_RUN / LLM_CALL / TOOL_CALL / HANDOFF / GUARDRAIL). ~5 lines per call site, ~10 call sites total.

### A4 -- LLM-driven handoffs (high effort, high impact)

Today the operator-code decides "if CEA fails, dispatch script_critic". The LLM never says "I want to hand off to vuln_xss now". SDK exposes handoff as a tool the LLM can call, which lets the model itself express "this is outside my lane, transfer please".

Concrete change: expose `handoff_to_<specialist>` as a tool in the orchestrator schema. Add an `on_handoff` callback that mirrors today's dispatch path. Add an `input_filter` that drops the lower-quality earlier-iteration context (analog to SDK's `nest_handoff_history`). HIGH effort because the orchestrator + scope-guard + dedup logic all need a new entry point. Would justify a dedicated M-item (file as **M12 LLM-driven handoffs** in beat-shannon-pro roadmap).

### A5 -- Per-agent model_settings (low effort, medium impact)

`vuln_xss` might benefit from `temperature=0.1` (deterministic XSS payloads) while `vuln_authz` benefits from `temperature=0.7` (creative privilege-escalation chains). Today both use the same default.

Concrete change: each specialist module exports an optional `MODEL_SETTINGS = {"temperature": 0.1, ...}` dict; orchestrator merges into the LLM call. Per-specialist tuning becomes a 1-line edit. ~10 lines orchestrator-side + per-spec entries as needed.

### A6 -- Per-tool input/output guardrails (medium effort, medium impact)

Runners ingest raw target stdout/stderr without per-tool validation. SDK's per-tool guardrails would catch e.g. a runner that returns 50MB of stdout (out-of-band attack) before findings extraction. Today an extractor crash on oversized input would silently lose the whole task's evidence.

Concrete change: add a `tool_output_guardrail` hook in `workers/orchestration/findings.py:extract_findings` that pre-validates `artifact.data` size, encoding, and presence of expected markers. Raise `ToolOutputTripwire` to skip with a clean log line. ~30 lines.

### A7 -- MCP server integration (medium effort, high long-term impact)

We deferred this in the HexStrike note. Re-noting here: SDK's `mcp_servers` parameter lets the agent receive MCP-exposed tools as if they were local. Adopting MCP would let us reach HexStrike's 150+ tool catalog without rewriting each runner.

Concrete change: file as a separate research/design doc, not action this session.

## What NOT to copy

- **SDK's "sessions" abstraction within a single run**: we already have `loop_state.iterations` + `hypothesis_queue` which serve the same purpose with more pentest-specific structure (per-hypothesis state machine). Don't replace.
- **OpenAI-only model coupling**: would lose Claude + Gemini + local-qwen support we built. Net negative.
- **Built-in trace dashboard going to OpenAI**: data-leak risk for client engagements. Stay on local OTEL collector.

## Decision

Land A1 + A2 + A3 in a follow-up sprint as small, additive PRs. Defer A4 (LLM-driven handoffs) to a proper M-item (**M12**) on the beat-shannon-pro roadmap. Defer A5/A6/A7 until A1-A3 prove the pattern.

**We are NOT migrating to the SDK.** We are adopting 3 specific patterns the SDK does well; we keep our 3 leads (multi-provider, cross-run M5, OTEL).
