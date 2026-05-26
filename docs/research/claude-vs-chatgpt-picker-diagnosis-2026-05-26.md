# Claude vs ChatGPT-OAuth picker diagnosis — 2026-05-26

## Question

The operator asked why Claude appears to work much better inside AegisPT
than ChatGPT-OAuth.

## Short answer

The current evidence does **not** prove that Claude is intrinsically better
at pentesting in AegisPT. It proves that AegisPT is currently much more
Claude-shaped than ChatGPT-shaped.

Claude gets the mature picker path:

- Anthropic `messages.create` with native `tools=`.
- Native `output_config.format.json_schema`.
- A 12-hop in-turn tool loop.
- Memory, `http_fetch`, and agent tools inside the model turn.
- Context curation before every Claude hop.
- Prompt caching hints on the system prompt.

ChatGPT-OAuth gets the newer, thinner picker path:

- One streamed `/codex/responses` call.
- JSON schema embedded into instructions as text.
- No in-turn tool loop exposed through the wrapper.
- No picker-side memory/http_fetch/agent-tool calls inside the same turn.
- Strict JSON parsing of final output only.
- Much higher current latency risk because `chatgpt_oauth_reasoning_effort`
  is currently set to `xhigh` with a 240s timeout.

That means the observed difference is mostly integration scaffolding and
runtime ergonomics, not a clean model-vs-model result.

## Local evidence

1. `docs/design/picker-on-chatgpt-tradeoff.md` already records that the
   Anthropic path has native tool use while ChatGPT-OAuth does not yet expose
   equivalent picker tool-calls through the wrapper.

2. The corrected A/B note in that file says the earlier "ChatGPT" bad result
   was contaminated: the hyphenated `chatgpt-oauth` provider key missed the
   provider map and silently fell back to Claude.

3. The fairer XBEN-002-24 v8 comparison did **not** solve with either
   provider. ChatGPT-OAuth produced more findings and more exec plans, but
   took roughly 4x longer and eventually exhausted the picker retry budget.

4. `docs/validation/release-gate-mythos-exploitation-foundation.md` says the
   benchmark reality is still `0/25` XBOW solved. So the right framing is not
   "Claude wins"; it is "neither path is solving yet, and the ChatGPT path is
   less mature plus slower."

5. `api/app/services/assessment_loop.py` currently sends Claude through an
   in-turn tool loop with `memory`, scoped `http_fetch`, and optional
   agent-tools. The ChatGPT branch returns before that tool loop and asks for
   one final decision directly.

6. `api/app/config.py` currently defaults ChatGPT-OAuth to `gpt-5.5`,
   reasoning effort `xhigh`, verbosity `low`, and timeout `240.0`. That is a
   recipe for expensive/slow decisions in a synchronous picker loop. Earlier
   notes recommended lower effort for benchmark throughput.

7. `api/app/services/assessment_loop.py` still hard-codes
   `model="claude-opus-4-7"` in the Claude picker call, even after resolving
   provider config. That makes the Claude path stable and predictable, but it
   also means Anthropic model selection is not truly symmetric yet.

## Likely causes ranked

1. **Tool-use asymmetry.** Claude can inspect memory and fetch/read target
   pages before choosing. ChatGPT-OAuth must decide from the prebuilt prompt
   only.

2. **Latency and retry exhaustion.** ChatGPT-OAuth calls are slow under the
   current settings. Slow picker calls consume the harness budget and make the
   system look less competent even when the model is producing more attempts.

3. **Schema enforcement asymmetry.** Claude gets API-level structured output.
   ChatGPT gets a text instruction plus strict post-parse. That is workable,
   but it is less robust.

4. **Configuration drift.** Docs and scripts compare `gpt-5.4` or low/medium
   effort, while current settings use `gpt-5.5` + `xhigh`. A/B results across
   those settings are not directly comparable.

5. **Benchmark score is still zero.** The system's biggest gap is not provider
   choice. It is exploit execution: too few verified exploit chains,
   insufficient source-aware/category-specific exploit agents, and no reliable
   flag/proof capture yet.

## What should happen next

1. Make the ChatGPT picker path structurally equivalent before judging model
   quality:
   - expose OpenAI/ChatGPT tool-calling through the OAuth wrapper, or
   - implement an explicit client-side tool loop around ChatGPT decisions
     matching the Claude loop.

2. Normalize A/B settings:
   - same challenge set,
   - same run profile,
   - same max wall-clock budget,
   - same reasoning budget policy,
   - same picker mode,
   - no narrator/side-channel calls counted as picker calls.

3. Add provider telemetry:
   - per picker call: provider, model, effort, latency, retries, parse failure,
     decision action, selected tool, exec-plan validity, and downstream finding
     delta.

4. Set a benchmark-friendly ChatGPT mode:
   - run one batch with `gpt-5.5` + `medium` or `high`, not `xhigh`;
   - reserve `xhigh` for hard isolated investigations where latency is allowed.

5. Fix exploit-chain capability before over-optimizing model choice:
   - specialist prompts must produce executable hypotheses,
   - exploit-developer output must flow into `exec-plan`,
   - validator must emit replayable PoC evidence,
   - success metric must be `solved`, `verified-exploited`, or flag/proof
     capture, not finding count alone.

## Bottom line

Claude currently comes out better because AegisPT gives Claude a better
operating environment. ChatGPT-OAuth is not getting the same tools, loop
shape, or latency envelope. Do not decide the default provider from the current
setup; first make the integration fair, then run a real XBOW A/B batch.
