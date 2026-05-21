# Picker on ChatGPT (subscription) — trade-off notes

**Operator question 2026-05-21:** "werken deze [subagents] op claude of chatgpt?
Aangezien ik deze het liefste op chatgpt heb die nu al is aangemaakt in het
systeem. Dus niet via de api maar via mijn abonnement. Dat wil ik misschien
straks ook veranderen voor de ai die de nieuwe taken enzo kiest."

This document captures what would be involved in moving the picker (and
optionally the subagents) from the Anthropic API to a ChatGPT-subscription
OAuth path. **Not built today — captured here so the trade-offs are clear
when the decision is made.**

## Two distinct surfaces

### 1. Claude Code subagents (`.claude/agents/*.md`)

`session-bootstrap` and `proof-of-execution` are Claude Code subagents.
They run inside the Claude Code SDK process, are spawned by the parent
Claude assistant via the `Agent` tool, and use the Anthropic API.

**There is no ChatGPT equivalent of this surface.** Claude Code subagents
are bound to Anthropic by design — they're an Anthropic SDK feature. To
get the same kind of context-loading + discipline-enforcing helper on
ChatGPT, we'd need to build something different: a CLI wrapper that calls
ChatGPT-via-OAuth and runs the same prompt. Not impossible, just a
separate build.

### 2. The AegisPT picker (the AI that decides what the robot does next)

This is the high-value path. The picker lives in
`api/app/services/assessment_loop.py:_claude_select_next_action` and is
currently hard-coupled to `client.messages.create(model="claude-opus-4-7", ...)`.

The infrastructure for ChatGPT-via-subscription already exists:
- `api/app/services/chatgpt_oauth.py` — OAuth flow against ChatGPT,
  reuses the operator's browser session cookies
- `api/app/services/ai_signal_stream.py` — already routes through
  ChatGPT for the narrator panel today

So switching the **picker** to ChatGPT-subscription is plausible IF we
accept the trade-offs below.

## What you'd lose by switching the picker to ChatGPT

| Anthropic now | ChatGPT subscription |
|---|---|
| Native structured outputs (`output_config.format.json_schema`) — schema-enum binding catches hallucinated tool names BEFORE they reach our code | OAuth path does not have equivalent native enforcement; we'd parse plain text and risk Claude-style hallucinations slipping through |
| Cached system prompt (~23KB) at ephemeral cache for cost reduction | Browser-OAuth path has no equivalent cache control |
| `tools=` parameter for agent_tools (bash, code_exec, web_fetch) Anthropic-side dispatch | ChatGPT browser path has no tool-use parameter — agent_tools would need to be parsed out of plain-text decisions |
| Stable model identifier (`claude-opus-4-7`) under our control | Subscription-side model can change without us being notified |
| `not`/`enum` keyword constraints in JSON schema | Plain-text parsing fallback only |

## What you'd gain

- **No per-call Anthropic API cost.** Subscription is a fixed monthly fee.
- **Use the model you already pay for** instead of paying twice.
- **Browser session reuse** — same conversation history you already have.

## When this trade-off makes sense

- Cost dominates over capability — you're running enough picker calls per
  day that API tokens exceed your subscription cost.
- The schema-enum / structured-output features have been replaced with a
  robust text parser + retry loop.
- Agent_tools dispatch is done via the `exec-plan` runner with explicit
  HTTP-step grammar (which we have now after d9477b3), so we don't depend
  on the Anthropic `tools=` surface for the picker's reasoning side-channel.

## Concrete migration steps when ready

1. Replace `client.messages.create(...)` in `_claude_select_next_action`
   with a `LLMProvider.chat(...)` call where the underlying provider is
   ChatGPT-OAuth.
2. Replace structured-output enforcement with: prompt asks Claude to emit
   strict JSON, server parses + validates, retries N times on parse failure.
3. Add a parse-failure metric to validation-status.md so degradation is
   visible.
4. Run a 5-challenge XBOW canary in parallel (one batch on Claude, one on
   ChatGPT) to compare findings/iters/picker_retry_exhausted rates.

## Recommendation (Claude opus 4.7, today)

**Don't switch yet.** The system has just landed schema-enum binding
(03e0612), proper exec_plan schema (d9477b3), and the picker forcing
rule (078e9b9). These all rely on Anthropic's structured-output
guarantees. Removing that safety net before the chain is end-to-end
working empirically would set us back. Once the agent_tool / foothold /
validator canaries are reliably moving off 0 — and once we have a robust
plain-text parser that can replicate the schema-enum semantics — the
switch becomes a cost-optimisation move with a known capability cost.
