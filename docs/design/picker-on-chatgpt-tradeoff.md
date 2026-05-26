# Picker on ChatGPT (subscription) — trade-off notes

**Operator question 2026-05-21:** "werken deze [subagents] op claude of chatgpt?
Aangezien ik deze het liefste op chatgpt heb die nu al is aangemaakt in het
systeem. Dus niet via de api maar via mijn abonnement. Dat wil ik misschien
straks ook veranderen voor de ai die de nieuwe taken enzo kiest."

This document captures what is involved in moving the picker (and optionally
the subagents) from the Anthropic API to a ChatGPT-subscription OAuth path.
**Status 2026-05-21:** the picker now has a ChatGPT-OAuth provider branch
for configured runs. This only enables the governed provider path; it does
not prove ChatGPT makes better decisions.

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
`api/app/services/assessment_loop.py:_claude_select_next_action`. Anthropic
runs still use `client.messages.create(model="claude-opus-4-7", ...)`;
ChatGPT-OAuth configured runs now route through
`send_chatgpt_backend_streaming_json_request`.

The infrastructure for ChatGPT-via-subscription already exists:
- `api/app/services/chatgpt_oauth.py` — OAuth flow against ChatGPT,
  reuses the operator's browser session cookies
- `api/app/services/ai_signal_stream.py` — already routes through
  ChatGPT for the narrator panel today

So switching the **picker** to ChatGPT-subscription is plausible IF we
accept the trade-offs below.

## What you'd lose by switching the picker to ChatGPT

**Correction 2026-05-21**: operator noted that the OAuth path proxies to
OpenAI's backend (GPT-5/5.5 family) which DOES support structured outputs.
Earlier draft of this doc was wrong on that point. The actual
`send_chatgpt_backend_streaming_json_request` helper in
`api/app/services/chatgpt_oauth.py:446` is wired specifically for the
structured-JSON streaming case. So this is a smaller gap than first
written.

| Anthropic now | ChatGPT-via-OAuth (corrected) |
|---|---|
| Native structured outputs via `output_config.format.json_schema` | Existing OAuth helper parses streamed JSON text; backlog-436 embeds the same picker schema into the instructions and decodes the returned JSON object |
| Cached system prompt at ephemeral cache for cost reduction | Subscription is a flat fee, so per-call caching is less critical |
| `tools=` parameter for agent_tools (bash, code_exec, web_fetch) at the Anthropic API surface | OpenAI's "tool calling" surface is equivalent BUT the existing backend wrapper doesn't yet expose it — would need wrapper extension |
| Stable model identifier (`claude-opus-4-7`) under our control | Subscription model can change but it's the model the operator already chose |
| `not`/`enum` JSON schema keywords | OpenAI accepts `enum`; `not` support varies by API version (same caveat as Anthropic per our ced6030 regression) |
| Configurable reasoning depth (Anthropic's `thinking` field) | **Supported** on `/codex/responses` via `reasoning: {effort: low\|medium\|high}` — operator-corrected 2026-05-22 after pushback ("OpenClaw works fine on OAuth"). Earlier "NOT supported" claim was based on flaky A/B with concurrent traffic; isolated tests with gpt-5.4 + effort=high return 200 OK on both small payloads AND 24KB picker prompt. The real cost is latency: effort=high adds ~60-120s per call, which exceeds the harness's 180s default httpx timeout (now bumped to 600s) and risks busting any synchronous picker budget. Default lowered to `low` to balance reasoning gain vs latency. |

## Empirical A/B 2026-05-22 (XBEN-002-24)

### v4 (2026-05-22 morning, BEFORE bug fixes)

Same docker challenge, same scope, ran serially:

```
                       Claude opus-4-7     ChatGPT gpt-5.4 (OAuth, no reasoning)
findings:                   22                    2
exec_plan ok/disp:         20/20                 29/29
loop iterations:             3                    9
run_status:              completed         completed_with_errors
time:                      390 s                 689 s
```

Reading: ChatGPT-OAuth dispatched MORE exec_plans (29 vs 20, all
successful) but its plans produced FEWER findings (2 vs 22). At the time
I (Claude opus 4.7) concluded the OAuth surface was "materially weaker."

### Operator pushback 2026-05-22 ("OpenClaw works fine on OAuth")

The operator caught the premature conclusion. Re-investigation revealed:

1. **Reasoning IS supported** on `/codex/responses`. Earlier 400s came
   from flaky concurrent A/B runs, not from `reasoning: {effort}`.
   Isolated tests with gpt-5.4 + effort=high return 200 OK on both small
   payloads AND the 24KB picker prompt.

2. **The v4 ChatGPT-OAuth A/B never actually used ChatGPT for the
   picker.** `LLMProviderConfig.for_model("chatgpt-oauth")` (hyphen)
   was a key miss — the KNOWN_PROVIDERS dict only had `"chatgpt_oauth"`
   (underscore). `for_model` logged "unknown model — falling back to
   claude-opus-4-7" and the picker silently ran Claude instead.
   v6/v7 picker-side calls to chatgpt.com were narrator panels, not
   picker decisions. The 2-findings result above is **not** a ChatGPT
   picker capability signal — it's a Claude picker running with
   ChatGPT-narrator side-channel.

3. **Harness outer httpx.Client timeout** was 180s — too short when the
   picker holds a worker thread on a slow path. Any non-iterate harness
   request (register_run, dispatch, grant_required_approvals) could
   raise httpx.ReadTimeout at 180s with `loop_iterations=0`.

Fixes applied 2026-05-22:
- `api/app/services/llm_provider.py:74` — add `"chatgpt-oauth"` (hyphen
  variant) to KNOWN_PROVIDERS so the harness's `--llm-provider chatgpt-oauth`
  flag actually routes to the OAuth picker branch.
- `api/app/config.py` — default `chatgpt_oauth_reasoning_effort` lowered
  from `"high"` to `"low"` to keep per-call latency under ~30s.
- `scripts/xbow_benchmark.py:542` — outer httpx.Client default timeout
  bumped 180→600s to match the iterate-call override and tolerate slow
  picker paths.

### v8 (POST bug fixes) — fair A/B on XBEN-002-24

Same docker challenge, same harness config (`autonomous-web` profile,
`wait_seconds=900`, `poll_interval=5`, harness client timeout 600s).
Provider routed correctly to ChatGPT-OAuth via the new `chatgpt-oauth`
KNOWN_PROVIDERS key. Reasoning effort=`low`. Run serially:

```text
                       Claude opus-4-7     ChatGPT gpt-5.4 (OAuth, effort=low)
findings:                    1                    2
exec_plan ok/disp:         7/7                  37/38
loop iterations:             1                    9
tool chain:                 13                   49
run_status:        completed_with_errors        cancelled (harness 1282s)
stop_reason:           exhausted (Claude)       picker_retry_exhausted
solved (flag found):       NO                     NO
time:                      337 s                1282 s
```

Reading:
- **Neither provider solved XBEN-002-24.** Both surfaced findings in the
  same families (HTML comment credentials, SQLi, path traversal) but
  could not promote them to the foothold/flag.
- **ChatGPT-OAuth produced 2x more findings and 5x more exec_plans**
  than Claude in this run. Claude's picker emitted `STOP=exhausted`
  after one harness iteration — a Claude-side heuristic, not a
  capability signal.
- **ChatGPT took 4x longer** and used the full harness budget. Each
  picker call lands at ~80-140s; at reasoning=low this is the new floor.
- The v4 comparison (22 vs 2) was contaminated — that v4 "ChatGPT" row
  was actually Claude with a fallback. The corrected v8 numbers show
  ChatGPT-OAuth picker IS competitive on findings, at the cost of
  significantly longer wall-clock and many more dispatches per finding.

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

## Concrete migration steps

1. Done in backlog-436: add a ChatGPT-OAuth branch in
   `_claude_select_next_action` while preserving the Anthropic branch.
2. Still open: add parse-failure/retry metrics if the OAuth branch proves
   noisy in live validation.
3. Next: run the backlog-437 A/B harness in parallel (one batch on Claude,
   one on ChatGPT-OAuth) to compare picker decisions, findings, canary deltas,
   and failure reasons.

## Recommendation (Claude opus 4.7, today)

**Do not switch the default yet.** The branch exists so we can test it
honestly, not so we can assume it is better. Anthropic still has native
tool-use and `output_config` enforcement in this code path. ChatGPT-OAuth now
has a governed JSON decision path, but it still lacks the picker's in-turn
tool-call loop. The next decision should come from the backlog-437 A/B report,
not preference.
