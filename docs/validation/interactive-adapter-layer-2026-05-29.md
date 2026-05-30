# Interactive exploit runner — provider-agnostic adapter layer (2026-05-29)

Durable record of the work that turned the interactive-exploit runner from
"two hard-coded provider branches" into a **general function-caller**: one
provider-agnostic tool-use loop driving any LLM through a thin adapter.

Convergent direction (operator + codex, 2026-05-29): *don't* add gpt-5.4 as a
loose branch — build a generic adapter layer and add providers as adapters, so
model quality is A/B-tested on the identical loop and there's one place for
scope, logging, score, budgets, transcripts.

## What was built

| Piece | File | Notes |
|---|---|---|
| Generic loop (request→observe→decide) | `workers/runners/interactive_exploit/runner.py` | One loop; provider chosen by a one-line factory call |
| Adapter layer | `workers/runners/interactive_exploit/adapters.py` | `ToolSpec/ToolCall/ToolResult/Turn` + `make_adapter()` |
| Anthropic adapter | adapters.py | native tool-use (`messages.create`) |
| Gemini adapter | adapters.py | native function-calling (`generateContent`) |
| ChatGPT-OAuth (gpt-5.4) adapter | adapters.py | JSON-action over `codex/responses` (engagement-scoped token) |
| **DeepSeek adapter** | adapters.py | **native** OpenAI-compatible function-calling, `DEEPSEEK_API_KEY` |
| Local (Qwen) adapter | adapters.py | JSON-action over `/v1/chat/completions`, strips `<think>` |
| Scope-guard hardening (codex) | runner.py `_allowed_hosts` | empty/non-loopback scope NO LONGER implicitly allows localhost |
| Methodology tag (codex) | runner.py | findings carry `methodology=interactive_exploit` (not code_exec_attack) |
| Telemetry (codex) | runner.py summary | `first_flag_step`, `first_flag_elapsed` |
| Parallel-focused harness | `scripts/focused_interactive_battery.py` | 1 challenge/run, per-challenge focused recon, concurrency, JSONL + grader |

## Empirical evidence — same generic loop, three providers solve the SSRF challenge

| Provider | Model | Result | Steps | Time-to-flag | Source |
|---|---|---|---|---|---|
| Gemini | gemini-3.1-pro-preview | ✅ solved (grader-verified) | 3 | 8.7s | focused harness |
| ChatGPT-OAuth | gpt-5.4 | ✅ solved (grader-verified) | 3 | 28.9s | single runner test |
| Claude | claude-opus-4-8 | ✅ 5/50 in-product earlier (run 86e95a73) | — | — | prior session |

gpt-5.4 is **NOT** cyber_policy-blocked on the exploit prompt — an earlier
"empty output/cyber_policy" reading was a bug in the adapter (it read the wrong
return key; `send_*` returns the *parsed* JSON object). After the fix gpt-5.4
solved in 3 steps.

## Focused battery (Gemini) — JSONL evidence

`scripts/focused_interactive_battery.py --provider gemini-3.1-pro-preview
--budget 120 --concurrency 3 --focus <5 mixed-family ids>`

```
solved=1/5  (ssrf-loopback-metadata: 3 steps, ttf=8.7s, grader-verified)
4× failure_reason=llm_error  — ALL gemini_http_429 "exceeded your current quota"
```

The 4 failures are **Gemini's 250/day free quota exhausting mid-run**, not a
capability failure: ssrf solved cleanly before the quota wall, and the failing
runs returned HTTP 429 on the first/early step. This is a provider-availability
limit, not an architecture limit.

## Honest provider-availability reality (2026-05-29)

| Provider | State | Blocker |
|---|---|---|
| Claude 4.8 | strongest, proven | **credit balance $0** |
| Gemini 3.1 | works, free | **250/day quota exhausted today (429)** |
| gpt-5.4 (ChatGPT-OAuth) | works, high quota | flaky strict-JSON under load; **unofficial** `codex/responses` (codex: build-lane only, needs official fallback) |
| local-qwen | adapter built, graceful when down | **server down** (no launcher found; model file present at `~/.aegispt-tools/models/…IQ3_M.gguf`) |
| **DeepSeek** | **adapter built + ready** | **needs `DEEPSEEK_API_KEY`** — cheap (≪ $1/M vs Opus $15/$75), stable official API, native function-calling |

**Conclusion:** the architecture is provider-agnostic and proven on three
backends, but every currently-wired provider has an availability constraint.
DeepSeek (cheap + stable + native FC) is the clean path to running the focused
battery at scale; it only needs an API key.

## UPDATE — DeepSeek live + codex measurement improvements + recon-lever proof

Operator supplied a `DEEPSEEK_API_KEY` (stored in `~/.aegispt-secrets`).
DeepSeek adapter **live-proven**: native function-calling through the generic
loop solved `ssrf-loopback-metadata` (grader-verified).

Codex measurement improvements applied (runner + adapters):
- **Softer prompt** — "authorized local lab, evidence-first, tool-bound, stop on
  verifier-confirmable proof" (removed "elite penetration tester / exploit"
  framing that trips ChatGPT-OAuth policy and helps nobody).
- **Failure taxonomy** (`Turn.error_category` → runner `stop_reason`):
  `policy_refusal` / `empty_output` / `tool_call_parse_error` / `provider_quota`
  / `transport_error` / `provider_error` vs solve-budget `max_steps` /
  `time_budget` — so model quality is never confused with integration failure.
- **Stop-on-proof** (`stop_on_first_flag`) + hard budgets (`max_steps`,
  `time_budget`, `max_tool_errors`, mandatory scope allowlist).
- Harness gained `--reset-each` (resets lab STATE before each challenge → no
  cross-run state-leakage inflation).

### The solve-rate lever is RECON, not model strength (proven)

| Run (5 mixed-family challenges) | Result |
|---|---|
| DeepSeek-chat, thin recon (routes+notes only) | **1/5** (ssrf only) |
| DeepSeek-**reasoner** (stronger), 2 hard challenges, thin recon | **0/2** → model strength is NOT the lever |
| DeepSeek-chat, **+ source-derived gate-token recon** | **3/5** |
| DeepSeek-chat, source recon + **--reset-each (clean)** | **3/5** (identical — number is real, not state-leaked) |

Source review showed every unsolved challenge gated on a token no model can
guess (`X-Lab-Preview`, `${lab:lookup:flag}`, `X-HTTP-Method-Override:
SUBSCRIBE`, `X-Preview-Principal: admin`, `"roadmap" in q`). The focused recon
had over-corrected from the old 52-token overload and dropped these. Fix: the
harness now extracts **per-challenge** gate facts (custom headers, interpolation
tokens, equality + membership constants, params, body fields) across ALL the
challenge's entrypoint handlers — the same fact-class `pre_recon_source`
produces, scoped per challenge. It surfaces what each endpoint INSPECTS; the
exploit assembly stays emergent (no hand-written recipe).

Clean 3/5: `ssrf` (2 steps/4.3s), `cache-key-header-confusion` (5 steps/10s),
`log-lookup-expression-expansion` (5 steps/8.4s). The remaining 2
(`search-index-acl-drift`, `socket-fallback-channel-smuggling`) have ALL recon
facts but are genuine **multi-step stateful chains** (reindex→search;
negotiate→subscribe→recv).

**reasoner A/B (recon + reset, 16 steps): 0/2 — CANDIDATE multi-step-chain
bottleneck (hypothesis, not a proven ceiling).** DeepSeek-reasoner also failed
both with full gate-token recon present, which points away from a pure recon gap
and away from DeepSeek model strength for these two. But this is NOT a hard
ceiling claim: `socket-fallback-channel-smuggling` showed contradictory results
across runs and is sensitive to lab state-leakage (it only became reproducible
after `--reset-each`), and the sample is 2 challenges on one provider family.
Treat as a hypothesis to test, not a fact. The honest next levers are a frontier
model (Claude 4.8 when credits return) A/B on the identical loop, or explicit
cross-handler state-flow recon (endpoint A mutates state endpoint B reads) — the
latter risks crossing into recipe territory, so prefer the model A/B first.

> Scope/labelling note: the focused harness extracts source-derived gate facts
> from the lab's own source, so these numbers are **source-assisted lab recon**,
> NOT black-box pentest performance. They measure "given good recon, can the
> agent exploit?", which is exactly the recon-lever question.

### Two levers, ranked by proven impact
1. **Recon completeness** — biggest proven lift (1/5 → 3/5). Cheap, honest,
   source-derived. DONE for single-gate challenges.
2. **Model reasoning for multi-step chains** — unproven; both DeepSeek variants
   fail. Needs a frontier-model A/B (Claude) to confirm.

Evidence: `docs/validation/focused-battery-gemini-2026-05-29.jsonl`,
`/tmp/focused_clean.jsonl`, `/tmp/focused_reasoner_multistep.jsonl`.

## Next step

1. Frontier-model A/B (Claude 4.8) on the multi-step chains once credits return,
   on the IDENTICAL loop — measures pure model lift vs DeepSeek.
2. Force structured JSON on the gpt-5.4 path (codex/responses `text.format`
   json_schema) to remove strict-JSON flakiness; consider native Responses
   tool-use (codex's deeper ask) as a follow-up.
3. Bring up the local Qwen server (launcher TBD) to validate the local adapter
   end-to-end.
