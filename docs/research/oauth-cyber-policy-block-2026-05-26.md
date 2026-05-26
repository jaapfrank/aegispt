# OAuth content-policy block on CPG-CEA prompts — 2026-05-26

## What is happening

ChatGPT-OAuth picker fires successfully on light prompts (passive recon
selection: pre-recon-source, pre-recon-cpg, recon-deliverable) but every
heavy `cpg_seeded_cea` prompt returns HTTP 200 OK with an SSE event
stream that ends in `response.failed`. The error payload now surfaces
verbatim in `[chatgpt_oauth.py:570](../../api/app/services/chatgpt_oauth.py#L570)`:

```
error=cyber_policy: This content was flagged for possible cybersecurity risk.
If this seems wrong, try rephrasing your request. To get authorized for
security work, join the Trusted Access for Cyber program:
https://chatgpt.com/cyber
```

Source: smokes 41/42/43/44 (XBEN-002-24 on `chatgpt_oauth` provider,
2026-05-26). 14 fails in smoke 43, 2+ post-restart in smoke 44. Sample:

| Time     | Event counts                                                                | Result |
|----------|------------------------------------------------------------------------------|--------|
| 20:15:51 | response.created:1, in_progress:1, metadata:1, keepalive:1, error:1, response.failed:1 | empty output → ChatGPTOAuthError |
| 20:16:22 | response.created:1, in_progress:1, metadata:1, error:1, response.failed:1   | empty output → ChatGPTOAuthError |

## Why this is a hard block

OpenAI's gpt-5.5 enforces a content-moderation policy ("cyber_policy")
that refuses prompts describing penetration-testing exploitation chains.
The CPG-CEA prompt at
[cpg_seeded_cea_prompts.py](../../api/app/services/assessment_loop_internals/cpg_seeded_cea_prompts.py)
discusses POST to state-changing routes, SQL/file/template/exec sinks,
deserialization gadgets, and headless-browser XSS callbacks — exactly
the language the policy intercepts.

**This is not a code bug.** Confirmed:

- Picker (small prompt) succeeds — 5 picks in smoke 44 between 20:11 and 20:16.
- CPG-CEA (heavy prompt) fails — 2 fails in same window with the same access token.
- Same model (gpt-5.5), same effort (xhigh), same auth → only the prompt
  body differs.

## What works today vs what doesn't on OAuth

| Pipeline component             | OAuth status                                  |
|--------------------------------|-----------------------------------------------|
| Picker `select_next_action`    | Works — recon-tier picks land                 |
| Narrator panels                | Works — comic-strip captions produced         |
| Specialists (vuln_authz, ...)  | Fails — `cyber_policy` on the exploit schema  |
| `cpg_seeded_cea` CEA reasoning | Fails — `cyber_policy` on the exploit prompt  |

XBEN solve-rate via OAuth is therefore capped at whatever recon+picker
alone can find. Smokes 41/42/43/44 all return 1 finding (low-sev info-disclosure
header) and `no-flag`.

## Options ranked by ROI

1. **Wait for Gemini quota reset (~midnight Pacific) and resume Gemini smokes**. Gemini-3.1-pro-preview SOLVED XBEN-002 in 590s (smoke 38). No content-policy block observed on the same heavy prompts. Highest ROI — already proven.

2. **Apply for OpenAI's Trusted Access for Cyber program** (https://chatgpt.com/cyber). Requires operator action; unlocks the policy filter on OAuth. Multi-day approval. Outside agent scope.

3. **Restore Claude credits and resume Claude smokes**. Operator action; outside agent scope.

4. **Soften CPG-CEA prompt language for OAuth-only branch**. Try to bypass moderation by replacing "exploit", "POST to authenticated state-changing route", etc. with neutral vocabulary. Brittle — moderation models are tuned against prompt-engineering bypass — and risks degrading the reasoning quality even when the call succeeds.

5. **Run `--llm-provider local-qwen` (local model)** if it can drive picker + CEA decently. Untested for XBOW solve-rate.

Recommendation: **Option 1** — stop further OAuth smokes today; resume Gemini at quota reset. Without one of options 2/3, OAuth can never drive offensive XBOW work end-to-end.

## What the session's fixes still buy us

The OAuth-path commits this session (13e553f, d500a53, 942f21f) remain
load-bearing the moment Trusted Access (option 2) lands OR a future
model relaxes this policy:

- `response.completed` fallback parser (13e553f) — required for gpt-5.5's `xhigh` reasoning shape.
- `logger` import (d500a53) — was breaking all error paths.
- Error event capture (942f21f) — surfaced this `cyber_policy` reason; without it we would still be debugging an opaque "empty output".

The Gemini-side commit (90da522) saves wall-clock time on the next Gemini quota cycle.
