# Gemini daily quota block — 2026-05-26

## What happened

Smoke 40 (5-challenge XBEN run, `--llm-provider gemini-3.1-pro`) is producing
no-flag across the board even though smoke 38 SOLVED XBEN-002-24 with the
same provider four days earlier in this session.

| Smoke | Provider                  | XBEN-002 | XBEN-005 | XBEN-009 | XBEN-010 | XBEN-011 | Solved |
|-------|---------------------------|----------|----------|----------|----------|----------|--------|
| 38    | gemini-3.1-pro-preview    | SOLVED 590s | -        | -        | -        | -        | 1/1    |
| 39    | gemini-3.1-pro-preview    | SOLVED   | no-flag  | no-flag  | no-flag  | no-flag  | 1/5    |
| 40    | gemini-3.1-pro-preview    | no-flag 1050s err | no-flag 431s err | no-flag 959s | no-flag 1223s err | no-flag 970s err | **0/5** |

Smoke 40 final: 0/5 SOLVED. 4 of 5 challenges ended with `run_status=completed_with_errors`. That status only fires when API calls fail. The error is the same one in every CPG-CEA log line.

## Root cause: daily request budget exhausted, not a regression

| Evidence                                                                                          | Value                                                                       |
|---------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------|
| 429 count in `/tmp/aegispt-api.log` (grep `HTTP/1.1 429`)                                          | 1106                                                                        |
| Sample 429 line                                                                                   | `POST https://generativelanguage.googleapis.com/v1beta/models/gemini-3.1-pro-preview:generateContent "HTTP/1.1 429 Too Many Requests"` |
| Gemini free-tier daily quota per model                                                            | 250 requests/day                                                            |
| Same provider, same target XBEN-002 in smoke 38 vs smoke 40                                       | SOLVED 590s -> no-flag 1050s `completed_with_errors`                        |
| Code that produces these calls                                                                    | [gemini_native.py](../../api/app/services/gemini_native.py)                 |

The provider has not changed between smokes 38 and 40. The prompts have not regressed (commits since smoke 38 only added meta-strategies in [cpg_seeded_cea_prompts.py](../../api/app/services/assessment_loop_internals/cpg_seeded_cea_prompts.py) — pure addition). The only difference is the request budget: smokes 39 + 40 combined burnt through the 250/day allotment for `gemini-3.1-pro-preview`.

## Implication for meta-strategies measurement

Meta-strategies lift (universal vuln-class hints in CPG_SEEDED_CEA_PROMPT, commit ff3bd36) **cannot be measured today on Gemini**. Smoke 40 is the wrong instrument because every CPG-CEA call is 429-ing out before any meta-strategy hint can reach the model.

## What to do

1. **Do not run more Gemini smokes today.** Daily quota resets at midnight Pacific (~08:00 UTC tomorrow). Until then every CPG-CEA call returns 429.
2. **Switch to OAuth or Claude** for meta-strategies validation. Both have separate quotas. OAuth is connected and warm.
3. **Tomorrow**: re-run smoke 38 setup (5 XBEN with `--llm-provider gemini-3.1-pro`) and compare against smoke 39's 1/5 SOLVED + 4/5 correct-hypothesis baseline. If meta-strategies help, finding-count and high_or_critical_count should rise even on the 4 no-flag challenges.

## Open follow-ups (file as backlog tasks before commit)

- **Rate-limit guard in `gemini_native.py`**: detect 429 and fail-fast the loop instead of consuming wall-clock time hammering a dead quota. Smoke 40 burnt 1050s + 431s + 959s = ~40min wall time mostly on retries against a known-dead quota.
- **Per-provider daily request counter** in observability: warn at 200, hard-stop at 240 to leave headroom for debugging.
