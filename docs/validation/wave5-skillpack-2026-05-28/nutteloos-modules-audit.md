# Nutteloos-modules audit — 2026-05-28

Per operator directive "vooral kijken als er nutteloze modules zijn
en/of deze zorgen voor verstoring dat je ze weg haald" — investigated
modules that are dead-weight OR actively interfere with the AI-first
SOLVE goal.

## Finding 1 — CRITICAL: legacy single-picker excludes Gemini

**Location**: `api/app/services/assessment_loop.py:2406`

```python
if not (provider_is_anthropic or provider_is_chatgpt_oauth or provider_is_local_qwen):
    logger.warning("picker: configured model %s has no governed picker branch.")
    return None
```

When `--llm-provider gemini-3.1-pro` is used:

1. `PICKER_MODE=specialists` runs first → `_specialists_select_next_action`
2. Gemini specialist factory exists at line 2022, calls `send_gemini_picker_request`
3. Today (2026-05-28) Gemini hit daily quota (250 req/day) → `gemini_native:
   skipping call ... daily quota previously exhausted (429)` → returns None
4. All 5 specialists ran=empty elapsed=0.0s → `errored=5` → return None from
   specialists path
5. Fall back to legacy single-picker (line 2397)
6. Line 2406: NOT (anthropic or chatgpt_oauth or local_qwen) — Gemini EXCLUDED
7. Returns None → "picker exhausted retries (3 attempts)" → loop stops
8. Result: `stop_reason=picker_retry_exhausted` — heuristic fallback only

**Impact on wave 4 + 5a (smokes 58/59/60/61/62)**:
- Smoke 58 XBEN-009: 5 findings / 688s / completed_with_errors — all
  findings came from passive scanners (heuristic fallback), zero LLM-driven
  picker decisions
- Smoke 59 XBEN-005: 5 findings / 362s / completed_with_errors — same
- Smokes 60/61/62: killed mid-flight after diagnosis confirmed they were
  going to repeat the same dead-picker pattern

**The skill-pack injection (commit 0e59456) is therefore UNUSED on every
Gemini smoke**, because all 3 picker call sites I instrumented (line 349
local-qwen, line 440 chatgpt-oauth, line 2791 anthropic) are unreachable
from the Gemini path.

## Finding 2 — Skill pack IS live for Anthropic + ChatGPT-OAuth + local-qwen

**Empirical PROOF_EXEC**: `/tmp/aegispt-api.log` line at 00:53:02 confirms
`PROOF_EXEC_SKILL_PACK_LOADED_2026052813 bytes=31159`. Module-level cache
populated at import. Anthropic / ChatGPT-OAuth / local-qwen pickers will
see `_picker_prompt_with_skills()` (base 25,391 → with skills 56,550
bytes — 4 vuln-class playbooks: SSTI engine-fingerprint, JWT none+forgery,
SQLi REST, access-control state-change-POST).

**Smoke 63 launched** (Claude Opus 4.7 on XBEN-009, 900s budget) to test
whether skill-pack injection actually shifts exploit-craft behavior in
the LLM picker. This is the first run where the skill pack reaches the
LLM. Cost: ≤ €1,25 per cost-discipline policy.

## Finding 3 — Specialists module: 5× duplicated recipe content

**Location**: `api/app/services/picker_specialists/vuln_{auth,authz,injection,ssrf,xss}.py`

Each file (~120-200 lines) contains a hard-coded Python string prompt that
duplicates content of the new generic skill files. E.g.
`vuln_injection.py:55` already has `"Template injection (SSTI):
code-exec-attack — submit '{{7*7}}', check '49' in response"` — which is
verbatim what `docs/skills/ssti-engine-fingerprint-then-escape.md` codifies.

**Verdict**: Not nutteloos (specialists actively rank hypotheses when the
LLM call succeeds), BUT duplicates skill-pack content. If skill pack
proves useful in smoke 63, the specialists' prompts should be re-derived
*from* the skill files, not maintained separately. Anti-overhaul rule:
defer this consolidation until SOLVE-rate movement justifies it.

## Recommendation

If smoke 63 SOLVES or produces an EXPLOITED-grade finding on XBEN-009:
- (1) Surgical add Gemini branch to legacy picker (line 2406+) so Gemini
  smokes also get skill-pack injection
- (2) Consolidate specialist prompts to reference docs/skills/*.md

If smoke 63 fails:
- Skill pack content isn't the binding constraint either. Look at
  exploit_developer_agent runner / code_exec_attack runner script
  generation — the actual exploit-craft layer.
