# Anthropic credit balance blocked smokes 28-31

Date: 2026-05-26

## Summary

Between smoke 27 (XBEN-002 SOLVED in 150s) and smoke 28 (XBEN-002 crashed by an unrelated API restart) the Anthropic credit balance fell below the threshold the API requires for picker calls. Every Claude-driven call since has returned:

```
Error code: 400 - Your credit balance is too low to access the Anthropic API.
Please go to Plans & Billing to upgrade or purchase credits.
```

This is **not a code regression** from any commit in this session. The O4 refactor (steps 1-8), the rank-schema fix (commit 542d62f), and the phantomjs hypothesis (commit e33bc13) are all correct.

## Evidence

`/tmp/aegispt-api.log` shows the WARNING line repeatedly:

```
2026-05-26 07:34:52,528 WARNING ... cpg_seeded_cea: LLM call failed:
  Error code: 400 ... 'message': 'Your credit balance is too low'
```

`_maybe_dispatch_cpg_seeded_cea` reaches `_GATE_` + `_SINKS_` log markers (proving the dispatcher's pure-Python pipeline works). The LLM-call layer's `except Exception: return None` swallows the 400 silently, so the symptom upstream is `picker_retry_exhausted`.

Smokes 23 + 24 + 27 SOLVED because credits were still available. Smokes 28-31 failed for purely credit reasons; no fix to AegisPT code can change that.

## Unblocking options

1. **Top up Anthropic credits** — Plans & Billing on console.anthropic.com. Single-line fix; once credits land, the next smoke should SOLVE again without code changes.
2. **Switch picker provider to chatgpt-oauth** — wired in already (`scripts/xbow_benchmark.py --llm-provider chatgpt_oauth`), but the 23KB system prompt times out the default 90s OAuth call (documented in TASK_QUEUE.md Discussion items "was #390"). Needs the picker-OAuth timeout bump to ≥180s before it is practically usable.
3. **Switch picker provider to local-qwen** — wired via `AEGISPT_LOCAL_LLM_URL` env. Qwen-3.6-27B-NEO-CODE worked in smoke 21 but had strict-JSON-schema adherence issues (it 'thinks' too much and emits `<think>` blocks). Workable for opportunistic recon but not for the schema-strict picker output.

## What this session can still do without credits

- Repo hygiene work (P2/P3/P4/P5 from `docs/research/repo-hygiene-and-open-tasks-audit-2026-05-24.md`): task-status reconcile, ui authority decision, .gitignore hygiene, more O4 splits.
- Code refactoring with import-only validation (no smoke needed).
- Writing documentation / triage docs.
- Pre-rendering bug fixes that don't require LLM calls.

## What this session can NOT do without credits

- Any XBOW smoke validation (every smoke goes through the picker, which calls Claude).
- M2 verdict gate live-verification (needs a run with findings).
- M5 cross-run measurement (needs a smoke).
- S2 XBEN-010/011/012 apply (needs a smoke).
- Triage XBEN-009 (needs a fresh run with completed tasks — DB cleanup removed prior artifacts).
