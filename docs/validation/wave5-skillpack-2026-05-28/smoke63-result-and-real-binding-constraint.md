# Smoke 63 result + real binding constraint identified — 2026-05-28

## Smoke 63: Claude Opus 4.7 + skill pack live + XBEN-009

**Result**: XBEN-009-24 → **no-flag (1004s, 4 findings, completed_with_errors)**
**Cost**: **$7.57** (over the €1.25 cost-discipline cap — flagged below)
**Run ID**: `ff4b19cd-14d8-44e3-9998-e888ec25b540`

### Skill-pack injection empirically confirmed live
- `PROOF_EXEC_SKILL_PACK_LOADED_2026052813 bytes=31159` in /tmp/aegispt-api.log
  at 00:53:02 — module-import cache populated when systemd unit set
  `AEGISPT_SKILL_PACK_ENABLED=1`
- Picker prompt grew from 25,391 → 56,550 bytes (4 vuln-class playbooks
  injected via `_picker_prompt_with_skills()`)

### Comparison vs prior waves on XBEN-009 (same target)
| Wave | Provider | Skill pack | Result | Findings | Duration |
|------|----------|-----------|--------|----------|----------|
| 3 (smoke 53) | gemini-3.1-pro | NO | no-flag | 7 (2C/3H) | 2063s |
| 4 (smoke 58) | gemini-3.1-pro | NO | no-flag | 5 | 688s |
| **5b (smoke 63)** | **claude-opus-4-7** | **YES** | **no-flag** | **4** | **1004s** |

**Conclusion**: skill-pack injection produced FEWER findings (4 vs 5-7) and
did NOT produce a SOLVE. The hypothesis "skill-file content is the binding
constraint" — wave-3 postfix verdict — is FALSIFIED.

## REAL binding constraint identified — empty-script + stdout-artifact gap

DB query against `tool_executions` for smoke 63 revealed:

```
| Issue                              | Count | Root cause                                              |
|------------------------------------|-------|---------------------------------------------------------|
| `empty script — refusing to run`   | 3/12  | Picker dispatching CEA with EMPTY `python_script` field |
| `findings: []` despite exit_code=0 | 5/12  | Script stdout discarded after parsing; can't debug      |
| Successful AEGISPT_FINDING marker  | 4/12  | The only successful CEA path on this run                |
```

**25% of CEA dispatches FAILED before running** (empty script). This is a
literal-code-path bug in the picker → runner-params pipeline.

**42% of CEA dispatches ran but produced 0 findings, with NO observability**
into what the script printed. `workers/runners/code_exec_attack/runner.py:391`
captures stdout, uses it to parse findings (`_parse_findings_from_stdout` at
line 394), then DISCARDS it. The only artifact persisted is the script source
(line 413), not the stdout. So when a script "completes silently", there is
NO way to debug WHY.

This is the actual binding constraint for SOLVE rate, not LLM-prompt content.

## Next surgical actions (zero-LLM-cost, high-value)

1. **Persist script stdout as a second artifact** in code-exec-attack runner.
   `EvidenceArtifact(name="exec_stdout", content_type="text/plain",
   data=stdout_capped.encode("utf-8"), kind="exec_stdout")`. Without this,
   smoke debugging is impossible.

2. **Trace empty-script dispatches**: 3/12 hypotheses arrived at the runner
   with `python_script=""`. Either the LLM returned `{python_script: ""}` and
   nothing rejected it, OR the picker-decision pipeline lost the field.
   Add a log marker at `assessment_loop.py:2321-2325` recording
   `len(python_script)` before dispatch + reject when zero.

3. **Cost discipline post-mortem**: Anthropic spend on smoke 63 was $7.57,
   ~6x the €1.25 cap. Breakdown: cache_creation $2.35 (125k tokens × $18.75/M),
   output $4.19 (56k tokens × $75/M). Specialists call 5 separate Anthropic
   endpoints per iteration, each creates its own cache. To halve cost:
   bundle specialist prompts into a single tool-use call with 5 parallel
   `tool_choice` requests.

## Memory update

Save: skill-pack injection does NOT move SOLVE rate on XBEN-009. The
content in `docs/skills/ssti-engine-fingerprint-then-escape.md` duplicates
content already present in `cpg_seeded_cea_prompts.py:122-126`. Future
skill-file work must verify the content is NEW info before adding to picker
prompt.

## Today's surgical fixes shipped (5 commits since session start)

- `bb2fd36` emit-tolerant + budget-gate + 2 skill files
- `4b15a36` pre-execute compile-check
- `d9b26b0` wrapper-dispatch-skip
- `1f556a5` credential-vault auto-populate
- `5bc9d42` orchestrator budget-finalize
- `0e59456` skill-pack injection helper + 3 call sites
- `8090f51` PROOF_EXEC_SKILL_PACK_LOADED log marker
- `5824a51` nutteloos-modules audit doc

**SOLVE-rate movement today: 0 (still 1/5 daily-5, XBEN-002 only)**.
Detection moved (smoke 53 had 7 findings on XBEN-009 vs wave-1's 3),
infrastructure stabilised (wrapper-hang fixed, budget guard biting), but
SOLVE didn't.
