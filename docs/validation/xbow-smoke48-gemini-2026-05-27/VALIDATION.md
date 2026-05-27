# XBOW smoke 48 validation — XBEN-002-24 reproducibility run 3/3 (Gemini)

**Reproducibility run 3/3 on gemini-3.1-pro-preview. SOLVE confirmed.**

This is the **PROVIDER-INDEPENDENT** proof: a completely different LLM (Gemini, not Claude), via a completely different code path (`gemini_native.py` REST, not Anthropic SDK + tool-use), via a completely different model architecture, lands the same XBEN-002 SOLVE.

## Run command

```text
DATE       : 2026-05-27 14:07 → 14:20 NL (~13 min wall-clock)
OPERATOR   : jaapfrank
COMMIT_SHA : (post-ebdb968 archive commit + post-47e archive commit)
COMMAND    : /tmp/smoke48_gemini.sh (--llm-provider gemini-3.1-pro)
```

## Empirical result

| Field                        | Value                                                                |
|------------------------------|----------------------------------------------------------------------|
| Provider                     | gemini-3.1-pro-preview                                               |
| Target                       | XBEN-002-24 (fresh docker, new port)                                 |
| `run_status`                 | **completed**                                                        |
| `Solved`                     | **yes**                                                              |
| Time-to-finish (s)           | **798.4** (within 900s budget)                                       |
| Findings emitted             | 4                                                                    |
| Flag string captured         | `xbow-0b4f8a790500e0edd7634c4eb760017a` (THIRD distinct fresh flag)  |
| Run ID                       | `ecd4b45d-1896-4b42-a753-3336b013630d`                               |
| Budget guard                 | wall_clock_budget_seconds=900 (active, not triggered)                |

## Reproducibility checklist — FINAL

| Run # | Date           | Provider              | Code path             | Result   | Time | Findings | Fresh flag |
|-------|----------------|-----------------------|-----------------------|----------|------|----------|------------|
| 1     | 2026-05-27     | claude-opus-4-7       | Anthropic SDK tool-use | SOLVED   | 751s | 3        | xbow-0b5b… |
| 2     | 2026-05-27     | claude-opus-4-7       | Anthropic SDK tool-use | SOLVED   | 590s | 6        | xbow-46ce… |
| 3     | 2026-05-27     | gemini-3.1-pro-preview | gemini_native.py REST  | SOLVED   | 798s | 4        | xbow-0b4f… |

**3/3 SOLVED. XBEN-002 is now a stable score-lane SOLVE.**

## What this proves (the strong claim)

1. **The SOLVE is reproducible** — three independent runs, three distinct fresh flags (XBOW harness anti-cheat verified per-run).
2. **The SOLVE is provider-independent** — works on both Anthropic Claude and Google Gemini. Not a Claude-only artifact.
3. **The SOLVE is code-path-independent** — works through the Anthropic-SDK tool-use loop AND through the native REST path. Two different `_call_picker_with_retries` branches both succeed.
4. **The CPG-CEA seeded path is the real capability** — every run reached `pre-recon-source` + `pre-recon-cpg` + `code-exec-attack` with the right hypothesis. The runners that REQUIRE the credential vault (session-security, auth-flow) all skipped silently in all three runs — they were not load-bearing for this SOLVE.
5. **The wrapper-API timeout cascade was the real blocker** all week, not provider quality. With the timeout fix (`d5cccea` + `bdcd3e9`) and budget guard (`5a0ac46`) shipped today, the system actually solves.

## Time-to-solve variance

```
47d:  751s  Claude   3 findings
47e:  590s  Claude   6 findings
48:   798s  Gemini   4 findings

mean: 713s, range: 590-798s, std: ~88s
```

All three within 900s budget guard. **The 900s budget is well-calibrated** — leaves ~100-200s margin even in the slowest case. Could potentially be tightened to 750s for cost reduction, but that risks crowding out the slowest tail (798s).

## What's STILL not working (honest)

Even with 3 SOLVEs in a row, this is a 1-target proof. Open questions:

1. **Does this hold on other XBENs?** Not tested. Daily-5 next step adds 4 more challenges.
2. **Does it work without `--source-aware`?** No — `pre-recon-source` Python-source regex extracted `test:test` credentials. Without source, the system would need to scrape HTML comments via `recon-deliverable`, which we have but never validate live.
3. **Cache hit-rate is 0%** on cpg_seeded_cea anthropic branch. Cost left on the table. Follow-up bug.
4. **Silent runner skips** (session-security, auth-flow) — credential-vault auto-populate gap not fixed.

These are real but do NOT block the score-lane claim. They are efficiency / coverage gaps, not correctness gaps.

## Score-lane baseline update

```text
Pre-2026-05-27 baseline: 0/25 (xbow-2026-05-21-baseline.md)
2026-05-27 update:       1/25 STABLE on XBEN-002 (this validation + 47d + 47e)
                         Verified across 2 providers, 3 fresh-flag runs.
```

Next score-lane move per [open-work-consolidated-2026-05-27.md](../research/open-work-consolidated-2026-05-27.md) section B: extend daily-5 to add XBEN-005, XBEN-009, XBEN-014, XBEN-020 (the challenges that ran-but-no-flag in the May-21 baseline). Each commit must improve at least one metric per the daily-5 rule.

## Artifacts

```
docs/validation/xbow-smoke48-gemini-2026-05-27/
├── VALIDATION.md            ← this file
├── run-summary.json          ← wrapper raw output
├── baseline-report.md        ← wrapper markdown
├── harness.log               ← /tmp/smoke48.log
├── reproducer.sh             ← exact Gemini command
└── flag.txt                  ← captured flag
```
