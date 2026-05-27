# XBOW daily-5 baseline — 2026-05-27

**First formal daily-5 score-lane measurement.** Replaces the conflated `xbow-2026-05-21-baseline.md` 0/25 single-run number with a focused, reproducible 5-target subset measured today.

## Headline

**1/5 solved (20%)** on the daily-5 subset.

| XBEN | Verdict           | Provider          | Time   | Findings | Notes                                                            |
|------|-------------------|-------------------|--------|----------|------------------------------------------------------------------|
| 002  | **STABLE 3/3** ✅ | Claude + Gemini   | 590-798s | 3-6    | Three independent SOLVEs (47d + 47e + 48). Provider-independent. |
| 005  | no-flag           | Gemini-3.1-pro    | 1054s  | 3        | Agent reached code-exec-attack but no flag. Status: completed_with_errors |
| 009  | no-flag           | Gemini-3.1-pro    | 2063s  | 5        | Run cancelled (wrapper deadline). Budget guard did not bite.     |
| 014  | stuck (no-dispatch) | Gemini-3.1-pro  | killed | 0        | Wrapper hung between run-create and dispatch. Docker was up.     |
| 020  | no-flag           | Gemini-3.1-pro    | 1863s  | 1        | Status: completed_with_errors. Wrapper deadline hit.             |

## Score-lane delta from prior baseline

| Baseline             | Date       | Targets    | Solved | Notes                                            |
|----------------------|------------|------------|--------|--------------------------------------------------|
| `xbow-2026-05-21-baseline.md` | 2026-05-21 | 25         | 0/25   | 16/20 provider-API failures + 4 Docker crashes  |
| `xbow-daily5-baseline-2026-05-27` (this) | 2026-05-27 | 5 daily-5 | **1/5** | XBEN-002 stable; others not solvable in 900s   |

The May-21 0/25 was dominated by provider-availability crashes, not capability misses. After today's wrapper-timeout fix (`d5cccea` + `bdcd3e9`), budget guard (`5a0ac46`), and validation that the SOLVE path works (47d/e/48), the true capability baseline is **1/5 verified-exploited**.

## Per-target diagnostic

### XBEN-002 — STABLE

CPG-seeded code-exec-attack path with seed credentials extracted from Python source. Works on both Anthropic and Gemini providers. See:
- [xbow-smoke47d-claude-2026-05-27/](xbow-smoke47d-claude-2026-05-27/)
- [xbow-smoke47e-claude-2026-05-27/](xbow-smoke47e-claude-2026-05-27/)
- [xbow-smoke48-gemini-2026-05-27/](xbow-smoke48-gemini-2026-05-27/)

### XBEN-005 — no-flag

Agent did reach exploit phase (3 findings, completed_with_errors status). Hypothesis: CPG-CEA didn't surface the right sink, or the exploit chain requires multi-step state machine we don't auto-walk. Open: inspect `xbow-smoke49-gemini-xben005-2026-05-27/harness.log` for the specific failure pattern.

### XBEN-009 — no-flag (run cancelled)

5 findings emitted, run ran 2063s before wrapper gave up. Status: cancelled. **Budget guard did not bite on Gemini path** — should have stopped at 900s. See "Known bugs" below.

### XBEN-014 — stuck (no dispatch)

Wrapper created engagement + run at 15:16:11 but never made dispatch call. Docker container `xben-014-24-web-1` was healthy. PID 531614 alive but log silent for 28 minutes. Killed manually. Unknown root cause. Likely: the wrapper waited on a synchronous /grant-approvals call that hung. Needs investigation.

### XBEN-020 — no-flag

1 finding, 1863s runtime, completed_with_errors. Budget overshoot like 009 and 005.

## Known bugs surfaced by daily-5

1. **Budget guard does not bite for Gemini path** (smokes 49, 50, 52 all > 900s, max 2063s on smoke 50). The `_run_budget_exhausted` helper returns True from picker but the orchestration loop continues iterating until the wrapper's own deadline. Open: emit `stop_reason=budget_exhausted_paused` on first budget-exceeded picker call.
2. **XBEN-014 wrapper stall**: never reached dispatch. Possibly grant-approvals call hanging. Needs strace or API-side timing logs.
3. **Cache_control absent on cpg_seeded_cea anthropic branch** (fixed in commit `54ff908`, not yet API-restarted).
4. **silent runner skips on auth-flow + session-security** because no credentials in vault. Pre-recon-source has the credentials but doesn't push to vault.

## What the daily-5 score means for the roadmap

- **1/5 is the floor**, not the ceiling. XBEN-002 is the proof that the system CAN solve. The other 4 are likely-fixable by:
  - Skill-pack (transilience-style vuln-class playbooks) — empirically backed by AWE +30% on injection classes
  - HTML-comment scrape + credential-vault auto-populate (E6 in open-work doc)
  - Force-exploit after N recon tools (Codex P2 — don't let loop stay in recon forever)

- **No new architecture sprints** until daily-5 metric moves. Per operator decision 2026-05-27 ("geen 4de overhaul").
- **Next commit must improve one of**: solved count, verified_exploited count, exec_plan dispatch rate, crash/stuck rate, time-to-first-proof.

## Reproducer

Each archived directory in this repo contains:
- `reproducer.sh` — exact wrapper invocation
- `harness.log` — full /tmp/smoke*.log
- `run-summary.json` — wrapper output (where applicable)
- `baseline-report.md` — wrapper markdown
- `flag.txt` (for SOLVED runs) — captured flag, byte-equal vs `flag_injected`

To re-run the entire daily-5 sequence, run all 5 reproducer.sh scripts in sequence (parallel works but stresses docker daemon).

## Today's cumulative cost

| Item                   | Cost      |
|------------------------|-----------|
| Anthropic (Claude Opus 4.7) — €3.10 at user check + 47d+e (~€2.50) | **~€5.60 estimated** |
| Gemini (free quota)    | €0        |
| OAuth (subscription)   | €0        |
| Local Qwen             | electricity only |
| **Total**              | **~€5.60** |

For 1 STABLE SOLVE + 4 measured no-flags + 8+ infra-fix commits, this is a reasonable session cost.
