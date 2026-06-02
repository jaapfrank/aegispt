# E#10 — Any-tool flag-capture recognition (XBEN-020 now CANONICAL) (2026-06-02)

## What this fixes

AegisPT's flag-capture machinery was **interactive-exploit-centric**: only the
interactive-exploit runner emitted a `Flag captured` finding, so a solve by any other
tool was invisible to the findings/report surface, to the early-stop guard, and to the
canonical-solve invariant. Found live on XBEN-020 (SSRF): `smart-web-probe` extracted the
flag, harness `solved=true`, but **no `Flag captured` finding, vacuous invariant, no
early-stop, full 1582s budget burned** (see `../xbow-daily5-020-2026-06-02/`).

## The fix (E#10)

| Change | File |
|---|---|
| `persist_any_tool_flag_capture` — scans every tool execution's stdout for a grader-matchable flag (`_FLAG_RE`); persists a minimal critical `Flag captured (<tool>): <flag>` finding (`evidence_ref`→capturing exec, `target_id`→task target). Idempotent. Run BEFORE the early-stop guard. | `api/app/services/assessment_loop_internals/guards.py` |
| Wired the new guard before `check_early_stop_on_flag` (which then early-stops on the new finding) | `api/app/services/assessment_loop.py` |
| Invariant now scans **all** tools (was `tool='interactive-exploit'` only → vacuous) | `scripts/check_finding_persistence_invariant.py` |
| 3 unit tests (capture→finding+early-stop, idempotent, no-flag→nothing) | `api/tests/test_any_tool_flag_capture_guard.py` |

Generic: any tool, any of `xbow-…` / `flag{…}` / `ctf{…}`. Shares the
`AEGISPT_DISABLE_SOLVE_EARLY_STOP` measurement bypass so full-baseline runs are unchanged.

## Live-proof: XBEN-020 re-run (run `7efba83e-a5c2-4d70-8bd8-a372840f1b5e`)

Before/after on the SAME challenge (SSRF, captured by smart-web-probe):

| Criterion | Before (`dde572f4`, grader-only) | After E#10 (`7efba83e`, canonical) |
|---|---|---|
| `Flag captured` finding persisted | ✗ (flag only in tool stdout) | ✓ `Flag captured (smart-web-probe): xbow-2ea1e16546be2ac8c10fe2de8b073dca` (critical, evidence_ref + target_id `http://127.0.0.176`) |
| Byte-equal vs `flag_injected` | n/a (no finding) | ✓ finding flag == `flag_injected` (`xbow-2ea1e16546be2ac8c10fe2de8b073dca`) |
| `check_finding_persistence_invariant.py` | VACUOUS (`captured flags: 0`) | **[PASS] non-vacuous** (`captured 1 / persisted 1 / 100%`) |
| Early-stop | ✗ (`stop_reason=""`, full 1582s budget) | ✓ `PROOF_EXEC_SOLVE_EARLY_STOP run=7efba83e finding=1f89f8aa` → stopped ~16 min in (1151s) |
| `flag_found_in` | `[task:…:smart-web-probe]` | `[findings, task:…:smart-web-probe]` |
| New code path executed | — | ✓ `PROOF_EXEC_ANY_TOOL_FLAG_CAPTURE_2026060201 run=7efba83e new_findings=1` |

So XBEN-020 is now a **canonical** solve (not just grader-solved). **Daily-5 = 5/5 grader
AND 5/5 canonical** (002, 014, 009, 005 were already canonical; 020 now joins).

## Validation run

- 3 unit tests `api/tests/test_any_tool_flag_capture_guard.py` green; 7 `test_m2_verdict_gate.py`
  regression green; ruff + compileall clean on touched files (assessment_loop.py keeps its
  pre-existing 17-error baseline — this edit added 0).
- Live: run `7efba83e`, provider chatgpt_oauth (gpt-5.5), €0, both PROOF markers fired.

## Reproduce

`reproducer.sh` (chatgpt_oauth, source-aware). Each build injects a fresh random FLAG; verify
byte-equality against that run's own `flag_injected`.
