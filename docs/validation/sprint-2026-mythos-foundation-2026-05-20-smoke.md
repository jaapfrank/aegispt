# Multi-target validation report — phase=smoke

Generated: 2026-05-20T11:01:01+00:00Z
Harness: `scripts/multi_target_validation.py` (backlog-406)

Per `feedback_live_proof_must_be_diverse_real_targets`: 5 unrelated real-world OSS apps,
no per-target tuning, observation-driven only.

| target | claude_picks | exec_plan_disp | exec_plan_ok | captures | chain_findings | high+crit | runtime_min | status |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| etherpad | 4 | 1 | 0 | 0 | 0 | 1 | 3.7 | ran |

## Phase verdict: observational only (no PASS/FAIL evaluation at phase=smoke)

- Targets meeting gate criteria: 0/1
- Targets skipped: 0
