# Multi-target validation report — phase=after-404

Generated: 2026-05-19T23:47:30+00:00Z
Harness: `scripts/multi_target_validation.py` (backlog-406)

Per `feedback_live_proof_must_be_diverse_real_targets`: 5 unrelated real-world OSS apps,
no per-target tuning, observation-driven only.

| target | claude_picks | exec_plan_disp | exec_plan_ok | captures | chain_findings | high+crit | runtime_min | status |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| mantis | 3 | 2 | 2 | 0 | 0 | 2 | 3.0 | ran |
| mediawiki | 3 | 2 | 1 | 0 | 0 | 3 | 3.8 | ran |
| roundcube | 2 | 0 | 0 | 0 | 0 | 0 | 3.3 | ran |
| gitea | 2 | 2 | 2 | 0 | 0 | 1 | 6.5 | ran |
| etherpad | 3 | 0 | 0 | 0 | 0 | 0 | 3.0 | ran |

## Phase verdict: observational only (no PASS/FAIL evaluation at phase=after-404)

- Targets meeting gate criteria: 0/5
- Targets skipped: 0
