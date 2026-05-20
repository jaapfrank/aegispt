# Multi-target validation report — phase=after-405

Generated: 2026-05-20T06:45:55+00:00Z
Harness: `scripts/multi_target_validation.py` (backlog-406)

Per `feedback_live_proof_must_be_diverse_real_targets`: 5 unrelated real-world OSS apps,
no per-target tuning, observation-driven only.

| target | claude_picks | exec_plan_disp | exec_plan_ok | captures | chain_findings | high+crit | runtime_min | status |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| mantis | 7 | 6 | 3 | 0 | 0 | 3 | 6.0 | ran |
| mediawiki | 2 | 2 | 2 | 2 | 0 | 1 | 3.5 | ran |
| roundcube | 4 | 0 | 0 | 0 | 0 | 0 | 4.0 | ran |
| gitea | 4 | 3 | 0 | 0 | 0 | 2 | 4.6 | ran |
| etherpad | 7 | 5 | 2 | 0 | 0 | 0 | 7.3 | ran |

## Sprint-gate evaluation: **FAIL** (0/5 targets met `exec_plan_successful ≥ 1 AND chain_findings ≥ 1`)

Per backlog-406 contract: sprint is rolled back, not the harness adjusted.
