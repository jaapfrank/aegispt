# Codex Results

Prepared task results and safe command plans are stored here.

## Current Data-Lane Handoff

Claude should read the latest data-lane handoff before continuing local model
training or adapter promotion work:

- `codex/results/aegispt-data-lane-iter5-claude-handoff-latest.md`
- `codex/results/aegispt-data-lane-iter5-claude-handoff-latest.json`

The dated immutable copy for the 2026-06-05 handoff is:

- `codex/results/aegispt-data-lane-iter5-claude-handoff-20260605.md`
- `codex/results/aegispt-data-lane-iter5-claude-handoff-20260605.json`

The handoff is data/eval-lane only. It does not imply runtime changes,
capability-pack promotion, or adapter promotion; the readiness report must pass
with real non-smoke SFT, deep-chain, and LLMSVS scores first.

The fixed data-lane validation target is:

```bash
bash scripts/run_data_lane_tests.sh
```
