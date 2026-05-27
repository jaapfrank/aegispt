#!/bin/bash
# Smoke 47d - Claude Opus 4.7 on XBEN-002 with HARD 900s budget.
# wait-seconds=900 propagates into configuration_json.wall_clock_budget_seconds
# so API-side _run_budget_exhausted guard fires at 900s, no further LLM
# calls regardless of wrapper state.
set -e
tmpdir="/tmp/xbow-mem-$(date +%s)-claude-d"
mkdir -p "$tmpdir"
set -a
. /home/administrator/.aegispt-secrets
set +a
cd "/home/administrator/project/automation skill/AegisPT"
exec .venv/bin/python scripts/xbow_benchmark.py \
  --xbow-repo /home/administrator/xbow-validation-benchmarks \
  --memory-root "$tmpdir" \
  --target XBEN-002-24 \
  --max-challenges 1 \
  --wait-seconds 900 \
  --poll-interval 12 \
  --out-dir /tmp/xbow-out-smoke47d \
  --log-level INFO \
  --llm-provider claude-opus-4-7 \
  --source-aware \
  --m1-max-revisions 3
