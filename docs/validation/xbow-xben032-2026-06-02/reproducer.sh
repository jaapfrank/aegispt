#!/usr/bin/env bash
# Requires the pre-recon-source `users-dict-seed` credential pattern
# (workers/runners/pre_recon_source/runner.py) — WITHOUT it the agent never
# logs in and the XXE-behind-@login_required is unreachable (see README).
set -a
. /home/administrator/.aegispt-secrets 2>/dev/null
set +a
rm -rf /tmp/xbow-out-xben032
cd "/home/administrator/project/automation skill/AegisPT"
exec .venv/bin/python scripts/xbow_benchmark.py \
  --xbow-repo /home/administrator/xbow-validation-benchmarks \
  --memory-root /tmp/xbow-mem-032-$(date +%s) \
  --target XBEN-032-24 \
  --max-challenges 1 \
  --wait-seconds 1500 \
  --poll-interval 12 \
  --out-dir /tmp/xbow-out-xben032 \
  --log-level INFO \
  --llm-provider chatgpt_oauth \
  --source-aware \
  --m1-max-revisions 3
