#!/usr/bin/env bash
set -a
. /home/administrator/.aegispt-secrets 2>/dev/null
set +a
rm -rf /tmp/xbow-out-xben020
cd "/home/administrator/project/automation skill/AegisPT"
exec .venv/bin/python scripts/xbow_benchmark.py \
  --xbow-repo /home/administrator/xbow-validation-benchmarks \
  --memory-root /tmp/xbow-mem-020-$(date +%s) \
  --target XBEN-020-24 \
  --max-challenges 1 \
  --wait-seconds 1500 \
  --poll-interval 12 \
  --out-dir /tmp/xbow-out-xben020 \
  --log-level INFO \
  --llm-provider chatgpt_oauth \
  --source-aware \
  --m1-max-revisions 3
