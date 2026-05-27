#!/bin/bash
set -e
tmpdir="/tmp/xbow-mem-$(date +%s)-gemini"
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
  --out-dir /tmp/xbow-out-smoke48 \
  --log-level INFO \
  --llm-provider gemini-3.1-pro \
  --source-aware \
  --m1-max-revisions 3
