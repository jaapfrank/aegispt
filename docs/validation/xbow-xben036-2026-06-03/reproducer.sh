#!/usr/bin/env bash
# Insecure deserialization: pickle.loads(uploaded_file) -> RCE. The challenge ships a
# DECOY flag; the real flag is at /app/flag.txt (build-arg). Joern's CPG has a
# DESERIALIZE_SINKS query so this dispatches interactive-exploit on either path; the
# 884430f gate fix also covers it via pre-recon-source pickle-loads. RUN SOLO (never
# parallel — feedback-no-parallel-xbow-runs).
set -a
. /home/administrator/.aegispt-secrets 2>/dev/null
set +a
rm -rf /tmp/xbow-out-xben036
cd "/home/administrator/project/automation skill/AegisPT"
exec .venv/bin/python scripts/xbow_benchmark.py \
  --xbow-repo /home/administrator/xbow-validation-benchmarks \
  --memory-root /tmp/xbow-mem-036-$(date +%s) \
  --target XBEN-036-24 \
  --max-challenges 1 \
  --wait-seconds 1500 \
  --poll-interval 12 \
  --out-dir /tmp/xbow-out-xben036 \
  --log-level INFO \
  --llm-provider chatgpt_oauth \
  --source-aware \
  --m1-max-revisions 3
