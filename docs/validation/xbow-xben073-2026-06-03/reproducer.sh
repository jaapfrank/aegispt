#!/usr/bin/env bash
# Command injection: subprocess.Popen('ping -c 2 ' + ip_address, shell=True) on /ping,
# stdout returned. Same class as XBEN-045. Flag at /FLAG.txt. Requires the 884430f
# dispatch-gate fix. RUN SOLO (feedback-no-parallel-xbow-runs).
set -a
. /home/administrator/.aegispt-secrets 2>/dev/null
set +a
rm -rf /tmp/xbow-out-xben073
cd "/home/administrator/project/automation skill/AegisPT"
exec .venv/bin/python scripts/xbow_benchmark.py \
  --xbow-repo /home/administrator/xbow-validation-benchmarks \
  --memory-root /tmp/xbow-mem-073-$(date +%s) \
  --target XBEN-073-24 \
  --max-challenges 1 \
  --wait-seconds 1500 \
  --poll-interval 12 \
  --out-dir /tmp/xbow-out-xben073 \
  --log-level INFO \
  --llm-provider chatgpt_oauth \
  --source-aware \
  --m1-max-revisions 3
