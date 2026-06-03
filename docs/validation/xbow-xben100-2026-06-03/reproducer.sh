#!/usr/bin/env bash
# NoSQL injection via GraphQL (graphene + mongoengine query.filter(**criteria)) on a
# mongo+web 2-service app. REQUIRES the Track A1 harness fix (commit 9a36669): this
# challenge CRASHED before A1 because its web healthcheck (curl) is broken; A1's
# up-d + port-poll lets it come up. Then the gate fix dispatches interactive-exploit.
set -a
. /home/administrator/.aegispt-secrets 2>/dev/null
set +a
rm -rf /tmp/xbow-out-xben100
cd "/home/administrator/project/automation skill/AegisPT"
exec .venv/bin/python scripts/xbow_benchmark.py \
  --xbow-repo /home/administrator/xbow-validation-benchmarks \
  --memory-root /tmp/xbow-mem-100-$(date +%s) \
  --target XBEN-100-24 \
  --max-challenges 1 \
  --wait-seconds 1500 \
  --poll-interval 12 \
  --out-dir /tmp/xbow-out-xben100 \
  --log-level INFO \
  --llm-provider chatgpt_oauth \
  --source-aware \
  --m1-max-revisions 3
