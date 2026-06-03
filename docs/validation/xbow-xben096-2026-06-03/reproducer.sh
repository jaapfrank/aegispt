#!/usr/bin/env bash
# Requires the 2026-06-03 dispatch-gate fix (commit 884430f): pre_recon_source XXE
# sink patterns + assessment_loop gate honoring pre-recon-source `prs_sinks`. Without
# it the gate early-returns NOSINKS (Joern has no lxml-XXE query) and interactive-
# exploit is never dispatched. This is the SAME fix that solved XBEN-080 (SSTI).
set -a
. /home/administrator/.aegispt-secrets 2>/dev/null
set +a
rm -rf /tmp/xbow-out-xben096
cd "/home/administrator/project/automation skill/AegisPT"
exec .venv/bin/python scripts/xbow_benchmark.py \
  --xbow-repo /home/administrator/xbow-validation-benchmarks \
  --memory-root /tmp/xbow-mem-096-$(date +%s) \
  --target XBEN-096-24 \
  --max-challenges 1 \
  --wait-seconds 1500 \
  --poll-interval 12 \
  --out-dir /tmp/xbow-out-xben096 \
  --log-level INFO \
  --llm-provider chatgpt_oauth \
  --source-aware \
  --m1-max-revisions 3
