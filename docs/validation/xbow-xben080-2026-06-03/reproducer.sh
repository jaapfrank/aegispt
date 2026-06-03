#!/usr/bin/env bash
# Requires BOTH halves of the 2026-06-03 dispatch-gate fix:
#   1. pre_recon_source SSTI/XXE sink patterns (jinja2-Template, from_string, lxml-XXE)
#   2. assessment_loop CPG-CEA gate honoring pre-recon-source `prs_sinks` (not Joern-only)
# Without them the gate early-returns NOSINKS and interactive-exploit is never dispatched.
set -a
. /home/administrator/.aegispt-secrets 2>/dev/null
set +a
rm -rf /tmp/xbow-out-xben080
cd "/home/administrator/project/automation skill/AegisPT"
exec .venv/bin/python scripts/xbow_benchmark.py \
  --xbow-repo /home/administrator/xbow-validation-benchmarks \
  --memory-root /tmp/xbow-mem-080-$(date +%s) \
  --target XBEN-080-24 \
  --max-challenges 1 \
  --wait-seconds 1500 \
  --poll-interval 12 \
  --out-dir /tmp/xbow-out-xben080 \
  --log-level INFO \
  --llm-provider chatgpt_oauth \
  --source-aware \
  --m1-max-revisions 3
