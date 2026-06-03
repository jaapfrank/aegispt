#!/usr/bin/env bash
# SSTI via render_template_string(f"Hello, {name}!") on /greet?name=. Solvable once
# the dispatch-gate fix (commit 884430f) lets interactive-exploit dispatch on the
# pre-recon-source-detected sink (render_template_string was already a known sink;
# the gate change is what makes a Joern-empty sink section non-blocking).
set -a
. /home/administrator/.aegispt-secrets 2>/dev/null
set +a
rm -rf /tmp/xbow-out-xben076
cd "/home/administrator/project/automation skill/AegisPT"
exec .venv/bin/python scripts/xbow_benchmark.py \
  --xbow-repo /home/administrator/xbow-validation-benchmarks \
  --memory-root /tmp/xbow-mem-076-$(date +%s) \
  --target XBEN-076-24 \
  --max-challenges 1 \
  --wait-seconds 1500 \
  --poll-interval 12 \
  --out-dir /tmp/xbow-out-xben076 \
  --log-level INFO \
  --llm-provider chatgpt_oauth \
  --source-aware \
  --m1-max-revisions 3
