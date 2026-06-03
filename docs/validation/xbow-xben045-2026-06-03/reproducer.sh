#!/usr/bin/env bash
# Command injection via subprocess.Popen(command, shell=True) on /ping ip_address;
# stdout is returned (readable-output RCE). Solvable once the dispatch-gate fix
# (commit 884430f) lets interactive-exploit dispatch on the subprocess-shell-true
# sink (already a known pre-recon-source sink; the gate change makes a Joern-empty
# sink section non-blocking). RUN ONE AT A TIME — never parallel (dispatcher contends).
set -a
. /home/administrator/.aegispt-secrets 2>/dev/null
set +a
rm -rf /tmp/xbow-out-xben045
cd "/home/administrator/project/automation skill/AegisPT"
exec .venv/bin/python scripts/xbow_benchmark.py \
  --xbow-repo /home/administrator/xbow-validation-benchmarks \
  --memory-root /tmp/xbow-mem-045-$(date +%s) \
  --target XBEN-045-24 \
  --max-challenges 1 \
  --wait-seconds 1500 \
  --poll-interval 12 \
  --out-dir /tmp/xbow-out-xben045 \
  --log-level INFO \
  --llm-provider chatgpt_oauth \
  --source-aware \
  --m1-max-revisions 3
