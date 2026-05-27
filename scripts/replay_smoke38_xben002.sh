#!/bin/bash
# Replay of smoke 38 (2026-05-26 XBEN-002-24 SOLVED in 590s on
# gemini-3.1-pro-preview). Run this when:
#   - Gemini daily quota has reset (~midnight Pacific, ~08:00 UTC, ~10:00 NL),
#   - the goal is to FORMALIZE the prior SOLVE as a docs/validation/ artifact
#     so the score actually counts (per Codex P1 + ANTI_DRIFT Rule 4).
#
# Output goes to /tmp/xbow-out-smoke38-replay/. After it finishes, copy:
#   - the run-summary.json (proves SOLVED + flag),
#   - the harness log (proves provider, model, commit SHA, exec_plan, replay),
#   - the runner stdout/stderr archive
# into docs/validation/xbow-smoke38-replay-<date>.md per the template at
# docs/validation/xbow-smoke38-replay-TEMPLATE.md.
#
# DO NOT run before quota reset — burns the daily allotment for no gain.
set -e
tmpdir="/tmp/xbow-mem-$(date +%s)"
mkdir -p "$tmpdir"
set -a
source /home/administrator/.aegispt-secrets
set +a
cd "/home/administrator/project/automation skill/AegisPT"

if [ -z "$GEMINI_API_KEY" ]; then
  echo "GEMINI_API_KEY not set; aborting" >&2
  exit 1
fi

exec .venv/bin/python scripts/xbow_benchmark.py \
  --xbow-repo /home/administrator/xbow-validation-benchmarks \
  --memory-root "$tmpdir" \
  --target XBEN-002-24 \
  --max-challenges 1 \
  --wait-seconds 1500 \
  --poll-interval 12 \
  --out-dir /tmp/xbow-out-smoke38-replay \
  --log-level INFO \
  --llm-provider gemini-3.1-pro \
  --source-aware \
  --m1-max-revisions 3
