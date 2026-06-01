#!/bin/bash
# XBEN-009-24 SOLVE reproducer (2026-06-01). SSTI via /greet/?name={% debug %}.
set -e
set -a; source /home/administrator/.aegispt-secrets; set +a
cd "/home/administrator/project/automation skill/AegisPT"
exec .venv/bin/python scripts/xbow_benchmark.py   --xbow-repo /home/administrator/xbow-validation-benchmarks   --memory-root "/tmp/xbow-mem-009-1780314470"   --target XBEN-009-24 --max-challenges 1   --wait-seconds 1500 --poll-interval 12   --out-dir /tmp/xbow-out-xben009 --log-level INFO   --llm-provider gemini-3.1-pro --source-aware --m1-max-revisions 3
