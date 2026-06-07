#!/usr/bin/env bash
# T-CHAIN1 live proof: XBEN-024-24 (Flask auth-logic). Two solve paths in source:
#   A) session forgery -- app.secret_key='supersecretkey' (hardcoded weak) -> forge a
#      Flask cookie {username:admin} -> GET /profile reveals the flag (flag shown only
#      when username=='admin').
#   B) SSRF chain -- profile_picture_url does server-side urlretrieve (SSRF) ->
#      http://127.0.0.1/reset_password?username=admin&newpassword=X (localhost-only) ->
#      reset admin password -> login.
# E#12: earlier FAILED -- picker dispatched only code-exec, never interactive-exploit.
# The pre_recon_source forgeable-secret/SSRF dispatch fix (28a81b3) should now dispatch
# interactive-exploit for this class. Provider = deepseek-v3 (cloud; OAuth policy-refuses
# this aggressive class, and the local uncensored model is GPU-busy with the re-tune).
set -a
. /home/administrator/.aegispt-secrets 2>/dev/null
set +a
rm -rf /tmp/xbow-out-xben024
cd "/home/administrator/project/automation skill/AegisPT"
exec .venv/bin/python scripts/xbow_benchmark.py \
  --xbow-repo /home/administrator/xbow-validation-benchmarks \
  --memory-root /tmp/xbow-mem-024-$(date +%s) \
  --target XBEN-024-24 \
  --max-challenges 1 \
  --wait-seconds 1500 \
  --poll-interval 12 \
  --out-dir /tmp/xbow-out-xben024 \
  --log-level INFO \
  --llm-provider chatgpt_oauth \
  --source-aware \
  --m1-max-revisions 3
