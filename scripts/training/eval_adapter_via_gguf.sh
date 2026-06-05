#!/usr/bin/env bash
# Post-DPO quantitative eval: merge an adapter -> GGUF -> serve on llama.cpp
# (our proven Blackwell server-cuda image) -> fast HTTP eval -> teardown.
# The 16GB 5080 can't hold qwen-gpu (27B) + the eval model at once, so qwen-gpu is
# stopped during the serve and restarted afterwards.
#
#   ADAPTER=<adapter_dir|base>  LABEL=<name>  [PORT=8810]  bash eval_adapter_via_gguf.sh
set -u
ADAPTER="${ADAPTER:-base}"
LABEL="${LABEL:-base}"
PORT="${PORT:-8810}"
PERFAM="${PERFAM:-40}"

TOOLS=/home/administrator/.aegispt-tools
TRAIN=$TOOLS/training
VENV=$TOOLS/train-venv/bin/python
LLAMA=$TOOLS/llama.cpp
REPO="/home/administrator/project/automation skill/AegisPT"
MERGED=$TRAIN/merged-$LABEL
GGUF_NAME=eval-$LABEL-f16.gguf
GGUF=$TOOLS/models/$GGUF_NAME

echo "=== [1/4] merge ($ADAPTER) -> $MERGED ==="
AEGISPT_MERGE_ADAPTER="$ADAPTER" AEGISPT_MERGE_OUT="$MERGED" \
  "$VENV" "$REPO/scripts/training/merge_adapter.py" || { echo "MERGE FAILED"; exit 1; }

echo "=== [2/4] convert -> GGUF f16 ($GGUF) ==="
"$VENV" "$LLAMA/convert_hf_to_gguf.py" "$MERGED" --outfile "$GGUF" --outtype f16 \
  || { echo "CONVERT FAILED"; exit 1; }

echo "=== [3/4] serve on llama.cpp server-cuda (port $PORT) ==="
docker stop qwen-gpu >/dev/null 2>&1 && echo "qwen-gpu stopped (free VRAM)"
docker rm -f eval-llm >/dev/null 2>&1
sleep 3
docker run -d --name eval-llm --gpus all \
  -v "$TOOLS/models":/models \
  -p 127.0.0.1:$PORT:8080 \
  ghcr.io/ggml-org/llama.cpp:server-cuda \
  -m /models/$GGUF_NAME --host 0.0.0.0 --port 8080 --n-gpu-layers 99 --ctx-size 8192 \
  >/dev/null 2>&1
echo "waiting for health ..."
HEALTHY=0
for ((i=0; i<80; i++)); do
  if curl -sf http://127.0.0.1:$PORT/health >/dev/null 2>&1; then HEALTHY=1; break; fi
  sleep 3
done
[ "$HEALTHY" = 1 ] && echo "server up" || echo "WARN: server not healthy after 240s (check: docker logs eval-llm)"

echo "=== [4a] fast HTTP eval ($PERFAM/family) ==="
cd "$REPO"
AEGISPT_EVAL_ENDPOINT=http://127.0.0.1:$PORT/v1/chat/completions \
AEGISPT_EVAL_MODEL=$LABEL \
  "$VENV" scripts/training/eval_harness.py --per-family "$PERFAM" --out "$TRAIN/eval_$LABEL.json"
RC=$?

echo "=== [4b] deep-chain eval (multi-step follow-through — the real gap) ==="
AEGISPT_EVAL_ENDPOINT=http://127.0.0.1:$PORT/v1/chat/completions \
AEGISPT_EVAL_MODEL=$LABEL AEGISPT_DEEP_OUT="$TRAIN/deep_$LABEL.json" \
  "$VENV" scripts/training/deep_chain_eval.py 2>&1 | tail -16

echo "=== teardown: remove eval-llm, restart qwen-gpu ==="
docker rm -f eval-llm >/dev/null 2>&1
docker start qwen-gpu >/dev/null 2>&1 && echo "qwen-gpu restarted"
echo "=== EVAL $LABEL DONE rc=$RC -> $TRAIN/eval_$LABEL.json ==="
exit $RC
