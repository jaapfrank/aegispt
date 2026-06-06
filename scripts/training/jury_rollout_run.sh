#!/usr/bin/env bash
# One round of expert iteration: serve a candidate, sample N temperature rollouts of
# the deep_chain scenario, then rank by env-reward and export the best as SFT
# demonstrations. SFT the candidate on best_sft.jsonl and repeat for a few rounds.
#   GGUF=eval-combined-q8.gguf N=16 bash jury_rollout_run.sh
set -u
TOOLS=/home/administrator/.aegispt-tools
VENV=$TOOLS/train-venv/bin/python
REPO="/home/administrator/project/automation skill/AegisPT"
GGUF="${GGUF:-eval-combined-q8.gguf}"
N="${N:-16}"
PORT=8810
EP=http://127.0.0.1:$PORT/v1/chat/completions
RDIR=$TOOLS/training/rollouts
rm -rf "$RDIR"; mkdir -p "$RDIR"

docker rm -f eval-llm >/dev/null 2>&1
docker stop qwen-gpu >/dev/null 2>&1 && echo "qwen-gpu stopped"
sleep 3
echo "=== serve $GGUF ==="
docker run -d --name eval-llm --gpus all -v "$TOOLS/models":/models -p 127.0.0.1:$PORT:8080 \
  ghcr.io/ggml-org/llama.cpp:server-cuda -m /models/$GGUF --host 0.0.0.0 --port 8080 --n-gpu-layers 99 --ctx-size 8192 >/dev/null 2>&1
for ((i=0;i<80;i++)); do curl -sf http://127.0.0.1:$PORT/health >/dev/null 2>&1 && { echo "server up"; break; }; sleep 3; done

cd "$REPO"
echo "=== $N temperature rollouts ==="
for ((i=0;i<N;i++)); do
  AEGISPT_EVAL_ENDPOINT=$EP AEGISPT_EVAL_MODEL=cand AEGISPT_DEEP_TEMP=0.8 AEGISPT_DEEP_MAXTOK=1024 \
  AEGISPT_DEEP_OUT="$RDIR/res_$i.json" AEGISPT_TRACE_OUT="$RDIR/roll_$i.jsonl" \
    "$VENV" scripts/training/deep_chain_eval.py >/dev/null 2>&1
  echo -n "."
done; echo

docker rm -f eval-llm >/dev/null 2>&1
docker start qwen-gpu >/dev/null 2>&1 && echo "qwen-gpu restarted"
echo "=== rank + export best as SFT demonstrations ==="
"$VENV" scripts/training/jury_rollout.py --rollouts "$RDIR" --out "$TOOLS/training/expert_iter_best_sft.jsonl"
echo "=== best SFT -> $TOOLS/training/expert_iter_best_sft.jsonl ==="
