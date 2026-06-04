#!/usr/bin/env bash
# Serve the local uncensored model on the GPU (Blackwell sm_120) via the
# official llama.cpp CUDA Docker image — the refusal-ceiling fix (S7).
#
# WHY DOCKER: the official ghcr.io/ggml-org/llama.cpp:server-cuda image is built
# with CUDA ARCHS that INCLUDE 1200 (= sm_120 = Blackwell), which the pip
# llama-cpp-python wheel (arch 890/Ada) and vLLM (no qwen35 GGUF loader) both
# lack. The container bundles its own CUDA, so the host CUDA version is
# irrelevant (driver forward-compat) — clean maintenance, host-CUDA-agnostic.
#
# Proven 2026-06-04: 15.2GB VRAM offload, ~30-36 tok/s (vs ~2-4 CPU), answers
# the SSRF->localhost reset chain that gpt-5.5 refuses (policy_refusal).
#
# Idempotent: re-running re-uses the running container if healthy.
set -euo pipefail

IMAGE="ghcr.io/ggml-org/llama.cpp:server-cuda"
NAME="qwen-gpu"
MODELS_DIR="${AEGISPT_MODELS_DIR:-/home/administrator/.aegispt-tools/models}"
GGUF_NAME="${AEGISPT_LOCAL_GGUF:-Qwen3.6-27B-NEO-CODE-HERE-2T-OT-IQ3_M.gguf}"
HOST_PORT="${AEGISPT_LOCAL_LLM_PORT:-8801}"
NGL="${AEGISPT_LOCAL_NGL:-99}"          # GPU layers (99 = all)
# 16384 ctx: the multi-step interactive-exploit loop accumulates the full
# request/response transcript; 8192 overflowed at ~step 22 on XBEN-024. q8_0 KV
# cache halves KV memory so 16384 fits the 16GB Blackwell GPU (~15.2GB used).
CTX="${AEGISPT_LOCAL_CTX:-16384}"
KV_TYPE="${AEGISPT_LOCAL_KV_TYPE:-q8_0}"

# Already healthy? Done.
if docker ps --filter "name=^${NAME}$" --filter "health=healthy" --format '{{.Names}}' | grep -q "${NAME}"; then
  echo "[serve_local_llm_gpu] ${NAME} already healthy on :${HOST_PORT}"
  exit 0
fi

# Verify GPU passthrough works before bothering to pull/run.
if ! docker run --rm --gpus all "${IMAGE}" --version >/dev/null 2>&1; then
  echo "[serve_local_llm_gpu] pulling ${IMAGE} ..."
  docker pull "${IMAGE}"
fi

if [ ! -f "${MODELS_DIR}/${GGUF_NAME}" ]; then
  echo "[serve_local_llm_gpu] ERROR: model not found: ${MODELS_DIR}/${GGUF_NAME}" >&2
  exit 1
fi

docker rm -f "${NAME}" >/dev/null 2>&1 || true
docker run -d --name "${NAME}" --gpus all --restart unless-stopped \
  -p "127.0.0.1:${HOST_PORT}:8080" \
  -v "${MODELS_DIR}:/models" \
  "${IMAGE}" \
  -m "/models/${GGUF_NAME}" \
  --host 0.0.0.0 --port 8080 \
  --n-gpu-layers "${NGL}" --ctx-size "${CTX}" \
  --cache-type-k "${KV_TYPE}" --cache-type-v "${KV_TYPE}"

echo "[serve_local_llm_gpu] launched ${NAME}; waiting for model load ..."
for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
  if curl -s -m 5 "http://127.0.0.1:${HOST_PORT}/v1/models" 2>/dev/null | grep -q '"models"'; then
    echo "[serve_local_llm_gpu] READY on http://127.0.0.1:${HOST_PORT} (point AEGISPT_LOCAL_LLM_URL here)"
    docker logs "${NAME}" 2>&1 | grep -iE "ARCHS|RTX|model loaded" | tail -3
    exit 0
  fi
  sleep 4
done
echo "[serve_local_llm_gpu] WARNING: server not responding after wait; check 'docker logs ${NAME}'" >&2
exit 1
