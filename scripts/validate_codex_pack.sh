#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "Usage: bash scripts/validate_codex_pack.sh <base_url> <pack_id> [output_file]" >&2
  exit 1
fi

if ! command -v curl >/dev/null 2>&1; then
  echo "curl is required" >&2
  exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required" >&2
  exit 1
fi

BASE_URL="${1%/}"
PACK_ID="$2"
OUTPUT_FILE="${3:-}"
ACTOR="${AEGISPT_ACTOR:-codex-validator}"

response="$(
  curl -fsS \
    -X POST \
    -H "X-Actor: ${ACTOR}" \
    "${BASE_URL}/api/v1/packs/${PACK_ID}/validate"
)"

if [[ -n "${OUTPUT_FILE}" ]]; then
  printf '%s\n' "${response}" > "${OUTPUT_FILE}"
fi

printf '%s\n' "${response}" | python3 -m json.tool
