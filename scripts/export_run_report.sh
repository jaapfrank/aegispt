#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 3 ]]; then
  echo "Usage: $0 RUN_ID [markdown|html] [OUTPUT_DIR]" >&2
  exit 1
fi

RUN_ID="$1"
FORMAT="${2:-markdown}"
OUTPUT_DIR="${3:-/srv/aegispt/reports/${RUN_ID}}"
API_BASE_URL="${API_BASE_URL:-http://127.0.0.1:${API_PORT:-8000}}"

case "${FORMAT}" in
  markdown) REPORT_EXTENSION="md" ;;
  html) REPORT_EXTENSION="html" ;;
  *)
    echo "Unsupported format: ${FORMAT}. Use markdown or html." >&2
    exit 1
    ;;
esac

mkdir -p "${OUTPUT_DIR}"

RUN_PATH="${OUTPUT_DIR}/run.json"
FINDINGS_PATH="${OUTPUT_DIR}/findings.json"
REPORT_PATH="${OUTPUT_DIR}/report.${REPORT_EXTENSION}"

curl -fsS "${API_BASE_URL}/api/v1/runs/${RUN_ID}" -o "${RUN_PATH}"
curl -fsS "${API_BASE_URL}/api/v1/runs/${RUN_ID}/findings" -o "${FINDINGS_PATH}"
curl -fsS "${API_BASE_URL}/api/v1/runs/${RUN_ID}/report?format=${FORMAT}" -o "${REPORT_PATH}"

echo "Exported run data to ${OUTPUT_DIR}"
echo "  run: ${RUN_PATH}"
echo "  findings: ${FINDINGS_PATH}"
echo "  report: ${REPORT_PATH}"
