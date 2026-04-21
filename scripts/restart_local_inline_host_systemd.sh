#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -eq 0 ]]; then
  SUDO=""
else
  SUDO="sudo"
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

if [[ ! -x "${REPO_ROOT}/.venv/bin/python" ]]; then
  echo "Missing virtual environment. Run bash scripts/setup_python_dev.sh first." >&2
  exit 1
fi

if ! command -v systemd-run >/dev/null 2>&1; then
  echo "systemd-run is required for the transient host-unit path." >&2
  exit 1
fi

PORT="${AEGISPT_PORT:-8000}"
HOST="${AEGISPT_BIND_HOST:-127.0.0.1}"
BASE_URL="${APP_PUBLIC_BASE_URL:-http://${HOST}:${PORT}}"
UNIT_NAME="${AEGISPT_LOCAL_SYSTEMD_UNIT:-aegispt-inline-host}"
LOG_INSTRUCTION="journalctl -u ${UNIT_NAME}.service -f"
HEALTH_URL="${BASE_URL%/}/health/live"
WAIT_SECONDS="${AEGISPT_LOCAL_HOST_WAIT_SECONDS:-20}"

export PLAYWRIGHT_BROWSERS_PATH="${PLAYWRIGHT_BROWSERS_PATH:-/opt/aegispt/ms-playwright}"

bash "${REPO_ROOT}/scripts/ensure_playwright_chromium.sh"

$SUDO systemctl stop "${UNIT_NAME}.service" >/dev/null 2>&1 || true
pkill -f "uvicorn api.app.main:create_app --factory --host ${HOST} --port ${PORT}" >/dev/null 2>&1 || true

$SUDO systemd-run \
  --unit="${UNIT_NAME}" \
  --property="WorkingDirectory=${REPO_ROOT}" \
  --setenv=PYTHONUNBUFFERED=1 \
  --setenv=TASK_DISPATCH_MODE="${TASK_DISPATCH_MODE:-inline}" \
  --setenv=ARTIFACTS_STORAGE_MODE="${ARTIFACTS_STORAGE_MODE:-inline}" \
  --setenv=APP_PUBLIC_BASE_URL="${BASE_URL}" \
  --setenv=PLAYWRIGHT_BROWSERS_PATH="${PLAYWRIGHT_BROWSERS_PATH}" \
  "${REPO_ROOT}/.venv/bin/python" -m uvicorn api.app.main:create_app --factory --host "${HOST}" --port "${PORT}" >/dev/null

for ((i=1; i<=WAIT_SECONDS; i+=1)); do
  if curl --fail --silent "${HEALTH_URL}" >/dev/null 2>&1; then
    echo "AegisPT transient host unit restarted."
    echo "Unit: ${UNIT_NAME}.service"
    echo "URL: ${BASE_URL}/app/"
    echo "Health: ${HEALTH_URL}"
    echo "Logs: ${LOG_INSTRUCTION}"
    exit 0
  fi
  sleep 1
done

echo "AegisPT transient host unit did not become healthy within ${WAIT_SECONDS}s." >&2
echo "Unit: ${UNIT_NAME}.service" >&2
echo "URL: ${BASE_URL}/app/" >&2
echo "Health: ${HEALTH_URL}" >&2
echo "Logs: ${LOG_INSTRUCTION}" >&2
$SUDO systemctl status "${UNIT_NAME}.service" --no-pager >&2 || true
exit 1
