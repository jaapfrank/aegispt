#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

if [[ ! -x "${REPO_ROOT}/.venv/bin/python" ]]; then
  echo "Missing virtual environment. Run bash scripts/setup_python_dev.sh first." >&2
  exit 1
fi

PORT="${AEGISPT_PORT:-8000}"
HOST="${AEGISPT_BIND_HOST:-127.0.0.1}"
BASE_URL="${APP_PUBLIC_BASE_URL:-http://${HOST}:${PORT}}"
LOG_PATH="${AEGISPT_LOCAL_HOST_LOG:-/tmp/aegispt-inline-host.log}"
HEALTH_URL="${BASE_URL%/}/health/live"
WAIT_SECONDS="${AEGISPT_LOCAL_HOST_WAIT_SECONDS:-20}"

pkill -f "uvicorn api.app.main:create_app --factory --host ${HOST} --port ${PORT}" >/dev/null 2>&1 || true

export PYTHONUNBUFFERED=1
export TASK_DISPATCH_MODE="${TASK_DISPATCH_MODE:-inline}"
export INLINE_DISPATCH_BACKGROUND="${INLINE_DISPATCH_BACKGROUND:-true}"
export RUNNER_TIMEOUT_SECONDS="${RUNNER_TIMEOUT_SECONDS:-60.0}"
export ARTIFACTS_STORAGE_MODE="${ARTIFACTS_STORAGE_MODE:-inline}"
export APP_PUBLIC_BASE_URL="${BASE_URL}"
export PLAYWRIGHT_BROWSERS_PATH="${PLAYWRIGHT_BROWSERS_PATH:-/opt/aegispt/ms-playwright}"
export ZAP_BASE_URL="${ZAP_BASE_URL:-http://127.0.0.1:8080}"
export ZAP_API_KEY="${ZAP_API_KEY:-change-me-zap-key}"
export AEGISPT_LOCAL_ENSURE_ZAP="${AEGISPT_LOCAL_ENSURE_ZAP:-1}"

bash "${REPO_ROOT}/scripts/ensure_playwright_chromium.sh"
if [[ "${AEGISPT_LOCAL_ENSURE_ZAP}" == "1" ]]; then
  bash "${REPO_ROOT}/scripts/ensure_local_zap_daemon.sh"
fi
"${REPO_ROOT}/.venv/bin/python" "${REPO_ROOT}/scripts/repair_local_sqlite_schema.py"
"${REPO_ROOT}/.venv/bin/python" -m alembic upgrade head

if command -v setsid >/dev/null 2>&1; then
  setsid "${REPO_ROOT}/.venv/bin/python" -m uvicorn \
    api.app.main:create_app \
    --factory \
    --host "${HOST}" \
    --port "${PORT}" \
    >"${LOG_PATH}" 2>&1 < /dev/null &
else
  nohup "${REPO_ROOT}/.venv/bin/python" -m uvicorn \
    api.app.main:create_app \
    --factory \
    --host "${HOST}" \
    --port "${PORT}" \
    >"${LOG_PATH}" 2>&1 < /dev/null &
fi

for ((i=1; i<=WAIT_SECONDS; i+=1)); do
  if curl --fail --silent "${HEALTH_URL}" >/dev/null 2>&1; then
    echo "AegisPT inline host restarted."
    echo "URL: ${BASE_URL}/app/"
    echo "Health: ${HEALTH_URL}"
    echo "Log: ${LOG_PATH}"
    exit 0
  fi
  sleep 1
done

echo "AegisPT inline host did not become healthy within ${WAIT_SECONDS}s." >&2
echo "URL: ${BASE_URL}/app/" >&2
echo "Health: ${HEALTH_URL}" >&2
echo "Log: ${LOG_PATH}" >&2
tail -n 80 "${LOG_PATH}" >&2 || true
exit 1
