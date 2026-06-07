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
CURL_TIMEOUT_SECONDS="${AEGISPT_LOCAL_HEALTH_CURL_TIMEOUT_SECONDS:-2}"
PORT_RELEASE_SECONDS="${AEGISPT_LOCAL_PORT_RELEASE_SECONDS:-8}"

listener_pids() {
  if command -v lsof >/dev/null 2>&1; then
    { lsof -nP -iTCP:"${PORT}" -sTCP:LISTEN -t 2>/dev/null || true; } | sort -u
    return 0
  fi
  if command -v fuser >/dev/null 2>&1; then
    { fuser "${PORT}/tcp" 2>/dev/null || true; } | tr ' ' '\n' | sed '/^$/d' | sort -u
    return 0
  fi
  if command -v ss >/dev/null 2>&1; then
    { ss -H -ltnp "sport = :${PORT}" 2>/dev/null || true; } \
      | sed -n 's/.*pid=\([0-9][0-9]*\).*/\1/p' \
      | sort -u
    return 0
  fi
  return 0
}

pid_command() {
  local pid="$1"
  if [[ -r "/proc/${pid}/cmdline" ]]; then
    tr '\0' ' ' <"/proc/${pid}/cmdline" 2>/dev/null || true
    return 0
  fi
  ps -p "${pid}" -o command= 2>/dev/null || true
}

is_aegispt_inline_host() {
  local pid="$1"
  local cmd
  cmd="$(pid_command "${pid}")"
  [[ "${cmd}" == *"uvicorn"* && "${cmd}" == *"api.app.main:create_app"* ]]
}

describe_port_listeners() {
  local found=0
  for pid in $(listener_pids); do
    found=1
    echo "pid=${pid} command=$(pid_command "${pid}")" >&2
  done
  if [[ "${found}" == "0" ]]; then
    echo "no TCP listeners found on ${HOST}:${PORT}" >&2
  fi
}

ensure_port_released() {
  local deadline="${1}"
  local pids aegispt_pids=() other_pids=()

  for ((i=1; i<=deadline; i+=1)); do
    pids="$(listener_pids | tr '\n' ' ')"
    if [[ -z "${pids// }" ]]; then
      return 0
    fi
    sleep 1
  done

  while read -r pid; do
    [[ -z "${pid}" ]] && continue
    if is_aegispt_inline_host "${pid}"; then
      aegispt_pids+=("${pid}")
    else
      other_pids+=("${pid}")
    fi
  done < <(listener_pids)

  if ((${#other_pids[@]} > 0)); then
    echo "Port ${HOST}:${PORT} is still occupied by a non-AegisPT process; refusing to replace it." >&2
    describe_port_listeners
    return 1
  fi

  if ((${#aegispt_pids[@]} > 0)); then
    echo "Port ${HOST}:${PORT} is still held by draining AegisPT host process(es): ${aegispt_pids[*]}. Terminating." >&2
    kill -TERM "${aegispt_pids[@]}" >/dev/null 2>&1 || true
    sleep 2
    while read -r pid; do
      [[ -z "${pid}" ]] && continue
      if is_aegispt_inline_host "${pid}"; then
        echo "AegisPT host pid=${pid} did not exit after TERM; sending KILL." >&2
        kill -KILL "${pid}" >/dev/null 2>&1 || true
      fi
    done < <(listener_pids)
  fi

  for ((i=1; i<=deadline; i+=1)); do
    if [[ -z "$(listener_pids | tr '\n' ' ')" ]]; then
      return 0
    fi
    sleep 1
  done

  echo "Port ${HOST}:${PORT} did not release after stale host termination." >&2
  describe_port_listeners
  return 1
}

export PLAYWRIGHT_BROWSERS_PATH="${PLAYWRIGHT_BROWSERS_PATH:-/opt/aegispt/ms-playwright}"

bash "${REPO_ROOT}/scripts/ensure_playwright_chromium.sh"
"${REPO_ROOT}/.venv/bin/python" "${REPO_ROOT}/scripts/repair_local_sqlite_schema.py"
"${REPO_ROOT}/.venv/bin/python" -m alembic upgrade head

$SUDO systemctl stop "${UNIT_NAME}.service" >/dev/null 2>&1 || true
pkill -f "uvicorn .*api.app.main:create_app.*--host ${HOST}.*--port ${PORT}" >/dev/null 2>&1 || true
pkill -f "uvicorn .*api.app.main:create_app.*--port ${PORT}" >/dev/null 2>&1 || true
ensure_port_released "${PORT_RELEASE_SECONDS}"

$SUDO systemd-run \
  --unit="${UNIT_NAME}" \
  --property="WorkingDirectory=${REPO_ROOT}" \
  --setenv=PYTHONUNBUFFERED=1 \
  --setenv=DATABASE_URL="${DATABASE_URL:-postgresql+psycopg://aegispt:aegispt_dev_pw@127.0.0.1:5432/aegispt}" \
  --setenv=TASK_DISPATCH_MODE="${TASK_DISPATCH_MODE:-inline}" \
  --setenv=INLINE_DISPATCH_BACKGROUND="${INLINE_DISPATCH_BACKGROUND:-true}" \
  --setenv=RUNNER_TIMEOUT_SECONDS="${RUNNER_TIMEOUT_SECONDS:-60.0}" \
  --setenv=ARTIFACTS_STORAGE_MODE="${ARTIFACTS_STORAGE_MODE:-inline}" \
  --setenv=APP_PUBLIC_BASE_URL="${BASE_URL}" \
  --setenv=PLAYWRIGHT_BROWSERS_PATH="${PLAYWRIGHT_BROWSERS_PATH}" \
  "${REPO_ROOT}/.venv/bin/python" -m uvicorn api.app.main:create_app --factory --host "${HOST}" --port "${PORT}" >/dev/null

for ((i=1; i<=WAIT_SECONDS; i+=1)); do
  if curl --max-time "${CURL_TIMEOUT_SECONDS}" --fail --silent "${HEALTH_URL}" >/dev/null 2>&1; then
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
echo "Port listener diagnostics:" >&2
describe_port_listeners
echo "Last health probe output:" >&2
curl --max-time "${CURL_TIMEOUT_SECONDS}" --silent --show-error "${HEALTH_URL}" >&2 || true
$SUDO systemctl status "${UNIT_NAME}.service" --no-pager >&2 || true
exit 1
