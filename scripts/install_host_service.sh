#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -eq 0 ]]; then
  SUDO=""
else
  SUDO="sudo"
fi

OWNER_USER="${SUDO_USER:-$USER}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_PATH="${AEGISPT_HOST_ENV_PATH:-/srv/aegispt/env/aegispt-host.env}"
SERVICE_NAME="${AEGISPT_SYSTEMD_SERVICE_NAME:-aegispt.service}"
SERVICE_PATH="/etc/systemd/system/${SERVICE_NAME}"
TEMPLATE_PATH="${REPO_ROOT}/infra/systemd/aegispt.service.template"

if [[ "${REPO_ROOT}" == *" "* ]]; then
  echo "Install the repository in a path without spaces before creating a systemd service." >&2
  echo "Recommended path: /opt/aegispt/repo" >&2
  exit 1
fi

if ! command -v systemctl >/dev/null 2>&1; then
  echo "systemd/systemctl is required for host service installation." >&2
  exit 1
fi

if [[ ! -f "${TEMPLATE_PATH}" ]]; then
  echo "Missing systemd template: ${TEMPLATE_PATH}" >&2
  exit 1
fi

run_as_owner() {
  local command="$1"
  if [[ "${EUID}" -eq 0 && "${OWNER_USER}" != "root" ]]; then
    su - "${OWNER_USER}" -s /bin/bash -c "${command}"
  else
    bash -lc "${command}"
  fi
}

bash "${REPO_ROOT}/scripts/init_runtime_dirs.sh"
run_as_owner "cd '${REPO_ROOT}' && bash scripts/setup_python_dev.sh"

if [[ ! -f "${ENV_PATH}" ]]; then
  bash "${REPO_ROOT}/scripts/generate_host_env.sh" "${ENV_PATH}"
fi

$SUDO chown "${OWNER_USER}:${OWNER_USER}" "${ENV_PATH}"
$SUDO chmod 600 "${ENV_PATH}"

set -a
# shellcheck disable=SC1090
source "${ENV_PATH}"
set +a

PLAYWRIGHT_BROWSERS_PATH="${PLAYWRIGHT_BROWSERS_PATH:-/opt/aegispt/ms-playwright}"
AEGISPT_PLAYWRIGHT_INSTALL_WITH_DEPS=1 \
  bash "${REPO_ROOT}/scripts/ensure_playwright_chromium.sh"

run_as_owner "cd '${REPO_ROOT}' && set -a && source '${ENV_PATH}' && set +a && .venv/bin/alembic upgrade head"

RUN_SCRIPT="${REPO_ROOT}/scripts/run_host_api.sh"
sed \
  -e "s|__OWNER_USER__|${OWNER_USER}|g" \
  -e "s|__REPO_ROOT__|${REPO_ROOT}|g" \
  -e "s|__ENV_PATH__|${ENV_PATH}|g" \
  -e "s|__RUN_SCRIPT__|${RUN_SCRIPT}|g" \
  "${TEMPLATE_PATH}" | $SUDO tee "${SERVICE_PATH}" >/dev/null

$SUDO systemctl daemon-reload
$SUDO systemctl enable "${SERVICE_NAME}"
if $SUDO systemctl is-active --quiet "${SERVICE_NAME}"; then
  $SUDO systemctl restart "${SERVICE_NAME}"
else
  $SUDO systemctl start "${SERVICE_NAME}"
fi

PORT="${AEGISPT_PORT:-8000}"
for _ in {1..20}; do
  if curl --fail --silent "http://127.0.0.1:${PORT}/health/live" >/dev/null; then
    break
  fi
  sleep 1
done

curl --fail --silent "http://127.0.0.1:${PORT}/health/live" >/dev/null
curl --fail --silent "http://127.0.0.1:${PORT}/app/" >/dev/null

echo "AegisPT host service installed."
echo "Service: ${SERVICE_NAME}"
echo "Environment file: ${ENV_PATH}"
echo "UI: http://127.0.0.1:${PORT}/app/"
echo "Logs: journalctl -u ${SERVICE_NAME} -f"
