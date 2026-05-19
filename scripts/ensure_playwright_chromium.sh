#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="${REPO_ROOT}/.venv/bin/python"

if [[ ! -x "${PYTHON_BIN}" ]]; then
  echo "Missing virtual environment. Run bash scripts/setup_python_dev.sh first." >&2
  exit 1
fi

PLAYWRIGHT_BROWSERS_PATH="${PLAYWRIGHT_BROWSERS_PATH:-/opt/aegispt/ms-playwright}"
OWNER_USER="${SUDO_USER:-$USER}"
PLAYWRIGHT_INSTALL_ARGS=(install chromium)

SUDO=()
USE_SUDO=0
if [[ "${EUID}" -ne 0 ]]; then
  if ! { [[ -d "${PLAYWRIGHT_BROWSERS_PATH}" && -w "${PLAYWRIGHT_BROWSERS_PATH}" ]] || { mkdir -p "${PLAYWRIGHT_BROWSERS_PATH}" 2>/dev/null && [[ -w "${PLAYWRIGHT_BROWSERS_PATH}" ]]; }; }; then
    SUDO=(sudo)
    USE_SUDO=1
  fi
fi

if [[ "${AEGISPT_PLAYWRIGHT_INSTALL_WITH_DEPS:-0}" == "1" ]]; then
  PLAYWRIGHT_INSTALL_ARGS=(install --with-deps chromium)
fi

"${SUDO[@]}" mkdir -p "${PLAYWRIGHT_BROWSERS_PATH}"
"${SUDO[@]}" env PLAYWRIGHT_BROWSERS_PATH="${PLAYWRIGHT_BROWSERS_PATH}" \
  "${PYTHON_BIN}" -m playwright "${PLAYWRIGHT_INSTALL_ARGS[@]}" >/dev/null

if [[ "${USE_SUDO}" -eq 1 ]]; then
  "${SUDO[@]}" chown -R "${OWNER_USER}:${OWNER_USER}" "${PLAYWRIGHT_BROWSERS_PATH}"
fi

echo "Playwright Chromium ensured at ${PLAYWRIGHT_BROWSERS_PATH}"
