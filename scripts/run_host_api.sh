#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

if [[ ! -x "${REPO_ROOT}/.venv/bin/uvicorn" ]]; then
  echo "Missing virtual environment. Run bash scripts/setup_python_dev.sh first." >&2
  exit 1
fi

export PYTHONUNBUFFERED=1
export PLAYWRIGHT_BROWSERS_PATH="${PLAYWRIGHT_BROWSERS_PATH:-/opt/aegispt/ms-playwright}"
export TASK_DISPATCH_MODE="${TASK_DISPATCH_MODE:-inline}"
export ARTIFACTS_STORAGE_MODE="${ARTIFACTS_STORAGE_MODE:-inline}"

exec "${REPO_ROOT}/.venv/bin/uvicorn" \
  api.app.main:app \
  --host "${AEGISPT_BIND_HOST:-127.0.0.1}" \
  --port "${AEGISPT_PORT:-8000}"
