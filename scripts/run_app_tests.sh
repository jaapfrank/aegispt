#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

if [[ ! -x "${REPO_ROOT}/.venv/bin/python" ]]; then
  echo "Missing virtual environment. Run bash scripts/setup_python_dev.sh first." >&2
  exit 1
fi

export PLAYWRIGHT_BROWSERS_PATH="${PLAYWRIGHT_BROWSERS_PATH:-${REPO_ROOT}/.playwright-browsers}"

test_files=(
  "ui/tests/test_operator_console_smoke_e2e.py"
  "ui/tests/test_mockup_port_e2e.py"
)

if [[ "${AEGISPT_APP_TESTS_INCLUDE_PROBLEMS:-${AEGISPT_UI_FAST_INCLUDE_PROBLEMS:-0}}" == "1" ]]; then
  test_files+=("ui/tests/test_problems_center_e2e.py")
fi

"${REPO_ROOT}/.venv/bin/python" -m pytest \
  --capture=no \
  -m ui_fast \
  "${test_files[@]}" \
  "$@"
