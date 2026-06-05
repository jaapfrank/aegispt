#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "run_ui_fast_tests.sh runs legacy /app fast tests. Use scripts/run_app_v2_tests.sh for React /app-v2." >&2
exec "${REPO_ROOT}/scripts/run_app_tests.sh" "$@"
