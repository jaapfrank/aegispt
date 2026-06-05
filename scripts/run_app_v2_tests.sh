#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
UI_V2_ROOT="${REPO_ROOT}/ui-v2"

if [[ ! -d "${UI_V2_ROOT}/node_modules" ]]; then
  echo "Missing ui-v2/node_modules. Run cd ui-v2 && npm ci first." >&2
  exit 1
fi

export UI_V2_PLAYWRIGHT_PORT="${UI_V2_PLAYWRIGHT_PORT:-5174}"

cd "${UI_V2_ROOT}"
npm run build
node scripts/check-i18n.mjs
npx playwright test "$@"
