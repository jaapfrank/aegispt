#!/usr/bin/env bash
set -euo pipefail

if command -v docker-compose >/dev/null 2>&1; then
  COMPOSE="docker-compose"
else
  COMPOSE="docker compose"
fi

API_BASE_URL="http://127.0.0.1:${API_PORT:-8000}"

$COMPOSE -f infra/compose/docker-compose.yml --env-file infra/compose/.env ps
$COMPOSE -f infra/compose/docker-compose.yml --env-file infra/compose/.env logs --tail=50

for endpoint in "/" "/health/live" "/health/ready"; do
  success=0
  for attempt in $(seq 1 10); do
    if curl -fsS "${API_BASE_URL}${endpoint}" >/dev/null; then
      success=1
      break
    fi
    sleep 1
  done
  if [[ "${success}" -ne 1 ]]; then
    echo "Failed to verify endpoint ${endpoint}" >&2
    exit 1
  fi
done

echo "Stack verification complete."
