#!/usr/bin/env bash
set -euo pipefail

ZAP_BASE_URL="${ZAP_BASE_URL:-http://127.0.0.1:8080}"
ZAP_API_KEY="${ZAP_API_KEY:-change-me-zap-key}"
ZAP_WAIT_SECONDS="${AEGISPT_LOCAL_ZAP_WAIT_SECONDS:-30}"
ZAP_LOG_PATH="${AEGISPT_LOCAL_ZAP_LOG:-/tmp/aegispt-zap.log}"
ZAP_BINARY="${AEGISPT_LOCAL_ZAP_BINARY:-/usr/local/bin/zap.sh}"

version_url="${ZAP_BASE_URL%/}/JSON/core/view/version/?apikey=${ZAP_API_KEY}"

if curl --fail --silent "${version_url}" >/dev/null 2>&1; then
  echo "ZAP daemon already reachable at ${ZAP_BASE_URL}."
  exit 0
fi

if [[ "${ZAP_BASE_URL}" != "http://127.0.0.1:8080" && "${ZAP_BASE_URL}" != "http://localhost:8080" ]]; then
  echo "ZAP daemon is not reachable at ${ZAP_BASE_URL}, and auto-start only supports the local default base URL." >&2
  exit 1
fi

if [[ ! -x "${ZAP_BINARY}" ]]; then
  echo "Missing ZAP binary at ${ZAP_BINARY}." >&2
  exit 1
fi

rm -f "${ZAP_LOG_PATH}"

if command -v setsid >/dev/null 2>&1; then
  setsid "${ZAP_BINARY}" \
    -daemon \
    -silent \
    -host 127.0.0.1 \
    -port 8080 \
    -config "api.key=${ZAP_API_KEY}" \
    -config "api.addrs.addr.name=127.0.0.1" \
    -config "api.addrs.addr.regex=false" \
    >"${ZAP_LOG_PATH}" 2>&1 < /dev/null &
else
  nohup "${ZAP_BINARY}" \
    -daemon \
    -silent \
    -host 127.0.0.1 \
    -port 8080 \
    -config "api.key=${ZAP_API_KEY}" \
    -config "api.addrs.addr.name=127.0.0.1" \
    -config "api.addrs.addr.regex=false" \
    >"${ZAP_LOG_PATH}" 2>&1 < /dev/null &
fi

for ((i=1; i<=ZAP_WAIT_SECONDS; i+=1)); do
  if curl --fail --silent "${version_url}" >/dev/null 2>&1; then
    echo "ZAP daemon ready at ${ZAP_BASE_URL}."
    echo "Log: ${ZAP_LOG_PATH}"
    exit 0
  fi
  sleep 1
done

echo "ZAP daemon did not become reachable within ${ZAP_WAIT_SECONDS}s." >&2
echo "Base URL: ${ZAP_BASE_URL}" >&2
echo "Log: ${ZAP_LOG_PATH}" >&2
tail -n 80 "${ZAP_LOG_PATH}" >&2 || true
exit 1
