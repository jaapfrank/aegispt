#!/usr/bin/env bash
set -euo pipefail

ZAP_BASE_URL="${ZAP_BASE_URL:-http://127.0.0.1:8080}"
ZAP_API_KEY="${ZAP_API_KEY:-change-me-zap-key}"
ZAP_WAIT_SECONDS="${AEGISPT_LOCAL_ZAP_WAIT_SECONDS:-60}"
ZAP_LOG_PATH="${AEGISPT_LOCAL_ZAP_LOG:-/tmp/aegispt-zap.log}"
ZAP_BINARY="${AEGISPT_LOCAL_ZAP_BINARY:-/usr/local/bin/zap.sh}"
ZAP_JAR="${AEGISPT_LOCAL_ZAP_JAR:-}"
ZAP_CURL_CONNECT_TIMEOUT="${AEGISPT_LOCAL_ZAP_CONNECT_TIMEOUT_SECONDS:-1}"
ZAP_CURL_MAX_TIME="${AEGISPT_LOCAL_ZAP_CURL_TIMEOUT_SECONDS:-2}"

version_url="${ZAP_BASE_URL%/}/JSON/core/view/version/?apikey=${ZAP_API_KEY}"
curl_zap_version() {
  curl \
    --connect-timeout "${ZAP_CURL_CONNECT_TIMEOUT}" \
    --max-time "${ZAP_CURL_MAX_TIME}" \
    --fail \
    --silent \
    "${version_url}"
}

if curl_zap_version >/dev/null 2>&1; then
  echo "ZAP daemon already reachable at ${ZAP_BASE_URL}."
  exit 0
fi

if [[ "${ZAP_BASE_URL}" != "http://127.0.0.1:8080" && "${ZAP_BASE_URL}" != "http://localhost:8080" ]]; then
  echo "ZAP daemon is not reachable at ${ZAP_BASE_URL}, and auto-start only supports the local default base URL." >&2
  exit 1
fi

# Resolve launcher: prefer java -jar (reliable across environments), fall back to zap.sh
_zap_launch_cmd=()
if [[ -z "${ZAP_JAR}" ]]; then
  # Auto-detect jar from zap.sh symlink target directory
  _zap_sh_real="$(readlink -f "${ZAP_BINARY}" 2>/dev/null || echo "${ZAP_BINARY}")"
  _zap_dir="$(dirname "${_zap_sh_real}")"
  _detected_jar="$(ls "${_zap_dir}"/zap-*.jar 2>/dev/null | head -1 || true)"
  if [[ -n "${_detected_jar}" ]]; then
    ZAP_JAR="${_detected_jar}"
  fi
fi

if [[ -n "${ZAP_JAR}" && -f "${ZAP_JAR}" ]]; then
  _zap_launch_cmd=(java -jar "${ZAP_JAR}")
elif [[ -x "${ZAP_BINARY}" ]]; then
  _zap_launch_cmd=("${ZAP_BINARY}")
else
  echo "Cannot find ZAP jar or binary. Set AEGISPT_LOCAL_ZAP_JAR or AEGISPT_LOCAL_ZAP_BINARY." >&2
  exit 1
fi

rm -f "${ZAP_LOG_PATH}"

if command -v setsid >/dev/null 2>&1; then
  setsid "${_zap_launch_cmd[@]}" \
    -daemon \
    -host 127.0.0.1 \
    -port 8080 \
    -config "api.key=${ZAP_API_KEY}" \
    -config "api.addrs.addr.name=127.0.0.1" \
    -config "api.addrs.addr.regex=false" \
    >"${ZAP_LOG_PATH}" 2>&1 < /dev/null &
else
  nohup "${_zap_launch_cmd[@]}" \
    -daemon \
    -host 127.0.0.1 \
    -port 8080 \
    -config "api.key=${ZAP_API_KEY}" \
    -config "api.addrs.addr.name=127.0.0.1" \
    -config "api.addrs.addr.regex=false" \
    >"${ZAP_LOG_PATH}" 2>&1 < /dev/null &
fi

for ((i=1; i<=ZAP_WAIT_SECONDS; i+=1)); do
  if curl_zap_version >/dev/null 2>&1; then
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
