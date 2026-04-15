#!/usr/bin/env bash
set -euo pipefail

proxy_safe_semgrep() {
  if command -v semgrep >/dev/null 2>&1; then
    env -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY -u http_proxy -u https_proxy -u all_proxy \
      semgrep --version
    return
  fi

  if [[ -x "${HOME}/.local/bin/semgrep" ]]; then
    env -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY -u http_proxy -u https_proxy -u all_proxy \
      "${HOME}/.local/bin/semgrep" --version
    return
  fi

  echo "semgrep is not installed" >&2
  return 1
}

verify_testssl() {
  local output

  if command -v testssl.sh >/dev/null 2>&1; then
    if output="$(timeout 20s testssl.sh --version 2>&1)"; then
      printf '%s\n' "${output}"
    else
      echo "testssl.sh present at $(command -v testssl.sh) (version probe timed out)"
    fi
    return
  fi

  if command -v testssl >/dev/null 2>&1; then
    if output="$(timeout 20s testssl --version 2>&1)"; then
      printf '%s\n' "${output}"
    else
      echo "testssl present at $(command -v testssl) (version probe timed out)"
    fi
    return
  fi

  echo "testssl is not installed" >&2
  return 1
}

echo "Verifying Docker"
docker --version
if command -v docker-compose >/dev/null 2>&1; then
  docker-compose version
else
  docker compose version
fi

echo "Verifying Python"
python3 --version
python3 -m pip --version
python3 -m venv --help >/dev/null
echo "venv support: ok"

echo "Verifying security tools"
nuclei -version
timeout 60s zaproxy -version
nmap --version | head -n 1
httpx-toolkit -version || true
ffuf -V
feroxbuster --version
verify_testssl
proxy_safe_semgrep

echo "Host verification complete."
