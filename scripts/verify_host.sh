#!/usr/bin/env bash
set -euo pipefail

echo "Verifying Docker"
docker --version
if command -v docker-compose >/dev/null 2>&1; then
  docker-compose version
else
  docker compose version
fi

echo "Verifying Python"
python3 --version

echo "Verifying security tools"
nuclei -version
zaproxy -version
nmap --version | head -n 1
httpx-toolkit -version || true
ffuf -V
feroxbuster --version
if command -v testssl.sh >/dev/null 2>&1; then
  testssl.sh --version
else
  testssl --version
fi
if command -v semgrep >/dev/null 2>&1; then
  semgrep --version
else
  "${HOME}/.local/bin/semgrep" --version
fi

echo "Host verification complete."
