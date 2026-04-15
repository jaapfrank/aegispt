#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -eq 0 ]]; then
  SUDO=""
else
  SUDO="sudo"
fi

OWNER_USER="${SUDO_USER:-$USER}"

$SUDO apt update
$SUDO apt install -y \
  zaproxy nuclei nmap httpx-toolkit ffuf feroxbuster testssl.sh \
  metasploit-framework

if [[ "${EUID}" -eq 0 && "${OWNER_USER}" != "root" ]]; then
  su - "${OWNER_USER}" -c "pipx ensurepath"
  if ! su - "${OWNER_USER}" -c "command -v semgrep >/dev/null 2>&1"; then
    su - "${OWNER_USER}" -c "pipx install semgrep"
  fi
else
  pipx ensurepath
  if ! command -v semgrep >/dev/null 2>&1; then
    pipx install semgrep
  fi
fi

echo "Security tooling installation complete."
