#!/usr/bin/env bash
set -euo pipefail

OWNER_USER="${SUDO_USER:-$USER}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

bash "${REPO_ROOT}/scripts/bootstrap_kali_host.sh"
bash "${REPO_ROOT}/scripts/install_security_tools.sh"
bash "${REPO_ROOT}/scripts/init_runtime_dirs.sh"

if [[ "${EUID}" -eq 0 && "${OWNER_USER}" != "root" ]]; then
  su - "${OWNER_USER}" -c "cd '${REPO_ROOT}' && bash scripts/setup_python_dev.sh"
  su - "${OWNER_USER}" -c "cd '${REPO_ROOT}' && bash scripts/verify_host.sh"
else
  bash "${REPO_ROOT}/scripts/setup_python_dev.sh"
  bash "${REPO_ROOT}/scripts/verify_host.sh"
fi

echo "Kali VM provisioned for AegisPT bootstrap."
