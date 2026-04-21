#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

bash "${REPO_ROOT}/scripts/bootstrap_kali_host.sh"
bash "${REPO_ROOT}/scripts/install_security_tools.sh"
bash "${REPO_ROOT}/scripts/install_host_service.sh"

echo "AegisPT host bootstrap and service install complete."
