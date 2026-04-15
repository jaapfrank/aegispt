#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -eq 0 ]]; then
  SUDO=""
else
  SUDO="sudo"
fi

OWNER_USER="${SUDO_USER:-$USER}"
AEGISPT_TIMEZONE="${AEGISPT_TIMEZONE:-Europe/Amsterdam}"

$SUDO apt update
$SUDO apt full-upgrade -y
$SUDO apt install -y \
  git curl wget jq unzip zip ca-certificates gnupg lsb-release \
  build-essential make tree tmux htop ripgrep \
  pipx python3 python3-venv python3-pip \
  docker.io docker-compose

$SUDO systemctl enable --now docker
$SUDO usermod -aG docker "$OWNER_USER"

cat <<'EOF' | $SUDO tee /etc/sysctl.d/99-aegispt.conf >/dev/null
vm.overcommit_memory = 1
EOF
$SUDO sysctl -w vm.overcommit_memory=1 >/dev/null

if command -v timedatectl >/dev/null 2>&1; then
  $SUDO timedatectl set-timezone "$AEGISPT_TIMEZONE"
fi

echo "Host bootstrap complete."
