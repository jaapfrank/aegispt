#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -eq 0 ]]; then
  SUDO=""
else
  SUDO="sudo"
fi

OWNER_USER="${SUDO_USER:-$USER}"

$SUDO mkdir -p /opt/aegispt/repo
$SUDO mkdir -p /opt/aegispt/bootstrap
$SUDO mkdir -p /srv/aegispt/{env,postgres,minio,reports,artifacts,backups}
$SUDO mkdir -p /var/log/aegispt/app

$SUDO chown -R "$OWNER_USER:$OWNER_USER" /opt/aegispt
$SUDO chown -R "$OWNER_USER:$OWNER_USER" /srv/aegispt
$SUDO chown -R "$OWNER_USER:$OWNER_USER" /var/log/aegispt

echo "Runtime directories initialized."
