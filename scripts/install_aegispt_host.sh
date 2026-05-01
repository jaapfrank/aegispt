#!/usr/bin/env bash
set -euo pipefail

info() {
  printf '[AegisPT installer] %s\n' "$*"
}

warn() {
  printf '[AegisPT installer] WARNING: %s\n' "$*" >&2
}

die() {
  printf '[AegisPT installer] ERROR: %s\n' "$*" >&2
  exit 1
}

generate_fernet_key() {
  python3 -c 'import base64, os; print(base64.urlsafe_b64encode(os.urandom(32)).decode("ascii"))'
}

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_PATH="${AEGISPT_HOST_ENV_PATH:-/srv/aegispt/env/aegispt-host.env}"
SERVICE_NAME="${AEGISPT_SYSTEMD_SERVICE_NAME:-aegispt.service}"
PORT="${AEGISPT_PORT:-8000}"

if [[ "${REPO_ROOT}" == *" "* ]]; then
  die "Install the repository in a path without spaces. Recommended path: /opt/aegispt/repo"
fi

if [[ "${EUID}" -ne 0 ]] && ! command -v sudo >/dev/null 2>&1; then
  die "sudo is required when the installer is not run as root"
fi

if [[ -r /etc/os-release ]]; then
  # shellcheck disable=SC1091
  source /etc/os-release
  OS_LABEL="${PRETTY_NAME:-${ID:-unknown}}"
  info "Detected host: ${OS_LABEL}"
  case "${ID:-}" in
    kali|debian|ubuntu) ;;
    *) warn "This installer is optimized for Kali, Debian, and Ubuntu hosts." ;;
  esac
else
  warn "Could not read /etc/os-release; continuing with generic Linux assumptions."
fi

if [[ "${AEGISPT_SKIP_BOOTSTRAP:-0}" != "1" ]]; then
  info "Installing host dependencies and Docker support"
  bash "${REPO_ROOT}/scripts/bootstrap_kali_host.sh"
else
  warn "Skipping host bootstrap because AEGISPT_SKIP_BOOTSTRAP=1"
fi

if [[ ! -f "${ENV_PATH}" && -z "${AEGISPT_LOCAL_SECRET_ENCRYPTION_KEY:-}" ]]; then
  info "Generating a host-local encryption key for ${ENV_PATH}"
  export AEGISPT_LOCAL_SECRET_ENCRYPTION_KEY
  AEGISPT_LOCAL_SECRET_ENCRYPTION_KEY="$(generate_fernet_key)"
fi

if [[ "${AEGISPT_SKIP_SECURITY_TOOLS:-0}" != "1" ]]; then
  info "Installing security toolchain"
  bash "${REPO_ROOT}/scripts/install_security_tools.sh"
else
  warn "Skipping security tools because AEGISPT_SKIP_SECURITY_TOOLS=1"
fi

if [[ "${AEGISPT_SKIP_SERVICE_INSTALL:-0}" != "1" ]]; then
  info "Configuring and starting ${SERVICE_NAME}"
  bash "${REPO_ROOT}/scripts/install_host_service.sh"
else
  warn "Skipping systemd service install because AEGISPT_SKIP_SERVICE_INSTALL=1"
fi

info "AegisPT ready at http://localhost:${PORT}/app/"
info "Health: http://localhost:${PORT}/health/live"
info "Environment file: ${ENV_PATH}"
info "Logs: journalctl -u ${SERVICE_NAME} -f"
