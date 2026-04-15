#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -eq 0 ]]; then
  SUDO=""
else
  SUDO="sudo"
fi

OWNER_USER="${SUDO_USER:-$USER}"
OWNER_HOME="$(getent passwd "${OWNER_USER}" | cut -d: -f6)"
if [[ -z "${OWNER_HOME}" ]]; then
  OWNER_HOME="${HOME}"
fi

NUCLEI_VERSION="${NUCLEI_VERSION:-3.7.1}"
HTTPX_VERSION="${HTTPX_VERSION:-1.9.0}"
FEROXBUSTER_VERSION="${FEROXBUSTER_VERSION:-2.13.1}"
ZAP_VERSION="${ZAP_VERSION:-2.17.0}"
AEGISPT_INSTALL_METASPLOIT="${AEGISPT_INSTALL_METASPLOIT:-auto}"

WORKDIR="$(mktemp -d)"
trap 'rm -rf "${WORKDIR}"' EXIT

proxy_clean_env() {
  env -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY -u http_proxy -u https_proxy -u all_proxy "$@"
}

run_as_owner() {
  local command="$1"
  if [[ "${EUID}" -eq 0 && "${OWNER_USER}" != "root" ]]; then
    su - "${OWNER_USER}" -c "${command}"
  else
    bash -lc "${command}"
  fi
}

download_to() {
  local url="$1"
  local destination="$2"
  proxy_clean_env curl -fsSL "${url}" -o "${destination}"
}

install_zip_binary() {
  local url="$1"
  local binary_name="$2"
  local destination_name="$3"
  local archive_path="${WORKDIR}/${destination_name}.zip"

  download_to "${url}" "${archive_path}"
  unzip -oq "${archive_path}" "${binary_name}" -d "${WORKDIR}/${destination_name}"
  $SUDO install -m 0755 "${WORKDIR}/${destination_name}/${binary_name}" "/usr/local/bin/${destination_name}"
}

ARCH="$(uname -m)"
case "${ARCH}" in
  x86_64|amd64)
    NUCLEI_ARCH="amd64"
    HTTPX_ARCH="amd64"
    FEROXBUSTER_ARCHIVE="x86_64-linux-feroxbuster.tar.gz"
    ;;
  aarch64|arm64)
    NUCLEI_ARCH="arm64"
    HTTPX_ARCH="arm64"
    FEROXBUSTER_ARCHIVE="aarch64-linux-feroxbuster.zip"
    ;;
  *)
    echo "Unsupported architecture for pinned security tooling: ${ARCH}" >&2
    exit 1
    ;;
esac

$SUDO apt update
$SUDO apt install -y \
  curl unzip tar ca-certificates pipx \
  openjdk-17-jre-headless \
  nmap ffuf testssl.sh

install_zip_binary \
  "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${NUCLEI_ARCH}.zip" \
  "nuclei" \
  "nuclei"

install_zip_binary \
  "https://github.com/projectdiscovery/httpx/releases/download/v${HTTPX_VERSION}/httpx_${HTTPX_VERSION}_linux_${HTTPX_ARCH}.zip" \
  "httpx" \
  "httpx-toolkit"

if [[ ! -e /usr/local/bin/httpx ]]; then
  $SUDO ln -sf /usr/local/bin/httpx-toolkit /usr/local/bin/httpx
fi

if [[ "${FEROXBUSTER_ARCHIVE}" == *.tar.gz ]]; then
  download_to \
    "https://github.com/epi052/feroxbuster/releases/download/v${FEROXBUSTER_VERSION}/${FEROXBUSTER_ARCHIVE}" \
    "${WORKDIR}/feroxbuster.tar.gz"
  mkdir -p "${WORKDIR}/feroxbuster"
  tar -xzf "${WORKDIR}/feroxbuster.tar.gz" -C "${WORKDIR}/feroxbuster"
  $SUDO install -m 0755 "${WORKDIR}/feroxbuster/feroxbuster" /usr/local/bin/feroxbuster
else
  install_zip_binary \
    "https://github.com/epi052/feroxbuster/releases/download/v${FEROXBUSTER_VERSION}/${FEROXBUSTER_ARCHIVE}" \
    "feroxbuster" \
    "feroxbuster"
fi

download_to \
  "https://github.com/zaproxy/zaproxy/releases/download/v${ZAP_VERSION}/ZAP_${ZAP_VERSION}_Linux.tar.gz" \
  "${WORKDIR}/zaproxy.tar.gz"
$SUDO rm -rf "/opt/ZAP_${ZAP_VERSION}"
$SUDO mkdir -p /opt
$SUDO tar -xzf "${WORKDIR}/zaproxy.tar.gz" -C /opt
cat <<EOF | $SUDO tee /usr/local/bin/zaproxy >/dev/null
#!/usr/bin/env bash
exec /opt/ZAP_${ZAP_VERSION}/zap.sh "\$@"
EOF
$SUDO chmod 0755 /usr/local/bin/zaproxy
$SUDO ln -sf "/opt/ZAP_${ZAP_VERSION}/zap.sh" /usr/local/bin/zap.sh

if [[ ! -x "${OWNER_HOME}/.local/bin/semgrep" ]]; then
  run_as_owner "env -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY -u http_proxy -u https_proxy -u all_proxy python3 -m pipx ensurepath"
  run_as_owner "env -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY -u http_proxy -u https_proxy -u all_proxy python3 -m pipx install semgrep"
fi

if [[ "${AEGISPT_INSTALL_METASPLOIT}" == "always" ]]; then
  $SUDO apt install -y metasploit-framework
elif [[ "${AEGISPT_INSTALL_METASPLOIT}" == "auto" ]] && apt-cache show metasploit-framework >/dev/null 2>&1; then
  $SUDO apt install -y metasploit-framework
else
  echo "Skipping metasploit-framework: package not available in current apt sources."
fi

echo "Security tooling installation complete."
