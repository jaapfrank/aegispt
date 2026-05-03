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
KERBRUTE_VERSION="${KERBRUTE_VERSION:-1.0.3}"
SUBFINDER_VERSION="${SUBFINDER_VERSION:-2.13.0}"
AEGISPT_INSTALL_METASPLOIT="${AEGISPT_INSTALL_METASPLOIT:-auto}"
METASPLOIT_INSTALL_URL="${METASPLOIT_INSTALL_URL:-https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb}"

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

install_apt_if_available() {
  local package_name="$1"
  if apt-cache show "${package_name}" >/dev/null 2>&1; then
    $SUDO apt install -y "${package_name}"
  else
    echo "Skipping ${package_name}: package not available in current apt sources."
  fi
}

link_owner_bin() {
  local binary_name="$1"
  if [[ -x "${OWNER_HOME}/.local/bin/${binary_name}" ]]; then
    $SUDO ln -sf "${OWNER_HOME}/.local/bin/${binary_name}" "/usr/local/bin/${binary_name}"
  fi
}

install_pipx_if_missing() {
  local command_name="$1"
  local package_spec="$2"
  if command -v "${command_name}" >/dev/null 2>&1 || [[ -x "${OWNER_HOME}/.local/bin/${command_name}" ]]; then
    link_owner_bin "${command_name}"
    return
  fi
  run_as_owner "TMPDIR=/tmp env -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY -u http_proxy -u https_proxy -u all_proxy python3 -m pipx install ${package_spec}"
  link_owner_bin "${command_name}"
}

install_responder_if_missing() {
  if command -v responder >/dev/null 2>&1; then
    return
  fi
  if apt-cache show responder >/dev/null 2>&1; then
    $SUDO apt install -y responder
    return
  fi
  proxy_clean_env git clone --depth 1 https://github.com/lgandx/Responder.git "${WORKDIR}/Responder"
  $SUDO rm -rf /opt/Responder
  $SUDO mv "${WORKDIR}/Responder" /opt/Responder
  cat <<'EOF' | $SUDO tee /usr/local/bin/responder >/dev/null
#!/usr/bin/env bash
exec python3 /opt/Responder/Responder.py "$@"
EOF
  $SUDO chmod 0755 /usr/local/bin/responder
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
    KERBRUTE_ARCH="amd64"
    SUBFINDER_ARCH="amd64"
    ;;
  aarch64|arm64)
    NUCLEI_ARCH="arm64"
    HTTPX_ARCH="arm64"
    FEROXBUSTER_ARCHIVE="aarch64-linux-feroxbuster.zip"
    KERBRUTE_ARCH="arm64"
    SUBFINDER_ARCH="arm64"
    ;;
  *)
    echo "Unsupported architecture for pinned security tooling: ${ARCH}" >&2
    exit 1
    ;;
esac

$SUDO apt update
$SUDO apt install -y \
  curl unzip tar ca-certificates pipx git python3-venv python3-aioquic \
  openjdk-17-jre-headless \
  nmap ffuf testssl.sh hashcat ssh-audit ldap-utils \
  snmp iw aircrack-ng wireless-tools

install_apt_if_available "impacket-scripts"
install_apt_if_available "netexec"
install_apt_if_available "bloodhound.py"

if command -v testssl >/dev/null 2>&1 && ! command -v testssl.sh >/dev/null 2>&1; then
  $SUDO ln -sf "$(command -v testssl)" /usr/local/bin/testssl.sh
fi

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
link_owner_bin "semgrep"

install_pipx_if_missing "bloodhound-python" "bloodhound"
install_pipx_if_missing "aws" "awscli"
install_pipx_if_missing "psexec.py" "impacket"
link_owner_bin "wmiexec.py"
link_owner_bin "secretsdump.py"
link_owner_bin "GetUserSPNs.py"
link_owner_bin "GetNPUsers.py"

if command -v secretsdump.py >/dev/null 2>&1 && ! command -v impacket-secretsdump >/dev/null 2>&1; then
  $SUDO ln -sf "$(command -v secretsdump.py)" /usr/local/bin/impacket-secretsdump
fi
if command -v psexec.py >/dev/null 2>&1 && ! command -v impacket-psexec >/dev/null 2>&1; then
  $SUDO ln -sf "$(command -v psexec.py)" /usr/local/bin/impacket-psexec
fi
if command -v wmiexec.py >/dev/null 2>&1 && ! command -v impacket-wmiexec >/dev/null 2>&1; then
  $SUDO ln -sf "$(command -v wmiexec.py)" /usr/local/bin/impacket-wmiexec
fi

if ! command -v nxc >/dev/null 2>&1 && [[ ! -x "${OWNER_HOME}/.local/bin/nxc" ]]; then
  run_as_owner "TMPDIR=/tmp env -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY -u http_proxy -u https_proxy -u all_proxy python3 -m pipx install git+https://github.com/Pennyw0rth/NetExec.git"
fi
link_owner_bin "nxc"
link_owner_bin "netexec"
link_owner_bin "NetExec"
link_owner_bin "nxcdb"

install_responder_if_missing

if ! command -v kerbrute >/dev/null 2>&1; then
  download_to \
    "https://github.com/ropnop/kerbrute/releases/download/v${KERBRUTE_VERSION}/kerbrute_linux_${KERBRUTE_ARCH}" \
    "${WORKDIR}/kerbrute"
  $SUDO install -m 0755 "${WORKDIR}/kerbrute" /usr/local/bin/kerbrute
fi

if ! command -v subfinder >/dev/null 2>&1; then
  install_zip_binary \
    "https://github.com/projectdiscovery/subfinder/releases/download/v${SUBFINDER_VERSION}/subfinder_${SUBFINDER_VERSION}_linux_${SUBFINDER_ARCH}.zip" \
    "subfinder" \
    "subfinder"
fi

if [[ "${AEGISPT_INSTALL_METASPLOIT}" == "always" ]]; then
  if apt-cache show metasploit-framework >/dev/null 2>&1; then
    $SUDO apt install -y metasploit-framework
  else
    download_to "${METASPLOIT_INSTALL_URL}" "${WORKDIR}/msfinstall"
    chmod 0755 "${WORKDIR}/msfinstall"
    $SUDO "${WORKDIR}/msfinstall"
  fi
elif [[ "${AEGISPT_INSTALL_METASPLOIT}" == "auto" ]] && apt-cache show metasploit-framework >/dev/null 2>&1; then
  $SUDO apt install -y metasploit-framework
elif [[ "${AEGISPT_INSTALL_METASPLOIT}" == "auto" ]]; then
  download_to "${METASPLOIT_INSTALL_URL}" "${WORKDIR}/msfinstall"
  chmod 0755 "${WORKDIR}/msfinstall"
  $SUDO "${WORKDIR}/msfinstall"
else
  echo "Skipping metasploit-framework: package not available in current apt sources."
fi

echo "Security tooling installation complete."
