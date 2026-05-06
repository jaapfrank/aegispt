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

verify_command() {
  local label="$1"
  shift
  echo "Verifying ${label}"
  timeout 30s "$@" 2>&1 | sed -n '1,12p'
  local status="${PIPESTATUS[0]}"
  if [[ "${status}" -ne 0 ]]; then
    echo "${label} probe exited with ${status}" >&2
    return "${status}"
  fi
}

verify_command_allow_nonzero() {
  local label="$1"
  shift
  echo "Verifying ${label}"
  set +o pipefail
  timeout 30s "$@" 2>&1 | sed -n '1,12p'
  set -o pipefail
}

verify_any_command() {
  local label="$1"
  shift
  echo "Verifying ${label}"
  local candidate
  local last_status=1
  for candidate in "$@"; do
    local binary="${candidate%% *}"
    local args="${candidate#* }"
    if [[ "${binary}" == "${args}" ]]; then
      args=""
    fi
    if command -v "${binary}" >/dev/null 2>&1; then
      set +o pipefail
      timeout 30s bash -lc "${candidate}" 2>&1 | sed -n '1,12p'
      local status="${PIPESTATUS[0]}"
      set -o pipefail
      if [[ "${status}" -eq 0 ]]; then
        return 0
      fi
      echo "${label} probe ${candidate} exited with ${status}" >&2
      last_status="${status}"
    fi
  done
  echo "${label} is not installed; tried: $*" >&2
  return "${last_status}"
}

verify_any_command_allow_nonzero() {
  local label="$1"
  shift
  echo "Verifying ${label}"
  local candidate
  for candidate in "$@"; do
    local binary="${candidate%% *}"
    if command -v "${binary}" >/dev/null 2>&1; then
      set +o pipefail
      timeout 30s bash -lc "${candidate}" 2>&1 | sed -n '1,12p'
      set -o pipefail
      return 0
    fi
  done
  echo "${label} is not installed; tried: $*" >&2
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
verify_command "nuclei" nuclei -version
verify_any_command "ZAP" "zaproxy -version -dir /tmp/aegispt-zap-verify" "zap.sh -version -dir /tmp/aegispt-zap-verify" "zap-baseline.py -h"
verify_command "nmap" nmap --version
verify_any_command "httpx" "httpx-toolkit -version" "httpx -version"
verify_command "ffuf" ffuf -V
verify_any_command "gobuster" "gobuster version" "gobuster --version"
verify_command "feroxbuster" feroxbuster --version
verify_command "nikto" nikto -Version
verify_command "sqlmap" sqlmap --version
verify_command "Hydra" hydra -h
verify_testssl
proxy_safe_semgrep
verify_command "ssh-audit" ssh-audit -h
verify_command "AWS CLI" aws --version
verify_command "Responder" responder --version
verify_any_command_allow_nonzero "NetExec" "nxc --version" "netexec --version" "crackmapexec --version"
verify_command "hashcat" hashcat --version
verify_command "Metasploit console" msfconsole -v
verify_command "Metasploit RPC daemon" msfrpcd -h
verify_command "ldapsearch" ldapsearch -VV
verify_command "snmpwalk" snmpwalk --version
verify_command "iw" iw --version
verify_command "aircrack-ng" aircrack-ng --help
verify_command "airodump-ng" airodump-ng --help
verify_any_command "Impacket psexec" "psexec.py -h" "impacket-psexec -h"
verify_any_command "Impacket wmiexec" "wmiexec.py -h" "impacket-wmiexec -h"
verify_any_command "Impacket secretsdump" "secretsdump.py -h" "impacket-secretsdump -h"
verify_any_command "Impacket GetUserSPNs" "GetUserSPNs.py -h" "impacket-GetUserSPNs -h"
verify_any_command "Impacket GetNPUsers" "GetNPUsers.py -h" "impacket-GetNPUsers -h"
verify_command "BloodHound Python" bloodhound-python --help
verify_command "kerbrute" kerbrute version
verify_command "subfinder" subfinder -version

echo "Host verification complete."
