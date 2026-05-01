#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEMPLATE_PATH="${AEGISPT_COMPOSE_ENV_TEMPLATE:-${REPO_ROOT}/.env.example}"
TARGET_PATH="${1:-${AEGISPT_COMPOSE_ENV_PATH:-${REPO_ROOT}/.env}}"

if [[ -f "${TARGET_PATH}" ]]; then
  echo "Refusing to overwrite existing env file: ${TARGET_PATH}" >&2
  exit 1
fi

if [[ ! -f "${TEMPLATE_PATH}" ]]; then
  echo "Compose env template is missing: ${TEMPLATE_PATH}" >&2
  exit 1
fi

mkdir -p "$(dirname "${TARGET_PATH}")"

POSTGRES_PASSWORD="$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')"
ZAP_API_KEY="$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')"
METASPLOIT_RPC_PASSWORD="$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')"
LOCAL_SECRET_ENCRYPTION_KEY="$(python3 -c 'import base64, os; print(base64.urlsafe_b64encode(os.urandom(32)).decode("ascii"))')"

cp "${TEMPLATE_PATH}" "${TARGET_PATH}"
chmod 600 "${TARGET_PATH}"

sed -i "s|^POSTGRES_PASSWORD=.*$|POSTGRES_PASSWORD=${POSTGRES_PASSWORD}|" "${TARGET_PATH}"
sed -i "s|^DATABASE_URL=.*$|DATABASE_URL=postgresql+psycopg://aegispt:${POSTGRES_PASSWORD}@aegispt-db:5432/aegispt|" "${TARGET_PATH}"
sed -i "s|^ZAP_API_KEY=.*$|ZAP_API_KEY=${ZAP_API_KEY}|" "${TARGET_PATH}"
sed -i "s|^METASPLOIT_RPC_PASSWORD=.*$|METASPLOIT_RPC_PASSWORD=${METASPLOIT_RPC_PASSWORD}|" "${TARGET_PATH}"
sed -i "s|^LOCAL_SECRET_ENCRYPTION_KEY=.*$|LOCAL_SECRET_ENCRYPTION_KEY=${LOCAL_SECRET_ENCRYPTION_KEY}|" "${TARGET_PATH}"

echo "Compose env generated at ${TARGET_PATH}"
