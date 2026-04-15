#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEMPLATE_PATH="${REPO_ROOT}/infra/compose/.env.example"
TARGET_PATH="${1:-${REPO_ROOT}/infra/compose/.env}"

if [[ -f "${TARGET_PATH}" ]]; then
  echo "Refusing to overwrite existing env file: ${TARGET_PATH}" >&2
  exit 1
fi

mkdir -p "$(dirname "${TARGET_PATH}")"

POSTGRES_PASSWORD="$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')"
MINIO_SECRET="$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')"
ZAP_API_KEY="$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')"

cp "${TEMPLATE_PATH}" "${TARGET_PATH}"
chmod 600 "${TARGET_PATH}"

sed -i "s|^POSTGRES_PASSWORD=.*$|POSTGRES_PASSWORD=${POSTGRES_PASSWORD}|" "${TARGET_PATH}"
sed -i "s|^DATABASE_URL=.*$|DATABASE_URL=postgresql+psycopg://aegispt:${POSTGRES_PASSWORD}@postgres:5432/aegispt|" "${TARGET_PATH}"
sed -i "s|^ARTIFACTS_S3_SECRET_KEY=.*$|ARTIFACTS_S3_SECRET_KEY=${MINIO_SECRET}|" "${TARGET_PATH}"
sed -i "s|^MINIO_ROOT_PASSWORD=.*$|MINIO_ROOT_PASSWORD=${MINIO_SECRET}|" "${TARGET_PATH}"
sed -i "s|^ZAP_API_KEY=.*$|ZAP_API_KEY=${ZAP_API_KEY}|" "${TARGET_PATH}"

echo "Compose env generated at ${TARGET_PATH}"
