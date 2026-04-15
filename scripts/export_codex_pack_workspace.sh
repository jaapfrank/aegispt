#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 3 ]]; then
  echo "Usage: bash scripts/export_codex_pack_workspace.sh <base_url> <pack_id> <output_dir>" >&2
  exit 1
fi

if ! command -v curl >/dev/null 2>&1; then
  echo "curl is required" >&2
  exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required" >&2
  exit 1
fi

BASE_URL="${1%/}"
PACK_ID="$2"
OUTPUT_DIR="$3"
ACTOR="${AEGISPT_ACTOR:-codex-operator}"

mkdir -p "${OUTPUT_DIR}/artifacts"

BUNDLE_PATH="${OUTPUT_DIR}/codex-review-bundle.json"
curl -fsS \
  -H "X-Actor: ${ACTOR}" \
  "${BASE_URL}/api/v1/packs/${PACK_ID}/codex-review-bundle" \
  -o "${BUNDLE_PATH}"

jq '.context' "${BUNDLE_PATH}" > "${OUTPUT_DIR}/codex-context.json"
jq '.pack' "${BUNDLE_PATH}" > "${OUTPUT_DIR}/pack.json"
jq '.artifacts' "${BUNDLE_PATH}" > "${OUTPUT_DIR}/artifacts.json"
jq '.validations' "${BUNDLE_PATH}" > "${OUTPUT_DIR}/validations.json"
jq '.approvals' "${BUNDLE_PATH}" > "${OUTPUT_DIR}/approvals.json"
jq '.deployments' "${BUNDLE_PATH}" > "${OUTPUT_DIR}/deployments.json"

while IFS= read -r artifact; do
  logical_name="$(printf '%s\n' "${artifact}" | jq -r '.logical_name')"
  target_path="${OUTPUT_DIR}/artifacts/${logical_name}"
  mkdir -p "$(dirname "${target_path}")"

  has_text="$(printf '%s\n' "${artifact}" | jq -r '.content_text != null')"
  has_json="$(printf '%s\n' "${artifact}" | jq -r '.content_json != null')"

  if [[ "${has_text}" == "true" ]]; then
    printf '%s\n' "${artifact}" | jq -r '.content_text' > "${target_path}"
  elif [[ "${has_json}" == "true" ]]; then
    printf '%s\n' "${artifact}" | jq '.content_json' > "${target_path}"
  else
    : > "${target_path}"
  fi
done < <(jq -c '.artifacts[]' "${BUNDLE_PATH}")

cat > "${OUTPUT_DIR}/operator-notes.md" <<EOF
# Operator Notes

- Pack ID: ${PACK_ID}
- Exported from: ${BASE_URL}
- Actor: ${ACTOR}

Record review notes, approval rationale, and any analyst caveats here.
EOF

cat > "${OUTPUT_DIR}/codex-change-summary.md" <<EOF
# Codex Change Summary

Use this file to summarize:

- which exported artifacts were refined
- why the changes were needed for this customer
- which validation hooks should be rerun
- what the operator still needs to review before approval
EOF

cat > "${OUTPUT_DIR}/README.md" <<EOF
# Codex Pack Workspace

This workspace was exported from the existing AegisPT adaptive pack APIs.

Files:

- \`codex-review-bundle.json\`: full build-lane bundle
- \`codex-context.json\`: guardrails, repo conventions, validation hooks
- \`pack.json\`: pack metadata
- \`artifacts/\`: materialized pack artifacts for supervised refinement
- \`validations.json\`, \`approvals.json\`, \`deployments.json\`: current lifecycle state
- \`operator-notes.md\`, \`codex-change-summary.md\`: review notes

Suggested next steps:

1. Refine only the exported artifacts and review notes.
2. Keep methodology/provenance references intact.
3. Trigger validation with:
   \`bash scripts/validate_codex_pack.sh ${BASE_URL} ${PACK_ID}\`
4. Use the existing approval and deployment APIs after successful validation.
EOF

echo "Exported Codex workspace to ${OUTPUT_DIR}"
