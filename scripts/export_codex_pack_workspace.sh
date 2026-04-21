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

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required" >&2
  exit 1
fi

BASE_URL="${1%/}"
PACK_ID="$2"
OUTPUT_DIR="$3"
ACTOR="${AEGISPT_ACTOR:-codex-operator}"
VALIDATION_OUTPUT_PATH="${OUTPUT_DIR}/validation-result.json"

mkdir -p "${OUTPUT_DIR}/artifacts"

BUNDLE_PATH="${OUTPUT_DIR}/codex-review-bundle.json"
curl -fsS \
  -H "X-Actor: ${ACTOR}" \
  "${BASE_URL}/api/v1/packs/${PACK_ID}/codex-review-bundle" \
  -o "${BUNDLE_PATH}"

python3 - "${BUNDLE_PATH}" "${OUTPUT_DIR}" <<'PY'
import json
import sys
from pathlib import Path

bundle_path = Path(sys.argv[1])
output_dir = Path(sys.argv[2])
bundle = json.loads(bundle_path.read_text(encoding="utf-8"))

for name in ("context", "pack", "artifacts", "validations", "approvals", "deployments"):
    payload = bundle.get(name, {} if name in {"context", "pack"} else [])
    (output_dir / f"{'codex-context' if name == 'context' else name}.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

for artifact in bundle.get("artifacts", []):
    logical_name = str(artifact.get("logical_name") or "unnamed-artifact")
    target_path = output_dir / "artifacts" / logical_name
    target_path.parent.mkdir(parents=True, exist_ok=True)
    if artifact.get("content_text") is not None:
        target_path.write_text(str(artifact.get("content_text")), encoding="utf-8")
    elif artifact.get("content_json") is not None:
        target_path.write_text(
            json.dumps(artifact.get("content_json"), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    else:
        target_path.touch()
PY

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
   \`bash scripts/validate_codex_pack.sh ${BASE_URL} ${PACK_ID} ${VALIDATION_OUTPUT_PATH}\`
4. Use the existing approval and deployment APIs after successful validation.
EOF

echo "Exported Codex workspace to ${OUTPUT_DIR}"
