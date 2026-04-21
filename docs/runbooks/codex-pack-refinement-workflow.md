# Codex Pack Refinement Workflow

## Goal

This runbook shows how to use Codex or ChatGPT-assisted tooling to refine an adaptive pack after inventory and relevance analysis, while staying inside the existing validation and promotion model.

## Preconditions

- the API is running
- an engagement already exists
- inventory and relevance analysis already completed
- a capability pack has already been generated through the existing pack API

## 1. Export a supervised workspace

```bash
cd /opt/aegispt/repo
bash scripts/export_codex_pack_workspace.sh http://127.0.0.1:8000 <pack_id> ./codex-workspaces/<pack-name>-<version>
```

The export uses the read-only Codex review bundle endpoint and writes:

- pack metadata
- current artifacts
- validation, approval, and deployment state
- operator notes and change-summary files

## 2. Refine exported artifacts with Codex

Use a supported Codex or ChatGPT client that is already signed in:

- Codex CLI
- Codex IDE extension
- Codex app workflow where supported

Refine only:

- exported artifact files under `artifacts/`
- `operator-notes.md`
- `codex-change-summary.md`

Do not use this step to mutate the live runtime or bypass the existing pack lifecycle.

## 3. Review guardrails and validation hooks

Open `codex-context.json` and confirm:

- runtime mutation is blocked
- methodology metadata is inherited from the existing pack
- validation still routes through the current pack validation endpoint
- approval and deployment are still separate operator steps

## 4. Hand the pack back to validation

```bash
cd /opt/aegispt/repo
bash scripts/validate_codex_pack.sh http://127.0.0.1:8000 <pack_id> ./codex-workspaces/<pack-name>-<version>/validation-result.json
```

That captured file is the supported handoff record for the validation result inside the exported workspace.

## 5. Review approval readiness

Check:

- validation summary
- blocking issues
- operator notes
- change summary
- artifact list and checksums

Approval should only happen after the validation result passes.

## 6. Approve and deploy through the existing APIs

Examples:

```bash
curl -X POST -H "X-Actor: reviewer-1" \
  "http://127.0.0.1:8000/api/v1/packs/<pack_id>/approve?notes=Codex-reviewed"
```

```bash
curl -X POST -H "Content-Type: application/json" -H "X-Actor: reviewer-1" \
  http://127.0.0.1:8000/api/v1/packs/<pack_id>/deploy \
  -d '{"engagement_id":"<engagement_id>","deployment_target":"engagement-runtime"}'
```

## Outcome

This workflow keeps Codex inside a supervised preparation lane:

- inventory and relevance remain authoritative
- pack validation and promotion remain authoritative
- runtime binding remains explicit
- reports and findings continue to use the existing Prompt 1 and Prompt 2 provenance model
