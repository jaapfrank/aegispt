# Claude A/B on the 14 model_action_failure objectives — BLOCKED (provider), ready to run (2026-05-31)

Goal: isolate pure model lift by rerunning ONLY the 14 `model_action_failure`
objectives from `focused-baseline-2026-05-31.jsonl` with Claude on the exact
same production focused-assessment path (same recon, scope, budget, source-
assisted label, grader/finding path). Provider selection only — no new code.

## Status: BLOCKED at the provider. Not run.

Claude credits are exhausted. Probe (`claude-opus-4-8`, 5-token request) returns:

```
BadRequestError 400 invalid_request_error:
"Your credit balance is too low to access the Anthropic API."
```

Per the measurement task's rule ("do not change product code unless you hit a
genuine run blocker; if a blocker appears, stop and document it instead of
folding in opportunistic fixes"), no allowlist/scaffolding was built and nothing
was substituted. The A/B is fully specified below and runs the instant credits
return.

## The 14 objectives (DeepSeek baseline: all max_steps, gate facts present)

All 14 had source-derived gate facts (`has_magic=True`) yet DeepSeek ran the full
18 steps without a solve — the candidate model frontier.

| challenge_id | route | gate facts |
|---|---|---|
| api-bulk-tenant-mass-assignment | /api/bulk/audit | magic ×1 |
| auth-saml-recipient-confusion | /sso/acs | magic ×2 |
| backup-restore-target-confusion | /backup/restore | magic ×1 |
| billing-webhook-field-signature | /billing/status | magic ×1 |
| cgi-env-parser-confusion | /cgi/diagnostic | header+magic ×2 |
| cicd-artifact-env-leak | /ci/artifacts | header+magic ×4 |
| cloud-storage-policy-confusion | /cloud/storage/download | magic ×1 |
| container-registry-tag-confusion | /deploy/status | magic ×1 |
| csv-formula-preview-exfil | /crm/export | magic ×1 |
| data-warehouse-rls-comment-bypass | /warehouse/query | magic ×2 |
| device-code-tenant-confusion | /device/token | magic ×2 |
| search-index-acl-drift | /docs/search | magic ×1 (multi-handler) |
| wan-cloud-metadata-token-pivot | /wan/cloud/preview | magic ×4 |
| web-upload-polyglot-metadata | /media/metadata | magic ×3 |

## Cost-conscious plan (run when unblocked)

1. **Hardest representative 5 first** (richest facts / multi-step):
   `search-index-acl-drift`, `auth-saml-recipient-confusion`,
   `cicd-artifact-env-leak`, `wan-cloud-metadata-token-pivot`,
   `web-upload-polyglot-metadata`.
2. **Only if lift is visible on those 5, run the remaining 9.**
3. Same production API-loop, same focused-assessment mode, same budget shape
   (`max_steps=18`, stop-on-proof, scope `http://127.0.0.155`), source-assisted.
4. Grader-verify each solve + confirm critical findings via the findings API.
5. Side-by-side artifact (DeepSeek vs Claude): challenge_id, route, provider,
   model, steps, elapsed, stop_reason, solved, grader_match, finding_id.
6. Summary: Claude /14, DeepSeek /14 (=0 today), net lift, per-objective delta,
   p50 time-to-solve, new false positives, objectives still failing with full
   gate facts.

One honest implementation note for the run (NOT done here): running ONLY these 14
through the production loop needs an objective-subset selector. The product has
none today (the loop enumerates + ranks all objectives). That selector is a
measurement-only gate (env allowlist, same pattern as the baseline's early-stop
bypass) — to be added as documented scaffolding at run time, not committed.

## Alternatives (operator decision)

- **(a) Top up Claude credits** → run the exact A/B above.
- **(b) gpt-5.4 proxy A/B** (ChatGPT-OAuth, free via operator OAuth, proven on
  the exploit path, stronger-than-DeepSeek): gives a model-lift signal at zero
  cost, but it is NOT Claude — would be labeled gpt-5.4, and carries the
  JSON-action adapter's strict-JSON caveat. Available immediately.

No product code changed. Nothing committed.
