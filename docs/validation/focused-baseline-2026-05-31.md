# Focused-assessment production baseline — all 50 lab challenges (2026-05-31)

First full production baseline of what the **real AegisPT product** solves today
through focused-assessment mode (per-objective interactive-exploit) — not the
standalone harness. Goal: measure where it works, where it doesn't, and why,
before building more.

## Run

- Run id `e010aabe-2642-4e93-8a34-4c2c5ce2b0ad` (real API assessment loop via
  `scripts/run_lab_suite.py`, deepseek-chat, `--source-aware`).
- Focused mode: per-route objective, ranked by gate-type solvability, one
  interactive-exploit per objective, `max_steps=18`, `stop_on_first_flag`,
  `max_tool_errors=20`, explicit loopback scope (`http://127.0.0.155`),
  live-port resolution.
- **Measurement-only deltas (uncommitted):** solve-early-stop bypassed
  (`AEGISPT_DISABLE_SOLVE_EARLY_STOP=1`, default OFF in product) so every
  objective runs; objective cap raised to 60; route-based dispatch dedup. The
  route-dedup is a genuine fix worth committing separately; the env bypass is
  measurement scaffolding only.
- **Source-assisted (white-box):** the focused recon extracts source-derived
  gate facts. These numbers are NOT black-box pentest performance.

## Result — 10 / 50 grader-verified solves

Each is a grader `match:true` flag persisted as a critical API finding with
transcript (`GET /api/v1/runs/e010aabe.../findings`):

| # | challenge | gate type |
|---|---|---|
| 1 | log-lookup-expression-expansion | interpolation token |
| 2 | cache-key-header-confusion | header + magic |
| 3 | graphql-batch-authz-confusion | body/magic |
| 4 | binder-nested-property-exposure | magic |
| 5 | cursor-pagination-tenant-leak | param/magic |
| 6 | wan-cdn-vary-poison | header + magic |
| 7 | web-ssti-sandbox-escape | body |
| 8 | supply-chain-dependency-confusion | magic |
| 9 | web-waf-double-decode-admin | path/magic |
| 10 | observability-trace-baggage-leak | param + magic |

36 of 60 enumerated objectives were reached (budget); per-objective rows are in
`focused-baseline-2026-05-31.jsonl` (challenge_id, route, provider, model, steps,
elapsed, stop_reason, solved, grader_match, finding_id, failure_reason,
fact_profile).

## Failure clusters (deduped by objective)

| cluster | n | meaning | dominant lever |
|---|---|---|---|
| **model_action_failure** | 14 | had the gate facts, DeepSeek ran 18 steps, no solve | **frontier model (Claude A/B)** |
| **recon_gap_or_multistep** | 11 | flag-emitting handler lacks the gate (it lives in another handler / multi-step state) | cross-handler state-flow recon |
| **non_http_lan_tool_gap** | 11 | raw TCP LAN/WAN services — no HTTP route, `http_request` can't reach them | safe `tcp_request`/protocol tool |
| **objective_never_reached** | 7 | not dispatched within budget | throughput (dispatch race + budget) |
| **false_positive** | 1 | captured a flag the grader rejected (`k8s-serviceaccount-secret-read`) | verifier tightening |

Cluster members:
- model_action_failure: cgi-env-parser, cicd-artifact-env-leak,
  api-bulk-tenant-mass-assignment, backup-restore-target-confusion,
  billing-webhook-field-signature, cloud-storage-policy-confusion,
  csv-formula-preview-exfil, container-registry-tag-confusion,
  **search-index-acl-drift**, device-code-tenant-confusion,
  **auth-saml-recipient-confusion**, data-warehouse-rls-comment-bypass, +2.
- recon_gap_or_multistep: jwt-kid-devnull-admin, frontend-backend-auth-rebind,
  **ssrf-loopback-metadata** (gate in the fetch handler, flag in /internal/metadata),
  wan-staging-vhost-reset, wan-origin-host-bypass, api-version-shadow-admin,
  **coupon-race-double-spend** (race), +4 routes without a 1:1 challenge map.
- non_http_lan_tool_gap: lan-printer/nas/ldap/ot/mqtt/dns/redis/mail/git/kubelet,
  wan-oauth-redirect-code-leak.

## Ranked next-fix list (do these, in order)

1. **Claude A/B on the model_action_failure cluster (14).** Same harness, same
   focused recon, same budget, swap deepseek→claude-opus-4-8 on JUST these
   (esp. search-index-acl-drift, auth-saml-recipient-confusion, the 3 hardest).
   This is the clean model-lift measurement and the biggest cluster.
2. **Cross-handler state-flow recon for recon_gap/multistep (11).** The
   flag-emitting handler's objective is missing the gate that lives in a DIFFERENT
   handler (ssrf, coupon-race, version-shadow). Extend `_focused_objectives_from_source`
   to also attribute the state-mutating handler's facts to the objective (the
   harness already does multi-handler attribution; bring it to production).
   Label source-assisted; do NOT seed exploit steps.
3. **Safe `tcp_request` / protocol tool for LAN/WAN (11).** `http_request` can
   not reach raw TCP services (printer/PJL, NAS, LDAP, MQTT, DNS, redis, …). Decide
   whether a bounded `tcp_request` tool (scope-guarded, line-protocol) is worth it
   — this is the single largest capability gap (11 challenges, 0 reachable).
4. **Throughput for never-reached (7).** Fully eliminate the dispatch race
   (run.tasks staleness still doubles ~1 objective occasionally) + larger budget /
   bounded concurrency so all 60 objectives run.
5. **Verifier tightening for the 1 false_positive** (k8s-serviceaccount-secret-read
   captured a flag-shaped string the grader rejected) — the runner's flag scan
   accepted a non-matching token.

## Honest caveats

- Source-assisted (white-box), not black-box.
- No multi-step chain is claimed solved unless grader-verified (none of the
  unsolved multi-step challenges are claimed).
- 10/50 is the reached-in-budget figure with DeepSeek; it is a floor, not a
  ceiling — model lift (1) and LAN tooling (3) are untested levers.
