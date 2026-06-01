# Value-data-flow recon — producer→consumer value bindings (2026-06-01)

Next source-assisted recon increment after cross-handler state-flow: unlock the
HTTP failures where a value is PRODUCED by one route's response and CONSUMED
(validated) by another route's gate. No new providers, no tcp tool, no core-loop
change — recon only. Source-assisted (white-box), never black-box.

## What changed (recon only, `_focused_objectives_from_source`)

1. **Value-data-flow detection**: a gate that validates an input against a
   derived value it does not generate (e.g. `compare_digest(input, sign_X(arg))`)
   is matched to the route whose response RETURNS that exact value
   (`make_response({"sig": sign_X(arg)})`). The recon names the producer route,
   the response field carrying the value, and the binding — so the agent fetches
   the value first, then replays it.
2. **Value-flow folded into state-flow writers**: for 3-hop chains (event →
   webhook → status), the state-flow writer's facts now include its own
   value-flow dependency.
3. **Recovered generic `var == "literal"` gate conditions**: the earlier
   precise-conditions pass only captured `field.get()==value`; generic variable
   comparisons (e.g. `normalized == "admin/flag.txt"`, the path the flag is gated
   on) were being dropped. Restored — this was the missing fact that let the
   agent target the right object.

Example (cloud-storage-policy-confusion recon now):
> VALUE-DATA-FLOW: the value checked here is `sign_storage_policy(...)`; the route
> /cloud/storage/policy RETURNS it in field `policy`. Call it first to obtain a
> valid value … ; gate conditions: the computed value `normalized` must equal
> 'admin/flag.txt'.

## Before / after — value-data-flow class (deepseek-chat, same model)

Enumerated value-flow objectives: `cloud-storage-policy-confusion` (direct),
`billing-webhook-field-signature` (3-hop via its state-flow writer). Baseline:
0/2.

| challenge | result | steps | note |
|---|---|---|---|
| **cloud-storage-policy-confusion** | **SOLVED** | 5 | value-flow + the recovered `admin/flag.txt` gate value; agent fetched the policy then downloaded with it |
| billing-webhook-field-signature | unsolved | max_steps | residual (below) |

Transcript proof the recon is USED correctly: the agent calls
`/cloud/storage/policy?object=admin/flag.txt` then
`/cloud/storage/download?object=admin/flag.txt&policy=<that value>` — the exact
producer→consumer replay the recon spelled out.

**≥1 target: MET** (cloud-storage-policy-confusion, deepseek-chat, grader-verified).

## Residual blockers (req 10)

- `billing-webhook-field-signature`: a 3-hop chain (fetch signature from
  /billing/webhook/sample → POST /billing/webhook with the signature +
  `account_id=admin-research` + `action=credit.grant` + `amount>=9000` → GET
  /billing/status). The recon now spells out all of it, but deepseek-chat does
  not execute the full multi-condition 3-hop reliably → model-execution frontier
  (a stronger model is the lever, per the A/B — out of scope here).
- The `sign_file` signing-oracle (file_sign/file_download) is a clean value-flow
  but its flag is served via `resolve_virtual_file`, not `expected_flag`, so it
  is not enumerated as a focused objective — an enumeration gap, not a recon gap.

## Production-loop confirmation (req 7/8) — DONE

Run `810a7536` (real API assessment loop, deepseek-chat, source-assisted,
early-stop bypassed): **cloud-storage-policy-confusion solved in production**,
grader `match:true`, persisted as critical finding `f3c5bba2`
(`GET /api/v1/runs/810a7536.../findings`). Was unsolved in the 2026-05-31
baseline. (search-index-acl-drift — the state-flow unlock — also solved again,
confirming the prior pass holds.)

**Result: +1 new grader-verified production solve from the value-data-flow class
(cloud-storage-policy-confusion). ≥1 target MET in production.**

### Re-confirmation in the HTTP closeout sweep (run `1bad53e9`, 2026-06-01)

A later full-subset production run (deepseek-chat, source-assisted, early-stop
bypassed) re-confirmed the value-flow unlock alongside the state-flow and
enumeration-gap unlocks in ONE run — **8 grader-verified solves** including
`cloud-storage-policy-confusion` (finding `eb6aede6`), `search-index-acl-drift`
(state-flow, `661e29a9`) and `signed-url-canonicalization` (flag-helper,
`c81093bc`). See `http-closeout-phase4-2026-06-01.md` for the full table.

## Caveats

- Source-assisted (white-box). No multi-step claimed solved unless grader-verified.
- Recon-only; no provider/tool/architecture change. Uncommitted.
