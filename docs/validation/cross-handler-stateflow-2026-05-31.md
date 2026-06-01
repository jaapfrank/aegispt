# Cross-handler state-flow recon — targeted HTTP unsolved subset (2026-05-31)

Improves source-assisted focused recon for the multi-step / objective failures
from the 2026-05-31 baseline that are NOT model-bound (Claude A/B showed model
lift is only +2/14). No new providers, no tcp tool, no core-loop change — recon
only. Source-assisted (white-box), never black-box.

## What changed (recon only, in `_focused_objectives_from_source`)

1. **Cross-handler state-flow**: when a flag-emitting handler READS a `STATE.<key>`
   that a DIFFERENT handler WRITES, the recon now names the writer route, the
   gate facts to trigger that write, and the writer→reader sequence edge. This
   spells out the multi-step dependency the single-objective recon was missing.
2. **Precise `field == value` gate conditions**: instead of listing fields and
   magic values separately (which let the agent shuffle values across fields),
   the recon now states each source gate condition exactly — e.g.
   *"body field `mode` must equal 'preview'; header `X-Preview-Principal` must
   equal 'admin'; `q` must contain 'roadmap'"*. These are the source's literal
   comparisons (facts), not an exploit recipe.

Example (search-index-acl-drift recon now):
> STATE-FLOW: state `search_index_public` is set by /docs/reindex when it sees
> header `X-Preview-Principal` must equal 'admin'; body field `mode` must equal
> 'preview'; then /docs/search reads it to release the flag.

## Before / after — targeted HTTP unsolved subset (deepseek-chat, same model)

21 objectives (the baseline's unsolved `model_action_failure` +
`recon_gap/multistep`, HTTP only, excluding raw-TCP LAN). Baseline DeepSeek-chat:
**0/21**. With cross-handler state-flow + precise gate conditions: **2/21 new
grader-verified solves** (reset-isolated):

| challenge | unlock | steps | note |
|---|---|---|---|
| **search-index-acl-drift** | cross-handler state-flow | 4 | unsolved by BOTH DeepSeek AND Claude in the baseline/A/B — the headline multi-step unlock |
| **data-warehouse-rls-comment-bypass** | precise gate conditions | 1 | was a Claude-ONLY solve before; precise conditions make it deepseek-chat-solvable |

Per-objective rows: `cross-handler-stateflow-2026-05-31.jsonl`.

## Residual blockers (req-10 documentation — why the ≥3 target was not reliably met)

The recon lift is real but below 3 in a single deepseek-chat run. The remaining
state-flow objectives split into:

- **multi-step execution flakiness** (`api-version-shadow-admin`,
  `api-bulk-tenant-mass-assignment`, `wan-staging-vhost-reset`): the recon now
  spells out the chain, and these DO solve on some runs (api-version-shadow
  solved in 4 steps on an earlier run) but deepseek-chat is inconsistent at
  sequencing 2–3 dependent requests. Not a recon gap — a model-execution
  frontier (where a stronger model would likely help, per the A/B).
- **data-flow dependency, not state-flow** (`billing-webhook-field-signature`):
  the writer requires a valid HMAC signature that must be FETCHED from
  `/billing/event` and replayed — a value-data-flow across handlers, which the
  STATE.<key> flow does not capture. Generalizing the recon to value-data-flow is
  the next recon increment (not done here).
- **concurrency** (`coupon-race-double-spend`): a race/double-spend that needs
  CONCURRENT requests; the sequential single-agent loop + `http_request` cannot
  express it. Tool/loop limit, not recon.

## Production-loop confirmation (req 7/8) — DONE

Run `f748b25b-3644-4562-8891-6f82339e17a0` (real API assessment loop,
deepseek-chat, source-assisted, early-stop bypassed for coverage): **2 NEW
grader-verified production solves vs the baseline**, both state-flow unlocks,
persisted as critical API findings:

| challenge | finding_id | grader_match | baseline |
|---|---|---|---|
| search-index-acl-drift | `40426a2f` | true | unsolved (by DeepSeek AND Claude) |
| api-version-shadow-admin | `17972f53` | true | unsolved (recon_gap/multistep) |

`GET /api/v1/runs/f748b25b.../findings` returns both as
`Flag captured (interactive-exploit)…`, severity critical, with transcripts.
api-version-shadow-admin — flaky standalone — solved cleanly in the production
loop, so the recon lift is real, not a standalone artefact.

**Result vs the ≥3 target:** +2 new grader-verified production solves (not 3).
The residual blockers above are documented per req 10; the next increments
(value-data-flow recon for billing-webhook; a frontier model for the multi-step
flakiness; a concurrency/tcp tool for coupon-race) are NOT folded in here.

## Caveats

- Source-assisted (white-box). No multi-step claimed solved unless grader-verified
  (the 2 are).
- Recon-only change; no provider/tool/architecture change. Uncommitted.
