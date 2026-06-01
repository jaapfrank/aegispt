# HTTP closeout — Phase-4 production validation (2026-06-01)

Freeze of the HTTP focused-assessment production path before the LAN/WAN
vertical slice. Real production API-loop (`scripts/run_lab_suite.py` →
`POST /api/v1/runs/{id}/iterate`), provider **deepseek-chat**, source-assisted
(white-box), early-stop bypassed for full-subset measurement.

## Run

| field | value |
|---|---|
| run_id | `1bad53e9-74c4-410e-90c1-f8549134074a` |
| driver | `run_lab_suite.py --llm-provider deepseek-chat --source-aware --reuse-running-lab` |
| early-stop | bypassed (`AEGISPT_DISABLE_SOLVE_EARLY_STOP=1`) — measurement only |
| Claude fallback | OFF (`AEGISPT_FOCUSED_CLAUDE_FALLBACK` unset) — pure DeepSeek lift |
| grader | lab `/__lab/score` (`match:true`) per challenge |

## Result — 8 grader-verified production solves (HTTP/WAN subset)

Before this closeout series the focused HTTP path scored these as no-flag; all 8
were captured in ONE production run, grader-verified, persisted as critical
findings:

| challenge_id | class | finding_id | grader_match |
|---|---|---|---|
| log-lookup-expression-expansion | interpolation gate | `98073f5e` | true |
| cache-key-header-confusion | header+magic | `68a9c2a9` | true |
| graphql-batch-authz-confusion | body/magic | `92e91bdc` | true |
| web-ssti-sandbox-escape | template sandbox | `a9688e3f` | true |
| wan-cdn-vary-poison | WAN cache key | `7d387d6d` | true |
| **search-index-acl-drift** | **cross-handler STATE-FLOW** | `661e29a9` | true |
| **cloud-storage-policy-confusion** | **cross-route VALUE-DATA-FLOW** | `eb6aede6` | true |
| **signed-url-canonicalization** | **flag-helper / signing-oracle (enum gap closed)** | `c81093bc` | true |

The three bold rows are the closeout-specific unlocks: state-flow (writer→reader),
value-data-flow (producer→consumer), and the objective-enumeration gap
(indirect flag served via a resolver/signing-oracle helper that has no direct
`expected_flag`). All three are grader-verified in production.

- **Min target (≥2 new HTTP solves): MET** — 3 closeout-class solves + 5 others.
- **Stretch (≥1 helper-chain/value-flow + ≥1 multi-hop): BOTH MET** — value-flow
  (`cloud-storage`) + helper-chain (`signed-url`) AND multi-hop state-flow
  (`search-index`).

Verification path per solve: grader `match:true` (run_lab_suite `-> SOLVED`) +
findings API (`GET /api/v1/runs/1bad53e9.../findings`, finding_ids above) +
transcript artifact (`interactive-exploit-transcript.json` shows the
producer→consumer / writer→reader request order the recon spelled out).

## Residual blocker classes (HTTP subset)

| class | example | lever |
|---|---|---|
| model_action_failure | `billing-webhook-field-signature` (3-hop: fetch sig → POST webhook w/ sig+account+action+amount → GET status) | stronger model; even Claude opus-4-8 failed it in the A/B → genuine frontier |
| multi-step execution flakiness | occasional max_steps stop on recon-complete objectives | budget / model |
| value/state-flow gap | none remaining in the targeted subset | — |
| objective enumeration gap | `sign_file` signing-oracle served via `resolve_virtual_file` (not `expected_flag`) — not yet enumerated | extend helper detection to indirect resolvers |
| throughput/budget | full 60-objective sweep ≈ 2.8h with bypass on | per-transport focus knob (added) |
| tool/protocol gap | the 10 `non_http_lan_tool_gap` LAN services (no TCP tool) | **closed in Phase 1–3 (tcp_request)** |

## Toggles to restore (done at end of session)

- `AEGISPT_DISABLE_SOLVE_EARLY_STOP` — remove so production keeps early-stop.
- `AEGISPT_FOCUS_TRANSPORT` — remove so production enumerates all transports.
- `AEGISPT_FOCUSED_CLAUDE_FALLBACK` — already default-off.

## Caveats

- Source-assisted (white-box). No multi-step claimed solved without grader
  verification. Recon-only + adapter `extra_tools` plumbing; uncommitted.
- The extra `aegispt{...}` finding in the run is a sample/placeholder flag that
  did not match a manifest challenge id (not counted in the 8).
