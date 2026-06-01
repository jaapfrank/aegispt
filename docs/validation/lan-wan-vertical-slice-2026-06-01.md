# LAN/WAN vertical slice — tcp_request production validation (2026-06-01)

Closes the `non_http_lan_tool_gap`: the 10 line-protocol LAN services were
previously unsolvable because the interactive-exploit loop had only an HTTP tool.
Phase 1 added a bounded `tcp_request` tool; Phase 2 added source-assisted LAN
recon; this is the Phase-3 production validation through the real API-loop.

## Capability (Phase 1) — bounded `tcp_request`

Optional second tool on the provider-agnostic loop (native function-calling
models only: deepseek/claude/gemini/grok). Safety envelope (all enforced):

- TCP **stream** sockets only — no UDP, no raw packets, no TLS.
- Only endpoints in the **explicit** `tcp_endpoints` allowlist AND that resolve
  to a **loopback/RFC1918 private** address (no public internet).
- Per-call connect + read **timeout** (5s); per-call **max bytes** read (4096);
  global **max round-trips** (60); genuine tcp failures count against
  `max_tool_errors`.
- **Persistent** connection per (host,port) across tool-calls — the LAN
  protocols are stateful (login/bind/connect/register-writes gate later
  commands) and several reveal a token mid-session that a later command replays.
- Scope guard + full transcript/evidence logging preserved.

## Recon (Phase 2) — `_focused_tcp_objectives_from_source`

Generic source-parse of the engagement manifest (TCP host:port) +
`network_services.py` (handler grammar). Per objective it surfaces: host+port,
on-connect banner, command→effect grammar, the flag-releasing command + the
state it is gated on, the command that SETS that state (sequencing edge), and
values a response reveals that a later command must replay (value-flow).
Source-assisted (white-box), never black-box; facts + sequencing, not a recipe.

## Run

| field | value |
|---|---|
| run_id | `7e589aea-bed8-4f06-8274-ac5d757f433d` |
| driver | `run_lab_suite.py --llm-provider deepseek-chat --source-aware --reuse-running-lab` |
| transport focus | `AEGISPT_FOCUS_TRANSPORT=tcp` (LAN-only measurement knob) |
| early-stop | bypassed (measurement) |
| Claude fallback | OFF for this run (pure DeepSeek) |
| grader | lab `/grade` per challenge (run_lab_suite `-> SOLVED`) |

## Result — 9/10 LAN services SOLVED in production (target ≥3)

All via `tcp_request` through the production API-loop, deepseek-chat,
grader-verified. steps/elapsed/round-trips/stop from the runner execution stdout
(`tool_executions`); finding_id from the findings API.

| challenge_id | endpoint | provider/model | steps | elapsed | rt | stop | solved | grader | finding_id | residual class |
|---|---|---|---|---|---|---|---|---|---|---|
| lan-printer-pjl-job-leak | 127.0.0.156:9100 | deepseek-chat | 6 | 11.3s | 6 | solved | ✅ | match:true | (not promoted)¹ | — |
| lan-nas-backup-share-leak | 127.0.0.157:4450 | deepseek-chat | 7 | 13.7s | 7 | solved | ✅ | match:true | (not promoted)¹ | — |
| lan-ldap-nested-group-reset | 127.0.0.158:1389 | deepseek-chat | 6 | 11.4s | 6 | solved | ✅ | match:true | `e0a4516d` | — |
| lan-ot-maintenance-register | 127.0.0.159:1502 | deepseek-chat | 3 | 6.0s | 3 | solved | ✅ | match:true | `fe602ecc` | — |
| lan-dns-zone-transfer-leak | 127.0.0.161:5353 | deepseek-chat | 4 | 13.5s | 4 | solved | ✅ | match:true | (not promoted)¹ | — |
| lan-redis-queue-secret | 127.0.0.162:6379 | deepseek-chat | 6 | 13.3s | 6 | solved | ✅ | match:true | `a1fcbfb7` | — |
| lan-mail-reset-code-takeover | 127.0.0.163:1100 | deepseek-chat | 6 | 17.2s | 6 | solved | ✅ | match:true | `03e6f536` | — |
| lan-git-history-secret | 127.0.0.164:9418 | deepseek-chat | 6 | 17.5s | 6 | solved | ✅ | match:true | `9ae4159d` | — |
| lan-kubelet-pod-secret | 127.0.0.165:10250 | deepseek-chat | 5 | 15.7s | 5 | solved | ✅ | match:true | `b68bf82c` | — |
| lan-mqtt-retained-diagnostic | 127.0.0.160:1883 | deepseek-chat | 22 | 50.1s | 22 | max_steps | ❌→✅ | — / match:true (round 2) | — | recon gap (CLOSED) |

**Round 1 (run `7e589aea`): 9/10. Round 2 (run `74017f96`, after the mqtt recon
fix): 10/10 — all 10 LAN line-protocol services grader-verified in production.
Before: 0/10. Target ≥3: MET (3×+).**

Round 2 confirms the Phase-4 recon fix: once the enumerator surfaced the publish
membership gate (`payload must contain: action=dump`), deepseek-chat solved
`lan-mqtt-retained-diagnostic` in production (flag
`aegispt{lan-mqtt-retained-diagnostic:...}` captured;
all 10 LAN flags fired in run `74017f96`).

Verification channels per solve:
- **grader match** — run_lab_suite `_grade(lab, cid, flag)` → `-> SOLVED` (authoritative).
- **execution stdout** — `tool_executions.stdout_text` JSON `stop_reason=solved`,
  `captured_count=1` (the runner summary), with the flag literal in the
  `interactive-exploit-transcript.json` artifact.
- **findings API** — 6/9 promoted to critical findings (ids above).

¹ **Finding-promotion gap (reported, not hidden):** printer / nas / dns were
captured (execution `captured_count=1`) AND grader-verified (`-> SOLVED`) but
their findings were not promoted to the `findings` table (absent under any
run). 6/9 promoted normally in the same run, so this is a selective
finding-pipeline issue, NOT a parse failure and NOT introduced by the LAN code
(the promotion path is shared orchestration). The solves remain triple-evidenced
by grader + execution stdout + transcript. Documented as a follow-up (DONE_LOG;
TASK_QUEUE is operator-frozen, so not filed as a package — to file against the
finding-pipeline when it is next touched).

## Residual (Phase 4)

| challenge | class | analysis |
|---|---|---|
| lan-mqtt-retained-diagnostic | recon gap + model_action_failure | Chain: CONNECT → SUBSCRIBE `$SYS/#` (reveals `token={token}`) → PUBLISH `lab/diag/run` with a payload containing **both** `token=<runtime value>` AND `action=dump` → SUBSCRIBE `lab/diag/result` → flag. The recon surfaces the runtime token value-flow but the publish-payload membership requirement (`"action=dump" in parts[2]`) is in the gate CONDITION and not yet surfaced as a fact — so the agent does not know the publish must include `action=dump`. deepseek burned all 22 steps. An optional objective-scoped Claude frontier retry is measured separately below. |

Other residual classes on this subset: none (no throughput/budget, value/state-flow,
or tool/protocol gap — the tool gap is closed for 9/10).

## Toggles to restore (done at end of session)

- `AEGISPT_DISABLE_SOLVE_EARLY_STOP`, `AEGISPT_FOCUS_TRANSPORT` — removed so
  production keeps early-stop and enumerates all transports.

## Caveats

- Source-assisted (white-box). No solve claimed without grader verification.
- Grok adapter untested (bad-credentials key) — out of scope, not used here.
- Code (runner tcp tool + adapter extra_tools + LAN enumerator + dispatch) is
  uncommitted per instruction.
