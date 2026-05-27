# Active Task

> **Read FIRST:** [`ANTI_DRIFT.md`](ANTI_DRIFT.md) (repo root) — 5 hard rules + pre-commit checklist + strenger DONE-definitie.
>
> **Read SECOND:** [`SESSION_PROMPT.md`](SESSION_PROMPT.md) — kickoff discipline voor AegisPT sessies.
>
> **Read THIRD (NEW 2026-05-27):** [`docs/research/open-work-consolidated-2026-05-27.md`](docs/research/open-work-consolidated-2026-05-27.md) — full inventory of open work after operator decision "geen 4de overhaul, focus daily-5 score-lane". Do NOT promote anything from `TASK_QUEUE.md` (388 packages frozen).

## Title

Score-lane: produce 1 formal verified-exploit SOLVE on XBEN-002 + start daily-5 cadence.

## Goal

Move the official baseline from `0/25` (xbow-2026-05-21-baseline.md) to `1/N` with a formal `docs/validation/` artifact containing flag byte-equality verification, commit SHA, reproducer script, and replay log. Operator decision 2026-05-27: no architecture overhaul, no new SPRINTs, no LiteLLM/observability/skill-pack work until daily-5 metric moves.

## Notes

### Active in-flight
- Smoke 47d (Claude Opus 4.7, XBEN-002, 900s hard budget) — PID 351417, background check `b51pazb7k`.
- After smoke 47d: smoke 48 Gemini (proven SOLVED in smoke 38), smoke 49 OAuth defensive (commit `6b0ac53`).

### Live infrastructure as of 2026-05-27
- **Wall-clock budget guard** (`5a0ac46`) enforces `wall_clock_budget_seconds` at picker + CPG-CEA dispatch. Default 1800s. Wrapper `--wait-seconds` plumbs in. Hard stop API-side regardless of wrapper state.
- **Cache hit-rate logging** (`a810f0d`) on 3 previously-silent Anthropic call sites. Next smoke produces `PROOF_EXEC_ANTHROPIC_USAGE_2026052712 site=... hit_pct=...` lines.
- **OAuth defensive-framed CPG-CEA prompt** (`6b0ac53`) to bypass cyber_policy filter — live for `chatgpt_oauth` provider only.
- **Wrapper timeouts** 600s → 1800s (`d5cccea` + `bdcd3e9`) on both iterate-explicit + client-default.
- **Live CLI screen** at `/live-cli` route in ui-v2 (`441a415`).

### Today's empirical findings (do not re-discover)
1. The May-21 0/25 baseline crashed 16/20 on PROVIDER-API failures (timed out / disconnect), not Docker.
2. Smoke 38 (2026-05-26) SOLVED XBEN-002 in 590s on `gemini-3.1-pro-preview` — evidence files lost in WSL reboot, awaiting replay.
3. OAuth `gpt-5.5` produces `cyber_policy` error on offensive-framed prompts. Defensive variant is the workaround.
4. Local-qwen `Qwen3.6-27B-IQ3_M` is wired (`e3b05ae`) but too slow on the 23KB picker prompt. Throughput-blocked.
5. Wrapper-API contract bug: wrapper crash → `docker compose down` → API run continues against dead target → exec-tasks all ConnectError. Fixed by `d5cccea` + `bdcd3e9` (timeout bump) + `5a0ac46` (API-side budget guard).
6. Transilience AI hit 100/104 on XBOW with markdown skill files + 15-iter loop, no finetune — confirms `docs/skills/` thesis.
7. AWE paper: +30.5% XSS / +33.3% blind-SQLi with memory-augmented multi-agent + browser-backed verification.

### What is frozen
- All 25 open SPRINT items in `TASK_QUEUE.md` (`mythos-exploitation-foundation`, `parity`, `domain-coverage`, `continuous-improvement`).
- All 388 backlog packages.
- All M-roadmap M4 / M5 / M6 / M7 / M8 substrate work — wait until M3-style live evidence comes from daily-5 first.
- The "do another big refactor" instinct. Operator decision: discipline, not architecture.

### Hard rules (operator-set this session)
1. No 4th overhaul.
2. No idle waiting — finish inline OR hand a concrete next-action.
3. Don't claim DONE on substrate-only. New rule: `substrate-shipped` ≠ `live-proven`.
4. Hard wall-clock budget on every cloud-LLM-using run. Override via env or config.
5. Cache hit-rate must be observable, not inferred. (Now is.)

## When does this active task end?

When `docs/validation/` contains at least one new validation doc filled per the [xbow-smoke38-replay-TEMPLATE](docs/validation/xbow-smoke38-replay-TEMPLATE.md) format with `Solved=yes` AND `MATCH=yes` on byte-equal flag verification.

At that point, the next active task is `Daily-5 scorelane: same 5 XBENs, one provider, one skill-write per failure day, commit only on metric delta` per [open-work-consolidated-2026-05-27.md](docs/research/open-work-consolidated-2026-05-27.md) section B.
