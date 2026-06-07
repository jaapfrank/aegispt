# Codex data-lane handoff — 2026-06-07

Context: iter7-chaintype SFT **regressed** the held-out deep-chain (lost login, hammered
`/admin/config`, idor=false). Empirical conclusion: **pure SFT on synthetic chains hits a
generalization wall** — it does not transfer to the held-out scenario's specifics, and
diverse chain-types taught *conflicting* patterns. Claude is testing one more SFT recipe
(IDOR-focused re-tune), but the indicated frontier lever is now **RL on interactive
training envs**, plus **real teacher-demonstrated data**. Two priorities for Codex:

## P1 — Real V4-Pro demonstrated rows (NOW UNBLOCKED)

Your biggest blocked item ("kan ik niet eerlijk maken zonder endpoint/API key") is
unblocked: the key works.

- Endpoint: `https://api.deepseek.com/v1/chat/completions`, model `deepseek-v4-pro`.
- Key: read `DEEPSEEK_API_KEY` from `~/.aegispt-secrets` at runtime — **never echo/commit it**.
- V4-Pro reasons internally → set `max_tokens` ≥ 2048 and read
  `choices[0].message.content` with a `reasoning_content` fallback.
- Proven + committed skeleton: `scripts/training/teacher_demonstration_gen.py`
  (`generate(chain_type, lab_hint)` → validated `{"messages":[...]}` row; balanced-brace
  extractor for the reasoner's prose-first output; `HELD_OUT_FORBIDDEN` contamination
  guard; `--n/--out` CLI). Validated 2026-06-07 (V4-Pro emits 9–11 msg / 4–5 assistant-turn
  IDOR chains, done=true). Scale it: more `CHAIN_TYPES` + volume, then ingest-guard. Generate at **scale + diversity**
  (IDOR / SSRF-internal / priv-esc / info-disclosure-lateral / multi-service), each on a
  **distinct fictional lab** (no shop.lab, `/notes/`, `/admin/config`, the held-out flag).
- Run every generated row through your **V4-Pro demonstration ingest guard** (schema +
  held-out collision check) before it enters the SFT mix. Emit `aegispt_v4pro_demonstrated_*.jsonl`.

## P2 — Interactive training ENVIRONMENTS for RL (the frontier lever)

SFT-on-data won't close the multi-step gap (generalization wall). RL/expert-iteration on
interactive envs will — but the deep-chain env is **held-out** (using it = contamination).

- Build a small family (~4–6) of **non-held-out** interactive lab envs with the SAME
  HTTP-backend interface as `scripts/training/deep_chain_eval.py` (agent emits JSON
  action → env returns observation → evidence-reward at the goal). Distinct scenarios:
  IDOR-via-different-object, SSRF-internal, low-priv→admin, cred-reuse-lateral.
- Each env exposes: a deterministic oracle (goal reached y/n), an intermediate progress
  signal (login y/n, pivot y/n) for shaped reward, and a scenario_hash for the registry.
- These become the **rollout/RL training envs** Claude's jury + `jury_rollout.py` consume.
  Claude RLs on these (training) and evaluates on the held-out deep-chain (clean transfer test).

**Diagnostic (Claude, 2026-06-07) — what the reward must target.** On the held-out
deep-chain, both combined-SFT and DPO now reliably LOG IN (multi-turn auth is solved),
but the env is *generous* (landing page lists `/notes`; login 302-redirects to `/notes`;
`/notes` explicitly reveals the IDOR surface; the 403 says "admin token required") and the
model STILL fails — it tunnel-visions on the goal endpoint, ignores the redirect/links,
hits the 403, and **gives up instead of backtracking to explore for the pivot**. So the
env is fair (V4-Pro solves it); the missing behavior is precisely
**"blocked at the goal → backtrack → explore the hinted intermediate resource → find the
pivot → retry."** P2 shaped reward should reward exactly that recovery: +reward for
visiting a hinted-but-not-yet-visited resource after a block, and for using a
credential/token revealed in an earlier response. P1 teacher demos should include a
*premature goal attempt → block → recover-by-exploring → succeed* arc, not just the happy path.

## P3 — Hygiene (with P1/P2)

- Add every new env + every demonstrated-data scenario_hash to the **held-out registry**
  and the contamination guard. The held-out deep-chain IDs must NEVER appear in any
  training/demonstrated set.
- Keep iter8 multi-service going as P3 diversity, below P1/P2.

Claude's side (parallel): DPO-LLMSVS gate (running) → IDOR-focus re-tune gate → if it hits
the wall, RL on your P2 envs. Jury flywheel (reviewers/calibration/committee/process-reward)
is complete and ready to consume P1 data + P2 rollouts.

## Codex implementation status — 2026-06-07

### P1 status

Codex added `scripts/training/generate_v4pro_demonstrated_chains_iter9.py`.
The generator:

- reads `DEEPSEEK_API_KEY` only at runtime from env or `~/.aegispt-secrets`
- uses `https://api.deepseek.com/v1/chat/completions`
- defaults to model `deepseek-v4-pro`, JSON response mode, and
  `max_tokens=8192`
- writes raw teacher rows, accepted train rows, rejected rows, manifest, and a
  demonstrated scenario-registry JSONL
- immediately routes candidates through
  `scripts/training/ingest_v4pro_demonstrated_chains_iter8.py`

Live provider proof:

- one real V4-Pro teacher row was generated and accepted after safe ingest
  normalization
- accepted artifact:
  `codex/results/training/v4pro-demonstrated-chains-20260607-accepted/aegispt_v4pro_demonstrated_chains_iter9_train.jsonl`
- stats: `accepted_count=1`, `assistant_turns={"6":1}`, `rejected_count=0`

Scale note: Codex attempted a wider 5-row batch, but stopped it after ~10
minutes because V4-Pro reasoning was too slow for this turn. The script now
flushes raw/accepted/rejected/scenario-registry JSONL plus manifest after every
attempt and supports `--wall-seconds`, so a supervised longer-running
generation job can be interrupted without losing accepted/rejected progress.

Recovery-shaping update: V4-Pro prompts now require a premature goal attempt,
403/blocked observation, backtrack to the hinted intermediate resource, reuse
of a revealed token/session/credential, and final successful retry. Rows that
do not contain this blocked-goal recovery arc are rejected before ingest.

### P2 status

Codex added `scripts/training/multichain_rl_envs_iter9.py` with six
non-held-out interactive RL envs:

- `rl-train-idormap-case-review-token`
- `rl-train-ssrf-recovery-ticket`
- `rl-train-lowpriv-delegated-admin`
- `rl-train-credential-reuse-lateral-wiki`
- `rl-train-graphql-worker-queue-pivot`
- `rl-train-oauth-callback-service-token`

Each env exposes JSON action -> HTTP-style observation, deterministic oracle,
shaped reward, `logged_in` / `pivot` / `flag` signals, and a `scenario_hash`.
Each oracle now exercises the diagnosed missing behavior:
blocked goal attempt -> hinted-resource recovery -> revealed-value reuse ->
successful goal retry. Env observations/results carry `blocked_goal`,
`recovered_after_block`, and `used_revealed_value`; all six committed scripted
rollouts solve with those signals true.
Oracle rollout artifacts are committed under:

`codex/results/training/multichain-rl-envs-20260607/`

They use `roll_*.jsonl` + `res_*.json`, so
`scripts/training/jury_rollout.py` can rank them directly.

### P3 status

- `scripts/training/make_lab_truth_heldout_registry_iter6.py` includes all six
  iter9 RL env registry entries with `scenario_hash`
- iter7 and iter8 committed registry artifact snapshots were refreshed so both
  include the six iter9 RL env hashes
- the V4-Pro ingest guard now rejects held-out collisions by `scenario_hash`
  as well as scenario/case/target IDs
- demonstrated ingest emits a scenario-registry JSONL for accepted rows
- the held-out deep-chain markers/routes remain rejected

## Codex continuation status — C1/C2/C3 (2026-06-07)

### C1 — V4-Pro scale batch

Started as a supervised `tmux` job because plain `nohup` children are cleaned up
by this shell environment.

- scale session: `aegispt_v4pro_iter9_scale`
- post-build watcher: `aegispt_v4pro_iter9_mixwatch`
- output dir:
  `codex/results/training/v4pro-demonstrated-chains-20260607-scale/`
- target: 20 accepted rows, max 100 attempts, `max_tokens=8192`,
  `timeout=300`, `wall_seconds=21600`
- monitor:
  `tmux attach -t aegispt_v4pro_iter9_scale`
- log:
  `tail -f codex/results/training/v4pro-demonstrated-chains-20260607-scale/v4pro_scale_generation.log`

The generator flushes raw/accepted/rejected/scenario-registry/manifest after
every attempt. The mixwatch session waits for C1 to finish, then reruns the C3
mix builder automatically.

### C2 — exact gap target

Done in Codex commits `613f7ba` and `7dd1cc1`.

- P2 envs now reward `blocked_goal`, `recovered_after_block`, and
  `used_revealed_value`
- every committed oracle rollout exercises:
  blocked goal -> hinted resource -> revealed value -> retry -> marker
- both V4-Pro generators now require/reject on the same blocked-goal recovery
  arc, so happy-path-only teacher rows do not enter C3

### C3 — combined SFT mix

Added `scripts/training/build_iter9_combined_sft_mix.py`.

Stable output path:

`codex/results/training/iter9-combined-sft-mix-20260607/`

Current bootstrap manifest, before the C1 scale job has accepted recovery-valid
V4 rows:

- `selected_total=16799`
- `curated_iter5=15999`
- `iter6_auth=800`
- `v4pro_demonstrated_iter9=0`
- the old single smoke V4 row is skipped as
  `missing_blocked_goal_recovery_arc=1`

After the C1 tmux job finishes, the mixwatch job rebuilds this same output path
so accepted recovery-valid V4-Pro rows enter the final train file.

P2 rollout integration smoke:

`python3 scripts/training/jury_rollout.py --rollouts codex/results/training/multichain-rl-envs-20260607 --out /tmp/aegispt_iter9_p2_jury_best.jsonl --top-frac 1.0 --min-reward 1`

Observed: `rollouts=6`, `kept=6`, `any_flag=true`, `any_idor=true`,
`any_recovered_after_block=true`, `any_used_revealed_value=true`.

## Codex continuation status — D1/D2/D3 (2026-06-07)

### D1 — full P1 teacher corpus

The V4-Pro generator now targets the full 8-class teacher family:

- `idor_object_swap_token_reuse`
- `ssrf_internal_endpoint_recovery`
- `lowpriv_to_admin_delegation`
- `info_disclosure_credential_reuse_lateral`
- `xxe_document_parser_pivot`
- `ssti_template_context_pivot`
- `auth_logic_session_forgery`
- `nosql_filter_bypass_chain`

`scripts/training/generate_v4pro_demonstrated_chains_iter9.py` now supports
`--min-per-chain-class`, computes `requested_count=max(count, min_per_class*8)`,
and only reports `completed` once both total rows and per-class quotas are met.
Its manifest now includes the requested quality report:

- `accepted_by_chain_class`
- `rejected_by_reason`
- `rejected_by_chain_class`
- `assistant_turn_distribution`
- `class_quota_satisfied`
- `missing_chain_classes`

The old 20-row / 5-class tmux job was stopped and replaced by the D1 long run:

- teacher session: `aegispt_v4pro_d1_teacher64`
- mix watcher: `aegispt_v4pro_d1_mixwatch`
- output dir:
  `codex/results/training/v4pro-teacher-corpus-d1-20260607/`
- target: `--count 64 --min-per-chain-class 8 --max-attempts 512`
- monitor:
  `tmux attach -t aegispt_v4pro_d1_teacher64`
- log:
  `tail -f codex/results/training/v4pro-teacher-corpus-d1-20260607/v4pro_d1_teacher64.log`

The watcher rebuilds `codex/results/training/iter9-combined-sft-mix-20260607/`
after D1 finishes, explicitly using the D1 train JSONL as the first V4-Pro
source.

### D2 — held-out eval-suite

Added `scripts/training/multichain_heldout_eval_envs_iter10.py`.

- dataset family: `aegispt_multichain_heldout_eval_envs_iter10`
- 8 eval-only scenarios, all `known_vulnerable`
- every scenario has deterministic oracle actions, a scenario hash, and the
  five no-finding labels:
  `true_negative`, `missed_finding`, `inconclusive`, `blocked`,
  `correct_restraint`
- all oracles exercise:
  blocked goal -> hinted resource -> revealed value reuse -> successful retry
- registry hook added to
  `scripts/training/make_lab_truth_heldout_registry_iter6.py`

Committed oracle artifacts are under:

`codex/results/training/multichain-heldout-eval-envs-20260607/`

Rollout smoke:

`python3 scripts/training/jury_rollout.py --rollouts codex/results/training/multichain-heldout-eval-envs-20260607 --out /tmp/aegispt_iter10_heldout_jury_best.jsonl --top-frac 1.0 --min-reward 1`

Observed: `rollouts=8`, `kept=8`, `any_flag=true`, `any_idor=true`,
`any_recovered_after_block=true`, `any_used_revealed_value=true`.

### D3 — XBEN solve-gap matrix

Added `scripts/training/build_xben_gap_matrix_iter10.py`.

The matrix writes one row per `XBEN-001..XBEN-104` with:

- `vuln_class`
- `chain_depth`
- `coverage_bucket`
- `has_env`
- `has_teacher_demo`
- `has_solve`
- `solve_status`
- `evidence_paths`
- `recommended_data_action`

Committed artifacts are under:

`codex/results/training/xben-gap-matrix-20260607/`

Current summary:

- `challenge_count=104`
- `solved_count=17`
- `attempted_no_solve=21`
- `infra_blocked_or_crashed=2`
- `unknown_untriaged=64`

Top actionable gaps now visible in data form:

- `headless_xss_ssrf`: 13 known unsolved, no env/demo yet
- `auth_logic_session_forgery`: 5 unsolved, now covered by D1 teacher target +
  D2 held-out env
- `blind_command_injection_filter_bypass`: 1 known unsolved, no env/demo yet
- `command_injection`: 1 known unsolved, no env/demo yet
- `unknown_untriaged`: 58 rows still need source/class triage before targeted
  data can be honest

Targeted D3 coverage now links the requested gaps:

- auth-logic/session-forgery -> D1 teacher class + D2 held-out env
- SSRF -> internal endpoint recovery -> D1 teacher class + P2/D2 envs
- multi-service credential/service-boundary pivot -> D1 teacher class + P2/D2
  envs

The iter7 and iter8 training artifact packs were refreshed so the canonical
held-out registry snapshots include the 8 D2 eval scenario hashes.

## Codex continuation status — D4 headless/OOB gap coverage (2026-06-07)

After D3, the largest known uncovered bucket was `headless_xss_ssrf`
(`env=false`, `demo=false`). Codex added the first lab-only data coverage for
that gap.

### D4 — headless/OOB callback proof envs + demos

Added `scripts/training/headless_oob_chain_envs_iter10.py`.

- env dataset family: `aegispt_headless_oob_chain_envs_iter10`
- demo dataset family: `aegispt_headless_oob_teacher_demos_iter10`
- 4 synthetic env variants:
  - `stored_profile_callback`
  - `report_preview_ssrf_callback`
  - `support_ticket_callback`
  - `pdf_render_callback`
- 32 deterministic teacher-demo rows, 8 per variant
- all env oracles exercise:
  blocked goal -> discover injection surface + callback inbox -> store
  lab-only callback marker -> trigger synthetic headless victim -> read callback
  proof -> retry goal
- no real browser, no real callback server, no runtime binding, no external
  target

Committed artifacts:

`codex/results/training/headless-oob-chain-envs-20260607/`

Rollout smoke:

`python3 scripts/training/jury_rollout.py --rollouts codex/results/training/headless-oob-chain-envs-20260607 --out /tmp/aegispt_iter10_headless_jury_best.jsonl --top-frac 1.0 --min-reward 1`

Observed: `rollouts=4`, `kept=4`, `any_flag=true`,
`any_recovered_after_block=true`, `any_used_revealed_value=true`.

D3 matrix was regenerated. Headless now reports env/demo coverage:

- `headless_xss_ssrf`: 14 known unsolved rows
- `has_any_env=true`
- `has_any_teacher_demo=true`
- recommended action:
  `covered_by_iter10_headless_oob_env_and_demo; prioritize_callback_runner_or_rollout_eval`

Registry snapshots were refreshed again; held-out registry now includes:

- `aegispt_headless_oob_chain_envs_iter10`: 4
- `rl_train_env`: 10 total reserved env hashes
