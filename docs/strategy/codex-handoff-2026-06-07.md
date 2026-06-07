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

## Codex continuation status — D5 blind-command/OOB proof coverage (2026-06-07)

After D4, the next known uncovered command buckets in the matrix were
`blind_command_injection_filter_bypass` (`XBEN-068`) and `command_injection`
(`XBEN-037` still unsolved). Codex added lab-only coverage for both without
adding shell payload strings or real callback infrastructure.

### D5 — blind-command/OOB bounded-proof envs + demos

Added `scripts/training/blind_oob_command_envs_iter10.py`.

- env dataset family: `aegispt_blind_oob_command_envs_iter10`
- demo dataset family:
  `aegispt_blind_oob_command_teacher_demos_iter10`
- 4 synthetic env variants:
  - `filtered_status_callback`
  - `archive_job_callback`
  - `bounded_output_proof`
  - `argument_normalization_proof`
- 32 deterministic teacher-demo rows:
  - 16 for `blind_command_injection_filter_bypass`
  - 16 for `command_injection`
  - 8 per variant
- all env oracles exercise:
  blocked goal -> inspect diagnostics/proof surface -> request bounded
  lab-only proof emission -> retrieve proof -> retry proof-gated goal
- policy/test guardrails:
  no shell payloads, no real callback server, no runtime execution, no runtime
  binding, no held-out deep-chain marker leakage

Committed artifacts:

`codex/results/training/blind-oob-command-envs-20260607/`

Rollout smoke:

`python3 scripts/training/jury_rollout.py --rollouts codex/results/training/blind-oob-command-envs-20260607 --out /tmp/aegispt_iter10_blind_command_jury_best.jsonl --top-frac 1.0 --min-reward 1`

Observed: `rollouts=4`, `kept=4`, `best_reward=25`,
`median_reward=25`, `any_flag=true`, `any_recovered_after_block=true`,
`any_used_revealed_value=true`.

D3 matrix was regenerated. Command buckets now report env/demo coverage:

- `blind_command_injection_filter_bypass`: target `XBEN-068`,
  `has_any_env=true`, `has_any_teacher_demo=true`
- `command_injection`: target `XBEN-037`, `has_any_env=true`,
  `has_any_teacher_demo=true`

Registry snapshots were refreshed again; held-out registry now includes:

- `aegispt_blind_oob_command_envs_iter10`: 4
- `rl_train_env`: 14 total reserved env hashes

## Codex continuation status — D6 XBEN unknown-triage backlog (2026-06-07)

After D5, the biggest remaining matrix bucket is still
`unknown_untriaged`. Codex added an evidence-first triage backlog so the next
data work does not guess labels.

Added `scripts/training/build_xben_triage_backlog_iter10.py`.

Committed artifacts:

`codex/results/training/xben-triage-backlog-20260607/`

Current summary:

- `item_count=87`
- `source_triage_required=57`
- `covered_needs_rollout_eval=25`
- `known_gap_needs_data=5`
- `source_triage_with_existing_evidence=3`

Policy encoded in the artifact:

- `unknown_rows_are_not_labeled=true`
- `neighbor_context_is_not_a_label=true`
- `no_training_rows_generated=true`

Interpretation for Claude:

- the 25 `covered_needs_rollout_eval` rows are candidates for rollout/live
  evaluation against existing D1/D2/P2/D4/D5 coverage
- the 5 `known_gap_needs_data` rows still need targeted env/demo coverage
- the 57 `source_triage_required` rows must be source/readout triaged before
  they become training data; neighbor context is only prioritization metadata,
  not a vulnerability label

## Codex continuation status — D1 supervised top-up active (2026-06-07)

Codex inspected the long-running D1 V4-Pro teacher corpus. Main D1 is still
running in `aegispt_v4pro_d1_teacher64`; at supervision it had:

- `accepted_count=45`
- `attempts=77`
- `requested_count=64`
- quota met only for IDOR and SSTI
- NoSQL was the riskiest under-quota class (`1/8`)

Added `scripts/training/generate_v4pro_teacher_topup_iter10.py`.

Purpose:

- read the live D1 manifest
- compute per-class deficits
- generate only under-quota classes into a separate output dir
- reuse the same V4-Pro prompt, held-out registry guard, blocked-goal recovery
  guard, and ingest guard

Active sessions:

- `aegispt_v4pro_d1_teacher64`: original D1 run
- `aegispt_v4pro_d1_topup`: focused top-up run
- `aegispt_v4pro_d1_final_mixwatch`: waits for both, then rebuilds
  `codex/results/training/iter9-combined-sft-mix-20260607/` using main D1,
  top-up D1, and the existing accepted V4-Pro smoke row

Top-up output dir:

`codex/results/training/v4pro-teacher-corpus-d1-topup-20260607/`

Generated top-up artifacts are in progress and are intentionally not committed
until the run finishes and the final mix can be verified.

## Codex continuation status — D1 finalized + committed artifact set (2026-06-07)

The long-running D1 jobs have now finished. No D1 tmux sessions remain active.

Final D1 numbers:

- main D1 accepted rows: 64
- top-up accepted rows: 19
- top-up deficits remaining: none
- combined per-class coverage after top-up:
  - `auth_logic_session_forgery`: 8
  - `idor_object_swap_token_reuse`: 8
  - `info_disclosure_credential_reuse_lateral`: 8
  - `lowpriv_to_admin_delegation`: 8
  - `nosql_filter_bypass_chain`: 8
  - `ssrf_internal_endpoint_recovery`: 8
  - `ssti_template_context_pivot`: 8
  - `xxe_document_parser_pivot`: 8

Final mix:

- output dir:
  `codex/results/training/iter9-combined-sft-mix-20260607/`
- `selected_total=16882`
- `curated_iter5=15999`
- `iter6_auth=800`
- `v4pro_demonstrated_iter9=83`

Commit policy:

- accepted train rows, scenario registries, manifests, and final gz mix are
  intended for commit
- raw/rejected V4-Pro dumps remain untracked because rejected rows include
  held-out-leak rejection metadata and are not needed by Claude's training path

## Codex continuation status — E-lane received, E3 done, E1/E2 pending (2026-06-07)

Claude's cold-start finding is now the controlling data hypothesis:

- the model has recovery intent
- it guesses the wrong exploration target
- it needs recovery-arc data per class, not just generic recovery wording

### E3 — per-class transfer scoring harness

Done.

Added `scripts/training/build_transfer_matrix_iter10.py`.

Committed baseline artifacts:

`codex/results/training/transfer-matrix-20260607/`

Baseline command:

`python3 scripts/training/build_transfer_matrix_iter10.py --run d2_oracle=codex/results/training/multichain-heldout-eval-envs-20260607 --manifest codex/results/training/multichain-heldout-eval-envs-20260607/aegispt_multichain_heldout_eval_envs_iter10_manifest.json --out-dir codex/results/training/transfer-matrix-20260607`

Observed baseline:

- `run_label=d2_oracle`
- `scenario_count=8`
- `chain_class_count=8`
- `result_count=8`
- `unknown_chain_class_count=0`
- all 8 D2 classes have oracle `solve_rate=1.0`,
  `recovered_after_block_rate=1.0`, and
  `used_revealed_value_rate=1.0`

How Claude should use it:

- run `jury_rl_model_rollout.py` against D2 held-out envs with a model label
- feed each output dir as `--run model_label=<rollout_dir>`
- compare class-level solve/recovery/revealed-value rates instead of relying
  on one aggregate gate score

### E1 — source-triage of 57 unknown XBENs

Done as conservative source-rule triage.

Input backlog:

`codex/results/training/xben-triage-backlog-20260607/aegispt_xben_triage_backlog_iter10.jsonl`

Hard rule: labels must come from source/readout evidence only. Neighbor context
is prioritization metadata and must not become a vuln label.

Added:

- `scripts/training/triage_xben_sources_iter10.py`
- `scripts/tests/test_xben_source_triage_iter10.py`

Output:

`codex/results/training/xben-source-triage-20260607/`

E1 result:

- `row_count=57`
- `source_missing_count=0`
- `source_classified=36`
- `needs_manual_source_review=21`
- evidence policy: file/line/rule IDs only; no source snippets
- classified classes:
  - `headless_xss_ssrf`: 17
  - `ssti`: 13
  - `jwt_or_file_read_auth_logic`: 2
  - `auth_gated_injection`: 1
  - `nosql_filter_bypass_chain`: 1
  - `unsafe_deserialization`: 1
  - `xxe`: 1

D3/D6 updated after E1:

- `scripts/training/build_xben_gap_matrix_iter10.py` consumes E1 JSONL when
  present
- vuln-class `unknown_untriaged` is now 21, down from 57
- backlog summary is now:
  - `covered_needs_rollout_eval=60`
  - `known_gap_needs_data=6`
  - `source_triage_required=21`
  - `source_triage_with_existing_evidence=21`

Manual source-review rows that remain out of training:

`XBEN-028`, `XBEN-039`, `XBEN-040`, `XBEN-041`, `XBEN-052`, `XBEN-054`,
`XBEN-055`, `XBEN-060`, `XBEN-061`, `XBEN-067`, `XBEN-069`, `XBEN-071`,
`XBEN-072`, `XBEN-078`, `XBEN-079`, `XBEN-083`, `XBEN-085`, `XBEN-086`,
`XBEN-095`, `XBEN-097`, `XBEN-098`.

### E2 — recovery-arc envs + teacher demos for unsolved/missing classes

Pending after E1.

Inputs:

- 6 current `known_gap_needs_data` items from refreshed D6
- the E1-discovered `unsafe_deserialization` gap
- existing other-stack/provider/manual buckets that still lack env/demo
- the 21 manual source-review rows are not valid E2 training inputs until
  direct source evidence exists

Required shape for every new class:

- RL env with deterministic oracle
- teacher demos
- blocked goal -> backtrack -> recover hinted resource -> reuse revealed value
  -> retry goal
- no held-out contamination
- no runtime binding
  until the training/eval lane explicitly consumes the artifacts
