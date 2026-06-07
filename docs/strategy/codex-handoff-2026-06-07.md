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

## P3 — Hygiene (with P1/P2)

- Add every new env + every demonstrated-data scenario_hash to the **held-out registry**
  and the contamination guard. The held-out deep-chain IDs must NEVER appear in any
  training/demonstrated set.
- Keep iter8 multi-service going as P3 diversity, below P1/P2.

Claude's side (parallel): DPO-LLMSVS gate (running) → IDOR-focus re-tune gate → if it hits
the wall, RL on your P2 envs. Jury flywheel (reviewers/calibration/committee/process-reward)
is complete and ready to consume P1 data + P2 rollouts.
