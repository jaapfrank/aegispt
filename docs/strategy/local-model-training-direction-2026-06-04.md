# Local-model training direction — COMMITTED (2026-06-04)

Operator concern (verbatim intent): "ja als je zeker weet dat dit het beste is.
Dat ik niet over een week weer een nieuw en totaal ander verhaal van je krijg en
een sorry." → This document is the **anchored decision of record** so the
direction is a contract, not a mood. It separates the STABLE CORE (will not
change) from REFINEMENTS (evolve *within* the same core, never replace it).

## Why this is durable (not my opinion — the field consensus)

Every SOTA autonomous-pentest LLM converges on the SAME recipe, independently:
- **xOffense** (arXiv 2509.13021, 79% sub-task, beats PentestGPT/VulnBot):
  Qwen3-32B fine-tuned on **Chain-of-Thought pentest data** + recon/scan/exploit
  **specialist agents** + orchestration.
- **CyberLLMInstruct** (arXiv 2503.09334): instruction-response pairs from real
  attack data + vuln reports + synthetic/counterfactual.
- **Pentest-R1** (arXiv 2508.07382): CoT reasoning optimised by RL (a *later* layer).
This convergence is why the core below is stable: it is the field's answer, and it
*builds on AegisPT's existing architecture* (picker_specialists ≈ xOffense's
specialist agents; the provider-agnostic adapter layer), not a rewrite.

## STABLE CORE — committed, will not change next week

1. **Controllable LOCAL model is the foundation.** Commercial models refuse
   offensive work + lag; the owned, fine-tunable local model is the answer.
   Served GPU-accelerated on Blackwell via llama.cpp (proven). HYBRID:
   commercial for neutral reasoning, local for offensive generation /
   refusal-fallback.
2. **Parameter-efficient fine-tuning on the local model** (PEFT on the verified
   Blackwell stack: torch cu128 + bitsandbytes 4-bit, sm_120). Adapter-based, so
   the *method* can improve without changing the approach.
3. **Data = Chain-of-Thought, multi-phase PENTEST curriculum**, not disconnected
   facts. The model learns the VAK: identity/mission + methodology
   (recon→enumerate→hypothesise→exploit→prove→pivot→report) + vuln taxonomy
   (OWASP/CWE) + real CoT reasoning + technique + tactical execution.
4. **Reinforces the existing specialist architecture**, does not replace it.
5. **Clean provenance**: public/legal sources only (NVD/CVE, ExploitDB, MITRE
   ATT&CK, Project-Zero/ZDI disclosures, open CoT datasets). Never scrape closed
   criminal forums. Be a *discoverer* (generalise patterns → novel variants), not
   only a consumer of public CVEs.

## REFINEMENTS — evolve within the core (these are NOT new stories)

- **Method: QLoRA → QDoRA + LoRA+** (combined — they are orthogonal). DoRA
  (`use_dora=True`; NVIDIA/ICML-2024) = adapter ARCHITECTURE (decompose weight
  into magnitude+direction): +3-4 pts over LoRA, less hyperparameter-sensitive,
  zero inference overhead. LoRA+ (Hayou et al. 2024) = OPTIMIZER setting (B
  matrices get ~16x the A matrices' LR via `create_loraplus_optimizer`): faster,
  more stable convergence. Combining = DoRA's precision + LoRA+'s stable LR
  (operator tip 2026-06-04). Both are toggles (`AEGISPT_TRAIN_USE_DORA`,
  `AEGISPT_TRAIN_LORAPLUS_RATIO`) → if either has a 4-bit/Blackwell compat issue,
  fall back WITHOUT changing the plan (the data approach is method-agnostic).
- **rsLoRA** (`use_rslora=True`, alpha/sqrt(r) scaling): lets RANK go to 32/64/128
  for a large CoT corpus WITHOUT gradient collapse, 0% extra compute. WIRED
  (`AEGISPT_TRAIN_RANK`). So the committed adapter method = **QDoRA + rsLoRA +
  LoRA+** (architecture + stable-scaling + optimizer — all orthogonal, all in PEFT).
- **Unsloth** (operator-recommended, 2x faster + less VRAM, optimised DoRA for
  cybersec): TEST on the Blackwell sm_120 stack at iter-3; adopt if it loads
  cleanly, else stay on plain PEFT (which is verified). A speed refinement, not a
  direction change.
- **EVAL-GATED candidates (must beat the committed stack on OUR eval —
  `deep_chain_eval` + live — before adoption, per anti-drift):** GaLore (projected-
  gradient near-full-FT — deeper but a different paradigm), base-model swap
  (DeepSeek-Coder vs Qwen3-8B-abliterated), AdaLoRA (dynamic rank pruning).
- **Later layer: RL** (à la Pentest-R1) on top of the SFT curriculum — additive,
  not a pivot.
- **Datasets for the CoT curriculum (public/legal, verified open):**
  `Trendyol/Trendyol-Cybersecurity-Instruction-Tuning-Dataset` (~53k),
  `WNT3D/Ultimate-Offensive-Red-Team`, `trend-cybertron/Primus-Seed` (Trend Micro,
  MITRE ATT&CK/threat-intel = methodology layer; the gated `trendmicro-ailab`
  original mirrored open), `expertdata-factory/cybersecurity-reasoning-cot-v1`
  (Project-Zero-sourced CoT), `detoxioai/exploit_db_train_v1` (PoC). CyberLLMInstruct
  (arXiv 2503.09334) to locate. Plus the collected corpus (47k ExploitDB + 24k CVE).
- **Dataset STRUCTURE = ~90% of success** (operator + field): Instruction→Input→
  Response SFT format; DEDUP / no over-repetition (don't drown the model in
  identical boilerplate output). The iter-3 builder enforces both.
- **Dataset growth**: synthetic curriculum + open CoT datasets
  (`expertdata-factory/cybersecurity-reasoning-cot-v1` from real research incl.
  Project Zero; `detoxioai/exploit_db_train_v1`) + the collected corpus (47k
  ExploitDB + 24k recent CVE) transformed into generalisation/variant CoT.

## Iteration plan (each builds on the last, same direction)

- **Iter-1 DONE**: synthetic follow-through (the building block). PROVEN: loss
  2.6→0.14; held-out generalisation (base rambles, trained emits the correct
  follow-through action). [[project_qlora_followthrough_trained]]
- **Iter-2 RUNNING**: deep multi-step (6-8 step) tactical chains. Eval =
  `deep_chain_eval.py` (adaptive target, fair).
- **Iter-3 NEXT (this commitment)**: the "knows-its-vak" CoT curriculum
  (identity + methodology + real CoT reasoning + technique), trained with QDoRA.
- **Iter-4+**: corpus-transform (generalisation), then RL.
- **QUALITY/EVAL PHASE (committed, the next priority — the gains are now in
  quality+ordering+evaluation, not more JSONL):** the biggest lever is making
  sure payload-training makes the system BETTER, not just "payload-happy". Order:
  1. **Dataset mixer** (`scripts/training/make_training_mix.py`, DONE): weighted
     blend 50% full-coverage / 25% open-corpus / 25% payload, exact-hash dedup,
     and a NO-LEAKAGE guard (drops any train conv whose hash is in *_eval/*_test —
     caught 306 full_coverage train/eval overlaps on first run). Manifest + seed.
  2. **Held-out eval harness + adapter GATE** (`scripts/training/eval_harness.py`,
     DONE): scores schema_ok / action_match / evidence_ok / safety_ok (no
     destructive/persistence/brute-force; approval-gating when approval_required)
     per family on the *_test splits; `--gate-vs prev.json` blocks promoting an
     adapter that does not beat the previous. Only promote what is measurably
     better on deep_chain_eval + this harness.
  3. **Negative/contrastive examples** (Codex, data): per payload class, cases
     where the model must NOT payload (out-of-scope / no-approval / prod /
     destructive requested / no baseline) — kills "payload-happy".
  4. **DPO/ORPO** (preference pairs good=scope→smallest-proof→evidence→cleanup vs
     bad=raw-exploit-spam/no-evidence/out-of-scope; TRL DPOTrainer — my lane).
  5. **GRPO/RL** (TRL) with reward = valid-JSON + correct class + evidence +
     cleanup, penalty = scope-bypass / payload-without-approval. The "later RL"
     layer made concrete.
  6. **Dedup/contamination guard** across all splits (hash + MinHash/semantic).
  Division: Codex = data (negatives, DPO pairs, more payload domains AD/cloud/LAN/
  IoT); me = mixer + eval harness + DPO/GRPO training + the eval gate.

## Anti-drift contract for this lane

If a genuinely better METHOD appears, it slots in as a REFINEMENT (a flag/an
added layer) — it does NOT restart the direction. The STABLE CORE above is fixed.
Any proposal to change the core must cite evidence it beats this on OUR eval
(`deep_chain_eval.py` + live XBEN/Gruyere), not a blog headline. Pipeline of
record: `scripts/training/` (version-controlled, reproducible).

Sources: NVIDIA DoRA blog + arXiv 2402.09353; xOffense 2509.13021;
CyberLLMInstruct 2503.09334; Pentest-R1 2508.07382; Google Tunix (JAX/TPU — noted,
not adopted: we are PyTorch/CUDA on Blackwell).
