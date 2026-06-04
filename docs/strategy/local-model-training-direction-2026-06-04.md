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
- **Later layer: RL** (à la Pentest-R1) on top of the SFT curriculum — additive,
  not a pivot.
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

## Anti-drift contract for this lane

If a genuinely better METHOD appears, it slots in as a REFINEMENT (a flag/an
added layer) — it does NOT restart the direction. The STABLE CORE above is fixed.
Any proposal to change the core must cite evidence it beats this on OUR eval
(`deep_chain_eval.py` + live XBEN/Gruyere), not a blog headline. Pipeline of
record: `scripts/training/` (version-controlled, reproducible).

Sources: NVIDIA DoRA blog + arXiv 2402.09353; xOffense 2509.13021;
CyberLLMInstruct 2503.09334; Pentest-R1 2508.07382; Google Tunix (JAX/TPU — noted,
not adopted: we are PyTorch/CUDA on Blackwell).
