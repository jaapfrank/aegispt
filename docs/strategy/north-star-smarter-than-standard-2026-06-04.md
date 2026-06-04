# North-star: smarter than the standard — autonomous, deliberate, future-proof — 2026-06-04

Operator's full vision (verbatim intent, 2026-06-04). This is the TRUE target; high
XBOW solve-rate via white-box source-surfacing is NOT it (XBOW = standard CTF vulns;
surfacing the source = hand-feeding the answer = what a scanner already does).

## The vision (7 pillars)
1. Find what other scanners MISS **and** what a standard scanner DOES see — comprehensive.
2. Work SMARTER: actually THINK first, then form a PLAN — deliberate, not reactive
   signature-matching.
3. On a DEAD END: re-reason at a higher level and try a DIFFERENT tactic; repeat.
4. EXHAUSTIVE: keep going until WE are confident the target is genuinely secure — not
   stop at the first miss or the time budget.
5. Outcome: give companies a real sense of security.
6. FUTURE-PROOF: automatically recognise NEW kinds of attacks, not only the ones we coded.
7. CONTINUOUS: ingest CVEs + zero-days, test them, stay current with the newest attacker
   techniques.

## Honest map: where we are vs the vision
- The INNER loop (interactive-exploit: request→observe→decide, gpt-5.5) is the right
  primitive for 2/3 — it explores + adapts, and just chained a multi-step admin takeover
  (XBEN-024). BUT it is somewhat REACTIVE (step-by-step) rather than "think → plan → act",
  and I have been BIASING it with white-box surfacing (pillar-2/6 anti-pattern).
- Pillar 1 (miss + see): standard coverage OK; beyond-standard weak (hand-fed).
- Pillar 2 (deliberate plan-first): weak — no explicit plan/hypothesis state it reasons over.
- Pillar 3 (dead-end re-reason → new tactic): partial — adapts per step + retries, but does
  not re-strategise at a higher level after a true dead end.
- Pillar 4 (exhaustive-until-secure): weak — stops on flag/budget, no "secure" judgement.
- Pillar 6 (recognise novel): weak — the frontier; recognises coded patterns, not novelty.
- Pillar 7 (CVE/0-day currency): partial — a CVE feed exists (cve_feed_sync_logs); not a
  closed "fetch latest → test → learn" loop.

## Task program (capability tracks — NOT individual challenges)
### S1 — Black-box exploratory baseline  [START: honest nulmeting]
Run interactive-exploit BLACK-BOX (no source surfacing) on known + real targets; READ the
transcript to judge reasoning quality: does it plan, notice anomalies, re-reason at dead
ends, or just react? Establishes the empirical gap before we strengthen reasoning.

### S2 — Deliberate "think → plan → act" inner loop
The loop forms an explicit PLAN/hypothesis set from observations BEFORE acting, and revises
it. Maintain a running plan state it reasons over (not just last-response reaction).
Policy-safe framing (neutral; gpt-5.5 refuses aggressive prompts).

### S3 — Dead-end re-strategise
On N non-productive steps, the loop STEPS BACK: summarise what's been ruled out, hypothesise
a fundamentally different tactic (different vuln class / different surface), pursue it.
Subsumes "don't stop while leads remain" (old T0.3).

### S4 — Exhaustive coverage + "secure" judgement
Don't terminate on first miss/budget; track UNtested surface + open hypotheses; only finish
when coverage is exhausted, and emit a confidence-of-security verdict for the report (pillar 5).

### S5 — Novelty recognition (frontier)
Reason from the app's intended logic + anomalies to find non-signature flaws (business logic,
unexpected chains). Hard; measured on real apps with non-standard flaws, not XBOW.

### S6 — CVE / zero-day currency loop
Close the loop: ingest the latest CVEs/0-days, derive test payloads, run them, keep current.
Builds on the existing CVE feed.

### S7 — Controllable (uncensored) model — the refusal-ceiling fix  [strategic foundation]
Operator (2026-06-04, correct): ChatGPT/Claude REFUSE offensive work (we hit
`policy_refusal` on XBEN-024). With only commercial models we always lag + are gagged; a
licence from OpenAI/Anthropic is unlikely (Trusted-Access pending). The sound foundation is
a CONTROLLABLE model we own + keep current. Architecture ALREADY supports it: the
interactive-exploit adapter layer is provider-agnostic (make_adapter), `AEGISPT_LOCAL_LLM_URL`
(:8801) is wired, and DeepSeek (less-censored, OpenAI-compatible, key in ~/.aegispt-secrets)
is already an adapter.
- NOW (bridge): run the exploit loop on DeepSeek — far less refusal than gpt-5.5, available
  today, no training needed.
- DEEP: a local fine-tuned 7-14B (Qwen/Llama / a security-tuned model) at :8801, trained on
  curated offensive data (CVE/0-day PoCs, ExploitDB, Metasploit modules, write-ups).
- CURRENCY (pillars 6-7): RAG over a CVE/exploit knowledge base is FASTER than retraining —
  inject the latest exploit knowledge into context; fine-tune for the deeper step.
- ARCHITECTURE: HYBRID — strong commercial model for general reasoning/planning (no refusal
  there), local-uncensored model for the actual exploit-payload generation (where commercial
  refuses). Best of both.
- HONEST: training + maintaining a competitive local offensive model is a real ML program
  (data curation, fine-tune, eval, keep-current), not a one-shot. The foundation exists.

#### S7 — Concrete BLACKWELL-NATIVE stack (operator-identified, 2026-06-04)
GPU = RTX 5080 Laptop 16GB (Blackwell sm_120). llama.cpp's bleeding-edge sm_120 build is
flaky; the right tools are Blackwell-native:
- **SERVE: vLLM** (sm_120-native, OpenAI-compatible, agentic/high-concurrency = our exploit
  loop). Install (no sudo, dedicated venv): `python -m venv vllm-venv; vllm-venv/bin/pip
  install vllm` — pulls torch + the `nvidia-*-cu13` CUDA-13 stack + `gguf` (so it can load
  our Qwen GGUF) + flashinfer/xgrammar. Serve OpenAI-compatible on :8801 → point
  AEGISPT_LOCAL_LLM_URL there. NOTE: Qwen3.6 (qwen35 arch) is brand-new — verify vLLM
  supports it; else use an HF AWQ/GPTQ 4-bit uncensored Qwen3 quant that fits 16GB.
- **TRAIN / keep-current (pillars 6-7): Unsloth** QLoRA on the Blackwell GPU. `pip install
  unsloth`; `FastLanguageModel.from_pretrained(model, load_in_4bit=True,
  full_finetuning=False)`, batch 2 / grad-accum 4 / rank 32, QLoRA on all linear layers. On
  16GB realistically an 8-14B base (5090/32GB does up to 40B). Fine-tune on curated
  CVE/0-day/exploit/write-up data; deploy the LoRA via vLLM. Source: NVIDIA "Train an LLM on
  a Blackwell Desktop with Unsloth" + r/Pentesting local-LLM thread.
- Other Blackwell engines (heavier): TensorRT-LLM (MXFP8/MXFP4), NVIDIA Dynamo.

## Discipline
- BLACK-BOX is the honest test of "smart" (no source crutch). Diverse REAL apps, dedicated
  IPs (memory feedback_local_test_dedicated_ip), never the standard-vuln source-surfacing path.
- Measure reasoning DEPTH (plans, re-strategising, novel finds), not just XBOW solve-count.
