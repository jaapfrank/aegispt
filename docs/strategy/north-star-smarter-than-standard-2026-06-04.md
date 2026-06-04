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

## Discipline
- BLACK-BOX is the honest test of "smart" (no source crutch). Diverse REAL apps, dedicated
  IPs (memory feedback_local_test_dedicated_ip), never the standard-vuln source-surfacing path.
- Measure reasoning DEPTH (plans, re-strategising, novel finds), not just XBOW solve-count.
