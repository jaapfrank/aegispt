# AegisPT — Reliability of Results & False-Positive Handling

*Honest engineering reference. Last updated 2026-06-02. Cross-checked against
`api/app/services/finding_verifier.py`, `api/app/services/m2_verdict_gate.py`,
`api/app/services/assessment_loop_internals/guards.py`, `scripts/check_finding_persistence_invariant.py`,
and `docs/methodology_mapping.md`.*

This document exists so the platform's reliability can be stated accurately to
customers, auditors, and operators — **without over-claiming**. Read it before
asserting what an AegisPT result proves.

---

## Samenvatting (NL — lees dit eerst)

- **Wat we testen volgens**: PTES (lifecycle), OWASP WSTG v4.2 (web/API-dekking),
  NIST SP 800-115 (discipline), OWASP ASVS v5.0.0 (optionele control-referentie),
  MITRE ATT&CK (interne emulatie), CVSS (severity). Zie `docs/methodology_mapping.md`.
- **Stuurt dit de tests?** Gedeeltelijk. De test-uitvoering is **emergent** —
  een AI-picker + tool-orkestratie kiest wélke tools/exploits draaien op dít
  target, begrensd door budget/approvals. Het is **géén** systematische
  "test elk WSTG-gebied af"-engine. De methodology-metadata stuurt vooral
  labeling en rapportstructuur, niet gegarandeerde volledige dekking.
- **Hoe betrouwbaar?** Gelaagd. **Captured-flag/exploited findings = hard bewijs.**
  Re-prover-bevestigde klassen = hoog. Al het andere = `UNCLASSIFIED`, bewaard
  voor menselijke review (dáár zitten de false positives).
- **False positives?** Drie mechanismen (re-prover, M2 verdict-gate, handmatige
  velden). Bekende gap: klassen zónder re-prover blijven `inconclusive` →
  `UNCLASSIFIED` → bewaard (lekken naar de operator).
- **Compliance (SOC2/ISO/PCI/NIS2/DORA/TIBER) = rapport-tijd mapping-views, GÉÉN
  certificeringen.** Afwezigheid van findings ≠ compliance.

---

## 1. Reliability tiers

Every finding is **evidence-first**: it links to raw artifacts (request/response,
transcript, hashes) so a human can verify. Reliability is NOT uniform:

| Tier | Finding type | How it is established | Trust |
|---|---|---|---|
| **Deterministic proof** | Captured flag / exploited (`DETERMINISTIC_PROOF`, `EXPLOITED`) | A grader-matchable flag literal (`xbow-…`/`flag{…}`/`aegispt{…}`) captured by any tool (E#10) **and** persisted as a finding with transcript (`evidence_ref`) + scope (`target_id`). Enforced by `scripts/check_finding_persistence_invariant.py`. | **Hard** — the flag either byte-matches the grader or it does not; no model judgment. |
| **Re-prover confirmed** | classes with an independent verifier strategy: `sqli` + `ssrf` (E#8), `admin_access`, `stored_xss`, `info_disclosure` | `finding_verifier.verify_finding` re-runs an **independent** HTTP check (a different code path than the originating runner) on critical/high findings → `confirmed`. | **High** — independently reproduced. |
| **Re-prover failed → dropped** | same classes, but not reproducible | verifier `failed` + no replay recipe → M2 gate `FALSE_POSITIVE` → dropped (when the gate is enabled). | n/a (removed) |
| **Unclassified / operator-review** | **everything else** (most tool findings) | no verifier strategy → `inconclusive` → M2 gate `UNCLASSIFIED` → **kept**. | **Variable** — real false positives live here. |

**Honest example (2026-06-02):** `smart-web-probe` emitted false-positive critical
"SQL Injection" findings on dead login forms with no backend SQL (XBEN-014/005).
Before E#8 these stayed `UNCLASSIFIED` (kept as critical). E#8 added a SQLi
re-prover, so they are now conclusively `FALSE_POSITIVE` and dropped
(`docs/validation/xbow-e8-sqli-reprover-2026-06-02/`).

## 2. False-positive handling — three mechanisms

1. **Pre-persistence independent re-prover** (`finding_verifier.py`). For
   `critical`/`high` findings (`VERIFIABLE_SEVERITIES`) a strategy is selected by
   `_select_strategy` and an independent HTTP re-check runs (bounded, scope-gated,
   evidence-attached). Verdict ∈ `confirmed` / `failed` / `inconclusive`.
   Strategies today: `sqli`, `ssrf`, `admin_access`, `stored_xss`, `info_disclosure`
   (+ the deterministic flag-proof exemption). All other titles → `inconclusive`.
2. **M2 verdict gate** (`m2_verdict_gate.py`). Maps verdict + replay-recipe to
   `EXPLOITED` / `DETERMINISTIC_PROOF` / `BLOCKED_BY_SECURITY` /
   `OUT_OF_SCOPE_INTERNAL` / `FALSE_POSITIVE` / `UNCLASSIFIED`. A `failed` finding
   with **no** replay recipe → `FALSE_POSITIVE`; when the gate is enabled
   (`AEGISPT_M2_VERDICT_GATE_ENABLED`) it is **dropped before persistence**.
   Captured flags are exempt (deterministic).
3. **Manual operator marking.** Findings carry `false_positive_reason`,
   `false_positive_confirmed_by`, and `validation_status` for human adjudication.

### The remaining gap (be explicit)

Re-provers exist for exactly the injection classes that a runner actually emits
as findings: **`sqli`** and **`ssrf`** (smart-web-probe), plus `admin_access` /
`stored_xss` / `info_disclosure`. The SSRF re-prover is conservative: it
conclusively drops only the cloud-metadata variant on a non-cloud target (a
recurring false positive); real internal-service/file variants stay `inconclusive`
(kept) unless content confirms them.

**SSTI, insecure-deserialization, and command-injection have NO re-prover — by
design, not omission: no runner currently emits findings of those classes**, so a
re-prover for them would be dead code (ANTI_DRIFT Rule 2). When a runner starts
emitting them, the re-prover should be added in the same change. Any finding class
without a re-prover (today: everything except the five above) returns `inconclusive`
→ `UNCLASSIFIED` → **kept** for operator review — that is where residual false
positives live.

The conservative design rule (all re-provers): return `failed` (→ droppable)
**only** when the issue is demonstrably not reproducible; on any doubt return
`inconclusive` (kept) — the system never drops a finding on uncertainty.

## 3. Coverage honesty — emergent, not a checklist

Test execution is driven by an **AI picker + tool orchestration** (recon → choose
tools → dispatch exploits), bounded by budget and approvals. AegisPT is **not** a
systematic engine that guarantees every WSTG area / every standard's test catalogue
is executed. WSTG/PTES/NIST drive **labeling and report structure** (the
`wstg_id`/`ptes_phase`/`nist_phase` finding metadata), **not** exhaustive coverage.

Practical consequence: **do not claim "full coverage" of any standard from a run.**
Coverage is what the orchestrator actually exercised, which the report shows
explicitly (tested areas, gaps, untested areas).

## 4. Compliance frameworks are mapping views, not certifications

Per `docs/methodology_mapping.md` and `docs/tiber_eu_alignment.md`, the
SOC 2 / ISO 27001 / PCI DSS / NIS2 / DORA / TIBER-EU report variants are
**report-time mapping views** over existing evidence-backed findings. They:

- do **not** assert control effectiveness, certification, validation, or attestation;
- treat **absence of findings as untested**, never as compliance;
- retain unmatched findings in a manual review queue and show controls without
  mapped findings as explicit untested/no-finding areas.

## 5. Customer-facing — do NOT claim

- ❌ "AegisPT certifies / validates / attests ISO 27001 / SOC 2 / PCI DSS / NIS2 / DORA / TIBER."
- ❌ "This run gives full WSTG / OWASP coverage."
- ❌ "No findings ⇒ the system is secure / compliant / resilient."
- ❌ "Every reported finding is confirmed." (Only `EXPLOITED` / `DETERMINISTIC_PROOF`
  / re-prover-`confirmed` findings are independently confirmed; `UNCLASSIFIED`
  findings are unconfirmed and may be false positives.)
- ✅ Safe to state: "Evidence-first, replayable results; confirmed exploits are
  independently verified; methodology mapped to PTES / OWASP WSTG v4.2 / NIST
  SP 800-115; compliance frameworks are evidence-mapping views, not certifications."

## 6. Source of truth (code)

| Concern | Code |
|---|---|
| Re-prover strategies + verdicts | `api/app/services/finding_verifier.py` |
| Verdict gate (drop logic) | `api/app/services/m2_verdict_gate.py` |
| Any-tool flag-capture (E#10) | `api/app/services/assessment_loop_internals/guards.py` (`persist_any_tool_flag_capture`) |
| Canonical-solve invariant | `scripts/check_finding_persistence_invariant.py` |
| Methodology / standards mapping | `docs/methodology_mapping.md` |
| EU/Dutch regulatory boundary | `docs/tiber_eu_alignment.md` |
