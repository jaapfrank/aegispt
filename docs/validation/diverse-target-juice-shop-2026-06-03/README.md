# Diverse-target validation #1 — OWASP Juice Shop (black-box) — 2026-06-03

Operator-requested (`feedback-live-proof-must-be-diverse-real-targets`): prove AegisPT
works on a real open-source app, not just the XBOW benchmark. This is target #1
(Juice Shop); WebGoat is target #2 (`docs/validation/diverse-target-webgoat-*`).

## Result — AegisPT works black-box on a real non-XBOW app

| Severity | Finding (all canonical, real Juice Shop vulns) |
|---|---|
| **critical** | SQL Injection — Admin Login Bypass (`' OR 1=1--`) |
| **critical** | SQLi — Product Search UNION Data Extraction |
| **high** | Reflected XSS via URL Path Component |
| **high** | Path Traversal — Restricted File via Null Byte / Encoding |
| medium ×6 / info ×13 | Hidden Endpoint Discovery (content-discovery) |

**Total: 2 critical, 2 high, 6 medium, 13 info (23 findings)** — black-box (no source),
provider `chatgpt_oauth` (gpt-5.5, €0; no policy_refusal on this target). The
critical/high are Juice Shop's well-known real vulnerabilities, so the detections are
genuine. Findings are currently `unvalidated` (probe-detected hypotheses matching the
known real vulns; the verifier confirms a subset). run `36c85811-afeb-4932-bf9b-b72a15a82975`,
engagement `f8c3df21-0871-48e9-8666-fe93e2b7a17f`.

## SAFETY — dedicated-IP isolation (the operator's catch)

**The first attempt was MIS-SCOPED and is the cautionary tale.** I ran Juice Shop on the
shared `127.0.0.1:3000`; `run_external_target.py` derived scope = bare host `127.0.0.1`
(allowlist `['http://127.0.0.1','http://127.0.0.1:3000','https://127.0.0.1']`) — the SAME
host our own API (`:8000`) + postgres (`:5432`) run on. The operator caught it
(`feedback-local-test-dedicated-ip`). Empirically the agent only hit `:3000` and our
`:8000/:5432` were not in the allowlist, so no real harm — BUT the scope covered the
shared host (`:80/:443`), which is unsafe, and it ALSO made the assessment probe the
wrong port (`127.0.0.1:80`, empty) → that run found **0 findings**.

**Fix:** rebind to a DEDICATED loopback IP `127.0.0.200:3000` and scope to it:

| Check | Mis-scoped (1st) | Dedicated-IP (corrected) |
|---|---|---|
| scope allowlist | `127.0.0.1` (+`:3000`) | `127.0.0.200` only |
| contains our API `:8000`? | (host-broad) | **False** |
| contains `127.0.0.1`? | yes (host) | **False** |
| agent touched our infra? | no (lucky) | **NONE — only `127.0.0.200`** (grep of all agent tool stdout) |
| findings | 0 (wrong port) | **23 (2 critical)** |

So the dedicated-IP fix delivered BOTH safety (agent physically cannot reach our infra)
AND a correct assessment (right port → real vulns found).

## Honest takeaways

1. **AegisPT generalizes beyond XBOW** — it found the canonical critical SQLi + XSS +
   path-traversal on a real app, black-box. The earlier "black-box is weak" read was
   purely the scope bug, now corrected.
2. **Local test targets MUST get a dedicated IP** (`feedback-local-test-dedicated-ip`).
   CODE FOLLOW-UP: `run_external_target.py` should auto-assign a free `127.0.0.X` +
   scope to the exact host:port for local docker targets, so this is the default.
3. Driver completed only 2 iterations in 900s (slow synchronous iterate) — findings came
   mostly from the seed recon/probe batch; deeper exploitation would need more budget.

## Evidence

`run-log.txt` (the run_external_target.py log — note `scope_hosts=['127.0.0.200']` and the
final FINDINGS-by-severity dump).
