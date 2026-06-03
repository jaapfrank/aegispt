# Diverse-target validation #2 — OWASP WebGoat (black-box) — 2026-06-03

Target #2 of the `feedback-live-proof-must-be-diverse-real-targets` bar (≥2 unrelated
real targets). #1 = Juice Shop (Node/Angular). WebGoat is a **different stack**
(Java/Spring), validating that AegisPT isn't over-fit to one app/framework.

## Result

Findings (DB, run on dedicated IP `127.0.0.201`): **5 high, 7 medium, 14 info (26 findings)**,
black-box, provider `chatgpt_oauth` (€0). WebGoat is heavily auth-gated (most lessons need
login), so black-box yield is recon/endpoint-heavy + the pre-auth surface — yet the agent
still produced 5 high-severity findings. Different stack, real app, real findings.

## SAFETY — dedicated-IP isolation (applied correctly this time)

Run on **dedicated IP `127.0.0.201:8080`** (NOT the shared `127.0.0.1`). Scope verified:
allowlist = `['http://127.0.0.201','http://127.0.0.201:8080/WebGoat','https://127.0.0.201']`,
contains `127.0.0.1` = **False**. Agent tool stdout scanned for `127.0.0.1:PORT` →
**NONE (clean)**. The agent could not reach our infra. (`feedback-local-test-dedicated-ip`;
now enforced by code — `run_external_target.py` refuses bare `127.0.0.1`, commit `ecf0db9` A3.)

## Combined diverse-target conclusion (#1 + #2)

| Target | Stack | Findings | Isolated |
|---|---|---|---|
| OWASP Juice Shop | Node/Angular | 23 (2 critical SQLi, 2 high) | ✅ 127.0.0.200 only |
| OWASP WebGoat | Java/Spring | 26 (5 high) | ✅ 127.0.0.201 only |

**AegisPT is validated beyond the XBOW benchmark on ≥2 unrelated real open-source apps,
black-box, each safely isolated on its own IP.** This is the operator-requested proof that
the system works on real targets, not just the synthetic benchmark.

## Evidence

`run-log.txt` (run_external_target.py log: `scope_hosts=['127.0.0.201']`).
