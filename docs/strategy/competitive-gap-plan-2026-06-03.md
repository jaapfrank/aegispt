# Competitive-gap plan — closing 15% → 96% on XBOW (2026-06-03)

## Where we stand vs the competition

| System | XBOW solve-rate (source-aware) |
|---|---|
| **Shannon** (reference/competitor) | **96.15%** (~100/104) |
| **XBOW** (the company's own agent) | high (benchmark is theirs) |
| **AegisPT (us), 2026-06-03** | **16/104 ≈ 15%** |

We are ~81 points behind. This session's dispatch-gate fix (`884430f`) unlocked the
**easy tranche** (no-auth, single-service, source-aware injection: SSTI/XXE/SQLi/cmd/pickle).
The remaining 88 are NOT 88 separate tasks — they cluster behind **4 capability gaps**.
We do NOT lack exploit skill on the classes we've solved; we lack the ability to REACH
the vuln (auth, multi-service startup, headless callback) and to handle logic/other-stack.

## The 88 unsolved, categorized (full 104-survey — `/tmp/survey_full.py`)

| Cluster | # | Why we can't solve it yet |
|---|---|---|
| **phantomjs headless** | 23 | needs an OOB-callback exploit (bot renders attacker input → exfil); no capability |
| **auth-gated injection** (SSTI/jwt/etc. behind login) | ~30 | we CAN exploit the vuln, but can't get PAST auth (login / JWT-forge / session) |
| **business-logic / IDOR / race** (PHP shops) | ~8 | multi-step stateful reasoning (price/coupon manipulation, IDOR, race) — model frontier |
| **other-stack / framework-CVE** (PHP CMS 044, Java/JSP 035, non-web) | ~6 | broader sink coverage + non-Python/PHP stacks |
| **multi-service (crosscuts the above)** | ~20 | CRASH at `up --wait` (broken curl healthcheck) — can't even RUN |

## TOP PRIORITY (operator-set 2026-06-03): CLOSE THE RECON→ACTION LOOP

**The single most important gap, proven on a live target — the system is recon-HEAVY,
action-LIGHT. It DISCOVERS but does not ACT.** Two operator observations, one root cause,
hard-confirmed on the Google Gruyere run (`15357dd6`):

1. **Discovered endpoints are not attacked.** content-discovery found **20 endpoints / 18
   distinct paths** — including `/admin` (the admin panel), `/upload.gtl` (file upload →
   potential RCE), `/saveprofile` (the stored-XSS sink), `/saveacct`, `/editprofile.gtl`.
   They were emitted as passive "Hidden Endpoint Discovered" findings and **dropped** — the
   agent never probed `/admin` for access-control bypass, `/upload.gtl` for unrestricted
   upload, etc. Discovered surface MUST feed back as TARGETS the loop systematically attacks.
2. **Found vuln-chains are not exploited to impact.** The agent found the EXACT admin-takeover
   chain — `Stored XSS via Profile Homepage Field` + `Session Cookie Theft via XSS` (both
   critical) — but **ALL 29 findings are `unvalidated`**: it stopped at "detected" and **never
   gained admin access**. Operator: "hij had gewoon admin access moeten vergaren."

A findings list without proven impact is a scanner, not a pentester. The competition (XBOW
etc.) CHAINS discovery → action → impact (flag / admin / account-takeover); we stop at
"detected". This is where our strength MUST be.

### Track 0 (NOW #1) — recon→action loop closure
- **0A Discovered-surface feedback:** every content-discovery endpoint, parameter, form,
  and gate-token becomes a first-class TARGET the picker iterates over — per-endpoint probe
  matrix (auth/access-control, injection, IDOR, upload, redirect, SSRF), not a passive finding.
- **0B Exhaustive follow-through:** the loop does not terminate while undr-tested discovered
  under-tested discovered surface remains; "Hidden Endpoint Discovered" is a TODO, not a deliverable.
- **0C Chain-to-impact (was Track C):** OOB-callback + victim-simulation to COMPLETE chains
  to `EXPLOITED` (admin session / account-takeover / flag) — see Track C* below.
- **Discipline rule:** never stop at `unvalidated` findings; push every chainable finding to
  `EXPLOITED`. Acceptance: re-run Gruyere → a `validation_status=exploited` admin-session
  finding + evidence each discovered endpoint was actively tested.

**This is the same capability as Track C** (the 23 phantomjs XBOW challenges): the win
requires a VICTIM (admin/bot) to render the attacker payload + an OUT-OF-BAND capture of
the result. So Track C is promoted to **#1** and reframed:

### Track C* (NOW #1) — chain-to-impact: OOB-callback + victim-simulation
- **C1** An in-scope attacker callback/collaborator server the agent controls (receives the
  exfil: stolen cookie, SSRF/blind-injection beacon, OOB DNS/HTTP).
- **C2** Victim-simulation: trigger the admin/bot to render the stored/reflected XSS (or the
  app's own headless renderer — phantomjs/puppeteer) so the payload fires in the victim
  session → exfil the admin cookie to C1 → REPLAY it to obtain an authenticated admin session.
- **C3** A `headless-exploit` / `chain-to-takeover` runner: the win condition is the
  EXPLOITED outcome (admin session / flag), NOT a detected hypothesis.
- **Discipline rule:** do not stop at `unvalidated` findings — push every chainable finding
  to `EXPLOITED` (admin/account-takeover/flag). Re-run Gruyere with objective "gain admin
  access" once C1-C3 exist; acceptance = a `validation_status=exploited` admin-session finding.
- **Acceptance (XBOW):** ≥3 phantomjs solves (004/008/011/047). Same mechanism.

## The plan — supporting tracks, ROI-ordered

### Track A — Harness robustness (PREREQUISITE, cheap, do first)
Without this, ~20 multi-service challenges CRASH before the agent runs.
- **A1** `_docker_challenge`: replace `up -d --wait` with `up -d` + poll the target port for
  HTTP reachability (root cause `1e3e31d`: app works, `curl` missing from healthcheck image).
- **A2** Pre-pull DB images + retry-on-pull for multi-service compose.
- **A3** `run_external_target.py`: auto-assign a free `127.0.0.X` + exact-scope for local
  docker targets (safety + the diverse-target work needs it; `feedback-local-test-dedicated-ip`).
- **Acceptance:** XBEN-094/100 + the multi-svc cluster BUILD (not CRASH); re-measure solve-rate.

### Track B — Reliable authentication (BIGGEST ROI, ~30 challenges)
Generalize E#12. We already exploit SSTI/jwt/etc. post-auth; we just can't log in.
- **B1** Cred-vault wiring: pre-recon-source seeded creds auto-populate a vault that
  `auth-flow` / `interactive-exploit` consume → authenticate BEFORE exploiting.
- **B2** JWT/session forgery: on a leaked `SECRET_KEY`/`secret_key`, forge an elevated
  token/cookie (proven once on XBEN-005; make it a first-class capability + Flask-session forge).
- **B3** Stateful auth in `interactive-exploit`: login → hold cookie → exploit in one session
  (the XBEN-024/032 failure mode — agent must chain auth+exploit, not restart per dispatch).
- **Acceptance:** ≥5 NEW auth-gated solves (e.g. 001/003/021/058 SSTI-behind-login, jwt class).

### Track C — phantomjs headless-XSS/SSRF capability (BIGGEST CLASS, 23)
The largest single cluster. Needs an out-of-band callback.
- **C1** In-scope attacker callback server the agent controls (receives exfil).
- **C2** Inject XSS/SSRF the headless bot renders → exfil flag/cookie to the callback.
- **C3** A `headless-exploit` runner/specialist (win = JS fired in the bot, not server state).
- **Acceptance:** ≥3 phantomjs solves (004/008/011/047 family).

### Track D — business-logic / IDOR / race + other stacks (long tail, ~14)
- **D1** Business-logic/IDOR/race reasoning (object-ID enumeration, price/coupon tamper,
  TOCTOU race) — multi-step stateful; may need a stronger model or a structured planner.
- **D2** Broader sink coverage: PHP framework CVEs (044), Java/JSP (035); characterize the
  remaining non-web "unknown" challenges (031/034 had no detectable source).

## Sequencing & projected trajectory

A (prereq) → B (biggest ROI) → C (biggest class) → D (tail).

| After | Projected solves |
|---|---|
| A + B | ~16 → ~40-48 |
| + C | ~63-71 |
| + D | toward ~85-96 |

## Strategic note — the real-world axis (a differentiator the benchmark hides)
Shannon's 96% is on the SYNTHETIC benchmark. This session also proved AegisPT works
**black-box on a real app** (OWASP Juice Shop: 23 findings incl. 2 critical SQLi, no source,
`docs/validation/diverse-target-juice-shop-2026-06-03/`). Real-world black-box capability is
how a PRODUCT is judged, and is harder than the source-aware benchmark. Keep a parallel
**Track E — real-world black-box hardening** (recon depth on SPAs, authenticated crawling,
the diverse-target matrix ≥2 unrelated apps) as the product differentiator, not just the score.

## Provider note
chatgpt_oauth (gpt-5.5, €0) solves most classes but REFUSES some (eval/arbitrary-code RCE:
XBEN-082 `policy_refusal`). Track B/C runs that hit refusals → retry on `deepseek-v3` /
`gemini-3.1-pro` (Trusted-Access-for-Cyber still pending).
