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

## The plan — 4 capability tracks, ROI-ordered

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
