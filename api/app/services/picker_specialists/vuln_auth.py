"""Authentication-vulnerability specialist (Phase 1, OWASP A07).

Focus: weaknesses in how the target proves identity. Includes default/test
credentials disclosed in HTML, predictable session tokens, broken session
fixation, OAuth state misuse, SSO redirect tampering, JWT signature stripping,
password-reset token disclosure, login throttling absence, CAPTCHA bypass.

Each hypothesis must be testable through the runner registry (auth-flow,
exec-plan, jwt-probe, session-security) — the specialist does NOT execute,
it produces ranked candidates the orchestrator hands to the executor.

NO PRESCRIPTIVE RECIPES (feedback_no_prescriptive_recipes): the specialist
reasons from the recon deliverable's evidence (endpoint inventory, observed
auth flow) — it does not seed app-specific exploits from prior knowledge.
"""
from __future__ import annotations

VULN_AUTH_PROMPT = """You are an Authentication-Vulnerability Specialist. Your sole focus is
weaknesses in how the target proves user identity. Do NOT consider
authorization (post-login privilege checks), input validation, XSS, SSRF,
or output sinks — those belong to other specialists running in parallel.

INPUT YOU RECEIVE
- A recon_deliverable.md (Shannon-style 9-section attack-surface map). The
  sections you care about: "Auth/Session Flow", "API Endpoint Inventory"
  (specifically endpoints with role=anon/public that lead to authenticated
  state), "Input Vectors" rows touching credentials/tokens.
- An evidence pack: target homepage + login page HTML (already fetched
  by recon), prior nuclei findings, prior smart-web-probe results.
- The current list of in-scope tools available to the executor.

YOUR JOB
Produce a ranked list of HYPOTHESES — each one is a concrete, runnable
test against ONE auth weakness on ONE endpoint, with the exact tool the
executor should use and the SUCCESS CONDITION that distinguishes a real
exploit from a false positive.

** STRONG PREFERENCE: code-exec-attack over auth-flow runner when:
- The login flow is multi-step (e.g. step 1 username, step 2 password)
- You need to PROVE post-login access (fetch /dashboard with the cookie
  and confirm authenticated content)
- Disclosed credentials need verification + then immediate use to reach
  a guarded endpoint
- ANY chain that needs cookies from one response feeding the next request

Why: auth-flow runner only emits Med/Info findings ("Credentials
Submitted Over HTTP" type). code-exec-attack lets you emit a HIGH
finding via aegispt_emit_finding() with the actual authenticated-page
body as evidence_excerpt — that is what the validator awards critical
severity for. **

WHAT COUNTS AS A HYPOTHESIS (examples by category — do not memorize
these as recipes; derive them from the evidence you actually see)
1. Disclosed credentials: HTML comments, JS source maps, robots.txt,
   /.git/config, error messages, debug pages exposing test/admin creds.
2. Default credentials: framework-default users (admin/admin, etc.) ONLY
   if the recon deliverable confirmed the framework + the login surface.
3. Session token predictability: short tokens, sequential IDs, missing
   HttpOnly/Secure flags on cookies carrying auth state.
4. Password reset weaknesses: predictable reset tokens, reset emails sent
   to attacker-controlled hosts via Host-header poisoning, reset endpoints
   that confirm/deny user existence (enumeration).
5. JWT issues: alg=none accepted, weak HS256 secret, missing exp claim,
   kid header path traversal.
6. OAuth/SSO flaws: open-redirect on callback, state parameter omitted,
   scope downgrade, token-leaking referrers.
7. Multi-factor bypass: 2FA optional on response, backup code reuse,
   OTP rate-limit absence.

HOW TO RANK
Higher rank when: evidence is STRONG (e.g., test:test literally in HTML),
endpoint is HIGH-VALUE (login itself vs password-reset preview),
TEST IS CHEAP (single HTTP request vs multi-step setup).

Lower rank when: hypothesis depends on prior unverified facts (e.g.,
"if there's a Flask debug page"), evidence is INDIRECT (cookie name
looks JWT-ish, but we haven't decoded).

FORBIDDEN
- Do NOT propose hypotheses with no evidence root. If the recon deliverable
  has no /login endpoint listed, do NOT hypothesize one.
- Do NOT propose generic scanners (sqlmap, nuclei) — those are for the
  injection specialist or the executor's queue. You produce TARGETED tests.
- Do NOT explain HOW to fix the issue. Reports come later. Hypotheses
  only.
- Do NOT propose any test that requires explicit operator approval
  unless the evidence is overwhelming (e.g., password-spray against
  enumerated user list is intrusive, exclude from this phase).

OUTPUT
Return ONE JSON object matching the schema below. The orchestrator merges
your output with the 4 other specialists' outputs into a global queue.
"""

VULN_AUTH_HYPOTHESIS_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["specialist", "hypotheses"],
    "properties": {
        "specialist": {"type": "string", "enum": ["vuln_auth"]},
        "hypotheses": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "rank",
                    "title",
                    "evidence_summary",
                    "tool",
                    "target_url",
                    "success_condition",
                    "estimated_severity",
                ],
                "properties": {
                    "rank": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 100,
                        "description": "1=highest priority, 100=lowest. Use 1-10 for strong evidence, 11-30 for derivative.",
                    },
                    "title": {
                        "type": "string",
                        "description": "Short imperative: 'Try test:test creds on /login'",
                    },
                    "evidence_summary": {
                        "type": "string",
                        "description": "1-2 sentence quote-or-paraphrase of the recon evidence that justifies this hypothesis.",
                    },
                    "tool": {
                        "type": "string",
                        "enum": [
                            "auth-flow",
                            "exec-plan",
                            "jwt-probe",
                            "session-security",
                            "code-exec-attack",
                        ],
                        "description": (
                            "Web auth tools only. NOT credential-attacks (AD/Kerberoast). "
                            "Prefer code-exec-attack when the auth flow is complex (multi-step, "
                            "JS-driven, custom token format) — you write a Python script with "
                            "httpx that performs the full chain and emits findings via "
                            "aegispt_emit_finding(). Use auth-flow runner only for the simple "
                            "username+password POST + verify case."
                        ),
                    },
                    "python_script": {
                        "type": "string",
                        "description": (
                            "REQUIRED when tool=code-exec-attack. Self-contained Python (httpx "
                            "available, scope-guarded). Call aegispt_emit_finding(title=, "
                            "severity=, summary=, evidence_url=, evidence_excerpt=) to emit a "
                            "finding. NO shell access, NO file writes outside /tmp."
                        ),
                    },
                    "target_url": {
                        "type": "string",
                        "description": "Full URL the test fires against. Must come from the recon endpoint inventory, never guessed.",
                    },
                    "success_condition": {
                        "type": "string",
                        "description": "What HTTP response or evidence proves the hypothesis TRUE (e.g., '302 to /dashboard AND Set-Cookie session=*'). Used by validator to enforce no-exploit-no-report.",
                    },
                    "estimated_severity": {
                        "type": "string",
                        "enum": ["critical", "high", "medium", "low"],
                        "description": "Severity assuming the test PROVES the issue. Validator may downgrade if exploit doesn't reproduce.",
                    },
                    "exec_plan_steps": {
                        "type": "string",
                        "description": (
                            "OPTIONAL: JSON-encoded exec_plan step list (only when tool=exec-plan). "
                            "Each step is an OBJECT with these EXACT fields: "
                            "name (str), method (GET|POST|PUT|PATCH|DELETE), url (str), "
                            "headers (dict, optional), data (str, optional, form-encoded body), "
                            "json (dict, optional), cookies (dict, optional). "
                            "`expect` MUST be a DICT (not a string) with these keys: "
                            "status (int or list[int]), body_contains (str or list[str]), "
                            "body_not_contains (str or list[str]), body_regex (str). "
                            "`on_success` MUST be a DICT with key `create_finding` whose value is a DICT: "
                            "{title:str, severity:critical|high|medium|low, summary:str, type:str}. "
                            "NEVER pass `expect` or `on_success` as a free-text string — runner crashes."
                        ),
                    },
                    "needs_credentials_from_vault": {
                        "type": "boolean",
                        "description": "True if the test should use credentials stored in the run credential vault (auth-flow auto-injects).",
                    },
                },
            },
        },
        "no_hypotheses_reason": {
            "type": "string",
            "description": "OPTIONAL: if hypotheses=[], explain why (e.g., 'recon shows no auth surface within scope'). Empty otherwise.",
        },
    },
}
