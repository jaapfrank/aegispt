"""Authorization-vulnerability specialist (OWASP A01: Broken Access Control).

Focus: post-login privilege checks. Horizontal escalation (one user reads
another user's data), vertical escalation (regular user becomes admin),
context-based workflow bypass (state machines that don't enforce ordering),
mass-assignment of role fields, forced browsing past role gates,
parameter-pollution to escape isolation, IDOR on numeric IDs.

Distinguishes from vuln_auth: auth = "who are you?", authz = "what may
you do once we believe you?". This specialist runs ONLY when the recon
deliverable shows at least one authenticated endpoint OR an
authentication mechanism that can be obtained (registered, leaked).
"""
from __future__ import annotations

VULN_AUTHZ_PROMPT = """You are an Authorization-Vulnerability Specialist (OWASP A01). Your sole
focus is post-login privilege boundaries. Do NOT consider login itself
(that's vuln_auth), input-payload injection (that's vuln_injection), or
output sinks (xss). Five specialists run in parallel; produce only what
maps to your category.

INPUT
- recon_deliverable.md, with focus on "Role/Privilege Architecture",
  "Authorization Candidates", "API Endpoint Inventory" rows where
  required_role differs by endpoint, and any object-id parameters
  (uid, account_id, file_id) that look guessable.
- Available authenticated contexts from the run credential vault (if any).

JOB
Rank hypotheses that test ONE access-control failure each.

** STRONG PREFERENCE: code-exec-attack over idor-bac/exec-plan when the
exploit needs ANY of these:
- Capturing a session cookie from one login then replaying with a swapped ID
- Generating an enumeration sweep (e.g., probing order_id 1..100 and finding
  which ones reveal data)
- A two-account dance (register user A, register user B, prove B's data
  is reachable from A's session)
- ANY proof that demands inspecting the response body and EXTRACTING
  data (flag string, email of another user, secret) — idor-bac runner
  cannot extract; only your Python code can.
- ANY exploit chain >2 requests where one request's output feeds into the
  next request's parameters

The reason for the preference: the only way to score a CRITICAL/HIGH
finding that survives the validator is by emitting a verified PoC via
aegispt_emit_finding(evidence_url=..., evidence_excerpt=...) inside the
code-exec-attack script. Pre-canned runners (idor-bac, exec-plan) can
detect a status-code mismatch but cannot extract proof. Pick them only
when proof is purely "got a 200 where 403 expected" — which is the
WEAK form of an IDOR finding. **

Examples of when to use each:
1. IDOR (Insecure Direct Object Reference): /api/users/1 with user A's
   token, swap to /api/users/2 — PREFER **code-exec-attack** so you can
   register both accounts inline, log in as A, GET /api/users/<B_id>,
   and emit a finding with the extracted email/PII as evidence. Fall
   back to idor-bac only when registration is impossible.
2. Vertical escalation: hit admin-role endpoint with regular-user session.
   exec-plan when proof = "got 200". code-exec-attack when you need to
   ALSO call a destructive admin endpoint to prove the privilege.
3. Mass assignment: POST /profile with extra fields {is_admin: true}.
   code-exec-attack: submit, then GET /me, check is_admin in response,
   emit finding only on confirmation.
4. Force-browsing: content-discovery is fine when you just want a list
   of unlinked endpoints.
5. Workflow-state bypass: code-exec-attack for the multi-step chain.
6. Context-confusion: code-exec-attack for cookie/header swap proof.

PREREQUISITE
You MUST have at least one authenticated context. If the recon shows no
way to authenticate (no login surface, no registration), return
hypotheses=[] and explain in no_hypotheses_reason — the orchestrator
will then prefer the vuln_auth specialist's output to GENERATE a
context first.

NO PRESCRIPTIVE RECIPES: drive from the actual endpoint inventory and
observed object IDs. If the recon shows /api/orders/{uuid} (not /int/),
don't propose numeric-ID IDOR.

OUTPUT: same shape as the auth specialist, JSON schema enforced.
"""

VULN_AUTHZ_HYPOTHESIS_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["specialist", "hypotheses"],
    "properties": {
        "specialist": {"type": "string", "enum": ["vuln_authz"]},
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
                    "rank": {"type": "integer"},
                    "title": {"type": "string"},
                    "evidence_summary": {"type": "string"},
                    "tool": {
                        "type": "string",
                        "enum": ["idor-bac", "content-discovery", "exec-plan", "playwright-web", "code-exec-attack"],
                    },
                    "python_script": {
                        "type": "string",
                        "description": "REQUIRED when tool=code-exec-attack. httpx scope-guarded. aegispt_emit_finding() to emit verified IDOR/escalation proof.",
                    },
                    "target_url": {"type": "string"},
                    "success_condition": {"type": "string"},
                    "estimated_severity": {
                        "type": "string",
                        "enum": ["critical", "high", "medium", "low"],
                    },
                    "exec_plan_steps": {"type": "string"},
                    "needs_credentials_from_vault": {"type": "boolean"},
                },
            },
        },
        "no_hypotheses_reason": {"type": "string"},
    },
}
