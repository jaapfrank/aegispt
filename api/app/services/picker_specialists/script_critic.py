"""Adversarial script critic — M1 of beat-shannon-pro-roadmap-2026-05-23.

When a code-exec-attack task ran but produced no AEGISPT_FINDING, the
orchestrator dispatches this specialist instead of re-running the 5
analysis specialists. The critic reads the prior script + its stdout
+ the recon deliverables and identifies what the prior script MISSED
(typically: a state-change primitive that grants access, a second-step
chain, or a captured-value replay).

Empirical anchor: XBEN-002 (2026-05-23 run b4385178) — code-exec-attack
script wrote a read-only horizontal IDOR probe across order IDs. It
missed the `/order/<int>/archive` route (sets archiver field) which is
the access-grant step before `/order/<int>/receipt` returns the flag.
The critic's job is exactly to spot patterns like that.

Output: a REVISED python_script that adds the missing primitive,
emitted via code-exec-attack on the next iteration.
"""
from __future__ import annotations

SCRIPT_CRITIC_PROMPT = """You are a senior security engineer reviewing an exploit script that ran
against a target but FAILED to emit a verified finding. Your job is to
identify what the script MISSED and emit a corrected version.

You are NOT analyzing the target. The 5 analysis specialists already
did that. You are reviewing ONE concrete artifact — the prior exploit
attempt — and explaining why it didn't reach a Level-3 proof, then
fixing it.

INPUTS YOU RECEIVE
1. The previous `python_script` source (full text).
2. The script's stdout + stderr from its sandboxed run.
3. The recon_deliverable.md (network-observed attack surface).
4. The pre-recon-source-deliverable.md (source-grepped routes, sinks,
   auth surface, default creds — present when source-aware mode is on).
5. The hypothesis title + evidence_summary that motivated the original
   script.

YOUR JOB — five-step critique

Step 1. **Re-read the recon deliverables**. For each ROUTE listed in
the source audit + the network endpoint inventory: ask "did the script
exercise this?". Make an explicit list of unused routes.

Step 2. **Identify STATE-CHANGE primitives**. Routes that mutate
server-side state (set fields, archive, transfer, approve, mark)
ALSO grant new access privileges in many apps. If the prior script
only did GET probes, list every available POST/PUT/DELETE/state-changing
GET route that could grant access to a resource the script tried to
read but got 401/403/404.

Step 3. **Trace the access-check logic**. The pre-recon-source
deliverable surfaces auth-check expressions (`or_(...==user, ...==user)`,
`@login_required`, `session['user_id']`). For each protected route
the prior script targeted, identify WHICH conditions would grant
access AND which state-change routes could SET those conditions.

Step 4. **Spot 2-step / N-step chains**. Common patterns missed by
single-pass exploit scripts:
  - state-change-then-read: POST /resource/<id>/archive to become
    archiver, then GET /resource/<id>/receipt where access requires
    creator OR archiver
  - register-then-IDOR: register a second account, log in as it, then
    enumerate IDs assigned to other users
  - capture-then-replay: an unauthenticated endpoint returns a token;
    use it to access a guarded one
  - mass-assignment: include extra POST fields (is_admin, role) and
    verify via a subsequent GET

Step 5. **Emit a REVISED python_script** that:
  - Keeps what worked (login, scope guard, session)
  - Adds the missed primitive (state-change call, second account, etc)
  - Verifies the new path with a GET after the state-change
  - Calls aegispt_emit_finding() with severity=critical or high and
    evidence_excerpt containing the literal extracted data (flag string,
    other user's email, etc) — NOT just "got 200 from a guarded URL"

FORBIDDEN
- Do not write a finding marker unless you have a HYPOTHESIS about
  what concrete data the corrected script will extract.
- Do not propose tools other than code-exec-attack. Your job is to
  revise THIS script, not to recommend a different tool family.
- Do not declare success without aegispt_emit_finding(...) being
  called by the revised script on a verified condition (response
  status + body content match expected pattern).

OUTPUT
Return ONE JSON object matching the schema. The revised_python_script
becomes the next code-exec-attack task's script param.
"""


SCRIPT_CRITIC_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "specialist",
        "missed_primitives",
        "revised_python_script",
        "expected_finding_severity",
        "expected_evidence_pattern",
    ],
    "properties": {
        "specialist": {"type": "string", "enum": ["script_critic"]},
        "missed_primitives": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["kind", "evidence", "why_missed"],
                "properties": {
                    "kind": {
                        "type": "string",
                        "enum": [
                            "state_change_route",
                            "second_account_register",
                            "capture_then_replay",
                            "mass_assignment",
                            "chained_redirect",
                            "header_or_cookie_swap",
                            "rate_limit_pivot",
                            "other",
                        ],
                    },
                    "evidence": {
                        "type": "string",
                        "description": "1-2 sentence quote/paraphrase from recon (file:line or endpoint inventory row) showing the primitive exists.",
                    },
                    "why_missed": {
                        "type": "string",
                        "description": "Why the prior script didn't use it (e.g. 'only did GETs, never POST', 'didn't link archive to receipt access-check').",
                    },
                },
            },
            "minItems": 1,
            "description": "MUST contain at least one identified missed primitive. If you cannot find any, return the response as a no-op revised script that explicitly logs that the prior attempt was already exhaustive.",
        },
        "revised_python_script": {
            "type": "string",
            "description": "Self-contained Python (httpx + aegispt_emit_finding helper). Addresses the missed primitive(s). Includes scope-guarded requests + final aegispt_emit_finding() call only when the verified condition is met.",
        },
        "expected_finding_severity": {
            "type": "string",
            "enum": ["critical", "high", "medium", "low"],
        },
        "expected_evidence_pattern": {
            "type": "string",
            "description": "Brief description of what evidence_excerpt should look like when the revised script succeeds (e.g. 'response body containing the literal flag string xbow-...', 'another user's email address').",
        },
        "critique_summary": {
            "type": "string",
            "description": "1-3 sentence operator-facing summary of what was wrong and how the revision fixes it.",
        },
    },
}
