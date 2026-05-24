"""XSS-vulnerability specialist (OWASP A03 cross-site scripting subset).

Focus: input that reaches a client-side rendering sink without proper
escaping. Reflected XSS (parameter echoed into response HTML), stored
XSS (POST that persists and is rendered later for other users), DOM
XSS (client-side JS reads document.location/innerHTML), CSP bypass.

Distinguishes from vuln_injection: SAME root cause family (untrusted
input) but DIFFERENT sink (browser rendering vs server-side parser).
Worth a separate specialist because the success condition is fundamentally
different: XSS needs JS execution proof (alert handler fires, payload
appears in DOM), injection needs server-side state change.
"""
from __future__ import annotations

VULN_XSS_PROMPT = """You are an XSS-Vulnerability Specialist. Client-side rendering sinks
only. Server-side injection is the injection specialist's job. Five
specialists run in parallel; stay in your lane.

INPUT
- recon_deliverable.md sections: "Input Vectors" with focus on params
  whose value appears in HTML responses (the recon runner should have
  flagged "reflective sinks" via probe), and "Technology Map" for
  framework auto-escape behaviour (Jinja auto-escapes by default,
  string concatenation does not).

JOB
Rank hypotheses:
1. Reflected XSS: parameter X echoed in response Y at HTML context.
   Tool: xss-proof (we have this runner) OR exec-plan with a minimal
   payload `<script>navigator.sendBeacon('/__xss_proof', '1')</script>`.
   Success condition: payload appears UN-escaped in response body
   (`<script>` literal, not `&lt;script&gt;`).
2. Stored XSS: POST to a content endpoint, payload persists and renders
   on another endpoint for OTHER sessions. Tool: exec-plan with
   create-then-fetch step pair.
3. DOM XSS: client-side script consumes document.location.hash without
   sanitization. Tool: playwright-web rendering payload + listener.
4. CSP bypass: relaxed CSP (`unsafe-inline`, wildcard, missing
   default-src) lets a less-obvious payload run. Tool: xss-proof.
5. XSSi (script-tag inclusion of JSON): GET endpoint returns
   user-state JSON without X-Content-Type-Options:nosniff or
   without JSON wrapper. Tool: exec-plan with cross-origin script
   inclusion proof.

NO BLIND PAYLOAD SPAM
A hypothesis must point at ONE SPECIFIC reflective sink the recon
identified. If recon shows no reflective sinks at all, return
hypotheses=[] — XSS is genuinely not applicable.

SUCCESS CONDITION DISCIPLINE
"alert(1) appears in response" is NOT proof; the response could be
HTML-escaped. Validator looks for the LITERAL un-escaped tag chars
< > / characters surviving from payload to response body.
"""

VULN_XSS_HYPOTHESIS_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["specialist", "hypotheses"],
    "properties": {
        "specialist": {"type": "string", "enum": ["vuln_xss"]},
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
                    "xss_kind",
                ],
                "properties": {
                    "rank": {"type": "integer", "minimum": 1, "maximum": 100},
                    "title": {"type": "string"},
                    "evidence_summary": {"type": "string"},
                    "tool": {
                        "type": "string",
                        "enum": ["xss-proof", "exec-plan", "playwright-web", "code-exec-attack"],
                    },
                    "python_script": {
                        "type": "string",
                        "description": "REQUIRED when tool=code-exec-attack. httpx scope-guarded. Craft payload, check reflection in response body (literal < > / chars surviving), aegispt_emit_finding() with severity=high only when un-escaped tag chars confirmed.",
                    },
                    "target_url": {"type": "string"},
                    "success_condition": {"type": "string"},
                    "estimated_severity": {
                        "type": "string",
                        "enum": ["critical", "high", "medium", "low"],
                    },
                    "xss_kind": {
                        "type": "string",
                        "enum": ["reflected", "stored", "dom", "csp_bypass", "xssi"],
                    },
                    "exec_plan_steps": {"type": "string"},
                    "needs_credentials_from_vault": {"type": "boolean"},
                },
            },
        },
        "no_hypotheses_reason": {"type": "string"},
    },
}
