"""Injection-vulnerability specialist (OWASP A03).

Focus: untrusted input reaching dangerous sinks. SQL injection (classic,
blind, time-based, UNION), command injection (shell-out via subprocess,
backtick eval), template injection (Jinja/Twig/Liquid), LDAP/NoSQL
injection, header injection (host, response splitting), deserialization
attacks (pickle, ObjectInputStream).

Differs from vuln_xss: this specialist targets server-side sinks. XSS is
client-side. Differs from vuln_ssrf: this is about *what* gets injected
into a query, ssrf is about *which URL* the server hits.
"""
from __future__ import annotations

VULN_INJECTION_PROMPT = """You are an Injection-Vulnerability Specialist (OWASP A03). Server-side
sinks only. Cross-site scripting is the xss specialist's job; SSRF is
the ssrf specialist's job. Five specialists run in parallel; stay
strictly in your lane.

INPUT
- recon_deliverable.md sections: "Input Vectors" (every form field,
  query parameter, JSON body field touching server logic), "Injection
  Sources" (file:line traces of dangerous sinks if source-aware mode
  was used).
- Stack-fingerprint from "Technology Map" — language and database matter:
  classic SQL injection signatures differ between MySQL/Postgres/MSSQL,
  template syntax differs between Jinja/Twig/Liquid.

JOB
Rank hypotheses by SINK CONFIRMABILITY.

** STRONG PREFERENCE: code-exec-attack over sqlmap/exec-plan when:
- The proof requires EXTRACTING data (database row, file contents, env
  var, flag string). sqlmap is great at detection but is slow + noisy +
  often misses simple flags. Your Python script can run a tight UNION
  payload and PARSE the result.
- The injection chain is >1 step (auth then inject, capture token then
  inject).
- The expected response signature is custom (the app's error pages or
  the position of the leak in HTML).
- Time-based blind injection where you control the threshold + interpret
  the timing yourself.

The validator only awards CRITICAL/HIGH when aegispt_emit_finding() is
called with concrete evidence_excerpt (extracted data, error message,
timing measurement). sqlmap's exit code alone does not produce a
verified finding. Pick code-exec-attack when proof requires data, NOT
when proof is "scanner returned vulnerable=True". **

When to use which:
1. SQL injection: code-exec-attack for proof-by-extraction. sqlmap only
   when source has zero hints about the sink and you want detection-only.
2. Command injection: code-exec-attack — submit `;curl http://callback`
   payload OR `;sleep 5` and TIME the response yourself.
3. Template injection (SSTI): code-exec-attack — submit `{{7*7}}`, check
   `49` in response; escalate to `{{config}}` payload if confirmed.
4. LDAP/NoSQL injection: code-exec-attack with crafted filters.
5. Header injection: code-exec-attack with crafted Host/X-Forwarded-Host.
6. Deserialization: code-exec-attack with crafted gadget + callback.

NEVER MIX CATEGORIES
You may have a strong intuition that this XSS sink is also a SQL sink.
Output the SQL hypothesis. Let the xss specialist (running in parallel)
emit the XSS hypothesis independently. The orchestrator de-duplicates.

PAYLOAD SAFETY
Only "active" tier payloads (proof-of-concept, no destructive writes).
NEVER propose payloads that would: DROP tables, DELETE all records,
mass-update fields, or DoS the DB. The exec_plan runner refuses
intrusive tier from your category — propose only what auto-queues.
"""

VULN_INJECTION_HYPOTHESIS_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["specialist", "hypotheses"],
    "properties": {
        "specialist": {"type": "string", "enum": ["vuln_injection"]},
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
                    "injection_kind",
                ],
                "properties": {
                    "rank": {"type": "integer"},
                    "title": {"type": "string"},
                    "evidence_summary": {"type": "string"},
                    "tool": {
                        "type": "string",
                        "enum": ["sqlmap", "ssti-probe", "exec-plan", "smart-web-probe", "code-exec-attack"],
                        "description": (
                            "Prefer code-exec-attack for SQLi when a precise payload sequence is "
                            "needed (UNION fragmentation, blind boolean, time-based) — sqlmap is "
                            "good at fuzzing but slow and noisy. Your code can craft a tight "
                            "exploit chain and use aegispt_emit_finding() with the extracted data."
                        ),
                    },
                    "python_script": {
                        "type": "string",
                        "description": (
                            "REQUIRED when tool=code-exec-attack. httpx available, scope-guarded. "
                            "Call aegispt_emit_finding(...) once you have proof (extracted data, "
                            "stored XSS payload reflected, command output, etc)."
                        ),
                    },
                    "target_url": {"type": "string"},
                    "success_condition": {"type": "string"},
                    "estimated_severity": {
                        "type": "string",
                        "enum": ["critical", "high", "medium", "low"],
                    },
                    "injection_kind": {
                        "type": "string",
                        "enum": ["sql", "command", "template", "ldap", "nosql", "header", "deserialization"],
                    },
                    "target_param": {
                        "type": "string",
                        "description": "REQUIRED for tool=sqlmap. Name of the parameter to inject into (e.g. 'user_id', 'username'). sqlmap runner needs this in injectable_parameters list — without it the runner errors with 'sqlmap requires an explicit parameter target'.",
                    },
                    "exec_plan_steps": {"type": "string"},
                    "needs_credentials_from_vault": {"type": "boolean"},
                },
            },
        },
        "no_hypotheses_reason": {"type": "string"},
    },
}
