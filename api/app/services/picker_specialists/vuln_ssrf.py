"""SSRF-vulnerability specialist (OWASP A10).

Focus: parameters that cause the SERVER to make outbound HTTP requests.
Image fetchers, webhook senders, URL preview generators, OAuth callback
endpoints, document-import endpoints accepting URLs, PDF generators
that follow embedded asset URLs.

The interesting target is metadata services (169.254.169.254 AWS,
metadata.google.internal GCP) and internal networks (10/8, 172.16/12,
192.168/16, 127/8). The specialist proposes server-side request
manipulation hypotheses; the orchestrator dispatches; the validator
confirms the OUT-OF-BAND signal (DNS exfil to a runner-controlled host
or HTTP-callback hit).
"""
from __future__ import annotations

VULN_SSRF_PROMPT = """You are an SSRF-Vulnerability Specialist (OWASP A10). Server-side
request forgery only. Five specialists run in parallel; do not propose
client-side or injection-style payloads.

INPUT
- recon_deliverable.md sections: "Input Vectors" filtered for fields
  whose name or context implies a URL (logo_url, callback_url,
  webhook_endpoint, avatar_src, import_from, fetch, preview), and
  "Network/Interaction Map" for any outbound calls the server already
  makes.

JOB
Rank hypotheses:
1. Direct SSRF: parameter accepts a URL and the server fetches it.
   Test by pointing at attacker-controlled callback host (we run a
   small HTTP listener) — if the listener gets a hit, confirmed.
   Tool: exec-plan with `expect.callback_received` check.
2. Cloud metadata SSRF: target accepts URL, point at
   169.254.169.254/latest/meta-data/. Tool: exec-plan; success =
   AWS-IMDS-style response body.
3. Internal-network reach: point at common internal ports (e.g.,
   localhost:6379 Redis, localhost:9200 Elasticsearch). Tool:
   exec-plan with banner-grab payload.
4. Blind SSRF with DNS exfil: parameters that don't echo the response;
   trigger DNS lookup against runner-controlled domain (we don't have
   a public catcher yet — propose this as LOW rank until Phase 6 ships
   the catcher).
5. PDF/image SSRF: file-import endpoints that follow embedded URLs
   inside uploaded SVG/PDF/HTML. Tool: exec-plan with crafted upload.

PREREQUISITE
The validator needs an OUT-OF-BAND signal to confirm SSRF. If we don't
have a callback host configured for this run, downgrade ALL hypotheses
to medium and warn in the hypothesis's success_condition.

NO PRESCRIPTIVE RECIPES: drive from actual url-shaped fields in the
inventory, not from generic SSRF wordlists.
"""

VULN_SSRF_HYPOTHESIS_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["specialist", "hypotheses"],
    "properties": {
        "specialist": {"type": "string", "enum": ["vuln_ssrf"]},
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
                    "target_url_in_payload",
                ],
                "properties": {
                    "rank": {"type": "integer"},
                    "title": {"type": "string"},
                    "evidence_summary": {"type": "string"},
                    "tool": {"type": "string", "enum": ["exec-plan", "smart-web-probe", "code-exec-attack"]},
                    "python_script": {
                        "type": "string",
                        "description": "REQUIRED when tool=code-exec-attack. httpx scope-guarded. Use code to craft SSRF payload targeting metadata/internal hosts and aegispt_emit_finding() on out-of-band hit.",
                    },
                    "target_url": {
                        "type": "string",
                        "description": "The VICTIM endpoint URL — the server we're testing.",
                    },
                    "target_url_in_payload": {
                        "type": "string",
                        "description": "What URL the attacker tries to make the server fetch (callback host / metadata IP / internal port).",
                    },
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
