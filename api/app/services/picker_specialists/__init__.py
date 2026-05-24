"""Picker specialist agents (Phase 1 of landscape-plan 2026-05-22).

Each specialist focuses on ONE OWASP category and emits a list of
hypothesized exploitable paths. The orchestrator (specialist_orchestrator.py)
fans out to all 5 in parallel and merges results into a ranked queue
that the existing exec_plan/runner pipeline consumes.

Pattern lifted from Shannon Lite (apps/worker/prompts/vuln-*.txt) which
hit 96.15% on XBOW with this architecture vs our single-picker 0%.

Specialist prompts intentionally remove the cross-category logic that
bloats our current 24KB picker. Each is ~6-8KB. No prescriptive recipes:
the specialist reasons from the recon deliverable, doesn't seed
app-specific exploits.
"""
from .vuln_auth import VULN_AUTH_PROMPT, VULN_AUTH_HYPOTHESIS_SCHEMA
from .vuln_authz import VULN_AUTHZ_PROMPT, VULN_AUTHZ_HYPOTHESIS_SCHEMA
from .vuln_injection import VULN_INJECTION_PROMPT, VULN_INJECTION_HYPOTHESIS_SCHEMA
from .vuln_ssrf import VULN_SSRF_PROMPT, VULN_SSRF_HYPOTHESIS_SCHEMA
from .vuln_xss import VULN_XSS_PROMPT, VULN_XSS_HYPOTHESIS_SCHEMA
from .script_critic import SCRIPT_CRITIC_PROMPT, SCRIPT_CRITIC_SCHEMA

__all__ = [
    "VULN_AUTH_PROMPT",
    "VULN_AUTH_HYPOTHESIS_SCHEMA",
    "VULN_AUTHZ_PROMPT",
    "VULN_AUTHZ_HYPOTHESIS_SCHEMA",
    "VULN_INJECTION_PROMPT",
    "VULN_INJECTION_HYPOTHESIS_SCHEMA",
    "VULN_SSRF_PROMPT",
    "VULN_SSRF_HYPOTHESIS_SCHEMA",
    "VULN_XSS_PROMPT",
    "VULN_XSS_HYPOTHESIS_SCHEMA",
    "SCRIPT_CRITIC_PROMPT",
    "SCRIPT_CRITIC_SCHEMA",
]
