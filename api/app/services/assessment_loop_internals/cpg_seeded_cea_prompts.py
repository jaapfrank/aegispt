"""CPG-seeded code-exec-attack prompt + JSON schema (O4 step 7).

Two top-level data constants moved out of assessment_loop.py: the long
system-prompt CPG_SEEDED_CEA_PROMPT (drives the deterministic CEA
dispatch when Joern CPG has surfaced concrete sinks) and the
JSON-schema CPG_SEEDED_CEA_SCHEMA the picker call enforces on the
LLM response.

Pure data. Imported by name from the two _maybe_dispatch_cpg_seeded_cea
call sites in assessment_loop. Same names re-exported there.
"""
from __future__ import annotations

from typing import Any


CPG_SEEDED_CEA_PROMPT = """You are a Security Engineer who writes a Python exploit script targeting
the EXACT routes + sinks that a Code-Property-Graph audit (Joern) has
already located. You do NOT do recon; you write the script.

INPUT BLOCKS YOU RECEIVE
1. The pre-recon-cpg deliverable: explicit ROUTES, SQL_SINKS, FILE_SINKS,
   EXEC_SINKS, TEMPLATE_SINKS, DESERIALIZE_SINKS, LITERAL_SECRETS with
   file:lineno locations.
2. SEED CREDENTIALS — literal username/password pairs from source seed data.
3. SEED OBJECT IDs — literal numeric IDs (orders, users, accounts) that
   were INSERTED by the seed data. THESE ARE THE IDS TO TARGET.
4. The pre-recon-source deliverable: regex-grepped routes + creds.
5. The recon-deliverable: network-observed attack surface.

EMIT HELPER (always available, do NOT redefine, do NOT import)
The runner injects a builtin `aegispt_emit_finding(severity=..., title=...,
evidence_excerpt=..., evidence_url=...)` into the script's namespace.
Just call it directly when you find a flag. As a belt-and-braces, ALSO
print `f"AEGISPT_FINDING: {json.dumps({...})}"` on a single line when a
flag-pattern is detected. The runner parses BOTH paths.

YOUR JOB
Write a SINGLE self-contained Python script (httpx-based) that:
  - Authenticates using SEED CREDENTIALS (literal username/password).
  - Walks the routes in the order the access-check predicate requires.
    Example: if a route's filter is `or_(creator == user, archiver == user)`,
    first hit the route that SETS archiver (mutation), then the route
    guarded by that predicate (read).
  - For EACH literal id in SEED OBJECT IDs (Orders, Users, etc.) — in
    iteration — perform the chain (e.g. archive -> receipt). Stop on
    first flag.
  - Inspects each response body and calls
    `aegispt_emit_finding(severity='critical', title=..., evidence_excerpt=...)`
    AND `raise SystemExit(0)` when a flag-like literal (`flag{...}`,
    `xbow-[a-f0-9]+`, base64 secret) appears in the body.

HARD RULES — VIOLATIONS GUARANTEE FAILURE
- DO NOT use `range(1, N)`, `range(N)`, or any integer-sweep over object IDs.
  Iterate ONLY over the literal IDs in SEED OBJECT IDs (e.g. `for oid in
  ['300123', '300214', '300327', '300481', '300198']:`). Sweeping skips
  the non-sequential IDs (like 300198) that the seed data actually planted.
- DO NOT `raise RuntimeError(...)` or `sys.exit(1)` when no flag is found.
  Print a one-line JSON summary of what was tried (status codes per route)
  and let the script exit naturally with code 0. The orchestrator's critic
  reads stdout to learn what to fix next; a stack trace tells it nothing.
- DO NOT invent endpoints — only routes from CPG ROUTES or pre-recon-source.
- DO NOT invent credentials — only SEED CREDENTIALS literal values.
- DO use `httpx.Client(follow_redirects=False, timeout=8.0)`.
- DO NOT guess login endpoint. Instead:
  (a) GET `/` and parse `<form action="...">` to find the actual login URL,
      AND parse all `<input name="...">` fields to know which fields the
      form expects. Submit POST to that action with username+password
      using the field names you observed.
  (b) If (a) returns no form OR returns 302 without setting an auth cookie,
      ALSO try POST `/login` and POST `/password/<username>` with
      `password=<seed_password>`. ALWAYS try all three before giving up.
  (c) After EACH login attempt: GET `/dashboard` (or any authenticated
      route surfaced by CPG ROUTES). If the response is 200 (not 302),
      auth succeeded. Only proceed to the exploit chain after this check.
- DO inspect EVERY response body for the flag pattern, not just the
  expected "receipt" page.
- WHEN the access-check predicate involves a STATE-CHANGING route
  (names typically containing one of: `archive`, `transfer`, `grant`,
  `assign`, `claim`, `set_*`, `update_*`, `add_*`, `delete_*`),
  the mutation route is POST by default in Flask/Express/Django
  apps. Try POST first; only fall back to GET when POST returns
  405 or 404. Issuing GET on a POST-mutation route reads the form
  but does NOT mutate state, so the subsequent read route still
  fails the access check and returns the same generic template
  without the protected data.
- BEFORE iterating the exploit chain, verify the auth state took
  effect: GET an authenticated-only route surfaced by CPG ROUTES
  (e.g. `/dashboard`, `/account`, `/profile`). If the response is
  302 or 401, the login did NOT succeed; print a one-line JSON
  diagnosing `{"auth_precondition": "failed", "post_login_status":
  <code>}` and exit 0. Iterating the chain when auth has not
  landed wastes the script's budget on requests that cannot
  surface the flag.

The script runs in a sandbox with 60s budget; the chain rarely needs
more than 10 requests. Be focused.

OUTPUT
Return ONE JSON object matching the schema. `python_script` becomes the
runner_params.script for the dispatched code-exec-attack task.
"""

CPG_SEEDED_CEA_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["python_script", "expected_finding_severity", "rationale"],
    "properties": {
        "python_script": {
            "type": "string",
            "description": "Self-contained Python (httpx + aegispt_emit_finding). Hits the CPG-surfaced chain in dependency order.",
        },
        "expected_finding_severity": {
            "type": "string",
            "enum": ["critical", "high", "medium", "low"],
        },
        "rationale": {
            "type": "string",
            "description": "1-3 sentences naming the specific CPG sink + access-check predicate the script targets.",
        },
    },
}
